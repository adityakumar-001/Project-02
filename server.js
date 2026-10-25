// ============================================================
// Get-Attended backend — Node.js + Express + MySQL (Render ready)
// Hierarchy: ORGANIZER (single row, top) -> ADMINS (multiple rows,
// Organizer-managed) -> EMPLOYEES (per-admin owner via adminId)
// Security model:
// - Passwords are stored as scrypt hashes (legacy plaintext upgraded
//   automatically on login / boot).
// - Login endpoints return short-lived bearer tokens. Tokens are stored
//   hashed (SHA-256) in auth_tokens and are required for every data API.
// - Every route is role-scoped: ORGANIZER -> admins only,
//   ADMIN -> its own employees/records/leaves, EMPLOYEE -> its own data.
// - API_SECRET (optional) stays as an extra shared app-key gate only.
// Run: npm install | node server.js | Deploy: Render Web Service
// ============================================================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const mysql = require('mysql2/promise');
const crypto = require('crypto');

// ---------------- Config ----------------
const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.API_SECRET || '';
const CORS_ORIGIN = String(process.env.CORS_ORIGIN || '').trim();
const TTL_ADMIN = Math.max(60, Number(process.env.TOKEN_TTL_ADMIN || 3600));
const TTL_ORGANIZER = Math.max(60, Number(process.env.TOKEN_TTL_ORGANIZER || 3600));
const TTL_EMPLOYEE = Math.max(60, Number(process.env.TOKEN_TTL_EMPLOYEE || 900));
const MIN_PASS = 8;

// ---------------- App + middleware ----------------
const app = express();
app.disable('x-powered-by');
// Render (and most reverse proxies) terminate TLS in front of the app.
// Correct client IPs keep per-IP login rate limiting useful.
app.set('trust proxy', 1);

// Safety net: wrap every route handler so a thrown error / rejected
// promise becomes a clean JSON 500 reply instead of a hanging request
// or a process crash (Node 18+ exits on unhandled rejections, Express 4
// does not catch async errors). Registered before any route below.
function wrapRoute(handler) {
  if (typeof handler !== 'function' || handler.length === 4) return handler; // skip error middleware
  return function (req, res, next) {
    try {
      const out = handler(req, res, next);
      if (out && typeof out.catch === 'function') out.catch(next);
    } catch (e) {
      next(e);
    }
  };
}
for (const method of ['get', 'post', 'put', 'delete', 'patch']) {
  const original = app[method].bind(app);
  app[method] = (pathArg, ...handlers) => original(pathArg, ...handlers.map(wrapRoute));
}

if (CORS_ORIGIN) {
  const origins = CORS_ORIGIN.split(',').map((s) => s.trim()).filter(Boolean);
  app.use(cors({
    origin(origin, cb) {
      if (!origin || origins.includes(origin)) return cb(null, true);
      return cb(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-secret'],
  }));
} else {
  // Bearer tokens (not cookies) are used, so a wildcard CORS policy does
  // not expose authenticated data. Set CORS_ORIGIN in production to lock
  // the API to your frontend origin(s).
  app.use(cors());
}
app.use(express.json({ limit: '50mb' })); // base64 photos travel inside JSON (full sync payloads)

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(self), geolocation=(self), microphone=()');
  next();
});

// ---------------- Shared app key (optional) ----------------
// The shared API_SECRET is NOT authentication. It only adds a cheap gate
// in front of the API when configured. Real identity comes from bearer
// tokens issued by /api/{organizer,admin,employee}/login.
function checkApiKey(req, res, next) {
  if (!API_SECRET) return next();
  const given = Buffer.from(String(req.headers['x-api-secret'] || ''));
  const expected = Buffer.from(API_SECRET);
  if (given.length === expected.length && crypto.timingSafeEqual(given, expected)) return next();
  return res.status(401).json({ ok: false, error: 'wrong-secret' });
}

app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.path === '/health') return next();
  checkApiKey(req, res, next);
});

// ---------------- Rate limiting (in-memory) ----------------
const buckets = new Map();
function rateLimit(name, max, windowMs) {
  return (req, res, next) => {
    const ip = String(req.ip || req.connection.remoteAddress || '');
    const key = name + '|' + ip;
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || b.reset <= now) {
      b = { count: 0, reset: now + windowMs };
      buckets.set(key, b);
    }
    b.count += 1;
    if (b.count > max) return res.status(429).json({ ok: false, error: 'too-many-attempts' });
    return next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (b.reset <= now) buckets.delete(k);
}, 10 * 60 * 1000).unref();

// ---------------- MySQL pool ----------------
// Managed MySQL providers (Aiven, Railway, PlanetScale, etc.) usually
// require SSL. Set DB_SSL=true in that case; local MySQL can leave it off.
const dbSslOn = /^(1|true|yes|on)$/i.test(String(process.env.DB_SSL || '').trim());
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'attend',
  port: Number(process.env.DB_PORT || 3306),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  dateStrings: true, // DATE returns 'YYYY-MM-DD' exactly as stored (no timezone shift)
  ...(dbSslOn ? { ssl: { rejectUnauthorized: false } } : {}),
});

// ---------------- Small helpers ----------------
function pad2(n) {
  return String(n).padStart(2, '0');
}

// Local (server-timezone safe) YYYY-MM-DD. Using toISOString() here can
// shift the date by one day for UTC+ timezones (e.g. IST), which made
// pulled records land on the previous day.
function dateOnly(v) {
  if (v instanceof Date) {
    return v.getFullYear() + '-' + pad2(v.getMonth() + 1) + '-' + pad2(v.getDate());
  }
  const s = String(v == null ? '' : v);
  return s.length >= 10 ? s.slice(0, 10) : s;
}

function todayD() {
  return dateOnly(new Date());
}

function txt(v) {
  return v == null ? '' : String(v).trim();
}

function cleanId(v, min = 1) {
  const s = txt(v);
  if (s.length < min || s.length > 50) return '';
  if (/[\u0000-\u001f\u007f]/.test(s)) return '';
  return s;
}

// Strict YYYY-MM-DD validation (also rejects 2026-02-31 style dates).
function isDateStr(v) {
  const s = txt(v);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const [y, m, d] = s.split('-').map(Number);
  const dt = new Date(y, m - 1, d);
  return dt.getFullYear() === y && dt.getMonth() === m - 1 && dt.getDate() === d;
}

function leaveStatus(v) {
  const s = txt(v);
  return ['Pending', 'Approved', 'Rejected'].includes(s) ? s : '';
}

function normAdminRow(a) {
  if (!a) return null;
  if (!a.status) a.status = 'Enabled';
  if (a.company === undefined || a.company === null) a.company = '';
  if (a.mustChangePass !== undefined) a.mustChangePass = !!a.mustChangePass;
  return a;
}

function normEmpRow(e) {
  if (!e) return e;
  if (!e.status) e.status = 'Enabled';
  if (e.mustChangePass !== undefined) e.mustChangePass = !!e.mustChangePass;
  if (e.adminId === undefined || e.adminId === null) e.adminId = '';
  return e;
}

// Strip the password hash from anything sent back to a browser.
function safeAdmin(a) {
  if (!a) return null;
  const x = { ...a };
  delete x.pass;
  return normAdminRow(x);
}

function safeEmp(e) {
  if (!e) return e;
  const x = { ...e };
  delete x.pass;
  return normEmpRow(x);
}

function safeOrganizer(o) {
  if (!o) return null;
  const x = { ...o };
  delete x.pass;
  return x;
}

function sameId(a, b) {
  return String(a || '').toLowerCase() === String(b || '').toLowerCase();
}

// ---------------- Password hashing (scrypt) ----------------
const SCRYPT_PREFIX = 'scrypt$';
const SCRYPT_KEYLEN = 64;

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, SCRYPT_KEYLEN);
  return SCRYPT_PREFIX + salt.toString('hex') + '$' + hash.toString('hex');
}

function isHashedPassword(v) {
  return /^scrypt\$[0-9a-f]{32}\$[0-9a-f]{128}$/i.test(String(v || ''));
}

function verifyPassword(password, stored) {
  const s = String(stored == null ? '' : stored);
  if (!s) return false;
  if (isHashedPassword(s)) {
    const parts = s.split('$');
    try {
      const salt = Buffer.from(parts[1], 'hex');
      const expected = Buffer.from(parts[2], 'hex');
      const actual = crypto.scryptSync(String(password), salt, expected.length);
      return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
    } catch (e) {
      return false;
    }
  }
  // Legacy plaintext rows: constant-time compare, then upgrade on login.
  const a = Buffer.from(String(password));
  const b = Buffer.from(s);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function passwordError(password) {
  const p = String(password == null ? '' : password);
  if (p.length < MIN_PASS) return 'password-too-short';
  if (p.length > 128) return 'password-too-long';
  return '';
}

async function upgradePasswordIfLegacy(table, id, plain, stored) {
  if (!stored || isHashedPassword(stored)) return;
  if (!verifyPassword(plain, stored)) return;
  try {
    await pool.query(
      `UPDATE ${table} SET pass=? WHERE id=? AND pass=?`,
      [hashPassword(plain), id, stored]
    );
  } catch (e) {
    // Non-fatal: login already succeeded with the legacy value.
  }
}

// ---------------- Auth: opaque bearer tokens ----------------
function sha256(v) {
  return crypto.createHash('sha256').update(String(v)).digest('hex');
}

async function issueToken(role, subjectId, ttlSeconds) {
  const raw = crypto.randomBytes(32).toString('base64url');
  const tokenHash = sha256(raw);
  const expiresAt = new Date(Date.now() + Math.floor(ttlSeconds) * 1000);
  await pool.query(
    'INSERT INTO auth_tokens (tokenHash, role, subjectId, expiresAt) VALUES (?,?,?,?)',
    [tokenHash, role, String(subjectId), expiresAt]
  );
  return { token: raw, expiresIn: Math.floor(ttlSeconds) };
}

function roleOnly(...roles) {
  return (req, res, next) => {
    if (!req.auth) return res.status(401).json({ ok: false, error: 'unauthorized' });
    if (!roles.includes(req.auth.role)) return res.status(403).json({ ok: false, error: 'forbidden' });
    return next();
  };
}

async function revokeTokens(role, id, keepHash) {
  const params = [role, String(id)];
  let sql = 'DELETE FROM auth_tokens WHERE role=? AND LOWER(subjectId)=LOWER(?)';
  if (keepHash) {
    sql += ' AND tokenHash<>?';
    params.push(keepHash);
  }
  await pool.query(sql, params);
}

async function revokeAdminAndEmployees(adminId) {
  await pool.query(
    `DELETE FROM auth_tokens
      WHERE (role='admin' AND LOWER(subjectId)=LOWER(?))
         OR (role='employee' AND LOWER(subjectId) IN
             (SELECT id FROM employees WHERE LOWER(adminId)=LOWER(?)))`,
    [adminId, adminId]
  );
}

// A token is only a pointer; the account must still exist and be enabled.
// This makes deletion/disable take effect immediately even if a token row
// was missed by a failed revoke call.
async function accountIsActive(role, id) {
  if (role === 'organizer') {
    const [rows] = await pool.query('SELECT id FROM organizers LIMIT 1');
    return !!rows[0] && sameId(rows[0].id, id);
  }
  if (role === 'admin') {
    const [rows] = await pool.query('SELECT status FROM admins WHERE LOWER(id)=LOWER(?) LIMIT 1', [id]);
    if (!rows[0]) return false;
    return String(rows[0].status || 'Enabled') !== 'Disabled';
  }
  if (role === 'employee') {
    const [rows] = await pool.query(
      `SELECT e.status AS empStatus, e.adminId,
              a.id AS ownerId, a.status AS ownerStatus
         FROM employees e
         LEFT JOIN admins a ON LOWER(e.adminId)=LOWER(a.id)
        WHERE LOWER(e.id)=LOWER(?) LIMIT 1`,
      [id]
    );
    const row = rows[0];
    if (!row) return false;
    if (String(row.empStatus || 'Enabled') === 'Disabled') return false;
    // Employees of a deleted/disabled admin are blocked too.
    if (row.adminId && (!row.ownerId || String(row.ownerStatus || 'Enabled') === 'Disabled')) return false;
    return true;
  }
  return false;
}

function authenticate(req, res, next) {
  const header = String(req.headers.authorization || '');
  const m = /^Bearer\s+(.+)$/i.exec(header);
  const token = m ? m[1].trim() : '';
  if (!token) return res.status(401).json({ ok: false, error: 'unauthorized' });
  const tokenHash = sha256(token);
  pool.query(
    'SELECT role, subjectId FROM auth_tokens WHERE tokenHash=? AND expiresAt > NOW() LIMIT 1',
    [tokenHash]
  ).then(async ([rows]) => {
    if (!rows.length) return res.status(401).json({ ok: false, error: 'session-expired' });
    const role = String(rows[0].role || '');
    const id = String(rows[0].subjectId);
    if (!(await accountIsActive(role, id))) {
      await pool.query('DELETE FROM auth_tokens WHERE tokenHash=?', [tokenHash]).catch(() => {});
      return res.status(401).json({ ok: false, error: 'session-expired' });
    }
    req.auth = { role, id, tokenHash };
    return next();
  }).catch(next);
}

async function moveTokens(conn, role, oldId, newId) {
  try {
    await conn.query(
      'UPDATE auth_tokens SET subjectId=? WHERE role=? AND LOWER(subjectId)=LOWER(?)',
      [newId, role, oldId]
    );
  } catch (e) {}
}

// Find the real stored ID with a case-insensitive fallback
// (utf8mb4_unicode_ci usually matches already, this is a safety net).
async function resolveAdminId(connOrPool, id) {
  const [rows] = await connOrPool.query('SELECT id FROM admins WHERE id=?', [id]);
  if (rows[0]) return rows[0].id;
  const [all] = await connOrPool.query('SELECT id FROM admins');
  const f = all.find((x) => sameId(x.id, id));
  return f ? f.id : null;
}

async function resolveEmployeeId(connOrPool, id) {
  const [rows] = await connOrPool.query('SELECT id FROM employees WHERE id=?', [id]);
  if (rows[0]) return rows[0].id;
  const [all] = await connOrPool.query('SELECT id FROM employees');
  const f = all.find((x) => sameId(x.id, id));
  return f ? f.id : null;
}

async function adminStatusById(adminId, db) {
  const conn = db || pool;
  if (!adminId) return 'Enabled';
  const [rows] = await conn.query('SELECT status FROM admins WHERE id=?', [adminId]);
  if (rows[0] && rows[0].status) return rows[0].status;
  const [all] = await conn.query('SELECT id, status FROM admins');
  const m = all.find((x) => sameId(x.id, adminId));
  if (m) return m.status || 'Enabled';
  // The Organizer deleted this Admin. Its employees/records are kept for
  // audit, but login/punch must stay blocked (matches the Organizer UI text).
  return 'Disabled';
}

// ---------------- Schema self-heal ----------------
// Upgrades older databases to the current hierarchy without a re-import.
// Every statement is safe to run on every boot. CREATE IF NOT EXISTS is a
// no-op when db.sql was imported; the ALTERs below patch older layouts.
async function ensureSchema() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS admins (
      id VARCHAR(50) NOT NULL PRIMARY KEY, name VARCHAR(100) NOT NULL DEFAULT '',
      company VARCHAR(150) NOT NULL DEFAULT '',
      pass VARCHAR(255) NOT NULL, mob VARCHAR(15) NOT NULL DEFAULT '',
      movie VARCHAR(100) NOT NULL DEFAULT '', birth VARCHAR(100) NOT NULL DEFAULT '',
      school VARCHAR(150) NOT NULL DEFAULT '', photo LONGTEXT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'Enabled',
      mustChangePass TINYINT(1) NOT NULL DEFAULT 0,
      created DATE NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  } catch (e) {}
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS employees (
      id VARCHAR(50) NOT NULL PRIMARY KEY, name VARCHAR(100) NOT NULL,
      pass VARCHAR(255) NOT NULL, desg VARCHAR(100) NOT NULL DEFAULT '',
      mob VARCHAR(15) NOT NULL DEFAULT '', photo LONGTEXT NULL,
      store VARCHAR(150) NOT NULL DEFAULT '', storeArea VARCHAR(150) NOT NULL DEFAULT '',
      storeLat DOUBLE NULL, storeLon DOUBLE NULL, storeLink TEXT NULL,
      created DATE NULL, mustChangePass TINYINT(1) NOT NULL DEFAULT 1,
      adminId VARCHAR(50) NOT NULL DEFAULT '', status VARCHAR(20) NOT NULL DEFAULT 'Enabled',
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_emp_admin (adminId)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  } catch (e) {}
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS records (
      empId VARCHAR(50) NOT NULL, \`date\` DATE NOT NULL,
      name VARCHAR(100) NOT NULL DEFAULT '', store VARCHAR(150) NOT NULL DEFAULT '',
      storeArea VARCHAR(150) NOT NULL DEFAULT '', storeLink TEXT NULL,
      type VARCHAR(20) NOT NULL DEFAULT 'Duty',
      inTime VARCHAR(30) NOT NULL DEFAULT '', inPhoto LONGTEXT NULL,
      inLat VARCHAR(30) NOT NULL DEFAULT '', inLon VARCHAR(30) NOT NULL DEFAULT '',
      inLocLink TEXT NULL, inDistM INT NULL,
      outTime VARCHAR(30) NOT NULL DEFAULT '', outPhoto LONGTEXT NULL,
      outLat VARCHAR(30) NOT NULL DEFAULT '', outLon VARCHAR(30) NOT NULL DEFAULT '',
      outLocLink TEXT NULL, outDistM INT NULL,
      adminId VARCHAR(50) NOT NULL DEFAULT '',
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (empId, \`date\`), INDEX idx_rec_admin (adminId)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  } catch (e) {}
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS leaves (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, empId VARCHAR(50) NOT NULL,
      name VARCHAR(100) NOT NULL DEFAULT '', leave_date DATE NOT NULL,
      reason VARCHAR(255) NOT NULL DEFAULT '', status VARCHAR(20) NOT NULL DEFAULT 'Pending',
      adminId VARCHAR(50) NOT NULL DEFAULT '',
      decided_by VARCHAR(50) NOT NULL DEFAULT '', decided_at TIMESTAMP NULL DEFAULT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uq_leave_emp_date (empId, leave_date),
      INDEX idx_leave_date (leave_date), INDEX idx_leave_emp (empId),
      INDEX idx_leave_status (status), INDEX idx_leave_admin (adminId)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  } catch (e) {}
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS organizers (
      id VARCHAR(50) NOT NULL PRIMARY KEY, pass VARCHAR(255) NOT NULL,
      mob VARCHAR(15) NOT NULL DEFAULT '', movie VARCHAR(100) NOT NULL DEFAULT '',
      birth VARCHAR(100) NOT NULL DEFAULT '', school VARCHAR(150) NOT NULL DEFAULT '',
      photo LONGTEXT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  } catch (e) {}
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS auth_tokens (
      tokenHash CHAR(64) NOT NULL PRIMARY KEY,
      role VARCHAR(20) NOT NULL,
      subjectId VARCHAR(50) NOT NULL,
      expiresAt DATETIME NOT NULL,
      createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_token_subject (role, subjectId),
      INDEX idx_token_expiry (expiresAt)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  } catch (e) {}
  // Patch older table layouts (missing columns in pre-hierarchy installs).
  try { await pool.query(`ALTER TABLE admins ADD COLUMN name VARCHAR(100) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE admins ADD COLUMN company VARCHAR(150) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE admins ADD COLUMN mustChangePass TINYINT(1) NOT NULL DEFAULT 0`); } catch (e) {}
  try { await pool.query(`ALTER TABLE admins ADD COLUMN mob VARCHAR(15) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE admins ADD COLUMN movie VARCHAR(100) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE admins ADD COLUMN birth VARCHAR(100) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE admins ADD COLUMN school VARCHAR(150) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE admins ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'Enabled'`); } catch (e) {}
  try { await pool.query(`ALTER TABLE admins ADD COLUMN created DATE NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE admins ADD COLUMN photo LONGTEXT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE admins ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`); } catch (e) {}
  try { await pool.query(`ALTER TABLE admins ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN desg VARCHAR(100) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN mob VARCHAR(15) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN photo LONGTEXT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN store VARCHAR(150) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN storeArea VARCHAR(150) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN storeLat DOUBLE NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN storeLon DOUBLE NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN storeLink TEXT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN adminId VARCHAR(50) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD INDEX idx_emp_admin (adminId)`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'Enabled'`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN created DATE NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN mustChangePass TINYINT(1) NOT NULL DEFAULT 1`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN name VARCHAR(100) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN store VARCHAR(150) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN storeArea VARCHAR(150) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN storeLink TEXT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN type VARCHAR(20) NOT NULL DEFAULT 'Duty'`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN inTime VARCHAR(30) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN inPhoto LONGTEXT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN inLat VARCHAR(30) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN inLon VARCHAR(30) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN inLocLink TEXT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN inDistM INT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN outTime VARCHAR(30) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN outPhoto LONGTEXT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN outLat VARCHAR(30) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN outLon VARCHAR(30) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN outLocLink TEXT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN outDistM INT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN adminId VARCHAR(50) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD INDEX idx_rec_admin (adminId)`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`); } catch (e) {}
  try { await pool.query(`ALTER TABLE records ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP`); } catch (e) {}
  try { await pool.query(`ALTER TABLE organizers ADD COLUMN mob VARCHAR(15) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE organizers ADD COLUMN movie VARCHAR(100) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE organizers ADD COLUMN birth VARCHAR(100) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE organizers ADD COLUMN school VARCHAR(150) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE organizers ADD COLUMN photo LONGTEXT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE leaves ADD COLUMN adminId VARCHAR(50) NOT NULL DEFAULT ''`); } catch (e) {}
  try { await pool.query(`ALTER TABLE leaves ADD INDEX idx_leave_admin (adminId)`); } catch (e) {}
  try { await pool.query(`ALTER TABLE leaves ADD INDEX idx_leave_status (status)`); } catch (e) {}
  // Widen legacy VARCHAR(100) password columns for scrypt hashes.
  try { await pool.query(`ALTER TABLE admins MODIFY pass VARCHAR(255) NOT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE employees MODIFY pass VARCHAR(255) NOT NULL`); } catch (e) {}
  try { await pool.query(`ALTER TABLE organizers MODIFY pass VARCHAR(255) NOT NULL`); } catch (e) {}
  try {
    // Backfill the owner snapshot for leaves created before adminId existed.
    await pool.query(`UPDATE leaves l JOIN employees e ON e.id=l.empId
      SET l.adminId=e.adminId, l.name=IF(l.name='',e.name,l.name)
      WHERE l.adminId=''`);
  } catch (e) {}
  // Seed only the organizer account. Admin accounts are never seeded: the
  // organizer is the single source of truth and must create every admin ID.
  // This also guarantees a deleted admin can never come back after a restart.
  try {
    const [o] = await pool.query('SELECT COUNT(*) AS n FROM organizers');
    if (!Number((o[0] || {}).n)) {
      await pool.query(
        'INSERT INTO organizers (id, pass, mob, movie, birth, school) VALUES (?,?,?,?,?,?)',
        ['organizer', hashPassword('Organizer@124'), '', '', '', '']
      );
    }
  } catch (e) {}
  // Remove the retired built-in admin account from databases created by older
  // versions. Only the exact legacy default (blank or Admin@124 password) is
  // deleted, so an organizer-created admin that happens to use the ID "admin"
  // with a different password is left alone.
  try {
    const [legacy] = await pool.query("SELECT id, pass FROM admins WHERE LOWER(id)=LOWER('admin')");
    for (const row of legacy) {
      if (!row.pass || verifyPassword('Admin@124', row.pass)) {
        await pool.query('DELETE FROM admins WHERE id=?', [row.id]);
        await revokeAdminAndEmployees(row.id).catch(() => {});
      }
    }
  } catch (e) {}
  // Migrate pre-hierarchy rows: when exactly one Admin exists, employees
  // without an owner are attached to it so they stay visible in cloud mode.
  try {
    const [adm] = await pool.query('SELECT COUNT(*) AS n FROM admins');
    if (Number((adm[0] || {}).n) === 1) {
      const [one] = await pool.query('SELECT id FROM admins LIMIT 1');
      const owner = one[0] && one[0].id;
      if (owner) {
        await pool.query("UPDATE employees SET adminId=? WHERE adminId IS NULL OR adminId=''", [owner]);
        await pool.query("UPDATE leaves l JOIN employees e ON e.id=l.empId SET l.adminId=e.adminId, l.name=IF(l.name='',e.name,l.name) WHERE l.adminId IS NULL OR l.adminId=''");
      }
    }
  } catch (e) {}
}

// Hash any legacy plaintext rows left in an imported db.sql. Runs in the
// background after boot; each UPDATE is conditional on the old value so a
// concurrent password change is never overwritten.
async function upgradeLegacyPasswords() {
  for (const table of ['organizers', 'admins', 'employees']) {
    let rows = [];
    try {
      const [r] = await pool.query(`SELECT id, pass FROM ${table}`);
      rows = r;
    } catch (e) {
      continue;
    }
    for (const row of rows) {
      if (!row.pass || isHashedPassword(row.pass)) continue;
      try {
        await pool.query(
          `UPDATE ${table} SET pass=? WHERE id=? AND pass=?`,
          [hashPassword(row.pass), row.id, row.pass]
        );
      } catch (e) {}
    }
  }
}

async function cleanupExpiredTokens() {
  try { await pool.query('DELETE FROM auth_tokens WHERE expiresAt <= NOW()'); } catch (e) {}
}

// ---------------- Health ----------------
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'db-unavailable' });
  }
});

// ---------------- ORGANIZER (single row, top level) ----------------
app.get('/api/organizer', authenticate, roleOnly('organizer'), async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM organizers LIMIT 1');
  res.json({ ok: true, organizer: safeOrganizer(rows[0] || null) });
});

app.post('/api/organizer/login', rateLimit('org-login', 20, 15 * 60 * 1000), async (req, res) => {
  const { id, pass } = req.body || {};
  const [rows] = await pool.query('SELECT * FROM organizers LIMIT 1');
  const og = rows[0];
  if (!og) return res.json({ ok: false, error: 'wrong' });
  if (!sameId(id, og.id) || !verifyPassword(pass, og.pass)) {
    return res.json({ ok: false, error: 'wrong' });
  }
  await upgradePasswordIfLegacy('organizers', og.id, pass, og.pass);
  const session = await issueToken('organizer', og.id, TTL_ORGANIZER);
  res.json({ ok: true, organizer: safeOrganizer(og), token: session.token, expiresIn: session.expiresIn });
});

app.put('/api/organizer', authenticate, roleOnly('organizer'), async (req, res) => {
  const a = req.body || {};
  const newId = cleanId(a.id) || req.auth.id;
  const [curRows] = await pool.query('SELECT * FROM organizers LIMIT 1');
  const cur = curRows[0];
  if (!cur) return res.json({ ok: false, error: 'no-organizer' });
  let passToStore = null;
  if (a.pass != null && String(a.pass) !== '') {
    if (!a.currentPass || !verifyPassword(a.currentPass, cur.pass)) {
      return res.json({ ok: false, error: 'wrong-current-password' });
    }
    const pe = passwordError(a.pass);
    if (pe) return res.json({ ok: false, error: pe });
    passToStore = hashPassword(a.pass);
  }
  await pool.query(
    "INSERT INTO organizers (id,pass,mob,movie,birth,school,photo) VALUES (?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE pass=VALUES(pass),mob=VALUES(mob),movie=VALUES(movie),birth=VALUES(birth),school=VALUES(school),photo=COALESCE(NULLIF(VALUES(photo),''),photo)",
    [newId, passToStore || cur.pass, a.mob || '', a.movie || '', a.birth || '', a.school || '', a.photo ?? null]
  );
  if (newId !== cur.id) await pool.query('DELETE FROM organizers WHERE id<>?', [newId]); // keep it single-row
  else await pool.query('DELETE FROM organizers WHERE id<>?', [cur.id]);
  if (newId !== cur.id) await moveTokens(pool, 'organizer', cur.id, newId);
  const [rows] = await pool.query('SELECT * FROM organizers LIMIT 1');
  res.json({ ok: true, organizer: safeOrganizer(rows[0] || null) });
});

app.post('/api/organizer/forgot', rateLimit('org-forgot', 10, 15 * 60 * 1000), async (req, res) => {
  const { id, mob, movie, birth, school, newPass } = req.body || {};
  const pe = passwordError(newPass);
  if (pe) return res.json({ ok: false, error: pe });
  const [rows] = await pool.query('SELECT * FROM organizers LIMIT 1');
  const og = rows[0];
  if (!og) return res.json({ ok: false, error: 'answers' });
  const ok =
    sameId(id, og.id) &&
    !!og.mob && !!og.movie && !!og.birth && !!og.school &&
    String(mob || '') === String(og.mob || '') &&
    String(movie || '').trim().toLowerCase() === String(og.movie || '').toLowerCase() &&
    String(birth || '').trim().toLowerCase() === String(og.birth || '').toLowerCase() &&
    String(school || '').trim().toLowerCase() === String(og.school || '').toLowerCase();
  if (!ok) return res.json({ ok: false, error: 'answers' });
  await pool.query('UPDATE organizers SET pass=? WHERE id=?', [hashPassword(newPass), og.id]);
  await revokeTokens('organizer', og.id);
  res.json({ ok: true });
});

// ---------------- ADMINS (multiple rows, Organizer-managed) ----------------
app.get('/api/admins', authenticate, roleOnly('organizer'), async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM admins ORDER BY created_at ASC');
  res.json({ ok: true, admins: rows.map(safeAdmin) });
});

app.post('/api/admins', authenticate, roleOnly('organizer'), async (req, res) => {
  const x = req.body || {};
  const id = cleanId(x.id);
  const company = txt(x.company).slice(0, 150);
  if (!id || !x.pass) return res.json({ ok: false, error: 'id-pass-required' });
  if (!company) return res.json({ ok: false, error: 'company-required' });
  const pe = passwordError(x.pass);
  if (pe) return res.json({ ok: false, error: pe });
  try {
    await pool.query(
      'INSERT INTO admins (id,name,company,pass,mob,movie,birth,school,photo,status,mustChangePass,created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
      [id, x.name || '', company, hashPassword(x.pass), x.mob || '', x.movie || '', x.birth || '', x.school || '', x.photo ?? null, 'Enabled', 1, x.created || todayD()]
    );
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: 'duplicate' });
  }
});

app.post('/api/admins/:id/enable', authenticate, roleOnly('organizer'), async (req, res) => {
  await pool.query('UPDATE admins SET status=? WHERE id=?', ['Enabled', req.params.id]);
  res.json({ ok: true });
});

app.post('/api/admins/:id/disable', authenticate, roleOnly('organizer'), async (req, res) => {
  const real = await resolveAdminId(pool, req.params.id);
  await pool.query('UPDATE admins SET status=? WHERE id=?', ['Disabled', real || req.params.id]);
  if (real) await revokeAdminAndEmployees(real);
  res.json({ ok: true });
});

// Edit an admin (name, ID, password, mobile). Renaming the ID cascades
// to employees.adminId and records.adminId in one transaction, so linked
// employees and attendance stay with the new Admin ID.
app.put('/api/admins/:id', authenticate, roleOnly('organizer'), async (req, res) => {
  const oldId = String(req.params.id || '');
  const b = req.body || {};
  const newId = cleanId(b.newId || b.id || oldId);
  if (!oldId || !newId) return res.json({ ok: false, error: 'ids-required' });
  let passHash = null;
  if (b.pass != null && String(b.pass) !== '') {
    const pe = passwordError(b.pass);
    if (pe) return res.json({ ok: false, error: pe });
    passHash = hashPassword(b.pass);
  }
  let company = null;
  if (b.company !== undefined) {
    company = txt(b.company).slice(0, 150);
    if (!company) return res.json({ ok: false, error: 'company-required' });
  }
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const realOld = await resolveAdminId(conn, oldId);
    if (!realOld) {
      await conn.rollback();
      return res.json({ ok: false, error: 'not-found' });
    }
    if (!sameId(newId, realOld)) {
      const [dup] = await conn.query('SELECT id FROM admins WHERE id=?', [newId]);
      if (dup.length) {
        await conn.rollback();
        return res.json({ ok: false, error: 'duplicate' });
      }
    }
    await conn.query(
      "UPDATE admins SET id=?, name=COALESCE(?,name), company=COALESCE(?,company), pass=COALESCE(?,pass), mob=COALESCE(?,mob), photo=COALESCE(NULLIF(?, ''), photo) WHERE id=?",
      [newId, b.name ?? null, company, passHash, b.mob ?? null, b.photo ?? null, realOld]
    );
    if (newId !== realOld) {
      await conn.query('UPDATE employees SET adminId=? WHERE adminId=?', [newId, realOld]);
      try { await conn.query('UPDATE employees SET adminId=? WHERE LOWER(adminId)=LOWER(?)', [newId, realOld]); } catch (e) {}
      try { await conn.query('UPDATE records SET adminId=? WHERE adminId=?', [newId, realOld]); } catch (e) {}
      try { await conn.query('UPDATE records SET adminId=? WHERE LOWER(adminId)=LOWER(?)', [newId, realOld]); } catch (e) {}
      try { await conn.query('UPDATE leaves SET adminId=? WHERE adminId=?', [newId, realOld]); } catch (e) {}
      try { await conn.query('UPDATE leaves SET adminId=? WHERE LOWER(adminId)=LOWER(?)', [newId, realOld]); } catch (e) {}
      await moveTokens(conn, 'admin', realOld, newId);
    }
    await conn.commit();
    res.json({ ok: true, renamed: newId !== realOld });
  } catch (e) {
    try { await conn.rollback(); } catch (_) {}
    res.json({ ok: false, error: 'db-error' });
  } finally {
    conn.release();
  }
});

app.delete('/api/admins/:id', authenticate, roleOnly('organizer'), async (req, res) => {
  const wanted = txt(req.params.id);
  if (!wanted) return res.json({ ok: false, error: 'id-required' });
  const real = await resolveAdminId(pool, wanted);
  const target = real || wanted;
  // Delete the account row first, then revoke every session belonging to it
  // and to its employees. The organizer is the only authority here, so a
  // deleted ID must stop working immediately AND stay deleted (no seed).
  const [result] = await pool.query('DELETE FROM admins WHERE LOWER(id)=LOWER(?)', [target]);
  await revokeAdminAndEmployees(target).catch(() => {});
  // Employees/records/leaves deliberately stay for audit, but their owner
  // adminId still points at the deleted ID, so both accountIsActive() and
  // employee login keep them blocked.
  res.json({ ok: true, deleted: result.affectedRows > 0 });
});

// ---------------- ADMIN self profile ----------------
app.get('/api/admin', authenticate, roleOnly('admin'), async (req, res) => {
  const real = await resolveAdminId(pool, req.auth.id);
  if (!real) return res.status(404).json({ ok: false, error: 'not-found' });
  const [rows] = await pool.query('SELECT * FROM admins WHERE id=?', [real]);
  res.json({ ok: true, admin: safeAdmin(rows[0] || null) });
});

app.put('/api/admin', authenticate, roleOnly('admin'), async (req, res) => {
  const b = req.body || {};
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const realOld = await resolveAdminId(conn, req.auth.id);
    if (!realOld) {
      await conn.rollback();
      return res.status(404).json({ ok: false, error: 'not-found' });
    }
    const [rows] = await conn.query('SELECT * FROM admins WHERE id=?', [realOld]);
    const cur = rows[0];
    const newId = cleanId(b.newId || b.id || realOld) || realOld;
    if (b.company !== undefined && !txt(b.company)) {
      await conn.rollback();
      return res.json({ ok: false, error: 'company-required' });
    }
    const company = b.company === undefined ? null : txt(b.company).slice(0, 150);
    let passHash = null;
    if (b.pass != null && String(b.pass) !== '') {
      if (!b.currentPass || !verifyPassword(b.currentPass, cur.pass)) {
        await conn.rollback();
        return res.json({ ok: false, error: 'wrong-current-password' });
      }
      const pe = passwordError(b.pass);
      if (pe) {
        await conn.rollback();
        return res.json({ ok: false, error: pe });
      }
      passHash = hashPassword(b.pass);
    }
    if (!sameId(newId, realOld)) {
      const [dup] = await conn.query('SELECT id FROM admins WHERE id=?', [newId]);
      if (dup.length) {
        await conn.rollback();
        return res.json({ ok: false, error: 'duplicate' });
      }
    }
    await conn.query(
      "UPDATE admins SET id=?, name=COALESCE(?,name), company=COALESCE(?,company), pass=COALESCE(?,pass), mob=COALESCE(?,mob), movie=COALESCE(?,movie), birth=COALESCE(?,birth), school=COALESCE(?,school), photo=COALESCE(NULLIF(?, ''), photo) WHERE id=?",
      [newId, b.name ?? null, company, passHash, b.mob ?? null, b.movie ?? null, b.birth ?? null, b.school ?? null, b.photo ?? null, realOld]
    );
    if (!sameId(newId, realOld)) {
      await conn.query('UPDATE employees SET adminId=? WHERE adminId=?', [newId, realOld]);
      try { await conn.query('UPDATE employees SET adminId=? WHERE LOWER(adminId)=LOWER(?)', [newId, realOld]); } catch (e) {}
      try { await conn.query('UPDATE records SET adminId=? WHERE adminId=?', [newId, realOld]); } catch (e) {}
      try { await conn.query('UPDATE records SET adminId=? WHERE LOWER(adminId)=LOWER(?)', [newId, realOld]); } catch (e) {}
      try { await conn.query('UPDATE leaves SET adminId=? WHERE adminId=?', [newId, realOld]); } catch (e) {}
      try { await conn.query('UPDATE leaves SET adminId=? WHERE LOWER(adminId)=LOWER(?)', [newId, realOld]); } catch (e) {}
      await moveTokens(conn, 'admin', realOld, newId);
      req.auth.id = newId;
    }
    if (passHash) await revokeTokens('admin', newId, req.auth.tokenHash);
    await conn.commit();
    const [out] = await pool.query('SELECT * FROM admins WHERE id=?', [newId]);
    res.json({ ok: true, admin: safeAdmin(out[0] || null), renamed: !sameId(newId, realOld) });
  } catch (e) {
    try { await conn.rollback(); } catch (_) {}
    res.json({ ok: false, error: 'db-error' });
  } finally {
    conn.release();
  }
});

app.post('/api/admin/login', rateLimit('admin-login', 20, 15 * 60 * 1000), async (req, res) => {
  const { id, pass } = req.body || {};
  const [rows] = await pool.query('SELECT * FROM admins');
  let ad = rows.find((x) => sameId(id, x.id));
  if (!ad || !verifyPassword(pass, ad.pass)) return res.json({ ok: false, error: 'wrong' });
  ad = normAdminRow(ad);
  if (String(ad.status || 'Enabled') === 'Disabled') return res.json({ ok: false, error: 'disabled' });
  await upgradePasswordIfLegacy('admins', ad.id, pass, ad.pass);
  const session = await issueToken('admin', ad.id, TTL_ADMIN);
  return res.json({ ok: true, admin: safeAdmin(ad), token: session.token, expiresIn: session.expiresIn });
});

app.post('/api/admin/forgot', rateLimit('admin-forgot', 10, 15 * 60 * 1000), async (req, res) => {
  const { id, mob, movie, birth, school, newPass } = req.body || {};
  const pe = passwordError(newPass);
  if (pe) return res.json({ ok: false, error: pe });
  const [rows] = await pool.query('SELECT * FROM admins');
  const ad = rows.find((x) => sameId(x.id, id)) || null;
  const ok = !!ad &&
    !!ad.mob && !!ad.movie && !!ad.birth && !!ad.school &&
    String(mob || '') === String(ad.mob || '') &&
    String(movie || '').trim().toLowerCase() === String(ad.movie || '').toLowerCase() &&
    String(birth || '').trim().toLowerCase() === String(ad.birth || '').toLowerCase() &&
    String(school || '').trim().toLowerCase() === String(ad.school || '').toLowerCase();
  if (!ok) return res.json({ ok: false, error: 'answers' });
  await pool.query('UPDATE admins SET pass=? WHERE id=?', [hashPassword(newPass), ad.id]);
  await revokeTokens('admin', ad.id);
  res.json({ ok: true });
});

// ---------------- AUTH: current user / logout / password ----------------
app.get('/api/me', authenticate, async (req, res) => {
  const role = req.auth.role;
  if (role === 'organizer') {
    const [rows] = await pool.query('SELECT * FROM organizers LIMIT 1');
    return res.json({ ok: true, role, organizer: safeOrganizer(rows[0] || null) });
  }
  if (role === 'admin') {
    const real = await resolveAdminId(pool, req.auth.id);
    const [rows] = real ? await pool.query('SELECT * FROM admins WHERE id=?', [real]) : [[]];
    return res.json({ ok: true, role, admin: safeAdmin(rows[0] || null) });
  }
  const [rows] = await pool.query('SELECT * FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1', [req.auth.id]);
  return res.json({ ok: true, role, emp: safeEmp(rows[0] || null) });
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  await pool.query('DELETE FROM auth_tokens WHERE tokenHash=?', [req.auth.tokenHash]);
  res.json({ ok: true });
});

app.put('/api/me/password', authenticate, async (req, res) => {
  const b = req.body || {};
  const role = req.auth.role;
  const pe = passwordError(b.newPass);
  if (pe) return res.json({ ok: false, error: pe });
  const table = role === 'organizer' ? 'organizers' : role === 'admin' ? 'admins' : 'employees';
  let row;
  if (role === 'organizer') {
    const [rows] = await pool.query('SELECT * FROM organizers LIMIT 1');
    row = rows[0];
  } else if (role === 'admin') {
    const real = await resolveAdminId(pool, req.auth.id);
    const [rows] = real ? await pool.query('SELECT * FROM admins WHERE id=?', [real]) : [[]];
    row = rows[0];
  } else {
    const [rows] = await pool.query('SELECT * FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1', [req.auth.id]);
    row = rows[0];
  }
  if (!row) return res.status(404).json({ ok: false, error: 'not-found' });
  // A first-login employee or admin may set a new password without proving the
  // preset one again (the bearer token itself was issued by a successful login).
  const allowWithoutCurrent = (role === 'employee' || role === 'admin') && !!row.mustChangePass;
  if (!allowWithoutCurrent && !verifyPassword(b.currentPass, row.pass)) {
    return res.json({ ok: false, error: 'wrong-current-password' });
  }
  await pool.query(
    role === 'employee'
      ? 'UPDATE employees SET pass=?, mustChangePass=0 WHERE id=?'
      : role === 'admin'
        ? 'UPDATE admins SET pass=?, mustChangePass=0 WHERE id=?'
        : `UPDATE ${table} SET pass=? WHERE id=?`,
    [hashPassword(b.newPass), row.id]
  );
  // Keep the current session, revoke every other session for this account.
  await revokeTokens(role, row.id, req.auth.tokenHash);
  res.json({ ok: true });
});

app.put('/api/me', authenticate, async (req, res) => {
  const b = req.body || {};
  const role = req.auth.role;
  if (role === 'employee') {
    // Employees may only refresh their own photo. All other profile fields
    // are Admin-controlled.
    if (b.photo === undefined) return res.json({ ok: false, error: 'nothing-to-update' });
    await pool.query('UPDATE employees SET photo=? WHERE LOWER(id)=LOWER(?)', [String(b.photo || '').slice(0, 10 * 1024 * 1024), req.auth.id]);
    return res.json({ ok: true });
  }
  if (role === 'admin') {
    const real = await resolveAdminId(pool, req.auth.id);
    if (!real) return res.status(404).json({ ok: false, error: 'not-found' });
    if (b.company !== undefined && !txt(b.company)) {
      return res.json({ ok: false, error: 'company-required' });
    }
    const company = b.company === undefined ? null : txt(b.company).slice(0, 150);
    await pool.query(
      "UPDATE admins SET name=COALESCE(?,name), company=COALESCE(?,company), mob=COALESCE(?,mob), movie=COALESCE(?,movie), birth=COALESCE(?,birth), school=COALESCE(?,school), photo=COALESCE(NULLIF(?, ''), photo) WHERE id=?",
      [b.name ?? null, company, b.mob ?? null, b.movie ?? null, b.birth ?? null, b.school ?? null, b.photo ?? null, real]
    );
    const [rows] = await pool.query('SELECT * FROM admins WHERE id=?', [real]);
    return res.json({ ok: true, admin: safeAdmin(rows[0] || null) });
  }
  await pool.query(
    "UPDATE organizers SET mob=COALESCE(?,mob), movie=COALESCE(?,movie), birth=COALESCE(?,birth), school=COALESCE(?,school), photo=COALESCE(NULLIF(?, ''), photo) LIMIT 1",
    [b.mob ?? null, b.movie ?? null, b.birth ?? null, b.school ?? null, b.photo ?? null]
  );
  const [rows] = await pool.query('SELECT * FROM organizers LIMIT 1');
  return res.json({ ok: true, organizer: safeOrganizer(rows[0] || null) });
});

// ---------------- LEAVES (employee applies, Admin decides) ----------------
const LEAVE_SELECT = `SELECT l.id, l.empId,
  COALESCE(NULLIF(l.name,''), e.name, '') AS name,
  DATE_FORMAT(l.leave_date,'%Y-%m-%d') AS leave_date,
  l.reason, l.status,
  COALESCE(NULLIF(l.adminId,''), e.adminId, '') AS adminId,
  l.decided_by, l.decided_at, l.created_at, l.updated_at
  FROM leaves l LEFT JOIN employees e ON e.id=l.empId`;

async function fetchLeaveById(id, db) {
  const conn = db || pool;
  const [rows] = await conn.query(LEAVE_SELECT + ' WHERE l.id=?', [id]);
  return rows[0] || null;
}

async function fetchLeavesForDates(conn, empId, dates) {
  if (!dates.length) return [];
  const [rows] = await conn.query(
    LEAVE_SELECT + ` WHERE l.empId=? AND l.leave_date IN (${dates.map(() => '?').join(',')}) ORDER BY l.leave_date ASC`,
    [empId, ...dates]
  );
  return rows;
}

function leaveVisibleTo(role, id, leave) {
  if (!leave) return false;
  if (role === 'employee') return sameId(leave.empId, id);
  if (role === 'admin') return sameId(leave.adminId, id);
  return false; // organizer never sees employee details
}

// Month/employee/admin summary (mirrors v_leave_summary in db.sql).
app.get('/api/leaves/summary', authenticate, async (req, res) => {
  if (req.auth.role === 'organizer') return res.status(403).json({ ok: false, error: 'forbidden' });
  const month = txt(req.query.month);
  const empId = txt(req.query.empId);
  if (month && !/^\d{4}-\d{2}$/.test(month)) return res.json({ ok: false, error: 'month-invalid' });
  const where = [];
  const params = [];
  if (req.auth.role === 'employee') { where.push('LOWER(l.empId)=LOWER(?)'); params.push(req.auth.id); }
  else { where.push("COALESCE(NULLIF(l.adminId,''), e.adminId, '')=?"); params.push(req.auth.id); }
  if (month) { where.push("DATE_FORMAT(l.leave_date,'%Y-%m')=?"); params.push(month); }
  if (empId && req.auth.role === 'admin') { where.push('LOWER(l.empId)=LOWER(?)'); params.push(empId); }
  const [rows] = await pool.query(
    `SELECT DATE_FORMAT(l.leave_date,'%Y-%m') AS ym, l.empId,
       COALESCE(NULLIF(l.adminId,''), e.adminId, '') AS adminId,
       COALESCE(MAX(NULLIF(l.name,'')), MAX(e.name), '') AS name,
       COUNT(CASE WHEN l.status='Approved' THEN 1 END) AS approved,
       COUNT(CASE WHEN l.status='Pending' THEN 1 END) AS pending,
       COUNT(CASE WHEN l.status='Rejected' THEN 1 END) AS rejected,
       COUNT(*) AS total
     FROM leaves l LEFT JOIN employees e ON e.id=l.empId
     WHERE ${where.join(' AND ')}
     GROUP BY ym, l.empId, COALESCE(NULLIF(l.adminId,''), e.adminId, '')
     ORDER BY ym DESC, name ASC`,
    params
  );
  res.json({ ok: true, summary: rows });
});

app.get('/api/leaves', authenticate, async (req, res) => {
  if (req.auth.role === 'organizer') return res.status(403).json({ ok: false, error: 'forbidden' });
  const empId = txt(req.query.empId);
  const status = txt(req.query.status);
  const month = txt(req.query.month);
  const from = txt(req.query.from);
  const to = txt(req.query.to);
  if (status && !leaveStatus(status)) return res.json({ ok: false, error: 'status-invalid' });
  if (month && !/^\d{4}-\d{2}$/.test(month)) return res.json({ ok: false, error: 'month-invalid' });
  if (from && !isDateStr(from)) return res.json({ ok: false, error: 'from-invalid' });
  if (to && !isDateStr(to)) return res.json({ ok: false, error: 'to-invalid' });
  const where = [];
  const params = [];
  if (req.auth.role === 'employee') {
    where.push('LOWER(l.empId)=LOWER(?)');
    params.push(req.auth.id);
  } else {
    where.push("COALESCE(NULLIF(l.adminId,''), e.adminId, '')=?");
    params.push(req.auth.id);
    if (empId) { where.push('LOWER(l.empId)=LOWER(?)'); params.push(empId); }
  }
  if (status) { where.push('l.status=?'); params.push(status); }
  if (month) { where.push("DATE_FORMAT(l.leave_date,'%Y-%m')=?"); params.push(month); }
  if (from) { where.push('l.leave_date>=?'); params.push(from); }
  if (to) { where.push('l.leave_date<=?'); params.push(to); }
  const [rows] = await pool.query(
    LEAVE_SELECT + ' WHERE ' + where.join(' AND ') + ' ORDER BY l.leave_date DESC, l.id DESC',
    params
  );
  res.json({ ok: true, leaves: rows });
});

app.get('/api/leaves/:id', authenticate, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.json({ ok: false, error: 'id-invalid' });
  const leave = await fetchLeaveById(id);
  if (!leave || !leaveVisibleTo(req.auth.role, req.auth.id, leave)) {
    return res.json({ ok: false, error: 'not-found' });
  }
  res.json({ ok: true, leave });
});

// Apply for one or more days. Multi-day leave = one row per day
// (UNIQUE empId+leave_date); re-applying after Rejected resets it to Pending.
app.post('/api/leaves', authenticate, async (req, res) => {
  if (req.auth.role === 'organizer') return res.status(403).json({ ok: false, error: 'forbidden' });
  const x = req.body || {};
  const empId = req.auth.role === 'employee' ? req.auth.id : txt(x.empId);
  if (!empId) return res.json({ ok: false, error: 'empId-required' });
  const rawDates = Array.isArray(x.dates) && x.dates.length ? x.dates : [x.date ?? x.leave_date];
  if (rawDates.length > 62) return res.json({ ok: false, error: 'too-many-dates' });
  const dates = [];
  for (const raw of rawDates) {
    const d = dateOnly(raw);
    if (!isDateStr(d)) return res.json({ ok: false, error: 'date-invalid' });
    if (!dates.includes(d)) dates.push(d);
  }
  if (!dates.length) return res.json({ ok: false, error: 'date-required' });
  const reason = txt(x.reason).slice(0, 255);
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    let emp = null;
    const [rows] = await conn.query('SELECT id,name,adminId,status FROM employees WHERE id=?', [empId]);
    emp = rows[0] || null;
    if (!emp) {
      const real = await resolveEmployeeId(conn, empId);
      if (real) {
        const [r2] = await conn.query('SELECT id,name,adminId,status FROM employees WHERE id=?', [real]);
        emp = r2[0] || null;
      }
    }
    if (!emp) {
      await conn.rollback();
      return res.json({ ok: false, error: 'no-employee' });
    }
    if (String(emp.status || 'Enabled') === 'Disabled') {
      await conn.rollback();
      return res.json({ ok: false, error: 'employee-disabled' });
    }
    const owner = String(emp.adminId || '');
    if (req.auth.role === 'admin' && owner && !sameId(req.auth.id, owner)) {
      await conn.rollback();
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    if (owner && String(await adminStatusById(owner, conn)) === 'Disabled') {
      await conn.rollback();
      return res.json({ ok: false, error: 'admin-disabled' });
    }
    for (const d of dates) {
      await conn.query(
        `INSERT INTO leaves (empId,name,leave_date,reason,status,adminId)
         VALUES (?,?,?,?,'Pending',?)
         ON DUPLICATE KEY UPDATE
           name=VALUES(name),
           reason=VALUES(reason),
           adminId=VALUES(adminId),
           decided_by=IF(status='Approved',decided_by,''),
           decided_at=IF(status='Approved',decided_at,NULL),
           status=IF(status='Approved','Approved','Pending')`,
        [emp.id, emp.name || '', d, reason, owner]
      );
    }
    const leaves = await fetchLeavesForDates(conn, emp.id, dates);
    await conn.commit();
    res.json({ ok: true, leaves });
  } catch (e) {
    try { await conn.rollback(); } catch (_) {}
    res.json({ ok: false, error: 'db-error' });
  } finally {
    conn.release();
  }
});

// Admin decision: Approved / Rejected (PUT with status=Pending resets it).
async function leaveDecision(req, res, forcedStatus) {
  if (req.auth.role !== 'admin') return res.status(403).json({ ok: false, error: 'forbidden' });
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.json({ ok: false, error: 'id-invalid' });
  const b = req.body || {};
  const status = forcedStatus || leaveStatus(b.status);
  if (!status) return res.json({ ok: false, error: 'status-invalid' });
  const leave = await fetchLeaveById(id);
  if (!leave || !leaveVisibleTo('admin', req.auth.id, leave)) {
    return res.json({ ok: false, error: 'not-found' });
  }
  const decidedBy = req.auth.id;
  if (status === 'Pending') {
    await pool.query("UPDATE leaves SET status='Pending', decided_by='', decided_at=NULL WHERE id=?", [id]);
  } else {
    await pool.query('UPDATE leaves SET status=?, decided_by=?, decided_at=NOW() WHERE id=?', [status, decidedBy, id]);
  }
  res.json({ ok: true, leave: await fetchLeaveById(id) });
}

app.put('/api/leaves/:id', authenticate, async (req, res) => leaveDecision(req, res));
app.post('/api/leaves/:id/approve', authenticate, async (req, res) => leaveDecision(req, res, 'Approved'));
app.post('/api/leaves/:id/reject', authenticate, async (req, res) => leaveDecision(req, res, 'Rejected'));

// Cancel/delete a leave. Employees may cancel their own; Admins their own.
app.delete('/api/leaves/:id', authenticate, async (req, res) => {
  if (req.auth.role === 'organizer') return res.status(403).json({ ok: false, error: 'forbidden' });
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.json({ ok: false, error: 'id-invalid' });
  const leave = await fetchLeaveById(id);
  if (!leave || !leaveVisibleTo(req.auth.role, req.auth.id, leave)) {
    return res.json({ ok: false, error: 'not-found' });
  }
  await pool.query('DELETE FROM leaves WHERE id=?', [id]);
  res.json({ ok: true });
});

// ---------------- ORGANIZER SYNC (privacy: no employee details) ----------------
// The Organizer console must never receive employee/record/leave data.
app.get('/api/organizer/pull', authenticate, roleOnly('organizer'), async (req, res) => {
  const [a] = await pool.query('SELECT * FROM admins ORDER BY created_at ASC');
  let organizer = null;
  try {
    const [o] = await pool.query('SELECT * FROM organizers LIMIT 1');
    organizer = safeOrganizer(o[0] || null);
  } catch (e) {}
  const admins = a.map(safeAdmin);
  res.json({ ok: true, admins, admin: admins[0] || null, organizer });
});

// ---------------- ROLE-SCOPED FULL SYNC ----------------
app.get('/api/pull', authenticate, async (req, res) => {
  if (req.auth.role === 'organizer') {
    const [a] = await pool.query('SELECT * FROM admins ORDER BY created_at ASC');
    let organizer = null;
    try {
      const [o] = await pool.query('SELECT * FROM organizers LIMIT 1');
      organizer = safeOrganizer(o[0] || null);
    } catch (e) {}
    const admins = a.map(safeAdmin);
    return res.json({ ok: true, admins, admin: admins[0] || null, organizer });
  }

  if (req.auth.role === 'admin') {
    const adminId = req.auth.id;
    const [emps] = await pool.query('SELECT * FROM employees WHERE LOWER(adminId)=LOWER(?)', [adminId]);
    const [recs] = await pool.query(
      `SELECT r.* FROM records r LEFT JOIN employees e ON e.id=r.empId
        WHERE LOWER(r.adminId)=LOWER(?) OR (r.adminId='' AND LOWER(e.adminId)=LOWER(?))
        ORDER BY r.\`date\` DESC`,
      [adminId, adminId]
    );
    let leaves = [];
    try {
      const [l] = await pool.query(
        LEAVE_SELECT + " WHERE COALESCE(NULLIF(l.adminId,''), e.adminId, '')=? ORDER BY l.leave_date DESC, l.id DESC",
        [adminId]
      );
      leaves = l;
    } catch (e) {}
    const [ad] = await pool.query('SELECT * FROM admins WHERE LOWER(id)=LOWER(?) LIMIT 1', [adminId]);
    const admin = safeAdmin(ad[0] || null);
    return res.json({
      ok: true,
      emp: emps.map(safeEmp),
      rec: recs.map((x) => ({ ...x, date: dateOnly(x.date) })),
      admin,
      admins: admin ? [admin] : [],
      leaves,
    });
  }

  // Employee: own profile, own records, own leaves, and the owner Admin's
  // non-secret status (needed to show the "disabled" lockout state).
  const [emps] = await pool.query('SELECT * FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1', [req.auth.id]);
  const empRow = emps[0];
  if (!empRow) return res.status(404).json({ ok: false, error: 'not-found' });
  const [recs] = await pool.query(
    'SELECT * FROM records WHERE LOWER(empId)=LOWER(?) ORDER BY `date` DESC',
    [empRow.id]
  );
  let leaves = [];
  try {
    const [l] = await pool.query(LEAVE_SELECT + ' WHERE LOWER(l.empId)=LOWER(?) ORDER BY l.leave_date DESC, l.id DESC', [empRow.id]);
    leaves = l;
  } catch (e) {}
  let owner = null;
  if (empRow.adminId) {
    const [ad] = await pool.query('SELECT * FROM admins WHERE LOWER(id)=LOWER(?) LIMIT 1', [empRow.adminId]);
    if (ad[0]) owner = safeAdmin(ad[0]);
  }
  res.json({
    ok: true,
    emp: [safeEmp(empRow)],
    rec: recs.map((x) => ({ ...x, date: dateOnly(x.date) })),
    admin: owner,
    admins: owner ? [owner] : [],
    leaves,
  });
});

app.post('/api/push', authenticate, async (req, res) => {
  const body = req.body || {};
  const role = req.auth.role;
  const emp = Array.isArray(body.emp) ? body.emp : [];
  const rec = Array.isArray(body.rec) ? body.rec : [];
  const admin = body.admin && typeof body.admin === 'object' ? body.admin : null;
  const admins = Array.isArray(body.admins) ? body.admins : [];
  const organizer = body.organizer && typeof body.organizer === 'object' ? body.organizer : null;
  const leaves = Array.isArray(body.leaves) ? body.leaves : [];
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    if (role === 'organizer') {
      // Organizer pushes only update admin metadata/status (never passwords)
      // and the organizer profile. Employee data is ignored by design.
      for (const a of admins) {
        if (!a || !cleanId(a.id)) continue;
        const real = await resolveAdminId(conn, a.id);
        if (real) {
          await conn.query(
            'UPDATE admins SET name=COALESCE(?,name), company=COALESCE(NULLIF(?,\'\'),company), mob=COALESCE(?,mob), movie=COALESCE(?,movie), birth=COALESCE(?,birth), school=COALESCE(?,school), photo=COALESCE(NULLIF(?, \'\'), photo), status=COALESCE(?,status) WHERE id=?',
            [a.name ?? null, a.company ?? null, a.mob ?? null, a.movie ?? null, a.birth ?? null, a.school ?? null, a.photo ?? null, a.status ?? null, real]
          );
          if (String(a.status || '') === 'Disabled') await revokeAdminAndEmployees(real);
        } else if (a.pass) {
          const pe = passwordError(a.pass);
          if (pe) continue;
          const company = txt(a.company).slice(0, 150);
          if (!company) continue;
          await conn.query(
            'INSERT INTO admins (id,name,company,pass,mob,movie,birth,school,photo,status,mustChangePass,created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
            [a.id, a.name || '', company, hashPassword(a.pass), a.mob || '', a.movie || '', a.birth || '', a.school || '', a.photo ?? null, a.status || 'Enabled', 1, a.created || todayD()]
          );
        }
      }
      if (organizer && organizer.id) {
        await conn.query(
          "UPDATE organizers SET mob=COALESCE(?,mob), movie=COALESCE(?,movie), birth=COALESCE(?,birth), school=COALESCE(?,school), photo=COALESCE(NULLIF(?, ''), photo) LIMIT 1",
          [organizer.mob ?? null, organizer.movie ?? null, organizer.birth ?? null, organizer.school ?? null, organizer.photo ?? null]
        );
      }
      await conn.commit();
      return res.json({ ok: true });
    }

    if (role === 'admin') {
      const adminId = req.auth.id;
      for (const x of emp) {
        const id = cleanId(x.id, 3);
        if (!id) continue;
        const [ex] = await conn.query('SELECT id, adminId FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1 FOR UPDATE', [id]);
        if (ex.length) {
          // Never touch an employee that belongs to another Admin.
          if (!sameId(ex[0].adminId, adminId)) continue;
          const passHash = x.pass ? hashPassword(x.pass) : '';
          if (x.pass) {
            const pe = passwordError(x.pass);
            if (pe) continue;
          }
          await conn.query(
            "UPDATE employees SET name=COALESCE(?,name), pass=IF(?='',pass,?), desg=COALESCE(?,desg), mob=COALESCE(?,mob), photo=COALESCE(NULLIF(?,''),photo), store=COALESCE(?,store), storeArea=COALESCE(?,storeArea), storeLat=COALESCE(?,storeLat), storeLon=COALESCE(?,storeLon), storeLink=COALESCE(?,storeLink), mustChangePass=COALESCE(?,mustChangePass), status=COALESCE(?,status) WHERE id=?",
            [x.name ?? null, passHash, passHash, x.desg ?? null, x.mob ?? null, x.photo ?? null, x.store ?? null, x.storeArea ?? null, x.storeLat ?? null, x.storeLon ?? null, x.storeLink ?? null, x.mustChangePass == null ? null : (x.mustChangePass ? 1 : 0), x.status ?? null, ex[0].id]
          );
          if (passHash) await revokeTokens('employee', ex[0].id);
          if (String(x.status || '') === 'Disabled') await revokeTokens('employee', ex[0].id);
        } else {
          if (!x.pass) continue; // new employees need a password
          const pe = passwordError(x.pass);
          if (pe) continue;
          await conn.query(
            'INSERT INTO employees (id,name,pass,desg,mob,photo,store,storeArea,storeLat,storeLon,storeLink,created,mustChangePass,adminId,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            [id, x.name || id, hashPassword(x.pass), x.desg || '', x.mob || '', x.photo || '', x.store || '', x.storeArea || '', x.storeLat ?? null, x.storeLon ?? null, x.storeLink || '', x.created || null, x.mustChangePass ? 1 : 0, adminId, x.status || 'Enabled']
          );
        }
      }
      for (const x of rec) {
        const empId = txt(x.empId);
        const d = dateOnly(x.date);
        if (!empId || !isDateStr(d)) continue;
        const [ownerRows] = await conn.query('SELECT id, adminId, name FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1', [empId]);
        let owner = ownerRows[0] ? ownerRows[0].adminId : '';
        if (ownerRows[0]) {
          if (!sameId(owner, adminId)) continue;
        } else {
          const [rr] = await conn.query('SELECT adminId FROM records WHERE empId=? AND `date`=?', [empId, d]);
          if (!rr.length || !sameId(rr[0].adminId, adminId)) continue;
        }
        await upsertRecord(conn, x, empId, d, adminId);
      }
      for (const x of leaves) {
        const empId = txt(x.empId);
        const d = dateOnly(x.leave_date || x.date);
        if (!empId || !isDateStr(d)) continue;
        const [ownerRows] = await conn.query('SELECT adminId, name FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1', [empId]);
        if (!ownerRows[0] || !sameId(ownerRows[0].adminId, adminId)) continue;
        const st = leaveStatus(x.status) || 'Pending';
        const decidedBy = st === 'Pending' ? '' : adminId;
        await conn.query(
          `INSERT INTO leaves (empId,name,leave_date,reason,status,adminId,decided_by,decided_at)
           VALUES (?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE
             name=VALUES(name),
             reason=VALUES(reason),
             adminId=VALUES(adminId),
             decided_by=IF(status='Approved',decided_by,VALUES(decided_by)),
             decided_at=IF(status='Approved',decided_at,VALUES(decided_at)),
             status=IF(status='Approved','Approved',VALUES(status))`,
          [empId, txt(x.name) || ownerRows[0].name || '', d, txt(x.reason).slice(0, 255), st, adminId, decidedBy, st === 'Pending' ? null : (x.decided_at || new Date())]
        );
      }
      // Admin profile metadata only (password changes go through PUT /api/admin).
      if (admin && sameId(admin.id, adminId)) {
        await conn.query(
          "UPDATE admins SET name=COALESCE(?,name), company=COALESCE(NULLIF(?,''),company), mob=COALESCE(?,mob), movie=COALESCE(?,movie), birth=COALESCE(?,birth), school=COALESCE(?,school), photo=COALESCE(NULLIF(?, ''), photo) WHERE id=?",
          [admin.name ?? null, admin.company ?? null, admin.mob ?? null, admin.movie ?? null, admin.birth ?? null, admin.school ?? null, admin.photo ?? null, adminId]
        );
      }
      await conn.commit();
      return res.json({ ok: true });
    }

    // Employee: only its own attendance records may be upserted. Profile,
    // leaves and other employees' data are rejected (ignored) here.
    const [emps] = await conn.query('SELECT * FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1', [req.auth.id]);
    const empRow = emps[0];
    if (!empRow) {
      await conn.rollback();
      return res.status(404).json({ ok: false, error: 'not-found' });
    }
    if (String(empRow.status || 'Enabled') === 'Disabled') {
      await conn.rollback();
      await revokeTokens('employee', empRow.id);
      return res.json({ ok: false, error: 'employee-disabled' });
    }
    if (empRow.adminId && String(await adminStatusById(empRow.adminId, conn)) === 'Disabled') {
      await conn.rollback();
      await revokeTokens('employee', empRow.id);
      return res.json({ ok: false, error: 'admin-disabled' });
    }
    for (const x of rec) {
      if (!sameId(x.empId, empRow.id)) continue;
      const d = dateOnly(x.date);
      if (!isDateStr(d)) continue;
      await upsertRecord(conn, x, empRow.id, d, empRow.adminId || '');
    }
    await conn.commit();
    return res.json({ ok: true });
  } catch (e) {
    try { await conn.rollback(); } catch (_) {}
    return res.json({ ok: false, error: 'db-error' });
  } finally {
    conn.release();
  }
});

async function upsertRecord(conn, x, empId, d, adminId) {
  await conn.query(
    "INSERT INTO records (empId,`date`,name,store,storeArea,storeLink,type,inTime,inPhoto,inLat,inLon,inLocLink,inDistM,outTime,outPhoto,outLat,outLon,outLocLink,outDistM,adminId) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE name=VALUES(name),store=VALUES(store),storeArea=VALUES(storeArea),storeLink=VALUES(storeLink),type=VALUES(type),inTime=VALUES(inTime),inPhoto=COALESCE(NULLIF(VALUES(inPhoto),''),inPhoto),inLat=VALUES(inLat),inLon=VALUES(inLon),inLocLink=VALUES(inLocLink),inDistM=VALUES(inDistM),outTime=VALUES(outTime),outPhoto=COALESCE(NULLIF(VALUES(outPhoto),''),outPhoto),outLat=VALUES(outLat),outLon=VALUES(outLon),outLocLink=VALUES(outLocLink),outDistM=VALUES(outDistM),adminId=VALUES(adminId)",
    [empId, d, x.name || '', x.store || '', x.storeArea || '', x.storeLink || '', x.type || 'Duty', x.inTime || '', x.inPhoto || '', x.inLat || '', x.inLon || '', x.inLocLink || '', x.inDistM ?? null, x.outTime || '', x.outPhoto || '', x.outLat || '', x.outLon || '', x.outLocLink || '', x.outDistM ?? null, adminId || '']
  );
}

// ---------------- EMPLOYEES (per-admin owner + Enabled/Disabled) ----------------
app.get('/api/employees', authenticate, roleOnly('admin'), async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM employees');
  const q = String(req.query.adminId || '').toLowerCase();
  if (q && q !== String(req.auth.id).toLowerCase()) {
    return res.status(403).json({ ok: false, error: 'forbidden' });
  }
  const out = rows.filter((x) => sameId(x.adminId, req.auth.id));
  res.json({ ok: true, emp: out.map(safeEmp) });
});

app.post('/api/employees', authenticate, roleOnly('admin'), async (req, res) => {
  const x = req.body || {};
  const id = cleanId(x.id, 3);
  if (!x.name || !id || !x.pass) return res.json({ ok: false, error: 'required' });
  const pe = passwordError(x.pass);
  if (pe) return res.json({ ok: false, error: pe });
  try {
    await pool.query(
      'INSERT INTO employees (id,name,pass,desg,mob,photo,store,storeArea,storeLat,storeLon,storeLink,created,mustChangePass,adminId,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [id, x.name, hashPassword(x.pass), x.desg || '', x.mob || '', x.photo || '', x.store || '', x.storeArea || '', x.storeLat ?? null, x.storeLon ?? null, x.storeLink || '', x.created || null, 1, req.auth.id, x.status || 'Enabled']
    );
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: 'duplicate' });
  }
});

app.put('/api/employees/:id', authenticate, async (req, res) => {
  const x = req.body || {};
  const target = String(req.params.id || '');
  // Self-service photo update for the employee portal.
  if (req.auth.role === 'employee') {
    if (!sameId(target, req.auth.id) || x.photo === undefined) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    await pool.query('UPDATE employees SET photo=? WHERE LOWER(id)=LOWER(?)', [String(x.photo || '').slice(0, 10 * 1024 * 1024), req.auth.id]);
    return res.json({ ok: true });
  }
  if (req.auth.role !== 'admin') return res.status(403).json({ ok: false, error: 'forbidden' });
  const [rows] = await pool.query('SELECT id, adminId FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1', [target]);
  if (!rows.length || !sameId(rows[0].adminId, req.auth.id)) {
    return res.status(403).json({ ok: false, error: 'forbidden' });
  }
  let passHash = null;
  if (x.pass != null && String(x.pass) !== '') {
    const pe = passwordError(x.pass);
    if (pe) return res.json({ ok: false, error: pe });
    passHash = hashPassword(x.pass);
  }
  await pool.query(
    "UPDATE employees SET name=COALESCE(?,name),pass=COALESCE(?,pass),desg=COALESCE(?,desg),mob=COALESCE(?,mob),photo=COALESCE(NULLIF(?,''),photo),store=COALESCE(?,store),storeArea=COALESCE(?,storeArea),storeLat=COALESCE(?,storeLat),storeLon=COALESCE(?,storeLon),storeLink=COALESCE(?,storeLink),mustChangePass=COALESCE(?,mustChangePass),status=COALESCE(?,status) WHERE id=?",
    [x.name ?? null, passHash, x.desg ?? null, x.mob ?? null, x.photo ?? null, x.store ?? null, x.storeArea ?? null, x.storeLat ?? null, x.storeLon ?? null, x.storeLink ?? null, x.mustChangePass == null ? null : (x.mustChangePass ? 1 : 0), x.status ?? null, rows[0].id]
  );
  if (passHash) await revokeTokens('employee', rows[0].id);
  res.json({ ok: true });
});

app.post('/api/employees/:id/enable', authenticate, roleOnly('admin'), async (req, res) => {
  const [rows] = await pool.query('SELECT id, adminId FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1', [req.params.id]);
  if (!rows.length || !sameId(rows[0].adminId, req.auth.id)) return res.status(403).json({ ok: false, error: 'forbidden' });
  await pool.query('UPDATE employees SET status=? WHERE id=?', ['Enabled', rows[0].id]);
  res.json({ ok: true });
});

app.post('/api/employees/:id/disable', authenticate, roleOnly('admin'), async (req, res) => {
  const [rows] = await pool.query('SELECT id, adminId FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1', [req.params.id]);
  if (!rows.length || !sameId(rows[0].adminId, req.auth.id)) return res.status(403).json({ ok: false, error: 'forbidden' });
  await pool.query('UPDATE employees SET status=? WHERE id=?', ['Disabled', rows[0].id]);
  await revokeTokens('employee', rows[0].id);
  res.json({ ok: true });
});

app.delete('/api/employees/:id', authenticate, roleOnly('admin'), async (req, res) => {
  const [rows] = await pool.query('SELECT id, adminId FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1', [req.params.id]);
  if (!rows.length || !sameId(rows[0].adminId, req.auth.id)) return res.status(403).json({ ok: false, error: 'forbidden' });
  await pool.query('DELETE FROM employees WHERE id=?', [rows[0].id]);
  await revokeTokens('employee', rows[0].id);
  res.json({ ok: true });
});

// Employee ID rename (Admin correction: oldId -> newId). Employees,
// attendance records and leaves move in one transaction. The frontend
// calls this first, then saves locally (push upsert is idempotent).
app.post('/api/employees/rename', authenticate, roleOnly('admin'), async (req, res) => {
  const { oldId, newId, name } = req.body || {};
  const cleanNew = cleanId(newId, 3);
  if (!oldId || !cleanNew) return res.json({ ok: false, error: 'ids-required' });
  if (sameId(oldId, cleanNew)) return res.json({ ok: true, renamed: false });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [ownRows] = await conn.query('SELECT id, adminId FROM employees WHERE LOWER(id)=LOWER(?) LIMIT 1', [oldId]);
    if (!ownRows.length || !sameId(ownRows[0].adminId, req.auth.id)) {
      await conn.rollback();
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    const realOld = ownRows[0].id;
    const [dup] = await conn.query('SELECT id FROM employees WHERE id=?', [cleanNew]);
    if (dup.length && !sameId(dup[0].id, realOld)) {
      await conn.rollback();
      return res.json({ ok: false, error: 'duplicate' });
    }
    await conn.query('UPDATE employees SET id=? WHERE id=?', [cleanNew, realOld]);
    try {
      await conn.query('UPDATE records SET empId=?, name=COALESCE(?,name) WHERE empId=?', [cleanNew, name || null, realOld]);
    } catch (e) {
      if (e && (e.code === 'ER_DUP_ENTRY' || /duplicate/i.test(e.message || ''))) {
        await conn.rollback();
        return res.json({ ok: false, error: 'duplicate' });
      }
      throw e;
    }
    try {
      await conn.query('UPDATE leaves SET empId=?, name=COALESCE(?,name) WHERE empId=?', [cleanNew, name || null, realOld]);
    } catch (e) {
      if (e && (e.code === 'ER_DUP_ENTRY' || /duplicate/i.test(e.message || ''))) {
        await conn.rollback();
        return res.json({ ok: false, error: 'duplicate' });
      }
      if (!(e && e.code === 'ER_NO_SUCH_TABLE')) throw e; // older DBs may not have leaves
    }
    await moveTokens(conn, 'employee', realOld, cleanNew);
    await conn.commit();
    res.json({ ok: true, renamed: true });
  } catch (e) {
    try { await conn.rollback(); } catch (_) {}
    res.json({ ok: false, error: 'db-error' });
  } finally {
    conn.release();
  }
});

app.post('/api/employee/login', rateLimit('emp-login', 30, 15 * 60 * 1000), async (req, res) => {
  const { id, pass } = req.body || {};
  const [rows] = await pool.query('SELECT * FROM employees WHERE id=?', [id]);
  let f = rows[0];
  if (!f) {
    const [all] = await pool.query('SELECT * FROM employees');
    f = all.find((x) => sameId(x.id, id));
  }
  if (!(f && verifyPassword(pass, f.pass))) return res.json({ ok: false, error: 'wrong' });
  f = normEmpRow(f);
  if (String(f.status || 'Enabled') === 'Disabled') return res.json({ ok: false, error: 'disabled' });
  // A disabled owner Admin automatically blocks all of its employees.
  try {
    if (f.adminId && String(await adminStatusById(f.adminId)) === 'Disabled') {
      return res.json({ ok: false, error: 'admin-disabled' });
    }
  } catch (e) {}
  await upgradePasswordIfLegacy('employees', f.id, pass, f.pass);
  const session = await issueToken('employee', f.id, TTL_EMPLOYEE);
  return res.json({ ok: true, emp: safeEmp(f), token: session.token, expiresIn: session.expiresIn });
});

app.post('/api/employee/forgot', rateLimit('emp-forgot', 15, 15 * 60 * 1000), async (req, res) => {
  const { id, mob, newPass } = req.body || {};
  const pe = passwordError(newPass);
  if (pe) return res.json({ ok: false, error: pe });
  const [rows] = await pool.query('SELECT * FROM employees');
  const emp = rows.find((x) => sameId(x.id, id)) || null;
  const ok = !!emp && !!emp.mob && String(mob || '') === String(emp.mob || '');
  if (!ok) return res.json({ ok: false, error: 'answers' });
  if (String(emp.status || 'Enabled') === 'Disabled') return res.json({ ok: false, error: 'disabled' });
  await pool.query('UPDATE employees SET pass=?, mustChangePass=0 WHERE id=?', [hashPassword(newPass), emp.id]);
  await revokeTokens('employee', emp.id);
  res.json({ ok: true });
});

// ---------------- RECORDS ----------------
app.get('/api/records', authenticate, async (req, res) => {
  if (req.auth.role === 'organizer') return res.status(403).json({ ok: false, error: 'forbidden' });
  let rows;
  if (req.auth.role === 'employee') {
    [rows] = await pool.query(
      'SELECT * FROM records WHERE LOWER(empId)=LOWER(?) ORDER BY `date` DESC',
      [req.auth.id]
    );
  } else {
    const adminId = req.auth.id;
    [rows] = await pool.query(
      `SELECT r.* FROM records r LEFT JOIN employees e ON e.id=r.empId
       WHERE LOWER(r.adminId)=LOWER(?) OR (r.adminId='' AND LOWER(e.adminId)=LOWER(?))
       ORDER BY r.\`date\` DESC`,
      [adminId, adminId]
    );
  }
  res.json({ ok: true, rec: rows.map((x) => ({ ...x, date: dateOnly(x.date) })) });
});

// Clear records. Admins can only clear their own scope; employees and the
// organizer cannot clear attendance data.
app.delete('/api/records', authenticate, roleOnly('admin'), async (req, res) => {
  const adminId = req.auth.id;
  const [result] = await pool.query(
    `DELETE r FROM records r LEFT JOIN employees e ON e.id=r.empId
     WHERE LOWER(r.adminId)=LOWER(?) OR (r.adminId='' AND LOWER(e.adminId)=LOWER(?))`,
    [adminId, adminId]
  );
  res.json({ ok: true, scope: 'admin', deleted: result.affectedRows });
});

// ---------------- Static frontend (single Render service) ----------------
// The React app is built into frontend/dist by `npm run build` (and by the
// Dockerfile). Old bookmarks keep working through explicit redirects.
const FRONTEND_DIST = path.join(__dirname, '..', 'frontend', 'dist');
const FRONTEND_INDEX = path.join(FRONTEND_DIST, 'index.html');
const LEGACY_ROUTES = {
  '/index.html': '/',
  '/organizer.html': '/organizer',
  '/admin.html': '/admin',
  '/employee.html': '/employee',
  '/legacy-unified.html': '/legacy-unified',
};

// Never expose server source or dependencies, even if static roots change.
app.use((req, res, next) => {
  let p = String(req.path || '');
  try { p = decodeURIComponent(p); } catch (e) {} // catch %2F/%62 encoded tricks
  const segs = p.split(/[\\/]+/).filter(Boolean);
  if (segs.some((s) => s.toLowerCase() === 'backend' || s.toLowerCase() === 'node_modules' || s.startsWith('.'))) {
    return res.status(404).json({ ok: false, error: 'not-found' });
  }
  next();
});

app.get(Object.keys(LEGACY_ROUTES), (req, res) => res.redirect(302, LEGACY_ROUTES[req.path]));
app.use(express.static(FRONTEND_DIST, {
  dotfiles: 'deny',
  index: false,
  setHeaders(res, filePath) {
    if (filePath.endsWith('index.html')) res.setHeader('Cache-Control', 'no-cache');
    else if (filePath.includes(`${path.sep}assets${path.sep}`)) res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  },
}));
app.get('*', (req, res) => {
  if (req.path === '/api' || req.path.startsWith('/api/')) return res.status(404).json({ ok: false });
  res.sendFile(FRONTEND_INDEX, (err) => {
    if (!err || res.headersSent) return;
    res.status(503).send('Frontend build not found. Run "npm run build" in frontend/ first.');
  });
});

// ---------------- Global error handler ----------------
// Last line of defence: any error forwarded by wrapRoute (or a sync throw)
// becomes a clean JSON 500 while the process stays alive. Internal error
// details are never sent to the browser in production.
app.use((err, req, res, next) => {
  console.error('API error:', (err && err.message) || err);
  if (res.headersSent) return next(err);
  const expose = process.env.NODE_ENV !== 'production';
  res.status(500).json({ ok: false, error: expose ? ((err && err.message) || 'server-error') : 'server-error' });
});

// ---------------- Boot ----------------
ensureSchema()
  .catch((e) => console.log('schema-heal note:', e.message))
  .finally(() => {
    app.listen(PORT, () => console.log('Get-Attended backend ON :' + PORT));
    upgradeLegacyPasswords()
      .then(() => console.log('password migration: legacy plaintext upgraded'))
      .catch((e) => console.log('password migration note:', e.message));
    cleanupExpiredTokens().catch(() => {});
    setInterval(() => cleanupExpiredTokens().catch(() => {}), 60 * 60 * 1000).unref();
  });
