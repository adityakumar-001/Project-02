-- ============================================================
-- Get-Attended : MySQL Schema (Production-grade)
-- DB: attend | Engine: InnoDB | Charset: utf8mb4_unicode_ci
--
-- Fresh import:
--   mysql -u root -p < db.sql
--   -- or phpMyAdmin > Import > db.sql
--
-- Existing database (no data loss on re-import):
--   This file is IDEMPOTENT — CREATE IF NOT EXISTS plus the
--   migration block below adds missing columns, indexes and
--   views to older tables without touching existing rows.
--
-- App contract (server.js — do not break):
--   organizers(id,pass,mob,movie,birth,school) : single row (top)
--   admins(id PK,pass,mob,movie,birth,school,company,status,created) : MULTIPLE rows
--   employees(id PK, ..., adminId owner, ...) : per-admin isolation
--   records(empId+date PK, type Duty|WeekOff|StoreClose, ...)
--   leaves(empId+leave_date unique, adminId owner, status Pending|Approved|Rejected)
--   Rows of deleted employees stay in records/leaves for AUDIT,
--   so there is NO foreign key from records to employees (by design).
-- ============================================================

-- ---------- 0) Session safety ----------
SET NAMES utf8mb4;
SET time_zone = '+05:30';
-- (Foreign-key checks stay off during migration, back on at the end.)
SET FOREIGN_KEY_CHECKS = 0;

CREATE DATABASE IF NOT EXISTS attend
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE attend;

-- ============================================================
-- 0.5) ORGANIZER — top level (single row, manages Admins only)
--    Flow: ORGANIZER -> ADMINS -> EMPLOYEES (per admin)
--    The Organizer never sees employee details, only the Admin list.
-- ============================================================
CREATE TABLE IF NOT EXISTS organizers (
  id         VARCHAR(50)  NOT NULL PRIMARY KEY COMMENT 'Single organizer ID',
  pass       VARCHAR(255) NOT NULL COMMENT 'Organizer password (scrypt hash)',
  mob        VARCHAR(15)  NOT NULL DEFAULT '' COMMENT 'Q1 recovery mobile',
  movie      VARCHAR(100) NOT NULL DEFAULT '' COMMENT 'Q2 favorite movie',
  birth      VARCHAR(100) NOT NULL DEFAULT '' COMMENT 'Q3 birth place',
  school     VARCHAR(150) NOT NULL DEFAULT '' COMMENT 'Q4 class-10 school',
  photo      LONGTEXT     NULL COMMENT 'Organizer profile photo (base64)',
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Single-row organizer (creates and manages multiple admins)';

-- Default organizer (only on a fresh/empty install; re-import never
-- overwrites the password or adds a second organizer row).
INSERT INTO organizers (id, pass, mob, movie, birth, school)
SELECT 'organizer', 'scrypt$ae59aaea967e3054c726a1044d5e1f24$55388e99fd92605fe7333d80bc9898aa6e689a30c788521964bcab5ac1de9a91ee8572022b73c206e53383eb1af0b55ed8a9edecd7fc9eb3eade3ac394a04dfc', '', '', '', ''
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM organizers);

-- ============================================================
-- 0.6) AUTH TOKENS - hashed bearer sessions (never store raw tokens)
--     One row per login; short TTL (employee 15 min, admin/organizer 1 h).
-- ============================================================
CREATE TABLE IF NOT EXISTS auth_tokens (
  tokenHash CHAR(64)     NOT NULL PRIMARY KEY COMMENT 'SHA-256 of the bearer token',
  role      VARCHAR(20)  NOT NULL COMMENT 'organizer|admin|employee',
  subjectId VARCHAR(50)  NOT NULL COMMENT 'organizer/admin/employee ID',
  expiresAt DATETIME     NOT NULL,
  createdAt TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_token_subject (role, subjectId),
  INDEX idx_token_expiry (expiresAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Opaque bearer sessions (raw token only exists on the client)';

-- ============================================================
-- 1) ADMINS — MULTIPLE rows (created and managed by the Organizer)
--    + status Enabled/Disabled (disabling an Admin also blocks
--      all of its Employees; the Organizer still only sees the list)
--    + each id is UNIQUE per row (primary key, never merged)
-- ============================================================
CREATE TABLE IF NOT EXISTS admins (
  id         VARCHAR(50)  NOT NULL PRIMARY KEY COMMENT 'Unique Admin ID (Organizer creates, one per admin)',
  name       VARCHAR(100) NOT NULL DEFAULT '' COMMENT 'Admin display name (Organizer editable)',
  company    VARCHAR(150) NOT NULL DEFAULT '' COMMENT 'Company name shown to every employee under this admin',
  pass       VARCHAR(255) NOT NULL COMMENT 'Admin password (scrypt hash)',
  mob        VARCHAR(15)  NOT NULL DEFAULT '' COMMENT 'Q1 recovery mobile',
  movie      VARCHAR(100) NOT NULL DEFAULT '' COMMENT 'Q2 favorite movie',
  birth      VARCHAR(100) NOT NULL DEFAULT '' COMMENT 'Q3 birth place',
  school     VARCHAR(150) NOT NULL DEFAULT '' COMMENT 'Q4 class-10 school',
  photo      LONGTEXT     NULL COMMENT 'Admin profile photo (base64, device + cloud)',
  status     VARCHAR(20)  NOT NULL DEFAULT 'Enabled' COMMENT 'Enabled|Disabled (Disabled blocks login and its employees)',
  mustChangePass TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = first-login password change compulsory',
  created    DATE         NULL COMMENT 'Admin creation date (app: todayStr)',
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT chk_admin_status CHECK (status IN ('Enabled', 'Disabled'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Multiple admin rows (Organizer-managed, separate IDs)';

-- No default Admin is seeded. The Organizer creates every Admin ID; this is
-- what makes a deleted Admin stay deleted after re-import/deploy.
-- The default Organizer above is the only bootstrap account.

-- ============================================================
-- 2) EMPLOYEES — manual unique ID + adminId owner (same on every
--    device via push/pull)
--    adminId = which Admin owns this employee (disabling that Admin
--    blocks all of its employees; each Admin only sees its own,
--    data is never collapsed or mixed across admins)
-- ============================================================
CREATE TABLE IF NOT EXISTS employees (
  id             VARCHAR(50)  NOT NULL PRIMARY KEY COMMENT 'Manual unique ID e.g. EMP001',
  name           VARCHAR(100) NOT NULL,
  pass           VARCHAR(255) NOT NULL COMMENT 'Login password (scrypt hash)',
  desg           VARCHAR(100) NOT NULL DEFAULT '',
  mob            VARCHAR(15)  NOT NULL DEFAULT '',
  photo          LONGTEXT     NULL COMMENT 'Profile photo base64 (10MB upload cap enforced app-side)',
  store          VARCHAR(150) NOT NULL DEFAULT '' COMMENT 'Store name (125m fence source)',
  storeArea      VARCHAR(150) NOT NULL DEFAULT '',
  storeLat       DOUBLE       NULL COMMENT '-90..90',
  storeLon       DOUBLE       NULL COMMENT '-180..180',
  storeLink      TEXT         NULL COMMENT 'Google Maps link',
  created        DATE         NULL COMMENT 'ID creation date (app: todayStr)',
  mustChangePass TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '1 = first-login password change compulsory',
  adminId        VARCHAR(50)  NOT NULL DEFAULT '' COMMENT 'Owner Admin ID (isolation: each admin sees only its own employees)',
  status         VARCHAR(20)  NOT NULL DEFAULT 'Enabled' COMMENT 'Enabled|Disabled (Disabled = login blocked by Admin)',
  created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_emp_name (name),
  INDEX idx_emp_store (store),
  INDEX idx_emp_mob (mob),
  INDEX idx_emp_admin (adminId),
  CONSTRAINT chk_emp_lat CHECK (storeLat IS NULL OR (storeLat BETWEEN -90 AND 90)),
  CONSTRAINT chk_emp_lon CHECK (storeLon IS NULL OR (storeLon BETWEEN -180 AND 180)),
  CONSTRAINT chk_emp_status CHECK (status IN ('Enabled', 'Disabled'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Employees + store geofence mapping + owner admin';

-- ============================================================
-- 3) RECORDS — attendance (empId + date unique)
--    NO foreign key to employees (rows of deleted IDs stay for audit)
-- ============================================================
CREATE TABLE IF NOT EXISTS records (
  empId      VARCHAR(50)  NOT NULL COMMENT 'May point to a deleted employee (audit)',
  `date`     DATE         NOT NULL COMMENT 'Punch date (today only, no back-date)',
  name       VARCHAR(100) NOT NULL DEFAULT '' COMMENT 'Name snapshot at punch time',
  store      VARCHAR(150) NOT NULL DEFAULT '',
  storeArea  VARCHAR(150) NOT NULL DEFAULT '',
  storeLink  TEXT         NULL,
  type       VARCHAR(20)  NOT NULL DEFAULT 'Duty' COMMENT 'Duty|WeekOff|StoreClose',
  inTime     VARCHAR(30)  NOT NULL DEFAULT '' COMMENT 'HH:MM:SS (app) or hh:mm:ss AM/PM (legacy)',
  inPhoto    LONGTEXT     NULL,
  inLat      VARCHAR(30)  NOT NULL DEFAULT '',
  inLon      VARCHAR(30)  NOT NULL DEFAULT '',
  inLocLink  TEXT         NULL,
  inDistM    INT          NULL COMMENT 'Meters from store at IN (<=125 ok)',
  outTime    VARCHAR(30)  NOT NULL DEFAULT '',
  outPhoto   LONGTEXT     NULL,
  outLat     VARCHAR(30)  NOT NULL DEFAULT '',
  outLon     VARCHAR(30)  NOT NULL DEFAULT '',
  outLocLink TEXT         NULL,
  outDistM   INT          NULL,
  adminId    VARCHAR(50)  NOT NULL DEFAULT '' COMMENT 'Owner Admin ID at punch time (per-admin isolation)',
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (empId, `date`),
  INDEX idx_rec_date (`date`),
  INDEX idx_rec_emp (empId),
  INDEX idx_rec_admin (adminId),
  INDEX idx_rec_type (type),
  INDEX idx_rec_store (store),
  INDEX idx_rec_date_type (`date`, type),
  CONSTRAINT chk_rec_type CHECK (type IN ('Duty', 'WeekOff', 'StoreClose'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Daily attendance; orphan rows (deleted employees) kept for audit';

SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================
-- 4) MIGRATIONS — bring older databases up to expert level
--    Each statement is independent and re-runnable.
--    (MySQL 8 has no ADD COLUMN IF NOT EXISTS, hence procedures.)
-- ============================================================
DELIMITER $$

DROP PROCEDURE IF EXISTS ga_add_column $$
CREATE PROCEDURE ga_add_column(
  IN p_table VARCHAR(64), IN p_col VARCHAR(64), IN p_ddl TEXT
)
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table AND COLUMN_NAME = p_col
  ) THEN
    SET @q = CONCAT('ALTER TABLE `', p_table, '` ADD COLUMN ', p_ddl);
    PREPARE s FROM @q; EXECUTE s; DEALLOCATE PREPARE s;
  END IF;
END $$

DROP PROCEDURE IF EXISTS ga_add_index $$
CREATE PROCEDURE ga_add_index(
  IN p_table VARCHAR(64), IN p_idx VARCHAR(64), IN p_ddl TEXT
)
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table AND INDEX_NAME = p_idx
  ) THEN
    SET @q = CONCAT('ALTER TABLE `', p_table, '` ADD ', p_ddl);
    PREPARE s FROM @q; EXECUTE s; DEALLOCATE PREPARE s;
  END IF;
END $$

DELIMITER ;

-- organizers: photo (missing in older installs)
CALL ga_add_column('organizers', 'photo',  '`photo` LONGTEXT NULL COMMENT ''Organizer profile photo''');

-- admins: name + company + first-login password flag + photo + status + created + timestamps (missing in older installs)
CALL ga_add_column('admins', 'name',       '`name` VARCHAR(100) NOT NULL DEFAULT '''' COMMENT ''Admin display name''');
CALL ga_add_column('admins', 'company',    '`company` VARCHAR(150) NOT NULL DEFAULT '''' COMMENT ''Company name shown to employees''');
CALL ga_add_column('admins', 'mustChangePass', '`mustChangePass` TINYINT(1) NOT NULL DEFAULT 0 COMMENT ''1 = first-login password change compulsory''');
CALL ga_add_column('admins', 'photo',      '`photo` LONGTEXT NULL COMMENT ''Admin profile photo''');
CALL ga_add_column('admins', 'status',     '`status` VARCHAR(20) NOT NULL DEFAULT ''Enabled''');
CALL ga_add_column('admins', 'created',    '`created` DATE NULL COMMENT ''Admin creation date''');
CALL ga_add_column('admins', 'created_at', '`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL ga_add_column('admins', 'updated_at', '`updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');

-- employees: owner adminId + status + timestamps + indexes
CALL ga_add_column('employees', 'adminId',    '`adminId` VARCHAR(50) NOT NULL DEFAULT '''' COMMENT ''Owner Admin ID''');
CALL ga_add_column('employees', 'status',     '`status` VARCHAR(20) NOT NULL DEFAULT ''Enabled'' COMMENT ''Enabled|Disabled''');
CALL ga_add_column('employees', 'created_at', '`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL ga_add_column('employees', 'updated_at', '`updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
CALL ga_add_index('employees', 'idx_emp_name',  'INDEX `idx_emp_name` (`name`)');
CALL ga_add_index('employees', 'idx_emp_store', 'INDEX `idx_emp_store` (`store`)');
CALL ga_add_index('employees', 'idx_emp_mob',   'INDEX `idx_emp_mob` (`mob`)');
CALL ga_add_index('employees', 'idx_emp_admin', 'INDEX `idx_emp_admin` (`adminId`)');

-- records: owner adminId + timestamps + indexes
CALL ga_add_column('records', 'adminId',    '`adminId` VARCHAR(50) NOT NULL DEFAULT '''' COMMENT ''Owner Admin ID''');
CALL ga_add_column('records', 'created_at', '`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP');
CALL ga_add_column('records', 'updated_at', '`updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
CALL ga_add_index('records', 'idx_rec_date',      'INDEX `idx_rec_date` (`date`)');
CALL ga_add_index('records', 'idx_rec_emp',       'INDEX `idx_rec_emp` (`empId`)');
CALL ga_add_index('records', 'idx_rec_admin',     'INDEX `idx_rec_admin` (`adminId`)');
CALL ga_add_index('records', 'idx_rec_type',      'INDEX `idx_rec_type` (`type`)');
CALL ga_add_index('records', 'idx_rec_store',     'INDEX `idx_rec_store` (`store`)');
CALL ga_add_index('records', 'idx_rec_date_type', 'INDEX `idx_rec_date_type` (`date`, `type`)');

-- Widen password columns for scrypt hashes on older installs
ALTER TABLE organizers MODIFY `pass` VARCHAR(255) NOT NULL COMMENT 'Organizer password (scrypt hash)';
ALTER TABLE admins     MODIFY `pass` VARCHAR(255) NOT NULL COMMENT 'Admin password (scrypt hash)';
ALTER TABLE employees  MODIFY `pass` VARCHAR(255) NOT NULL COMMENT 'Login password (scrypt hash)';

DROP PROCEDURE IF EXISTS ga_add_column;
DROP PROCEDURE IF EXISTS ga_add_index;

-- ============================================================
-- 5) VIEWS — reporting (Excel/CSV-style, straight from MySQL)
-- ============================================================

-- 5a) Daily status view (mirrors app getStatus()):
--     Accepts app 24-hour HH:MM:SS and legacy hh:mm:ss AM/PM.
--     Store Close / Week Off / IN Only / Half Day (OUT before 6 PM) / Present
CREATE OR REPLACE VIEW v_daily_status AS
SELECT
  p.empId,
  p.`date`,
  p.name,
  p.store,
  p.storeArea,
  p.type,
  p.inTime,
  p.outTime,
  CASE
    WHEN p.type = 'StoreClose' THEN 'Store Close'
    WHEN p.type = 'WeekOff'    THEN 'Week Off'
    WHEN p.outTime = '' OR p.outTime IS NULL THEN 'IN Only'
    WHEN p.outTs IS NULL THEN 'Present'
    WHEN TIME(p.outTs) < TIME('18:00:00') THEN 'Half Day'
    ELSE 'Present'
  END AS status,
  CASE
    WHEN p.outTs IS NULL OR p.inTs IS NULL OR p.type <> 'Duty' THEN '—'
    ELSE TIME_FORMAT(
      SEC_TO_TIME((TIME_TO_SEC(p.outTs) - TIME_TO_SEC(p.inTs) + 86400) % 86400),
      '%kh %im')
  END AS workHrs
FROM (
  SELECT
    r.*,
    CASE
      WHEN r.inTime IS NULL OR r.inTime = '' THEN NULL
      WHEN UPPER(TRIM(r.inTime)) LIKE '%AM' OR UPPER(TRIM(r.inTime)) LIKE '%PM'
        THEN STR_TO_DATE(TRIM(r.inTime), '%h:%i:%s %p')
      ELSE STR_TO_DATE(TRIM(r.inTime), '%H:%i:%s')
    END AS inTs,
    CASE
      WHEN r.outTime IS NULL OR r.outTime = '' THEN NULL
      WHEN UPPER(TRIM(r.outTime)) LIKE '%AM' OR UPPER(TRIM(r.outTime)) LIKE '%PM'
        THEN STR_TO_DATE(TRIM(r.outTime), '%h:%i:%s %p')
      ELSE STR_TO_DATE(TRIM(r.outTime), '%H:%i:%s')
    END AS outTs
  FROM records r
) p;

-- 5b) Month-wise per-employee summary (deleted IDs tagged 'Deleted')
--     Accepts app 24-hour HH:MM:SS and legacy hh:mm:ss AM/PM.
CREATE OR REPLACE VIEW v_monthly_summary AS
SELECT
  DATE_FORMAT(p.`date`, '%Y-%m') AS ym,
  p.empId,
  COALESCE(e.name, p.name) AS name,
  CASE WHEN e.id IS NULL THEN 'Deleted' ELSE 'Active' END AS empState,
  SUM(p.type = 'Duty' AND p.outTs IS NOT NULL AND TIME(p.outTs) >= TIME('18:00:00')) AS present,
  SUM(p.type = 'Duty' AND p.outTs IS NOT NULL AND TIME(p.outTs) <  TIME('18:00:00')) AS halfDay,
  SUM(p.type = 'Duty' AND (p.outTime = '' OR p.outTime IS NULL)) AS inOnly,
  SUM(p.type = 'StoreClose') AS storeClose,
  SUM(p.type = 'WeekOff')    AS weekOff,
  COUNT(*) AS records
FROM (
  SELECT
    r.*,
    CASE
      WHEN r.outTime IS NULL OR r.outTime = '' THEN NULL
      WHEN UPPER(TRIM(r.outTime)) LIKE '%AM' OR UPPER(TRIM(r.outTime)) LIKE '%PM'
        THEN STR_TO_DATE(TRIM(r.outTime), '%h:%i:%s %p')
      ELSE STR_TO_DATE(TRIM(r.outTime), '%H:%i:%s')
    END AS outTs
  FROM records r
) p
LEFT JOIN employees e ON e.id = p.empId
GROUP BY DATE_FORMAT(p.`date`, '%Y-%m'), p.empId, name, empState;

-- 5c) Today dashboard counts (mirrors the stat cards)
CREATE OR REPLACE VIEW v_today_counts AS
SELECT
  (SELECT COUNT(*) FROM employees) AS totalEmployees,
  (SELECT COUNT(*) FROM records WHERE `date` = CURDATE()) AS markedToday,
  (SELECT COUNT(*) FROM v_daily_status WHERE `date` = CURDATE() AND status = 'Present') AS presentToday,
  (SELECT COUNT(*) FROM v_daily_status WHERE `date` = CURDATE() AND status = 'Half Day') AS halfDayToday;

-- ============================================================
-- 6) MAINTENANCE — optional cleanup (run only when needed)
-- ============================================================
-- -- Set punch photos older than 90 days to NULL (rows and counts stay,
-- -- the database gets lighter). Verify with SELECT first, then run:
-- -- SELECT COUNT(*) FROM records
-- --  WHERE `date` < CURDATE() - INTERVAL 90 DAY
-- --    AND (inPhoto IS NOT NULL OR outPhoto IS NOT NULL);
-- -- UPDATE records
-- --    SET inPhoto = NULL, outPhoto = NULL, updated_at = updated_at
-- --  WHERE `date` < CURDATE() - INTERVAL 90 DAY;

-- -- Orphan audit check (rows of deleted IDs — above 0 is normally OK):
-- -- SELECT r.empId, COUNT(*) AS rowsKept
-- --   FROM records r LEFT JOIN employees e ON e.id = r.empId
-- --  WHERE e.id IS NULL GROUP BY r.empId;

-- ============================================================
-- 7) VERIFY — run after import, expect one row per table
-- ============================================================
-- SELECT 'organizers' AS t, COUNT(*) AS n FROM organizers
-- UNION ALL SELECT 'admins', COUNT(*) FROM admins
-- UNION ALL SELECT 'employees', COUNT(*) FROM employees
-- UNION ALL SELECT 'records', COUNT(*) FROM records;
-- SHOW INDEX FROM records;
-- SELECT TABLE_NAME, ENGINE, TABLE_COLLATION
--   FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE();

-- ============================================================
-- 8) LEAVES — time off (employee applies, admin approves/rejects)

--    No punch happens on a leave day; this table tracks the reason
--    and the approval. No FK to employees (rows of deleted IDs stay
--    for audit — same design as records).
--    Multi-day leave = 1 row per day (UNIQUE empId+date).
-- ============================================================
CREATE TABLE IF NOT EXISTS leaves (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  empId      VARCHAR(50)  NOT NULL COMMENT 'Employee ID',
  name       VARCHAR(100) NOT NULL DEFAULT '' COMMENT 'Name snapshot at apply time',
  leave_date DATE         NOT NULL COMMENT 'Day of leave',
  reason     VARCHAR(255) NOT NULL DEFAULT '' COMMENT 'Reason for leave',
  status     VARCHAR(20)  NOT NULL DEFAULT 'Pending' COMMENT 'Pending|Approved|Rejected',
  adminId    VARCHAR(50)  NOT NULL DEFAULT '' COMMENT 'Owner Admin ID (isolation + fast filtering)',
  decided_by VARCHAR(50)  NOT NULL DEFAULT '' COMMENT 'Admin ID that approved/rejected',
  decided_at TIMESTAMP    NULL DEFAULT NULL COMMENT 'Decision time',
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Apply time',
  updated_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_leave_emp_date (empId, leave_date),
  INDEX idx_leave_date (leave_date),
  INDEX idx_leave_emp (empId),
  INDEX idx_leave_status (status),
  INDEX idx_leave_admin (adminId),
  CONSTRAINT chk_leave_status CHECK (status IN ('Pending', 'Approved', 'Rejected'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Leave applications + admin approvals';

-- 8.1) Upgrade older leaves tables (adds owner Admin + index, no data loss)
SET @has_leave_admin := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'leaves' AND COLUMN_NAME = 'adminId'
);
SET @ddl := IF(@has_leave_admin = 0,
  'ALTER TABLE leaves ADD COLUMN adminId VARCHAR(50) NOT NULL DEFAULT '''' AFTER status',
  'SELECT 1');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @has_leave_admin_idx := (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'leaves' AND INDEX_NAME = 'idx_leave_admin'
);
SET @ddl := IF(@has_leave_admin_idx = 0,
  'ALTER TABLE leaves ADD INDEX idx_leave_admin (adminId)',
  'SELECT 1');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

-- Fill the owner snapshot for rows created before adminId existed.
UPDATE leaves l
JOIN employees e ON e.id = l.empId
SET l.adminId = e.adminId,
    l.name = IF(l.name = '', e.name, l.name)
WHERE l.adminId = '';

-- 8a) Month-wise leave summary (per employee)
CREATE OR REPLACE VIEW v_leave_summary AS
SELECT
  DATE_FORMAT(leave_date, '%Y-%m') AS ym,
  empId,
  adminId,
  MAX(name) AS name,
  SUM(status = 'Approved') AS approved,
  SUM(status = 'Pending')  AS pending,
  SUM(status = 'Rejected') AS rejected,
  COUNT(*) AS total
FROM leaves
GROUP BY DATE_FORMAT(leave_date, '%Y-%m'), empId, adminId;

-- 8b) Sample flows (reference):
-- -- Apply (1 day): INSERT INTO leaves (empId, name, leave_date, reason, adminId)
-- --   VALUES ('EMP001', 'Aditya Kumar', '2026-10-20', 'Fever — doctor visit', 'ADMIN001');
-- -- Approve: UPDATE leaves SET status='Approved', decided_by='ADMIN001', decided_at=NOW()
-- --   WHERE empId='EMP001' AND leave_date='2026-10-20';
-- -- Reject: UPDATE leaves SET status='Rejected', decided_by='ADMIN001', decided_at=NOW()
-- --   WHERE id=5;
-- -- Pending list: SELECT * FROM leaves WHERE adminId='ADMIN001' AND status='Pending'
-- --   ORDER BY leave_date;
