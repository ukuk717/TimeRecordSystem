const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const DB_FILE = process.env.DB_FILE || path.join(__dirname, '..', 'data', 'database.sqlite');

if (DB_FILE !== ':memory:') {
  const dir = path.dirname(DB_FILE);
  fs.mkdirSync(dir, { recursive: true });
}

const db = new Database(DB_FILE);
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');

initializeSchema();

const tenantStatements = {
  insert: db.prepare(`
    INSERT INTO tenants (tenant_uid, name, contact_email)
    VALUES (@tenant_uid, @name, @contact_email)
  `),
  byId: db.prepare(`SELECT * FROM tenants WHERE id = ?`),
  byUid: db.prepare(`SELECT * FROM tenants WHERE tenant_uid = ?`),
  all: db.prepare(`SELECT * FROM tenants ORDER BY created_at ASC`),
};

const userStatements = {
  insert: db.prepare(`
    INSERT INTO users (
      tenant_id,
      username,
      email,
      password_hash,
      role,
      must_change_password,
      first_name,
      last_name
    )
    VALUES (
      @tenant_id,
      @username,
      @email,
      @password_hash,
      @role,
      @must_change_password,
      @first_name,
      @last_name
    )
  `),
  byEmail: db.prepare(`SELECT * FROM users WHERE email = ?`),
  byId: db.prepare(`SELECT * FROM users WHERE id = ?`),
  employeesByTenant: db.prepare(`
    SELECT * FROM users
    WHERE tenant_id = ? AND role = 'employee'
    ORDER BY username ASC
  `),
  allPlatformAdmins: db.prepare(`
    SELECT * FROM users WHERE role = 'platform_admin'
  `),
  updatePassword: db.prepare(`
    UPDATE users
    SET password_hash = ?, must_change_password = ?, failed_attempts = 0, locked_until = NULL
    WHERE id = ?
  `),
  updateMustChange: db.prepare(`
    UPDATE users
    SET must_change_password = ?
    WHERE id = ?
  `),
  incrementFailedAttempts: db.prepare(`
    UPDATE users
    SET failed_attempts = failed_attempts + 1
    WHERE id = ?
  `),
  setLockedUntil: db.prepare(`
    UPDATE users
    SET locked_until = ?
    WHERE id = ?
  `),
  resetFailures: db.prepare(`
    UPDATE users
    SET failed_attempts = 0,
        locked_until = NULL
    WHERE id = ?
  `),
  getAuthMeta: db.prepare(`
    SELECT failed_attempts, locked_until
    FROM users
    WHERE id = ?
  `),
};

const roleCodeStatements = {
  insert: db.prepare(`
    INSERT INTO role_codes (
      tenant_id,
      code,
      expires_at,
      max_uses,
      usage_count,
      is_disabled,
      created_by
    )
    VALUES (
      @tenant_id,
      @code,
      @expires_at,
      @max_uses,
      @usage_count,
      @is_disabled,
      @created_by
    )
  `),
  byCode: db.prepare(`
    SELECT *
    FROM role_codes
    WHERE code = ?
  `),
  byId: db.prepare(`
    SELECT *
    FROM role_codes
    WHERE id = ?
  `),
  incrementUsage: db.prepare(`
    UPDATE role_codes
    SET usage_count = usage_count + 1
    WHERE id = ?
  `),
  disable: db.prepare(`
    UPDATE role_codes
    SET is_disabled = 1
    WHERE id = ?
  `),
  listByTenant: db.prepare(`
    SELECT *
    FROM role_codes
    WHERE tenant_id = ?
    ORDER BY created_at DESC
  `),
};

const passwordResetStatements = {
  insert: db.prepare(`
    INSERT INTO password_resets (user_id, token, expires_at)
    VALUES (?, ?, ?)
  `),
  byToken: db.prepare(`
    SELECT *
    FROM password_resets
    WHERE token = ? AND used_at IS NULL
  `),
  markUsed: db.prepare(`
    UPDATE password_resets
    SET used_at = datetime('now')
    WHERE id = ?
  `),
  deleteByUser: db.prepare(`
    DELETE FROM password_resets
    WHERE user_id = ?
  `),
};

const workSessionStatements = {
  insert: db.prepare(`
    INSERT INTO work_sessions (user_id, start_time)
    VALUES (?, ?)
  `),
  insertWithEnd: db.prepare(`
    INSERT INTO work_sessions (user_id, start_time, end_time)
    VALUES (?, ?, ?)
  `),
  updateEnd: db.prepare(`
    UPDATE work_sessions SET end_time = ? WHERE id = ?
  `),
  updateTimes: db.prepare(`
    UPDATE work_sessions
    SET start_time = ?, end_time = ?
    WHERE id = ?
  `),
  openForUser: db.prepare(`
    SELECT * FROM work_sessions
    WHERE user_id = ? AND end_time IS NULL
    ORDER BY start_time DESC
    LIMIT 1
  `),
  byId: db.prepare(`
    SELECT * FROM work_sessions
    WHERE id = ?
  `),
  byUserBetween: db.prepare(`
    SELECT * FROM work_sessions
    WHERE user_id = ?
      AND start_time >= ?
      AND start_time < ?
    ORDER BY start_time ASC
  `),
  allByUser: db.prepare(`
    SELECT * FROM work_sessions
    WHERE user_id = ?
    ORDER BY start_time DESC
  `),
  delete: db.prepare(`
    DELETE FROM work_sessions
    WHERE id = ?
  `),
};

function initializeSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS tenants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_uid TEXT NOT NULL UNIQUE,
      name TEXT,
      contact_email TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER,
      username TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('platform_admin','tenant_admin','employee')),
      must_change_password INTEGER NOT NULL DEFAULT 0,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TEXT,
      first_name TEXT,
      last_name TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS role_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      code TEXT NOT NULL UNIQUE,
      expires_at TEXT,
      max_uses INTEGER,
      usage_count INTEGER NOT NULL DEFAULT 0,
      is_disabled INTEGER NOT NULL DEFAULT 0,
      created_by INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS work_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  migrateUsersTable();
  ensureIndexes();
}

function migrateUsersTable() {
  const columns = db.prepare(`PRAGMA table_info(users)`).all();
  const columnNames = columns.map((col) => col.name);

  const hasEmail = columnNames.includes('email');
  const hasMustChange = columnNames.includes('must_change_password');

  if (!hasEmail || !hasMustChange) {
    db.exec('BEGIN TRANSACTION;');
    db.exec(`
      CREATE TABLE IF NOT EXISTS users_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id INTEGER,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('platform_admin','tenant_admin','employee')),
        must_change_password INTEGER NOT NULL DEFAULT 0,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        first_name TEXT,
        last_name TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
      );
    `);

    const hasOldUsers = columns.length > 0;
    if (hasOldUsers) {
      db.exec(`
        INSERT INTO users_new (
          id,
          tenant_id,
          username,
          email,
          password_hash,
          role,
          must_change_password,
          failed_attempts,
          locked_until,
          first_name,
          last_name,
          created_at
        )
        SELECT
          id,
          NULL AS tenant_id,
          username,
          username || '_' || id || '@placeholder.local' AS email,
          password_hash,
          CASE role
            WHEN 'admin' THEN 'platform_admin'
            ELSE 'employee'
          END AS role,
          0,
          0,
          NULL,
          NULL,
          NULL,
          created_at
        FROM users;
      `);

      db.exec('DROP TABLE users;');
    }

    db.exec('ALTER TABLE users_new RENAME TO users;');
    db.exec('COMMIT;');
  } else {
    ensureAdditionalUserColumns(columnNames);
    ensureRoleConstraint();
  }
}

function ensureAdditionalUserColumns(existingColumns) {
  const requiredColumns = [
    { name: 'tenant_id', definition: 'ALTER TABLE users ADD COLUMN tenant_id INTEGER' },
    {
      name: 'must_change_password',
      definition: 'ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0',
    },
    {
      name: 'failed_attempts',
      definition: 'ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0',
    },
    { name: 'locked_until', definition: 'ALTER TABLE users ADD COLUMN locked_until TEXT' },
    { name: 'first_name', definition: 'ALTER TABLE users ADD COLUMN first_name TEXT' },
    { name: 'last_name', definition: 'ALTER TABLE users ADD COLUMN last_name TEXT' },
  ];

  requiredColumns.forEach((column) => {
    if (!existingColumns.includes(column.name)) {
      try {
        db.exec(column.definition);
      } catch (error) {
        // eslint-disable-next-line no-console
        console.warn(`[schema] 繧ｫ繝ｩ繝 ${column.name} 縺ｮ霑ｽ蜉縺ｫ螟ｱ謨励＠縺ｾ縺励◆`, error);
      }
    }
  });
}

function ensureRoleConstraint() {
  const info = db.prepare(`SELECT sql FROM sqlite_master WHERE type='table' AND name='users'`).get();
  if (!info || !info.sql.includes("'platform_admin'")) {
    db.exec('BEGIN TRANSACTION;');
    db.exec(`
      CREATE TABLE users_tmp (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id INTEGER,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('platform_admin','tenant_admin','employee')),
        must_change_password INTEGER NOT NULL DEFAULT 0,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        first_name TEXT,
        last_name TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
      );
    `);
    db.exec(`
      INSERT INTO users_tmp (
        id,
        tenant_id,
        username,
        email,
        password_hash,
        role,
        must_change_password,
        failed_attempts,
        locked_until,
        first_name,
        last_name,
        created_at
      )
      SELECT
        id,
        tenant_id,
        username,
        email,
        password_hash,
        CASE role
          WHEN 'admin' THEN 'platform_admin'
          ELSE role
        END,
        must_change_password,
        failed_attempts,
        locked_until,
        first_name,
        last_name,
        created_at
      FROM users;
    `);
    db.exec('DROP TABLE users;');
    db.exec('ALTER TABLE users_tmp RENAME TO users;');
    db.exec('COMMIT;');
  }
}

function ensureIndexes() {
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_role_codes_tenant ON role_codes(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_role_codes_active ON role_codes(is_disabled, expires_at);
    CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token);
    CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);
  `);
}

function createTenant({ tenantUid, name, contactEmail }) {
  const result = tenantStatements.insert.run({
    tenant_uid: tenantUid,
    name: name || null,
    contact_email: contactEmail || null,
  });
  return { id: result.lastInsertRowid, tenant_uid: tenantUid, name, contact_email: contactEmail };
}

function getTenantById(id) {
  return tenantStatements.byId.get(id);
}

function getTenantByUid(tenantUid) {
  return tenantStatements.byUid.get(tenantUid);
}

function listTenants() {
  return tenantStatements.all.all();
}

function createUser({
  tenantId = null,
  username,
  email,
  passwordHash,
  role,
  mustChangePassword = false,
  firstName = null,
  lastName = null,
}) {
  const result = userStatements.insert.run({
    tenant_id: tenantId,
    username,
    email,
    password_hash: passwordHash,
    role,
    must_change_password: mustChangePassword ? 1 : 0,
    first_name: firstName,
    last_name: lastName,
  });
  return getUserById(result.lastInsertRowid);
}

function updateUserPassword(userId, passwordHash, mustChangePassword = false) {
  userStatements.updatePassword.run(passwordHash, mustChangePassword ? 1 : 0, userId);
}

function setMustChangePassword(userId, mustChange) {
  userStatements.updateMustChange.run(mustChange ? 1 : 0, userId);
}

function getUserByEmail(email) {
  return userStatements.byEmail.get(email);
}

function getUserById(id) {
  return userStatements.byId.get(id);
}

function getAllEmployeesByTenant(tenantId) {
  return userStatements.employeesByTenant.all(tenantId);
}

function recordLoginFailure(userId, lockedUntil = null) {
  userStatements.incrementFailedAttempts.run(userId);
  if (lockedUntil) {
    userStatements.setLockedUntil.run(lockedUntil, userId);
  }
  return userStatements.getAuthMeta.get(userId);
}

function resetLoginFailures(userId) {
  userStatements.resetFailures.run(userId);
}

function createRoleCode({
  tenantId,
  code,
  expiresAt = null,
  maxUses = null,
  createdBy = null,
}) {
  const result = roleCodeStatements.insert.run({
    tenant_id: tenantId,
    code,
    expires_at: expiresAt,
    max_uses: maxUses,
    usage_count: 0,
    is_disabled: 0,
    created_by: createdBy,
  });
  return roleCodeStatements.byCode.get(code);
}

function getRoleCodeByCode(code) {
  return roleCodeStatements.byCode.get(code);
}

function getRoleCodeById(id) {
  return roleCodeStatements.byId.get(id);
}

function listRoleCodesByTenant(tenantId) {
  return roleCodeStatements.listByTenant.all(tenantId);
}

function incrementRoleCodeUsage(roleCodeId) {
  roleCodeStatements.incrementUsage.run(roleCodeId);
}

function disableRoleCode(roleCodeId) {
  roleCodeStatements.disable.run(roleCodeId);
}

function createPasswordResetToken(userId, token, expiresAt) {
  passwordResetStatements.deleteByUser.run(userId);
  const result = passwordResetStatements.insert.run(userId, token, expiresAt);
  return passwordResetStatements.byToken.get(token) || { id: result.lastInsertRowid };
}

function getPasswordResetToken(token) {
  return passwordResetStatements.byToken.get(token);
}

function consumePasswordResetToken(id) {
  passwordResetStatements.markUsed.run(id);
}

function createWorkSession(userId, isoStart) {
  const info = workSessionStatements.insert.run(userId, isoStart);
  return { id: info.lastInsertRowid, user_id: userId, start_time: isoStart, end_time: null };
}

function closeWorkSession(sessionId, isoEnd) {
  return workSessionStatements.updateEnd.run(isoEnd, sessionId);
}

function updateWorkSessionTimes(sessionId, startIso, endIso) {
  return workSessionStatements.updateTimes.run(startIso, endIso, sessionId);
}

function createWorkSessionWithEnd(userId, isoStart, isoEnd) {
  const info = workSessionStatements.insertWithEnd.run(userId, isoStart, isoEnd);
  return {
    id: info.lastInsertRowid,
    user_id: userId,
    start_time: isoStart,
    end_time: isoEnd,
  };
}

function getOpenWorkSession(userId) {
  return workSessionStatements.openForUser.get(userId);
}

function getWorkSessionsByUserBetween(userId, startIso, endIso) {
  return workSessionStatements.byUserBetween.all(userId, startIso, endIso);
}

function getAllWorkSessionsByUser(userId) {
  return workSessionStatements.allByUser.all(userId);
}

function getWorkSessionById(id) {
  return workSessionStatements.byId.get(id);
}

function deleteWorkSession(sessionId) {
  return workSessionStatements.delete.run(sessionId);
}

function ensureDefaultPlatformAdmin() {
  const emailInput = process.env.DEFAULT_PLATFORM_ADMIN_EMAIL || '';
  const password = process.env.DEFAULT_PLATFORM_ADMIN_PASSWORD || '';

  if (!emailInput || !password) {
    // eslint-disable-next-line no-console
    console.warn('[setup] DEFAULT_PLATFORM_ADMIN_EMAIL/PASSWORD are not set; skipping initial platform admin creation.');
    return;
  }

  const email = emailInput.trim().toLowerCase();
  const existing = getUserByEmail(email);
  if (existing && existing.role === 'platform_admin') {
    return;
  }

  const passwordHash = bcrypt.hashSync(password, 10);

  try {
    createUser({
      username: 'PlatformAdmin',
      email,
      passwordHash,
      role: 'platform_admin',
      mustChangePassword: true,
    });
    // eslint-disable-next-line no-console
    console.info(`[setup] Created platform admin account ${email}.`);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error('[setup] Failed to create platform admin account', error);
  }
}
function deleteAllData() {
  db.exec(`
    DELETE FROM password_resets;
    DELETE FROM role_codes;
    DELETE FROM work_sessions;
    DELETE FROM users;
    DELETE FROM tenants;
  `);
}

module.exports = {
  db,
  createTenant,
  getTenantById,
  getTenantByUid,
  listTenants,
  createUser,
  updateUserPassword,
  setMustChangePassword,
  getUserByEmail,
  getUserById,
  getAllEmployeesByTenant,
  recordLoginFailure,
  resetLoginFailures,
  createRoleCode,
  getRoleCodeByCode,
  getRoleCodeById,
  listRoleCodesByTenant,
  incrementRoleCodeUsage,
  disableRoleCode,
  createPasswordResetToken,
  getPasswordResetToken,
  consumePasswordResetToken,
  createWorkSession,
  closeWorkSession,
  createWorkSessionWithEnd,
  updateWorkSessionTimes,
  getOpenWorkSession,
  getWorkSessionsByUserBetween,
  getAllWorkSessionsByUser,
  getWorkSessionById,
  deleteWorkSession,
  ensureDefaultPlatformAdmin,
  deleteAllData,
};
