const bcrypt = require('bcryptjs');
const { getKnexClient } = require('./knexClient');

function isoNow() {
  return new Date().toISOString();
}

function normalizeRow(row) {
  if (!row || typeof row !== 'object') {
    return row;
  }
  const normalized = {};
  Object.entries(row).forEach(([key, value]) => {
    if (value instanceof Date) {
      normalized[key] = value.toISOString();
    } else if (Buffer.isBuffer(value)) {
      normalized[key] = value.toString('utf8');
    } else {
      normalized[key] = value;
    }
  });
  return normalized;
}

function toDbBool(value) {
  return Boolean(value);
}

class SqlRepository {
  constructor(knexInstance) {
    this.knex = knexInstance;
    this.initialized = false;
    this.initializingPromise = null;
  }

  async initialize() {
    if (this.initialized) {
      return;
    }
    if (this.initializingPromise) {
      await this.initializingPromise;
      return;
    }
    this.initializingPromise = (async () => {
      await this.knex.migrate.latest();
      this.initialized = true;
      this.initializingPromise = null;
    })();
    await this.initializingPromise;
  }

  async insertAndFetch(tableName, payload) {
    const client = this.knex.client.config.client;
    if (client === 'pg' || client === 'oracledb' || client === 'mssql') {
      const [row] = await this.knex(tableName).insert(payload).returning('*');
      return normalizeRow(row);
    }
    if (client === 'mysql' || client === 'mysql2' || client === 'sqlite3') {
      const insertedIds = await this.knex(tableName).insert(payload);
      const id = Array.isArray(insertedIds) ? insertedIds[0] : insertedIds;
      const row = await this.knex(tableName).where({ id }).first();
      return normalizeRow(row);
    }
    throw new Error(`Unsupported client "${client}" for insert.`);
  }

  async ensureInitialized() {
    await this.initialize();
  }

  async createTenant({ tenantUid, tenant_uid, name = null, contactEmail = null, contact_email = null }) {
  await this.ensureInitialized();
  const payload = {
    tenant_uid: tenant_uid || tenantUid,
    name,
    contact_email: contact_email || contactEmail,
    created_at: isoNow(),
  };
  return this.insertAndFetch('tenants', payload);
  }


  async getTenantById(id) {
    await this.ensureInitialized();
    const row = await this.knex('tenants').where({ id }).first();
    return normalizeRow(row);
  }

  async getTenantByUid(tenantUid) {
    await this.ensureInitialized();
    const row = await this.knex('tenants').where({ tenant_uid: tenantUid }).first();
    return normalizeRow(row);
  }

  async listTenants() {
    await this.ensureInitialized();
    const rows = await this.knex('tenants').orderBy('created_at', 'asc');
    return rows.map(normalizeRow);
  }

  async createUser({
    tenantId = null,
    username,
    email,
    passwordHash,
    role,
    mustChangePassword = false,
    firstName = null,
    lastName = null,
  }) {
    await this.ensureInitialized();
    const payload = {
      tenant_id: tenantId,
      username,
      email,
      password_hash: passwordHash,
      role,
      must_change_password: toDbBool(mustChangePassword),
      failed_attempts: 0,
      locked_until: null,
      first_name: firstName,
      last_name: lastName,
      created_at: isoNow(),
    };
    return this.insertAndFetch('users', payload);
  }

  async updateUserPassword(userId, passwordHash, mustChangePassword = false) {
    await this.ensureInitialized();
    await this.knex('users')
      .where({ id: userId })
      .update({
        password_hash: passwordHash,
        must_change_password: toDbBool(mustChangePassword),
        failed_attempts: 0,
        locked_until: null,
      });
  }

  async setMustChangePassword(userId, mustChange) {
    await this.ensureInitialized();
    await this.knex('users')
      .where({ id: userId })
      .update({ must_change_password: toDbBool(mustChange) });
  }

  async getUserByEmail(email) {
    await this.ensureInitialized();
    const row = await this.knex('users')
      .whereRaw('LOWER(email) = LOWER(?)', [email])
      .first();
    return normalizeRow(row);
  }

  async getUserById(id) {
    await this.ensureInitialized();
    const row = await this.knex('users').where({ id }).first();
    return normalizeRow(row);
  }

  async getAllEmployeesByTenant(tenantId) {
    await this.ensureInitialized();
    const rows = await this.knex('users')
      .where({ tenant_id: tenantId, role: 'employee' })
      .orderBy('username', 'asc');
    return rows.map(normalizeRow);
  }

  async recordLoginFailure(userId, lockedUntil = null) {
    await this.ensureInitialized();
    return this.knex.transaction(async (trx) => {
      await trx('users').where({ id: userId }).increment('failed_attempts', 1);
      if (lockedUntil) {
        await trx('users').where({ id: userId }).update({ locked_until: lockedUntil });
      }
      const row = await trx('users')
        .select('failed_attempts', 'locked_until')
        .where({ id: userId })
        .first();
      return normalizeRow(row);
    });
  }

  async resetLoginFailures(userId) {
    await this.ensureInitialized();
    await this.knex('users')
      .where({ id: userId })
      .update({
        failed_attempts: 0,
        locked_until: null,
      });
  }

  async createRoleCode({ tenantId, code, expiresAt = null, maxUses = null, createdBy = null }) {
    await this.ensureInitialized();
    const payload = {
      tenant_id: tenantId,
      code,
      expires_at: expiresAt,
      max_uses: maxUses,
      usage_count: 0,
      is_disabled: false,
      created_by: createdBy,
      created_at: isoNow(),
    };
    return this.insertAndFetch('role_codes', payload);
  }

  async getRoleCodeByCode(code) {
    await this.ensureInitialized();
    const row = await this.knex('role_codes').where({ code }).first();
    return normalizeRow(row);
  }

  async getRoleCodeById(id) {
    await this.ensureInitialized();
    const row = await this.knex('role_codes').where({ id }).first();
    return normalizeRow(row);
  }

  async listRoleCodesByTenant(tenantId) {
    await this.ensureInitialized();
    const rows = await this.knex('role_codes')
      .where({ tenant_id: tenantId })
      .orderBy('created_at', 'desc');
    return rows.map(normalizeRow);
  }

  async incrementRoleCodeUsage(id) {
    await this.ensureInitialized();
    await this.knex('role_codes').where({ id }).increment('usage_count', 1);
  }

  async disableRoleCode(id) {
    await this.ensureInitialized();
    await this.knex('role_codes').where({ id }).update({ is_disabled: true });
  }

  async createPasswordResetToken({ userId, token, expiresAt }) {
    await this.ensureInitialized();
    const payload = {
      user_id: userId,
      token,
      expires_at: expiresAt,
      used_at: null,
      created_at: isoNow(),
    };
    return this.insertAndFetch('password_resets', payload);
  }

  async getPasswordResetToken(token) {
    await this.ensureInitialized();
    const row = await this.knex('password_resets').where({ token }).first();
    return normalizeRow(row);
  }

  async consumePasswordResetToken(id) {
    await this.ensureInitialized();
    await this.knex('password_resets')
      .where({ id })
      .update({ used_at: isoNow() });
  }

  async createWorkSession(userId, isoStart) {
    await this.ensureInitialized();
    const payload = {
      user_id: userId,
      start_time: isoStart,
      end_time: null,
      created_at: isoNow(),
    };
    const row = await this.insertAndFetch('work_sessions', payload);
    return row;
  }

  async closeWorkSession(sessionId, isoEnd) {
    await this.ensureInitialized();
    await this.knex('work_sessions').where({ id: sessionId }).update({ end_time: isoEnd });
  }

  async updateWorkSessionTimes(sessionId, startIso, endIso) {
    await this.ensureInitialized();
    await this.knex('work_sessions')
      .where({ id: sessionId })
      .update({ start_time: startIso, end_time: endIso });
  }

  async createWorkSessionWithEnd(userId, isoStart, isoEnd) {
    await this.ensureInitialized();
    const payload = {
      user_id: userId,
      start_time: isoStart,
      end_time: isoEnd,
      created_at: isoNow(),
    };
    const row = await this.insertAndFetch('work_sessions', payload);
    return row;
  }

  async getOpenWorkSession(userId) {
    await this.ensureInitialized();
    const row = await this.knex('work_sessions')
      .where({ user_id: userId })
      .andWhere({ end_time: null })
      .orderBy('start_time', 'desc')
      .first();
    return normalizeRow(row);
  }

  async getWorkSessionsByUserBetween(userId, startIso, endIso) {
    await this.ensureInitialized();
    const rows = await this.knex('work_sessions')
      .where({ user_id: userId })
      .andWhere('start_time', '>=', startIso)
      .andWhere('start_time', '<', endIso)
      .orderBy('start_time', 'asc');
    return rows.map(normalizeRow);
  }

  async getAllWorkSessionsByUser(userId) {
    await this.ensureInitialized();
    const rows = await this.knex('work_sessions')
      .where({ user_id: userId })
      .orderBy('start_time', 'desc');
    return rows.map(normalizeRow);
  }

  async getWorkSessionById(id) {
    await this.ensureInitialized();
    const row = await this.knex('work_sessions').where({ id }).first();
    return normalizeRow(row);
  }

  async deleteWorkSession(id) {
    await this.ensureInitialized();
    await this.knex('work_sessions').where({ id }).del();
  }

  async createPayrollRecord({
    tenantId,
    employeeId,
    uploadedBy = null,
    originalFileName,
    storedFilePath,
    mimeType = null,
    fileSize = null,
    sentOn,
    sentAt,
  }) {
    await this.ensureInitialized();
    const payload = {
      tenant_id: tenantId,
      employee_id: employeeId,
      uploaded_by: uploadedBy,
      original_file_name: originalFileName,
      stored_file_path: storedFilePath,
      mime_type: mimeType,
      file_size: fileSize,
      sent_on: sentOn,
      sent_at: sentAt,
      created_at: isoNow(),
    };
    return this.insertAndFetch('payroll_records', payload);
  }

  async listPayrollRecordsByTenant(tenantId, limit = 200, offset = 0) {
    await this.ensureInitialized();
    const rows = await this.knex('payroll_records')
      .where({ tenant_id: tenantId })
      .orderBy('sent_at', 'desc')
      .limit(limit)
      .offset(offset);
    return rows.map(normalizeRow);
  }

  async listPayrollRecordsByEmployee(employeeId) {
    await this.ensureInitialized();
    const rows = await this.knex('payroll_records')
      .where({ employee_id: employeeId })
      .orderBy('sent_at', 'desc');
    return rows.map(normalizeRow);
  }

  async getPayrollRecordById(id) {
    await this.ensureInitialized();
    const row = await this.knex('payroll_records').where({ id }).first();
    return normalizeRow(row);
  }

  async getLatestPayrollRecordForDate(employeeId, sentOn) {
    await this.ensureInitialized();
    const row = await this.knex('payroll_records')
      .where({ employee_id: employeeId, sent_on: sentOn })
      .orderBy('sent_at', 'desc')
      .first();
    return normalizeRow(row);
  }

  async ensureDefaultPlatformAdmin() {
    await this.ensureInitialized();
    const emailInput = process.env.DEFAULT_PLATFORM_ADMIN_EMAIL || '';
    const password = process.env.DEFAULT_PLATFORM_ADMIN_PASSWORD || '';

    if (!emailInput || !password) {
      if (process.env.NODE_ENV !== 'test') {
        // eslint-disable-next-line no-console
        console.warn(
          '[setup] DEFAULT_PLATFORM_ADMIN_EMAIL/PASSWORD are not set; skipping initial platform admin creation.'
        );
      }
      return;
    }

    const email = emailInput.trim().toLowerCase();
    const existing = await this.getUserByEmail(email);
    if (existing && existing.role === 'platform_admin') {
      return;
    }

    const passwordHash = await bcrypt.hash(password, 10);

    if (existing) {
      await this.knex('users')
        .where({ id: existing.id })
        .update({
          role: 'platform_admin',
          password_hash: passwordHash,
          must_change_password: toDbBool(true),
          failed_attempts: 0,
          locked_until: null,
        });
      if (process.env.NODE_ENV !== 'test') {
        // eslint-disable-next-line no-console
        console.info(`[setup] Elevated existing account ${email} to platform admin.`);
      }
      return;
    }

    await this.insertAndFetch('users', {
      tenant_id: null,
      username: 'PlatformAdmin',
      email,
      password_hash: passwordHash,
      role: 'platform_admin',
      must_change_password: toDbBool(true),
      failed_attempts: 0,
      locked_until: null,
      first_name: null,
      last_name: null,
      created_at: isoNow(),
    });

    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.info(`[setup] Created platform admin account ${email}.`);
    }
  }

  async deleteAllData() {
    await this.ensureInitialized();
    await this.knex.transaction(async (trx) => {
      await trx('password_resets').del();
      await trx('role_codes').del();
      await trx('payroll_records').del();
      await trx('work_sessions').del();
      await trx('users').del();
      await trx('tenants').del();
    });
  }
}

function createSqlRepository() {
  const knexInstance = getKnexClient();
  return new SqlRepository(knexInstance);
}

module.exports = {
  createSqlRepository,
};
