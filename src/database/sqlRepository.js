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

function parseJson(value) {
  if (typeof value !== 'string') {
    return null;
  }
  try {
    return JSON.parse(value);
  } catch (error) {
    return null;
  }
}

function stringifyJson(value) {
  if (value === undefined) {
    return null;
  }
  try {
    return JSON.stringify(value);
  } catch (error) {
    return null;
  }
}

function normalizeLogPayload(value) {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value === 'string') {
    return value;
  }
  try {
    return JSON.stringify(value);
  } catch (error) {
    return null;
  }
}

function mapMfaRow(row) {
  const normalized = normalizeRow(row);
  if (!normalized) {
    return normalized;
  }
  if ('config_json' in normalized) {
    normalized.config = parseJson(normalized.config_json);
    delete normalized.config_json;
  }
  return normalized;
}

function mapEmailOtpRow(row) {
  const normalized = normalizeRow(row);
  if (!normalized) {
    return normalized;
  }
  if ('metadata_json' in normalized) {
    normalized.metadata = parseJson(normalized.metadata_json);
    delete normalized.metadata_json;
  }
  return normalized;
}

function applyEmailOtpFilters(query, filters = {}) {
  if (!filters || typeof filters !== 'object') {
    return query;
  }
  if ('id' in filters && filters.id !== undefined && filters.id !== null) {
    query.where({ id: filters.id });
  }
  if ('userId' in filters) {
    if (filters.userId === null) {
      query.whereNull('user_id');
    } else {
      query.where('user_id', filters.userId);
    }
  }
  if ('tenantId' in filters) {
    if (filters.tenantId === null) {
      query.whereNull('tenant_id');
    } else {
      query.where('tenant_id', filters.tenantId);
    }
  }
  if ('roleCodeId' in filters) {
    if (filters.roleCodeId === null) {
      query.whereNull('role_code_id');
    } else {
      query.where('role_code_id', filters.roleCodeId);
    }
  }
  if (filters.purpose) {
    query.where('purpose', filters.purpose);
  }
  if (filters.targetEmail) {
    query.where('target_email', filters.targetEmail);
  }
  if (filters.onlyActive) {
    const nowIso = filters.activeAt || isoNow();
    query.whereNull('consumed_at').andWhere('expires_at', '>', nowIso);
  }
  return query;
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

  async insertAndFetch(tableName, payload, executor = this.knex) {
    const db = executor || this.knex;
    const client = db.client && db.client.config ? db.client.config.client : null;
    const supportsReturning = client === 'pg' || client === 'oracledb' || client === 'mssql';

    const insertWithConnection = async (conn) => {
      if (supportsReturning) {
        const [row] = await conn(tableName).insert(payload).returning('*');
        return normalizeRow(row);
      }
      const insertedIds = await conn(tableName).insert(payload);
      const id = Array.isArray(insertedIds) ? insertedIds[0] : insertedIds;
      const row = await conn(tableName).where({ id }).first();
      return normalizeRow(row);
    };

    if (supportsReturning || db.isTransaction) {
      return insertWithConnection(db);
    }

    if (client === 'mysql' || client === 'mysql2' || client === 'sqlite3') {
      return db.transaction((trx) => insertWithConnection(trx));
    }

    throw new Error(`Unsupported client "${client}" for insert.`);
  }

  async ensureInitialized() {
    await this.initialize();
  }

  async createTenant({
    tenantUid,
    tenant_uid,
    name = null,
    contactEmail = null,
    contact_email = null,
    status = 'active',
  }) {
    await this.ensureInitialized();
    const payload = {
      tenant_uid: tenant_uid || tenantUid,
      name,
      contact_email: contact_email || contactEmail,
      created_at: isoNow(),
      status,
      deactivated_at: null,
      require_employee_email_verification: toDbBool(false),
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

  async updateTenantStatus(tenantId, status) {
    await this.ensureInitialized();
    if (status === 'active') {
      await this.knex('tenants').where({ id: tenantId }).update({ status, deactivated_at: null });
      return;
    }
    await this.knex('tenants').where({ id: tenantId }).update({
      status,
      deactivated_at: isoNow(),
    });
  }

  async updateTenantRegistrationSettings(tenantId, { requireEmailVerification } = {}) {
    await this.ensureInitialized();
    const patch = {};
    if (requireEmailVerification !== undefined) {
      patch.require_employee_email_verification = toDbBool(requireEmailVerification);
    }
    if (Object.keys(patch).length === 0) {
      return this.getTenantById(tenantId);
    }
    await this.knex('tenants').where({ id: tenantId }).update(patch);
    return this.getTenantById(tenantId);
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
    phoneNumber = null,
    status = 'active',
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
      phone_number: phoneNumber,
      created_at: isoNow(),
      status,
      deactivated_at: null,
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

  async updateUserProfile(userId, { firstName, lastName, phoneNumber } = {}) {
    await this.ensureInitialized();
    const patch = {};
    if (firstName !== undefined) {
      patch.first_name = firstName;
    }
    if (lastName !== undefined) {
      patch.last_name = lastName;
    }
    if (phoneNumber !== undefined) {
      patch.phone_number = phoneNumber;
    }
    if (Object.keys(patch).length === 0) {
      return;
    }
    await this.knex('users').where({ id: userId }).update(patch);
  }

  async updateUserEmail(userId, email) {
    await this.ensureInitialized();
    await this.knex('users').where({ id: userId }).update({ email });
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

  async listTenantAdmins() {
    await this.ensureInitialized();
    const rows = await this.knex('users as u')
      .leftJoin('tenants as t', 'u.tenant_id', 't.id')
      .select(
        'u.*',
        this.knex.ref('t.name').as('tenant_name'),
        this.knex.ref('t.tenant_uid').as('tenant_uid'),
        this.knex.ref('t.status').as('tenant_status')
      )
      .where('u.role', 'tenant_admin')
      .orderBy('u.username', 'asc');
    return rows.map(normalizeRow);
  }

  async getAllEmployeesByTenant(tenantId) {
    await this.ensureInitialized();
    const rows = await this.knex('users')
      .where({ tenant_id: tenantId, role: 'employee', status: 'active' })
      .orderBy('username', 'asc');
    return rows.map(normalizeRow);
  }

  async getAllEmployeesByTenantIncludingInactive(tenantId) {
    await this.ensureInitialized();
    const rows = await this.knex('users')
      .where({ tenant_id: tenantId, role: 'employee' })
      .orderBy('username', 'asc');
    return rows.map(normalizeRow);
  }

  async updateUserStatus(userId, status) {
    await this.ensureInitialized();
    if (status === 'active') {
      await this.knex('users').where({ id: userId }).update({
        status,
        deactivated_at: null,
      });
      return;
    }
    await this.knex('users').where({ id: userId }).update({
      status,
      deactivated_at: isoNow(),
    });
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

  async createPasswordResetToken({ userId, tokenHash, expiresAt }) {
    await this.ensureInitialized();
    if (!userId) {
      throw new Error('userId must be provided.');
    }
    if (!tokenHash) {
      throw new Error('tokenHash must be provided.');
    }
    if (!expiresAt) {
      throw new Error('expiresAt must be provided.');
    }
    const payload = {
      user_id: userId,
      token: tokenHash,
      expires_at: expiresAt,
      used_at: null,
      created_at: isoNow(),
    };
    return this.insertAndFetch('password_resets', payload);
  }

  async getPasswordResetToken({ tokenHash, fallbackToken = null }) {
    await this.ensureInitialized();
    const row = await this.knex('password_resets')
      .where({ token: tokenHash })
      .andWhere({ used_at: null })
      .first();
    if (row) {
      return normalizeRow(row);
    }
    if (fallbackToken) {
      const legacyRow = await this.knex('password_resets')
        .where({ token: fallbackToken })
        .andWhere({ used_at: null })
        .first();
      if (legacyRow && tokenHash) {
        await this.knex('password_resets')
          .where({ id: legacyRow.id })
          .update({ token: tokenHash });
        legacyRow.token = tokenHash;
      }
      return normalizeRow(legacyRow);
    }
    return null;
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
      archived_at: null,
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
      archived_at: null,
    };
    const row = await this.insertAndFetch('work_sessions', payload);
    return row;
  }

  async getOpenWorkSession(userId) {
    await this.ensureInitialized();
    const row = await this.knex('work_sessions')
      .where({ user_id: userId })
      .andWhere({ end_time: null })
      .whereNull('archived_at')
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
      .whereNull('archived_at')
      .orderBy('start_time', 'asc');
    return rows.map(normalizeRow);
  }

  async getAllWorkSessionsByUser(userId) {
    await this.ensureInitialized();
    const rows = await this.knex('work_sessions')
      .where({ user_id: userId })
      .whereNull('archived_at')
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
      archived_at: null,
    };
    return this.insertAndFetch('payroll_records', payload);
  }

  async listPayrollRecordsByTenant(tenantId, limit = 200, offset = 0) {
    await this.ensureInitialized();
    const rows = await this.knex('payroll_records')
      .where({ tenant_id: tenantId })
      .whereNull('archived_at')
      .orderBy('sent_at', 'desc')
      .limit(limit)
      .offset(offset);
    return rows.map(normalizeRow);
  }

  async listPayrollRecordsByEmployee(employeeId) {
    await this.ensureInitialized();
    const rows = await this.knex('payroll_records')
      .where({ employee_id: employeeId })
      .whereNull('archived_at')
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
      .whereNull('archived_at')
      .orderBy('sent_at', 'desc')
      .first();
    return normalizeRow(row);
  }

  async markPayrollRecordsArchived(recordIds, archivedAtIso) {
    if (!Array.isArray(recordIds) || recordIds.length === 0) {
      return;
    }
    await this.ensureInitialized();
    await this.knex('payroll_records')
      .whereIn('id', recordIds)
      .update({ archived_at: archivedAtIso });
  }

  async deletePayrollRecords(recordIds) {
    if (!Array.isArray(recordIds) || recordIds.length === 0) {
      return;
    }
    await this.ensureInitialized();
    await this.knex('payroll_records').whereIn('id', recordIds).del();
  }

  async findPayrollRecordsOlderThan(cutoffIso, limit = 200) {
    await this.ensureInitialized();
    const rows = await this.knex('payroll_records')
      .where('created_at', '<', cutoffIso)
      .andWhere((qb) => {
        qb.whereNull('archived_at').orWhere('archived_at', '<', cutoffIso);
      })
      .orderBy('created_at', 'asc')
      .limit(limit);
    return rows.map(normalizeRow);
  }

  async findWorkSessionsOlderThan(cutoffIso, limit = 500) {
    await this.ensureInitialized();
    const rows = await this.knex('work_sessions')
      .where('start_time', '<', cutoffIso)
      .andWhere((qb) => {
        qb.whereNull('archived_at').orWhere('archived_at', '<', cutoffIso);
      })
      .orderBy('start_time', 'asc')
      .limit(limit);
    return rows.map(normalizeRow);
  }

  async markWorkSessionsArchived(sessionIds, archivedAtIso) {
    if (!Array.isArray(sessionIds) || sessionIds.length === 0) {
      return;
    }
    await this.ensureInitialized();
    await this.knex('work_sessions')
      .whereIn('id', sessionIds)
      .update({ archived_at: archivedAtIso });
  }

  async deleteWorkSessions(sessionIds) {
    if (!Array.isArray(sessionIds) || sessionIds.length === 0) {
      return;
    }
    await this.ensureInitialized();
    await this.knex('work_sessions').whereIn('id', sessionIds).del();
  }

  async deleteEmailOtpRequests(filters = {}) {
    await this.ensureInitialized();
    const query = this.knex('email_otp_requests');
    applyEmailOtpFilters(query, filters);
    await query.del();
  }

  async createEmailOtpRequest({
    userId = null,
    tenantId = null,
    roleCodeId = null,
    purpose,
    targetEmail,
    codeHash,
    expiresAt,
    maxAttempts = 5,
    metadata = null,
    lastSentAt = null,
  }) {
    await this.ensureInitialized();
    const payload = {
      user_id: userId,
      tenant_id: tenantId,
      role_code_id: roleCodeId,
      purpose,
      target_email: targetEmail,
      code_hash: codeHash,
      metadata_json: stringifyJson(metadata),
      expires_at: expiresAt,
      consumed_at: null,
      failed_attempts: 0,
      max_attempts: maxAttempts,
      lock_until: null,
      last_sent_at: lastSentAt || isoNow(),
      created_at: isoNow(),
      updated_at: isoNow(),
    };
    const row = await this.insertAndFetch('email_otp_requests', payload);
    return mapEmailOtpRow(row);
  }

  async getEmailOtpRequestById(id) {
    await this.ensureInitialized();
    const row = await this.knex('email_otp_requests').where({ id }).first();
    return mapEmailOtpRow(row);
  }

  async findEmailOtpRequest(filters = {}) {
    await this.ensureInitialized();
    const query = this.knex('email_otp_requests');
    applyEmailOtpFilters(query, filters);
    query.orderBy('created_at', 'desc');
    const row = await query.first();
    return mapEmailOtpRow(row);
  }

  async updateEmailOtpRequest(id, updates = {}) {
    await this.ensureInitialized();
    const patch = { updated_at: isoNow() };
    if ('codeHash' in updates) {
      patch.code_hash = updates.codeHash;
    }
    if ('expiresAt' in updates) {
      patch.expires_at = updates.expiresAt;
    }
    if ('consumedAt' in updates) {
      patch.consumed_at = updates.consumedAt;
    }
    if ('failedAttempts' in updates) {
      patch.failed_attempts = updates.failedAttempts;
    }
    if ('maxAttempts' in updates) {
      patch.max_attempts = updates.maxAttempts;
    }
    if ('lockUntil' in updates) {
      patch.lock_until = updates.lockUntil;
    }
    if ('lastSentAt' in updates) {
      patch.last_sent_at = updates.lastSentAt;
    }
    if ('metadata' in updates) {
      patch.metadata_json = stringifyJson(updates.metadata);
    }
    await this.knex('email_otp_requests').where({ id }).update(patch);
    return this.getEmailOtpRequestById(id);
  }

  async incrementEmailOtpFailure(id, maxAttempts = 5, lockDurationMs = 0) {
    await this.ensureInitialized();
    return this.knex.transaction(async (trx) => {
      const row = await trx('email_otp_requests').where({ id }).forUpdate().first();
      if (!row) {
        return null;
      }
      const current = mapEmailOtpRow(row);
      const attempts = (current.failed_attempts || 0) + 1;
      const threshold = Number.isInteger(current.max_attempts) ? current.max_attempts : maxAttempts;
      const shouldLock = Number.isInteger(threshold) && attempts >= threshold;
      const nextLock =
        shouldLock && lockDurationMs > 0
          ? new Date(Date.now() + lockDurationMs).toISOString()
          : current.lock_until || null;
      await trx('email_otp_requests').where({ id }).update({
        failed_attempts: attempts,
        lock_until: nextLock,
        updated_at: isoNow(),
      });
      const updated = await trx('email_otp_requests').where({ id }).first();
      return mapEmailOtpRow(updated);
    });
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
          status: 'active',
          deactivated_at: null,
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
      phone_number: null,
      created_at: isoNow(),
      status: 'active',
      deactivated_at: null,
    });

    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.info(`[setup] Created platform admin account ${email}.`);
    }
  }

  async deleteAllData() {
    await this.ensureInitialized();
    await this.knex.transaction(async (trx) => {
      await trx('email_otp_requests').del();
      await trx('user_mfa_trusted_devices').del();
      await trx('user_mfa_recovery_codes').del();
      await trx('tenant_admin_mfa_reset_logs').del();
      await trx('user_mfa_methods').del();
      await trx('password_resets').del();
      await trx('role_codes').del();
      await trx('payroll_records').del();
      await trx('work_sessions').del();
      await trx('users').del();
      await trx('tenants').del();
    });
  }

  async deleteTenantById(id) {
    await this.ensureInitialized();
    await this.knex('tenants').where({ id }).del();
  }

  async getWorkSessionsByUserOverlapping(userId, rangeStartIso, rangeEndIso) {
    await this.ensureInitialized();
    if (!rangeStartIso) {
      throw new Error('rangeStartIso must be provided.');
    }
    if (!rangeEndIso) {
      throw new Error('rangeEndIso must be provided.');
    }
    const rows = await this.knex('work_sessions')
      .where({ user_id: userId })
      .andWhere('start_time', '<', rangeEndIso)
      .andWhere((qb) => {
        qb.where('end_time', '>', rangeStartIso).orWhereNull('end_time');
      })
      .whereNull('archived_at')
      .orderBy('start_time', 'asc');
    return rows.map(normalizeRow);
  }

  async listRecentWorkSessionsByUser(userId, limit = 10) {
    await this.ensureInitialized();
    const rows = await this.knex('work_sessions')
      .where({ user_id: userId })
      .whereNull('archived_at')
      .orderBy('start_time', 'desc')
      .limit(limit);
    return rows.map(normalizeRow);
  }

  async listMfaMethodsByUser(userId) {
    await this.ensureInitialized();
    const rows = await this.knex('user_mfa_methods').where({ user_id: userId }).orderBy('type', 'asc');
    return rows.map(mapMfaRow);
  }

  async getMfaMethodByUserAndType(userId, type) {
    await this.ensureInitialized();
    const row = await this.knex('user_mfa_methods').where({ user_id: userId, type }).first();
    return mapMfaRow(row);
  }

  async getVerifiedMfaMethod(userId, type) {
    await this.ensureInitialized();
    const row = await this.knex('user_mfa_methods')
      .where({ user_id: userId, type, is_verified: true })
      .first();
    return mapMfaRow(row);
  }

  async createMfaMethod({ userId, type, secret = null, config = null, isVerified = false }) {
    await this.ensureInitialized();
    const payload = {
      user_id: userId,
      type,
      secret,
      config_json: config ? JSON.stringify(config) : null,
      is_verified: toDbBool(isVerified),
      verified_at: isVerified ? isoNow() : null,
      last_used_at: null,
      created_at: isoNow(),
      updated_at: isoNow(),
    };
    const row = await this.insertAndFetch('user_mfa_methods', payload);
    return mapMfaRow(row);
  }

  async restoreMfaMethod(userId, type, snapshot = {}) {
    await this.ensureInitialized();
    const payload = {
      user_id: userId,
      type,
      secret: snapshot.secret || null,
      config_json: snapshot.config ? JSON.stringify(snapshot.config) : null,
      is_verified: toDbBool(snapshot.is_verified),
      verified_at: snapshot.verified_at || null,
      last_used_at: snapshot.last_used_at || null,
      created_at: snapshot.created_at || isoNow(),
      updated_at: snapshot.updated_at || isoNow(),
    };
    const row = await this.insertAndFetch('user_mfa_methods', payload);
    return mapMfaRow(row);
  }

  async updateMfaMethod(id, updates = {}) {
    await this.ensureInitialized();
    const payload = {
      updated_at: isoNow(),
    };
    if (Object.prototype.hasOwnProperty.call(updates, 'secret')) {
      payload.secret = updates.secret;
    }
    if (Object.prototype.hasOwnProperty.call(updates, 'config')) {
      payload.config_json = updates.config ? JSON.stringify(updates.config) : null;
    }
    if (Object.prototype.hasOwnProperty.call(updates, 'isVerified')) {
      payload.is_verified = toDbBool(updates.isVerified);
      payload.verified_at = updates.isVerified ? isoNow() : null;
      if (!updates.isVerified) {
        payload.last_used_at = null;
      }
    }
    if (Object.prototype.hasOwnProperty.call(updates, 'verifiedAt')) {
      payload.verified_at = updates.verifiedAt;
    }
    if (Object.prototype.hasOwnProperty.call(updates, 'lastUsedAt')) {
      payload.last_used_at = updates.lastUsedAt;
    }
    await this.knex('user_mfa_methods').where({ id }).update(payload);
    const row = await this.knex('user_mfa_methods').where({ id }).first();
    return mapMfaRow(row);
  }

  async updateMfaFailureState(id, { reset = false, maxFailures = 5, lockDurationMs = 0 } = {}) {
    await this.ensureInitialized();
    return this.knex.transaction(async (trx) => {
      const row = await trx('user_mfa_methods').where({ id }).forUpdate().first();
      if (!row) {
        return null;
      }
      const method = mapMfaRow(row);
      const config =
        method && method.config && typeof method.config === 'object' ? { ...method.config } : {};
      if (reset) {
        config.failedAttempts = 0;
        config.lockUntil = null;
      } else {
        const attempts = Number.isFinite(config.failedAttempts) ? config.failedAttempts + 1 : 1;
        config.failedAttempts = attempts;
        if (attempts >= maxFailures && lockDurationMs > 0) {
          config.lockUntil = new Date(Date.now() + lockDurationMs).toISOString();
        }
      }
      await trx('user_mfa_methods')
        .where({ id })
        .update({
          config_json: stringifyJson(config),
          updated_at: isoNow(),
        });
      const updated = await trx('user_mfa_methods').where({ id }).first();
      return mapMfaRow(updated);
    });
  }

  async deleteMfaMethodsByUserAndType(userId, type) {
    await this.ensureInitialized();
    await this.knex('user_mfa_methods').where({ user_id: userId, type }).del();
  }

  async touchMfaMethodUsed(id) {
    await this.ensureInitialized();
    const timestamp = isoNow();
    await this.knex('user_mfa_methods').where({ id }).update({
      last_used_at: timestamp,
      updated_at: timestamp,
    });
  }

  async deleteRecoveryCodesByUser(userId) {
    await this.ensureInitialized();
    await this.knex('user_mfa_recovery_codes').where({ user_id: userId }).del();
  }

  async listRecoveryCodesByUser(userId) {
    await this.ensureInitialized();
    const rows = await this.knex('user_mfa_recovery_codes')
      .where({ user_id: userId })
      .orderBy('id', 'asc');
    return rows.map(normalizeRow);
  }

  async createRecoveryCodes(userId, codeHashes = []) {
    if (!Array.isArray(codeHashes) || codeHashes.length === 0) {
      return;
    }
    await this.ensureInitialized();
    const nowIso = isoNow();
    const records = codeHashes.map((codeHash) => ({
      user_id: userId,
      code_hash: codeHash,
      used_at: null,
      created_at: nowIso,
    }));
    await this.knex('user_mfa_recovery_codes').insert(records);
  }

  async findRecoveryCode(userId, codeHash) {
    await this.ensureInitialized();
    const row = await this.knex('user_mfa_recovery_codes')
      .where({ user_id: userId, code_hash: codeHash })
      .first();
    return normalizeRow(row);
  }

  async findUsableRecoveryCode(userId, codeHash) {
    await this.ensureInitialized();
    const row = await this.knex('user_mfa_recovery_codes')
      .where({ user_id: userId, code_hash: codeHash })
      .whereNull('used_at')
      .first();
    return normalizeRow(row);
  }

  async markRecoveryCodeUsed(id) {
    await this.ensureInitialized();
    await this.knex('user_mfa_recovery_codes').where({ id }).update({
      used_at: isoNow(),
    });
  }

  async restoreRecoveryCodes(userId, codes = []) {
    if (!Array.isArray(codes) || codes.length === 0) {
      return;
    }
    await this.ensureInitialized();
    const nowIso = isoNow();
    const payload = codes.map((code) => ({
      user_id: userId,
      code_hash: code.code_hash,
      used_at: code.used_at || null,
      created_at: code.created_at || nowIso,
    }));
    await this.knex('user_mfa_recovery_codes').insert(payload);
  }

  async createTrustedDevice({ userId, tokenHash, deviceInfo = null, expiresAt }) {
    await this.ensureInitialized();
    const payload = {
      user_id: userId,
      token_hash: tokenHash,
      device_info: deviceInfo,
      expires_at: expiresAt,
      last_used_at: null,
      created_at: isoNow(),
    };
    return this.insertAndFetch('user_mfa_trusted_devices', payload);
  }

  async getTrustedDeviceByToken(userId, tokenHash) {
    await this.ensureInitialized();
    const row = await this.knex('user_mfa_trusted_devices')
      .where({ user_id: userId, token_hash: tokenHash })
      .first();
    return normalizeRow(row);
  }

  async touchTrustedDevice(id) {
    await this.ensureInitialized();
    await this.knex('user_mfa_trusted_devices')
      .where({ id })
      .update({ last_used_at: isoNow() });
  }

  async deleteTrustedDeviceById(id) {
    await this.ensureInitialized();
    await this.knex('user_mfa_trusted_devices').where({ id }).del();
  }

  async deleteTrustedDevicesByUser(userId) {
    await this.ensureInitialized();
    await this.knex('user_mfa_trusted_devices').where({ user_id: userId }).del();
  }

  async createTenantAdminMfaResetLog({
    targetUserId,
    performedByUserId = null,
    reason,
    previousMethod = null,
    previousRecoveryCodes = [],
  }) {
    await this.ensureInitialized();
    const payload = {
      target_user_id: targetUserId,
      performed_by_user_id: performedByUserId,
      reason,
      previous_method_json: normalizeLogPayload(previousMethod),
      previous_recovery_codes_json: normalizeLogPayload(previousRecoveryCodes),
      created_at: isoNow(),
      rolled_back_at: null,
      rolled_back_by_user_id: null,
      rollback_reason: null,
    };
    return this.insertAndFetch('tenant_admin_mfa_reset_logs', payload);
  }

  async getLatestTenantAdminMfaResetLog(targetUserId) {
    await this.ensureInitialized();
    const row = await this.knex('tenant_admin_mfa_reset_logs')
      .where({ target_user_id: targetUserId })
      .orderBy('created_at', 'desc')
      .first();
    return normalizeRow(row);
  }

  async markTenantAdminMfaResetRolledBack(logId, rollbackReason, rolledBackByUserId = null) {
    await this.ensureInitialized();
    await this.knex('tenant_admin_mfa_reset_logs')
      .where({ id: logId })
      .update({
        rolled_back_at: isoNow(),
        rolled_back_by_user_id: rolledBackByUserId,
        rollback_reason: rollbackReason || null,
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
