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
      await this.ensureTables();
      await this.ensureIndexes();
      this.initialized = true;
      this.initializingPromise = null;
    })();
    await this.initializingPromise;
  }

  async ensureTables() {
    const { knex } = this;

    const hasTenants = await knex.schema.hasTable('tenants');
    if (!hasTenants) {
      await knex.schema.createTable('tenants', (table) => {
        table.increments('id').primary();
        table.string('tenant_uid', 64).notNullable().unique();
        table.string('name');
        table.string('contact_email');
        table.string('created_at').notNullable();
      });
    }

    const hasUsers = await knex.schema.hasTable('users');
    if (!hasUsers) {
      await knex.schema.createTable('users', (table) => {
        table.increments('id').primary();
        table
          .integer('tenant_id')
          .unsigned()
          .references('id')
          .inTable('tenants')
          .onDelete('SET NULL');
        table.string('username').notNullable();
        table.string('email').notNullable().unique();
        table.string('password_hash').notNullable();
        table.string('role', 32).notNullable();
        table.boolean('must_change_password').notNullable().defaultTo(false);
        table.integer('failed_attempts').notNullable().defaultTo(0);
        table.string('locked_until');
        table.string('first_name');
        table.string('last_name');
        table.string('created_at').notNullable();
      });
    }

    const hasRoleCodes = await knex.schema.hasTable('role_codes');
    if (!hasRoleCodes) {
      await knex.schema.createTable('role_codes', (table) => {
        table.increments('id').primary();
        table
          .integer('tenant_id')
          .unsigned()
          .notNullable()
          .references('id')
          .inTable('tenants')
          .onDelete('CASCADE');
        table.string('code', 64).notNullable().unique();
        table.string('expires_at');
        table.integer('max_uses');
        table.integer('usage_count').notNullable().defaultTo(0);
        table.boolean('is_disabled').notNullable().defaultTo(false);
        table
          .integer('created_by')
          .unsigned()
          .references('id')
          .inTable('users')
          .onDelete('SET NULL');
        table.string('created_at').notNullable();
      });
    }

    const hasPasswordResets = await knex.schema.hasTable('password_resets');
    if (!hasPasswordResets) {
      await knex.schema.createTable('password_resets', (table) => {
        table.increments('id').primary();
        table
          .integer('user_id')
          .unsigned()
          .notNullable()
          .references('id')
          .inTable('users')
          .onDelete('CASCADE');
        table.string('token', 128).notNullable().unique();
        table.string('expires_at').notNullable();
        table.string('used_at');
        table.string('created_at').notNullable();
      });
    }

    const hasWorkSessions = await knex.schema.hasTable('work_sessions');
    if (!hasWorkSessions) {
      await knex.schema.createTable('work_sessions', (table) => {
        table.increments('id').primary();
        table
          .integer('user_id')
          .unsigned()
          .notNullable()
          .references('id')
          .inTable('users')
          .onDelete('CASCADE');
        table.string('start_time').notNullable();
        table.string('end_time');
        table.string('created_at').notNullable();
      });
    }
  }

  async ensureIndexes() {
    const { knex } = this;
    const indexChecks = [
      ['users', 'users_role_idx', ['role']],
      ['users', 'users_email_idx', ['email']],
      ['users', 'users_tenant_role_idx', ['tenant_id', 'role']],
      ['role_codes', 'role_codes_tenant_idx', ['tenant_id']],
      ['role_codes', 'role_codes_code_idx', ['code']],
      ['password_resets', 'password_resets_token_idx', ['token']],
      ['work_sessions', 'work_sessions_user_start_idx', ['user_id', 'start_time']],
    ];

    // eslint-disable-next-line no-restricted-syntax
    for (const [table, indexName, columns] of indexChecks) {
      // eslint-disable-next-line no-await-in-loop
      const exists = await knex.schema.hasIndex(table, indexName);
      if (!exists) {
        // eslint-disable-next-line no-await-in-loop
        await knex.schema.alterTable(table, (tbl) => {
          tbl.index(columns, indexName);
        });
      }
    }
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

  async createTenant({ tenant_uid, name = null, contact_email = null }) {
    await this.ensureInitialized();
    const payload = {
      tenant_uid,
      name,
      contact_email,
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
