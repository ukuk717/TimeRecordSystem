/* eslint-disable camelcase */
async function ensureTables(knex) {
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

async function ensureIndexes(knex) {
  const indexChecks = [
    ['users', 'users_role_idx', ['role']],
    ['users', 'users_email_idx', ['email']],
    ['users', 'users_tenant_role_idx', ['tenant_id', 'role']],
    ['role_codes', 'role_codes_tenant_idx', ['tenant_id']],
    ['role_codes', 'role_codes_code_idx', ['code']],
    ['password_resets', 'password_resets_token_idx', ['token']],
    ['work_sessions', 'work_sessions_user_start_idx', ['user_id', 'start_time']],
  ];

  const client = knex.client.config.client;

  // eslint-disable-next-line no-restricted-syntax
  for (const [table, indexName, columns] of indexChecks) {
    if (client === 'sqlite3') {
      const quotedColumns = columns
        .map((column) => `"${column.replace(/"/g, '""')}"`)
        .join(', ');
      // eslint-disable-next-line no-await-in-loop
      await knex.raw(`CREATE INDEX IF NOT EXISTS "${indexName}" ON "${table}" (${quotedColumns})`);
      // eslint-disable-next-line no-continue
      continue;
    }

    const hasIndexFn = typeof knex.schema.hasIndex === 'function' ? knex.schema.hasIndex.bind(knex.schema) : null;
    let exists = false;
    if (hasIndexFn) {
      // eslint-disable-next-line no-await-in-loop
      exists = await hasIndexFn(table, indexName);
    }
    if (!exists) {
      // eslint-disable-next-line no-await-in-loop
      await knex.schema.alterTable(table, (tbl) => {
        tbl.index(columns, indexName);
      });
    }
  }
}

exports.up = async (knex) => {
  await ensureTables(knex);
  await ensureIndexes(knex);
};

exports.down = async (knex) => {
  await knex.schema.dropTableIfExists('work_sessions');
  await knex.schema.dropTableIfExists('password_resets');
  await knex.schema.dropTableIfExists('role_codes');
  await knex.schema.dropTableIfExists('users');
  await knex.schema.dropTableIfExists('tenants');
};
