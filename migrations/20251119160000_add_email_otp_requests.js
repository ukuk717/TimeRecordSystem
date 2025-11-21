/* eslint-disable camelcase */

const TABLE_NAME = 'email_otp_requests';
const TENANT_COLUMN = 'require_employee_email_verification';

function addTenantFlag(knex) {
  return knex.schema.alterTable('tenants', (table) => {
    table.boolean(TENANT_COLUMN).notNullable().defaultTo(false);
  });
}

exports.up = async (knex) => {
  const hasTenantFlag = await knex.schema.hasColumn('tenants', TENANT_COLUMN);
  if (!hasTenantFlag) {
    await addTenantFlag(knex);
  }

  const hasTable = await knex.schema.hasTable(TABLE_NAME);
  if (!hasTable) {
    await knex.schema.createTable(TABLE_NAME, (table) => {
      table.increments('id').primary();
      table
        .integer('user_id')
        .unsigned()
        .notNullable()
        .references('id')
        .inTable('users')
        .onDelete('CASCADE');
      table
        .integer('tenant_id')
        .unsigned()
        .references('id')
        .inTable('tenants')
        .onDelete('SET NULL');
      table
        .integer('role_code_id')
        .unsigned()
        .references('id')
        .inTable('role_codes')
        .onDelete('SET NULL');
      table.string('purpose', 64).notNullable();
      table.string('target_email', 320).notNullable();
      table.string('code_hash', 128).notNullable();
      table.text('metadata_json');
      table.timestamp('expires_at', { useTz: true }).notNullable();
      table.timestamp('consumed_at', { useTz: true });
      table.integer('failed_attempts').notNullable().defaultTo(0);
      table.integer('max_attempts').notNullable().defaultTo(5);
      table.timestamp('lock_until', { useTz: true });
      table.timestamp('last_sent_at', { useTz: true }).notNullable();
      table.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.unique(['user_id', 'purpose']);
      table.index(['purpose', 'target_email'], 'email_otp_requests_purpose_email_idx');
    });
  }
};

exports.down = async (knex) => {
  const hasTable = await knex.schema.hasTable(TABLE_NAME);
  if (hasTable) {
    await knex.schema.dropTable(TABLE_NAME);
  }

  const hasTenantFlag = await knex.schema.hasColumn('tenants', TENANT_COLUMN);
  if (hasTenantFlag) {
    await knex.schema.alterTable('tenants', (table) => {
      table.dropColumn(TENANT_COLUMN);
    });
  }
};
