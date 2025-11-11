const TABLE_NAME = 'tenant_admin_mfa_reset_logs';

async function createTable(knex) {
  const exists = await knex.schema.hasTable(TABLE_NAME);
  if (exists) {
    return;
  }
  await knex.schema.createTable(TABLE_NAME, (table) => {
    table.increments('id').primary();
    table
      .integer('target_user_id')
      .unsigned()
      .notNullable()
      .references('id')
      .inTable('users')
      .onDelete('CASCADE');
    table
      .integer('performed_by_user_id')
      .unsigned()
      .references('id')
      .inTable('users')
      .onDelete('SET NULL');
    table.text('reason').notNullable();
    table.text('previous_method_json');
    table.text('previous_recovery_codes_json');
    table.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
    table.timestamp('rolled_back_at');
    table
      .integer('rolled_back_by_user_id')
      .unsigned()
      .references('id')
      .inTable('users')
      .onDelete('SET NULL');
    table.text('rollback_reason');
    table.index(['target_user_id', 'created_at'], 'tenant_admin_mfa_reset_logs_user_created_idx');
  });
}

exports.up = async (knex) => {
  await createTable(knex);
};

exports.down = async (knex) => {
  await knex.schema.dropTableIfExists(TABLE_NAME);
};
