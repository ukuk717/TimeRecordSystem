const TABLE_NAME = 'user_mfa_recovery_codes';

async function createRecoveryCodesTable(knex) {
  const hasTable = await knex.schema.hasTable(TABLE_NAME);
  if (hasTable) {
    return;
  }

  await knex.schema.createTable(TABLE_NAME, (table) => {
    table.increments('id').primary();
    table
      .integer('user_id')
      .unsigned()
      .notNullable()
      .references('id')
      .inTable('users')
      .onDelete('CASCADE');
    table.string('code_hash', 128).notNullable();
    table.string('used_at');
    table.string('created_at').notNullable();
    table.unique(['user_id', 'code_hash'], 'user_mfa_recovery_codes_unique_code');
    table.index(['user_id'], 'user_mfa_recovery_codes_user_idx');
  });
}

exports.up = async (knex) => {
  await createRecoveryCodesTable(knex);
};

exports.down = async (knex) => {
  await knex.schema.dropTableIfExists(TABLE_NAME);
};
