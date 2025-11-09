const TABLE_NAME = 'user_mfa_methods';

async function createMfaTable(knex) {
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
    table.string('type', 32).notNullable();
    table.text('secret');
    table.text('config_json');
    table.boolean('is_verified').notNullable().defaultTo(false);
    table.string('verified_at');
    table.string('last_used_at');
    table.string('created_at').notNullable();
    table.string('updated_at').notNullable();
    table.unique(['user_id', 'type']);
    table.index(['user_id', 'is_verified'], 'user_mfa_methods_user_verified_idx');
  });
}

exports.up = async (knex) => {
  await createMfaTable(knex);
};

exports.down = async (knex) => {
  await knex.schema.dropTableIfExists(TABLE_NAME);
};
