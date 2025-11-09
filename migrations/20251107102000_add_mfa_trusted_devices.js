const TABLE_NAME = 'user_mfa_trusted_devices';

async function createTrustedDevicesTable(knex) {
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
    table.string('token_hash', 128).notNullable().unique();
    table.string('device_info', 255);
    table.string('expires_at').notNullable();
    table.string('last_used_at');
    table.string('created_at').notNullable();
  });
}

exports.up = async (knex) => {
  await createTrustedDevicesTable(knex);
};

exports.down = async (knex) => {
  await knex.schema.dropTableIfExists(TABLE_NAME);
};
