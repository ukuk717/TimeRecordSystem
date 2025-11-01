async function renameExpireColumn(knex) {
  const hasTable = await knex.schema.hasTable('sessions');
  if (!hasTable) {
    return;
  }
  const hasExpire = await knex.schema.hasColumn('sessions', 'expire');
  const hasExpired = await knex.schema.hasColumn('sessions', 'expired');

  if (hasExpire && !hasExpired) {
    await knex.schema.alterTable('sessions', (table) => {
      table.renameColumn('expire', 'expired');
    });
    return;
  }

  if (!hasExpired) {
    await knex.schema.alterTable('sessions', (table) => {
      table.timestamp('expired').notNullable().defaultTo(knex.fn.now());
    });
  }
}

exports.up = async (knex) => {
  await renameExpireColumn(knex);
};

exports.down = async (knex) => {
  const hasTable = await knex.schema.hasTable('sessions');
  if (!hasTable) {
    return;
  }
  const hasExpire = await knex.schema.hasColumn('sessions', 'expire');
  const hasExpired = await knex.schema.hasColumn('sessions', 'expired');
  if (hasExpired && !hasExpire) {
    await knex.schema.alterTable('sessions', (table) => {
      table.renameColumn('expired', 'expire');
    });
  }
};
