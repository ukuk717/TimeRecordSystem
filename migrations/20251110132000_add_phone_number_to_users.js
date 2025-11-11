const TABLE_NAME = 'users';
const COLUMN_NAME = 'phone_number';

exports.up = async (knex) => {
  const hasColumn = await knex.schema.hasColumn(TABLE_NAME, COLUMN_NAME);
  if (hasColumn) {
    return;
  }
  await knex.schema.alterTable(TABLE_NAME, (table) => {
    table.string(COLUMN_NAME, 32);
  });
};

exports.down = async (knex) => {
  const hasColumn = await knex.schema.hasColumn(TABLE_NAME, COLUMN_NAME);
  if (!hasColumn) {
    return;
  }
  await knex.schema.alterTable(TABLE_NAME, (table) => {
    table.dropColumn(COLUMN_NAME);
  });
};
