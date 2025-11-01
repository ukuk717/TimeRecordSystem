/* eslint-disable camelcase */
function getClient(knex) {
  return knex.client && knex.client.config ? knex.client.config.client : null;
}

async function createIndexes(knex, tableName, indexes) {
  const client = getClient(knex);
  if (client === 'sqlite3') {
    // eslint-disable-next-line no-restricted-syntax
    for (const [indexName, columns] of indexes) {
      const quotedColumns = columns.map((column) => `"${column.replace(/"/g, '""')}"`).join(', ');
      // eslint-disable-next-line no-await-in-loop
      await knex.raw(`CREATE INDEX IF NOT EXISTS "${indexName}" ON "${tableName}" (${quotedColumns})`);
    }
    return;
  }

  // eslint-disable-next-line no-restricted-syntax
  for (const [indexName, columns] of indexes) {
    // eslint-disable-next-line no-await-in-loop
    const exists =
      typeof knex.schema.hasIndex === 'function' ? await knex.schema.hasIndex(tableName, indexName) : false;
    if (!exists) {
      // eslint-disable-next-line no-await-in-loop
      await knex.schema.alterTable(tableName, (table) => {
        table.index(columns, indexName);
      });
    }
  }
}

exports.up = async (knex) => {
  const hasTable = await knex.schema.hasTable('payroll_records');
  if (!hasTable) {
    await knex.schema.createTable('payroll_records', (table) => {
      table.increments('id').primary();
      table
        .integer('tenant_id')
        .unsigned()
        .notNullable()
        .references('id')
        .inTable('tenants')
        .onDelete('CASCADE');
      table
        .integer('employee_id')
        .unsigned()
        .notNullable()
        .references('id')
        .inTable('users')
        .onDelete('CASCADE');
      table
        .integer('uploaded_by')
        .unsigned()
        .references('id')
        .inTable('users')
        .onDelete('SET NULL');
      table.string('original_file_name').notNullable();
      table.string('stored_file_path').notNullable();
      table.string('mime_type');
      table.integer('file_size');
      table.string('sent_on').notNullable(); // yyyy-MM-dd (tenant timezone)
      table.string('sent_at').notNullable(); // ISO8601 UTC
      table.string('created_at').notNullable();
    });
  }

  await createIndexes(knex, 'payroll_records', [
    ['payroll_records_tenant_idx', ['tenant_id']],
    ['payroll_records_employee_idx', ['employee_id']],
    ['payroll_records_sent_on_idx', ['sent_on']],
  ]);
};

exports.down = async (knex) => {
  await knex.schema.dropTableIfExists('payroll_records');
};

