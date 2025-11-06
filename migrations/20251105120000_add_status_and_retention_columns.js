/* eslint-disable camelcase */

async function addStatusColumns(knex, tableName, columns) {
  const hasStatus = await knex.schema.hasColumn(tableName, 'status');
  if (!hasStatus) {
    await knex.schema.alterTable(tableName, (table) => {
      table.string('status', 32).notNullable().defaultTo('active');
    });
  }

  const hasDeactivatedAt = await knex.schema.hasColumn(tableName, 'deactivated_at');
  if (!hasDeactivatedAt && columns.includes('deactivated_at')) {
    await knex.schema.alterTable(tableName, (table) => {
      table.string('deactivated_at');
    });
  }
}

exports.up = async (knex) => {
  await addStatusColumns(knex, 'users', ['deactivated_at']);
  await addStatusColumns(knex, 'tenants', ['deactivated_at']);

  const hasRetentionFlag = await knex.schema.hasColumn('payroll_records', 'archived_at');
  if (!hasRetentionFlag) {
    await knex.schema.alterTable('payroll_records', (table) => {
      table.string('archived_at');
    });
  }

  const hasWorkSessionArchive = await knex.schema.hasColumn('work_sessions', 'archived_at');
  if (!hasWorkSessionArchive) {
    await knex.schema.alterTable('work_sessions', (table) => {
      table.string('archived_at');
    });
  }

  const client = knex.client.config.client;
  if (client !== 'sqlite3' && typeof knex.schema.hasIndex === 'function') {
    const userStatusIndex = await knex.schema.hasIndex('users', 'users_status_idx');
    if (!userStatusIndex) {
      await knex.schema.alterTable('users', (table) => {
        table.index(['status'], 'users_status_idx');
      });
    }

    const tenantStatusIndex = await knex.schema.hasIndex('tenants', 'tenants_status_idx');
    if (!tenantStatusIndex) {
      await knex.schema.alterTable('tenants', (table) => {
        table.index(['status'], 'tenants_status_idx');
      });
    }

    const payrollArchiveIdx = await knex.schema.hasIndex(
      'payroll_records',
      'payroll_records_archived_idx'
    );
    if (!payrollArchiveIdx) {
      await knex.schema.alterTable('payroll_records', (table) => {
        table.index(['archived_at'], 'payroll_records_archived_idx');
      });
    }

    const workArchiveIdx = await knex.schema.hasIndex('work_sessions', 'work_sessions_archived_idx');
    if (!workArchiveIdx) {
      await knex.schema.alterTable('work_sessions', (table) => {
        table.index(['archived_at'], 'work_sessions_archived_idx');
      });
    }
  }
};

exports.down = async (knex) => {
  const hasUserStatus = await knex.schema.hasColumn('users', 'status');
  if (hasUserStatus) {
    await knex.schema.alterTable('users', (table) => {
      table.dropColumn('status');
    });
  }
  const hasUserDeactivated = await knex.schema.hasColumn('users', 'deactivated_at');
  if (hasUserDeactivated) {
    await knex.schema.alterTable('users', (table) => {
      table.dropColumn('deactivated_at');
    });
  }

  const hasTenantStatus = await knex.schema.hasColumn('tenants', 'status');
  if (hasTenantStatus) {
    await knex.schema.alterTable('tenants', (table) => {
      table.dropColumn('status');
    });
  }
  const hasTenantDeactivated = await knex.schema.hasColumn('tenants', 'deactivated_at');
  if (hasTenantDeactivated) {
    await knex.schema.alterTable('tenants', (table) => {
      table.dropColumn('deactivated_at');
    });
  }

  const hasPayrollArchive = await knex.schema.hasColumn('payroll_records', 'archived_at');
  if (hasPayrollArchive) {
    await knex.schema.alterTable('payroll_records', (table) => {
      table.dropColumn('archived_at');
    });
  }

  const hasWorkArchive = await knex.schema.hasColumn('work_sessions', 'archived_at');
  if (hasWorkArchive) {
    await knex.schema.alterTable('work_sessions', (table) => {
      table.dropColumn('archived_at');
    });
  }

  const client = knex.client.config.client;
  const canCheckIndex = typeof knex.schema.hasIndex === 'function';
  if (client !== 'sqlite3' && canCheckIndex) {
    if (await knex.schema.hasIndex('users', 'users_status_idx')) {
      await knex.schema.alterTable('users', (table) => {
        table.dropIndex(['status'], 'users_status_idx');
      });
    }
    if (await knex.schema.hasIndex('tenants', 'tenants_status_idx')) {
      await knex.schema.alterTable('tenants', (table) => {
        table.dropIndex(['status'], 'tenants_status_idx');
      });
    }
    if (await knex.schema.hasIndex('payroll_records', 'payroll_records_archived_idx')) {
      await knex.schema.alterTable('payroll_records', (table) => {
        table.dropIndex(['archived_at'], 'payroll_records_archived_idx');
      });
    }
    if (await knex.schema.hasIndex('work_sessions', 'work_sessions_archived_idx')) {
      await knex.schema.alterTable('work_sessions', (table) => {
        table.dropIndex(['archived_at'], 'work_sessions_archived_idx');
      });
    }
  }
};
