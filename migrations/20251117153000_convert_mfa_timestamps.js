const ISO_8601_UTC = 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"';
const SOURCE_STRING = 'string';
const SOURCE_TIMESTAMP = 'timestamp_without_tz';

const TABLE_SPECS = [
  {
    name: 'user_mfa_methods',
    columns: [
      { name: 'verified_at', nullable: true, source: SOURCE_STRING },
      { name: 'last_used_at', nullable: true, source: SOURCE_STRING },
      { name: 'created_at', nullable: false, source: SOURCE_STRING },
      { name: 'updated_at', nullable: false, source: SOURCE_STRING },
    ],
  },
  {
    name: 'user_mfa_recovery_codes',
    columns: [
      { name: 'used_at', nullable: true, source: SOURCE_STRING },
      { name: 'created_at', nullable: false, source: SOURCE_STRING },
    ],
  },
  {
    name: 'user_mfa_trusted_devices',
    columns: [
      { name: 'expires_at', nullable: false, source: SOURCE_STRING },
      { name: 'last_used_at', nullable: true, source: SOURCE_STRING },
      { name: 'created_at', nullable: false, source: SOURCE_STRING },
    ],
  },
  {
    name: 'tenant_admin_mfa_reset_logs',
    columns: [
      { name: 'created_at', nullable: false, source: SOURCE_TIMESTAMP, defaultToNow: true },
      { name: 'rolled_back_at', nullable: true, source: SOURCE_TIMESTAMP },
    ],
  },
];

const POSTGRES_CLIENTS = new Set(['pg', 'postgres', 'postgresql']);

function isPostgres(knex) {
  const client =
    (knex && knex.client && (knex.client.config && knex.client.config.client)) ||
    (knex && knex.client && knex.client.dialect);
  if (!client) {
    return false;
  }
  return POSTGRES_CLIENTS.has(String(client).toLowerCase());
}

function wrapIdentifier(knex, identifier) {
  if (knex && knex.client && typeof knex.client.wrapIdentifier === 'function') {
    return knex.client.wrapIdentifier(identifier);
  }
  return `"${identifier.replace(/"/g, '""')}"`;
}

async function convertColumnToTimestamptzPostgres(knex, tableName, columnSpec) {
  const tableId = wrapIdentifier(knex, tableName);
  const columnId = wrapIdentifier(knex, columnSpec.name);
  const usingExpr =
    columnSpec.source === SOURCE_STRING
      ? `NULLIF(${columnId}, '')::timestamptz`
      : `${columnId} AT TIME ZONE 'UTC'`;
  await knex.raw(`ALTER TABLE ${tableId} ALTER COLUMN ${columnId} DROP DEFAULT`);
  await knex.raw(
    `ALTER TABLE ${tableId} ALTER COLUMN ${columnId} TYPE TIMESTAMPTZ USING (${usingExpr})`
  );
  if (columnSpec.nullable) {
    await knex.raw(`ALTER TABLE ${tableId} ALTER COLUMN ${columnId} DROP NOT NULL`);
  } else {
    await knex.raw(`ALTER TABLE ${tableId} ALTER COLUMN ${columnId} SET NOT NULL`);
  }
  if (columnSpec.defaultToNow) {
    await knex.raw(`ALTER TABLE ${tableId} ALTER COLUMN ${columnId} SET DEFAULT NOW()`);
  } else {
    await knex.raw(`ALTER TABLE ${tableId} ALTER COLUMN ${columnId} DROP DEFAULT`);
  }
}

async function revertColumnFromTimestamptzPostgres(knex, tableName, columnSpec) {
  const tableId = wrapIdentifier(knex, tableName);
  const columnId = wrapIdentifier(knex, columnSpec.name);
  const targetType =
    columnSpec.source === SOURCE_TIMESTAMP ? 'TIMESTAMP WITHOUT TIME ZONE' : 'VARCHAR(255)';
  const usingExpr =
    columnSpec.source === SOURCE_TIMESTAMP
      ? `${columnId} AT TIME ZONE 'UTC'`
      : `to_char(${columnId} AT TIME ZONE 'UTC', '${ISO_8601_UTC}')`;
  await knex.raw(`ALTER TABLE ${tableId} ALTER COLUMN ${columnId} DROP DEFAULT`);
  await knex.raw(
    `ALTER TABLE ${tableId} ALTER COLUMN ${columnId} TYPE ${targetType} USING (${usingExpr})`
  );
  if (columnSpec.nullable) {
    await knex.raw(`ALTER TABLE ${tableId} ALTER COLUMN ${columnId} DROP NOT NULL`);
  } else {
    await knex.raw(`ALTER TABLE ${tableId} ALTER COLUMN ${columnId} SET NOT NULL`);
  }
  if (columnSpec.defaultToNow) {
    await knex.raw(`ALTER TABLE ${tableId} ALTER COLUMN ${columnId} SET DEFAULT NOW()`);
  } else {
    await knex.raw(`ALTER TABLE ${tableId} ALTER COLUMN ${columnId} DROP DEFAULT`);
  }
}

async function runPostgresMigration(knex, direction) {
  await knex.transaction(async (trx) => {
    for (const table of TABLE_SPECS) {
      for (const column of table.columns) {
        if (direction === 'up') {
          // eslint-disable-next-line no-await-in-loop
          await convertColumnToTimestamptzPostgres(trx, table.name, column);
        } else {
          // eslint-disable-next-line no-await-in-loop
          await revertColumnFromTimestamptzPostgres(trx, table.name, column);
        }
      }
    }
  });
}

exports.up = async (knex) => {
  if (isPostgres(knex)) {
    await runPostgresMigration(knex, 'up');
    return;
  }
  throw new Error('20251117153000_convert_mfa_timestamps requires PostgreSQL.');
};

exports.down = async (knex) => {
  if (isPostgres(knex)) {
    await runPostgresMigration(knex, 'down');
    return;
  }
  throw new Error('20251117153000_convert_mfa_timestamps requires PostgreSQL.');
};
