const knex = require('knex');

let knexInstance;

function toNumber(value, fallback) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toBoolean(value, fallback = false) {
  if (value === undefined || value === null) {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(normalized)) {
    return false;
  }
  return fallback;
}

function resolveClientName(provider) {
  const normalized = (provider || '').toLowerCase();
  if (!normalized || normalized === 'postgres' || normalized === 'postgresql' || normalized === 'pg') {
    return 'pg';
  }
  if (normalized === 'mysql' || normalized === 'mysql2') {
    return 'mysql2';
  }
  if (normalized === 'sqlite' || normalized === 'sqlite3') {
    return 'sqlite3';
  }
  throw new Error(`Unsupported DB_PROVIDER "${provider}". Use postgres, mysql, or sqlite.`);
}

function buildConnectionConfig() {
  const explicitUrl = process.env.DATABASE_URL;
  const providerName = (() => {
    if (process.env.DB_PROVIDER) {
      return process.env.DB_PROVIDER;
    }
    if (explicitUrl) {
      if (explicitUrl.startsWith('postgres')) {
        return 'postgres';
      }
      if (explicitUrl.startsWith('mysql')) {
        return 'mysql';
      }
      if (explicitUrl.startsWith('sqlite')) {
        return 'sqlite';
      }
    }
    return undefined;
  })();
  const provider = resolveClientName(providerName);

  if (explicitUrl) {
    return {
      client: provider,
      connection: explicitUrl,
    };
  }

  if (provider === 'sqlite3') {
    const filename = process.env.SQLITE_FILENAME || ':memory:';
    return {
      client: 'sqlite3',
      connection: {
        filename,
      },
      useNullAsDefault: true,
    };
  }

  const host = process.env.DB_HOST;
  const port = toNumber(process.env.DB_PORT, provider === 'pg' ? 5432 : 3306);
  const database = process.env.DB_NAME;
  const user = process.env.DB_USER;
  const password = process.env.DB_PASSWORD;

  if (!host || !database || !user) {
    throw new Error('DB_HOST, DB_NAME, and DB_USER must be configured for SQL providers.');
  }

  const sslEnabled = toBoolean(process.env.DB_SSL, provider === 'pg');
  const rejectUnauthorized = toBoolean(process.env.DB_SSL_REJECT_UNAUTHORIZED, true);

  return {
    client: provider,
    connection: {
      host,
      port,
      database,
      user,
      password,
      ssl: sslEnabled
        ? {
            rejectUnauthorized,
            ca: process.env.DB_CA_CERT || undefined,
          }
        : undefined,
    },
    pool: {
      min: toNumber(process.env.DB_POOL_MIN, 0),
      max: toNumber(process.env.DB_POOL_MAX, provider === 'pg' ? 10 : 5),
      idleTimeoutMillis: toNumber(process.env.DB_POOL_IDLE_TIMEOUT_MS, 30000),
    },
    log: {
      warn(message) {
        if (toBoolean(process.env.DB_DEBUG_WARNINGS, false)) {
          // eslint-disable-next-line no-console
          console.warn('[db:warn]', message);
        }
      },
      error(message) {
        // eslint-disable-next-line no-console
        console.error('[db:error]', message);
      },
    },
    debug: toBoolean(process.env.DB_DEBUG, false),
  };
}

function getKnexClient() {
  if (!knexInstance) {
    const config = buildConnectionConfig();
    knexInstance = knex(config);
  }
  return knexInstance;
}

async function destroyKnexClient() {
  if (knexInstance) {
    await knexInstance.destroy();
    knexInstance = null;
  }
}

module.exports = {
  getKnexClient,
  destroyKnexClient,
};
