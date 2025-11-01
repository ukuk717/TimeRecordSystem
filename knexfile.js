const path = require('path');
const { buildConnectionConfig } = require('./src/database/knexClient');

function createConfig() {
  return buildConnectionConfig();
}

function fallbackSqliteConfig() {
  return {
    client: 'sqlite3',
    connection: { filename: ':memory:' },
    useNullAsDefault: true,
    migrations: {
      directory: path.resolve(__dirname, 'migrations'),
      tableName: process.env.DB_MIGRATIONS_TABLE || 'knex_migrations',
      loadExtensions: ['.js'],
    },
  };
}

function safeConfig() {
  try {
    return createConfig();
  } catch (error) {
    if (process.env.NODE_ENV === 'test') {
      return fallbackSqliteConfig();
    }
    throw error;
  }
}

module.exports = {
  development: safeConfig(),
  production: safeConfig(),
  test: safeConfig(),
};
