const { createSqlRepository } = require('./sqlRepository');

let repositoryInstance;

function getRepository() {
  if (repositoryInstance) {
    return repositoryInstance;
  }

  const provider = (process.env.DB_PROVIDER || 'postgres').toLowerCase();

  if (provider === 'dynamodb') {
    throw new Error(
      'DB_PROVIDER=dynamodb はまだメインデータのリポジトリ実装がありません。RDS 用の postgres/mysql を指定してください。'
    );
  }

  repositoryInstance = createSqlRepository();
  return repositoryInstance;
}

module.exports = {
  getRepository,
};
