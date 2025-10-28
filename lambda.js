process.env.TZ = process.env.APP_TIMEZONE || 'Asia/Tokyo';

const serverless = require('serverless-http');
const app = require('./src/app');
const { initializeApp } = require('./src/bootstrap');

let handlerPromise = null;

async function getHandler() {
  if (!handlerPromise) {
    handlerPromise = (async () => {
      await initializeApp();
      return serverless(app);
    })();
  }
  return handlerPromise;
}

module.exports.handler = async (event, context) => {
  const handler = await getHandler();
  // Lambda の推奨設定：コネクションプールをウォームに保つ
  if (context) {
    // eslint-disable-next-line no-param-reassign
    context.callbackWaitsForEmptyEventLoop = false;
  }
  return handler(event, context);
};

module.exports.app = app;
