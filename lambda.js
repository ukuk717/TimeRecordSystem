process.env.TZ = process.env.APP_TIMEZONE || 'Asia/Tokyo';

const serverless = require('serverless-http');
const app = require('./src/app');
const { initializeApp } = require('./src/bootstrap');

initializeApp();

const serverlessHandler = serverless(app);

module.exports.handler = async (event, context) => serverlessHandler(event, context);
module.exports.app = app;
