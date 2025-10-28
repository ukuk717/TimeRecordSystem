process.env.TZ = process.env.APP_TIMEZONE || 'Asia/Tokyo';

let app;
try {
  // eslint-disable-next-line global-require
  app = require('./src/app');
} catch (error) {
  // eslint-disable-next-line no-console
  console.error('[bootstrap] Failed to load application.', error);
  process.exit(1);
}
const { initializeApp } = require('./src/bootstrap');

const PORT = process.env.PORT || 3000;

(async () => {
  try {
    await initializeApp();
    app.listen(PORT, () => {
      // eslint-disable-next-line no-console
      console.log('TimeRecordSystem server is running on http://localhost:' + PORT);
    });
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error('[bootstrap] Failed to initialize server.', error);
    process.exit(1);
  }
})();
