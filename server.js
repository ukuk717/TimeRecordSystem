process.env.TZ = process.env.APP_TIMEZONE || 'Asia/Tokyo';

const app = require('./src/app');
const { ensureDefaultPlatformAdmin } = require('./src/db');

const PORT = process.env.PORT || 3000;

ensureDefaultPlatformAdmin();

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`TimeRecordSystem server is running on http://localhost:${PORT}`);
});
