const { ensureDefaultPlatformAdmin, initializeDatabase } = require('./db');

let initPromise = null;

async function initializeApp() {
  if (initPromise) {
    return initPromise;
  }

  initPromise = (async () => {
    await initializeDatabase();
    await ensureDefaultPlatformAdmin();
  })();

  return initPromise;
}

module.exports = {
  initializeApp,
};
