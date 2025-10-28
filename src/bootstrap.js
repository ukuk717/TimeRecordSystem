const { ensureDefaultPlatformAdmin } = require('./db');

let initialized = false;

function initializeApp() {
  if (initialized) {
    return;
  }
  ensureDefaultPlatformAdmin();
  initialized = true;
}

module.exports = {
  initializeApp,
};
