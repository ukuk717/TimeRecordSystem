const express = require('express');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const crypto = require('crypto');
const session = require('express-session');
const Tokens = require('csrf');
const multer = require('multer');
const XlsxPopulate = require('xlsx-populate');

const {
  getSqlClient,
  createTenant,
  getTenantById,
  getTenantByUid,
  listTenants,
  updateTenantStatus,
  createUser,
  updateUserPassword,
  setMustChangePassword,
  getUserByEmail,
  getUserById,
  listTenantAdmins,
  getAllEmployeesByTenant,
  getAllEmployeesByTenantIncludingInactive,
  createWorkSession,
  closeWorkSession,
  createWorkSessionWithEnd,
  updateWorkSessionTimes,
  getOpenWorkSession,
  getWorkSessionsByUserBetween,
  getAllWorkSessionsByUser,
  getWorkSessionsByUserOverlapping,
  listRecentWorkSessionsByUser,
  getWorkSessionById,
  deleteWorkSession,
  recordLoginFailure,
  resetLoginFailures,
  updateUserStatus,
  createRoleCode,
  getRoleCodeByCode,
  getRoleCodeById,
  listRoleCodesByTenant,
  incrementRoleCodeUsage,
  disableRoleCode,
  createPasswordResetToken,
  getPasswordResetToken,
  consumePasswordResetToken,
  createPayrollRecord,
  listPayrollRecordsByTenant,
  listPayrollRecordsByEmployee,
  getPayrollRecordById,
  getLatestPayrollRecordForDate,
  deleteTenantById,
  listMfaMethodsByUser,
  getMfaMethodByUserAndType,
  getVerifiedMfaMethod,
  createMfaMethod,
  restoreMfaMethod,
  updateMfaMethod,
  deleteMfaMethodsByUserAndType,
  touchMfaMethodUsed,
  deleteRecoveryCodesByUser,
  createRecoveryCodes,
  listRecoveryCodesByUser,
  restoreRecoveryCodes,
  findUsableRecoveryCode,
  markRecoveryCodeUsed,
  createTrustedDevice,
  getTrustedDeviceByToken,
  touchTrustedDevice,
  deleteTrustedDeviceById,
  deleteTrustedDevicesByUser,
  createTenantAdminMfaResetLog,
  getLatestTenantAdminMfaResetLog,
  markTenantAdminMfaResetRolledBack,
} = require('./db');
const {
  validatePassword,
  generateInitialAdminPassword,
  hashPassword,
  comparePassword,
  PASSWORD_MIN_LENGTH,
} = require('./services/userService');
const {
  getUserDailySummary,
  getUserMonthlySummary,
  getUserMonthlyDetailedSessions,
  getMonthlySummaryForAllEmployees,
} = require('./services/reportService');
const {
  formatDateTime,
  formatMinutesToHM,
  getMonthRange,
  toZonedDateTime,
  dateKey,
  diffMinutes,
  formatForDateTimeInput,
  parseDateTimeInput,
  formatDateKey,
} = require('./utils/time');
const {
  MFA_TYPES,
  MFA_CHANNELS,
  getMfaIssuer,
  generateTotpSecret,
  buildTotpKeyUri,
  verifyTotpToken,
  generateQrCodeDataUrl,
  getMfaChannelLabel,
  generateRecoveryCodes,
  hashRecoveryCode,
  normalizeRecoveryCodeInput,
} = require('./services/mfaService');

const app = express();
app.set('trust proxy', 1);
const isTestEnv = process.env.NODE_ENV === 'test';
const tokens = new Tokens({ saltLength: 16, secretLength: 32 });

function resolveBaseUrl() {
  const fallback = `http://localhost:${process.env.PORT || 3000}`;
  const candidate = process.env.APP_BASE_URL || fallback;
  try {
    const parsed = new URL(candidate);
    if (!parsed.protocol || (parsed.protocol !== 'http:' && parsed.protocol !== 'https:')) {
      throw new Error('Only http and https protocols are supported.');
    }
    return parsed;
  } catch (error) {
    if (!isTestEnv) {
      // eslint-disable-next-line no-console
      console.warn(`[config] Invalid APP_BASE_URL "${candidate}". Falling back to ${fallback}.`, error);
    }
    return new URL(fallback);
  }
}

const appBaseUrl = resolveBaseUrl();
const baseHostname = appBaseUrl.hostname.toLowerCase();
const allowedHostnames = (() => {
  const defaults = new Set(['localhost', '127.0.0.1', '[::1]']);
  if (baseHostname) {
    defaults.add(baseHostname);
  }
  const configured = (process.env.ALLOWED_HOSTS || '')
    .split(',')
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
  configured.forEach((host) => defaults.add(host));
  return Array.from(defaults);
})();

const OVERLAP_ERROR_MESSAGE =
  '他の勤怠記録と時間が重複しています。修正対象の時間帯を見直してください。';
const LOGIN_FAILURE_LIMIT = 5;
const LOGIN_LOCK_MINUTES = 15;
const ROLE_CODE_LENGTH = 16;
const ROLE_CODE_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ROLES = {
  PLATFORM: 'platform_admin',
  TENANT: 'tenant_admin',
  EMPLOYEE: 'employee',
};
const MFA_CHALLENGE_TTL_MS = 10 * 60 * 1000;
const MFA_SETTINGS_PATH = '/password/change#mfa';
const MFA_ISSUER = getMfaIssuer();
const MFA_TRUST_COOKIE_NAME = 'trs_dev';
const MFA_TRUST_DURATION_DAYS = Number.parseInt(process.env.MFA_TRUST_TTL_DAYS || '30', 10) || 30;
const MFA_TRUST_DURATION_MS = MFA_TRUST_DURATION_DAYS * 24 * 60 * 60 * 1000;
const TRUSTED_DEVICE_TOKEN_BYTES = 32;

const USER_STATUS = {
  ACTIVE: 'active',
  INACTIVE: 'inactive',
};

const TENANT_STATUS = {
  ACTIVE: 'active',
  INACTIVE: 'inactive',
};

const DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 12;
const DEFAULT_DATA_RETENTION_YEARS = 5;
const DATA_RETENTION_YEARS = Math.max(
  1,
  parsePositiveInt(process.env.DATA_RETENTION_YEARS, DEFAULT_DATA_RETENTION_YEARS)
);
const SESSION_YEAR_MIN = 2000;
const SESSION_YEAR_MAX = 2100;
const SESSION_YEAR_RANGE_MESSAGE = `${SESSION_YEAR_MIN}年から${SESSION_YEAR_MAX}年までの日時を入力してください。`;

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (Number.isFinite(parsed) && parsed > 0) {
    return parsed;
  }
  return fallback;
}

function parseBoolean(value, fallback = false) {
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

function safeParseJson(value, fallback = null) {
  if (typeof value !== 'string' || value.length === 0) {
    return fallback;
  }
  try {
    return JSON.parse(value);
  } catch (error) {
    return fallback;
  }
}

function snapshotMfaMethod(method) {
  if (!method) {
    return null;
  }
  return {
    secret: method.secret || null,
    config: method.config || null,
    is_verified: Boolean(method.is_verified),
    verified_at: method.verified_at || null,
    last_used_at: method.last_used_at || null,
    created_at: method.created_at || null,
    updated_at: method.updated_at || null,
  };
}

function snapshotRecoveryCodes(codes = []) {
  if (!Array.isArray(codes) || codes.length === 0) {
    return [];
  }
  return codes.map((code) => ({
    code_hash: code.code_hash,
    used_at: code.used_at || null,
    created_at: code.created_at || null,
  }));
}

function isSessionDateWithinAllowedRange(isoString) {
  if (!isoString) {
    return false;
  }
  const dt = toZonedDateTime(isoString);
  if (!dt || !dt.isValid) {
    return false;
  }
  return dt.year >= SESSION_YEAR_MIN && dt.year <= SESSION_YEAR_MAX;
}

function resolveSessionCookieSecure() {
  const raw = process.env.SESSION_COOKIE_SECURE;
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return 'auto';
  }
  const normalized = String(raw).trim().toLowerCase();
  if (normalized === 'auto') {
    return 'auto';
  }
  return parseBoolean(raw, false);
}

const configuredSessionTtlSeconds = parsePositiveInt(
  process.env.SESSION_TTL_SECONDS,
  DEFAULT_SESSION_TTL_SECONDS
);

const PROJECT_ROOT = path.resolve(__dirname, '..');
const PAYROLL_UPLOAD_ROOT = path.join(PROJECT_ROOT, 'data', 'payrolls');
const PAYROLL_ALLOWED_EXTENSIONS = new Set(['.xlsx', '.xlsm', '.xls', '.pdf']);
const PAYROLL_UPLOAD_FIELD = 'payrollFile';
const PAYROLL_MAX_UPLOAD_BYTES = parsePositiveInt(
  process.env.PAYROLL_MAX_UPLOAD_BYTES,
  20 * 1024 * 1024
);

function ensureDirectorySync(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

function buildPayrollRelativePath(tenantId, fileName) {
  return path.join('data', 'payrolls', String(tenantId), fileName);
}

function resolvePayrollAbsolutePath(storedPath) {
  const absolute = path.resolve(PROJECT_ROOT, storedPath);
  const relative = path.relative(PAYROLL_UPLOAD_ROOT, absolute);
  if (
    relative.startsWith('..') ||
    path.isAbsolute(relative) ||
    relative.includes('..\\') ||
    relative.includes('../')
  ) {
    throw new Error('Invalid payroll file path detected.');
  }
  return absolute;
}

const payrollStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      const tenantId = req.session?.user?.tenantId;
      if (!tenantId) {
        cb(new Error('テナント情報を取得できませんでした。'));
        return;
      }
      ensureDirectorySync(PAYROLL_UPLOAD_ROOT);
      const tenantDirectory = path.join(PAYROLL_UPLOAD_ROOT, String(tenantId));
      ensureDirectorySync(tenantDirectory);
      cb(null, tenantDirectory);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    const uniqueName = `${Date.now()}-${crypto.randomUUID()}${ext}`;
    cb(null, uniqueName);
  },
});

function validatePayrollExtension(fileName) {
  const ext = path.extname(fileName || '').toLowerCase();
  return PAYROLL_ALLOWED_EXTENSIONS.has(ext);
}

const uploadPayroll = multer({
  storage: payrollStorage,
  limits: {
    fileSize: PAYROLL_MAX_UPLOAD_BYTES,
  },
  fileFilter: (req, file, cb) => {
    if (!validatePayrollExtension(file.originalname)) {
      const error = new Error(
        `許可されていないファイル形式です。使用可能な拡張子: ${Array.from(
          PAYROLL_ALLOWED_EXTENSIONS
        ).join(', ')}`
      );
      error.code = 'UNSUPPORTED_PAYROLL_FILE';
      cb(error);
      return;
    }
    cb(null, true);
  },
});

async function removePayrollFileQuietly(filePath) {
  if (!filePath) {
    return;
  }
  try {
    await fsp.unlink(filePath);
  } catch (error) {
    if (error && error.code !== 'ENOENT' && !isTestEnv) {
      // eslint-disable-next-line no-console
      console.warn('[payroll] ファイル削除に失敗しました', { filePath, error });
    }
  }
}

function formatReadableBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) {
    return '';
  }
  if (bytes === 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  const display = idx === 0 ? Math.round(value) : value.toFixed(1);
  return `${display} ${units[idx]}`;
}

function createAsciiFallbackName(value) {
  const sanitized = value
    .replace(/["'\\]/g, '')
    .replace(/[;=]/g, '_')
    .replace(/[^\x20-\x7E]+/g, '_')
    .replace(/_+/g, '_')
    .trim();
  if (sanitized.length === 0) {
    return 'download';
  }
  return sanitized;
}

function applyContentDisposition(res, fileName, disposition = 'attachment') {
  const baseName = (fileName || 'payroll').toString().replace(/\r|\n/g, '');
  const fallbackName = createAsciiFallbackName(baseName);
  const encoded = encodeURIComponent(baseName);
  res.setHeader(
    'Content-Disposition',
    `${disposition}; filename="${fallbackName}"; filename*=UTF-8''${encoded}`
  );
}

function decodeUploadedFileName(fileName) {
  if (typeof fileName !== 'string' || fileName.length === 0) {
    return '';
  }
  const withoutNull = fileName.replace(/\0/g, '');
  try {
    return Buffer.from(withoutNull, 'latin1').toString('utf8');
  } catch (error) {
    return withoutNull;
  }
}

function loadSessionSecret() {
  const envSecret = (process.env.SESSION_SECRET || '').trim();
  if (envSecret) {
    return envSecret;
  }
  if (!isTestEnv) {
    // eslint-disable-next-line no-console
    console.warn('[session] SESSION_SECRET is not set; generating ephemeral runtime secret.');
  }
  return crypto.randomBytes(32).toString('hex');
}

function createSessionStore(secret) {
  const driver = (process.env.SESSION_STORE_DRIVER || 'knex').toLowerCase();
  if (driver === 'memory' || driver === 'in-memory') {
    if (!isTestEnv) {
      // eslint-disable-next-line no-console
      console.warn('[session] Using MemoryStore. Sessions will be lost when the Lambda container is recycled.');
    }
    return new session.MemoryStore();
  }

  if (driver === 'dynamodb') {
    // Lazy-require to avoid unnecessary dependency cost when譛ｪ菴ｿ逕ｨ.
    // eslint-disable-next-line global-require
    const DynamoDBStore = require('connect-dynamodb')({ session });
    const tablePrefix = process.env.DYNAMODB_TABLE_PREFIX || 'timerecord';
    const tableName = process.env.DYNAMODB_SESSION_TABLE || `${tablePrefix}-sessions`;
    const opts = {
      table: tableName,
      crypto: { secret },
      ttl: configuredSessionTtlSeconds,
      AWSConfigJSON: {},
    };
    if (process.env.AWS_REGION) {
      opts.AWSConfigJSON.region = process.env.AWS_REGION;
    }
    if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
      opts.AWSConfigJSON.accessKeyId = process.env.AWS_ACCESS_KEY_ID;
      opts.AWSConfigJSON.secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
    }
    if (process.env.DYNAMODB_ENDPOINT) {
      opts.AWSConfigJSON.endpoint = process.env.DYNAMODB_ENDPOINT;
    }
    const readCapacity = parsePositiveInt(process.env.DYNAMODB_SESSION_READ_CAPACITY, null);
    const writeCapacity = parsePositiveInt(process.env.DYNAMODB_SESSION_WRITE_CAPACITY, null);
    if (readCapacity) {
      opts.readCapacityUnits = readCapacity;
    }
    if (writeCapacity) {
      opts.writeCapacityUnits = writeCapacity;
    }
    return new DynamoDBStore(opts);
  }

  // Default: RDS/SQL backed store
  // eslint-disable-next-line global-require
  const KnexSessionStore = require('connect-session-knex')(session);
  const clearIntervalMs = parsePositiveInt(
    process.env.SESSION_PRUNE_INTERVAL_MS,
    10 * 60 * 1000
  );
  const handleCleanupError = (error) => {
    if (!isTestEnv) {
      // eslint-disable-next-line no-console
      console.warn('[session] Failed to prune expired sessions.', error);
    }
  };
  return new KnexSessionStore({
    knex: getSqlClient(),
    tablename: process.env.SESSION_TABLE_NAME || 'sessions',
    createtable: true,
    clearInterval: clearIntervalMs,
    ttl: configuredSessionTtlSeconds,
    onDbCleanupError: handleCleanupError,
  });
}

const sessionSecret = loadSessionSecret();
const sessionStore = createSessionStore(sessionSecret);
const ENCRYPTED_LOG_PREFIX = 'enc:';
const ENCRYPTION_FAILURE_SENTINEL = 'error:encryption_failed';

function deriveMfaResetLogKey() {
  const configured = (process.env.MFA_RESET_LOG_ENCRYPTION_KEY || '').trim();
  if (configured) {
    if (/^[0-9a-fA-F]{64}$/.test(configured)) {
      return Buffer.from(configured, 'hex');
    }
    return crypto.createHash('sha256').update(configured, 'utf8').digest();
  }
  if (!isTestEnv) {
    // eslint-disable-next-line no-console
    console.warn(
      '[mfa] MFA_RESET_LOG_ENCRYPTION_KEY is not set; deriving encryption key from SESSION_SECRET.'
    );
  }
  return crypto.createHash('sha256').update(String(sessionSecret || ''), 'utf8').digest();
}

const mfaResetLogKey = deriveMfaResetLogKey();

function verifyMfaLogEncryptionKey() {
  const probe = JSON.stringify({ ok: true, ts: Date.now() });
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', mfaResetLogKey, iv);
    const ciphertext = Buffer.concat([cipher.update(probe, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const decipher = crypto.createDecipheriv('aes-256-gcm', mfaResetLogKey, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    if (plaintext !== probe) {
      throw new Error('MFA reset log encryption key self-test failed: mismatch.');
    }
  } catch (error) {
    throw new Error(`MFA reset log encryption key self-test failed: ${error.message}`);
  }
}

verifyMfaLogEncryptionKey();

function encryptSensitiveLogPayload(payload) {
  if (payload === null || payload === undefined) {
    return null;
  }
  let serialized;
  try {
    serialized = typeof payload === 'string' ? payload : JSON.stringify(payload);
  } catch (error) {
    if (!isTestEnv) {
      // eslint-disable-next-line no-console
      console.warn('[mfa] Failed to serialize MFA reset log payload.', error);
    }
    return ENCRYPTION_FAILURE_SENTINEL;
  }
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', mfaResetLogKey, iv);
    const ciphertext = Buffer.concat([cipher.update(serialized, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const blob = Buffer.concat([iv, authTag, ciphertext]).toString('base64');
    return `${ENCRYPTED_LOG_PREFIX}${blob}`;
  } catch (error) {
    if (!isTestEnv) {
      // eslint-disable-next-line no-console
      console.warn('[mfa] Failed to encrypt MFA reset log payload; storing sentinel only.', error);
    }
    return ENCRYPTION_FAILURE_SENTINEL;
  }
}

function decryptSensitiveLogPayload(payload) {
  if (!payload) {
    return null;
  }
  try {
    let raw = payload;
    if (raw.startsWith(ENCRYPTED_LOG_PREFIX)) {
      raw = raw.slice(ENCRYPTED_LOG_PREFIX.length);
    }
    const buffer = Buffer.from(raw, 'base64');
    if (buffer.length < 29) {
      return null;
    }
    const iv = buffer.subarray(0, 12);
    const authTag = buffer.subarray(12, 28);
    const ciphertext = buffer.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', mfaResetLogKey, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  } catch (error) {
    if (!isTestEnv) {
      // eslint-disable-next-line no-console
      console.warn('[mfa] Failed to decrypt MFA reset log payload.', error);
    }
    return null;
  }
}

function readResetLogPayload(payload, fallback = null) {
  if (typeof payload !== 'string' || payload.trim().length === 0) {
    return fallback;
  }
  const trimmed = payload.trim();
  if (trimmed === ENCRYPTION_FAILURE_SENTINEL) {
    return fallback;
  }
  if (trimmed.startsWith(ENCRYPTED_LOG_PREFIX)) {
    return decryptSensitiveLogPayload(trimmed) || fallback;
  }
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return safeParseJson(trimmed, fallback);
  }
  return decryptSensitiveLogPayload(trimmed) || safeParseJson(trimmed, fallback);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

function validateHostHeader(req, res, next) {
  const rawHost = (req.headers.host || '').trim().toLowerCase();
  if (!rawHost) {
    return res.status(400).send('Invalid Host header');
  }
  const hostname = rawHost.split(':')[0];
  if (!allowedHostnames.includes(hostname)) {
    if (!isTestEnv) {
      // eslint-disable-next-line no-console
      console.warn(`[security] Blocked request with disallowed host header: ${rawHost}`);
    }
    return res.status(400).send('Invalid Host header');
  }
  return next();
}

const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS']);

function csrfProtection(req, res, next) {
  if (!req.session) {
    throw new Error('Session middleware must be initialized before CSRF protection.');
  }

  if (!req.session.csrfSecret) {
    req.session.csrfSecret = tokens.secretSync();
  }

  req.csrfToken = function csrfToken() {
    if (!req._csrfTokenCache) {
      req._csrfTokenCache = tokens.create(req.session.csrfSecret);
    }
    return req._csrfTokenCache;
  };

  if (safeMethods.has(req.method)) {
    return next();
  }

  const token =
    (req.body && req.body._csrf) ||
    (req.query && req.query._csrf) ||
    req.headers['csrf-token'] ||
    req.headers['xsrf-token'] ||
    req.headers['x-csrf-token'] ||
    req.headers['x-xsrf-token'];

  if (!token || !tokens.verify(req.session.csrfSecret, token)) {
    const error = new Error('Invalid CSRF token');
    error.code = 'EBADCSRFTOKEN';
    return next(error);
  }

  return next();
}

app.use(validateHostHeader);
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    store: sessionStore,
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: configuredSessionTtlSeconds * 1000,
      httpOnly: true,
      sameSite: 'lax',
      secure: resolveSessionCookieSecure(),
    },
  })
);

app.use(csrfProtection);

app.use((req, res, next) => {
  const csrfTokenGenerator = typeof req.csrfToken === 'function' ? req.csrfToken : null;
  const csrfToken = csrfTokenGenerator ? csrfTokenGenerator() : null;
  res.locals.currentUser = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  res.locals.csrfToken = csrfToken;
  delete req.session.flash;
  res.locals.mfaBackupCodes = req.session.mfaBackupCodes || null;
  delete req.session.mfaBackupCodes;
  next();
});

app.use((req, res, next) => {
  const user = req.session.user;
  if (!user || !user.mustChangePassword) {
    return next();
  }
  const ext = path.extname(req.path || '');
  if (
    ext ||
    req.path === '/password/change' ||
    req.path === '/logout' ||
    req.path.startsWith('/password/reset')
  ) {
    return next();
  }
  if (req.method !== 'GET') {
    return res.redirect('/password/change');
  }
  setFlash(req, 'info', '初回ログインのためパスワードを変更してください。');
  return res.redirect('/password/change');
});

app.use((req, res, next) => {
  const user = req.session.user;
  if (!user || !user.mustEnableMfa) {
    return next();
  }
  const ext = path.extname(req.path || '');
  if (
    ext ||
    req.path === '/password/change' ||
    req.path === '/logout' ||
    req.path.startsWith('/settings/mfa/') ||
    req.path.startsWith('/password/reset')
  ) {
    return next();
  }
  if (req.method !== 'GET') {
    return res.redirect(MFA_SETTINGS_PATH);
  }
  setFlash(req, 'info', 'テナント管理者は多要素認証を有効化してください。');
  return res.redirect(MFA_SETTINGS_PATH);
});

app.use(async (req, res, next) => {
  if (!req.session.user) {
    next();
    return;
  }
  try {
    const dbUser = await getUserById(req.session.user.id);
    if (!dbUser || dbUser.status !== USER_STATUS.ACTIVE) {
      setFlash(req, 'error', 'アカウントが無効化されたためログアウトします。');
      delete req.session.user;
      res.redirect('/login');
      return;
    }
    let tenantStatus = null;
    if (dbUser.tenant_id) {
      const tenant = await getTenantById(dbUser.tenant_id);
      if (!tenant || tenant.status !== TENANT_STATUS.ACTIVE) {
        setFlash(req, 'error', '所属テナントが利用停止中のため操作できません。');
        delete req.session.user;
        res.redirect('/login');
        return;
      }
      tenantStatus = tenant.status;
    }
    req.session.user.status = dbUser.status;
    req.session.user.tenantStatus = tenantStatus;
    next();
  } catch (error) {
    next(error);
  }
});

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function getMfaChallenge(req) {
  if (!req.session) {
    return null;
  }
  return req.session.pendingMfa || null;
}

function setMfaChallenge(req, payload) {
  if (!req.session) {
    return;
  }
  req.session.pendingMfa = payload;
}

function clearPendingMfa(req) {
  if (req.session && req.session.pendingMfa) {
    delete req.session.pendingMfa;
  }
}

function isMfaChallengeExpired(challenge) {
  if (!challenge || !challenge.issuedAt) {
    return true;
  }
  return Date.now() - challenge.issuedAt > MFA_CHALLENGE_TTL_MS;
}

function normalizeOtpToken(input) {
  return String(input || '')
    .trim()
    .replace(/\s+/g, '')
    .replace(/[^0-9]/g, '');
}

function rememberBackupCodes(req, codes) {
  if (!req.session) {
    return;
  }
  req.session.mfaBackupCodes = Array.isArray(codes) ? codes : [];
}

async function createRecoveryCodesForUser(req, userId, count = 10) {
  await deleteRecoveryCodesByUser(userId);
  const codes = generateRecoveryCodes(count);
  const hashed = codes.map((code) => hashRecoveryCode(code));
  await createRecoveryCodes(userId, hashed);
  rememberBackupCodes(req, codes);
  return codes;
}

function requiresMfaForUser(user) {
  return Boolean(user && user.role === ROLES.TENANT);
}

function parseCookies(req) {
  const header = req.headers && req.headers.cookie;
  if (!header) {
    return {};
  }
  return header.split(';').reduce((acc, part) => {
    const [rawKey, ...rest] = part.split('=');
    if (!rawKey) {
      return acc;
    }
    const key = rawKey.trim();
    if (!key) {
      return acc;
    }
    const value = rest.join('=').trim();
    acc[key] = decodeURIComponent(value || '');
    return acc;
  }, {});
}

function getCookieValue(req, name) {
  if (!name) {
    return null;
  }
  const cookies = parseCookies(req);
  return cookies[name] || null;
}

function hashTrustedDeviceToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function getTrustedDeviceToken(req) {
  return getCookieValue(req, MFA_TRUST_COOKIE_NAME);
}

function shouldUseSecureCookie(req) {
  const setting = resolveSessionCookieSecure();
  if (setting === 'auto') {
    const forwardedProto = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
    return Boolean(req.secure || forwardedProto === 'https');
  }
  return Boolean(setting);
}

function buildTrustCookieOptions(req, maxAgeMs = null) {
  const options = {
    httpOnly: true,
    sameSite: 'lax',
    secure: shouldUseSecureCookie(req),
    path: '/',
  };
  if (Number.isFinite(maxAgeMs) && maxAgeMs > 0) {
    options.maxAge = maxAgeMs;
  }
  return options;
}

function setTrustedDeviceCookie(req, res, token, expiresAtIso) {
  if (!req || !res || typeof res.cookie !== 'function' || !token) {
    return;
  }
  const expiresMs = Date.parse(expiresAtIso) - Date.now();
  const maxAge = Number.isFinite(expiresMs) && expiresMs > 0 ? expiresMs : MFA_TRUST_DURATION_MS;
  res.cookie(MFA_TRUST_COOKIE_NAME, token, buildTrustCookieOptions(req, maxAge));
}

function clearTrustedDeviceCookie(req, res) {
  if (!req || !res || typeof res.clearCookie !== 'function') {
    return;
  }
  res.clearCookie(MFA_TRUST_COOKIE_NAME, buildTrustCookieOptions(req));
}

function describeDevice(req) {
  const userAgent = (req.headers['user-agent'] || '').slice(0, 200);
  const forwarded = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ip = forwarded || req.ip || (req.socket && req.socket.remoteAddress) || '';
  return [userAgent, ip].filter(Boolean).join(' | ').slice(0, 240);
}

async function issueTrustedDevice(req, res, userId) {
  try {
    const token = crypto.randomBytes(TRUSTED_DEVICE_TOKEN_BYTES).toString('hex');
    const expiresAt = new Date(Date.now() + MFA_TRUST_DURATION_MS).toISOString();
    const tokenHash = hashTrustedDeviceToken(token);
    await createTrustedDevice({
      userId,
      tokenHash,
      deviceInfo: describeDevice(req),
      expiresAt,
    });
    setTrustedDeviceCookie(req, res, token, expiresAt);
    return true;
  } catch (error) {
    if (!isTestEnv) {
      // eslint-disable-next-line no-console
      console.warn('[mfa] Failed to register trusted device token', error);
    }
    return false;
  }
}

function normalizeEmail(email) {
  return (email || '').trim().toLowerCase();
}

async function ensureTenantActiveForUser(user) {
  if (!user || !user.tenant_id) {
    return { ok: true, tenant: null };
  }
  const tenant = await getTenantById(user.tenant_id);
  if (!tenant || tenant.status !== TENANT_STATUS.ACTIVE) {
    return {
      ok: false,
      message: '所属テナントが利用停止中のためログインできません。管理者にお問い合わせください。',
    };
  }
  return { ok: true, tenant };
}

function applyUserSession(req, user, tenant, overrides = {}) {
  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role,
    tenantId: user.tenant_id,
    status: user.status,
    tenantStatus: tenant ? tenant.status : null,
    ...overrides,
  };
  if (user.must_change_password) {
    req.session.user.mustChangePassword = true;
  }
}

async function completeLogin(req, user, options = {}) {
  const tenantResult = await ensureTenantActiveForUser(user);
  if (!tenantResult.ok) {
    setFlash(req, 'error', tenantResult.message);
    return { success: false, redirectTo: '/login' };
  }
  applyUserSession(req, user, tenantResult.tenant);
  let redirectTo = '/';
  let flashType = 'success';
  let flashMessage = 'ログインしました。';
  if (user.must_change_password) {
    redirectTo = '/password/change';
    flashType = 'info';
    flashMessage = '初回ログインのためパスワードを変更してください。';
  }
  if (options.overrideFlash) {
    flashType = options.overrideFlash.type || flashType;
    flashMessage = options.overrideFlash.message || flashMessage;
  } else if (options.appendFlashMessage) {
    flashMessage = `${flashMessage} ${options.appendFlashMessage}`.trim();
  }
  setFlash(req, flashType, flashMessage);
  return { success: true, redirectTo };
}

async function generateTenantUid() {
  let attempt = 0;
  while (attempt < 10) {
    const candidate = `ten_${crypto.randomBytes(6).toString('hex')}`;
    // eslint-disable-next-line no-await-in-loop
    const existing = await getTenantByUid(candidate);
    if (!existing) {
      return candidate;
    }
    attempt += 1;
  }
  return `ten_${crypto.randomBytes(8).toString('hex')}`;
}

function generateRoleCodeValue(length = ROLE_CODE_LENGTH) {
  const bytes = crypto.randomBytes(length * 2);
  const chars = [];
  for (let i = 0; i < bytes.length && chars.length < length; i += 1) {
    const nextChar = ROLE_CODE_CHARSET[bytes[i] % ROLE_CODE_CHARSET.length];
    chars.push(nextChar);
  }
  if (chars.length < length) {
    return generateRoleCodeValue(length);
  }
  return chars.join('');
}

function buildRoleCodeShareUrl(codeValue) {
  if (!codeValue) {
    return '';
  }
  const registerUrl = new URL('/register', appBaseUrl);
  registerUrl.searchParams.set('roleCode', codeValue);
  return registerUrl.toString();
}

function hashPasswordResetToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function formatDisplayDateTime(isoString) {
  if (!isoString) return '';
  const formatted = formatDateTime(isoString);
  if (formatted) {
    return formatted;
  }
  const fallback = new Date(isoString);
  if (Number.isNaN(fallback.getTime())) {
    return '';
  }
  return fallback.toLocaleString('ja-JP');
}

async function hasOverlappingSessions(userId, startIso, endIso, excludeSessionId = null) {
  let sessions;
  if (endIso) {
    sessions = await getWorkSessionsByUserOverlapping(userId, startIso, endIso);
  } else {
    sessions = await getAllWorkSessionsByUser(userId);
  }
  const targetStart = Date.parse(startIso);
  const targetEnd = endIso ? Date.parse(endIso) : Number.POSITIVE_INFINITY;

  return sessions.some((session) => {
    if (excludeSessionId && session.id === excludeSessionId) {
      return false;
    }
    const existingStart = Date.parse(session.start_time);
    const existingEnd = session.end_time ? Date.parse(session.end_time) : Number.POSITIVE_INFINITY;
    return existingStart < targetEnd && targetStart < existingEnd;
  });
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session.user) {
      setFlash(req, 'error', 'ログインしてください。');
      return res.redirect('/login');
    }
    if (!roles.includes(req.session.user.role)) {
      setFlash(req, 'error', '権限がありません。');
      return res.redirect('/');
    }
    return next();
  };
}

function ensureTenantContext(req, res, next) {
  if (!req.session.user || !req.session.user.tenantId) {
    setFlash(req, 'error', 'テナント情報が存在しません。');
    return res.redirect('/');
  }
  return next();
}

function buildSessionQuery(query = {}) {
  const params = [];
  if (query.year) {
    params.push(`year=${encodeURIComponent(query.year)}`);
  }
  if (query.month) {
    params.push(`month=${encodeURIComponent(query.month)}`);
  }
  return params.length > 0 ? `?${params.join('&')}` : '';
}

async function getTenantAdminForPlatform(req, res) {
  const userId = Number.parseInt(req.params.userId, 10);
  if (!Number.isFinite(userId)) {
    setFlash(req, 'error', 'テナント管理者が見つかりません。');
    res.redirect('/platform/tenants');
    return null;
  }
  const tenantAdmin = await getUserById(userId);
  if (!tenantAdmin || tenantAdmin.role !== ROLES.TENANT) {
    setFlash(req, 'error', 'テナント管理者が見つかりません。');
    res.redirect('/platform/tenants');
    return null;
  }
  return tenantAdmin;
}

function normalizeSessionQueryParams(query = {}) {
  const normalized = {};
  const rawYear = Number.parseInt(query.year, 10);
  if (!Number.isNaN(rawYear)) {
    const clampedYear = Math.min(Math.max(rawYear, SESSION_YEAR_MIN), SESSION_YEAR_MAX);
    normalized.year = clampedYear;
  }
  const rawMonth = Number.parseInt(query.month, 10);
  if (!Number.isNaN(rawMonth)) {
    const clampedMonth = Math.min(Math.max(rawMonth, 1), 12);
    normalized.month = clampedMonth;
  }
  return normalized;
}

const buildAdminSessionsUrl = (userId, query = {}) =>
  `/admin/employees/${userId}/sessions${buildSessionQuery(query)}`;

async function getEmployeeForTenantAdmin(req, res) {
  const employeeId = Number.parseInt(req.params.userId, 10);
  const employee = Number.isNaN(employeeId) ? null : await getUserById(employeeId);
  if (!employee || employee.role !== ROLES.EMPLOYEE) {
    setFlash(req, 'error', '従業員が見つかりません。');
    res.redirect('/admin');
    return null;
  }
  if (employee.tenant_id !== req.session.user.tenantId) {
    setFlash(req, 'error', '他テナントの従業員にはアクセスできません。');
    res.redirect('/admin');
    return null;
  }
  return employee;
}

function validateNameField(label, value) {
  const trimmed = (value || '').trim();
  if (!trimmed) {
    return { valid: false, message: `${label}を入力してください。` };
  }
  if (trimmed.length > 64) {
    return { valid: false, message: `${label}は64文字以内で入力してください。` };
  }
  for (let i = 0; i < trimmed.length; i += 1) {
    const code = trimmed.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return { valid: false, message: `${label}に制御文字は使用できません。` };
    }
  }
  return { valid: true, value: trimmed };
}

function validatePhoneNumberField(label, value) {
  const raw = (value || '').trim();
  if (!raw) {
    return { valid: false, message: `${label}を入力してください。` };
  }
  const digits = raw.replace(/\D/g, '');
  if (digits.length < 10 || digits.length > 15) {
    return {
      valid: false,
      message: `${label}は10〜15桁の数字で入力してください（ハイフン可）。`,
    };
  }
  return { valid: true, value: digits };
}

app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  if (req.session.user.role === ROLES.PLATFORM) {
    return res.redirect('/platform/tenants');
  }
  if (req.session.user.role === ROLES.TENANT) {
    return res.redirect('/admin');
  }
  if (req.session.user.role === ROLES.EMPLOYEE) {
    return res.redirect('/employee');
  }
  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  const challenge = getMfaChallenge(req);
  if (challenge) {
    if (isMfaChallengeExpired(challenge)) {
      clearPendingMfa(req);
    } else {
      return res.redirect('/login/mfa');
    }
  }
  return res.render('login', {
    minPasswordLength: PASSWORD_MIN_LENGTH,
    lockLimit: LOGIN_FAILURE_LIMIT,
    lockMinutes: LOGIN_LOCK_MINUTES,
  });
});

app.post('/login', async (req, res) => {
  clearPendingMfa(req);
  const email = normalizeEmail(req.body.email);
  const password = (req.body.password || '').trim();

  if (!email || !password) {
    setFlash(req, 'error', 'メールアドレスとパスワードを入力してください。');
    return res.redirect('/login');
  }

  const user = await getUserByEmail(email);
  if (!user) {
    setFlash(req, 'error', 'メールアドレスまたはパスワードが正しくありません。');
    return res.redirect('/login');
  }
  if (user.status !== USER_STATUS.ACTIVE) {
    setFlash(req, 'error', 'アカウントが無効化されています。管理者にお問い合わせください。');
    return res.redirect('/login');
  }

  const now = new Date();
  if (user.locked_until && Date.parse(user.locked_until) > now.getTime()) {
    const remainingMs = Date.parse(user.locked_until) - now.getTime();
    const remainingMinutes = Math.ceil(remainingMs / (60 * 1000));
    setFlash(
      req,
      'error',
      `アカウントがロックされています。${remainingMinutes}分後に再度お試しください。`
    );
    return res.redirect('/login');
  }

  const ok = await comparePassword(password, user.password_hash);
  if (!ok) {
    const willLock = user.failed_attempts + 1 >= LOGIN_FAILURE_LIMIT;
    const lockUntilIso = willLock
      ? new Date(now.getTime() + LOGIN_LOCK_MINUTES * 60 * 1000).toISOString()
      : null;
    const meta = await recordLoginFailure(user.id, lockUntilIso);
    if (willLock) {
      setFlash(
        req,
        'error',
        `ログインに${LOGIN_FAILURE_LIMIT}回連続で失敗したため、${LOGIN_LOCK_MINUTES}分間ロックしました。`
      );
    } else {
      const remaining = Math.max(0, LOGIN_FAILURE_LIMIT - meta.failed_attempts);
      setFlash(
        req,
        'error',
        `メールアドレスまたはパスワードが正しくありません。（あと${remaining}回でロックされます）`
      );
    }
    return res.redirect('/login');
  }

  let userTenant = null;
  if (user.tenant_id) {
    userTenant = await getTenantById(user.tenant_id);
    if (!userTenant || userTenant.status !== TENANT_STATUS.ACTIVE) {
      setFlash(req, 'error', '所属テナントが利用停止中のためログインできません。管理者にお問い合わせください。');
      return res.redirect('/login');
    }
  }

  await resetLoginFailures(user.id);

  const verifiedTotp = await getVerifiedMfaMethod(user.id, MFA_TYPES.TOTP);
  const requiresMfa = requiresMfaForUser(user);
  if (requiresMfa && !verifiedTotp) {
    applyUserSession(req, user, userTenant, { mustEnableMfa: true });
    clearTrustedDeviceCookie(req, res);
    setFlash(req, 'info', 'テナント管理者は多要素認証を有効化してください。');
    return res.redirect(MFA_SETTINGS_PATH);
  }

  if (!verifiedTotp) {
    const outcome = await completeLogin(req, user);
    return res.redirect(outcome.redirectTo);
  }

  const trustedToken = getTrustedDeviceToken(req);
  if (trustedToken) {
    const hashedToken = hashTrustedDeviceToken(trustedToken);
    const trustedDevice = await getTrustedDeviceByToken(user.id, hashedToken);
    const expiresAtMs = trustedDevice ? Date.parse(trustedDevice.expires_at) : NaN;
    if (trustedDevice && Number.isFinite(expiresAtMs) && expiresAtMs > Date.now()) {
      await touchTrustedDevice(trustedDevice.id);
      const outcome = await completeLogin(req, user);
      return res.redirect(outcome.redirectTo);
    }
    if (trustedDevice) {
      await deleteTrustedDeviceById(trustedDevice.id);
    }
    clearTrustedDeviceCookie(req, res);
  }

  setMfaChallenge(req, {
    userId: user.id,
    email: user.email,
    methods: [MFA_TYPES.TOTP],
    issuedAt: Date.now(),
  });
  setFlash(req, 'info', '認証アプリのコードを入力してください。');
  return res.redirect('/login/mfa');
});

app.get('/login/mfa', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  const challenge = getMfaChallenge(req);
  if (!challenge) {
    setFlash(req, 'error', '多要素認証の手続きが見つかりません。再度ログインしてください。');
    return res.redirect('/login');
  }
  if (isMfaChallengeExpired(challenge)) {
    clearPendingMfa(req);
    setFlash(req, 'error', '多要素認証の有効時間が切れました。もう一度ログインしてください。');
    return res.redirect('/login');
  }
  const factorLabel = (challenge.methods || []).map(getMfaChannelLabel).join(' / ');
  return res.render('login_mfa', {
    factorLabel: factorLabel || '多要素認証',
    email: challenge.email || '',
    trustDurationDays: MFA_TRUST_DURATION_DAYS,
  });
});

app.get('/login/mfa/cancel', (req, res) => {
  clearPendingMfa(req);
  setFlash(req, 'info', '多要素認証をキャンセルしました。再度ログインしてください。');
  return res.redirect('/login');
});

app.post('/login/mfa', async (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  const challenge = getMfaChallenge(req);
  if (!challenge) {
    setFlash(req, 'error', '多要素認証の手続きが見つかりません。再度ログインしてください。');
    return res.redirect('/login');
  }
  if (isMfaChallengeExpired(challenge)) {
    clearPendingMfa(req);
    setFlash(req, 'error', '多要素認証の有効時間が切れました。もう一度ログインしてください。');
    return res.redirect('/login');
  }
  const authMode = (req.body.authMode || '').toLowerCase();
  const token = normalizeOtpToken(req.body.token);
  const backupCodeInput = normalizeRecoveryCodeInput(req.body.backupCode || '');
  const rememberDevice = req.body.rememberDevice === 'on';
  const user = await getUserById(challenge.userId);
  if (!user || user.status !== USER_STATUS.ACTIVE) {
    clearPendingMfa(req);
    setFlash(req, 'error', 'ユーザー情報を確認できませんでした。再度ログインしてください。');
    return res.redirect('/login');
  }

  // 現状は TOTP のみ対応しており、将来的にメール/SMS OTP を追加できる構造にしている。
  const requiredMethods = challenge.methods || [];
  const useBackupMode = authMode === 'backup' || (!token && backupCodeInput);
  if (useBackupMode) {
    if (!backupCodeInput) {
      setFlash(req, 'error', 'バックアップコードを入力してください。');
      return res.redirect('/login/mfa');
    }
    const hashedCode = hashRecoveryCode(backupCodeInput);
    const recovery = await findUsableRecoveryCode(user.id, hashedCode);
    if (!recovery) {
      setFlash(req, 'error', 'バックアップコードが正しくないか、すでに使用済みです。');
      return res.redirect('/login/mfa');
    }
    await markRecoveryCodeUsed(recovery.id);
    clearPendingMfa(req);
    const outcome = await completeLogin(req, user, {
      appendFlashMessage: 'バックアップコードを使用しました。新しいバックアップコードを再発行してください。',
    });
    return res.redirect(outcome.redirectTo);
  }

  if (!token) {
    setFlash(req, 'error', '認証コードを入力してください。');
    return res.redirect('/login/mfa');
  }

  let trustDeviceFailed = false;
  // eslint-disable-next-line no-restricted-syntax
  for (const methodType of requiredMethods) {
    if (methodType === MFA_TYPES.TOTP) {
      const verifiedTotp = await getVerifiedMfaMethod(user.id, MFA_TYPES.TOTP);
      if (!verifiedTotp) {
        clearPendingMfa(req);
        setFlash(req, 'error', '多要素認証の設定が変更されました。再度ログインしてください。');
        return res.redirect('/login');
      }
      const valid = verifyTotpToken({ secret: verifiedTotp.secret, token });
      if (!valid) {
        setFlash(req, 'error', '認証コードが正しくありません。');
        return res.redirect('/login/mfa');
      }
      await touchMfaMethodUsed(verifiedTotp.id);
      if (rememberDevice) {
        const issued = await issueTrustedDevice(req, res, user.id);
        if (!issued) {
          trustDeviceFailed = true;
        }
      }
      continue;
    }
    clearPendingMfa(req);
    setFlash(req, 'error', '未対応の多要素認証方式です。');
    return res.redirect('/login');
  }

  clearPendingMfa(req);
  const completeOptions = trustDeviceFailed
    ? { appendFlashMessage: 'デバイスの記憶に失敗しました。後でもう一度設定してください。' }
    : undefined;
  const outcome = await completeLogin(req, user, completeOptions || {});
  return res.redirect(outcome.redirectTo);
});

app.post('/logout', (req, res) => {
  clearPendingMfa(req);
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  let queryValue = '';
  if (typeof req.query.roleCode === 'string') {
    queryValue = req.query.roleCode;
  } else if (Array.isArray(req.query.roleCode) && req.query.roleCode.length > 0) {
    [queryValue] = req.query.roleCode;
  }
  const prefilledRoleCode = (queryValue || '').trim().toUpperCase();
  const sanitizedRoleCode = /^[A-Z0-9]+$/.test(prefilledRoleCode) ? prefilledRoleCode : '';
  return res.render('register', {
    minPasswordLength: PASSWORD_MIN_LENGTH,
    roleCodeValue: sanitizedRoleCode,
  });
});

app.post('/register', async (req, res) => {
  const roleCodeValue = (req.body.roleCode || '').trim().toUpperCase();
  const firstNameResult = validateNameField('名', req.body.firstName);
  if (!firstNameResult.valid) {
    setFlash(req, 'error', firstNameResult.message);
    return res.redirect('/register');
  }
  const lastNameResult = validateNameField('姓', req.body.lastName);
  if (!lastNameResult.valid) {
    setFlash(req, 'error', lastNameResult.message);
    return res.redirect('/register');
  }
  const email = normalizeEmail(req.body.email);
  if (!email) {
    setFlash(req, 'error', 'メールアドレスを入力してください。');
    return res.redirect('/register');
  }
  const newPassword = req.body.password || '';

  if (!roleCodeValue) {
    setFlash(req, 'error', 'ロールコードを入力してください。');
    return res.redirect('/register');
  }

  const roleCode = await getRoleCodeByCode(roleCodeValue);
  if (!roleCode) {
    setFlash(req, 'error', 'ロールコードが無効です。');
    return res.redirect('/register');
  }
  if (roleCode.is_disabled) {
    setFlash(req, 'error', 'このロールコードは無効化されています。');
    return res.redirect('/register');
  }
  if (roleCode.expires_at && Date.parse(roleCode.expires_at) <= Date.now()) {
    setFlash(req, 'error', 'ロールコードの有効期限が切れています。');
    return res.redirect('/register');
  }
  if (roleCode.max_uses !== null && roleCode.usage_count >= roleCode.max_uses) {
    setFlash(req, 'error', 'ロールコードの利用上限に達しています。');
    return res.redirect('/register');
  }

  const existingUser = await getUserByEmail(email);
  if (existingUser) {
    setFlash(req, 'error', 'このメールアドレスは既に登録されています。');
    return res.redirect('/register');
  }

  const validation = validatePassword(newPassword);
  if (!validation.valid) {
    setFlash(req, 'error', validation.message);
    return res.redirect('/register');
  }

  const tenant = await getTenantById(roleCode.tenant_id);
  if (!tenant) {
    setFlash(req, 'error', 'ロールコードに対応するテナントが見つかりません。');
    return res.redirect('/register');
  }

  const hashed = await hashPassword(newPassword);
  const username = `${lastNameResult.value}${firstNameResult.value}`;

  try {
    await createUser({
      tenantId: tenant.id,
      username,
      email,
      passwordHash: hashed,
      role: ROLES.EMPLOYEE,
      firstName: firstNameResult.value,
      lastName: lastNameResult.value,
    });
    await incrementRoleCodeUsage(roleCode.id);
    const updatedRoleCode = await getRoleCodeById(roleCode.id);
    if (
      updatedRoleCode &&
      updatedRoleCode.max_uses !== null &&
      updatedRoleCode.usage_count >= updatedRoleCode.max_uses
    ) {
      await disableRoleCode(updatedRoleCode.id);
    }
    setFlash(req, 'success', 'アカウントを作成しました。ログインしてください。');
    return res.redirect('/login');
  } catch (error) {
    console.error('[register] 従業員アカウント作成に失敗しました', error);
    setFlash(req, 'error', 'アカウント作成中にエラーが発生しました。');
    return res.redirect('/register');
  }
});

app.get('/password/reset', (req, res) => {
  res.render('password_reset_request');
});

app.post('/password/reset', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  if (!email) {
    setFlash(req, 'error', 'メールアドレスを入力してください。');
    return res.redirect('/password/reset');
  }

  const user = await getUserByEmail(email);
  if (!user) {
    setFlash(req, 'info', 'パスワードリセット用のリンクをメールアドレスへ送信しました。（開発環境ではサーバーログを確認してください）');
    return res.redirect('/login');
  }

  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashPasswordResetToken(token);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await createPasswordResetToken({
    userId: user.id,
    tokenHash,
    expiresAt,
  });

  const resetLink = new URL(`/password/reset/${token}`, appBaseUrl).toString();
  if (process.env.NODE_ENV !== 'production') {
    console.info(`[password-reset] ${email} 用リセットリンク: ${resetLink}`);
  } else {
    console.info(`[password-reset] ${email} へのリセット手続きを記録しました`);
  }

  setFlash(
    req,
    'info',
    'パスワードリセット用のリンクをメールアドレスへ送信しました。（開発環境ではサーバーログを確認してください）'
  );
  return res.redirect('/login');
});

app.get('/password/reset/:token', async (req, res) => {
  const rawToken = req.params.token || '';
  const tokenHash = hashPasswordResetToken(rawToken);
  const record = await getPasswordResetToken({
    tokenHash,
    fallbackToken: rawToken,
  });
  if (!record) {
    setFlash(req, 'error', 'リセットリンクが無効です。再度手続きを行ってください。');
    return res.redirect('/password/reset');
  }
  if (Date.parse(record.expires_at) <= Date.now()) {
    setFlash(req, 'error', 'リセットリンクの有効期限が切れています。');
    return res.redirect('/password/reset');
  }
  return res.render('password_reset_update', {
    token: req.params.token,
    minPasswordLength: PASSWORD_MIN_LENGTH,
  });
});

app.post('/password/reset/:token', async (req, res) => {
  const rawToken = req.params.token || '';
  const tokenHash = hashPasswordResetToken(rawToken);
  const record = await getPasswordResetToken({
    tokenHash,
    fallbackToken: rawToken,
  });
  if (!record) {
    setFlash(req, 'error', 'リセットリンクが無効です。再度手続きを行ってください。');
    return res.redirect('/password/reset');
  }
  if (record.used_at) {
    setFlash(req, 'error', 'このリセットリンクは既に使用されています。再度手続きを行ってください。');
    return res.redirect('/password/reset');
  }
  if (Date.parse(record.expires_at) <= Date.now()) {
    setFlash(req, 'error', 'リセットリンクの有効期限が切れています。');
    return res.redirect('/password/reset');
  }

  const user = await getUserById(record.user_id);
  if (!user) {
    setFlash(req, 'error', 'ユーザーが存在しません。');
    return res.redirect('/password/reset');
  }

  const newPassword = req.body.password || '';
  const validation = validatePassword(newPassword);
  if (!validation.valid) {
    setFlash(req, 'error', validation.message);
    return res.redirect(`/password/reset/${req.params.token}`);
  }

  const hashed = await hashPassword(newPassword);
  await updateUserPassword(user.id, hashed, false);
  await resetLoginFailures(user.id);
  await consumePasswordResetToken(record.id);

  setFlash(req, 'success', 'パスワードを再設定しました。ログインしてください。');
  return res.redirect('/login');
});

app.get('/password/change', requireRole(ROLES.PLATFORM, ROLES.TENANT, ROLES.EMPLOYEE), async (req, res) => {
  const user = await getUserById(req.session.user.id);
  if (!user) {
    delete req.session.user;
    setFlash(req, 'error', 'ユーザー情報を再取得できませんでした。再度ログインしてください。');
    return res.redirect('/login');
  }
  const methods = await listMfaMethodsByUser(req.session.user.id);
  const totpActive = methods.find((method) => method.type === MFA_TYPES.TOTP && method.is_verified);
  const totpPending = methods.find((method) => method.type === MFA_TYPES.TOTP && !method.is_verified);

  let pendingSetup = null;
  if (totpPending && totpPending.secret) {
    const config = totpPending.config || {};
    const labelSource = config.label || user?.email || user?.username || `user-${req.session.user.id}`;
    const issuer = config.issuer || MFA_ISSUER;
    const otpauthUrl = buildTotpKeyUri({
      secret: totpPending.secret,
      label: labelSource,
      issuer,
    });
    const qrCodeDataUrl = await generateQrCodeDataUrl(otpauthUrl);
    pendingSetup = {
      secret: totpPending.secret,
      otpauthUrl,
      qrCodeDataUrl,
      issuer,
      label: labelSource,
    };
  }

  res.render('password_change', {
    action: '/password/change',
    minPasswordLength: PASSWORD_MIN_LENGTH,
    mfa: {
      supportedChannels: MFA_CHANNELS,
      totp: {
        isEnabled: Boolean(totpActive),
        verifiedAtDisplay: formatDisplayDateTime(totpActive?.verified_at),
        lastUsedAtDisplay: formatDisplayDateTime(totpActive?.last_used_at),
        pendingSetup,
      },
    },
  });
});

app.post(
  '/password/change',
  requireRole(ROLES.PLATFORM, ROLES.TENANT, ROLES.EMPLOYEE),
  async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const user = await getUserById(req.session.user.id);
    if (!user) {
      setFlash(req, 'error', 'ユーザーが見つかりません。');
      return res.redirect('/password/change');
    }

    const ok = await comparePassword(currentPassword || '', user.password_hash);
    if (!ok) {
      setFlash(req, 'error', '現在のパスワードが正しくありません。');
      return res.redirect('/password/change');
    }

    const validation = validatePassword(newPassword || '');
    if (!validation.valid) {
      setFlash(req, 'error', validation.message);
      return res.redirect('/password/change');
    }

    const hashed = await hashPassword(newPassword);
    await updateUserPassword(user.id, hashed, false);
    await setMustChangePassword(user.id, false);
    if (req.session.user) {
      delete req.session.user.mustChangePassword;
    }
    setFlash(req, 'success', 'パスワードを変更しました。');
    return res.redirect('/');
  }
);

app.post(
  '/settings/mfa/totp/start',
  requireRole(ROLES.PLATFORM, ROLES.TENANT, ROLES.EMPLOYEE),
  async (req, res) => {
    const user = await getUserById(req.session.user.id);
    if (!user) {
      delete req.session.user;
      setFlash(req, 'error', 'ユーザー情報を再取得できませんでした。再度ログインしてください。');
      return res.redirect('/login');
    }
    const existing = await getMfaMethodByUserAndType(user.id, MFA_TYPES.TOTP);
    if (existing && existing.is_verified) {
      setFlash(req, 'info', '認証アプリによる多要素認証はすでに有効です。無効化してから再設定してください。');
      return res.redirect(MFA_SETTINGS_PATH);
    }
    const secret = generateTotpSecret();
    const totpConfig = {
      issuer: MFA_ISSUER,
      label: user.email || user.username || `user-${user.id}`,
    };
    if (existing) {
      await updateMfaMethod(existing.id, {
        secret,
        config: totpConfig,
        isVerified: false,
        lastUsedAt: null,
      });
    } else {
      await createMfaMethod({
        userId: user.id,
        type: MFA_TYPES.TOTP,
        secret,
        config: totpConfig,
        isVerified: false,
      });
    }
    await deleteTrustedDevicesByUser(user.id);
    clearTrustedDeviceCookie(req, res);
    setFlash(req, 'success', '認証アプリのセットアップを開始しました。QRコードを読み取り、コードを入力してください。');
    return res.redirect(MFA_SETTINGS_PATH);
  }
);

app.post(
  '/settings/mfa/totp/verify',
  requireRole(ROLES.PLATFORM, ROLES.TENANT, ROLES.EMPLOYEE),
  async (req, res) => {
    const userId = req.session.user.id;
    const pending = await getMfaMethodByUserAndType(userId, MFA_TYPES.TOTP);
    if (!pending || pending.is_verified) {
      setFlash(req, 'error', 'セットアップ情報が見つかりません。最初からやり直してください。');
      return res.redirect(MFA_SETTINGS_PATH);
    }
    const token = normalizeOtpToken(req.body.verificationCode);
    if (!token) {
      setFlash(req, 'error', '認証コードを入力してください。');
      return res.redirect(MFA_SETTINGS_PATH);
    }
    const valid = verifyTotpToken({ secret: pending.secret, token });
    if (!valid) {
      setFlash(req, 'error', '認証コードが正しくありません。');
      return res.redirect(MFA_SETTINGS_PATH);
    }
    await updateMfaMethod(pending.id, { isVerified: true });
    await createRecoveryCodesForUser(req, userId);
    if (req.session.user && req.session.user.id === userId) {
      delete req.session.user.mustEnableMfa;
    }
    setFlash(
      req,
      'success',
      '認証アプリによる多要素認証を有効化しました。バックアップコードを安全な場所に保管してください。'
    );
    return res.redirect(MFA_SETTINGS_PATH);
  }
);

app.post(
  '/settings/mfa/totp/disable',
  requireRole(ROLES.PLATFORM, ROLES.TENANT, ROLES.EMPLOYEE),
  async (req, res) => {
    if (requiresMfaForUser(req.session.user)) {
      setFlash(req, 'error', 'テナント管理者は多要素認証を無効化できません。');
      return res.redirect(MFA_SETTINGS_PATH);
    }
    await deleteMfaMethodsByUserAndType(req.session.user.id, MFA_TYPES.TOTP);
    await deleteRecoveryCodesByUser(req.session.user.id);
    await deleteTrustedDevicesByUser(req.session.user.id);
    clearPendingMfa(req);
    clearTrustedDeviceCookie(req, res);
    setFlash(req, 'success', '認証アプリによる多要素認証を無効化しました。');
    return res.redirect(MFA_SETTINGS_PATH);
  }
);

app.post(
  '/settings/mfa/recovery-codes/regenerate',
  requireRole(ROLES.PLATFORM, ROLES.TENANT, ROLES.EMPLOYEE),
  async (req, res) => {
    const user = await getUserById(req.session.user.id);
    if (!user) {
      delete req.session.user;
      setFlash(req, 'error', 'ユーザー情報を再取得できませんでした。再度ログインしてください。');
      return res.redirect('/login');
    }
    const verifiedTotp = await getVerifiedMfaMethod(user.id, MFA_TYPES.TOTP);
    if (!verifiedTotp) {
      setFlash(req, 'error', '認証アプリによる多要素認証を有効化してからバックアップコードを再発行してください。');
      return res.redirect(MFA_SETTINGS_PATH);
    }
    const ok = await comparePassword(req.body.currentPassword || '', user.password_hash);
    if (!ok) {
      setFlash(req, 'error', '現在のパスワードが正しくありません。');
      return res.redirect(MFA_SETTINGS_PATH);
    }
    await createRecoveryCodesForUser(req, user.id);
    setFlash(req, 'success', 'バックアップコードを再発行しました。新しいコードのみが有効です。');
    return res.redirect(MFA_SETTINGS_PATH);
  }
);

app.get('/employee', requireRole(ROLES.EMPLOYEE), async (req, res) => {
  const userId = req.session.user.id;
  const now = new Date();
  const openSession = await getOpenWorkSession(userId);
  const dailySummary = await getUserDailySummary(userId, 30);
  const monthDate = toZonedDateTime(now.toISOString());
  const monthlySummary = await getUserMonthlySummary(userId, monthDate.year, monthDate.month);

  const recentSessions = await listRecentWorkSessionsByUser(userId, 10);
  const sessionHistory = recentSessions.map((session) => {
    const durationMinutes = session.end_time
      ? diffMinutes(session.start_time, session.end_time)
      : null;
    return {
      id: session.id,
      startFormatted: formatDateTime(session.start_time),
      endFormatted: session.end_time ? formatDateTime(session.end_time) : '記録中',
      minutes: durationMinutes,
      formattedMinutes: durationMinutes !== null ? formatMinutesToHM(durationMinutes) : '--',
    };
  });

  res.render('employee_dashboard', {
    openSession: openSession
      ? {
          ...openSession,
          startFormatted: formatDateTime(openSession.start_time),
        }
      : null,
    dailySummary,
    monthlySummary,
    sessionHistory,
  });
});

app.get('/employee/payrolls', requireRole(ROLES.EMPLOYEE), async (req, res, next) => {
  try {
    const userId = req.session.user.id;
    const records = await listPayrollRecordsByEmployee(userId);
    const decorated = records.map((record) => ({
      id: record.id,
      sentAtDisplay: formatDateTime(record.sent_at),
      originalFileName: record.original_file_name,
      fileSizeDisplay: formatReadableBytes(record.file_size),
      downloadUrl: `/employee/payrolls/${record.id}/download`,
      inlineUrl: `/employee/payrolls/${record.id}/download?disposition=inline`,
    }));
    res.render('employee_payrolls', {
      payrollRecords: decorated,
    });
  } catch (error) {
    next(error);
  }
});

app.get(
  '/employee/payrolls/:recordId/download',
  requireRole(ROLES.EMPLOYEE),
  async (req, res, next) => {
    try {
      const userId = req.session.user.id;
      const tenantId = req.session.user.tenantId;
      const recordId = Number.parseInt(req.params.recordId, 10);
      if (!Number.isFinite(recordId)) {
        setFlash(req, 'error', '指定された給与明細が見つかりません。');
        return res.redirect('/employee/payrolls');
      }

      const record = await getPayrollRecordById(recordId);
      if (
        !record ||
        record.employee_id !== userId ||
        (tenantId && record.tenant_id !== tenantId) ||
        record.archived_at
      ) {
        setFlash(req, 'error', '指定された給与明細が見つかりません。');
        return res.redirect('/employee/payrolls');
      }

      let absolutePath;
      try {
        absolutePath = resolvePayrollAbsolutePath(record.stored_file_path);
      } catch (pathError) {
        setFlash(req, 'error', '給与明細ファイルの参照に失敗しました。');
        return res.redirect('/employee/payrolls');
      }

      try {
        await fsp.access(absolutePath);
      } catch (accessError) {
        setFlash(req, 'error', '給与明細ファイルが見つかりません。');
        return res.redirect('/employee/payrolls');
      }

      const disposition = req.query.disposition === 'inline' ? 'inline' : 'attachment';
      applyContentDisposition(res, record.original_file_name, disposition);
      res.setHeader('Content-Type', record.mime_type || 'application/octet-stream');
      if (Number.isFinite(record.file_size) && record.file_size >= 0) {
        res.setHeader('Content-Length', record.file_size);
      }
      const stream = fs.createReadStream(absolutePath);
      stream.on('error', next);
      return stream.pipe(res);
    } catch (error) {
      return next(error);
    }
  }
);

app.post('/employee/record', requireRole(ROLES.EMPLOYEE), async (req, res) => {
  const userId = req.session.user.id;
  const openSession = await getOpenWorkSession(userId);
  const nowIso = new Date().toISOString();
  if (openSession) {
    await closeWorkSession(openSession.id, nowIso);
    setFlash(req, 'success', '勤務終了を記録しました。');
  } else {
    await createWorkSession(userId, nowIso);
    setFlash(req, 'success', '勤務開始を記録しました。');
  }
  return res.redirect('/employee');
});

app.get(
  '/admin',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const now = new Date();
    const normalizedQueryInput = normalizeSessionQueryParams(req.query);
    const nowZoned = toZonedDateTime(now.toISOString());
    const targetYear = normalizedQueryInput.year || nowZoned.year;
    const targetMonth = normalizedQueryInput.month || nowZoned.month;
    const effectiveQuery = { year: targetYear, month: targetMonth };

    const tenantId = req.session.user.tenantId;
    const monthlySummary = await getMonthlySummaryForAllEmployees(tenantId, targetYear, targetMonth);
    const allEmployees = await getAllEmployeesByTenantIncludingInactive(tenantId);
    const employeesActive = allEmployees
      .filter((employee) => employee.status === USER_STATUS.ACTIVE)
      .sort((a, b) => (a.username || '').localeCompare(b.username || '', 'ja'));
    const employeesInactive = allEmployees
      .filter((employee) => employee.status !== USER_STATUS.ACTIVE)
      .sort((a, b) => (a.username || '').localeCompare(b.username || '', 'ja'));
    const employeesInactiveDisplay = employeesInactive.map((employee) => ({
      ...employee,
      deactivatedAtDisplay: employee.deactivated_at ? formatDateTime(employee.deactivated_at) : '',
    }));
    res.render('admin_dashboard', {
      monthlySummary,
      targetYear,
      targetMonth,
      tenantId,
      employeesActive,
      employeesInactive: employeesInactiveDisplay,
      retentionYears: DATA_RETENTION_YEARS,
      queryString: buildSessionQuery(effectiveQuery),
    });
  }
);

app.post(
  '/admin/employees/:userId/status',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const employee = await getEmployeeForTenantAdmin(req, res);
    if (!employee) {
      return;
    }
    const action = (req.body.action || '').toLowerCase();
    if (action === 'deactivate') {
      if (employee.status === USER_STATUS.INACTIVE) {
        setFlash(req, 'info', 'すでに無効化されています。');
      } else {
        await updateUserStatus(employee.id, USER_STATUS.INACTIVE);
        setFlash(req, 'success', '従業員アカウントを無効化しました。');
      }
    } else if (action === 'activate') {
      if (employee.status === USER_STATUS.ACTIVE) {
        setFlash(req, 'info', 'すでに有効です。');
      } else {
        await updateUserStatus(employee.id, USER_STATUS.ACTIVE);
        setFlash(req, 'success', '従業員アカウントを再有効化しました。');
      }
    } else {
      setFlash(req, 'error', '不明な操作です。');
    }
    res.redirect('/admin');
  }
);

app.post(
  '/admin/employees/:userId/mfa/reset',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const employee = await getEmployeeForTenantAdmin(req, res);
    if (!employee) {
      return;
    }
    await deleteMfaMethodsByUserAndType(employee.id, MFA_TYPES.TOTP);
    await deleteRecoveryCodesByUser(employee.id);
    await deleteTrustedDevicesByUser(employee.id);
    if (req.session.pendingMfa && req.session.pendingMfa.userId === employee.id) {
      clearPendingMfa(req);
    }
    setFlash(req, 'success', `従業員「${employee.username}」の多要素認証をリセットしました。`);
    res.redirect('/admin');
  }
);

app.get(
  '/admin/payrolls',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res, next) => {
    try {
      const tenantId = req.session.user.tenantId;
      const employees = await getAllEmployeesByTenant(tenantId);
      const employeeMap = new Map(employees.map((employee) => [employee.id, employee]));
      const payrollRecords = await listPayrollRecordsByTenant(tenantId, 100, 0);
      const nowZoned = toZonedDateTime(new Date().toISOString());
      const todayKey = nowZoned ? dateKey(nowZoned) : null;
      const sentTodayEmployeeIds = todayKey
        ? payrollRecords
            .filter((record) => record.sent_on === todayKey)
            .map((record) => String(record.employee_id))
        : [];

      const decoratedRecords = payrollRecords.map((record) => {
        const employee = employeeMap.get(record.employee_id) || null;
        return {
          id: record.id,
          employeeId: record.employee_id,
          employeeName: employee ? employee.username : `ID:${record.employee_id}`,
          employeeEmail: employee ? employee.email : '',
          sentOnDisplay: formatDateKey(record.sent_on),
          sentAtDisplay: formatDateTime(record.sent_at),
          originalFileName: record.original_file_name,
          fileSize: record.file_size,
          fileSizeDisplay: formatReadableBytes(record.file_size),
          downloadUrl: `/admin/payrolls/${record.id}/download`,
          inlineUrl: `/admin/payrolls/${record.id}/download?disposition=inline`,
        };
      });

      const employeeOptions = [...employees]
        .sort((a, b) => (a.username || '').localeCompare(b.username || '', 'ja'))
        .map((employee) => ({
          id: employee.id,
          name: employee.username,
          email: employee.email,
        }));

      res.render('admin_payrolls', {
        employees: employeeOptions,
        payrollRecords: decoratedRecords,
        allowedExtensions: Array.from(PAYROLL_ALLOWED_EXTENSIONS),
        maxFileSizeBytes: PAYROLL_MAX_UPLOAD_BYTES,
        sentTodayEmployeeIds,
        retentionYears: DATA_RETENTION_YEARS,
      });
    } catch (error) {
      next(error);
    }
  }
);

function wrapPayrollUpload(req, res, next) {
  uploadPayroll.single(PAYROLL_UPLOAD_FIELD)(req, res, (err) => {
    if (!err) {
      next();
      return;
    }
    if (err.code === 'LIMIT_FILE_SIZE') {
      const maxMb = Math.max(1, Math.floor(PAYROLL_MAX_UPLOAD_BYTES / (1024 * 1024)));
      setFlash(
        req,
        'error',
        `ファイルサイズが大きすぎます。最大${maxMb}MBまでアップロード可能です。`
      );
      return res.redirect('/admin/payrolls');
    }
    if (err.code === 'UNSUPPORTED_PAYROLL_FILE') {
      setFlash(req, 'error', err.message);
      return res.redirect('/admin/payrolls');
    }
    return next(err);
  });
}

app.post(
  '/admin/payrolls/send',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  wrapPayrollUpload,
  async (req, res, next) => {
    const uploadedFile = req.file || null;
    try {
      const tenantId = req.session.user.tenantId;
      const adminId = req.session.user.id;
      const employeeIdRaw = req.body.employeeId || '';
      const forceResend = req.body.forceResend === 'true';

      const employeeId = Number.parseInt(employeeIdRaw, 10);
      if (!Number.isFinite(employeeId)) {
        setFlash(req, 'error', '従業員を選択してください。');
        if (uploadedFile) {
          await removePayrollFileQuietly(uploadedFile.path);
        }
        return res.redirect('/admin/payrolls');
      }

      if (!uploadedFile) {
        setFlash(req, 'error', '給与明細ファイルを選択してください。');
        return res.redirect('/admin/payrolls');
      }

      const originalFileName =
        decodeUploadedFileName(uploadedFile.originalname) || uploadedFile.originalname || '';

      const employee = await getUserById(employeeId);
      if (!employee || employee.tenant_id !== tenantId || employee.role !== ROLES.EMPLOYEE) {
        setFlash(req, 'error', '選択された従業員が見つかりません。');
        await removePayrollFileQuietly(uploadedFile.path);
        return res.redirect('/admin/payrolls');
      }

      if (!validatePayrollExtension(originalFileName)) {
        setFlash(
          req,
          'error',
          `許可されていないファイル形式です。使用可能な拡張子: ${Array.from(
            PAYROLL_ALLOWED_EXTENSIONS
          ).join(', ')}`
        );
        await removePayrollFileQuietly(uploadedFile.path);
        return res.redirect('/admin/payrolls');
      }

      const sentAtIso = new Date().toISOString();
      const zonedNow = toZonedDateTime(sentAtIso);
      const sentOnKey = zonedNow ? dateKey(zonedNow) : sentAtIso.slice(0, 10);

      const latestRecordToday = await getLatestPayrollRecordForDate(employee.id, sentOnKey);
      if (latestRecordToday && !forceResend) {
        await removePayrollFileQuietly(uploadedFile.path);
        setFlash(
          req,
          'error',
          '本日既に給与明細を送信済みです。確認ダイアログで再送信を明示的に承認してください。'
        );
        return res.redirect('/admin/payrolls');
      }

      const storedRelativePath = buildPayrollRelativePath(tenantId, uploadedFile.filename);

      await createPayrollRecord({
        tenantId,
        employeeId: employee.id,
        uploadedBy: adminId,
        originalFileName,
        storedFilePath: storedRelativePath,
        mimeType: uploadedFile.mimetype,
        fileSize: uploadedFile.size,
        sentOn: sentOnKey,
        sentAt: sentAtIso,
      });

      setFlash(req, 'success', '給与明細を送信しました。');
      return res.redirect('/admin/payrolls');
    } catch (error) {
      if (uploadedFile) {
        await removePayrollFileQuietly(uploadedFile.path);
      }
      return next(error);
    }
  }
);

app.get(
  '/admin/payrolls/:recordId/download',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res, next) => {
    try {
      const tenantId = req.session.user.tenantId;
      const recordId = Number.parseInt(req.params.recordId, 10);
      if (!Number.isFinite(recordId)) {
        setFlash(req, 'error', '指定された給与明細が見つかりません。');
        return res.redirect('/admin/payrolls');
      }

      const record = await getPayrollRecordById(recordId);
      if (!record || record.tenant_id !== tenantId || record.archived_at) {
        setFlash(req, 'error', '指定された給与明細が見つかりません。');
        return res.redirect('/admin/payrolls');
      }

      let absolutePath;
      try {
        absolutePath = resolvePayrollAbsolutePath(record.stored_file_path);
      } catch (pathError) {
        setFlash(req, 'error', '給与明細ファイルの参照に失敗しました。');
        return res.redirect('/admin/payrolls');
      }

      try {
        await fsp.access(absolutePath);
      } catch (accessError) {
        setFlash(req, 'error', '給与明細ファイルが見つかりません。');
        return res.redirect('/admin/payrolls');
      }

      const disposition = req.query.disposition === 'inline' ? 'inline' : 'attachment';
      applyContentDisposition(res, record.original_file_name, disposition);
      res.setHeader('Content-Type', record.mime_type || 'application/octet-stream');
      if (Number.isFinite(record.file_size) && record.file_size >= 0) {
        res.setHeader('Content-Length', record.file_size);
      }

      const stream = fs.createReadStream(absolutePath);
      stream.on('error', next);
      return stream.pipe(res);
    } catch (error) {
      return next(error);
    }
  }
);

app.get(
  '/admin/role-codes',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const tenantId = req.session.user.tenantId;
    const now = Date.now();
    const codeRows = await listRoleCodesByTenant(tenantId);
    const codes = codeRows.map((code) => {
      const expiresAtMs = code.expires_at ? Date.parse(code.expires_at) : null;
      const isExpired = Boolean(expiresAtMs && expiresAtMs <= now);
      const isExhausted = code.max_uses !== null && code.usage_count >= code.max_uses;
      const status = code.is_disabled
        ? 'disabled'
        : isExpired
        ? 'expired'
        : isExhausted
        ? 'exhausted'
        : 'active';
      return {
        ...code,
        status,
        expiresAt: expiresAtMs,
        expiresDisplay: formatDisplayDateTime(code.expires_at),
        shareUrl: buildRoleCodeShareUrl(code.code),
      };
    });

    let generated = req.session.generatedRoleCodeResult || null;
    delete req.session.generatedRoleCodeResult;
    if (generated) {
      generated = {
        ...generated,
        expiresDisplay: generated.expiresDisplay || formatDisplayDateTime(generated.expiresAt),
        shareUrl: generated.shareUrl || buildRoleCodeShareUrl(generated.code),
      };
    }

    res.render('role_codes', {
      codes,
      tenantId,
      generated,
    });
  }
);

app.post(
  '/admin/role-codes',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const tenantId = req.session.user.tenantId;
    const expiresInput = (req.body.expiresAt || '').trim();
    const maxUsesInput = (req.body.maxUses || '').trim();
    const expiresAt = expiresInput ? parseDateTimeInput(expiresInput) : null;

    if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
      setFlash(req, 'error', '有効期限は現在より後の日時を指定してください。');
      return res.redirect('/admin/role-codes');
    }

    let maxUses = null;
    if (maxUsesInput) {
      const parsed = Number.parseInt(maxUsesInput, 10);
      if (Number.isNaN(parsed) || parsed <= 0) {
        setFlash(req, 'error', '使用回数上限は1以上の整数で指定してください。');
        return res.redirect('/admin/role-codes');
      }
      maxUses = parsed;
    }

    let codeValue = '';
    while (true) {
      codeValue = generateRoleCodeValue();
      // eslint-disable-next-line no-await-in-loop
      const existingCode = await getRoleCodeByCode(codeValue);
      if (!existingCode) {
        break;
      }
    }

    await createRoleCode({
      tenantId,
      code: codeValue,
      expiresAt,
      maxUses,
      createdBy: req.session.user.id,
    });

    req.session.generatedRoleCodeResult = {
      code: codeValue,
      expiresAt,
      expiresDisplay: formatDisplayDateTime(expiresAt),
      maxUses,
      shareUrl: buildRoleCodeShareUrl(codeValue),
    };

    setFlash(req, 'success', 'ロールコードを発行しました。');
    return res.redirect('/admin/role-codes');
  }
);

app.post(
  '/admin/role-codes/:codeId/disable',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const tenantId = req.session.user.tenantId;
    const codeId = Number.parseInt(req.params.codeId, 10);
    const roleCode = Number.isNaN(codeId) ? null : await getRoleCodeById(codeId);
    if (!roleCode || roleCode.tenant_id !== tenantId) {
      setFlash(req, 'error', 'ロールコードが見つかりません。');
      return res.redirect('/admin/role-codes');
    }
    await disableRoleCode(roleCode.id);
    setFlash(req, 'success', 'ロールコードを無効化しました。');
    return res.redirect('/admin/role-codes');
  }
);

app.get(
  '/admin/employees/:userId/sessions',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const employee = await getEmployeeForTenantAdmin(req, res);
    if (!employee) {
      return;
    }
    if (employee.status !== USER_STATUS.ACTIVE) {
      setFlash(req, 'error', '無効化された従業員の勤怠記録にはアクセスできません。');
      res.redirect('/admin');
      return;
    }

    const now = new Date();
    const normalizedQueryInput = normalizeSessionQueryParams(req.query);
    const nowZoned = toZonedDateTime(now.toISOString());
    const targetYear = normalizedQueryInput.year || nowZoned.year;
    const targetMonth = normalizedQueryInput.month || nowZoned.month;
    const effectiveQuery = { year: targetYear, month: targetMonth };

    const { start, end } = getMonthRange(targetYear, targetMonth);
    const startIso = start.toUTC().toISO();
    const endIso = end.toUTC().toISO();
    const records = await getWorkSessionsByUserBetween(employee.id, startIso, endIso);

    const sessions = records.map((session) => {
      const durationMinutes = session.end_time
        ? diffMinutes(session.start_time, session.end_time)
        : null;
      return {
        id: session.id,
        startInput: formatForDateTimeInput(session.start_time),
        endInput: session.end_time ? formatForDateTimeInput(session.end_time) : '',
        startDisplay: formatDateTime(session.start_time),
        endDisplay: session.end_time ? formatDateTime(session.end_time) : '記録中',
        formattedMinutes: durationMinutes !== null ? formatMinutesToHM(durationMinutes) : '--',
      };
    });

    const monthlySummary = await getUserMonthlySummary(employee.id, targetYear, targetMonth);

    res.render('admin_sessions', {
      employee,
      sessions,
      targetYear,
      targetMonth,
      monthlySummary,
      queryString: buildSessionQuery(effectiveQuery),
    });
  }
);

app.post(
  '/admin/employees/:userId/sessions',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const employee = await getEmployeeForTenantAdmin(req, res);
    if (!employee) {
      return;
    }
    if (employee.status !== USER_STATUS.ACTIVE) {
      setFlash(req, 'error', '無効化された従業員の勤怠記録は編集できません。');
      res.redirect('/admin');
      return;
    }

    const normalizedQuery = normalizeSessionQueryParams(req.query);
    const startInput = (req.body.startTime || '').trim();
    const endInput = (req.body.endTime || '').trim();
    const startIso = parseDateTimeInput(startInput);
    const endIso = parseDateTimeInput(endInput);

    if (!startIso || !endIso) {
      setFlash(req, 'error', '開始と終了の日時を正しく入力してください。');
      res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
      return;
    }

    if (
      !isSessionDateWithinAllowedRange(startIso) ||
      !isSessionDateWithinAllowedRange(endIso)
    ) {
      setFlash(req, 'error', SESSION_YEAR_RANGE_MESSAGE);
      res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
      return;
    }

    if (diffMinutes(startIso, endIso) <= 0) {
      setFlash(req, 'error', '終了時刻は開始時刻より後に設定してください。');
      res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
      return;
    }

    if (await hasOverlappingSessions(employee.id, startIso, endIso)) {
      setFlash(req, 'error', OVERLAP_ERROR_MESSAGE);
      res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
      return;
    }

    await createWorkSessionWithEnd(employee.id, startIso, endIso);
    setFlash(req, 'success', '勤務記録を追加しました。');
    res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
  }
);

app.post(
  '/admin/employees/:userId/sessions/:sessionId/update',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const employee = await getEmployeeForTenantAdmin(req, res);
    if (!employee) {
      return;
    }
    if (employee.status !== USER_STATUS.ACTIVE) {
      setFlash(req, 'error', '無効化された従業員の勤怠記録は編集できません。');
      res.redirect('/admin');
      return;
    }

    const normalizedQuery = normalizeSessionQueryParams(req.query);
    const sessionId = Number.parseInt(req.params.sessionId, 10);
    const sessionRecord = Number.isNaN(sessionId) ? null : await getWorkSessionById(sessionId);
    if (!sessionRecord || sessionRecord.user_id !== employee.id) {
      setFlash(req, 'error', '該当する勤務記録が見つかりません。');
      res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
      return;
    }

    const startInput = (req.body.startTime || '').trim();
    const endInput = (req.body.endTime || '').trim();
    const startIso = parseDateTimeInput(startInput);

    if (!startIso) {
      setFlash(req, 'error', '開始時刻を正しく入力してください。');
      res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
      return;
    }

    if (!isSessionDateWithinAllowedRange(startIso)) {
      setFlash(req, 'error', SESSION_YEAR_RANGE_MESSAGE);
      res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
      return;
    }

    let endIso = null;
    if (endInput) {
      endIso = parseDateTimeInput(endInput);
      if (!endIso) {
        setFlash(req, 'error', '終了時刻を正しく入力してください。');
        res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
        return;
      }
      if (!isSessionDateWithinAllowedRange(endIso)) {
        setFlash(req, 'error', SESSION_YEAR_RANGE_MESSAGE);
        res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
        return;
      }
      if (diffMinutes(startIso, endIso) <= 0) {
        setFlash(req, 'error', '終了時刻は開始時刻より後に設定してください。');
        res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
        return;
      }
    }

    if (await hasOverlappingSessions(employee.id, startIso, endIso, sessionRecord.id)) {
      setFlash(req, 'error', OVERLAP_ERROR_MESSAGE);
      res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
      return;
    }

    await updateWorkSessionTimes(sessionRecord.id, startIso, endIso);
    setFlash(req, 'success', '勤務記録を更新しました。');
    res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
  }
);

app.post(
  '/admin/employees/:userId/sessions/:sessionId/delete',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const employee = await getEmployeeForTenantAdmin(req, res);
    if (!employee) {
      return;
    }
    if (employee.status !== USER_STATUS.ACTIVE) {
      setFlash(req, 'error', '無効化された従業員の勤怠記録は削除できません。');
      res.redirect('/admin');
      return;
    }

    const normalizedQuery = normalizeSessionQueryParams(req.query);
    const sessionId = Number.parseInt(req.params.sessionId, 10);
    const sessionRecord = Number.isNaN(sessionId) ? null : await getWorkSessionById(sessionId);
    if (!sessionRecord || sessionRecord.user_id !== employee.id) {
      setFlash(req, 'error', '該当する勤務記録が見つかりません。');
      res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
      return;
    }

    await deleteWorkSession(sessionRecord.id);
    setFlash(req, 'success', '勤務記録を削除しました。');
    res.redirect(buildAdminSessionsUrl(employee.id, normalizedQuery));
  }
);

app.post(
  '/admin/export',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const userId = Number.parseInt(req.body.userId, 10);
    const year = Number.parseInt(req.body.year, 10);
    const month = Number.parseInt(req.body.month, 10);

    if (!Number.isFinite(userId)) {
      setFlash(req, 'error', '従業員を選択してください。');
      return res.redirect('/admin');
    }

    if (
      !Number.isFinite(year) ||
      year < SESSION_YEAR_MIN ||
      year > SESSION_YEAR_MAX ||
      !Number.isFinite(month) ||
      month < 1 ||
      month > 12
    ) {
      setFlash(req, 'error', '出力対象の年月が正しくありません。');
      return res.redirect('/admin');
    }

    const employee = await getUserById(userId);
    if (
      !employee ||
      employee.role !== ROLES.EMPLOYEE ||
      employee.tenant_id !== req.session.user.tenantId
    ) {
      setFlash(req, 'error', '対象の従業員が見つかりません。');
      return res.redirect('/admin');
    }
    if (employee.status !== USER_STATUS.ACTIVE) {
      setFlash(req, 'error', '無効化された従業員のデータはエクスポートできません。');
      return res.redirect('/admin');
    }
    const targetYear = year;
    const targetMonth = month;

    const detailed = await getUserMonthlyDetailedSessions(employee.id, targetYear, targetMonth);
    const { start } = getMonthRange(targetYear, targetMonth);
    const fileName = `${employee.username}_${start.toFormat('yyyyMM')}.xlsx`;

    const workbook = await XlsxPopulate.fromBlankAsync();
    const sheet = workbook.sheet(0);
    sheet.name('勤務記録');

    sheet.cell('A1').value('従業員');
    sheet.cell('B1').value(employee.username);
    sheet.cell('A2').value('対象月');
    sheet.cell('A2').value('対象月');
    sheet.cell('B2').value(`${targetYear}年${String(targetMonth).padStart(2, '0')}月`);
    sheet.cell('A4').value('日付');
    sheet.cell('B4').value('勤務開始');
    sheet.cell('C4').value('勤務終了');
    sheet.cell('D4').value('勤務時間（分）');
    sheet.cell('E4').value('勤務時間（hh:mm）');
    let row = 5;
    detailed.days.forEach((day) => {
      day.sessions.forEach((session) => {
        sheet.cell(`A${row}`).value(day.date);
        sheet.cell(`B${row}`).value(session.start);
        sheet.cell(`C${row}`).value(session.end);
        sheet.cell(`D${row}`).value(session.minutes);
        sheet.cell(`E${row}`).value(session.formattedMinutes);
        row += 1;
      });
      if (day.sessions.length === 0) {
        sheet.cell(`A${row}`).value(day.date);
        sheet.cell(`E${row}`).value(day.formattedMinutes);
        row += 1;
      }
    });

    sheet.cell(`D${row + 1}`).value('合計（分）');
    sheet.cell(`E${row + 1}`).value('合計（hh:mm）');
    sheet.cell(`D${row + 2}`).value(detailed.totalMinutes);
    sheet.cell(`E${row + 2}`).value(detailed.formattedTotal);

    const buffer = await workbook.outputAsync();

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader('Content-Disposition', `attachment; filename=${encodeURIComponent(fileName)}`);
    res.send(buffer);
  }
);

app.post(
  '/platform/tenant-admins/:userId/mfa/reset',
  requireRole(ROLES.PLATFORM),
  async (req, res) => {
    const tenantAdmin = await getTenantAdminForPlatform(req, res);
    if (!tenantAdmin) {
      return;
    }
    const reason = (req.body.reason || '').trim();
    if (!reason) {
      setFlash(req, 'error', 'リセット理由を入力してください。');
      return res.redirect('/platform/tenants');
    }
    const existingTotp = await getMfaMethodByUserAndType(tenantAdmin.id, MFA_TYPES.TOTP);
    const recoveryCodes = await listRecoveryCodesByUser(tenantAdmin.id);
    const previousMethodSnapshot = snapshotMfaMethod(existingTotp);
    const previousRecoveryCodesSnapshot = snapshotRecoveryCodes(recoveryCodes);
    const previousMethodPayload = previousMethodSnapshot
      ? encryptSensitiveLogPayload(previousMethodSnapshot)
      : null;
    const previousRecoveryCodesPayload =
      Array.isArray(previousRecoveryCodesSnapshot) && previousRecoveryCodesSnapshot.length > 0
        ? encryptSensitiveLogPayload(previousRecoveryCodesSnapshot)
        : null;
    if (
      (previousMethodSnapshot &&
        (!previousMethodPayload || previousMethodPayload === ENCRYPTION_FAILURE_SENTINEL)) ||
      (previousRecoveryCodesSnapshot &&
        previousRecoveryCodesSnapshot.length > 0 &&
        (!previousRecoveryCodesPayload ||
          previousRecoveryCodesPayload === ENCRYPTION_FAILURE_SENTINEL))
    ) {
      setFlash(
        req,
        'error',
        '監査ログの暗号化に失敗したため、リセット処理を中断しました。システム管理者へ連絡してください。'
      );
      return res.redirect('/platform/tenants');
    }
    await createTenantAdminMfaResetLog({
      targetUserId: tenantAdmin.id,
      performedByUserId: req.session.user.id,
      reason,
      previousMethod: previousMethodPayload,
      previousRecoveryCodes: previousRecoveryCodesPayload,
    });
    await deleteMfaMethodsByUserAndType(tenantAdmin.id, MFA_TYPES.TOTP);
    await deleteRecoveryCodesByUser(tenantAdmin.id);
    await deleteTrustedDevicesByUser(tenantAdmin.id);
    if (req.session.pendingMfa && req.session.pendingMfa.userId === tenantAdmin.id) {
      clearPendingMfa(req);
    }
    setFlash(req, 'success', `テナント管理者「${tenantAdmin.username}」の2FAをリセットしました。`);
    return res.redirect('/platform/tenants');
  }
);

app.post(
  '/platform/tenant-admins/:userId/mfa/rollback',
  requireRole(ROLES.PLATFORM),
  async (req, res) => {
    const tenantAdmin = await getTenantAdminForPlatform(req, res);
    if (!tenantAdmin) {
      return;
    }
    const rollbackReason = (req.body.rollbackReason || '').trim();
    if (!rollbackReason) {
      setFlash(req, 'error', '取消理由を入力してください。');
      return res.redirect('/platform/tenants');
    }
    const logId = Number.parseInt(req.body.logId, 10);
    if (!Number.isFinite(logId)) {
      setFlash(req, 'error', '取り消す対象のリセット情報が見つかりません。');
      return res.redirect('/platform/tenants');
    }
    const latestLog = await getLatestTenantAdminMfaResetLog(tenantAdmin.id);
    if (!latestLog || latestLog.id !== logId) {
      setFlash(req, 'error', '直前のリセット情報が一致しないため、取り消しできません。');
      return res.redirect('/platform/tenants');
    }
    if (latestLog.rolled_back_at) {
      setFlash(req, 'error', 'このリセットはすでに取り消されています。');
      return res.redirect('/platform/tenants');
    }
    const currentMethod = await getMfaMethodByUserAndType(tenantAdmin.id, MFA_TYPES.TOTP);
    if (currentMethod) {
      setFlash(req, 'error', '現在2FAが再設定されているため、取り消しできません。');
      return res.redirect('/platform/tenants');
    }
    const previousMethod = readResetLogPayload(latestLog.previous_method_json, null);
    const previousRecoveryCodes = readResetLogPayload(
      latestLog.previous_recovery_codes_json,
      []
    );
    await deleteMfaMethodsByUserAndType(tenantAdmin.id, MFA_TYPES.TOTP);
    if (previousMethod) {
      await restoreMfaMethod(tenantAdmin.id, MFA_TYPES.TOTP, previousMethod);
    }
    await deleteRecoveryCodesByUser(tenantAdmin.id);
    if (Array.isArray(previousRecoveryCodes) && previousRecoveryCodes.length > 0) {
      await restoreRecoveryCodes(tenantAdmin.id, previousRecoveryCodes);
    }
    await markTenantAdminMfaResetRolledBack(logId, rollbackReason, req.session.user.id);
    setFlash(
      req,
      'success',
      `テナント管理者「${tenantAdmin.username}」の直前の2FAリセットを取り消しました。`
    );
    return res.redirect('/platform/tenants');
  }
);

app.get('/platform/tenants', requireRole(ROLES.PLATFORM), async (req, res) => {
  const tenantRows = await listTenants();
  const tenants = tenantRows.map((tenant) => ({
    ...tenant,
    createdAtDisplay: formatDisplayDateTime(tenant.created_at),
  }));
  const tenantAdminRows = await listTenantAdmins();
  const tenantAdmins = await Promise.all(
    tenantAdminRows.map(async (admin) => {
      const verifiedTotp = await getVerifiedMfaMethod(admin.id, MFA_TYPES.TOTP);
      const latestReset = await getLatestTenantAdminMfaResetLog(admin.id);
      const lastReset = latestReset
        ? {
            id: latestReset.id,
            createdAtDisplay: latestReset.created_at ? formatDisplayDateTime(latestReset.created_at) : '',
            reason: latestReset.reason || '',
            rolledBackAtDisplay: latestReset.rolled_back_at
              ? formatDisplayDateTime(latestReset.rolled_back_at)
              : null,
            rollbackReason: latestReset.rollback_reason || null,
          }
        : null;
      return {
        id: admin.id,
        username: admin.username,
        email: admin.email,
        phoneNumber: admin.phone_number || '',
        tenantName: admin.tenant_name || '名称未設定',
        tenantUid: admin.tenant_uid || '-',
        tenantStatus: admin.tenant_status || TENANT_STATUS.INACTIVE,
        hasMfa: Boolean(verifiedTotp),
        lastReset,
      };
    })
  );
  const generated = req.session.generatedTenantCredential || null;
  delete req.session.generatedTenantCredential;

  res.render('platform_tenants', {
    tenants,
    tenantAdmins,
    generated,
    minPasswordLength: PASSWORD_MIN_LENGTH,
  });
});

app.post('/platform/tenants', requireRole(ROLES.PLATFORM), async (req, res) => {
  const tenantNameResult = validateNameField('テナント名', req.body.tenantName || '名称未設定');
  if (!tenantNameResult.valid) {
    setFlash(req, 'error', tenantNameResult.message);
    return res.redirect('/platform/tenants');
  }
  const contactEmail = normalizeEmail(req.body.contactEmail);
  if (!contactEmail) {
    setFlash(req, 'error', 'テナント連絡先メールアドレスを入力してください。');
    return res.redirect('/platform/tenants');
  }
  const adminFirstNameResult = validateNameField('管理者（名）', req.body.adminFirstName);
  if (!adminFirstNameResult.valid) {
    setFlash(req, 'error', adminFirstNameResult.message);
    return res.redirect('/platform/tenants');
  }
  const adminLastNameResult = validateNameField('管理者（姓）', req.body.adminLastName);
  if (!adminLastNameResult.valid) {
    setFlash(req, 'error', adminLastNameResult.message);
    return res.redirect('/platform/tenants');
  }
  const adminEmail = normalizeEmail(req.body.adminEmail);
  if (!adminEmail) {
    setFlash(req, 'error', '管理者メールアドレスを入力してください。');
    return res.redirect('/platform/tenants');
  }
  const adminPhoneResult = validatePhoneNumberField('管理者電話番号', req.body.adminPhoneNumber);
  if (!adminPhoneResult.valid) {
    setFlash(req, 'error', adminPhoneResult.message);
    return res.redirect('/platform/tenants');
  }
  const existingTenantAdmin = await getUserByEmail(adminEmail);
  if (existingTenantAdmin) {
    setFlash(req, 'error', '指定された管理者メールアドレスは既に使用されています。');
    return res.redirect('/platform/tenants');
  }

  const tenantUid = await generateTenantUid();
  let tenant;
  try {
    tenant = await createTenant({
      tenantUid,
      name: tenantNameResult.value,
      contactEmail,
    });
  } catch (error) {
    console.error('[platform] テナント作成に失敗しました', error);
    setFlash(req, 'error', 'テナントの登録に失敗しました。時間をおいて再試行してください。');
    return res.redirect('/platform/tenants');
  }

  const initialPassword = generateInitialAdminPassword(16);
  const hashedPassword = await hashPassword(initialPassword);
  const username = `${adminLastNameResult.value}${adminFirstNameResult.value}`;

  try {
    await createUser({
      tenantId: tenant.id,
      username,
      email: adminEmail,
      passwordHash: hashedPassword,
      role: ROLES.TENANT,
      mustChangePassword: true,
      firstName: adminFirstNameResult.value,
      lastName: adminLastNameResult.value,
      phoneNumber: adminPhoneResult.value,
    });
  } catch (error) {
    console.error('[platform] テナント管理者アカウント作成に失敗しました', error);
    try {
      await deleteTenantById(tenant.id);
    } catch (cleanupError) {
      console.error('[platform] テナント作成失敗時のロールバックに失敗しました', cleanupError);
    }
    setFlash(req, 'error', 'テナント管理者アカウントの作成に失敗しました。');
    return res.redirect('/platform/tenants');
  }

  req.session.generatedTenantCredential = {
    tenantUid,
    adminEmail,
    initialPassword,
  };

  setFlash(req, 'success', 'テナントと管理者アカウントを作成しました。');
  return res.redirect('/platform/tenants');
});

app.post('/platform/tenants/:tenantId/status', requireRole(ROLES.PLATFORM), async (req, res) => {
  const tenantId = Number.parseInt(req.params.tenantId, 10);
  if (!Number.isFinite(tenantId)) {
    setFlash(req, 'error', 'テナントが見つかりません。');
    return res.redirect('/platform/tenants');
  }
  const tenant = await getTenantById(tenantId);
  if (!tenant) {
    setFlash(req, 'error', 'テナントが見つかりません。');
    return res.redirect('/platform/tenants');
  }
  const action = (req.body.action || '').toLowerCase();
  if (action === 'deactivate') {
    if (tenant.status === TENANT_STATUS.INACTIVE) {
      setFlash(req, 'info', 'すでに停止済みです。');
    } else {
      await updateTenantStatus(tenant.id, TENANT_STATUS.INACTIVE);
      setFlash(req, 'success', 'テナントを停止しました。');
    }
  } else if (action === 'activate') {
    if (tenant.status === TENANT_STATUS.ACTIVE) {
      setFlash(req, 'info', 'すでに有効です。');
    } else {
      await updateTenantStatus(tenant.id, TENANT_STATUS.ACTIVE);
      setFlash(req, 'success', 'テナントを再開しました。');
    }
  } else {
    setFlash(req, 'error', '不明な操作です。');
  }
  return res.redirect('/platform/tenants');
});

app.use((err, req, res, next) => {
  if (err.code !== 'EBADCSRFTOKEN') {
    return next(err);
  }
  // eslint-disable-next-line no-console
  console.warn('[csrf] Invalid CSRF token detected', { path: req.path });
  if (req.session) {
    setFlash(req, 'error', 'セキュリティチェックに失敗しました。もう一度操作をやり直してください。');
    const fallbackRedirect = req.get('referer') || '/';
    return res.redirect(fallbackRedirect);
  }
  return res.status(403).send('Invalid CSRF token');
});

module.exports = app;
