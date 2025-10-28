﻿const express = require('express');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const Tokens = require('csrf');
const XlsxPopulate = require('xlsx-populate');

const {
  getSqlClient,
  createTenant,
  getTenantById,
  getTenantByUid,
  listTenants,
  createUser,
  updateUserPassword,
  setMustChangePassword,
  getUserByEmail,
  getUserById,
  getAllEmployeesByTenant,
  createWorkSession,
  closeWorkSession,
  createWorkSessionWithEnd,
  updateWorkSessionTimes,
  getOpenWorkSession,
  getWorkSessionsByUserBetween,
  getAllWorkSessionsByUser,
  getWorkSessionById,
  deleteWorkSession,
  recordLoginFailure,
  resetLoginFailures,
  createRoleCode,
  getRoleCodeByCode,
  getRoleCodeById,
  listRoleCodesByTenant,
  incrementRoleCodeUsage,
  disableRoleCode,
  createPasswordResetToken,
  getPasswordResetToken,
  consumePasswordResetToken,
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
  diffMinutes,
  formatForDateTimeInput,
  parseDateTimeInput,
} = require('./utils/time');

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
  '莉悶・蜍､諤險倬鹸縺ｨ譎る俣縺碁㍾隍・＠縺ｦ縺・∪縺吶ゆｿｮ豁｣蟇ｾ雎｡縺ｮ譎る俣蟶ｯ繧定ｦ狗峩縺励※縺上□縺輔＞縲・;
const LOGIN_FAILURE_LIMIT = 5;
const LOGIN_LOCK_MINUTES = 15;
const ROLE_CODE_LENGTH = 16;
const ROLE_CODE_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ROLES = {
  PLATFORM: 'platform_admin',
  TENANT: 'tenant_admin',
  EMPLOYEE: 'employee',
};

const DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 12;

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

const configuredSessionTtlSeconds = parsePositiveInt(
  process.env.SESSION_TTL_SECONDS,
  DEFAULT_SESSION_TTL_SECONDS
);

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
  return new KnexSessionStore({
    knex: getSqlClient(),
    tablename: process.env.SESSION_TABLE_NAME || 'sessions',
    createtable: true,
    clearInterval: clearIntervalMs,
    ttl: configuredSessionTtlSeconds * 1000,
  });
}

const sessionSecret = loadSessionSecret();
const sessionStore = createSessionStore(sessionSecret);

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
      secure: parseBoolean(process.env.SESSION_COOKIE_SECURE, process.env.NODE_ENV === 'production'),
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
  setFlash(req, 'info', '蛻晏屓繝ｭ繧ｰ繧､繝ｳ縺ｮ縺溘ａ繝代せ繝ｯ繝ｼ繝峨ｒ螟画峩縺励※縺上□縺輔＞縲・);
  return res.redirect('/password/change');
});

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function normalizeEmail(email) {
  return (email || '').trim().toLowerCase();
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
  const sessions = await getAllWorkSessionsByUser(userId);
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
      setFlash(req, 'error', '繝ｭ繧ｰ繧､繝ｳ縺励※縺上□縺輔＞縲・);
      return res.redirect('/login');
    }
    if (!roles.includes(req.session.user.role)) {
      setFlash(req, 'error', '讓ｩ髯舌′縺ゅｊ縺ｾ縺帙ｓ縲・);
      return res.redirect('/');
    }
    return next();
  };
}

function ensureTenantContext(req, res, next) {
  if (!req.session.user || !req.session.user.tenantId) {
    setFlash(req, 'error', '繝・リ繝ｳ繝域ュ蝣ｱ縺悟ｭ伜惠縺励∪縺帙ｓ縲・);
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

const buildAdminSessionsUrl = (userId, query = {}) =>
  `/admin/employees/${userId}/sessions${buildSessionQuery(query)}`;

async function getEmployeeForTenantAdmin(req, res) {
  const employeeId = Number.parseInt(req.params.userId, 10);
  const employee = Number.isNaN(employeeId) ? null : await getUserById(employeeId);
  if (!employee || employee.role !== ROLES.EMPLOYEE) {
    setFlash(req, 'error', '蠕捺･ｭ蜩｡縺瑚ｦ九▽縺九ｊ縺ｾ縺帙ｓ縲・);
    res.redirect('/admin');
    return null;
  }
  if (employee.tenant_id !== req.session.user.tenantId) {
    setFlash(req, 'error', '莉悶ユ繝翫Φ繝医・蠕捺･ｭ蜩｡縺ｫ縺ｯ繧｢繧ｯ繧ｻ繧ｹ縺ｧ縺阪∪縺帙ｓ縲・);
    res.redirect('/admin');
    return null;
  }
  return employee;
}

function validateNameField(label, value) {
  const trimmed = (value || '').trim();
  if (!trimmed) {
    return { valid: false, message: `${label}繧貞・蜉帙＠縺ｦ縺上□縺輔＞縲Ａ };
  }
  if (trimmed.length > 64) {
    return { valid: false, message: `${label}縺ｯ64譁・ｭ嶺ｻ･蜀・〒蜈･蜉帙＠縺ｦ縺上□縺輔＞縲Ａ };
  }
  for (let i = 0; i < trimmed.length; i += 1) {
    const code = trimmed.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return { valid: false, message: `${label}縺ｫ蛻ｶ蠕｡譁・ｭ励・菴ｿ逕ｨ縺ｧ縺阪∪縺帙ｓ縲Ａ };
    }
  }
  return { valid: true, value: trimmed };
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
  return res.render('login', {
    minPasswordLength: PASSWORD_MIN_LENGTH,
    lockLimit: LOGIN_FAILURE_LIMIT,
    lockMinutes: LOGIN_LOCK_MINUTES,
  });
});

app.post('/login', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = (req.body.password || '').trim();

  if (!email || !password) {
    setFlash(req, 'error', '繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｨ繝代せ繝ｯ繝ｼ繝峨ｒ蜈･蜉帙＠縺ｦ縺上□縺輔＞縲・);
    return res.redirect('/login');
  }

  const user = await getUserByEmail(email);
  if (!user) {
    setFlash(req, 'error', '繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｾ縺溘・繝代せ繝ｯ繝ｼ繝峨′豁｣縺励￥縺ゅｊ縺ｾ縺帙ｓ縲・);
    return res.redirect('/login');
  }

  const now = new Date();
  if (user.locked_until && Date.parse(user.locked_until) > now.getTime()) {
    const remainingMs = Date.parse(user.locked_until) - now.getTime();
    const remainingMinutes = Math.ceil(remainingMs / (60 * 1000));
    setFlash(
      req,
      'error',
      `繧｢繧ｫ繧ｦ繝ｳ繝医′繝ｭ繝・け縺輔ｌ縺ｦ縺・∪縺吶・{remainingMinutes}蛻・ｾ後↓蜀榊ｺｦ縺願ｩｦ縺励￥縺縺輔＞縲Ａ
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
        `繝ｭ繧ｰ繧､繝ｳ縺ｫ${LOGIN_FAILURE_LIMIT}蝗樣｣邯壹〒螟ｱ謨励＠縺溘◆繧√・{LOGIN_LOCK_MINUTES}蛻・俣繝ｭ繝・け縺励∪縺励◆縲Ａ
      );
    } else {
      const remaining = Math.max(0, LOGIN_FAILURE_LIMIT - meta.failed_attempts);
      setFlash(
        req,
        'error',
        `繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｾ縺溘・繝代せ繝ｯ繝ｼ繝峨′豁｣縺励￥縺ゅｊ縺ｾ縺帙ｓ縲ゑｼ医≠縺ｨ${remaining}蝗槭〒繝ｭ繝・け・荏
      );
    }
    return res.redirect('/login');
  }

  await resetLoginFailures(user.id);
  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role,
    tenantId: user.tenant_id,
  };

  if (user.must_change_password) {
    req.session.user.mustChangePassword = true;
    setFlash(req, 'info', '蛻晏屓繝ｭ繧ｰ繧､繝ｳ縺ｮ縺溘ａ繝代せ繝ｯ繝ｼ繝峨ｒ螟画峩縺励※縺上□縺輔＞縲・);
    return res.redirect('/password/change');
  }

  setFlash(req, 'success', '繝ｭ繧ｰ繧､繝ｳ縺励∪縺励◆縲・);
  return res.redirect('/');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  return res.render('register', { minPasswordLength: PASSWORD_MIN_LENGTH });
});

app.post('/register', async (req, res) => {
  const roleCodeValue = (req.body.roleCode || '').trim().toUpperCase();
  const firstNameResult = validateNameField('蜷・, req.body.firstName);
  if (!firstNameResult.valid) {
    setFlash(req, 'error', firstNameResult.message);
    return res.redirect('/register');
  }
  const lastNameResult = validateNameField('蟋・, req.body.lastName);
  if (!lastNameResult.valid) {
    setFlash(req, 'error', lastNameResult.message);
    return res.redirect('/register');
  }
  const email = normalizeEmail(req.body.email);
  if (!email) {
    setFlash(req, 'error', '繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ繧貞・蜉帙＠縺ｦ縺上□縺輔＞縲・);
    return res.redirect('/register');
  }
  const newPassword = req.body.password || '';

  if (!roleCodeValue) {
    setFlash(req, 'error', '繝ｭ繝ｼ繝ｫ繧ｳ繝ｼ繝峨ｒ蜈･蜉帙＠縺ｦ縺上□縺輔＞縲・);
    return res.redirect('/register');
  }

  const roleCode = await getRoleCodeByCode(roleCodeValue);
  if (!roleCode) {
    setFlash(req, 'error', '繝ｭ繝ｼ繝ｫ繧ｳ繝ｼ繝峨′辟｡蜉ｹ縺ｧ縺吶・);
    return res.redirect('/register');
  }
  if (roleCode.is_disabled) {
    setFlash(req, 'error', '縺薙・繝ｭ繝ｼ繝ｫ繧ｳ繝ｼ繝峨・辟｡蜉ｹ蛹悶＆繧後※縺・∪縺吶・);
    return res.redirect('/register');
  }
  if (roleCode.expires_at && Date.parse(roleCode.expires_at) <= Date.now()) {
    setFlash(req, 'error', '繝ｭ繝ｼ繝ｫ繧ｳ繝ｼ繝峨・譛牙柑譛滄剞縺悟・繧後※縺・∪縺吶・);
    return res.redirect('/register');
  }
  if (roleCode.max_uses !== null && roleCode.usage_count >= roleCode.max_uses) {
    setFlash(req, 'error', '繝ｭ繝ｼ繝ｫ繧ｳ繝ｼ繝峨・蛻ｩ逕ｨ荳企剞縺ｫ驕斐＠縺ｦ縺・∪縺吶・);
    return res.redirect('/register');
  }

  const existingUser = await getUserByEmail(email);
  if (existingUser) {
    setFlash(req, 'error', '縺薙・繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｯ譌｢縺ｫ逋ｻ骭ｲ縺輔ｌ縺ｦ縺・∪縺吶・);
    return res.redirect('/register');
  }

  const validation = validatePassword(newPassword);
  if (!validation.valid) {
    setFlash(req, 'error', validation.message);
    return res.redirect('/register');
  }

  const tenant = await getTenantById(roleCode.tenant_id);
  if (!tenant) {
    setFlash(req, 'error', '繝ｭ繝ｼ繝ｫ繧ｳ繝ｼ繝峨↓蟇ｾ蠢懊☆繧九ユ繝翫Φ繝医′隕九▽縺九ｊ縺ｾ縺帙ｓ縲・);
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
    setFlash(req, 'success', '繧｢繧ｫ繧ｦ繝ｳ繝医ｒ菴懈・縺励∪縺励◆縲ゅΟ繧ｰ繧､繝ｳ縺励※縺上□縺輔＞縲・);
    return res.redirect('/login');
  } catch (error) {
    console.error('[register] 蠕捺･ｭ蜩｡繧｢繧ｫ繧ｦ繝ｳ繝井ｽ懈・縺ｫ螟ｱ謨励＠縺ｾ縺励◆', error);
    setFlash(req, 'error', '繧｢繧ｫ繧ｦ繝ｳ繝井ｽ懈・荳ｭ縺ｫ繧ｨ繝ｩ繝ｼ縺檎匱逕溘＠縺ｾ縺励◆縲・);
    return res.redirect('/register');
  }
});

app.get('/password/reset', (req, res) => {
  res.render('password_reset_request');
});

app.post('/password/reset', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  if (!email) {
    setFlash(req, 'error', '繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ繧貞・蜉帙＠縺ｦ縺上□縺輔＞縲・);
    return res.redirect('/password/reset');
  }

  const user = await getUserByEmail(email);
  if (!user) {
    setFlash(req, 'info', '繝代せ繝ｯ繝ｼ繝峨Μ繧ｻ繝・ヨ謇矩・ｒ繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｸ騾∽ｿ｡縺励∪縺励◆縲・);
    return res.redirect('/login');
  }

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await createPasswordResetToken(user.id, token, expiresAt);

  const resetLink = new URL(`/password/reset/${token}`, appBaseUrl).toString();
  if (process.env.NODE_ENV !== 'production') {
    console.info(`[password-reset] ${email} 逕ｨ繝ｪ繧ｻ繝・ヨ繝ｪ繝ｳ繧ｯ: ${resetLink}`);
  } else {
    console.info(`[password-reset] ${email} 縺ｸ縺ｮ繝ｪ繧ｻ繝・ヨ謇狗ｶ壹″繧定ｨ倬鹸縺励∪縺励◆`);
  }

  setFlash(
    req,
    'info',
    '繝代せ繝ｯ繝ｼ繝峨Μ繧ｻ繝・ヨ逕ｨ縺ｮ繝ｪ繝ｳ繧ｯ繧偵Γ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｸ騾∽ｿ｡縺励∪縺励◆縲ゑｼ郁ｩｦ菴懃腸蠅・〒縺ｯ繧ｵ繝ｼ繝舌・繝ｭ繧ｰ繧堤｢ｺ隱阪＠縺ｦ縺上□縺輔＞・・
  );
  return res.redirect('/login');
});

app.get('/password/reset/:token', async (req, res) => {
  const record = await getPasswordResetToken(req.params.token);
  if (!record) {
    setFlash(req, 'error', '繝ｪ繧ｻ繝・ヨ繝ｪ繝ｳ繧ｯ縺檎┌蜉ｹ縺ｧ縺吶ょ・蠎ｦ謇狗ｶ壹″繧定｡後▲縺ｦ縺上□縺輔＞縲・);
    return res.redirect('/password/reset');
  }
  if (Date.parse(record.expires_at) <= Date.now()) {
    setFlash(req, 'error', '繝ｪ繧ｻ繝・ヨ繝ｪ繝ｳ繧ｯ縺ｮ譛牙柑譛滄剞縺悟・繧後※縺・∪縺吶・);
    return res.redirect('/password/reset');
  }
  return res.render('password_reset_update', {
    token: req.params.token,
    minPasswordLength: PASSWORD_MIN_LENGTH,
  });
});

app.post('/password/reset/:token', async (req, res) => {
  const record = await getPasswordResetToken(req.params.token);
  if (!record) {
    setFlash(req, 'error', '繝ｪ繧ｻ繝・ヨ繝ｪ繝ｳ繧ｯ縺檎┌蜉ｹ縺ｧ縺吶ょ・蠎ｦ謇狗ｶ壹″繧定｡後▲縺ｦ縺上□縺輔＞縲・);
    return res.redirect('/password/reset');
  }
  if (Date.parse(record.expires_at) <= Date.now()) {
    setFlash(req, 'error', '繝ｪ繧ｻ繝・ヨ繝ｪ繝ｳ繧ｯ縺ｮ譛牙柑譛滄剞縺悟・繧後※縺・∪縺吶・);
    return res.redirect('/password/reset');
  }

  const user = await getUserById(record.user_id);
  if (!user) {
    setFlash(req, 'error', '繝ｦ繝ｼ繧ｶ繝ｼ縺悟ｭ伜惠縺励∪縺帙ｓ縲・);
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

  setFlash(req, 'success', '繝代せ繝ｯ繝ｼ繝峨ｒ蜀崎ｨｭ螳壹＠縺ｾ縺励◆縲ゅΟ繧ｰ繧､繝ｳ縺励※縺上□縺輔＞縲・);
  return res.redirect('/login');
});

app.get('/password/change', requireRole(ROLES.PLATFORM, ROLES.TENANT, ROLES.EMPLOYEE), (req, res) => {
  res.render('password_change', {
    action: '/password/change',
    minPasswordLength: PASSWORD_MIN_LENGTH,
  });
});

app.post(
  '/password/change',
  requireRole(ROLES.PLATFORM, ROLES.TENANT, ROLES.EMPLOYEE),
  async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const user = await getUserById(req.session.user.id);
    if (!user) {
      setFlash(req, 'error', '繝ｦ繝ｼ繧ｶ繝ｼ縺瑚ｦ九▽縺九ｊ縺ｾ縺帙ｓ縲・);
      return res.redirect('/password/change');
    }

    const ok = await comparePassword(currentPassword || '', user.password_hash);
    if (!ok) {
      setFlash(req, 'error', '迴ｾ蝨ｨ縺ｮ繝代せ繝ｯ繝ｼ繝峨′豁｣縺励￥縺ゅｊ縺ｾ縺帙ｓ縲・);
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
    setFlash(req, 'success', '繝代せ繝ｯ繝ｼ繝峨ｒ螟画峩縺励∪縺励◆縲・);
    return res.redirect('/');
  }
);

app.get('/employee', requireRole(ROLES.EMPLOYEE), async (req, res) => {
  const userId = req.session.user.id;
  const now = new Date();
  const openSession = await getOpenWorkSession(userId);
  const dailySummary = await getUserDailySummary(userId, 30);
  const monthDate = toZonedDateTime(now.toISOString());
  const monthlySummary = await getUserMonthlySummary(userId, monthDate.year, monthDate.month);

  const allSessions = await getAllWorkSessionsByUser(userId);
  const sessionHistory = allSessions
    .slice(0, 10)
    .map((session) => {
      const durationMinutes = session.end_time
        ? diffMinutes(session.start_time, session.end_time)
        : null;
      return {
        id: session.id,
        startFormatted: formatDateTime(session.start_time),
        endFormatted: session.end_time ? formatDateTime(session.end_time) : '險倬鹸荳ｭ',
        minutes: durationMinutes,
        formattedMinutes: durationMinutes !== null ? formatMinutesToHM(durationMinutes) : '窶・,
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

app.post('/employee/record', requireRole(ROLES.EMPLOYEE), async (req, res) => {
  const userId = req.session.user.id;
  const openSession = await getOpenWorkSession(userId);
  const nowIso = new Date().toISOString();
  if (openSession) {
    await closeWorkSession(openSession.id, nowIso);
    setFlash(req, 'success', '蜍､蜍咏ｵゆｺ・ｒ險倬鹸縺励∪縺励◆縲・);
  } else {
    await createWorkSession(userId, nowIso);
    setFlash(req, 'success', '蜍､蜍咎幕蟋九ｒ險倬鹸縺励∪縺励◆縲・);
  }
  return res.redirect('/employee');
});

app.get(
  '/admin',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const now = new Date();
    const { year, month } = req.query;
    const baseDate =
      year && month
        ? toZonedDateTime(new Date(Date.UTC(year, month - 1, 1)).toISOString())
        : toZonedDateTime(now.toISOString());
    const targetYear = parseInt(year || baseDate.year, 10);
    const targetMonth = parseInt(month || baseDate.month, 10);

    const tenantId = req.session.user.tenantId;
    const monthlySummary = await getMonthlySummaryForAllEmployees(tenantId, targetYear, targetMonth);

    res.render('admin_dashboard', {
      monthlySummary,
      targetYear,
      targetMonth,
      tenantId,
    });
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
      };
    });

    let generated = req.session.generatedRoleCodeResult || null;
    delete req.session.generatedRoleCodeResult;
    if (generated) {
      generated = {
        ...generated,
        expiresDisplay: generated.expiresDisplay || formatDisplayDateTime(generated.expiresAt),
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
      setFlash(req, 'error', '譛牙柑譛滄剞縺ｯ迴ｾ蝨ｨ繧医ｊ蠕後・譌･譎ゅｒ謖・ｮ壹＠縺ｦ縺上□縺輔＞縲・);
      return res.redirect('/admin/role-codes');
    }

    let maxUses = null;
    if (maxUsesInput) {
      const parsed = Number.parseInt(maxUsesInput, 10);
      if (Number.isNaN(parsed) || parsed <= 0) {
        setFlash(req, 'error', '菴ｿ逕ｨ蝗樊焚荳企剞縺ｯ1莉･荳翫・謨ｴ謨ｰ縺ｧ謖・ｮ壹＠縺ｦ縺上□縺輔＞縲・);
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
    };

    setFlash(req, 'success', '繝ｭ繝ｼ繝ｫ繧ｳ繝ｼ繝峨ｒ逋ｺ陦後＠縺ｾ縺励◆縲・);
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
      setFlash(req, 'error', '繝ｭ繝ｼ繝ｫ繧ｳ繝ｼ繝峨′隕九▽縺九ｊ縺ｾ縺帙ｓ縲・);
      return res.redirect('/admin/role-codes');
    }
    await disableRoleCode(roleCode.id);
    setFlash(req, 'success', '繝ｭ繝ｼ繝ｫ繧ｳ繝ｼ繝峨ｒ辟｡蜉ｹ蛹悶＠縺ｾ縺励◆縲・);
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

    const now = new Date();
    const requestedYear = Number.parseInt(req.query.year, 10);
    const requestedMonth = Number.parseInt(req.query.month, 10);
    const baseDate =
      !Number.isNaN(requestedYear) && !Number.isNaN(requestedMonth)
        ? toZonedDateTime(new Date(Date.UTC(requestedYear, requestedMonth - 1, 1)).toISOString())
        : toZonedDateTime(now.toISOString());
    const targetYear = Number.isNaN(requestedYear) ? baseDate.year : requestedYear;
    const targetMonth = Number.isNaN(requestedMonth) ? baseDate.month : requestedMonth;

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
        endDisplay: session.end_time ? formatDateTime(session.end_time) : '險倬鹸荳ｭ',
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
      queryString: buildSessionQuery(req.query),
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

    const startInput = (req.body.startTime || '').trim();
    const endInput = (req.body.endTime || '').trim();
    const startIso = parseDateTimeInput(startInput);
    const endIso = parseDateTimeInput(endInput);

    if (!startIso || !endIso) {
      setFlash(req, 'error', '髢句ｧ九→邨ゆｺ・・譌･譎ゅｒ豁｣縺励￥蜈･蜉帙＠縺ｦ縺上□縺輔＞縲・);
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    if (diffMinutes(startIso, endIso) <= 0) {
      setFlash(req, 'error', '邨ゆｺ・凾蛻ｻ縺ｯ髢句ｧ区凾蛻ｻ繧医ｊ蠕後↓險ｭ螳壹＠縺ｦ縺上□縺輔＞縲・);
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    if (await hasOverlappingSessions(employee.id, startIso, endIso)) {
      setFlash(req, 'error', OVERLAP_ERROR_MESSAGE);
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    await createWorkSessionWithEnd(employee.id, startIso, endIso);
    setFlash(req, 'success', '蜍､蜍呵ｨ倬鹸繧定ｿｽ蜉縺励∪縺励◆縲・);
    res.redirect(buildAdminSessionsUrl(employee.id, req.query));
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

    const sessionId = Number.parseInt(req.params.sessionId, 10);
    const sessionRecord = Number.isNaN(sessionId) ? null : await getWorkSessionById(sessionId);
    if (!sessionRecord || sessionRecord.user_id !== employee.id) {
      setFlash(req, 'error', '隧ｲ蠖薙☆繧句共蜍呵ｨ倬鹸縺瑚ｦ九▽縺九ｊ縺ｾ縺帙ｓ縲・);
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    const startInput = (req.body.startTime || '').trim();
    const endInput = (req.body.endTime || '').trim();
    const startIso = parseDateTimeInput(startInput);

    if (!startIso) {
      setFlash(req, 'error', '髢句ｧ区凾蛻ｻ繧呈ｭ｣縺励￥蜈･蜉帙＠縺ｦ縺上□縺輔＞縲・);
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    let endIso = null;
    if (endInput) {
      endIso = parseDateTimeInput(endInput);
      if (!endIso) {
        setFlash(req, 'error', '邨ゆｺ・凾蛻ｻ繧呈ｭ｣縺励￥蜈･蜉帙＠縺ｦ縺上□縺輔＞縲・);
        res.redirect(buildAdminSessionsUrl(employee.id, req.query));
        return;
      }
      if (diffMinutes(startIso, endIso) <= 0) {
        setFlash(req, 'error', '邨ゆｺ・凾蛻ｻ縺ｯ髢句ｧ区凾蛻ｻ繧医ｊ蠕後↓險ｭ螳壹＠縺ｦ縺上□縺輔＞縲・);
        res.redirect(buildAdminSessionsUrl(employee.id, req.query));
        return;
      }
    }

    if (await hasOverlappingSessions(employee.id, startIso, endIso, sessionRecord.id)) {
      setFlash(req, 'error', OVERLAP_ERROR_MESSAGE);
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    await updateWorkSessionTimes(sessionRecord.id, startIso, endIso);
    setFlash(req, 'success', '蜍､蜍呵ｨ倬鹸繧呈峩譁ｰ縺励∪縺励◆縲・);
    res.redirect(buildAdminSessionsUrl(employee.id, req.query));
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

    const sessionId = Number.parseInt(req.params.sessionId, 10);
    const sessionRecord = Number.isNaN(sessionId) ? null : await getWorkSessionById(sessionId);
    if (!sessionRecord || sessionRecord.user_id !== employee.id) {
      setFlash(req, 'error', '隧ｲ蠖薙☆繧句共蜍呵ｨ倬鹸縺瑚ｦ九▽縺九ｊ縺ｾ縺帙ｓ縲・);
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    await deleteWorkSession(sessionRecord.id);
    setFlash(req, 'success', '蜍､蜍呵ｨ倬鹸繧貞炎髯､縺励∪縺励◆縲・);
    res.redirect(buildAdminSessionsUrl(employee.id, req.query));
  }
);

app.get(
  '/admin/export',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  async (req, res) => {
    const { userId, year, month } = req.query;
    if (!userId) {
      setFlash(req, 'error', '蠕捺･ｭ蜩｡繧帝∈謚槭＠縺ｦ縺上□縺輔＞縲・);
      return res.redirect('/admin');
    }
    const employee = await getUserById(Number(userId));
    if (
      !employee ||
      employee.role !== ROLES.EMPLOYEE ||
      employee.tenant_id !== req.session.user.tenantId
    ) {
      setFlash(req, 'error', '蟇ｾ雎｡縺ｮ蠕捺･ｭ蜩｡縺瑚ｦ九▽縺九ｊ縺ｾ縺帙ｓ縲・);
      return res.redirect('/admin');
    }
    const now = toZonedDateTime(new Date().toISOString());
    const targetYear = parseInt(year || now.year, 10);
    const targetMonth = parseInt(month || now.month, 10);

    const detailed = await getUserMonthlyDetailedSessions(employee.id, targetYear, targetMonth);
    const { start } = getMonthRange(targetYear, targetMonth);
    const fileName = `${employee.username}_${start.toFormat('yyyyMM')}.xlsx`;

    const workbook = await XlsxPopulate.fromBlankAsync();
    const sheet = workbook.sheet(0);
    sheet.name('蜍､蜍呵ｨ倬鹸');

    sheet.cell('A1').value('蠕捺･ｭ蜩｡');
    sheet.cell('B1').value(employee.username);
    sheet.cell('A2').value('蟇ｾ雎｡譛・);
    sheet.cell('B2').value(`${targetYear}蟷ｴ${String(targetMonth).padStart(2, '0')}譛・);
    sheet.cell('A4').value('譌･莉・);
    sheet.cell('B4').value('蜍､蜍咎幕蟋・);
    sheet.cell('C4').value('蜍､蜍咏ｵゆｺ・);
    sheet.cell('D4').value('蜍､蜍呎凾髢・蛻・');
    sheet.cell('E4').value('蜍､蜍呎凾髢・譎・蛻・');

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

    sheet.cell(`D${row + 1}`).value('蜷郁ｨ・蛻・');
    sheet.cell(`E${row + 1}`).value('蜷郁ｨ・譎・蛻・');
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

app.get('/platform/tenants', requireRole(ROLES.PLATFORM), async (req, res) => {
  const tenantRows = await listTenants();
  const tenants = tenantRows.map((tenant) => ({
    createdAtDisplay: formatDisplayDateTime(tenant.created_at),
  }));
  const generated = req.session.generatedTenantCredential || null;
  delete req.session.generatedTenantCredential;

  res.render('platform_tenants', {
    tenants,
    generated,
    minPasswordLength: PASSWORD_MIN_LENGTH,
  });
});

app.post('/platform/tenants', requireRole(ROLES.PLATFORM), async (req, res) => {
  const tenantNameResult = validateNameField('繝・リ繝ｳ繝亥錐', req.body.tenantName || '蜷咲ｧｰ譛ｪ險ｭ螳・);
  if (!tenantNameResult.valid) {
    setFlash(req, 'error', tenantNameResult.message);
    return res.redirect('/platform/tenants');
  }
  const contactEmail = normalizeEmail(req.body.contactEmail);
  if (!contactEmail) {
    setFlash(req, 'error', '繝・リ繝ｳ繝磯｣邨｡蜈医Γ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ繧貞・蜉帙＠縺ｦ縺上□縺輔＞縲・);
    return res.redirect('/platform/tenants');
  }
  const adminFirstNameResult = validateNameField('邂｡逅・・錐・亥錐・・, req.body.adminFirstName);
  if (!adminFirstNameResult.valid) {
    setFlash(req, 'error', adminFirstNameResult.message);
    return res.redirect('/platform/tenants');
  }
  const adminLastNameResult = validateNameField('邂｡逅・・錐・亥ｧ難ｼ・, req.body.adminLastName);
  if (!adminLastNameResult.valid) {
    setFlash(req, 'error', adminLastNameResult.message);
    return res.redirect('/platform/tenants');
  }
  const adminEmail = normalizeEmail(req.body.adminEmail);
  if (!adminEmail) {
    setFlash(req, 'error', '邂｡逅・・・繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ繧貞・蜉帙＠縺ｦ縺上□縺輔＞縲・);
    return res.redirect('/platform/tenants');
  }
  const existingTenantAdmin = await getUserByEmail(adminEmail);
  if (existingTenantAdmin) {
    setFlash(req, 'error', '謖・ｮ壹＆繧後◆邂｡逅・・Γ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｯ譌｢縺ｫ菴ｿ逕ｨ縺輔ｌ縺ｦ縺・∪縺吶・);
    return res.redirect('/platform/tenants');
  }

  const tenantUid = await generateTenantUid();
  const tenant = await createTenant({
    tenantUid,
    name: tenantNameResult.value,
    contactEmail,
  });

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
    });
  } catch (error) {
    console.error('[platform] 繝・リ繝ｳ繝育ｮ｡逅・・ｽ懈・縺ｫ螟ｱ謨励＠縺ｾ縺励◆', error);
    setFlash(req, 'error', '繝・リ繝ｳ繝育ｮ｡逅・・・菴懈・縺ｫ螟ｱ謨励＠縺ｾ縺励◆縲・);
    return res.redirect('/platform/tenants');
  }

  req.session.generatedTenantCredential = {
    tenantUid,
    adminEmail,
    initialPassword,
  };

  setFlash(req, 'success', '繝・リ繝ｳ繝医→邂｡逅・・い繧ｫ繧ｦ繝ｳ繝医ｒ菴懈・縺励∪縺励◆縲・);
  return res.redirect('/platform/tenants');
});

app.use((err, req, res, next) => {
  if (err.code !== 'EBADCSRFTOKEN') {
    return next(err);
  }
  // eslint-disable-next-line no-console
  console.warn('[csrf] Invalid CSRF token detected', { path: req.path });
  if (req.session) {
    setFlash(req, 'error', '繧ｻ繧ｭ繝･繝ｪ繝・ぅ繝√ぉ繝・け縺ｫ螟ｱ謨励＠縺ｾ縺励◆縲ゅｂ縺・ｸ蠎ｦ謫堺ｽ懊ｒ繧・ｊ逶ｴ縺励※縺上□縺輔＞縲・);
    const fallbackRedirect = req.get('referer') || '/';
    return res.redirect(fallbackRedirect);
  }
  return res.status(403).send('Invalid CSRF token');
});

module.exports = app;


