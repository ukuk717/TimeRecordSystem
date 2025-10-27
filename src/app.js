const express = require('express');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const csrf = require('csurf');
const SQLiteStore = require('better-sqlite3-session-store')(session);
const XlsxPopulate = require('xlsx-populate');

const {
  db,
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
const isTestEnv = process.env.NODE_ENV === 'test';

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

const sessionStoreOptions = {
  client: db,
};

if (!isTestEnv) {
  sessionStoreOptions.expired = {
    clear: true,
    intervalMs: 10 * 60 * 1000,
  };
}

const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET && process.env.NODE_ENV !== 'test') {
  // eslint-disable-next-line no-console
  console.warn('[session] SESSION_SECRET is not set; using a random ephemeral secret.');
}
const sessionStore = new SQLiteStore(sessionStoreOptions);
const csrfProtection = csrf();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    store: sessionStore,
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 12,
      httpOnly: true,
      sameSite: 'lax',
    },
  })
);

app.use(csrfProtection);
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  res.locals.csrfToken = typeof req.csrfToken === 'function' ? req.csrfToken() : null;
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
  setFlash(req, 'info', '初回ログインのためパスワードを変更してください。');
  return res.redirect('/password/change');
});

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function normalizeEmail(email) {
  return (email || '').trim().toLowerCase();
}

function generateTenantUid() {
  let attempt = 0;
  while (attempt < 10) {
    const candidate = `ten_${crypto.randomBytes(6).toString('hex')}`;
    if (!getTenantByUid(candidate)) {
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

function hasOverlappingSessions(userId, startIso, endIso, excludeSessionId = null) {
  const sessions = getAllWorkSessionsByUser(userId);
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

const buildAdminSessionsUrl = (userId, query = {}) =>
  `/admin/employees/${userId}/sessions${buildSessionQuery(query)}`;

function getEmployeeForTenantAdmin(req, res) {
  const employeeId = Number.parseInt(req.params.userId, 10);
  const employee = Number.isNaN(employeeId) ? null : getUserById(employeeId);
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
    setFlash(req, 'error', 'メールアドレスとパスワードを入力してください。');
    return res.redirect('/login');
  }

  const user = getUserByEmail(email);
  if (!user) {
    setFlash(req, 'error', 'メールアドレスまたはパスワードが正しくありません。');
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
    const meta = recordLoginFailure(user.id, lockUntilIso);
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
        `メールアドレスまたはパスワードが正しくありません。（あと${remaining}回でロック）`
      );
    }
    return res.redirect('/login');
  }

  resetLoginFailures(user.id);
  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role,
    tenantId: user.tenant_id,
  };

  if (user.must_change_password) {
    req.session.user.mustChangePassword = true;
    setFlash(req, 'info', '初回ログインのためパスワードを変更してください。');
    return res.redirect('/password/change');
  }

  setFlash(req, 'success', 'ログインしました。');
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

  const roleCode = getRoleCodeByCode(roleCodeValue);
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

  if (getUserByEmail(email)) {
    setFlash(req, 'error', 'このメールアドレスは既に登録されています。');
    return res.redirect('/register');
  }

  const validation = validatePassword(newPassword);
  if (!validation.valid) {
    setFlash(req, 'error', validation.message);
    return res.redirect('/register');
  }

  const tenant = getTenantById(roleCode.tenant_id);
  if (!tenant) {
    setFlash(req, 'error', 'ロールコードに対応するテナントが見つかりません。');
    return res.redirect('/register');
  }

  const hashed = await hashPassword(newPassword);
  const username = `${lastNameResult.value}${firstNameResult.value}`;

  try {
    createUser({
      tenantId: tenant.id,
      username,
      email,
      passwordHash: hashed,
      role: ROLES.EMPLOYEE,
      firstName: firstNameResult.value,
      lastName: lastNameResult.value,
    });
    incrementRoleCodeUsage(roleCode.id);
    const updatedRoleCode = getRoleCodeById(roleCode.id);
    if (
      updatedRoleCode &&
      updatedRoleCode.max_uses !== null &&
      updatedRoleCode.usage_count >= updatedRoleCode.max_uses
    ) {
      disableRoleCode(updatedRoleCode.id);
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

app.post('/password/reset', (req, res) => {
  const email = normalizeEmail(req.body.email);
  if (!email) {
    setFlash(req, 'error', 'メールアドレスを入力してください。');
    return res.redirect('/password/reset');
  }

  const user = getUserByEmail(email);
  if (!user) {
    setFlash(req, 'info', 'パスワードリセット手順をメールアドレスへ送信しました。');
    return res.redirect('/login');
  }

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  createPasswordResetToken(user.id, token, expiresAt);

  const resetLink = `${req.protocol}://${req.get('host')}/password/reset/${token}`;
  if (process.env.NODE_ENV !== 'production') {
    console.info(`[password-reset] ${email} 用リセットリンク: ${resetLink}`);
  } else {
    console.info(`[password-reset] ${email} へのリセット手続きを記録しました`);
  }

  setFlash(
    req,
    'info',
    'パスワードリセット用のリンクをメールアドレスへ送信しました。（試作環境ではサーバーログを確認してください）'
  );
  return res.redirect('/login');
});

app.get('/password/reset/:token', (req, res) => {
  const record = getPasswordResetToken(req.params.token);
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
  const record = getPasswordResetToken(req.params.token);
  if (!record) {
    setFlash(req, 'error', 'リセットリンクが無効です。再度手続きを行ってください。');
    return res.redirect('/password/reset');
  }
  if (Date.parse(record.expires_at) <= Date.now()) {
    setFlash(req, 'error', 'リセットリンクの有効期限が切れています。');
    return res.redirect('/password/reset');
  }

  const user = getUserById(record.user_id);
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
  updateUserPassword(user.id, hashed, false);
  resetLoginFailures(user.id);
  consumePasswordResetToken(record.id);

  setFlash(req, 'success', 'パスワードを再設定しました。ログインしてください。');
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
    const user = getUserById(req.session.user.id);
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
    updateUserPassword(user.id, hashed, false);
    setMustChangePassword(user.id, false);
    if (req.session.user) {
      delete req.session.user.mustChangePassword;
    }
    setFlash(req, 'success', 'パスワードを変更しました。');
    return res.redirect('/');
  }
);

app.get('/employee', requireRole(ROLES.EMPLOYEE), (req, res) => {
  const userId = req.session.user.id;
  const now = new Date();
  const openSession = getOpenWorkSession(userId);
  const dailySummary = getUserDailySummary(userId, 30);
  const monthDate = toZonedDateTime(now.toISOString());
  const monthlySummary = getUserMonthlySummary(userId, monthDate.year, monthDate.month);

  const sessionHistory = getAllWorkSessionsByUser(userId)
    .slice(0, 10)
    .map((session) => {
      const durationMinutes = session.end_time
        ? diffMinutes(session.start_time, session.end_time)
        : null;
      return {
        id: session.id,
        startFormatted: formatDateTime(session.start_time),
        endFormatted: session.end_time ? formatDateTime(session.end_time) : '記録中',
        minutes: durationMinutes,
        formattedMinutes: durationMinutes !== null ? formatMinutesToHM(durationMinutes) : '—',
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

app.post('/employee/record', requireRole(ROLES.EMPLOYEE), (req, res) => {
  const userId = req.session.user.id;
  const openSession = getOpenWorkSession(userId);
  const nowIso = new Date().toISOString();
  if (openSession) {
    closeWorkSession(openSession.id, nowIso);
    setFlash(req, 'success', '勤務終了を記録しました。');
  } else {
    createWorkSession(userId, nowIso);
    setFlash(req, 'success', '勤務開始を記録しました。');
  }
  res.redirect('/employee');
});

app.get(
  '/admin',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  (req, res) => {
    const now = new Date();
    const { year, month } = req.query;
    const baseDate =
      year && month
        ? toZonedDateTime(new Date(Date.UTC(year, month - 1, 1)).toISOString())
        : toZonedDateTime(now.toISOString());
    const targetYear = parseInt(year || baseDate.year, 10);
    const targetMonth = parseInt(month || baseDate.month, 10);

    const tenantId = req.session.user.tenantId;
    const monthlySummary = getMonthlySummaryForAllEmployees(tenantId, targetYear, targetMonth);

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
  (req, res) => {
    const tenantId = req.session.user.tenantId;
    const now = Date.now();
    const codes = listRoleCodesByTenant(tenantId).map((code) => {
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
  (req, res) => {
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
    do {
      codeValue = generateRoleCodeValue();
    } while (getRoleCodeByCode(codeValue));

    createRoleCode({
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

    setFlash(req, 'success', 'ロールコードを発行しました。');
    return res.redirect('/admin/role-codes');
  }
);

app.post(
  '/admin/role-codes/:codeId/disable',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  (req, res) => {
    const tenantId = req.session.user.tenantId;
    const codeId = Number.parseInt(req.params.codeId, 10);
    const roleCode = Number.isNaN(codeId) ? null : getRoleCodeById(codeId);
    if (!roleCode || roleCode.tenant_id !== tenantId) {
      setFlash(req, 'error', 'ロールコードが見つかりません。');
      return res.redirect('/admin/role-codes');
    }
    disableRoleCode(roleCode.id);
    setFlash(req, 'success', 'ロールコードを無効化しました。');
    return res.redirect('/admin/role-codes');
  }
);

app.get(
  '/admin/employees/:userId/sessions',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  (req, res) => {
    const employee = getEmployeeForTenantAdmin(req, res);
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
    const records = getWorkSessionsByUserBetween(employee.id, startIso, endIso);

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

    const monthlySummary = getUserMonthlySummary(employee.id, targetYear, targetMonth);

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
  (req, res) => {
    const employee = getEmployeeForTenantAdmin(req, res);
    if (!employee) {
      return;
    }

    const startInput = (req.body.startTime || '').trim();
    const endInput = (req.body.endTime || '').trim();
    const startIso = parseDateTimeInput(startInput);
    const endIso = parseDateTimeInput(endInput);

    if (!startIso || !endIso) {
      setFlash(req, 'error', '開始と終了の日時を正しく入力してください。');
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    if (diffMinutes(startIso, endIso) <= 0) {
      setFlash(req, 'error', '終了時刻は開始時刻より後に設定してください。');
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    if (hasOverlappingSessions(employee.id, startIso, endIso)) {
      setFlash(req, 'error', OVERLAP_ERROR_MESSAGE);
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    createWorkSessionWithEnd(employee.id, startIso, endIso);
    setFlash(req, 'success', '勤務記録を追加しました。');
    res.redirect(buildAdminSessionsUrl(employee.id, req.query));
  }
);

app.post(
  '/admin/employees/:userId/sessions/:sessionId/update',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  (req, res) => {
    const employee = getEmployeeForTenantAdmin(req, res);
    if (!employee) {
      return;
    }

    const sessionId = Number.parseInt(req.params.sessionId, 10);
    const sessionRecord = Number.isNaN(sessionId) ? null : getWorkSessionById(sessionId);
    if (!sessionRecord || sessionRecord.user_id !== employee.id) {
      setFlash(req, 'error', '該当する勤務記録が見つかりません。');
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    const startInput = (req.body.startTime || '').trim();
    const endInput = (req.body.endTime || '').trim();
    const startIso = parseDateTimeInput(startInput);

    if (!startIso) {
      setFlash(req, 'error', '開始時刻を正しく入力してください。');
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    let endIso = null;
    if (endInput) {
      endIso = parseDateTimeInput(endInput);
      if (!endIso) {
        setFlash(req, 'error', '終了時刻を正しく入力してください。');
        res.redirect(buildAdminSessionsUrl(employee.id, req.query));
        return;
      }
      if (diffMinutes(startIso, endIso) <= 0) {
        setFlash(req, 'error', '終了時刻は開始時刻より後に設定してください。');
        res.redirect(buildAdminSessionsUrl(employee.id, req.query));
        return;
      }
    }

    if (hasOverlappingSessions(employee.id, startIso, endIso, sessionRecord.id)) {
      setFlash(req, 'error', OVERLAP_ERROR_MESSAGE);
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    updateWorkSessionTimes(sessionRecord.id, startIso, endIso);
    setFlash(req, 'success', '勤務記録を更新しました。');
    res.redirect(buildAdminSessionsUrl(employee.id, req.query));
  }
);

app.post(
  '/admin/employees/:userId/sessions/:sessionId/delete',
  requireRole(ROLES.TENANT),
  ensureTenantContext,
  (req, res) => {
    const employee = getEmployeeForTenantAdmin(req, res);
    if (!employee) {
      return;
    }

    const sessionId = Number.parseInt(req.params.sessionId, 10);
    const sessionRecord = Number.isNaN(sessionId) ? null : getWorkSessionById(sessionId);
    if (!sessionRecord || sessionRecord.user_id !== employee.id) {
      setFlash(req, 'error', '該当する勤務記録が見つかりません。');
      res.redirect(buildAdminSessionsUrl(employee.id, req.query));
      return;
    }

    deleteWorkSession(sessionRecord.id);
    setFlash(req, 'success', '勤務記録を削除しました。');
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
      setFlash(req, 'error', '従業員を選択してください。');
      return res.redirect('/admin');
    }
    const employee = getUserById(Number(userId));
    if (
      !employee ||
      employee.role !== ROLES.EMPLOYEE ||
      employee.tenant_id !== req.session.user.tenantId
    ) {
      setFlash(req, 'error', '対象の従業員が見つかりません。');
      return res.redirect('/admin');
    }
    const now = toZonedDateTime(new Date().toISOString());
    const targetYear = parseInt(year || now.year, 10);
    const targetMonth = parseInt(month || now.month, 10);

    const detailed = getUserMonthlyDetailedSessions(employee.id, targetYear, targetMonth);
    const { start } = getMonthRange(targetYear, targetMonth);
    const fileName = `${employee.username}_${start.toFormat('yyyyMM')}.xlsx`;

    const workbook = await XlsxPopulate.fromBlankAsync();
    const sheet = workbook.sheet(0);
    sheet.name('勤務記録');

    sheet.cell('A1').value('従業員');
    sheet.cell('B1').value(employee.username);
    sheet.cell('A2').value('対象月');
    sheet.cell('B2').value(`${targetYear}年${String(targetMonth).padStart(2, '0')}月`);
    sheet.cell('A4').value('日付');
    sheet.cell('B4').value('勤務開始');
    sheet.cell('C4').value('勤務終了');
    sheet.cell('D4').value('勤務時間(分)');
    sheet.cell('E4').value('勤務時間(時:分)');

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

    sheet.cell(`D${row + 1}`).value('合計(分)');
    sheet.cell(`E${row + 1}`).value('合計(時:分)');
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

app.get('/platform/tenants', requireRole(ROLES.PLATFORM), (req, res) => {
  const tenants = listTenants().map((tenant) => ({
    ...tenant,
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
  const adminFirstNameResult = validateNameField('管理者名（名）', req.body.adminFirstName);
  if (!adminFirstNameResult.valid) {
    setFlash(req, 'error', adminFirstNameResult.message);
    return res.redirect('/platform/tenants');
  }
  const adminLastNameResult = validateNameField('管理者名（姓）', req.body.adminLastName);
  if (!adminLastNameResult.valid) {
    setFlash(req, 'error', adminLastNameResult.message);
    return res.redirect('/platform/tenants');
  }
  const adminEmail = normalizeEmail(req.body.adminEmail);
  if (!adminEmail) {
    setFlash(req, 'error', '管理者のメールアドレスを入力してください。');
    return res.redirect('/platform/tenants');
  }
  if (getUserByEmail(adminEmail)) {
    setFlash(req, 'error', '指定された管理者メールアドレスは既に使用されています。');
    return res.redirect('/platform/tenants');
  }

  const tenantUid = generateTenantUid();
  const tenant = createTenant({
    tenantUid,
    name: tenantNameResult.value,
    contactEmail,
  });

  const initialPassword = generateInitialAdminPassword(16);
  const hashedPassword = await hashPassword(initialPassword);
  const username = `${adminLastNameResult.value}${adminFirstNameResult.value}`;

  try {
    createUser({
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
    console.error('[platform] テナント管理者作成に失敗しました', error);
    setFlash(req, 'error', 'テナント管理者の作成に失敗しました。');
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
