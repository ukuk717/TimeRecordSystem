const express = require('express');
const path = require('path');
const session = require('express-session');
const SQLiteStore = require('better-sqlite3-session-store')(session);
const XlsxPopulate = require('xlsx-populate');

const {
  db,
  createUser,
  updateUserPassword,
  getUserByUsername,
  getUserById,
  getAllEmployees,
  createWorkSession,
  closeWorkSession,
  getOpenWorkSession,
  getAllWorkSessionsByUser,
} = require('./db');
const {
  validatePassword,
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
} = require('./utils/time');

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    store: new SQLiteStore({
      client: db,
      expired: {
        clear: true,
        intervalMs: 10 * 60 * 1000,
      },
    }),
    secret: process.env.SESSION_SECRET || 'change-this-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 12,
      httpOnly: true,
      sameSite: 'lax',
    },
  })
);

app.use(express.static(path.join(__dirname, '..', 'public')));

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    setFlash(req, 'error', 'ログインしてください。');
    return res.redirect('/login');
  }
  return next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role) {
      setFlash(req, 'error', '権限がありません。');
      return res.redirect('/login');
    }
    return next();
  };
}

app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  if (req.session.user.role === 'admin') {
    return res.redirect('/admin');
  }
  return res.redirect('/employee');
});

app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  return res.render('login', {
    minPasswordLength: PASSWORD_MIN_LENGTH,
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = getUserByUsername(username);
  if (!user) {
    setFlash(req, 'error', 'ユーザー名またはパスワードが正しくありません。');
    return res.redirect('/login');
  }
  const ok = await comparePassword(password, user.password_hash);
  if (!ok) {
    setFlash(req, 'error', 'ユーザー名またはパスワードが正しくありません。');
    return res.redirect('/login');
  }
  req.session.user = { id: user.id, username: user.username, role: user.role };
  setFlash(req, 'success', 'ログインしました。');
  return res.redirect('/');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/employee', requireRole('employee'), (req, res) => {
  const userId = req.session.user.id;
  const now = new Date();
  const openSession = getOpenWorkSession(userId);
  const dailySummary = getUserDailySummary(userId, 30);
  const monthDate = toZonedDateTime(now.toISOString());
  const monthlySummary = getUserMonthlySummary(
    userId,
    monthDate.year,
    monthDate.month
  );

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

app.post('/employee/record', requireRole('employee'), (req, res) => {
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

app.get('/employee/password', requireRole('employee'), (req, res) => {
  res.render('password_change', { action: '/employee/password' });
});

app.post('/employee/password', requireRole('employee'), async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = getUserById(req.session.user.id);
  if (!user) {
    setFlash(req, 'error', 'ユーザーが見つかりません。');
    return res.redirect('/employee/password');
  }
  const ok = await comparePassword(currentPassword, user.password_hash);
  if (!ok) {
    setFlash(req, 'error', '現在のパスワードが正しくありません。');
    return res.redirect('/employee/password');
  }
  const validation = validatePassword(newPassword);
  if (!validation.valid) {
    setFlash(req, 'error', validation.message);
    return res.redirect('/employee/password');
  }
  const hashed = await hashPassword(newPassword);
  updateUserPassword(user.id, hashed);
  setFlash(req, 'success', 'パスワードを変更しました。');
  res.redirect('/employee');
});

app.get('/admin', requireRole('admin'), (req, res) => {
  const now = new Date();
  const { year, month } = req.query;
  const baseDate = year && month
    ? toZonedDateTime(new Date(Date.UTC(year, month - 1, 1)).toISOString())
    : toZonedDateTime(now.toISOString());
  const targetYear = parseInt(year || baseDate.year, 10);
  const targetMonth = parseInt(month || baseDate.month, 10);
  const monthlySummary = getMonthlySummaryForAllEmployees(targetYear, targetMonth);
  const employees = getAllEmployees();
  res.render('admin_dashboard', {
    employees,
    monthlySummary,
    targetYear,
    targetMonth,
  });
});

app.get('/admin/users/new', requireRole('admin'), (req, res) => {
  res.render('user_create', {
    minPasswordLength: PASSWORD_MIN_LENGTH,
  });
});

app.post('/admin/users', requireRole('admin'), async (req, res) => {
  const { username, password } = req.body;
  if (!username) {
    setFlash(req, 'error', 'ユーザー名を入力してください。');
    return res.redirect('/admin/users/new');
  }
  const validation = validatePassword(password);
  if (!validation.valid) {
    setFlash(req, 'error', validation.message);
    return res.redirect('/admin/users/new');
  }
  try {
    const hashed = await hashPassword(password);
    createUser({ username, passwordHash: hashed, role: 'employee' });
    setFlash(req, 'success', `従業員アカウント「${username}」を作成しました。`);
    res.redirect('/admin');
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      setFlash(req, 'error', '同じユーザー名が既に存在します。');
    } else {
      setFlash(req, 'error', 'アカウント作成中にエラーが発生しました。');
      // eslint-disable-next-line no-console
      console.error(error);
    }
    res.redirect('/admin/users/new');
  }
});

app.get('/admin/export', requireRole('admin'), async (req, res) => {
  const { userId, year, month } = req.query;
  if (!userId) {
    setFlash(req, 'error', '従業員を選択してください。');
    return res.redirect('/admin');
  }
  const employee = getUserById(Number(userId));
  if (!employee || employee.role !== 'employee') {
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
});

module.exports = app;
