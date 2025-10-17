const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const DB_FILE = process.env.DB_FILE || path.join(__dirname, '..', 'data', 'database.sqlite');

if (DB_FILE !== ':memory:') {
  const dir = path.dirname(DB_FILE);
  fs.mkdirSync(dir, { recursive: true });
}

const db = new Database(DB_FILE);
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'employee')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS work_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

const userStatements = {
  insert: db.prepare(`
    INSERT INTO users (username, password_hash, role)
    VALUES (@username, @password_hash, @role)
  `),
  byUsername: db.prepare(`SELECT * FROM users WHERE username = ?`),
  byId: db.prepare(`SELECT * FROM users WHERE id = ?`),
  allEmployees: db.prepare(`SELECT * FROM users WHERE role = 'employee' ORDER BY username ASC`),
  updatePassword: db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`),
  adminCount: db.prepare(`SELECT COUNT(*) AS count FROM users WHERE role = 'admin'`),
};

const workSessionStatements = {
  insert: db.prepare(`
    INSERT INTO work_sessions (user_id, start_time)
    VALUES (?, ?)
  `),
  updateEnd: db.prepare(`
    UPDATE work_sessions SET end_time = ? WHERE id = ?
  `),
  openForUser: db.prepare(`
    SELECT * FROM work_sessions
    WHERE user_id = ? AND end_time IS NULL
    ORDER BY start_time DESC
    LIMIT 1
  `),
  byUserBetween: db.prepare(`
    SELECT * FROM work_sessions
    WHERE user_id = ?
      AND start_time >= ?
      AND start_time < ?
    ORDER BY start_time ASC
  `),
  allByUser: db.prepare(`
    SELECT * FROM work_sessions
    WHERE user_id = ?
    ORDER BY start_time DESC
  `),
  adminCount: db.prepare(`SELECT COUNT(*) as count FROM users WHERE role = 'admin'`),
};

function createUser({ username, passwordHash, role }) {
  return userStatements.insert.run({
    username,
    password_hash: passwordHash,
    role,
  });
}

function updateUserPassword(userId, passwordHash) {
  return userStatements.updatePassword.run(passwordHash, userId);
}

function getUserByUsername(username) {
  return userStatements.byUsername.get(username);
}

function getUserById(id) {
  return userStatements.byId.get(id);
}

function getAllEmployees() {
  return userStatements.allEmployees.all();
}

function createWorkSession(userId, isoStart) {
  const info = workSessionStatements.insert.run(userId, isoStart);
  return { id: info.lastInsertRowid, user_id: userId, start_time: isoStart, end_time: null };
}

function closeWorkSession(sessionId, isoEnd) {
  return workSessionStatements.updateEnd.run(isoEnd, sessionId);
}

function getOpenWorkSession(userId) {
  return workSessionStatements.openForUser.get(userId);
}

function getWorkSessionsByUserBetween(userId, startIso, endIso) {
  return workSessionStatements.byUserBetween.all(userId, startIso, endIso);
}

function getAllWorkSessionsByUser(userId) {
  return workSessionStatements.allByUser.all(userId);
}

function ensureDefaultAdmin() {
  const { count } = userStatements.adminCount.get();
  if (count > 0) {
    return;
  }
  const username = process.env.DEFAULT_ADMIN_USERNAME || 'admin';
  const password = process.env.DEFAULT_ADMIN_PASSWORD || 'Admin123!';
  const passwordHash = bcrypt.hashSync(password, 10);
  try {
    createUser({ username, passwordHash, role: 'admin' });
    // eslint-disable-next-line no-console
    console.info(
      `[setup] 管理者アカウント ${username} を作成しました。初期パスワード: ${password}`
    );
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error('[setup] 管理者アカウントの作成に失敗しました', error);
  }
}

function deleteAllData() {
  db.exec(`DELETE FROM work_sessions; DELETE FROM users;`);
}

module.exports = {
  db,
  createUser,
  updateUserPassword,
  getUserByUsername,
  getUserById,
  getAllEmployees,
  createWorkSession,
  closeWorkSession,
  getOpenWorkSession,
  getWorkSessionsByUserBetween,
  getAllWorkSessionsByUser,
  ensureDefaultAdmin,
  deleteAllData,
};
