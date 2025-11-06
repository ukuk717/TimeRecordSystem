#!/usr/bin/env node

process.env.TZ = process.env.APP_TIMEZONE || 'Asia/Tokyo';

const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');

const {
  initializeApp,
} = require('../src/bootstrap');
const {
  findPayrollRecordsOlderThan,
  markPayrollRecordsArchived,
  deletePayrollRecords,
  findWorkSessionsOlderThan,
  markWorkSessionsArchived,
  deleteWorkSessions,
} = require('../src/db');
const { destroyKnexClient } = require('../src/database/knexClient');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const DATA_DIR = path.join(PROJECT_ROOT, 'data');
const PAYROLL_ARCHIVE_ROOT = path.join(DATA_DIR, 'payrolls_archive');
const RETENTION_ARCHIVE_DIR = path.join(DATA_DIR, 'archive');
const WORK_SESSION_ARCHIVE_DIR = path.join(RETENTION_ARCHIVE_DIR, 'work_sessions');

const DEFAULT_RETENTION_YEARS = 5;

function resolveRetentionYears() {
  const raw = Number.parseInt(process.env.DATA_RETENTION_YEARS, 10);
  if (Number.isFinite(raw) && raw > 0) {
    return raw;
  }
  return DEFAULT_RETENTION_YEARS;
}

function computeCutoffIso(retentionYears) {
  const now = new Date();
  now.setFullYear(now.getFullYear() - retentionYears);
  return now.toISOString();
}

async function ensureDirectory(dirPath) {
  await fsp.mkdir(dirPath, { recursive: true });
}

function resolvePayrollAbsolutePath(storedPath) {
  const absolute = path.resolve(PROJECT_ROOT, storedPath);
  const payrollRoot = path.join(PROJECT_ROOT, 'data', 'payrolls');
  const relative = path.relative(payrollRoot, absolute);
  if (
    relative.startsWith('..') ||
    path.isAbsolute(relative) ||
    relative.includes('..\\') ||
    relative.includes('../')
  ) {
    throw new Error(`Invalid payroll path detected: ${storedPath}`);
  }
  return absolute;
}

async function appendJsonLine(filePath, payload) {
  await ensureDirectory(path.dirname(filePath));
  await fsp.appendFile(filePath, `${JSON.stringify(payload)}\n`, 'utf8');
}

async function moveFileIfExists(sourcePath, destPath) {
  try {
    await ensureDirectory(path.dirname(destPath));
    await fsp.rename(sourcePath, destPath);
    return true;
  } catch (error) {
    if (error && (error.code === 'ENOENT' || error.code === 'ENOTEMPTY')) {
      return false;
    }
    throw error;
  }
}

async function processExpiredPayrollRecords(cutoffIso) {
  const batchSize = 100;
  const archivedAt = new Date().toISOString();
  let processed = 0;

  while (true) {
    const records = await findPayrollRecordsOlderThan(cutoffIso, batchSize);
    if (records.length === 0) {
      break;
    }

    const idsToDelete = [];
    for (const record of records) {
      try {
        const archiveContext = {
          ...record,
          archived_at: archivedAt,
        };
        const archiveFile = path.join(
          RETENTION_ARCHIVE_DIR,
          'payroll_records',
          `${record.tenant_id || 'tenantless'}-${archivedAt.slice(0, 10)}.jsonl`
        );
        await appendJsonLine(archiveFile, archiveContext);

        if (record.stored_file_path) {
          try {
            const sourcePath = resolvePayrollAbsolutePath(record.stored_file_path);
            const targetPath = path.join(
              PAYROLL_ARCHIVE_ROOT,
              String(record.tenant_id || 'tenantless'),
              path.basename(record.stored_file_path)
            );
            await moveFileIfExists(sourcePath, targetPath);
          } catch (fileError) {
            // eslint-disable-next-line no-console
            console.warn('[retention] 給与明細ファイル移動に失敗しました', {
              recordId: record.id,
              storedPath: record.stored_file_path,
              error: fileError.message,
            });
          }
        }

        idsToDelete.push(record.id);
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error('[retention] 給与明細アーカイブ中にエラーが発生しました', {
          recordId: record.id,
          error,
        });
      }
    }

    if (idsToDelete.length > 0) {
      await markPayrollRecordsArchived(idsToDelete, archivedAt);
      await deletePayrollRecords(idsToDelete);
      processed += idsToDelete.length;
    } else {
      break;
    }
  }

  return processed;
}

async function processExpiredWorkSessions(cutoffIso) {
  const batchSize = 500;
  const archivedAt = new Date().toISOString();
  let processed = 0;

  while (true) {
    const sessions = await findWorkSessionsOlderThan(cutoffIso, batchSize);
    if (sessions.length === 0) {
      break;
    }

    const idsToDelete = [];
    for (const session of sessions) {
      try {
        const archiveFile = path.join(
          WORK_SESSION_ARCHIVE_DIR,
          `${session.user_id || 'user'}-${archivedAt.slice(0, 10)}.jsonl`
        );
        await appendJsonLine(archiveFile, { ...session, archived_at: archivedAt });
        idsToDelete.push(session.id);
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error('[retention] 勤怠データアーカイブ中にエラーが発生しました', {
          sessionId: session.id,
          error,
        });
      }
    }

    if (idsToDelete.length > 0) {
      await markWorkSessionsArchived(idsToDelete, archivedAt);
      await deleteWorkSessions(idsToDelete);
      processed += idsToDelete.length;
    } else {
      break;
    }
  }

  return processed;
}

async function main() {
  const retentionYears = resolveRetentionYears();
  const cutoffIso = computeCutoffIso(retentionYears);

  await ensureDirectory(RETENTION_ARCHIVE_DIR);
  await ensureDirectory(PAYROLL_ARCHIVE_ROOT);
  await ensureDirectory(WORK_SESSION_ARCHIVE_DIR);

  await initializeApp();

  const payrollCount = await processExpiredPayrollRecords(cutoffIso);
  const workSessionCount = await processExpiredWorkSessions(cutoffIso);

  // eslint-disable-next-line no-console
  console.log(
    `[retention] 完了: 勤怠 ${workSessionCount} 件, 給与明細 ${payrollCount} 件を保持期間(${retentionYears}年)経過により整理しました。`
  );
}

main()
  .catch((error) => {
    // eslint-disable-next-line no-console
    console.error('[retention] エラーにより処理が中断されました', error);
    process.exitCode = 1;
  })
  .finally(async () => {
    try {
      await destroyKnexClient();
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('[retention] DBクライアントの破棄に失敗しました', error);
    }
  });

