const { DateTime, Duration } = require('luxon');

const ZONE = process.env.APP_TIMEZONE || 'Asia/Tokyo';
const DATE_OPTIONS = { locale: 'ja-JP' };

function toZonedDateTime(isoString) {
  if (!isoString) return null;
  return DateTime.fromISO(isoString, { zone: 'utc' }).setZone(ZONE);
}

function formatDateTime(isoString) {
  const dt = toZonedDateTime(isoString);
  if (!dt) return '';
  return dt.toFormat('yyyy/MM/dd HH:mm');
}

function formatDate(isoString) {
  const dt = toZonedDateTime(isoString);
  if (!dt) return '';
  return dt.toFormat('yyyy/MM/dd');
}

function formatForDateTimeInput(isoString) {
  const dt = toZonedDateTime(isoString);
  if (!dt) return '';
  return dt.toFormat("yyyy-LL-dd'T'HH:mm");
}

function formatMinutesToHM(totalMinutes) {
  if (typeof totalMinutes !== 'number' || Number.isNaN(totalMinutes)) {
    return '0:00';
  }
  const sign = totalMinutes < 0 ? '-' : '';
  const absolute = Math.floor(Math.abs(totalMinutes));
  const hours = Math.floor(absolute / 60);
  const minutes = absolute % 60;
  return `${sign}${hours}:${minutes.toString().padStart(2, '0')}`;
}

function diffMinutes(startIso, endIso) {
  if (!startIso || !endIso) return 0;
  const start = toZonedDateTime(startIso);
  const end = toZonedDateTime(endIso);
  if (!start || !end || end < start) return 0;
  const seconds = end.toSeconds() - start.toSeconds();
  return Math.floor(seconds / 60);
}

function getMonthRange(year, month) {
  const start = DateTime.fromObject(
    { year, month, day: 1, hour: 0, minute: 0, second: 0 },
    { zone: ZONE }
  );
  const end = start.plus({ months: 1 });
  return { start, end };
}

function getRecentRange(days) {
  const end = DateTime.now().setZone(ZONE);
  const start = end.minus({ days });
  return { start, end };
}

function toISO(dt) {
  return dt.toUTC().toISO();
}

function parseDateTimeInput(value) {
  if (!value) return null;
  const dt = DateTime.fromISO(value, { zone: ZONE });
  if (!dt.isValid) return null;
  return dt.toUTC().toISO();
}

function dateKey(dt) {
  return dt.toFormat('yyyy-MM-dd');
}

function formatDateKey(dateString) {
  if (!dateString) return '';
  const dt = DateTime.fromISO(dateString, { zone: ZONE });
  if (!dt.isValid) return dateString;
  return dt.toFormat('yyyy/MM/dd');
}

module.exports = {
  ZONE,
  DATE_OPTIONS,
  toZonedDateTime,
  formatDateTime,
  formatDate,
  formatForDateTimeInput,
  formatMinutesToHM,
  diffMinutes,
  getMonthRange,
  getRecentRange,
  toISO,
  parseDateTimeInput,
  dateKey,
  formatDateKey,
  Duration,
};
