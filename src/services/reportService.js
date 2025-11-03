const {
  getWorkSessionsByUserOverlapping,
  getAllEmployeesByTenant,
} = require('../db');
const {
  toZonedDateTime,
  dateKey,
  formatDateTime,
  formatDateKey,
  formatMinutesToHM,
  getMonthRange,
  getRecentRange,
  toISO,
} = require('../utils/time');

function accumulateMinutesPerDay(map, start, end) {
  if (!start || !end || end <= start) {
    return;
  }
  let cursor = start;
  while (cursor < end) {
    const nextDay = cursor.plus({ days: 1 }).startOf('day');
    const segmentEnd = end < nextDay ? end : nextDay;
    if (segmentEnd <= cursor) {
      break;
    }
    const minutes = Math.floor(segmentEnd.diff(cursor, 'seconds').seconds / 60);
    if (minutes > 0) {
      const key = dateKey(cursor);
      map.set(key, (map.get(key) || 0) + minutes);
    }
    if (+segmentEnd === +end) {
      break;
    }
    cursor = segmentEnd;
  }
}

function splitSessionByDay(start, end) {
  const segments = [];
  if (!start || !end || end <= start) {
    return segments;
  }
  let cursor = start;
  while (cursor < end) {
    const nextDayStart = cursor.plus({ days: 1 }).startOf('day');
    const segmentEnd = end < nextDayStart ? end : nextDayStart;
    if (segmentEnd <= cursor) {
      break;
    }
    segments.push({ start: cursor, end: segmentEnd });
    if (+segmentEnd === +end) {
      break;
    }
    cursor = segmentEnd;
  }
  return segments;
}

async function getUserDailySummary(userId, days = 30) {
  const { start: boundaryStart, end: boundaryEnd } = getRecentRange(days);
  const sessions = await getWorkSessionsByUserOverlapping(
    userId,
    toISO(boundaryStart),
    toISO(boundaryEnd)
  );
  const minutesMap = new Map();

  sessions.forEach((session) => {
    const start = toZonedDateTime(session.start_time);
    const end = session.end_time ? toZonedDateTime(session.end_time) : null;
    if (!start || !end) return;
    if (end <= boundaryStart) return;
    const effectiveStart = start < boundaryStart ? boundaryStart : start;
    const effectiveEnd = end > boundaryEnd ? boundaryEnd : end;
    if (effectiveEnd <= effectiveStart) {
      return;
    }
    accumulateMinutesPerDay(minutesMap, effectiveStart, effectiveEnd);
  });

  const results = Array.from(minutesMap.entries())
    .map(([date, minutes]) => ({
      dateKey: date,
      date: formatDateKey(date),
      minutes,
      formatted: formatMinutesToHM(minutes),
    }))
    .sort((a, b) => (a.date > b.date ? -1 : 1));

  return results;
}

async function getUserMonthlySummary(userId, year, month) {
  const { start, end } = getMonthRange(year, month);
  const sessions = await getWorkSessionsByUserOverlapping(
    userId,
    toISO(start),
    toISO(end)
  );
  const minutesMap = new Map();

  sessions.forEach((session) => {
    const startDt = toZonedDateTime(session.start_time);
    const endDt = session.end_time ? toZonedDateTime(session.end_time) : null;
    if (!startDt || !endDt) return;
    if (endDt <= start || startDt >= end) return;
    const boundedStart = startDt < start ? start : startDt;
    const boundedEnd = endDt > end ? end : endDt;
    if (boundedEnd <= boundedStart) {
      return;
    }
    accumulateMinutesPerDay(minutesMap, boundedStart, boundedEnd);
  });

  const byDay = Array.from(minutesMap.entries())
    .map(([date, minutes]) => ({
      dateKey: date,
      date: formatDateKey(date),
      minutes,
      formatted: formatMinutesToHM(minutes),
    }))
    .sort((a, b) => (a.date < b.date ? -1 : 1));

  const totalMinutes = byDay.reduce((sum, item) => sum + item.minutes, 0);

  return { byDay, totalMinutes, formattedTotal: formatMinutesToHM(totalMinutes) };
}

async function getUserMonthlyDetailedSessions(userId, year, month) {
  const { start, end } = getMonthRange(year, month);
  const sessions = await getWorkSessionsByUserOverlapping(
    userId,
    toISO(start),
    toISO(end)
  );
  const grouped = new Map();

  sessions.forEach((session) => {
    const startDt = toZonedDateTime(session.start_time);
    const endDt = session.end_time ? toZonedDateTime(session.end_time) : null;
    if (!startDt || !endDt) return;
    if (endDt <= start || startDt >= end) return;
    const boundedStart = startDt < start ? start : startDt;
    const boundedEnd = endDt > end ? end : endDt;
    if (boundedEnd <= boundedStart) {
      return;
    }
    const segments = splitSessionByDay(boundedStart, boundedEnd);
    segments.forEach(({ start: segStart, end: segEnd }) => {
      const key = dateKey(segStart);
      if (!grouped.has(key)) {
        grouped.set(key, []);
      }
      grouped.get(key).push({
        start: segStart,
        end: segEnd,
        minutes: Math.floor(segEnd.diff(segStart, 'seconds').seconds / 60),
        startUtc: segStart.toUTC().toISO(),
        endUtc: segEnd.toUTC().toISO(),
      });
    });
  });

  const summary = Array.from(grouped.entries())
    .map(([dateKeyValue, segments]) => {
      const displayDate = formatDateKey(dateKeyValue);
      const minutes = segments.reduce((sum, seg) => sum + seg.minutes, 0);
      return {
        dateKey: dateKeyValue,
        date: displayDate,
        minutes,
        formattedMinutes: formatMinutesToHM(minutes),
        sessions: segments.map((seg) => ({
          start: formatDateTime(seg.startUtc),
          end: formatDateTime(seg.endUtc),
          minutes: seg.minutes,
          formattedMinutes: formatMinutesToHM(seg.minutes),
        })),
      };
    })
    .sort((a, b) => (a.date < b.date ? -1 : 1));

  const totalMinutes = summary.reduce((sum, item) => sum + item.minutes, 0);

  return { days: summary, totalMinutes, formattedTotal: formatMinutesToHM(totalMinutes) };
}

async function getMonthlySummaryForAllEmployees(tenantId, year, month) {
  const employees = await getAllEmployeesByTenant(tenantId);
  const summaries = await Promise.all(
    employees.map(async (employee) => {
      const summary = await getUserMonthlySummary(employee.id, year, month);
      return {
        user: employee,
        totalMinutes: summary.totalMinutes,
        formattedTotal: summary.formattedTotal,
      };
    })
  );
  return summaries;
}

module.exports = {
  getUserDailySummary,
  getUserMonthlySummary,
  getUserMonthlyDetailedSessions,
  getMonthlySummaryForAllEmployees,
};
