const { getRepository } = require('./database');
const { getKnexClient } = require('./database/knexClient');

const repository = getRepository();

function bind(methodName) {
  const method = repository[methodName];
  if (typeof method !== 'function') {
    throw new Error(`Repository method "${methodName}" is not defined.`);
  }
  return method.bind(repository);
}

const initializeDatabase = bind('initialize');

module.exports = {
  initializeDatabase,
  getSqlClient: getKnexClient,
  createTenant: bind('createTenant'),
  getTenantById: bind('getTenantById'),
  getTenantByUid: bind('getTenantByUid'),
  listTenants: bind('listTenants'),
  updateTenantStatus: bind('updateTenantStatus'),
  createUser: bind('createUser'),
  updateUserPassword: bind('updateUserPassword'),
  setMustChangePassword: bind('setMustChangePassword'),
  getUserByEmail: bind('getUserByEmail'),
  getUserById: bind('getUserById'),
  getAllEmployeesByTenant: bind('getAllEmployeesByTenant'),
  getAllEmployeesByTenantIncludingInactive: bind('getAllEmployeesByTenantIncludingInactive'),
  updateUserStatus: bind('updateUserStatus'),
  recordLoginFailure: bind('recordLoginFailure'),
  resetLoginFailures: bind('resetLoginFailures'),
  createRoleCode: bind('createRoleCode'),
  getRoleCodeByCode: bind('getRoleCodeByCode'),
  getRoleCodeById: bind('getRoleCodeById'),
  listRoleCodesByTenant: bind('listRoleCodesByTenant'),
  incrementRoleCodeUsage: bind('incrementRoleCodeUsage'),
  disableRoleCode: bind('disableRoleCode'),
  createPasswordResetToken: bind('createPasswordResetToken'),
  getPasswordResetToken: bind('getPasswordResetToken'),
  consumePasswordResetToken: bind('consumePasswordResetToken'),
  createWorkSession: bind('createWorkSession'),
  closeWorkSession: bind('closeWorkSession'),
  createWorkSessionWithEnd: bind('createWorkSessionWithEnd'),
  updateWorkSessionTimes: bind('updateWorkSessionTimes'),
  getOpenWorkSession: bind('getOpenWorkSession'),
  getWorkSessionsByUserBetween: bind('getWorkSessionsByUserBetween'),
  getAllWorkSessionsByUser: bind('getAllWorkSessionsByUser'),
  getWorkSessionById: bind('getWorkSessionById'),
  deleteWorkSession: bind('deleteWorkSession'),
  createPayrollRecord: bind('createPayrollRecord'),
  listPayrollRecordsByTenant: bind('listPayrollRecordsByTenant'),
  listPayrollRecordsByEmployee: bind('listPayrollRecordsByEmployee'),
  getPayrollRecordById: bind('getPayrollRecordById'),
  getLatestPayrollRecordForDate: bind('getLatestPayrollRecordForDate'),
  markPayrollRecordsArchived: bind('markPayrollRecordsArchived'),
  deletePayrollRecords: bind('deletePayrollRecords'),
  findPayrollRecordsOlderThan: bind('findPayrollRecordsOlderThan'),
  findWorkSessionsOlderThan: bind('findWorkSessionsOlderThan'),
  markWorkSessionsArchived: bind('markWorkSessionsArchived'),
  deleteWorkSessions: bind('deleteWorkSessions'),
  ensureDefaultPlatformAdmin: bind('ensureDefaultPlatformAdmin'),
  deleteAllData: bind('deleteAllData'),
  deleteTenantById: bind('deleteTenantById'),
  getWorkSessionsByUserOverlapping: bind('getWorkSessionsByUserOverlapping'),
  listRecentWorkSessionsByUser: bind('listRecentWorkSessionsByUser'),
};
