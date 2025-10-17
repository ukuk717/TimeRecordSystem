const request = require('supertest');
const app = require('../src/app');
const {
  deleteAllData,
  ensureDefaultAdmin,
  createUser,
  getUserByUsername,
  getOpenWorkSession,
  getAllWorkSessionsByUser,
} = require('../src/db');
const { hashPassword } = require('../src/services/userService');

beforeEach(async () => {
  deleteAllData();
  ensureDefaultAdmin();
});

describe('App integration', () => {
  test('GET /login renders login page', async () => {
    const response = await request(app).get('/login');
    expect(response.status).toBe(200);
    expect(response.text).toContain('ログイン');
  });

  test('employee can record start and end times', async () => {
    const password = 'Emp12345!';
    const hashed = await hashPassword(password);
    createUser({ username: 'employee1', passwordHash: hashed, role: 'employee' });

    const agent = request.agent(app);
    let response = await agent
      .post('/login')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=employee1&password=${encodeURIComponent(password)}`);

    expect(response.status).toBe(302);
    expect(response.headers.location).toBe('/');

    response = await agent.post('/employee/record');
    expect(response.status).toBe(302);

    const employee = getUserByUsername('employee1');
    let openSession = getOpenWorkSession(employee.id);
    expect(openSession).not.toBeUndefined();

    response = await agent.post('/employee/record');
    expect(response.status).toBe(302);

    openSession = getOpenWorkSession(employee.id);
    expect(openSession).toBeUndefined();

    const sessions = getAllWorkSessionsByUser(employee.id);
    expect(sessions.length).toBe(1);
    expect(sessions[0].end_time).toBeTruthy();
  });

  test('admin can export excel for an employee', async () => {
    const password = 'Emp22334!';
    const hashed = await hashPassword(password);
    createUser({ username: 'excel-user', passwordHash: hashed, role: 'employee' });
    const employee = getUserByUsername('excel-user');

    const employeeAgent = request.agent(app);
    await employeeAgent
      .post('/login')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=excel-user&password=${encodeURIComponent(password)}`);
    await employeeAgent.post('/employee/record');
    await new Promise((resolve) => setTimeout(resolve, 1000));
    await employeeAgent.post('/employee/record');

    const adminAgent = request.agent(app);
    const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'Admin123!';
    await adminAgent
      .post('/login')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(`username=admin&password=${encodeURIComponent(adminPassword)}`);

    const now = new Date();
    const response = await adminAgent.get(
      `/admin/export?userId=${employee.id}&year=${now.getFullYear()}&month=${now.getMonth() + 1}`
    );

    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toBe(
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    expect(response.headers['content-disposition']).toContain('attachment; filename=');
  });
});

