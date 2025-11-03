const request = require('supertest');
const app = require('../src/app');
const { deleteAllData, ensureDefaultPlatformAdmin } = require('../src/db');

beforeEach(async () => {
  await deleteAllData();
  await ensureDefaultPlatformAdmin();
});

describe('Public pages', () => {
  test('GET /login renders login page', async () => {
    const response = await request(app).get('/login');
    expect(response.status).toBe(200);
    expect(response.text).toContain('ログイン');
    expect(response.text).toContain('新規アカウントを作成する');
  });
});

describe.skip('App integration (multi-tenant flow)', () => {
  test('placeholder', () => {
    // Pending new multi-tenant end-to-end tests.
  });
});
