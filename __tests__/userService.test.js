const { validatePassword } = require('../src/services/userService');

describe('validatePassword', () => {
  test('accepts ASCII passwords meeting length requirements', () => {
    const { valid } = validatePassword('Passw0rd!');
    expect(valid).toBe(true);
  });

  test('rejects short passwords', () => {
    const result = validatePassword('Abc1!');
    expect(result.valid).toBe(false);
  });

  test('rejects passwords containing Japanese characters', () => {
    const result = validatePassword('passwordあ');
    expect(result.valid).toBe(false);
  });
});

