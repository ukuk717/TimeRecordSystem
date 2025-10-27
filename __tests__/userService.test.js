const { validatePassword } = require('../src/services/userService');

describe('validatePassword', () => {
  test('accepts ASCII passwords meeting length requirements', () => {
    const { valid } = validatePassword('Abcdef12#$XY');
    expect(valid).toBe(true);
  });

  test('rejects short passwords', () => {
    const result = validatePassword('Abcd123!@#');
    expect(result.valid).toBe(false);
  });

  test('rejects passwords containing Japanese characters', () => {
    const result = validatePassword('Passwordあ123!');
    expect(result.valid).toBe(false);
  });

  test('rejects passwords missing required character classes', () => {
    const result = validatePassword('ABCDEFGHIJKL');
    expect(result.valid).toBe(false);
  });
});
