const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const PASSWORD_MIN_LENGTH = 12;
const PASSWORD_ASCII_REGEX = /^[\x20-\x7E]+$/;
const PASSWORD_REQUIRED_SETS = [
  /[A-Za-z]/,
  /[0-9]/,
  /[^A-Za-z0-9]/,
];
const ADMIN_PASSWORD_CHARSET =
  'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=';

function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, message: 'パスワードを入力してください。' };
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return {
      valid: false,
      message: `パスワードは${PASSWORD_MIN_LENGTH}文字以上で設定してください。`,
    };
  }
  if (!PASSWORD_ASCII_REGEX.test(password)) {
    return {
      valid: false,
      message: 'パスワードには半角英数字および記号のみ使用できます。',
    };
  }
  const missingSet = PASSWORD_REQUIRED_SETS.find((pattern) => !pattern.test(password));
  if (missingSet) {
    return {
      valid: false,
      message: 'パスワードには英字・数字・記号をすべて含めてください。',
    };
  }
  return { valid: true };
}

function generateSecurePassword(length, charset) {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error('Password length must be a positive integer.');
  }
  if (!charset || typeof charset !== 'string' || charset.length === 0) {
    throw new Error('Character set must be a non-empty string.');
  }

  const chars = [];
  const max = 256 - (256 % charset.length);

  while (chars.length < length) {
    const bytes = crypto.randomBytes(length);
    for (let i = 0; i < bytes.length && chars.length < length; i += 1) {
      const value = bytes[i];
      if (value < max) {
        chars.push(charset[value % charset.length]);
      }
    }
  }

  return chars.join('');
}

function generatePasswordMeetingRequirements(length, charset, patterns = []) {
  const maxAttempts = 100;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const candidate = generateSecurePassword(length, charset);
    const isValid = patterns.every((pattern) => pattern.test(candidate));
    if (isValid) {
      return candidate;
    }
  }
  throw new Error('Failed to generate password that meets complexity requirements.');
}

function generateInitialAdminPassword(length = 16) {
  return generatePasswordMeetingRequirements(length, ADMIN_PASSWORD_CHARSET, PASSWORD_REQUIRED_SETS);
}

async function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
}

async function comparePassword(candidate, hash) {
  return bcrypt.compare(candidate, hash);
}

module.exports = {
  validatePassword,
  generateSecurePassword,
  generatePasswordMeetingRequirements,
  generateInitialAdminPassword,
  hashPassword,
  comparePassword,
  PASSWORD_MIN_LENGTH,
};
