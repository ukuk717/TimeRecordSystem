const bcrypt = require('bcryptjs');

const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_ASCII_REGEX = /^[\x20-\x7E]+$/;

function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, message: 'パスワードを入力してください。' };
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return { valid: false, message: `パスワードは${PASSWORD_MIN_LENGTH}文字以上で設定してください。` };
  }
  if (!PASSWORD_ASCII_REGEX.test(password)) {
    return { valid: false, message: 'パスワードには半角英数字および記号のみ使用できます。' };
  }
  return { valid: true };
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
  hashPassword,
  comparePassword,
  PASSWORD_MIN_LENGTH,
};

