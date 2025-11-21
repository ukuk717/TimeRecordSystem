const crypto = require('crypto');

const OTP_CODE_LENGTH = 6;

function generateNumericOtp(length = OTP_CODE_LENGTH) {
  const targetLength = Number.isInteger(length) && length > 0 ? length : OTP_CODE_LENGTH;
  const digits = [];
  while (digits.length < targetLength) {
    const value = crypto.randomInt(0, 10);
    digits.push(value);
  }
  return digits.join('');
}

function hashOtpCode(code) {
  return crypto.createHash('sha256').update(String(code || '').trim()).digest('hex');
}

function maskEmail(email) {
  if (typeof email !== 'string') {
    return '';
  }
  const [local, domain] = email.split('@');
  if (!domain) {
    return email;
  }
  const maskedLocal =
    local.length <= 2
      ? `${local[0] || ''}*`
      : `${local.slice(0, 2)}${'*'.repeat(Math.max(1, local.length - 2))}`;
  return `${maskedLocal}@${domain}`;
}

module.exports = {
  OTP_CODE_LENGTH,
  generateNumericOtp,
  hashOtpCode,
  maskEmail,
};
