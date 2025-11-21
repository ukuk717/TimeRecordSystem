const crypto = require('crypto');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');

const MFA_TYPES = {
  TOTP: 'totp',
  EMAIL_OTP: 'email_otp',
  SMS_OTP: 'sms_otp',
};

const MFA_CHANNELS = [
  { type: MFA_TYPES.TOTP, label: '認証アプリ (TOTP)', status: 'available' },
  { type: MFA_TYPES.EMAIL_OTP, label: 'メールワンタイムコード', status: 'planned' },
  { type: MFA_TYPES.SMS_OTP, label: 'SMSワンタイムコード', status: 'planned' },
];

const DEFAULT_TOTP_OPTIONS = {
  step: Number.parseInt(process.env.MFA_TOTP_PERIOD || '30', 10) || 30,
  digits: 6,
  window: 1,
};

authenticator.options = {
  ...authenticator.options,
  ...DEFAULT_TOTP_OPTIONS,
};

function getMfaIssuer(defaultName = 'TimeRecordSystem') {
  return process.env.MFA_ISSUER || defaultName;
}

function generateTotpSecret() {
  return authenticator.generateSecret();
}

function buildTotpKeyUri({ secret, label, issuer = getMfaIssuer() }) {
  if (!secret || !label) {
    return '';
  }
  const sanitizedLabel = String(label).replace(/:/g, '').trim() || 'user';
  return authenticator.keyuri(sanitizedLabel, issuer, secret);
}

function verifyTotpToken({ secret, token }) {
  if (!secret || !token) {
    return false;
  }
  return authenticator.verify({
    secret,
    token,
  });
}

async function generateQrCodeDataUrl(text) {
  if (!text) {
    return null;
  }
  try {
    return await qrcode.toDataURL(text, {
      margin: 1,
      scale: 4,
      errorCorrectionLevel: 'M',
    });
  } catch (error) {
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.warn('[mfa] QRコードの生成に失敗しました。', error);
    }
    return null;
  }
}

function getMfaChannelLabel(type) {
  const channel = MFA_CHANNELS.find((entry) => entry.type === type);
  if (!channel) {
    return '多要素認証';
  }
  return channel.label;
}

const RECOVERY_CODE_CHARS = '2346789ABCDEFGHJKLMNPQRSTUVWXYZ';

function generateRecoveryCode(length = 10) {
  const bytes = crypto.randomBytes(length * 2);
  const chars = [];
  for (let i = 0; i < bytes.length && chars.length < length; i += 1) {
    const index = bytes[i] % RECOVERY_CODE_CHARS.length;
    chars.push(RECOVERY_CODE_CHARS[index]);
  }
  if (chars.length < length) {
    return generateRecoveryCode(length);
  }
  const raw = chars.join('');
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

function generateRecoveryCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i += 1) {
    codes.push(generateRecoveryCode());
  }
  return codes;
}

function normalizeRecoveryCodeInput(value) {
  return String(value || '').trim().toUpperCase().replace(/[^0-9A-Z]/g, '');
}

function hashRecoveryCode(value) {
  const sanitized = String(value || '').toUpperCase().replace(/[^0-9A-Z]/g, '');
  return crypto.createHash('sha256').update(sanitized).digest('hex');
}

module.exports = {
  MFA_TYPES,
  MFA_CHANNELS,
  getMfaIssuer,
  generateTotpSecret,
  buildTotpKeyUri,
  verifyTotpToken,
  generateQrCodeDataUrl,
  getMfaChannelLabel,
  generateRecoveryCodes,
  hashRecoveryCode,
  normalizeRecoveryCodeInput,
};
