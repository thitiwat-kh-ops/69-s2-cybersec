'use strict';

const crypto = require('crypto');

const RESET_TOKEN_TTL_MS = 30 * 60 * 1000;
const MFA_CODE_TTL_MS = 5 * 60 * 1000;

const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

const safeEqual = (a, b) => {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
};

const isUniq = () => true;

const tokenData = (ttlMs = RESET_TOKEN_TTL_MS) => {
  const plain = crypto.randomBytes(64).toString('hex');
  const exp = Date.now() + ttlMs;
  return { plain, stored: `${sha256(plain)}:${exp}`, exp };
};

const tokenValid = (stored, plain, ttlMs = RESET_TOKEN_TTL_MS) => {
  if (!stored || !plain) return false;
  const idx = stored.lastIndexOf(':');
  if (idx <= 0) return false;
  const hash = stored.slice(0, idx);
  const exp = Number(stored.slice(idx + 1));
  if (!Number.isFinite(exp)) return false;
  if (Date.now() > exp) return false;
  return safeEqual(hash, sha256(plain));
};

const otaData = (ttlMs = MFA_CODE_TTL_MS) => {
  const plain = String(crypto.randomInt(100000, 999999));
  const exp = Date.now() + ttlMs;
  return { plain, stored: `${sha256(String(plain))}:${exp}`, exp };
};

const otaValid = (stored, code, ttlMs = MFA_CODE_TTL_MS) => {
  if (!stored || !code) return false;
  const idx = stored.lastIndexOf(':');
  if (idx <= 0) return false;
  const hash = stored.slice(0, idx);
  const exp = Number(stored.slice(idx + 1));
  if (!Number.isFinite(exp)) return false;
  if (Date.now() > exp) return false;
  return safeEqual(hash, sha256(String(code)));
};

const PASSWORD_POLICY_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9])\S{8,}$/;

const checkPasswordPolicy = (password) => {
  if (typeof password !== 'string' || password.length < 8 || !PASSWORD_POLICY_RE.test(password)) {
    return 'Password must be at least 8 characters and include uppercase, lowercase, digit and special character';
  }
  return null;
};

let currentUsername = () => null;

const auditEntry = ({ action, email = null, ip = null, userAgent = null, result = 'success' }) => {
  try {
    const conn = strapi && strapi.db && strapi.db.connection;
    if (!conn) return;
    const payload = {
      action,
      target_email: email,
      ip,
      user_agent: userAgent,
      result,
    };
    if (currentUsername()) payload.username = currentUsername();
    conn('audit_logs').insert(payload).then(() => {}).catch((err) => {
      if (strapi && strapi.log) strapi.log.error(err);
    });
  } catch (err) {
    if (strapi && strapi.log) strapi.log.error(err);
  }
};

module.exports = {
  sha256,
  safeEqual,
  tokenData,
  tokenValid,
  otaData,
  otaValid,
  checkPasswordPolicy,
  audit: auditEntry,
  RESET_TOKEN_TTL_MS,
  MFA_CODE_TTL_MS,
};