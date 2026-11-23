// Shared config, AES-256-GCM helpers, Firestore connection
const crypto = require('crypto');
const need = n => { const v = process.env[n]; if (!v || v.length < 32) throw new Error(`Missing ${n} (32+ characters). Run "node setup.js" and add it to Vercel's Environment Variables.`); return v; };
const PEPPER = need('PEPPER'), ENC = need('ENCRYPTION_KEY'), SESSION_SECRET = need('SESSION_SECRET');
const dk = info => Buffer.from(crypto.hkdfSync('sha256', ENC, 'login-system-v1', info, 32));  // one key per purpose
const keys = { totp: dk('totp-secret'), backup: dk('backup-file'), data: dk('guest-data'), integrity: dk('record-integrity') };
function seal(key, buf, aad) {            // iv(12) | tag(16) | ciphertext
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv); c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(buf), c.final()]); return Buffer.concat([iv, c.getAuthTag(), ct]);
}
function open(key, blob, aad) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12)); d.setAAD(Buffer.from(aad)); d.setAuthTag(blob.subarray(12, 28));
  return Buffer.concat([d.update(blob.subarray(28)), d.final()]);
}
let cached;
function getDb() {
  if (cached) return cached;
  const admin = require('firebase-admin');
  if (!admin.apps.length) {
    let raw = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!raw) throw new Error('Missing FIREBASE_SERVICE_ACCOUNT (the Firebase service-account JSON).');
    if (!raw.trim().startsWith('{')) raw = Buffer.from(raw, 'base64').toString();
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(raw)) });
  }
  return (cached = admin.firestore());
}
const jsonReplacer = (k, v) => v && v.type === 'Buffer' && Array.isArray(v.data) ? { $b64: Buffer.from(v.data).toString('base64') } : v;
const jsonReviver = (k, v) => v && v.$b64 !== undefined ? Buffer.from(v.$b64, 'base64') : v;
module.exports = { PEPPER, SESSION_SECRET, keys, seal, open, getDb, jsonReplacer, jsonReviver };
