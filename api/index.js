const express = require('express'), crypto = require('crypto'), zlib = require('zlib'), path = require('path'), QRCode = require('qrcode');
const { PEPPER, SESSION_SECRET, keys, seal, open, getDb, jsonReplacer } = require('../lib');
const F = getDb(), users = F.collection('users');
const ROLES = ['user', 'manager', 'admin'], MAX_FAILS = 5, LOCK_MS = 15 * 60e3, KEEP = Number(process.env.BACKUP_KEEP || 14), ZERO = '0'.repeat(64);

// ---------- Crypto: scrypt(HMAC(pepper, password), salt) ----------
const hashPassword = (pw, salt) => crypto.scryptSync(crypto.createHmac('sha256', PEPPER).update(pw).digest(), salt, 64, { N: 16384, r: 8, p: 1 });
const DUMMY_SALT = crypto.randomBytes(16), DUMMY_HASH = hashPassword('dummy', DUMMY_SALT);
const checkPassword = (u, pw) => { const ok = crypto.timingSafeEqual(hashPassword(pw, u ? u.salt : DUMMY_SALT), u ? u.hash : DUMMY_HASH); return !!u && ok; };
const sealSecret = (id, s) => seal(keys.totp, Buffer.from(s), 'totp:' + id).toString('base64');   // TOTP secrets encrypted at rest
const readSecret = u => open(keys.totp, Buffer.from(u.totp_secret, 'base64'), 'totp:' + u.id).toString();
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32enc = buf => { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; };
const b32dec = s => { let bits = ''; for (const c of s) bits += B32.indexOf(c).toString(2).padStart(5, '0'); const by = []; for (let i = 0; i + 8 <= bits.length; i += 8) by.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(by); };
function hotp(key, counter) { const m = Buffer.alloc(8); m.writeBigUInt64BE(BigInt(counter)); const h = crypto.createHmac('sha1', key).update(m).digest(), o = h[19] & 15; return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0'); }
function verifyTotp(u, code) {
  const key = b32dec(readSecret(u)), t = Math.floor(Date.now() / 30000), c = String(code || '').trim();
  return c.length === 6 && [-1, 0, 1].some(w => crypto.timingSafeEqual(Buffer.from(hotp(key, t + w)), Buffer.from(c)));
}

// ---------- Stateless signed-cookie sessions (serverless has no shared memory) ----------
const sign = p => crypto.createHmac('sha256', SESSION_SECRET).update(p).digest('base64url');
const cookieFlags = ttl => `; HttpOnly; SameSite=Strict; Path=/; Max-Age=${ttl}${process.env.VERCEL ? '; Secure' : ''}`;
function setSession(res, data, ttl) { const p = Buffer.from(JSON.stringify({ ...data, exp: Date.now() + ttl * 1000 })).toString('base64url'); res.setHeader('Set-Cookie', `sid=${p}.${sign(p)}${cookieFlags(ttl)}`); }
const clearSession = res => res.setHeader('Set-Cookie', 'sid=' + cookieFlags(0));
function getSession(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || ''); if (!m) return {};
  const [p, s] = m[1].split('.'); if (!p || !s) return {};
  const a = Buffer.from(s), b = Buffer.from(sign(p)); if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return {};
  try { const d = JSON.parse(Buffer.from(p, 'base64url')); return d.exp > Date.now() ? d : {}; } catch { return {}; }
}

// ---------- Firestore helpers ----------
const uidOf = email => crypto.createHash('sha256').update(email).digest('hex');   // doc id = hash of email => atomic uniqueness
const getUser = async id => { const s = await users.doc(id).get(); return s.exists ? { id: s.id, ...s.data() } : null; };
const sha = (...p) => crypto.createHash('sha256').update(p.join('|')).digest('hex');
async function audit(event, userId = null, detail = '') {   // tamper-evident SHA-256 hash chain
  try {
    const head = F.doc('meta/auditHead');
    await F.runTransaction(async t => {
      const h = await t.get(head), seq = (h.exists ? h.data().seq : 0) + 1, prev = h.exists ? h.data().hash : ZERO, ts = new Date().toISOString();
      const hash = sha(prev, ts, event, userId ?? '', detail);
      t.set(F.collection('audit').doc(String(seq).padStart(9, '0')), { seq, ts, event, user_id: userId, detail, prev_hash: prev, hash });
      t.set(head, { seq, hash });
    });
  } catch (e) { console.error('audit failed:', e.message); }
}
async function verifyAudit() {
  let prev = ZERO;
  for (const d of (await F.collection('audit').orderBy('seq').get()).docs) {
    const r = d.data();
    if (r.prev_hash !== prev || r.hash !== sha(prev, r.ts, r.event, r.user_id ?? '', r.detail)) return { ok: false, brokenAt: r.seq };
    prev = r.hash;
  }
  return { ok: true };
}

// ---------- Encrypted backups (stored in Firestore; run daily by Vercel Cron) ----------
async function runBackup() {
  const snap = {}; for (const c of ['users', 'audit', 'meta']) snap[c] = (await F.collection(c).get()).docs.map(d => ({ id: d.id, data: d.data() }));
  const blob = seal(keys.backup, zlib.gzipSync(JSON.stringify(snap, jsonReplacer)), 'backup-v1');
  if (blob.length > 900000) throw new Error('Backup is too large for one Firestore document');
  const id = new Date().toISOString().replace(/[:.]/g, '-'), created = new Date().toISOString();
  await F.collection('backups').doc(id).set({ created, bytes: blob.length, users: snap.users.length, data: blob });
  const all = await F.collection('backups').orderBy('created', 'desc').get();
  await Promise.all(all.docs.slice(KEEP).map(d => d.ref.delete()));   // retention
  await audit('backup.created', null, id);
  return id;
}

// ---------- App ----------
const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));   // local use; Vercel serves public/ itself
const ah = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const fail = (res, code, error) => res.status(code).json({ error });
const isLocked = u => u && u.locked_until > Date.now();
async function recordFail(u) {
  const f = (u.failed || 0) + 1, lock = f >= MAX_FAILS;
  await users.doc(u.id).update({ failed: lock ? 0 : f, locked_until: lock ? Date.now() + LOCK_MS : 0 });
  await audit(lock ? 'account.locked' : 'login.failed', u.id);
}
const requireRole = (...roles) => ah(async (req, res, next) => {
  const s = getSession(req), u = s.kind === 'full' && await getUser(s.uid);
  if (!u) return fail(res, 401, 'Sign in required');
  if (roles.length && !roles.includes(u.role)) { await audit('access.denied', u.id, req.path); return fail(res, 403, `Access denied: this area needs the ${roles.join(' or ')} role`); }
  req.user = u; next();
});
async function finishLogin(res, u) {
  await users.doc(u.id).update({ failed: 0, locked_until: 0, last_login: new Date().toISOString() });
  await audit('login.success', u.id);
  setSession(res, { kind: 'full', uid: u.id }, 3600); res.json({ ok: true });
}
async function beginSetup(res, u) {
  let secret;
  if (u.totp_secret) secret = readSecret(u);
  else { secret = b32enc(crypto.randomBytes(20)); await users.doc(u.id).update({ totp_secret: sealSecret(u.id, secret) }); }
  setSession(res, { kind: 'setup', uid: u.id }, 600);
  return { step: 'setup', secret, qr: await QRCode.toDataURL(`otpauth://totp/LoginSystem:${encodeURIComponent(u.email)}?secret=${secret}&issuer=LoginSystem`) };
}

app.post('/api/register', ah(async (req, res) => {
  const { name, email, password } = req.body || {};
  const nm = String(name || '').trim(), em = String(email || '').trim().toLowerCase();
  if (nm.length < 2 || nm.length > 80) return fail(res, 400, 'Enter your full name');
  if (em.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(em)) return fail(res, 400, 'Enter a valid email address');
  if (typeof password !== 'string' || password.length < 8 || password.length > 128 || !/[A-Za-z]/.test(password) || !/\d/.test(password))
    return fail(res, 400, 'Password needs at least 8 characters, including a letter and a number');
  const id = uidOf(em);
  if ((await users.doc(id).get()).exists) return fail(res, 409, 'An account with this email already exists');
  const first = await F.doc('meta/firstAdmin').create({ at: new Date().toISOString() }).then(() => true, () => false);   // first account = admin
  const salt = crypto.randomBytes(16);
  try {
    await users.doc(id).create({ name: nm, email: em, salt, hash: hashPassword(password, salt), role: first ? 'admin' : 'user', totp_secret: null,
      totp_enabled: false, totp_confirmed_at: null, failed: 0, locked_until: 0, created_at: new Date().toISOString(), last_login: null });
  } catch { return fail(res, 409, 'An account with this email already exists'); }
  await audit('user.registered', id);
  res.json(await beginSetup(res, await getUser(id)));
}));

app.post('/api/login', ah(async (req, res) => {
  const u = await getUser(uidOf(String(req.body?.email || '').trim().toLowerCase()));
  if (isLocked(u)) return fail(res, 429, 'Too many failed attempts. Account locked for 15 minutes.');
  if (!checkPassword(u, String(req.body?.password || ''))) { if (u) await recordFail(u); return fail(res, 401, 'Wrong email or password'); }
  if (!u.totp_enabled) return res.json(await beginSetup(res, u));
  setSession(res, { kind: 'pending', uid: u.id }, 600); res.json({ step: 'totp' });
}));

app.post('/api/login/totp', ah(async (req, res) => {
  const s = getSession(req), u = s.kind === 'pending' && await getUser(s.uid);
  if (!u) return fail(res, 401, 'Enter your password first');
  if (isLocked(u)) return fail(res, 429, 'Account locked. Try again later.');
  if (!verifyTotp(u, req.body?.code)) { await recordFail(u); return fail(res, 401, 'That code is not valid. Check your authenticator app and try again.'); }
  await finishLogin(res, u);
}));

app.post('/api/2fa/confirm', ah(async (req, res) => {
  const s = getSession(req), u = s.kind === 'setup' && await getUser(s.uid);
  if (!u || u.totp_enabled) return fail(res, 401, 'No two-factor setup in progress');
  if (!verifyTotp(u, req.body?.code)) return fail(res, 401, 'That code is not valid. Check your authenticator app and try again.');
  await users.doc(u.id).update({ totp_enabled: true, totp_confirmed_at: new Date().toISOString() });
  await audit('2fa.enabled', u.id);
  await finishLogin(res, u);
}));

app.post('/api/logout', (req, res) => { clearSession(res); res.json({ ok: true }); });
app.get('/api/me', requireRole(), (req, res) => { const u = req.user; res.json({ id: u.id.slice(0, 8), name: u.name, email: u.email, role: u.role, last_login: u.last_login, totp_confirmed_at: u.totp_confirmed_at,
  security: { authLevel: u.totp_enabled ? 'Two-factor authenticated (password + RFC 6238 TOTP)' : 'Password only', salt: `Unique ${u.salt.length}-byte random salt (per user)`,
    kdf: 'scrypt (N=16384, r=8, p=1)', pepper: 'Active (HMAC-SHA256 keyed with PEPPER from environment)', pepperStorage: 'Vercel environment variable, not stored in the database',
    totpStorage: 'AES-256-GCM encrypted at rest (key derived with HKDF-SHA256)' } }); });

app.get('/api/manager/reports', requireRole('manager', 'admin'), (req, res) => res.json({ message: `Manager area opened. Access granted for role: ${req.user.role}.` }));
app.get('/api/admin/users', requireRole('admin'), ah(async (req, res) =>
  res.json((await users.orderBy('created_at').get()).docs.map(d => ({ id: d.id, name: d.data().name, email: d.data().email, role: d.data().role, totp_enabled: d.data().totp_enabled })))));
app.post('/api/admin/users/:id/role', requireRole('admin'), ah(async (req, res) => {
  const role = req.body?.role, id = req.params.id;
  if (!ROLES.includes(role)) return fail(res, 400, 'Unknown role');
  if (id === req.user.id) return fail(res, 400, "You can't change your own role");
  if (!(await users.doc(id).get()).exists) return fail(res, 404, 'No such user');
  await users.doc(id).update({ role }); await audit('role.changed', req.user.id, `${id.slice(0, 8)} -> ${role}`); res.json({ ok: true });
}));
app.get('/api/admin/system', requireRole('admin'), ah(async (req, res) => {
  const last = await F.collection('backups').orderBy('created', 'desc').limit(1).get(), count = (await F.collection('backups').get()).size;
  res.json({ backups: { count, last: last.docs[0]?.data().created || null, keep: KEEP, schedule: 'Daily (Vercel Cron)' }, audit: await verifyAudit() });
}));
app.post('/api/admin/backup', requireRole('admin'), ah(async (req, res) => res.json({ ok: true, file: await runBackup() })));
app.get('/api/cron/backup', ah(async (req, res) => {   // Vercel Cron calls this with "Authorization: Bearer $CRON_SECRET"
  if (!process.env.CRON_SECRET || req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) return fail(res, 401, 'Unauthorized');
  res.json({ ok: true, id: await runBackup() });
}));

app.use('/api', (req, res) => fail(res, 404, 'Unknown API route'));
app.use((err, req, res, next) => { console.error(err); fail(res, err.status === 400 ? 400 : 500, err.status === 400 ? 'Invalid request' : 'Server error. Check the Vercel function logs for details.'); });
if (require.main === module) app.listen(3000, () => console.log('Open http://localhost:3000'));
module.exports = app;
