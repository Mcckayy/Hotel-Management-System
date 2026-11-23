const express = require('express'), crypto = require('crypto'), zlib = require('zlib'), path = require('path'), QRCode = require('qrcode');
const { PEPPER, SESSION_SECRET, keys, seal, open, getDb, jsonReplacer, jsonReviver } = require('../lib');
const F = getDb(), P = process.env.DB_PREFIX || '';   // DB_PREFIX keeps this system's data separate from anything else in the same Firebase project
if (P && !/^[A-Za-z0-9_]{1,20}$/.test(P)) throw new Error('DB_PREFIX may only contain letters, numbers and underscores (max 20).');
const col = n => F.collection(P + n), docp = p => F.doc(P + p), users = col('users'), archive = col('archive'), rooms = col('rooms'), bookings = col('bookings');
const ROLES = ['manager', 'receptionist', 'housekeeping', 'accountant'], ROOM_STATES = ['available', 'occupied', 'cleaning', 'maintenance'];
const MAX_FAILS = 5, LOCK_MS = 15 * 60e3, KEEP = Number(process.env.BACKUP_KEEP || 14), ZERO = '0'.repeat(64);
const S3_ON = !!(process.env.S3_BUCKET && process.env.AWS_REGION && process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY);
const httpErr = (status, message) => Object.assign(new Error(message), { status });

// ===== SALT + PEPPER (confidentiality of passwords) =====
// pepper: one secret from the environment, never stored in the database.
// salt:   16 random bytes per user, stored next to the hash.
// scrypt: deliberately slow, so each guess is expensive for an attacker.
const pepperize = pw => crypto.createHmac('sha256', PEPPER).update(pw).digest();
const scryptHash = (input, salt) => crypto.scryptSync(input, salt, 64, { N: 16384, r: 8, p: 1 });
const hashPassword = (pw, salt) => scryptHash(pepperize(pw), salt);
const DUMMY_SALT = crypto.randomBytes(16), DUMMY_HASH = hashPassword('dummy', DUMMY_SALT);
const checkPassword = (u, pw) => { const ok = crypto.timingSafeEqual(hashPassword(pw, u ? u.salt : DUMMY_SALT), u ? u.hash : DUMMY_HASH); return !!u && ok; };
const pwProblem = pw => typeof pw !== 'string' || pw.length < 8 || pw.length > 128 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw) ? 'Password needs at least 8 characters, including a letter and a number' : null;
const sealSecret = (id, s) => seal(keys.totp, Buffer.from(s), 'totp:' + id).toString('base64');
const readSecret = u => open(keys.totp, Buffer.from(u.totp_secret, 'base64'), 'totp:' + u.id).toString();
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32enc = buf => { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; };
const b32dec = s => { let bits = ''; for (const c of s) bits += B32.indexOf(c).toString(2).padStart(5, '0'); const by = []; for (let i = 0; i + 8 <= bits.length; i += 8) by.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(by); };
function hotp(key, counter) { const m = Buffer.alloc(8); m.writeBigUInt64BE(BigInt(counter)); const h = crypto.createHmac('sha1', key).update(m).digest(), o = h[19] & 15; return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0'); }
function verifyTotp(u, code) { const key = b32dec(readSecret(u)), t = Math.floor(Date.now() / 30000), c = String(code || '').trim(); return c.length === 6 && [-1, 0, 1].some(w => crypto.timingSafeEqual(Buffer.from(hotp(key, t + w)), Buffer.from(c))); }

// ===== Sessions: signed token, sent as cookie (web) or Bearer header (mobile) =====
const sign = p => crypto.createHmac('sha256', SESSION_SECRET).update(p).digest('base64url');
const cookieFlags = ttl => `; HttpOnly; SameSite=Strict; Path=/; Max-Age=${ttl}${process.env.VERCEL ? '; Secure' : ''}`;
function setSession(req, res, data, ttl) {
  const p = Buffer.from(JSON.stringify({ ...data, exp: Date.now() + ttl * 1000 })).toString('base64url'), token = `${p}.${sign(p)}`;
  res.setHeader('Set-Cookie', `sid=${token}${cookieFlags(ttl)}`);
  return req.headers['x-client'] === 'mobile' ? token : undefined;
}
function getSession(req) {
  const raw = (/^Bearer (\S+)$/.exec(req.headers.authorization || '') || [])[1] || (/(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '') || [])[1];
  if (!raw) return {}; const [p, s] = raw.split('.'); if (!p || !s) return {};
  const a = Buffer.from(s), b = Buffer.from(sign(p)); if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return {};
  try { const d = JSON.parse(Buffer.from(p, 'base64url')); return d.exp > Date.now() ? d : {}; } catch { return {}; }
}

// ===== Data helpers =====
const uidOf = email => crypto.createHash('sha256').update(email).digest('hex');
const getUser = async id => { const s = await users.doc(id).get(); return s.exists ? { id: s.id, ...s.data() } : null; };
const sha = (...p) => crypto.createHash('sha256').update(p.join('|')).digest('hex');
async function audit(event, userId = null, detail = '') {   // INTEGRITY: hash-chained audit log
  try {
    const head = docp('meta/auditHead');
    await F.runTransaction(async t => {
      const h = await t.get(head), seq = (h.exists ? h.data().seq : 0) + 1, prev = h.exists ? h.data().hash : ZERO, ts = new Date().toISOString(), hash = sha(prev, ts, event, userId ?? '', detail);
      t.set(col('audit').doc(String(seq).padStart(9, '0')), { seq, ts, event, user_id: userId, detail, prev_hash: prev, hash }); t.set(head, { seq, hash });
    });
  } catch (e) { console.error('audit failed:', e.message); }
}
async function verifyAudit() { let prev = ZERO; for (const d of (await col('audit').orderBy('seq').get()).docs) { const r = d.data(); if (r.prev_hash !== prev || r.hash !== sha(prev, r.ts, r.event, r.user_id ?? '', r.detail)) return { ok: false, brokenAt: r.seq }; prev = r.hash; } return { ok: true }; }
// CONFIDENTIALITY: guest phone/email encrypted per record. INTEGRITY: every booking carries an HMAC signature.
const sealField = (id, v) => v ? seal(keys.data, Buffer.from(v), 'guest:' + id).toString('base64') : '';
const openField = (id, v) => { try { return v ? open(keys.data, Buffer.from(v, 'base64'), 'guest:' + id).toString() : ''; } catch { return '[unreadable]'; } };
const sigOf = b => crypto.createHmac('sha256', keys.integrity).update(JSON.stringify([b.guest, b.phone, b.email, b.room, b.checkIn, b.checkOut, b.total, b.status, b.paid, b.created])).digest('hex');
const withSig = b => ({ ...b, sig: sigOf(b) });
const bookingView = (b, role) => ({ id: b.id, guest: b.guest, room: b.room, checkIn: b.checkIn, checkOut: b.checkOut, total: b.total, status: b.status, paid: b.paid, verified: sigOf(b) === b.sig,
  ...(['manager', 'receptionist'].includes(role) ? { phone: openField(b.id, b.phone), email: openField(b.id, b.email) } : {}) });   // accountant: no contact details
async function seedRooms() { const t = [['Standard', 80], ['Deluxe', 120], ['Suite', 220]]; await Promise.all(t.flatMap(([type, rate], i) => [1, 2, 3, 4].map(n => { const num = String((i + 1) * 100 + n); return rooms.doc(num).set({ number: num, type, rate, status: 'available' }); }))); }

// ===== Backups: AES-256-GCM encrypted, AWS S3 (+ Firestore copy) =====
let s3c; const S3 = () => s3c || (s3c = new (require('@aws-sdk/client-s3').S3Client)({ region: process.env.AWS_REGION, credentials: { accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY } }));
const s3cmd = (name, input) => S3().send(new (require('@aws-sdk/client-s3')[name])({ Bucket: process.env.S3_BUCKET, ...input }));
async function listBackups() {
  const m = new Map();
  for (const d of (await col('backups').orderBy('created', 'desc').get()).docs) m.set(d.id, { id: d.id, created: d.data().created, bytes: d.data().bytes, where: ['Firestore'] });
  if (S3_ON) try { for (const o of (await s3cmd('ListObjectsV2Command', { Prefix: 'backups/' })).Contents || []) { const id = o.Key.slice(8, -4), e = m.get(id) || { id, created: new Date(o.LastModified).toISOString(), bytes: o.Size, where: [] }; e.where.push('AWS S3'); m.set(id, e); } } catch (e) { console.error('S3 list failed:', e.message); }
  return [...m.values()].sort((a, b) => a.created < b.created ? 1 : -1);
}
async function runBackup(by) {
  const g = async c => (await col(c).get()).docs.map(d => ({ id: d.id, data: d.data() }));
  const snap = { config: { users: await g('users'), archive: await g('archive'), rooms: await g('rooms') }, data: { bookings: await g('bookings'), audit: await g('audit') } };
  const blob = seal(keys.backup, zlib.gzipSync(JSON.stringify(snap, jsonReplacer)), 'backup-v1'), created = new Date().toISOString(), id = created.replace(/[:.]/g, '-'), where = [];
  if (S3_ON) try { await s3cmd('PutObjectCommand', { Key: `backups/${id}.enc`, Body: blob, ServerSideEncryption: 'AES256' }); where.push('AWS S3'); } catch (e) { console.error('S3 backup failed:', e.message); }
  if (blob.length < 900000) { await col('backups').doc(id).set({ created, bytes: blob.length, data: blob }); where.push('Firestore'); }
  if (!where.length) throw new Error('Backup failed: no storage accepted it');
  for (const b of (await listBackups()).slice(KEEP)) { if (b.where.includes('Firestore')) await col('backups').doc(b.id).delete(); if (b.where.includes('AWS S3')) await s3cmd('DeleteObjectCommand', { Key: `backups/${b.id}.enc` }); }
  await audit('backup.created', by, `${id} -> ${where.join(' + ')}`); return { id, where };
}
async function readBackup(id) {
  if (S3_ON) try { return Buffer.from(await (await s3cmd('GetObjectCommand', { Key: `backups/${id}.enc` })).Body.transformToByteArray()); } catch { /* fall back */ }
  const s = await col('backups').doc(id).get(); if (!s.exists) throw httpErr(404, 'Backup not found'); return s.data().data;
}
// Restore point = CONFIGURATION only (staff accounts, roles, archive, room types and rates). Bookings, guest data, room status and the audit log are never touched.
async function restoreConfig(id, by) {
  const snap = JSON.parse(zlib.gunzipSync(open(keys.backup, await readBackup(id), 'backup-v1')).toString(), jsonReviver);   // throws if tampered
  for (const u of snap.config.users) await users.doc(u.id).set(u.data);
  for (const u of snap.config.archive) await archive.doc(u.id).set(u.data);
  for (const r of snap.config.rooms) await rooms.doc(r.id).set({ number: r.data.number, type: r.data.type, rate: r.data.rate }, { merge: true });
  await audit('backup.restored.config', by, id); return { users: snap.config.users.length, archived: snap.config.archive.length, rooms: snap.config.rooms.length };
}

// ===== App =====
const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));
const ah = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const fail = (res, code, error) => res.status(code).json({ error });
const isLocked = u => u && u.locked_until > Date.now();
async function recordFail(u) { const f = (u.failed || 0) + 1, lock = f >= MAX_FAILS; await users.doc(u.id).update({ failed: lock ? 0 : f, locked_until: lock ? Date.now() + LOCK_MS : 0 }); await audit(lock ? 'account.locked' : 'login.failed', u.id); }
const guard = (roles, { allowChange = false } = {}) => ah(async (req, res, next) => {
  const s = getSession(req), u = s.kind === 'full' && await getUser(s.uid);
  if (!u) return fail(res, 401, 'Sign in required');
  if (u.must_change && !allowChange) return fail(res, 403, 'Change your temporary password first');
  if (roles.length && !roles.includes(u.role)) { await audit('access.denied', u.id, `${req.method} ${req.path}`); return fail(res, 403, `Access denied: the ${u.role} role cannot do this`); }
  req.user = u; next();
});
async function finishLogin(req, res, u) { await users.doc(u.id).update({ failed: 0, locked_until: 0, last_login: new Date().toISOString() }); await audit('login.success', u.id); res.json({ ok: true, token: setSession(req, res, { kind: 'full', uid: u.id }, 3600) }); }
async function beginSetup(req, res, u) {
  let secret; if (u.totp_secret) secret = readSecret(u); else { secret = b32enc(crypto.randomBytes(20)); await users.doc(u.id).update({ totp_secret: sealSecret(u.id, secret) }); }
  const uri = `otpauth://totp/HotelDesk:${encodeURIComponent(u.email)}?secret=${secret}&issuer=HotelDesk`;
  return { step: 'setup', secret, uri, qr: await QRCode.toDataURL(uri), token: setSession(req, res, { kind: 'setup', uid: u.id }, 600) };
}
function cleanUser({ name, email, password }) {
  const nm = String(name || '').trim(), em = String(email || '').trim().toLowerCase();
  if (nm.length < 2 || nm.length > 80) return { error: 'Enter a full name' };
  if (em.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(em)) return { error: 'Enter a valid email address' };
  const pw = pwProblem(password); return pw ? { error: pw } : { name: nm, email: em };
}
const newUserDoc = (v, password, role, mustChange) => { const salt = crypto.randomBytes(16); return { name: v.name, email: v.email, salt, hash: hashPassword(password, salt), role, totp_secret: null, totp_enabled: false, totp_confirmed_at: null, failed: 0, locked_until: 0, created_at: new Date().toISOString(), last_login: null, must_change: mustChange }; };

app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));
app.get('/api/status', ah(async (req, res) => res.json({ open: !(await docp('meta/firstAdmin').get()).exists })));
app.post('/api/register', ah(async (req, res) => {   // only the very first account; it becomes the Hotel Manager
  const v = cleanUser(req.body || {}); if (v.error) return fail(res, 400, v.error);
  if (!(await docp('meta/firstAdmin').create({ at: new Date().toISOString() }).then(() => true, () => false))) return fail(res, 403, 'Registration is closed. Ask your Hotel Manager to create your account.');
  const id = uidOf(v.email); await users.doc(id).create(newUserDoc(v, req.body.password, 'manager', false)); await seedRooms(); await audit('user.registered', id, 'first account (manager)');
  res.json(await beginSetup(req, res, await getUser(id)));
}));
app.post('/api/login', ah(async (req, res) => {
  const u = await getUser(uidOf(String(req.body?.email || '').trim().toLowerCase()));
  if (isLocked(u)) return fail(res, 429, 'Too many failed attempts. Account locked for 15 minutes.');
  if (!checkPassword(u, String(req.body?.password || ''))) { if (u) await recordFail(u); return fail(res, 401, 'Wrong email or password'); }
  if (!u.totp_enabled) return res.json(await beginSetup(req, res, u));
  res.json({ step: 'totp', token: setSession(req, res, { kind: 'pending', uid: u.id }, 600) });
}));
app.post('/api/login/totp', ah(async (req, res) => {
  const s = getSession(req), u = s.kind === 'pending' && await getUser(s.uid); if (!u) return fail(res, 401, 'Enter your password first');
  if (isLocked(u)) return fail(res, 429, 'Account locked. Try again later.');
  if (!verifyTotp(u, req.body?.code)) { await recordFail(u); return fail(res, 401, 'That code is not valid. Check your authenticator app and try again.'); }
  await finishLogin(req, res, u);
}));
app.post('/api/2fa/confirm', ah(async (req, res) => {
  const s = getSession(req), u = s.kind === 'setup' && await getUser(s.uid); if (!u || u.totp_enabled) return fail(res, 401, 'No two-factor setup in progress');
  if (!verifyTotp(u, req.body?.code)) return fail(res, 401, 'That code is not valid. Check your authenticator app and try again.');
  await users.doc(u.id).update({ totp_enabled: true, totp_confirmed_at: new Date().toISOString() }); await audit('2fa.enabled', u.id); await finishLogin(req, res, u);
}));
app.post('/api/logout', (req, res) => { res.setHeader('Set-Cookie', 'sid=' + cookieFlags(0)); res.json({ ok: true }); });
app.post('/api/password', guard([], { allowChange: true }), ah(async (req, res) => {
  const { current, next } = req.body || {}, u = req.user;
  if (!checkPassword(u, String(current || ''))) return fail(res, 401, 'Current password is wrong');
  const p = pwProblem(next); if (p) return fail(res, 400, p); if (next === current) return fail(res, 400, 'Choose a different password');
  const salt = crypto.randomBytes(16); await users.doc(u.id).update({ salt, hash: hashPassword(next, salt), must_change: false }); await audit('password.changed', u.id); res.json({ ok: true });
}));
app.get('/api/me', guard([], { allowChange: true }), (req, res) => { const u = req.user; res.json({ id: u.id.slice(0, 8), name: u.name, email: u.email, role: u.role, must_change: !!u.must_change, last_login: u.last_login, totp_confirmed_at: u.totp_confirmed_at }); });

// ----- Rooms & bookings -----
app.get('/api/rooms', guard([]), ah(async (req, res) => res.json((await rooms.orderBy('number').get()).docs.map(d => d.data()))));
app.post('/api/rooms/:n/status', guard(['manager', 'housekeeping']), ah(async (req, res) => {
  const st = req.body?.status; if (!ROOM_STATES.includes(st)) return fail(res, 400, 'Unknown room status');
  if (!(await rooms.doc(req.params.n).get()).exists) return fail(res, 404, 'No such room');
  await rooms.doc(req.params.n).update({ status: st }); await audit('room.status', req.user.id, `${req.params.n} -> ${st}`); res.json({ ok: true });
}));
app.get('/api/bookings', guard(['manager', 'receptionist', 'accountant']), ah(async (req, res) =>
  res.json((await bookings.get()).docs.map(d => bookingView(d.data(), req.user.role)).sort((a, b) => a.checkIn < b.checkIn ? 1 : -1))));
app.post('/api/bookings', guard(['manager', 'receptionist']), ah(async (req, res) => {
  const { guest, phone, email, room, checkIn, checkOut } = req.body || {}, day = /^\d{4}-\d{2}-\d{2}$/;
  if (String(guest || '').trim().length < 2 || String(guest).length > 80) return fail(res, 400, 'Enter the guest name');
  if (!day.test(checkIn) || !day.test(checkOut) || checkOut <= checkIn) return fail(res, 400, 'Check-out must be after check-in');
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return fail(res, 400, 'Guest email looks wrong');
  if (String(phone || '').length > 30) return fail(res, 400, 'Guest phone looks wrong');
  const id = crypto.randomBytes(5).toString('hex'), nights = Math.round((Date.parse(checkOut) - Date.parse(checkIn)) / 864e5);
  if (nights > 60) return fail(res, 400, 'Stays are limited to 60 nights');
  await F.runTransaction(async t => {   // transaction = no double booking
    const r = await t.get(rooms.doc(String(room))); if (!r.exists) throw httpErr(404, 'No such room'); if (r.data().status === 'maintenance') throw httpErr(409, 'Room is under maintenance');
    if ((await t.get(bookings.where('room', '==', String(room)))).docs.some(d => ['booked', 'checked-in'].includes(d.data().status) && d.data().checkIn < checkOut && checkIn < d.data().checkOut)) throw httpErr(409, 'That room is already booked for those dates');
    t.set(bookings.doc(id), withSig({ id, guest: String(guest).trim(), phone: sealField(id, phone), email: sealField(id, email), room: String(room), checkIn, checkOut, total: nights * r.data().rate, status: 'booked', paid: 0, created: new Date().toISOString() }));
  });
  await audit('booking.created', req.user.id, `${id} room ${room}`); res.json({ ok: true, id });
}));
const ACTIONS = { checkin: { roles: ['manager', 'receptionist'], from: 'booked', to: 'checked-in', room: 'occupied' }, checkout: { roles: ['manager', 'receptionist'], from: 'checked-in', to: 'checked-out', room: 'cleaning' },
  cancel: { roles: ['manager', 'receptionist'], from: 'booked', to: 'cancelled' }, pay: { roles: ['manager', 'accountant'] } };
app.post('/api/bookings/:id/:action', ah(async (req, res, next) => {
  const a = ACTIONS[req.params.action]; if (!a) return fail(res, 404, 'Unknown action');
  return guard(a.roles)(req, res, async err => {
    if (err) return next(err);
    try {
      const ref = bookings.doc(req.params.id), s = await ref.get(); if (!s.exists) return fail(res, 404, 'No such booking');
      const b = s.data(); if (sigOf(b) !== b.sig) return fail(res, 409, 'Integrity check failed: this record was altered outside the system');
      if (a.from && b.status !== a.from) return fail(res, 409, `Booking is ${b.status}`);
      if (!a.from && (b.paid >= b.total || b.status === 'cancelled')) return fail(res, 409, 'Nothing to pay on this booking');
      await ref.set(withSig(a.from ? { ...b, status: a.to } : { ...b, paid: b.total }));
      if (a.room) await rooms.doc(b.room).update({ status: a.room });
      await audit(`booking.${req.params.action}`, req.user.id, b.id); res.json({ ok: true });
    } catch (e) { next(e); }
  });
}));

// ----- Staff: add, modify, archive (never destroyed), restore -----
app.get('/api/staff', guard(['manager']), ah(async (req, res) => {
  const pick = (d, extra) => ({ id: d.id, name: d.data().name, email: d.data().email, role: d.data().role, ...extra(d.data()) });
  res.json({ active: (await users.orderBy('created_at').get()).docs.map(d => pick(d, x => ({ totp_enabled: x.totp_enabled, last_login: x.last_login }))), archived: (await archive.get()).docs.map(d => pick(d, x => ({ archived_at: x.archived_at }))) });
}));
app.post('/api/staff', guard(['manager']), ah(async (req, res) => {
  const v = cleanUser(req.body || {}); if (v.error) return fail(res, 400, v.error); if (!ROLES.includes(req.body.role)) return fail(res, 400, 'Choose one of the four roles');
  const id = uidOf(v.email); if ((await archive.doc(id).get()).exists) return fail(res, 409, 'This person is in the archive. Restore them instead.');
  try { await users.doc(id).create(newUserDoc(v, req.body.password, req.body.role, true)); } catch { return fail(res, 409, 'An account with this email already exists'); }
  await audit('staff.added', req.user.id, `${id.slice(0, 8)} as ${req.body.role}`); res.json({ ok: true });
}));
const managersLeft = async exceptId => (await users.get()).docs.filter(d => d.id !== exceptId && d.data().role === 'manager').length;
app.patch('/api/staff/:id', guard(['manager']), ah(async (req, res) => {
  const u = await getUser(req.params.id); if (!u) return fail(res, 404, 'No such staff member'); const { name, role, password } = req.body || {}, patch = {};
  if (name !== undefined) { if (String(name).trim().length < 2) return fail(res, 400, 'Enter a full name'); patch.name = String(name).trim(); }
  if (role !== undefined && role !== u.role) { if (!ROLES.includes(role)) return fail(res, 400, 'Unknown role'); if (u.role === 'manager' && !(await managersLeft(u.id))) return fail(res, 400, 'There must always be one Hotel Manager'); patch.role = role; }
  if (password) { const p = pwProblem(password); if (p) return fail(res, 400, p); const salt = crypto.randomBytes(16); Object.assign(patch, { salt, hash: hashPassword(password, salt), must_change: true, failed: 0, locked_until: 0 }); }
  if (!Object.keys(patch).length) return fail(res, 400, 'Nothing to change'); await users.doc(u.id).update(patch); await audit('staff.modified', req.user.id, `${u.id.slice(0, 8)}: ${Object.keys(patch).filter(k => !['salt', 'hash'].includes(k)).join(',')}${password ? ' password-reset' : ''}`); res.json({ ok: true });
}));
app.delete('/api/staff/:id', guard(['manager']), ah(async (req, res) => {   // moved to a separate archive, not deleted
  const u = await getUser(req.params.id); if (!u) return fail(res, 404, 'No such staff member'); if (u.id === req.user.id) return fail(res, 400, "You can't archive yourself");
  if (u.role === 'manager' && !(await managersLeft(u.id))) return fail(res, 400, 'There must always be one Hotel Manager');
  const { id, ...data } = u; await archive.doc(id).set({ ...data, archived_at: new Date().toISOString(), archived_by: req.user.id }); await users.doc(id).delete(); await audit('staff.archived', req.user.id, id.slice(0, 8)); res.json({ ok: true });
}));
app.post('/api/staff/:id/restore', guard(['manager']), ah(async (req, res) => {
  const s = await archive.doc(req.params.id).get(); if (!s.exists) return fail(res, 404, 'Not in the archive');
  const { archived_at, archived_by, ...data } = s.data(); await users.doc(s.id).set(data); await archive.doc(s.id).delete(); await audit('staff.restored', req.user.id, s.id.slice(0, 8)); res.json({ ok: true });
}));

// ----- Security reports (manager) -----
app.get('/api/security/passwords', guard(['manager']), ah(async (req, res) => {
  const fp = sha('pepper-fingerprint', PEPPER).slice(0, 8);
  res.json({ note: 'Plain passwords are never stored. Only these irreversible values exist.', pepper: `HMAC-SHA256, fingerprint ${fp} (the pepper itself is never shown or stored in the database)`, kdf: 'scrypt, N=16384, r=8, p=1, 64-byte output',
    users: (await users.orderBy('created_at').get()).docs.map(d => ({ name: d.data().name, email: d.data().email, role: d.data().role, salt: d.data().salt.toString('hex'), hash: d.data().hash.toString('hex') })) });
}));
app.post('/api/security/hashlab', guard(['manager']), (req, res) => {
  const pw = String(req.body?.password || '').slice(0, 128); if (!pw) return fail(res, 400, 'Type a sample password');
  const sA = crypto.randomBytes(16), sB = crypto.randomBytes(16), pep = pepperize(pw), x = b => b.toString('hex');
  res.json({ pepperedInput: x(pep), saltA: x(sA), hashA: x(scryptHash(pep, sA)), saltB: x(sB), hashB: x(scryptHash(pep, sB)), withoutPepperA: x(scryptHash(Buffer.from(pw), sA)) });
});
async function ciaReport() {
  const us = (await users.get()).docs.map(d => d.data()), aud = await verifyAudit(), bs = (await bookings.get()).docs.map(d => d.data()), bad = bs.filter(b => sigOf(b) !== b.sig).length;
  const bk = await listBackups(), last = bk[0], fresh = last && Date.now() - Date.parse(last.created) < 26 * 3600e3, c = (name, ok, detail) => ({ name, ok, detail });
  return {
    confidentiality: [c('Passwords salted, peppered and hashed with scrypt', true, 'No plain passwords are stored'), c('Two-factor sign-in enrolled for every staff account', us.every(u => u.totp_enabled), `${us.filter(u => u.totp_enabled).length} of ${us.length} enrolled`),
      c('Guest phone and email encrypted (AES-256-GCM)', true, 'Encrypted per booking record'), c('Least-privilege roles', true, 'The accountant never sees guest contact details'), c('HTTPS-only secure cookies', !!process.env.VERCEL, process.env.VERCEL ? 'Secure flag on' : 'Local run. HTTPS applies on Vercel')],
    integrity: [c('Audit log hash chain intact', aud.ok, aud.ok ? 'Verified' : `Broken at entry ${aud.brokenAt}`), c('Booking records pass signature check', bad === 0, `${bs.length - bad} of ${bs.length} verified`),
      c('Backups are tamper-evident', true, 'A changed backup is refused on restore'), c('Double booking prevented', true, 'Transactions reject overlapping stays')],
    availability: [c('Automatic daily backups', !!fresh, last ? `Last: ${new Date(last.created).toLocaleString()}` : 'No backup yet'), c('Off-site copy in AWS S3', S3_ON && !!last?.where.includes('AWS S3'), S3_ON ? 'Bucket configured' : 'AWS variables not set'),
      c('Second copy in Firestore', !!last?.where.includes('Firestore'), 'Redundant copy of the latest backup'), c('Brute-force lockout', true, '5 failed tries lock an account for 15 minutes'), c('Health check', true, '/api/health')] };
}
app.get('/api/security/cia', guard(['manager']), ah(async (req, res) => res.json(await ciaReport())));

// ----- Backups (manager) -----
app.get('/api/backups', guard(['manager']), ah(async (req, res) => res.json({ s3: S3_ON, backups: await listBackups(), keep: KEEP })));
app.post('/api/backups', guard(['manager']), ah(async (req, res) => res.json({ ok: true, ...(await runBackup(req.user.id)) })));
app.post('/api/backups/:id/restore', guard(['manager']), ah(async (req, res) => {
  if (!/^[0-9T-]+Z$/.test(req.params.id)) return fail(res, 400, 'Bad backup id');
  try { res.json({ ok: true, ...(await restoreConfig(req.params.id, req.user.id)) }); } catch (e) { if (e.status) throw e; fail(res, 422, 'This backup could not be verified and was NOT restored'); }
}));
app.get('/api/cron/backup', ah(async (req, res) => {
  if (!process.env.CRON_SECRET || req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) return fail(res, 401, 'Unauthorized');
  res.json({ ok: true, ...(await runBackup(null)) });
}));

app.use('/api', (req, res) => fail(res, 404, 'Unknown API route'));
app.use((err, req, res, next) => { if (err.status && err.status < 500) return fail(res, err.status, err.type ? 'Invalid request' : err.message); console.error(err); res.status(500).json({ error: 'Server error. Check the Vercel function logs for details.', ...(process.env.VERCEL ? {} : { detail: String(err.message).slice(0, 300) }) }); });
if (require.main === module) app.listen(3000, () => console.log('Open http://localhost:3000'));
module.exports = app;
