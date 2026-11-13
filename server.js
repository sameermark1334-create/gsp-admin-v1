const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

// ---------- Settings (set these as environment variables) ----------
const PORT = process.env.PORT || 3000;
const ADMIN_PIN = process.env.ADMIN_PIN;
const APP_SECRET = process.env.APP_SECRET;
if (!ADMIN_PIN || ADMIN_PIN.length < 6 || !APP_SECRET || APP_SECRET.length < 16) {
  console.error('Missing settings: ADMIN_PIN (6+ characters) and APP_SECRET (16+ characters) are required.');
  process.exit(1);
}

// ---------- Database ----------
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'data.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS services(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '',
  key_hash TEXT NOT NULL, key_enc TEXT NOT NULL, active INTEGER DEFAULT 1, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS keys(
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL, key TEXT UNIQUE NOT NULL,
  duration_seconds INTEGER NOT NULL, single_use INTEGER DEFAULT 0, status TEXT DEFAULT 'active',
  created_at INTEGER NOT NULL, created_by TEXT, activated_at INTEGER, expires_at INTEGER,
  verify_count INTEGER DEFAULT 0, last_verified_at INTEGER, ban_reason TEXT, banned_at INTEGER);
CREATE INDEX IF NOT EXISTS ix_keys_svc ON keys(service_id, status);
CREATE TABLE IF NOT EXISTS resellers(
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL, name TEXT NOT NULL,
  token_hash TEXT UNIQUE NOT NULL, token_prefix TEXT NOT NULL, max_keys INTEGER NOT NULL,
  keys_used INTEGER DEFAULT 0, active INTEGER DEFAULT 1, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, service_id TEXT, reseller_id TEXT,
  action TEXT, result TEXT, detail TEXT, ip TEXT);
`);

// ---------- Helpers ----------
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const rid = (p) => p + crypto.randomBytes(6).toString('hex');
const iso = (t) => new Date(t).toISOString();
const safeEq = (a, b) => crypto.timingSafeEqual(Buffer.from(sha(a)), Buffer.from(sha(b)));
const ENC = crypto.scryptSync(APP_SECRET, 'gsp-license-salt', 32);
function enc(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', ENC, iv);
  const data = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), data].map((b) => b.toString('hex')).join(':');
}
function dec(blob) {
  const [iv, tag, data] = blob.split(':').map((h) => Buffer.from(h, 'hex'));
  const d = crypto.createDecipheriv('aes-256-gcm', ENC, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]).toString('utf8');
}
const UNIT = { minutes: 60, hours: 3600, days: 86400 };
function dur(d) {
  const v = Number(d && d.value), u = d && d.unit;
  if (!UNIT[u] || !Number.isInteger(v) || v < 1) return null;
  const s = v * UNIT[u];
  return s > 315360000 ? null : s; // max 10 years
}
const AL = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function mkKey() {
  let s = '';
  for (const x of crypto.randomBytes(12)) s += AL[x % 32];
  return 'GSP-' + s.match(/.{4}/g).join('-');
}
const insKey = db.prepare('INSERT INTO keys(id,service_id,key,duration_seconds,single_use,created_at,created_by) VALUES(?,?,?,?,?,?,?)');
const createKeys = db.transaction((sid, count, secs, single, by) => {
  const out = [];
  for (let i = 0; i < count; i++) {
    const k = mkKey();
    insKey.run(rid('k_'), sid, k, secs, single ? 1 : 0, Date.now(), by);
    out.push(k);
  }
  return out;
});
const logSt = db.prepare('INSERT INTO logs(ts,service_id,reseller_id,action,result,detail,ip) VALUES(?,?,?,?,?,?,?)');
const log = (sid, rs, action, result, detail, ip) => logSt.run(Date.now(), sid, rs, action, result, detail || '', ip || '');
const getSvc = (id) => db.prepare('SELECT * FROM services WHERE id=?').get(id);

// ---------- App ----------
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' });
  next();
});

// ---------- Master admin login & sessions ----------
const sessions = new Map();
const IDLE = 10 * 60 * 1000; // session locks after 10 minutes of no activity
const fails = new Map();
const getTok = (req) => { const m = (req.headers.cookie || '').match(/(?:^|; )gsp_s=([a-f0-9]+)/); return m && m[1]; };
function auth(req, res, next) {
  const t = getTok(req), s = t && sessions.get(t);
  if (!s || Date.now() - s.last > IDLE) { if (t) sessions.delete(t); return res.status(401).json({ error: 'locked' }); }
  s.last = Date.now();
  next();
}
const cookie = (req, v, age) => `gsp_s=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${req.secure ? '; Secure' : ''}`;

app.post('/admin/login', (req, res) => {
  const ip = req.ip, f = fails.get(ip) || { n: 0, until: 0 };
  if (Date.now() < f.until) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  if (safeEq(String(req.body.pin || ''), ADMIN_PIN)) {
    fails.delete(ip);
    const t = crypto.randomBytes(32).toString('hex');
    sessions.set(t, { last: Date.now() });
    res.setHeader('Set-Cookie', cookie(req, t, 43200));
    return res.json({ ok: true });
  }
  f.n++;
  if (f.n >= 5) { f.until = Date.now() + 15 * 60 * 1000; f.n = 0; }
  fails.set(ip, f);
  res.status(401).json({ error: 'Wrong PIN' });
});
app.post('/admin/logout', (req, res) => {
  sessions.delete(getTok(req));
  res.setHeader('Set-Cookie', cookie(req, '', 0));
  res.json({ ok: true });
});
app.use('/admin', auth);
app.get('/admin/session', (req, res) => res.json({ ok: true }));

// ---------- Admin: stats ----------
app.get('/admin/stats', (req, res) => {
  const c = (q) => db.prepare(q).get().n;
  res.json({
    services: c('SELECT COUNT(*) n FROM services'),
    keys: c('SELECT COUNT(*) n FROM keys'),
    banned: c("SELECT COUNT(*) n FROM keys WHERE status='banned'"),
    resellers: c('SELECT COUNT(*) n FROM resellers WHERE active=1'),
    calls: c('SELECT COUNT(*) n FROM logs WHERE ts>' + (Date.now() - 86400000)),
  });
});

// ---------- Admin: services (each gets its own API key + endpoints) ----------
const svcOut = (s) => ({ id: s.id, name: s.name, description: s.description, active: s.active, created_at: s.created_at });
app.get('/admin/services', (req, res) => {
  const rows = db.prepare('SELECT s.*,(SELECT COUNT(*) FROM keys WHERE service_id=s.id) keys FROM services s ORDER BY created_at DESC').all();
  res.json(rows.map((s) => ({ ...svcOut(s), keys: s.keys })));
});
app.post('/admin/services', (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'Name is required' });
  const id = rid('svc_'), k = 'gsp_live_' + crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO services(id,name,description,key_hash,key_enc,created_at) VALUES(?,?,?,?,?,?)')
    .run(id, name, String(req.body.description || '').slice(0, 120), sha(k), enc(k), Date.now());
  res.json({ id });
});
app.get('/admin/services/:id', (req, res) => {
  const s = getSvc(req.params.id);
  if (!s) return res.status(404).json({ error: 'Service not found' });
  res.json({ ...svcOut(s), api_key: dec(s.key_enc) });
});
app.post('/admin/services/:id/rotate', (req, res) => {
  const k = 'gsp_live_' + crypto.randomBytes(24).toString('hex');
  const n = db.prepare('UPDATE services SET key_hash=?,key_enc=? WHERE id=?').run(sha(k), enc(k), req.params.id).changes;
  res.json({ ok: !!n });
});
app.post('/admin/services/:id/toggle', (req, res) => {
  db.prepare('UPDATE services SET active=1-active WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- Admin: key bank ----------
app.get('/admin/services/:id/keys', (req, res) => {
  let q = 'SELECT * FROM keys WHERE service_id=?';
  const a = [req.params.id];
  if (['active', 'used', 'banned'].includes(req.query.status)) { q += ' AND status=?'; a.push(req.query.status); }
  res.json(db.prepare(q + ' ORDER BY created_at DESC LIMIT 200').all(...a));
});
app.post('/admin/services/:id/keys', (req, res) => {
  if (!getSvc(req.params.id)) return res.status(404).json({ error: 'Service not found' });
  const c = Number(req.body.count), s = dur(req.body.duration);
  if (!Number.isInteger(c) || c < 1 || c > 50) return res.status(400).json({ error: 'Number of keys must be 1 to 50' });
  if (!s) return res.status(400).json({ error: 'Invalid duration' });
  res.json({ keys: createKeys(req.params.id, c, s, !!req.body.single_use, 'admin') });
});
app.post('/admin/keys/:id/ban', (req, res) => {
  const reason = String(req.body.reason || '').trim().slice(0, 200);
  if (!reason) return res.status(400).json({ error: 'Ban reason is required' });
  const n = db.prepare("UPDATE keys SET status='banned',ban_reason=?,banned_at=? WHERE id=?").run(reason, Date.now(), req.params.id).changes;
  res.json({ ok: !!n });
});
app.post('/admin/keys/:id/unban', (req, res) => {
  db.prepare("UPDATE keys SET status=CASE WHEN single_use=1 AND activated_at IS NOT NULL THEN 'used' ELSE 'active' END,ban_reason=NULL,banned_at=NULL WHERE id=? AND status='banned'").run(req.params.id);
  res.json({ ok: true });
});

// ---------- Admin: resellers ----------
app.get('/admin/resellers', (req, res) => {
  res.json(db.prepare('SELECT r.id,r.name,r.token_prefix,r.max_keys,r.keys_used,r.active,r.created_at,s.name service_name FROM resellers r LEFT JOIN services s ON s.id=r.service_id ORDER BY r.created_at DESC').all());
});
app.post('/admin/resellers', (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60), max = Number(req.body.max_keys);
  if (!name) return res.status(400).json({ error: 'Reseller name is required' });
  if (!Number.isInteger(max) || max < 1 || max > 1000000) return res.status(400).json({ error: 'Max keys must be 1 or more' });
  if (!getSvc(req.body.service_id)) return res.status(400).json({ error: 'Choose a service' });
  const token = 'gsp_rs_' + crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO resellers(id,service_id,name,token_hash,token_prefix,max_keys,created_at) VALUES(?,?,?,?,?,?,?)')
    .run(rid('rs_'), req.body.service_id, name, sha(token), token.slice(0, 13), max, Date.now());
  res.json({ token }); // shown only once
});
app.post('/admin/resellers/:id/revoke', (req, res) => { db.prepare('UPDATE resellers SET active=0 WHERE id=?').run(req.params.id); res.json({ ok: true }); });
app.post('/admin/resellers/:id/restore', (req, res) => { db.prepare('UPDATE resellers SET active=1 WHERE id=?').run(req.params.id); res.json({ ok: true }); });
app.get('/admin/logs', (req, res) => {
  const r = req.query.reseller;
  res.json(db.prepare(`SELECT l.*,s.name service_name,r.name reseller_name FROM logs l
    LEFT JOIN services s ON s.id=l.service_id LEFT JOIN resellers r ON r.id=l.reseller_id
    ${r ? 'WHERE l.reseller_id=?' : ''} ORDER BY l.id DESC LIMIT 100`).all(...(r ? [r] : [])));
});

// ---------- Public API (used by your websites and resellers) ----------
const hits = new Map();
setInterval(() => hits.clear(), 60000).unref();
function limit(req, res, next) {
  const n = (hits.get(req.ip) || 0) + 1;
  hits.set(req.ip, n);
  if (n > 120) return res.status(429).json({ status: 'error', error: 'rate_limited' });
  next();
}
app.use('/api/v1', (req, res, next) => {
  res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type,X-API-Key,Authorization', 'Access-Control-Allow-Methods': 'POST,OPTIONS' });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
function pub(req, res, next) {
  const svc = getSvc(req.params.sid);
  const tok = String(req.headers['x-api-key'] || (req.headers.authorization || '').replace(/^Bearer /, '')).trim();
  const bad = () => res.status(401).json({ status: 'error', error: 'unauthorized' });
  if (!svc || !tok) return bad();
  if (tok.startsWith('gsp_live_')) {
    if (sha(tok) !== svc.key_hash) return bad();
    req.rs = null;
  } else {
    const rs = db.prepare('SELECT * FROM resellers WHERE token_hash=? AND service_id=?').get(sha(tok), svc.id);
    if (!rs) return bad();
    if (!rs.active) return res.status(403).json({ status: 'error', error: 'reseller_revoked' });
    req.rs = rs;
  }
  if (!svc.active) return res.status(403).json({ status: 'error', error: 'service_disabled' });
  req.svc = svc;
  next();
}

app.post('/api/v1/:sid/verify', limit, pub, (req, res) => {
  const key = String(req.body.key || '').trim().toUpperCase();
  const k = db.prepare('SELECT * FROM keys WHERE key=? AND service_id=?').get(key, req.svc.id);
  const now = Date.now();
  let out;
  if (!k) out = { status: 'invalid' };
  else if (k.status === 'banned') out = { status: 'banned', ban_reason: k.ban_reason };
  else if (k.status === 'used') out = { status: 'used' };
  else if (k.expires_at && now > k.expires_at) out = { status: 'expired', expired_at: iso(k.expires_at) };
  else {
    // First successful check starts the timer. Single-use keys are burned right now.
    const act = k.activated_at || now;
    const exp = k.expires_at || now + k.duration_seconds * 1000;
    db.prepare('UPDATE keys SET activated_at=?,expires_at=?,status=?,verify_count=verify_count+1,last_verified_at=? WHERE id=?')
      .run(act, exp, k.single_use ? 'used' : 'active', now, k.id);
    out = { status: 'valid', single_use: !!k.single_use, activated_at: iso(act), expires_at: iso(exp), remaining_seconds: Math.max(0, Math.round((exp - now) / 1000)) };
  }
  log(req.svc.id, req.rs ? req.rs.id : null, 'verify', out.status, key, req.ip);
  res.json(out);
});

app.post('/api/v1/:sid/generate', limit, pub, (req, res) => {
  const count = Number(req.body.count === undefined ? 1 : req.body.count), secs = dur(req.body.duration);
  if (!Number.isInteger(count) || count < 1 || count > 50) return res.status(400).json({ status: 'error', error: 'count_must_be_1_to_50' });
  if (!secs) return res.status(400).json({ status: 'error', error: 'invalid_duration' });
  const run = db.transaction(() => {
    if (req.rs) {
      const r = db.prepare('SELECT * FROM resellers WHERE id=?').get(req.rs.id);
      if (r.keys_used + count > r.max_keys) return null;
      db.prepare('UPDATE resellers SET keys_used=keys_used+? WHERE id=?').run(count, r.id);
    }
    return createKeys(req.svc.id, count, secs, !!req.body.single_use, req.rs ? req.rs.id : 'api');
  });
  const keys = run();
  if (!keys) {
    log(req.svc.id, req.rs.id, 'generate', 'quota_exceeded', 'asked ' + count, req.ip);
    return res.status(403).json({ status: 'error', error: 'quota_exceeded' });
  }
  log(req.svc.id, req.rs ? req.rs.id : null, 'generate', 'ok', keys.length + ' keys', req.ip);
  res.json({ status: 'ok', count: keys.length, keys });
});

// ---------- Frontend & errors ----------
app.use(express.static(path.join(__dirname, 'public')));
app.use((e, req, res, next) => {
  if (e.type === 'entity.parse.failed') return res.status(400).json({ error: 'Bad JSON' });
  console.error(e);
  res.status(500).json({ error: 'Server error' });
});
app.listen(PORT, () => console.log('GSP dashboard running on port ' + PORT));
