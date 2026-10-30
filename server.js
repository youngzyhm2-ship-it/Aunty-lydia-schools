/* ============================================================
   Aunty Lydia Schools: backend
   Zero dependencies. Needs Node 22.13 or newer (uses node:sqlite).
   Serves the website, the content API, admin login, photo uploads,
   and stores contact-form and admission-form submissions.
   ============================================================ */
'use strict';
const origEmit = process.emitWarning;
process.emitWarning = (w, ...a) => (String(w).includes('SQLite') ? undefined : origEmit.call(process, w, ...a));

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

/* ---------- config ---------- */
(function loadEnvFile() {
  try {
    for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  } catch (e) { /* no .env: fine */ }
})();

const PORT = +process.env.PORT || 3000;
const SITE_ROOT = path.resolve(process.env.SITE_ROOT || path.join(__dirname, '..'));
const DATA_DIR = path.resolve(__dirname, process.env.DATA_DIR || './data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';
// Only trusted frontend origins may submit cross-origin requests.
const ALLOWED_ORIGINS = new Set((process.env.ALLOWED_ORIGINS || 'https://aunty-lydia-schools.vercel.app').split(',').map(s => s.trim()).filter(Boolean));
const WEBHOOK = process.env.NOTIFY_WEBHOOK_URL || '';
const SESSION_DAYS = 7;
const MAX_BODY = 20 * 1024 * 1024;      // content save can carry new photos
const MAX_IMAGE = 4 * 1024 * 1024;      // per decoded photo
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ---------- database ---------- */
const db = new DatabaseSync(path.join(DATA_DIR, 'school.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK (id = 1), salt TEXT NOT NULL, hash TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, expires INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    is_read INTEGER NOT NULL DEFAULT 0
  );
`);
const q = {
  getKV: db.prepare('SELECT value FROM kv WHERE key = ?'),
  setKV: db.prepare('INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'),
  delKV: db.prepare('DELETE FROM kv WHERE key = ?'),
  getAdmin: db.prepare('SELECT salt, hash FROM admin WHERE id = 1'),
  setAdmin: db.prepare('INSERT INTO admin (id, salt, hash) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET salt = excluded.salt, hash = excluded.hash'),
  addSession: db.prepare('INSERT INTO sessions (token, expires) VALUES (?, ?)'),
  getSession: db.prepare('SELECT expires FROM sessions WHERE token = ?'),
  delSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  delExpired: db.prepare('DELETE FROM sessions WHERE expires < ?'),
  delAllSessions: db.prepare('DELETE FROM sessions'),
  addSub: db.prepare('INSERT INTO submissions (type, data) VALUES (?, ?)'),
  listSubs: db.prepare('SELECT id, type, data, created_at, is_read FROM submissions ORDER BY id DESC LIMIT 1000'),
  listSubsByType: db.prepare('SELECT id, type, data, created_at, is_read FROM submissions WHERE type = ? ORDER BY id DESC LIMIT 1000'),
  readSub: db.prepare('UPDATE submissions SET is_read = ? WHERE id = ?'),
  delSub: db.prepare('DELETE FROM submissions WHERE id = ?'),
  unread: db.prepare('SELECT COUNT(*) AS n FROM submissions WHERE is_read = 0')
};

/* ---------- passwords & sessions ---------- */
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
function setPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  q.setAdmin.run(salt, hashPw(pw, salt));
}
function checkPassword(pw) {
  const a = q.getAdmin.get(); if (!a) return false;
  const x = Buffer.from(hashPw(String(pw), a.salt), 'hex'), y = Buffer.from(a.hash, 'hex');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
const sha = s => crypto.createHash('sha256').update(s).digest('hex');

function ensureAdmin() {
  if (q.getAdmin.get()) return;
  let pw = process.env.ADMIN_PASSWORD, generated = false;
  if (!pw || pw.length < 8) { pw = crypto.randomBytes(9).toString('base64url'); generated = true; }
  setPassword(pw);
  console.log('\n  ┌─ FIRST-TIME ADMIN PASSWORD ─────────────────────────────');
  console.log('  │  ' + pw + (generated ? '   (randomly generated: save it now)' : '   (from ADMIN_PASSWORD)'));
  console.log('  │  Log in at /admin.html, then change it under Backup & Security.');
  console.log('  └──────────────────────────────────────────────────────────\n');
}

/* CLI: node server.js reset-password NewPassword */
if (process.argv[2] === 'reset-password') {
  const pw = process.argv[3];
  if (!pw || pw.length < 8) { console.error('Usage: node server.js reset-password <at least 8 characters>'); process.exit(1); }
  setPassword(pw); q.delAllSessions.run(); console.log('Admin password reset. All sessions signed out.'); process.exit(0);
}
ensureAdmin();

/* ---------- small helpers ---------- */
const clientIp = req => (TRUST_PROXY && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress) || 'unknown';
const isHttps = req => COOKIE_SECURE || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https');

function send(res, status, body, headers = {}) {
  const isObj = body !== null && typeof body === 'object' && !Buffer.isBuffer(body);
  const payload = isObj ? JSON.stringify(body) : body;
  res.writeHead(status, Object.assign({
    'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN', 'Referrer-Policy': 'strict-origin-when-cross-origin'
  }, headers));
  res.end(payload);
}
const fail = (res, status, error) => send(res, status, { ok: false, error }, { 'Cache-Control': 'no-store' });
const ok = (res, extra) => send(res, 200, Object.assign({ ok: true }, extra), { 'Cache-Control': 'no-store' });

function readBody(req, limit = MAX_BODY) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', c => { n += c.length; if (n > limit) { reject(Object.assign(new Error('too big'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      try { resolve(n ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch (e) { reject(Object.assign(new Error('bad json'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}

/* simple in-memory rate limiter: allow(key, max, windowMs) */
const buckets = new Map();
function allow(key, max, windowMs) {
  const now = Date.now(); let b = buckets.get(key);
  if (!b || now - b.start > windowMs) b = { start: now, n: 0 };
  b.n++; buckets.set(key, b);
  return b.n <= max;
}
setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (now - b.start > 3600e3) buckets.delete(k); q.delExpired.run(now); }, 10 * 60e3).unref();

/* ---------- auth ---------- */
const parseCookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(p => p[0]));
function sessionToken(req) { return parseCookies(req).al_sid || null; }
function isAuthed(req) {
  const t = sessionToken(req); if (!t) return false;
  const s = q.getSession.get(sha(t));
  return !!s && s.expires > Date.now();
}
function cookie(req, value, maxAgeSec) {
  return `al_sid=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}` + (isHttps(req) ? '; Secure' : '');
}

/* ---------- content validation ---------- */
const GAL_CATS = ['classroom', 'sports', 'events', 'campus'];
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const id = (v, prefix) => (typeof v === 'string' && /^[\w-]{1,40}$/.test(v) ? v : prefix + crypto.randomBytes(4).toString('hex'));
const arr = (v, max = 500) => (Array.isArray(v) ? v.slice(0, max).filter(x => x && typeof x === 'object') : []);
const safeLink = v => { v = str(v, 300); return /^\s*(javascript|data|vbscript):/i.test(v) ? '' : v; };
const httpUrl = v => { v = str(v, 300); return /^https?:\/\//i.test(v) ? v : ''; };
const IMG_DATA = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/;
const IMG_PATH = /^\/?(uploads|images)\/[\w.\-]+$/;
const img = v => { v = typeof v === 'string' ? v.trim() : ''; return IMG_DATA.test(v) || IMG_PATH.test(v) || /^https?:\/\/\S{1,500}$/i.test(v) ? v : ''; };

function sanitizeContent(c) {
  c = c && typeof c === 'object' ? c : {};
  const s = c.settings || {}, a = c.announcement || {}, f = c.fees || {};
  const settings = {};
  ['phone', 'phone2', 'email', 'address', 'motto'].forEach(k => settings[k] = str(s[k], 300));
  settings.whatsapp = str(s.whatsapp, 20).replace(/\D/g, '');
  ['facebook', 'instagram', 'youtube'].forEach(k => settings[k] = httpUrl(s[k]));
  settings.popup = !!s.popup;
  return {
    settings,
    announcement: { on: !!a.on && !!str(a.text, 160), text: str(a.text, 160), link: safeLink(a.link) },
    news: arr(c.news).map(n => ({ id: id(n.id, 'n'), title: str(n.title, 200), cat: str(n.cat, 40), date: str(n.date, 10), img: img(n.img), body: str(n.body, 5000) })),
    events: arr(c.events).map(e => ({ id: id(e.id, 'e'), date: str(e.date, 60), title: str(e.title, 200), venue: str(e.venue, 200) })),
    gallery: arr(c.gallery).map(g => ({ id: id(g.id, 'g'), cat: GAL_CATS.includes(g.cat) ? g.cat : 'campus', caption: str(g.caption, 200), img: img(g.img), tall: !!g.tall })),
    staff: arr(c.staff).map(m => ({ id: id(m.id, 's'), name: str(m.name, 120), role: str(m.role, 160), photo: img(m.photo) })),
    fees: {
      rows: arr(f.rows, 50).map(r => ({ id: id(r.id, 'f'), section: str(r.section, 80), tuition: str(r.tuition, 60), other: str(r.other, 60), bus: str(r.bus, 60) })),
      notice: str(f.notice, 500), bank: str(f.bank, 1000)
    }
  };
}

/* turn pasted/uploaded data: URLs into real files under uploads/ */
function sniffExt(buf) {
  if (buf.length > 12 && buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return 'jpg';
  if (buf.length > 8 && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return 'png';
  if (buf.length > 12 && buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP') return 'webp';
  return null;
}
function saveDataUrl(v) {
  const m = IMG_DATA.exec(v); if (!m) return v;
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > MAX_IMAGE) throw Object.assign(new Error('A photo is larger than 4 MB. Please use a smaller one.'), { status: 413 });
  const ext = sniffExt(buf);
  if (!ext) throw Object.assign(new Error('One of the files is not a valid JPG, PNG or WebP image.'), { status: 400 });
  const name = sha(buf.toString('base64')).slice(0, 24) + '.' + ext;
  const file = path.join(UPLOAD_DIR, name);
  if (!fs.existsSync(file)) fs.writeFileSync(file, buf);
  return 'uploads/' + name;
}
function persistImages(c) {
  c.news.forEach(n => n.img = saveDataUrl(n.img));
  c.gallery.forEach(g => g.img = saveDataUrl(g.img));
  c.staff.forEach(m => m.photo = saveDataUrl(m.photo));
}
function cleanOrphans(c) {
  const used = new Set();
  [...c.news.map(n => n.img), ...c.gallery.map(g => g.img), ...c.staff.map(m => m.photo)].forEach(p => { if (p && /uploads\//.test(p)) used.add(path.basename(p)); });
  for (const f of fs.readdirSync(UPLOAD_DIR)) if (!used.has(f)) fs.rmSync(path.join(UPLOAD_DIR, f), { force: true });
}
const getContent = () => { const r = q.getKV.get('content'); return r ? JSON.parse(r.value) : null; };

/* ---------- public form submissions ---------- */
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
function validateContact(b) {
  const d = { name: str(b.name, 120), phone: str(b.phone, 40), email: str(b.email, 200), subject: str(b.subject, 80), message: str(b.message, 4000) };
  if (!d.name || !d.message) return ['Please enter your name and message.'];
  if (!EMAIL.test(d.email)) return ['Please enter a valid email address.'];
  return [null, d];
}
function validateAdmission(b) {
  const d = {
    childName: str(b.childName, 120), dob: str(b.dob, 10), gender: str(b.gender, 10), section: str(b.section, 40),
    parentName: str(b.parentName, 120), phone: str(b.phone, 40), email: str(b.email, 200),
    previousSchool: str(b.previousSchool, 200), address: str(b.address, 500)
  };
  if (!d.childName || !d.parentName || !d.phone) return ['Please fill in the child’s name, parent’s name and phone number.'];
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d.dob)) return ['Please enter a valid date of birth.'];
  if (d.email && !EMAIL.test(d.email)) return ['Please enter a valid email address.'];
  return [null, d];
}
async function notify(type, data) {
  if (!WEBHOOK) return;
  try { await fetch(WEBHOOK, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type, data, at: new Date().toISOString() }), signal: AbortSignal.timeout(5000) }); }
  catch (e) { console.error('Webhook failed:', e.message); }
}

/* ---------- static files ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml' };
function serveFile(req, res, file, cache) {
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return send(res, 404, 'Not found');
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream', 'Content-Length': st.size,
      'Cache-Control': cache, 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN'
    });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}
function serveStatic(req, res, pathname) {
  let p; try { p = decodeURIComponent(pathname); } catch (e) { return send(res, 400, 'Bad request'); }
  if (p.includes('\0')) return send(res, 400, 'Bad request');
  if (p === '/' ) p = '/index.html';
  if (p === '/admin') p = '/admin.html';
  if (p.startsWith('/uploads/')) {
    const f = path.join(UPLOAD_DIR, path.basename(p));
    return serveFile(req, res, f, 'public, max-age=31536000, immutable');
  }
  const file = path.resolve(SITE_ROOT, '.' + p);
  const rel = path.relative(SITE_ROOT, file);
  const top = rel.split(path.sep)[0];
  if (rel.startsWith('..') || path.isAbsolute(rel) || top === 'server' || rel.split(path.sep).some(s => s.startsWith('.'))) return send(res, 404, 'Not found');
  if (!MIME[path.extname(file).toLowerCase()]) return send(res, 404, 'Not found');
  serveFile(req, res, file, /\.(png|jpe?g|webp|svg|ico)$/i.test(file) ? 'public, max-age=86400' : 'no-cache');
}

/* ---------- router ---------- */
async function api(req, res, pathname, url) {
  const m = req.method;
  const write = m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE';

  if (write) {
    const origin = req.headers.origin;
    if (origin) { try { const parsed = new URL(origin); if (parsed.origin !== origin || (parsed.host !== req.headers.host && !ALLOWED_ORIGINS.has(parsed.origin))) return fail(res, 403, 'Cross-site request blocked.'); } catch (e) { return fail(res, 403, 'Bad origin.'); } }
    if ((m === 'POST' || m === 'PUT' || m === 'PATCH') && !/^application\/json/i.test(req.headers['content-type'] || '')) return fail(res, 415, 'JSON required.');
  }

  /* ---- public ---- */
  if (pathname === '/api/health' && m === 'GET') return ok(res);

  if (pathname === '/api/content' && m === 'GET') return send(res, 200, { ok: true, content: getContent() }, { 'Cache-Control': 'no-cache' });

  if (pathname === '/api/content.js' && m === 'GET') {
    const js = 'window.AL_CONTENT=' + JSON.stringify(getContent()).replace(/</g, '\\u003c').replace(/\u2028|\u2029/g, '') + ';';
    return send(res, 200, js, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-cache' });
  }

  if ((pathname === '/api/contact' || pathname === '/api/admissions') && m === 'POST') {
    const type = pathname === '/api/contact' ? 'contact' : 'admission';
    if (!allow('form:' + clientIp(req), 10, 3600e3)) return fail(res, 429, 'Too many submissions. Please try again later or call the school office.');
    const b = await readBody(req, 50 * 1024);
    if (b.website) return ok(res);                       // honeypot: bots fill hidden fields; pretend success
    const [err, d] = type === 'contact' ? validateContact(b) : validateAdmission(b);
    if (err) return fail(res, 400, err);
    q.addSub.run(type, JSON.stringify(d));
    notify(type, d);
    return ok(res);
  }

  /* ---- auth ---- */
  if (pathname === '/api/login' && m === 'POST') {
    const ip = clientIp(req);
    if (!allow('login:' + ip, 8, 15 * 60e3)) return fail(res, 429, 'Too many attempts. Wait 15 minutes and try again.');
    const b = await readBody(req, 4096);
    if (!checkPassword(typeof b.password === 'string' ? b.password : '')) { await new Promise(r => setTimeout(r, 400)); return fail(res, 401, 'Wrong password.'); }
    const token = crypto.randomBytes(32).toString('hex');
    q.addSession.run(sha(token), Date.now() + SESSION_DAYS * 864e5);
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookie(req, token, SESSION_DAYS * 86400), 'Cache-Control': 'no-store' });
  }
  if (pathname === '/api/logout' && m === 'POST') {
    const t = sessionToken(req); if (t) q.delSession.run(sha(t));
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookie(req, '', 0), 'Cache-Control': 'no-store' });
  }
  if (pathname === '/api/session' && m === 'GET') return ok(res, { authed: isAuthed(req) });

  /* ---- admin (everything below needs a valid session) ---- */
  if (!pathname.startsWith('/api/admin/')) return fail(res, 404, 'Not found.');
  if (!isAuthed(req)) return fail(res, 401, 'Please log in.');

  if (pathname === '/api/admin/content') {
    if (m === 'GET') return ok(res, { content: getContent(), unread: q.unread.get().n });
    if (m === 'PUT') {
      const c = sanitizeContent((await readBody(req)).content);
      persistImages(c);
      q.setKV.run('content', JSON.stringify(c));
      cleanOrphans(c);
      return ok(res, { content: c });
    }
    if (m === 'DELETE') { q.delKV.run('content'); cleanOrphans({ news: [], gallery: [], staff: [] }); return ok(res); }
  }

  if (pathname === '/api/admin/password' && m === 'POST') {
    const b = await readBody(req, 4096);
    if (!checkPassword(typeof b.current === 'string' ? b.current : '')) return fail(res, 403, 'Current password is wrong.');
    if (typeof b.password !== 'string' || b.password.length < 8) return fail(res, 400, 'New password must be at least 8 characters.');
    setPassword(b.password); q.delAllSessions.run();
    const token = crypto.randomBytes(32).toString('hex');
    q.addSession.run(sha(token), Date.now() + SESSION_DAYS * 864e5);
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookie(req, token, SESSION_DAYS * 86400), 'Cache-Control': 'no-store' });
  }

  const parse = r => ({ id: r.id, type: r.type, data: JSON.parse(r.data), created_at: r.created_at, read: !!r.is_read });
  if (pathname === '/api/admin/submissions' && m === 'GET') {
    const type = url.searchParams.get('type');
    const rows = type === 'contact' || type === 'admission' ? q.listSubsByType.all(type) : q.listSubs.all();
    return ok(res, { submissions: rows.map(parse), unread: q.unread.get().n });
  }
  if (pathname === '/api/admin/submissions.csv' && m === 'GET') {
    const rows = q.listSubs.all().map(parse);
    const cols = ['id', 'type', 'created_at', 'read', 'name', 'childName', 'dob', 'gender', 'section', 'parentName', 'phone', 'email', 'subject', 'message', 'previousSchool', 'address'];
    const esc = v => { v = v == null ? '' : String(v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; };
    const csv = [cols.join(',')].concat(rows.map(r => cols.map(c => esc(c in r ? r[c] : r.data[c])).join(','))).join('\r\n');
    return send(res, 200, '\ufeff' + csv, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="aunty-lydia-submissions.csv"', 'Cache-Control': 'no-store' });
  }
  const sm = pathname.match(/^\/api\/admin\/submissions\/(\d+)$/);
  if (sm) {
    const sid = +sm[1];
    if (m === 'PATCH') { const b = await readBody(req, 1024); q.readSub.run(b.read ? 1 : 0, sid); return ok(res, { unread: q.unread.get().n }); }
    if (m === 'DELETE') { q.delSub.run(sid); return ok(res, { unread: q.unread.get().n }); }
  }
  return fail(res, 404, 'Not found.');
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url.pathname, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
    serveStatic(req, res, url.pathname);
  } catch (e) {
    if (e.status) return fail(res, e.status, e.status === 413 ? (e.message === 'too big' ? 'Upload too large.' : e.message) : e.message === 'bad json' ? 'Invalid request.' : e.message);
    console.error(e);
    if (!res.headersSent) fail(res, 500, 'Something went wrong on the server.');
  }
});
server.requestTimeout = 60e3;

if (require.main === module) {
  server.listen(PORT, () => console.log(`Aunty Lydia Schools running at http://localhost:${PORT}  (admin: /admin.html)\nData folder: ${DATA_DIR}`));
  const stop = () => { server.close(() => { db.close(); process.exit(0); }); setTimeout(() => process.exit(0), 3000).unref(); };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
}
module.exports = { server };
