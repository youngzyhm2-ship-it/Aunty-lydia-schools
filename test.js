/* End-to-end smoke test: node test.js  (starts its own server on a temp database) */
'use strict';
const { spawn } = require('node:child_process');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const assert = require('node:assert/strict');

const PORT = 3900 + Math.floor(Math.random() * 90), BASE = `http://127.0.0.1:${PORT}`;
const DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'al-test-'));
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
let cookie = '', passed = 0;
const t = async (name, fn) => { try { await fn(); passed++; console.log('  ok  ' + name); } catch (e) { console.error('FAIL  ' + name + '\n      ' + e.message); process.exitCode = 1; } };
const call = async (method, url, body, extra = {}) => {
  const r = await fetch(BASE + url, { method, redirect: 'manual', headers: Object.assign({ cookie, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) }, extra), body: body !== undefined ? JSON.stringify(body) : undefined });
  const sc = r.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0].replace(/^al_sid=$/, '');
  const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch (e) {}
  return { status: r.status, json, text, headers: r.headers };
};

(async () => {
  const srv = spawn(process.execPath, [path.join(__dirname, 'server.js')], { env: { ...process.env, PORT, DATA_DIR: DATA, ADMIN_PASSWORD: 'test-pass-123' }, stdio: ['ignore', 'pipe', 'inherit'] });
  for (let i = 0; i < 50; i++) { try { if ((await fetch(BASE + '/api/health')).ok) break; } catch (e) { await new Promise(r => setTimeout(r, 100)); } }

  await t('health', async () => assert.equal((await call('GET', '/api/health')).json.ok, true));
  await t('site pages are served', async () => { const r = await call('GET', '/'); assert.equal(r.status, 200); assert.match(r.text, /Aunty Lydia/); assert.equal((await call('GET', '/css/style.css')).status, 200); assert.equal((await call('GET', '/images/logo.png')).status, 200); });
  await t('server code / dotfiles / traversal are NOT served', async () => {
    for (const p of ['/server/server.js', '/server/.env', '/server/data/school.db', '/%2e%2e/server/server.js', '/..%2fserver%2fserver.js', '/.git/config']) assert.equal((await call('GET', p)).status, 404, p);
  });
  await t('content.js is null before any save', async () => assert.equal((await call('GET', '/api/content.js')).text, 'window.AL_CONTENT=null;'));
  await t('admin API needs login', async () => { assert.equal((await call('GET', '/api/admin/content')).status, 401); assert.equal((await call('PUT', '/api/admin/content', { content: {} })).status, 401); assert.equal((await call('GET', '/api/admin/submissions')).status, 401); });
  await t('wrong password rejected', async () => assert.equal((await call('POST', '/api/login', { password: 'nope' })).status, 401));
  await t('login works + session cookie is HttpOnly/SameSite', async () => {
    const r = await call('POST', '/api/login', { password: 'test-pass-123' });
    assert.equal(r.status, 200); const sc = r.headers.get('set-cookie'); assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Strict/);
    assert.equal((await call('GET', '/api/session')).json.authed, true);
  });
  await t('cross-site write is blocked', async () => assert.equal((await call('POST', '/api/admin/password', {}, { Origin: 'https://evil.example' })).status, 403));
  await t('non-JSON write is rejected', async () => { const r = await fetch(BASE + '/api/admin/content', { method: 'PUT', headers: { cookie, 'Content-Type': 'text/plain' }, body: '{}' }); assert.equal(r.status, 415); });

  let uploaded;
  await t('save content: sanitised, data-URL photo becomes a file', async () => {
    const r = await call('PUT', '/api/admin/content', { content: {
      settings: { phone: '0800', whatsapp: '+234 80-1', facebook: 'javascript:alert(1)', popup: false, evil: 'x' },
      announcement: { on: true, text: 'Resume Monday', link: 'javascript:alert(1)' },
      news: [{ id: 'n1', title: '<b>Hi</b>', cat: 'Sports', date: '2026-10', img: PNG, body: 'x' }],
      events: [], gallery: [{ id: 'g1', cat: 'bogus', caption: 'c', img: '', tall: 1 }], staff: [{ id: 's1', name: 'A', role: 'B', photo: 'javascript:1' }],
      fees: { rows: [{ id: 'f1', section: 'Nursery', tuition: '₦1', other: '', bus: '' }], notice: 'n', bank: 'b' }
    } });
    assert.equal(r.status, 200); const c = r.json.content;
    assert.match(c.news[0].img, /^uploads\/[a-f0-9]{24}\.png$/); uploaded = c.news[0].img;
    assert.equal(c.settings.facebook, ''); assert.equal(c.settings.whatsapp, '234801'); assert.equal(c.settings.evil, undefined);
    assert.equal(c.announcement.link, ''); assert.equal(c.gallery[0].cat, 'campus'); assert.equal(c.staff[0].photo, '');
  });
  await t('uploaded photo is served publicly with correct type', async () => { const r = await call('GET', '/' + uploaded); assert.equal(r.status, 200); assert.equal(r.headers.get('content-type'), 'image/png'); });
  await t('public content.js now carries saved content, `<` escaped', async () => { const r = await call('GET', '/api/content.js'); assert.match(r.text, /Resume Monday/); assert.ok(!r.text.includes('<b>')); });
  await t('fake image bytes are refused', async () => { const r = await call('PUT', '/api/admin/content', { content: { news: [{ id: 'n1', title: 't', img: 'data:image/png;base64,' + Buffer.from('<script>alert(1)</script>').toString('base64') }] } }); assert.equal(r.status, 400); });
  await t('removing a photo deletes the orphaned file', async () => {
    await call('PUT', '/api/admin/content', { content: { news: [{ id: 'n1', title: 't', img: '' }] } });
    assert.equal(fs.readdirSync(path.join(DATA, 'uploads')).length, 0); assert.equal((await call('GET', '/' + uploaded)).status, 404);
  });

  await t('contact form: validation, honeypot, success', async () => {
    assert.equal((await call('POST', '/api/contact', { name: 'A', email: 'bad', message: 'x' })).status, 400);
    assert.equal((await call('POST', '/api/contact', { name: 'Ada', email: 'ada@example.com', phone: '080', subject: 'School fees', message: 'How much?' })).status, 200);
    assert.equal((await call('POST', '/api/contact', { name: 'Bot', email: 'b@example.com', message: 'spam', website: 'http://spam' })).status, 200);   // silently dropped
  });
  await t('admission form: validation + success', async () => {
    assert.equal((await call('POST', '/api/admissions', { childName: 'Ben', parentName: 'P', phone: '1', dob: 'tomorrow' })).status, 400);
    assert.equal((await call('POST', '/api/admissions', { childName: 'Ben Obi', dob: '2021-05-04', gender: 'Male', section: 'Nursery', parentName: 'Mrs Obi', phone: '0803', email: '', previousSchool: '', address: 'Aba' })).status, 200);
  });
  await t('inbox lists real submissions only, read/unread/delete work', async () => {
    let r = await call('GET', '/api/admin/submissions'); assert.equal(r.json.submissions.length, 2); assert.equal(r.json.unread, 2);
    const id = r.json.submissions[0].id;
    r = await call('PATCH', '/api/admin/submissions/' + id, { read: true }); assert.equal(r.json.unread, 1);
    r = await call('DELETE', '/api/admin/submissions/' + id); assert.equal(r.json.unread, 1);
    assert.equal((await call('GET', '/api/admin/submissions')).json.submissions.length, 1);
  });
  await t('CSV export neutralises formula injection', async () => {
    await call('POST', '/api/contact', { name: '=HYPERLINK("x")', email: 'a@b.co', message: 'm' });
    const r = await call('GET', '/api/admin/submissions.csv'); assert.match(r.headers.get('content-type'), /csv/); assert.match(r.text, /"'=HYPERLINK/);
  });
  await t('change password: old rejected, new works, old sessions die', async () => {
    assert.equal((await call('POST', '/api/admin/password', { current: 'wrong', password: 'brand-new-pass' })).status, 403);
    assert.equal((await call('POST', '/api/admin/password', { current: 'test-pass-123', password: 'short' })).status, 400);
    assert.equal((await call('POST', '/api/admin/password', { current: 'test-pass-123', password: 'brand-new-pass' })).status, 200);
    assert.equal((await call('GET', '/api/session')).json.authed, true);   // fresh session issued
    const old = cookie; await call('POST', '/api/logout', {}); cookie = old;
    assert.equal((await call('GET', '/api/session')).json.authed, false); cookie = '';
    assert.equal((await call('POST', '/api/login', { password: 'test-pass-123' })).status, 401);
    assert.equal((await call('POST', '/api/login', { password: 'brand-new-pass' })).status, 200);
  });
  await t('reset content returns to defaults', async () => { assert.equal((await call('DELETE', '/api/admin/content')).status, 200); assert.equal((await call('GET', '/api/content.js')).text, 'window.AL_CONTENT=null;'); });
  await t('login is rate-limited', async () => { cookie = ''; let last; for (let i = 0; i < 10; i++) last = await call('POST', '/api/login', { password: 'x' + i }); assert.equal(last.status, 429); });

  srv.kill('SIGTERM'); fs.rmSync(DATA, { recursive: true, force: true });
  console.log(`\n${passed} passed` + (process.exitCode ? ', some FAILED' : ', all good'));
})();
