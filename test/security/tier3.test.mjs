// Tier 3 wave 1 security regressions (Raymond): API keys, webhooks (SSRF, HMAC, payload), folders, bulk send, public template link.
// Run against FRESH disposable servers (ALLOW_SIGNUP=true, SIGNUP_MAX_PER_HOUR=1000, explicit ENCRYPTION_KEY, no TRUST_PROXY):
//   Server A: WEBHOOK_ALLOW_PRIVATE=true WEBHOOK_ALLOW_HTTP=true (local receiver tests)
//   Server B (optional): default webhook settings (SSRF default-off tests)
//   BASE_URL=http://localhost:<A> BASE_URL_DEFAULTS=http://localhost:<B> DATA_DIR=<A's DATA_DIR> ENCRYPTION_KEY=<A's key> \
//     WEBHOOK_ALLOW_PRIVATE=true node --test test/security/tier3.test.mjs
// Without DATA_DIR/ENCRYPTION_KEY the at-rest checks skip; without BASE_URL_DEFAULTS the default-off checks skip; the receiver
// tests skip unless WEBHOOK_ALLOW_PRIVATE=true is also set in this env (mirroring server A).
// The T3-03 mail test needs SMTP_HOST, APP_URL and QA_SMTP_SINK_PORT in this env (server A: SMTP_HOST=127.0.0.1
// SMTP_PORT=<sink> APP_URL=<BASE_URL>); it starts its own capturing sink on that port. Without them it skips.
// Expects a build that includes the 2026-11-03 Tier 3 fix round (T3-02..T3-10, cap 50/day, bulk Idempotency-Key and limit).
// Budgets: the public-link tests spend this client IP's 10 public-link requests per hour on server A (the IP rate-limit test
// runs last). Bulk sends are limited to 10 per hour per user, counted before validation: each test uses its own users.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import zlib from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';

const BASE = new URL(process.env.BASE_URL || 'http://localhost:3000');
const DEFAULTS = process.env.BASE_URL_DEFAULTS ? new URL(process.env.BASE_URL_DEFAULTS) : null;
const DATA_DIR = process.env.DATA_DIR;
const KEY = process.env.ENCRYPTION_KEY;
const needDb = !(DATA_DIR && KEY) && 'needs DATA_DIR and ENCRYPTION_KEY of server A';
const needDefaults = !DEFAULTS && 'needs BASE_URL_DEFAULTS (a server with default WEBHOOK_* settings)';
const needMail = !(process.env.SMTP_HOST && process.env.APP_URL && process.env.QA_SMTP_SINK_PORT)
  && 'needs SMTP_HOST, APP_URL and QA_SMTP_SINK_PORT (server SMTP_HOST=127.0.0.1 SMTP_PORT=<sink> APP_URL=<BASE_URL>)';
const needReceiver = process.env.WEBHOOK_ALLOW_PRIVATE !== 'true' && 'needs WEBHOOK_ALLOW_PRIVATE=true (server A started with WEBHOOK_ALLOW_PRIVATE=true WEBHOOK_ALLOW_HTTP=true)';
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const rnd = () => crypto.randomBytes(5).toString('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let _db;
const db = () => {
  if (!_db) { _db = new DatabaseSync(path.join(DATA_DIR, 'countersign.db')); _db.exec('PRAGMA busy_timeout = 5000'); }
  return _db;
};
const keyBytes = () => (/^[0-9a-fA-F]{64}$/.test(KEY.trim()) ? Buffer.from(KEY.trim(), 'hex') : Buffer.from(KEY.trim(), 'base64'));
const keyedHash = (info, data) => crypto.createHmac('sha256', Buffer.from(crypto.hkdfSync('sha256', keyBytes(), Buffer.alloc(0), 'countersign-' + info, 32))).update(data).digest('hex');

function png() {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(zlib.crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(1, 0); ihdr.writeUInt32BE(1, 4); ihdr[8] = 8; ihdr[9] = 2;
  const bytes = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(Buffer.from([0, 7, 7, 7]))), chunk('IEND', Buffer.alloc(0))]);
  return `data:image/png;base64,${bytes.toString('base64')}`;
}
const PNG = png();

function call(p, { method = 'GET', cookie, body, headers = {}, base = BASE } = {}) {
  const h = { ...headers };
  if (cookie) h.cookie = cookie;
  let b = body;
  if (b !== undefined && !Buffer.isBuffer(b) && typeof b !== 'string') { b = JSON.stringify(b); h['content-type'] ??= 'application/json'; }
  return new Promise((resolve, reject) => {
    const req = http.request({ host: base.hostname === 'localhost' ? '127.0.0.1' : base.hostname, port: base.port, path: p, method, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        let json; try { json = JSON.parse(buf.toString()); } catch {}
        resolve({ status: res.statusCode, headers: res.headers, json, text: buf.toString('utf8'), setCookie: res.headers['set-cookie'] || [] });
      });
    });
    req.on('error', reject);
    req.end(b);
  });
}
const bearer = (key) => ({ authorization: `Bearer ${key}` });
const props = (html) => JSON.parse(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s.exec(html)[1]).props.pageProps;

async function signup(base = BASE, name = 'T3 Owner') {
  const email = `t3-${rnd()}@example.com`;
  const r = await call('/api/auth/signup', { method: 'POST', base, body: { name, email, password: `pw-${rnd()}-${rnd()}` } });
  assert.equal(r.status, 200, r.text);
  return { email, name, base, cookie: r.setCookie.find((c) => c.startsWith('cs_session=')).split(';')[0] };
}
async function pdfBytes() {
  const pdf = await PDFDocument.create();
  pdf.addPage([612, 792]).drawText(`t3 ${rnd()}`, { x: 50, y: 700 });
  return Buffer.from(await pdf.save({ useObjectStreams: false }));
}
const sigF = (rid) => ({ recipientId: rid, type: 'signature', page: 0, x: 0.1, y: 0.1, w: 0.3, h: 0.06 });
async function upload(o, template = false) {
  const up = await call('/api/documents', { method: 'POST', cookie: o.cookie, body: await pdfBytes(), headers: { 'content-type': 'application/pdf', 'x-file-name': 'T3.pdf', ...(template && { 'x-template': '1' }) } });
  assert.equal(up.status, 201, up.text);
  return up.json.id;
}
const save = (o, id, body) => call(`/api/documents/${id}`, { method: 'PUT', cookie: o.cookie, body: { title: 'T3', ...body } });
const action = (o, id, name, body = {}, headers = {}) => call(`/api/documents/${id}/${name}`, { method: 'POST', cookie: o.cookie, body, headers });
// Template with `roles` signer roles, one signature field each.
async function template(o, roles = 1, title = 'T3 template') {
  const id = await upload(o, true);
  const recipients = Array.from({ length: roles }, (_, i) => ({ id: `r${i}`, name: `Role ${i + 1}`, email: '', role: 'signer', routingOrder: 1 }));
  const put = await save(o, id, { title, recipients, fields: recipients.map((r) => sigF(r.id)) });
  assert.equal(put.status, 200, put.text);
  return id;
}
async function draft(o, email) {
  const id = await upload(o);
  const put = await save(o, id, { recipients: [{ id: 'a', name: 'Signer One', email, role: 'signer' }], fields: [sigF('a')] });
  assert.equal(put.status, 200, put.text);
  return { id, sigId: put.json.fields[0].id };
}
const docCount = async (o, q = '') => (await call(`/api/documents?limit=1${q}`, { cookie: o.cookie })).json.total;
async function newKey(o, name = 'k') {
  const r = await call('/api/api-keys', { method: 'POST', cookie: o.cookie, body: { name } });
  assert.equal(r.status, 201, r.text);
  return r.json;
}

// ---------- API keys ----------

test('API key: shown once, stored only as keyed hash, works on document routes, revocation is immediate', { skip: needDb }, async () => {
  const a = await signup();
  const { id, key } = await newKey(a);
  assert.match(key, /^cs_[A-Za-z0-9_-]{43}$/);
  const row = db().prepare('SELECT * FROM api_keys WHERE id = ?').get(id);
  assert.equal(row.key_hash, keyedHash('apikey', key));
  assert.equal(Object.values(row).some((v) => typeof v === 'string' && v.includes(key.slice(10))), false, 'no column holds the key');
  assert.equal(row.prefix, key.slice(0, 10));
  const list = await call('/api/api-keys', { cookie: a.cookie });
  assert.equal(list.text.includes(key.slice(10)), false, 'list never returns the key');
  assert.equal((await call('/api/documents', { headers: bearer(key) })).status, 200);
  assert.equal((await call('/api/documents', { headers: { authorization: `bearer ${key}` } })).status, 200, 'scheme is case-insensitive');
  assert.equal((await call(`/api/api-keys/${id}`, { method: 'DELETE', cookie: a.cookie })).status, 200);
  const after = await call('/api/documents', { headers: bearer(key) });
  assert.deepEqual([after.status, after.json.error], [401, 'Invalid API key']);
});

test('API key: refused on account, auth, key, webhook, contacts, signatures and signing routes, even when valid', async () => {
  const a = await signup();
  const { id, key } = await newKey(a);
  const routes = [['PATCH', '/api/account'], ['GET', '/api/api-keys'], ['POST', '/api/api-keys'], ['DELETE', `/api/api-keys/${id}`],
    ['GET', '/api/webhooks'], ['POST', '/api/webhooks'], ['GET', '/api/auth/session'], ['POST', '/api/auth/logout'], ['POST', '/api/auth/logout-all'],
    ['POST', '/api/auth/login'], ['POST', '/api/auth/signup'], ['GET', '/api/contacts'], ['GET', '/api/signatures'], ['GET', '/api/email-templates'],
    ['POST', '/api/sign/xyz'], ['POST', '/api/public-templates/xyz'], ['GET', '/api/verify?hash=00']];
  for (const [method, p] of routes) {
    const r = await call(p, { method, cookie: a.cookie, headers: bearer(key), body: method === 'GET' || method === 'DELETE' ? undefined : {} });
    assert.deepEqual([r.status, r.json?.error], [401, 'API keys cannot be used here'], `${method} ${p}`);
  }
  // The refused logout/key-delete did nothing: the session and the key both still work.
  assert.equal((await call('/api/auth/session', { cookie: a.cookie })).json.user?.email, a.email);
  assert.equal((await call('/api/documents', { headers: bearer(key) })).status, 200);
});

test('API key: origin check is skipped only with a valid key; a session cookie is never consulted on the bearer path', async () => {
  const a = await signup(), b = await signup();
  const { key } = await newKey(a);
  const doc = await upload(a);
  const folder = (await call('/api/folders', { method: 'POST', cookie: a.cookie, body: { name: `f-${rnd()}` } })).json.id;
  const evil = { origin: 'https://evil.example' };
  // Session + foreign Origin: blocked.
  assert.equal((await action(a, doc, 'move', { folderId: folder }, evil)).status, 403);
  // Invalid key + foreign Origin + valid cookie: 401, nothing moved.
  const bad = await call(`/api/documents/${doc}/move`, { method: 'POST', cookie: a.cookie, body: { folderId: folder }, headers: { ...evil, ...bearer(`cs_${'A'.repeat(43)}`) } });
  assert.deepEqual([bad.status, bad.json.error], [401, 'Invalid API key']);
  for (const h of ['Bearer', 'Bearer ', 'Bearer cs_short', `Bearer ${key} extra`, `Bearer ${key.slice(0, -1)}!`]) {
    assert.equal((await call('/api/documents', { headers: { authorization: h } })).status, 401, h);
  }
  assert.equal((await call(`/api/documents/${doc}`, { cookie: a.cookie })).json.doc.folder_id, null);
  // Valid key + foreign Origin: allowed (no cookies involved, so no CSRF).
  assert.equal((await call(`/api/documents/${doc}/move`, { method: 'POST', body: { folderId: folder }, headers: { ...evil, ...bearer(key) } })).status, 200);
  assert.equal((await call(`/api/documents/${doc}`, { cookie: a.cookie })).json.doc.folder_id, folder);
  // Key of A with B's cookie acts as A only.
  const asA = await call('/api/documents', { cookie: b.cookie, headers: bearer(key) });
  assert.deepEqual(asA.json.documents.map((d) => d.id), [doc]);
  // A's key cannot reach B's documents.
  const bDoc = await upload(b);
  for (const [m, p] of [['GET', `/api/documents/${bDoc}`], ['GET', `/api/documents/${bDoc}/file`], ['DELETE', `/api/documents/${bDoc}`], ['POST', `/api/documents/${bDoc}/copy`]]) {
    assert.equal((await call(p, { method: m, headers: bearer(key), body: m === 'POST' ? {} : undefined })).status, 404, `${m} ${p}`);
  }
});

test('API key: 600 requests per hour per key, then 429 with Retry-After', { skip: needDb }, async () => {
  const a = await signup();
  const { id, key } = await newKey(a);
  db().prepare('INSERT INTO login_attempts (key, window_start, count, locked_until) VALUES (?, ?, 599, NULL)').run(`apikey:${id}`, new Date().toISOString());
  assert.equal((await call('/api/documents', { headers: bearer(key) })).status, 200, '600th request is allowed');
  const r = await call('/api/documents', { headers: bearer(key) });
  assert.equal(r.status, 429);
  assert.ok(Number(r.headers['retry-after']) > 3000, r.headers['retry-after']);
  // Another key of the same user is not affected.
  assert.equal((await call('/api/documents', { headers: bearer((await newKey(a, 'k2')).key) })).status, 200);
});

test('API key: GET /api/documents is owner-scoped and clamps limit/offset', async () => {
  const a = await signup(), b = await signup();
  await upload(b);
  const { key } = await newKey(a);
  const r = await call('/api/documents?limit=100000&offset=-5&status=x%27%20OR%201=1--', { headers: bearer(key) });
  assert.deepEqual([r.status, r.json.total, r.json.documents.length], [200, 0, 0]);
  await upload(a);
  assert.equal((await call('/api/documents?limit=100000&offset=-5', { headers: bearer(key) })).json.total, 1);
});

test('GET /api/documents/[id]: no token hashes, ciphertexts or OTP data; public token only as the owner URL', async () => {
  const a = await signup();
  const t = await template(a);
  const url = (await action(a, t, 'public', { enabled: true })).json.url;
  const d = await draft(a, `s-${rnd()}@example.com`);
  assert.equal((await action(a, d.id, 'send')).status, 200);
  for (const id of [t, d.id]) {
    const r = await call(`/api/documents/${id}`, { cookie: a.cookie });
    assert.equal(r.headers['cache-control'], 'private, no-store');
    for (const k of ['public_token_hash', 'public_token_enc']) assert.equal(k in r.json.doc, false, k);
    for (const rec of r.json.recipients) for (const k of ['token_hash', 'token_enc', 'otp_hash', 'otp_session_hash']) assert.equal(k in rec, false, k);
  }
  assert.equal((await call(`/api/documents/${t}`, { cookie: a.cookie })).json.publicUrl, url);
});

test('T3-04: GET /api/documents/[id] gives signer tokens to the session owner only, never to an API key', async () => {
  const a = await signup();
  const { key } = await newKey(a);
  const d = await draft(a, `s-${rnd()}@example.com`);
  assert.equal((await action(a, d.id, 'send')).status, 200);
  const viaKey = await call(`/api/documents/${d.id}`, { headers: bearer(key) });
  assert.equal(viaKey.status, 200);
  assert.equal(viaKey.json.recipients.length, 1);
  assert.equal(viaKey.json.recipients.some((x) => 'token' in x), false, 'an API key could impersonate signers with these tokens');
  const viaSession = await call(`/api/documents/${d.id}`, { cookie: a.cookie });
  assert.match(viaSession.json.recipients[0].token || '', /^[A-Za-z0-9_-]{20,}$/, 'the owner still gets the link to copy');
  // The key's response holds no token value anywhere.
  assert.equal(viaKey.text.includes(viaSession.json.recipients[0].token), false);
});

// ---------- Folders, move, bulk, public: IDOR ----------

test('folders: another user cannot rename, delete, list, filter by or move into them; deleting unfiles', async () => {
  const a = await signup(), b = await signup();
  const fa = (await call('/api/folders', { method: 'POST', cookie: a.cookie, body: { name: 'Private A' } })).json.id;
  const docA = await upload(a);
  assert.equal((await action(a, docA, 'move', { folderId: fa })).status, 200);
  assert.equal((await call(`/api/folders/${fa}`, { method: 'PUT', cookie: b.cookie, body: { name: 'pwned' } })).status, 404);
  assert.equal((await call(`/api/folders/${fa}`, { method: 'DELETE', cookie: b.cookie })).status, 404);
  assert.deepEqual((await call('/api/folders', { cookie: b.cookie })).json.folders, []);
  assert.equal((await call(`/api/documents?folder=${fa}`, { cookie: b.cookie })).json.total, 0);
  const docB = await upload(b);
  assert.equal((await action(b, docB, 'move', { folderId: fa })).status, 404, "B can't file into A's folder");
  assert.equal((await action(b, docA, 'move', { folderId: null })).status, 404, "B can't unfile A's document");
  for (const v of [{ folderId: 1 }, { folderId: ['x'] }, { folderId: { a: 1 } }]) assert.equal((await action(a, docA, 'move', v)).status, 404, JSON.stringify(v));
  assert.deepEqual((await call('/api/folders', { cookie: a.cookie })).json.folders, [{ id: fa, name: 'Private A', count: 1 }]);
  assert.equal((await call(`/api/folders/${fa}`, { method: 'DELETE', cookie: a.cookie })).status, 200);
  const after = await call(`/api/documents/${docA}`, { cookie: a.cookie });
  assert.deepEqual([after.status, after.json.doc.folder_id], [200, null]);
});

test('bulk and public actions: 404 on another user\'s template, nothing created', async () => {
  const a = await signup(), b = await signup();
  const t = await template(a);
  const before = await docCount(a);
  const bulk = await action(b, t, 'bulk', { rows: [[{ name: 'X', email: 'x@example.com' }]] });
  const csv = await call(`/api/documents/${t}/bulk`, { method: 'POST', cookie: b.cookie, body: 'X,x@example.com\n', headers: { 'content-type': 'text/csv' } });
  const pub = await action(b, t, 'public', { enabled: true });
  assert.deepEqual([bulk.status, csv.status, pub.status], [404, 404, 404]);
  assert.equal(await docCount(a), before);
  assert.equal(await docCount(b), 0);
  assert.equal((await call(`/api/documents/${t}`, { cookie: a.cookie })).json.publicUrl, null);
});

// ---------- Bulk send limits ----------

test('bulk send: all rows validated before anything is created; row, size and type limits', async () => {
  const a = await signup();
  const t = await template(a, 2);
  const ok = (i) => [{ name: `A${i}`, email: `a${i}-${rnd()}@example.com` }, { name: `B${i}`, email: `b${i}-${rnd()}@example.com` }];
  const before = await docCount(a);
  const cases = [
    [{ rows: Array.from({ length: 501 }, (_, i) => ok(i)) }, 400, /up to 500 rows/],
    [{ rows: [ok(1), [{ name: 'A', email: 'nope' }, { name: 'B', email: 'b@example.com' }]] }, 400, /^Row 2:/],
    [{ rows: [ok(1), ok(2), [{ name: 'A', email: 'same@example.com' }, { name: 'B', email: 'SAME@example.com' }]] }, 400, /^Row 3:.*different email/],
    [{ rows: [[{ name: 'A', email: 'a@example.com' }]] }, 400, /^Row 1:/],
    [{ rows: [ok(1).map((p) => ({ ...p, name: 'x'.repeat(201) }))] }, 400, /^Row 1:/],
    [{ rows: [ok(1).map((p, i) => ({ ...p, email: `a${i}@x.com\r\nBcc: v@example.com` }))] }, 400, /^Row 1:/],
    [{ rows: 'a,b' }, 400, /at least one row/],
    [{}, 400, /at least one row/],
  ];
  for (const [body, status, msg] of cases) {
    const r = await action(a, t, 'bulk', body);
    assert.equal(r.status, status, r.text);
    assert.match(r.json.error, msg);
  }
  const big = await call(`/api/documents/${t}/bulk`, { method: 'POST', cookie: a.cookie, body: Buffer.alloc(1048577, 'a'), headers: { 'content-type': 'text/csv' } });
  assert.equal(big.status, 413);
  assert.equal(await docCount(a), before, 'nothing was created');
  // Non-template checks on another user, so this test stays under 10 bulk sends per hour per user (the 413 above is not
  // counted: the body is read before the action runs).
  const c = await signup();
  const notTpl = await draft(c, `s-${rnd()}@example.com`);
  assert.equal((await action(c, notTpl.id, 'bulk', { rows: [ok(1)] })).status, 409);
  assert.equal((await call(`/api/documents/${notTpl.id}/bulk`, { method: 'POST', cookie: c.cookie, body: 'A,a@x.com,B,b@x.com\n', headers: { 'content-type': 'text/csv' } })).status, 409);
  assert.equal(await docCount(c), 1, 'only the draft was created');
  const good = await action(a, t, 'bulk', { rows: [ok(1), ok(2)] });
  assert.equal(good.status, 201, good.text);
  assert.deepEqual([good.json.created, good.json.failed], [2, []]);
  for (const id of good.json.documentIds) assert.equal((await call(`/api/documents/${id}`, { cookie: a.cookie })).json.doc.bulk_id, good.json.bulkId);
});

// ---------- Public template link ----------

let ipBudgetUsed = 0; // POSTs to /api/public-templates from this IP that reached the limiter
const publicPost = (token, body, headers = {}) => { ipBudgetUsed++; return call(`/api/public-templates/${encodeURIComponent(token)}`, { method: 'POST', body, headers }); };
const tokenOf = (url) => url.replace(/^\/t\//, '');

test('public link: token stored hashed + encrypted, rotation and disable kill old links, rule change disables, unknown = disabled', { skip: needDb }, async () => {
  const a = await signup();
  const t = await template(a);
  assert.deepEqual((await action(a, (await draft(a, `s-${rnd()}@example.com`)).id, 'public', { enabled: true })).json, { error: 'Only templates can have a public link' });
  const t2 = await template(a, 2);
  assert.equal((await action(a, t2, 'public', { enabled: true })).status, 400);
  const first = (await action(a, t, 'public', { enabled: true })).json.url;
  assert.match(first, /^\/t\/[A-Za-z0-9_-]{43}$/);
  const row = db().prepare('SELECT public_token_hash, public_token_enc FROM documents WHERE id = ?').get(t);
  assert.equal(row.public_token_hash, sha(tokenOf(first)));
  assert.equal(row.public_token_enc.includes(tokenOf(first)), false);
  assert.equal((await call(first)).status, 200);
  const second = (await action(a, t, 'public', { enabled: true })).json.url;
  assert.notEqual(second, first);
  const unknown = await call(`/t/${crypto.randomBytes(32).toString('base64url')}`);
  const old = await call(first);
  assert.deepEqual([old.status, unknown.status], [404, 404]);
  assert.deepEqual(props(old.text), props(unknown.text), 'a rotated link looks exactly like one that never existed');
  const oldPost = await publicPost(tokenOf(first), { name: 'V', email: 'v@example.com' });
  assert.deepEqual([oldPost.status, oldPost.json.error], [404, 'This link is not active']);
  assert.deepEqual((await action(a, t, 'public', { enabled: false })).json, { ok: true });
  assert.equal((await call(second)).status, 404);
  assert.equal(db().prepare('SELECT public_token_hash FROM documents WHERE id = ?').get(t).public_token_hash, null);
  // Saving the template with a second signer turns the link off.
  const third = (await action(a, t, 'public', { enabled: true })).json.url;
  const put = await save(a, t, { recipients: [{ id: 'x', name: 'R1', email: '', role: 'signer' }, { id: 'y', name: 'R2', email: '', role: 'signer' }], fields: [sigF('x'), sigF('y')] });
  assert.equal(put.status, 200, put.text);
  assert.equal((await call(third)).status, 404);
  assert.equal((await call(`/api/documents/${t}`, { cookie: a.cookie })).json.publicUrl, null);
});

test('public link: page exposes only title, owner name, OTP flag and page count; title is escaped', async () => {
  const a = await signup(BASE, 'Owner <b>Name</b>');
  const evilTitle = '</script><script>alert(1)</script><img src=x onerror=alert(2)>';
  const t = await template(a, 1, evilTitle);
  const url = (await action(a, t, 'public', { enabled: true })).json.url;
  const page = await call(url);
  assert.equal(page.status, 200);
  const p = props(page.text);
  assert.deepEqual(Object.keys(p.tpl).sort(), ['ownerName', 'pageCount', 'requireOtp', 'title']);
  assert.equal(p.tpl.title, evilTitle);
  assert.equal(page.text.includes('<script>alert(1)'), false);
  assert.equal(page.text.includes('<img src=x'), false);
  assert.equal(page.text.includes('<b>Name</b>'), false);
  assert.equal(page.text.includes(a.email), false, 'owner email not on the public page');
  assert.equal(page.text.includes(t), false, 'template id not on the public page');
});

test('public link: honeypot creates nothing; success gives only a signUrl; cross-origin POST blocked; per-template cap', { skip: needDb }, async () => {
  const a = await signup();
  const t = await template(a);
  const tok = tokenOf((await action(a, t, 'public', { enabled: true })).json.url);
  const before = await docCount(a);
  const cross = await call(`/api/public-templates/${tok}`, { method: 'POST', body: { name: 'V', email: 'v@example.com' }, headers: { origin: 'https://evil.example' } });
  assert.equal(cross.status, 403);
  const hp = await publicPost(tok, { name: 'Bot', email: 'bot@example.com', website: 'http://spam.example' });
  assert.deepEqual([hp.status, hp.json], [200, { ok: true }]);
  assert.equal(await docCount(a), before, 'honeypot submission created nothing');
  const ok = await publicPost(tok, { name: 'Visitor', email: `v-${rnd()}@example.com` });
  assert.equal(ok.status, 200, ok.text);
  assert.deepEqual(Object.keys(ok.json), ['signUrl']);
  assert.match(ok.json.signUrl, /^\/sign\/[A-Za-z0-9_-]+$/);
  assert.equal(await docCount(a), before + 1);
  // The per-template cap is keyed on sha256(token) (T3-10) and answers 429 once reached.
  db().prepare(`INSERT INTO login_attempts (key, window_start, count, locked_until) VALUES (?, ?, 50, ?)
    ON CONFLICT(key) DO UPDATE SET count = 50, locked_until = excluded.locked_until`).run(`publictpl:${sha(tok)}`, new Date().toISOString(), new Date(Date.now() + 864e5).toISOString());
  const capped = await publicPost(tok, { name: 'Visitor', email: `v-${rnd()}@example.com` });
  assert.equal(capped.status, 429);
  assert.ok(Number(capped.headers['retry-after']) > 0);
  assert.equal(await docCount(a), before + 1);
  // T3-10: rotating the link starts a fresh budget; the old token's exhausted counter does not carry over.
  const fresh = tokenOf((await action(a, t, 'public', { enabled: true })).json.url);
  assert.notEqual(fresh, tok);
  const after = await publicPost(fresh, { name: 'Visitor', email: `v-${rnd()}@example.com` });
  assert.equal(after.status, 200, after.text);
  assert.equal(await docCount(a), before + 2);
  assert.equal(db().prepare('SELECT count FROM login_attempts WHERE key = ?').get(`publictpl:${sha(fresh)}`)?.count, 1);
});

// ---------- Webhooks ----------

function receiver(handler = (req, res) => res.end('ok')) {
  const got = [];
  let open = 0, maxOpen = 0;
  const server = http.createServer((req, res) => {
    open++; maxOpen = Math.max(maxOpen, open);
    res.on('close', () => { open--; });
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => { got.push({ headers: req.headers, body: Buffer.concat(chunks).toString('utf8'), path: req.url }); handler(req, res); });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    got, url: (p = '/hook') => `http://127.0.0.1:${server.address().port}${p}`, maxOpen: () => maxOpen, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
  })));
}
async function until(fn, ms = 8000) {
  const end = Date.now() + ms;
  for (;;) { const v = await fn(); if (v) return v; if (Date.now() > end) return v; await sleep(100); }
}
const verifySig = (secret, header, body) => {
  const m = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(header || '');
  if (!m) return false;
  const want = crypto.createHmac('sha256', secret).update(`${m[1]}.${body}`).digest();
  return crypto.timingSafeEqual(want, Buffer.from(m[2], 'hex')) && Math.abs(Date.now() / 1000 - Number(m[1])) < 300;
};
const hook = (o, url, events, base = BASE) => call('/api/webhooks', { method: 'POST', cookie: o.cookie, base, body: { url, events } });
const deliveries = async (o, id, base = BASE) => (await call(`/api/webhooks/${id}/deliveries`, { cookie: o.cookie, base })).json.deliveries;

test('webhooks: management is per owner; another user gets 404; secret stored encrypted; URL rules', { skip: needDb }, async () => {
  const a = await signup(), b = await signup();
  const made = await hook(a, 'https://example.com/hook', ['document.sent']);
  assert.equal(made.status, 201, made.text);
  const { id, secret } = made.json;
  assert.match(secret, /^whsec_[A-Za-z0-9_-]{43}$/);
  const row = db().prepare('SELECT secret_enc FROM webhooks WHERE id = ?').get(id);
  assert.equal(row.secret_enc.includes(secret.slice(6)), false);
  assert.equal((await call('/api/webhooks', { cookie: a.cookie })).text.includes(secret.slice(6)), false);
  for (const [m, p, body] of [['PUT', `/api/webhooks/${id}`, { url: 'https://evil.example/x' }], ['DELETE', `/api/webhooks/${id}`], ['POST', `/api/webhooks/${id}/test`, {}], ['GET', `/api/webhooks/${id}/deliveries`]]) {
    assert.equal((await call(p, { method: m, cookie: b.cookie, body })).status, 404, `${m} ${p}`);
  }
  assert.deepEqual((await call('/api/webhooks', { cookie: b.cookie })).json.webhooks, []);
  assert.equal((await call('/api/webhooks', { cookie: a.cookie })).json.webhooks[0].url, 'https://example.com/hook');
  for (const [url, events] of [['https://u:p@example.com/', ['document.sent']], ['https://example.com/', []], ['https://example.com/', ['ping']], ['https://example.com/', ['nope']],
    ['javascript:alert(1)', ['document.sent']], [`https://example.com/${'a'.repeat(500)}`, ['document.sent']]]) {
    assert.equal((await hook(a, url, events)).status, 400, `${url} ${events}`);
  }
});

test('webhooks: signed with HMAC over "<t>.<raw body>", whitelisted payload, full signing sequence', { skip: needReceiver }, async () => {
  const rx = await receiver();
  try {
    const a = await signup();
    const { secret } = (await hook(a, rx.url(), ['document.sent', 'recipient.viewed', 'recipient.signed', 'document.completed'])).json;
    const email = `s-${rnd()}@example.com`;
    const id = await upload(a);
    const put = await save(a, id, { recipients: [{ id: 'a', name: 'Signer One', email, role: 'signer' }],
      fields: [sigF('a'), { recipientId: 'a', type: 'text', page: 0, x: 0.5, y: 0.5, w: 0.2, h: 0.05, label: 'note' }] });
    assert.equal(put.status, 200, put.text);
    const textId = put.json.fields.find((f) => f.type === 'text').id;
    const sigId = put.json.fields.find((f) => f.type === 'signature').id;
    assert.equal((await action(a, id, 'send')).status, 200);
    const token = props((await call(`/app/documents/${id}`, { cookie: a.cookie })).text).recipients[0].token;
    assert.equal((await call(`/sign/${token}`)).status, 200);
    const secretText = `secret-field-${rnd()}`;
    const sub = await call(`/api/sign/${token}`, { method: 'POST', body: { values: { [sigId]: PNG, [textId]: secretText } } });
    assert.equal(sub.status, 200, sub.text);
    await until(() => rx.got.length >= 4);
    const events = rx.got.map((g) => g.headers['countersign-event']);
    assert.equal(rx.got.length, 4, events.join());
    assert.equal(events[0], 'document.sent');
    assert.deepEqual([...events].sort(), ['document.completed', 'document.sent', 'recipient.signed', 'recipient.viewed']);
    for (const g of rx.got) {
      assert.ok(verifySig(secret, g.headers['countersign-signature'], g.body), 'signature verifies');
      assert.equal(verifySig(secret, g.headers['countersign-signature'], g.body + ' '), false, 'tampered body fails');
      assert.equal(g.headers['user-agent'], 'Countersign-Webhooks');
      const p = JSON.parse(g.body);
      assert.deepEqual(Object.keys(p).sort(), ['createdAt', 'data', 'event', 'id']);
      assert.equal(p.id, g.headers['countersign-delivery']);
      assert.deepEqual(Object.keys(p.data.document).sort(), ['id', 'status', 'title']);
      if (p.data.recipient) assert.deepEqual(Object.keys(p.data.recipient).sort(), ['email', 'id', 'name', 'role', 'status']);
      for (const leak of [token, secretText, PNG.slice(30, 60), secret, 'otp', 'token', 'sha256']) assert.equal(g.body.includes(leak), false, `payload leaks ${leak}`);
    }
  } finally { await rx.close(); }
});

test('webhooks: redirects are not followed (3xx is a failure)', { skip: needReceiver }, async () => {
  const target = await receiver();
  const rx = await receiver((req, res) => { res.writeHead(302, { location: target.url('/stolen') }); res.end(); });
  try {
    const a = await signup();
    const { id } = (await hook(a, rx.url(), ['document.sent'])).json;
    assert.equal((await call(`/api/webhooks/${id}/test`, { method: 'POST', cookie: a.cookie, body: {} })).status, 200);
    const d = await until(async () => (await deliveries(a, id)).find((x) => x.attempts > 0));
    assert.deepEqual([d?.event, d?.status, d?.lastStatusCode, d?.lastError], ['ping', 'pending', 302, 'HTTP 302']);
    await sleep(500);
    assert.equal(target.got.length, 0, 'redirect target never contacted');
  } finally { await rx.close(); await target.close(); }
});

test('T3-02: webhook deliveries are coalesced, so an 80-row bulk opens at most 50 connections to one receiver', { skip: needReceiver }, async () => {
  const rx = await receiver((req, res) => setTimeout(() => res.end('ok'), 2500));
  try {
    const a = await signup();
    await hook(a, rx.url(), ['document.sent']);
    const t = await template(a);
    const rows = Array.from({ length: 80 }, (_, i) => [{ name: `P${i}`, email: `p${i}-${rnd()}@example.com` }]);
    assert.equal((await action(a, t, 'bulk', { rows })).status, 201);
    // Batches of at most 50, each held 2.5 s by the receiver: allow plenty of time for all 80.
    await until(() => rx.got.length >= 80, 30000);
    assert.equal(rx.got.length, 80, 'every delivery still arrives');
    assert.ok(rx.maxOpen() <= 50, `max concurrent webhook connections: ${rx.maxOpen()}`);
    assert.equal(new Set(rx.got.map((g) => g.headers['countersign-delivery'])).size, 80, 'no delivery sent twice');
  } finally { await rx.close(); }
});

// ---------- Webhook SSRF with default settings (server B) ----------

test('webhooks (defaults): http, private, loopback, link-local and mapped literals refused at create', { skip: needDefaults }, async () => {
  const a = await signup(DEFAULTS);
  assert.deepEqual((await hook(a, 'http://example.com/', ['document.sent'], DEFAULTS)).json, { error: 'Use an https:// URL' });
  for (const u of ['https://127.0.0.1/', 'https://127.1/', 'https://2130706433/', 'https://0x7f.0.0.1/', 'https://0/', 'https://[::1]/', 'https://[::]/',
    'https://[::ffff:127.0.0.1]/', 'https://[::ffff:a9fe:a9fe]/', 'https://169.254.169.254/', 'https://10.0.0.1/', 'https://172.16.0.1/', 'https://192.168.0.1/',
    'https://100.64.0.1/', 'https://[fd00::1]/', 'https://[fe80::1]/', 'https://224.0.0.1/', 'https://[64:ff9b::a9fe:a9fe]/',
    // T3-05: IPv4-translated, 6to4, Teredo and discard prefixes.
    'https://[::ffff:0:7f00:1]/', 'https://[2002:7f00:1::1]/', 'https://[2001::1]/', 'https://[100::1]/']) {
    const r = await hook(a, u, ['document.sent'], DEFAULTS);
    assert.deepEqual([r.status, r.json.error], [400, 'This address is not allowed'], u);
  }
});

test('webhooks (defaults): a hostname resolving to loopback is refused at connect time', { skip: needDefaults }, async () => {
  const a = await signup(DEFAULTS);
  const made = await hook(a, 'https://localhost:1/hook', ['document.sent'], DEFAULTS);
  assert.equal(made.status, 201, 'hostnames pass create; the check runs on the resolved address');
  assert.equal((await call(`/api/webhooks/${made.json.id}/test`, { method: 'POST', cookie: a.cookie, base: DEFAULTS, body: {} })).status, 200);
  const d = await until(async () => (await deliveries(a, made.json.id, DEFAULTS)).find((x) => x.attempts > 0));
  assert.deepEqual([d?.status, d?.lastStatusCode, d?.lastError], ['pending', null, 'This address is not allowed']);
});

// ---------- 2026-11-03 fix round ----------

test('T3-07: removing the signature field from a template turns its public link off', async () => {
  const a = await signup();
  const t = await template(a);
  const url = (await action(a, t, 'public', { enabled: true })).json.url;
  assert.equal((await call(url)).status, 200);
  const put = await save(a, t, { recipients: [{ id: 'r0', name: 'Role 1', email: '', role: 'signer' }], fields: [] });
  assert.equal(put.status, 200, put.text);
  assert.equal((await call(url)).status, 404);
  assert.equal((await call(`/api/documents/${t}`, { cookie: a.cookie })).json.publicUrl, null);
});

test('T3-08 and T3-01: document actions take JSON or CSV only (415); bulk sends are limited to 10 per hour per user', async () => {
  const a = await signup(), b = await signup();
  const doc = await upload(a);
  for (const type of ['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x', null]) {
    const r = await call(`/api/documents/${doc}/move`, { method: 'POST', cookie: a.cookie, body: '{"folderId":null}', headers: type ? { 'content-type': type } : {} });
    assert.deepEqual([r.status, r.json?.error], [415, 'Send JSON or CSV'], String(type));
  }
  const t = await template(a);
  const row = () => ({ rows: [[{ name: 'P', email: `p-${rnd()}@example.com` }]] });
  // Counted before validation: ten invalid bodies use up the hour.
  for (let i = 1; i <= 10; i++) assert.equal((await action(a, t, 'bulk', {})).status, 400, `bulk ${i}`);
  const before = await docCount(a);
  const r = await action(a, t, 'bulk', row());
  assert.deepEqual([r.status, r.json.error], [429, 'Too many bulk sends. Try again later.']);
  assert.ok(Number(r.headers['retry-after']) > 0);
  // A's API key shares A's budget; B has its own.
  const { key } = await newKey(a);
  assert.equal((await call(`/api/documents/${t}/bulk`, { method: 'POST', body: row(), headers: bearer(key) })).status, 429);
  assert.equal(await docCount(a), before, 'nothing was created');
  assert.equal((await action(b, await template(b), 'bulk', row())).status, 201);
});

// Capturing SMTP sink (same as tier2): records envelope recipients and the raw DATA of each message.
function smtpSink(port) {
  const mails = [];
  const server = net.createServer((s) => {
    let data = false, buf = '', cur = { rcpt: [], raw: '' };
    s.write('220 sink\r\n');
    s.on('data', (c) => {
      buf += c.toString('latin1');
      for (;;) {
        if (data) {
          const end = buf.indexOf('\r\n.\r\n'); if (end < 0) break;
          cur.raw = buf.slice(0, end); buf = buf.slice(end + 5); data = false; mails.push(cur); cur = { rcpt: [], raw: '' }; s.write('250 ok\r\n'); continue;
        }
        const i = buf.indexOf('\r\n'); if (i < 0) break;
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === 'EHLO' || cmd === 'HELO') s.write('250 sink\r\n');
        else if (cmd === 'RCPT') { cur.rcpt.push(line.slice(8).trim().toLowerCase()); s.write('250 ok\r\n'); }
        else if (cmd === 'DATA') { data = true; s.write('354 go\r\n'); }
        else if (cmd === 'QUIT') s.end('221 bye\r\n');
        else s.write('250 ok\r\n');
      }
    });
    s.on('error', () => {});
  });
  return new Promise((r) => server.listen(port, '127.0.0.1', () => r({ mails, close: () => server.close() })));
}

test('T3-03: a completed public-link copy without email codes mails the owner, never the visitor-typed address', { skip: needMail }, async () => {
  const sink = await smtpSink(Number(process.env.QA_SMTP_SINK_PORT));
  try {
    const a = await signup();
    const t = await template(a, 1, `T3-03 ${rnd()}`);
    const tok = tokenOf((await action(a, t, 'public', { enabled: true })).json.url);
    const visitor = `visitor-${rnd()}@example.com`;
    const started = await publicPost(tok, { name: 'Visitor', email: visitor });
    assert.equal(started.status, 200, started.text);
    const [copy] = (await call('/api/documents?template=0&limit=1', { cookie: a.cookie })).json.documents;
    const sigId = (await call(`/api/documents/${copy.id}`, { cookie: a.cookie })).json.fields.find((f) => f.type === 'signature').id;
    const token = started.json.signUrl.replace(/^\/sign\//, '');
    assert.equal((await call(`/sign/${token}`)).status, 200);
    const done = await call(`/api/sign/${token}`, { method: 'POST', body: { values: { [sigId]: PNG } } });
    assert.equal(done.json?.status, 'completed', done.text);
    // Positive control: the sink works and the owner's completion email still goes.
    assert.ok(await until(() => sink.mails.find((m) => m.rcpt.some((x) => x.includes(a.email))), 10000), 'owner completion email');
    await sleep(500);
    assert.equal(sink.mails.some((m) => m.rcpt.some((x) => x.includes(visitor))), false, 'nothing was mailed to the typed address');
  } finally { sink.close(); }
});

test('fix: bulk send Idempotency-Key is validated and a reuse by the same owner is refused', async () => {
  const a = await signup(), b = await signup();
  const t = await template(a);
  const tb = await template(b);
  const row = () => [[{ name: 'P', email: `p-${rnd()}@example.com` }]];
  for (const k of ['short', 'a'.repeat(65), 'bad key!', 'abc/def12', 'ümlaut123']) {
    const r = await action(a, t, 'bulk', { rows: row() }, { 'idempotency-key': k });
    assert.deepEqual([r.status, r.json.error], [400, 'Invalid Idempotency-Key'], k);
  }
  const before = await docCount(a);
  const key = `bulk_${rnd()}-${rnd()}`;
  const first = await action(a, t, 'bulk', { rows: row() }, { 'idempotency-key': key });
  assert.equal(first.status, 201, first.text);
  const again = await action(a, t, 'bulk', { rows: row() }, { 'idempotency-key': key });
  assert.deepEqual([again.status, again.json.error], [409, 'This bulk send was already started']);
  const csv = await call(`/api/documents/${t}/bulk`, { method: 'POST', cookie: a.cookie, body: `P,p-${rnd()}@example.com\n`, headers: { 'content-type': 'text/csv', 'idempotency-key': key } });
  assert.equal(csv.status, 409, 'the CSV path honours the key too');
  assert.equal(await docCount(a), before + 1, 'the retries created nothing');
  // Scoped per owner: B using the same key value is not blocked by A's send, and does not learn it was used.
  assert.equal((await action(b, tb, 'bulk', { rows: row() }, { 'idempotency-key': key })).status, 201);
});

test('fix: a public link needs a template that can be sent (e.g. one with a signature field)', async () => {
  const a = await signup();
  const id = await upload(a, true);
  assert.equal((await save(a, id, { recipients: [{ id: 'r', name: 'Client', email: '', role: 'signer' }], fields: [] })).status, 200);
  const r = await action(a, id, 'public', { enabled: true });
  assert.equal(r.status, 400, r.text);
  assert.equal((await call(`/api/documents/${id}`, { cookie: a.cookie })).json.publicUrl, null);
});

test('fix: public-link copies expire after 1 day when the template sets none; per-template cap is 50 a day', { skip: needDb }, async () => {
  const a = await signup();
  const t = await template(a);
  const tok = tokenOf((await action(a, t, 'public', { enabled: true })).json.url);
  const ok = await publicPost(tok, { name: 'Visitor', email: `v-${rnd()}@example.com` });
  assert.equal(ok.status, 200, ok.text);
  const [copy] = (await call('/api/documents?template=0&limit=1', { cookie: a.cookie })).json.documents;
  const d = (await call(`/api/documents/${copy.id}`, { cookie: a.cookie })).json.doc;
  assert.equal(d.expire_days, 1);
  const left = Date.parse(d.expires_at) - Date.now();
  assert.ok(left > 23 * 36e5 && left <= 24 * 36e5 + 6e4, `expires_at ${d.expires_at}`);
  // 49 used today: the 50th is allowed, the 51st is refused.
  db().prepare(`INSERT INTO login_attempts (key, window_start, count, locked_until) VALUES (?, ?, 49, NULL)
    ON CONFLICT(key) DO UPDATE SET count = 49, locked_until = NULL, window_start = excluded.window_start`).run(`publictpl:${sha(tok)}`, new Date().toISOString());
  assert.equal((await publicPost(tok, { name: 'Visitor', email: `v-${rnd()}@example.com` })).status, 200, '50th of the day');
  const capped = await publicPost(tok, { name: 'Visitor', email: `v-${rnd()}@example.com` });
  assert.equal(capped.status, 429, '51st of the day');
});

// ---------- Last: spends the per-IP public-link budget ----------

test('public link: per-IP limit (10/h) counts probes of unknown tokens, applies before the token lookup, ignores X-Forwarded-For', async () => {
  const a = await signup();
  const t = await template(a);
  const tok = tokenOf((await action(a, t, 'public', { enabled: true })).json.url);
  let first429 = null;
  for (let i = 0; i < 12 && first429 === null; i++) {
    const r = await publicPost(crypto.randomBytes(32).toString('base64url'), { name: 'P', email: 'p@example.com' });
    if (r.status === 429) first429 = r; else assert.equal(r.status, 404);
  }
  assert.ok(first429, 'probing unknown tokens hits the limit');
  assert.ok(ipBudgetUsed <= 11, `limit reached after ${ipBudgetUsed} requests (want 10 allowed)`);
  assert.ok(Number(first429.headers['retry-after']) > 0);
  const real = await publicPost(tok, { name: 'P', email: 'p@example.com' });
  assert.equal(real.status, 429, 'a valid token is limited too: probing costs the same as using');
  const spoof = await publicPost(tok, { name: 'P', email: 'p@example.com' }, { 'x-forwarded-for': '203.0.113.9' });
  assert.equal(spoof.status, 429, 'X-Forwarded-For is ignored without TRUST_PROXY');
  const hp = await publicPost(tok, { name: 'P', email: 'p@example.com', website: 'x' });
  assert.equal(hp.status, 429, 'the honeypot does not bypass the limit');
});
