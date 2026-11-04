// Tier 3 wave 1 over HTTP: folders (CRUD, move, filter), GET /api/documents, API keys (Bearer, origin bypass, revoke),
// bulk send (JSON and CSV, validation, partial failure), public template link (/t page, submit, sign, rotate, disable,
// honeypot, rate limit) and webhooks (local receiver: HMAC signature, event sequence, test ping, delivery log).
// Needs a running FRESH server (ALLOW_SIGNUP=true, SIGNUP_MAX_PER_HOUR=1000, explicit ENCRYPTION_KEY):
//   BASE_URL=http://localhost:3492 DATA_DIR=<server's DATA_DIR> ENCRYPTION_KEY=<same as server> node --test test/tier3.test.mjs
// DATA_DIR (+ ENCRYPTION_KEY or DATA_DIR/encryption.key) enables at-rest checks and the forced bulk-row failure.
// Webhook delivery tests need the server started with WEBHOOK_ALLOW_PRIVATE=true WEBHOOK_ALLOW_HTTP=true (the receiver
// listens on 127.0.0.1); without them they skip. Detected by creating a webhook to http://127.0.0.1 (400 = off).
// Public-link POSTs are rate limited per IP (10/hour), so they go out from random 127.x.y.z source addresses (loopback
// BASE_URL) with the same X-Forwarded-For (used instead when the server runs with TRUST_PROXY=true).
// SERVER_LOG (optional): the server's log file; the last test checks it has no errors from these routes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const DATA = process.env.DATA_DIR;
const NEEDS_DB = !DATA && 'needs DATA_DIR pointing at the server data folder';
const LOOPBACK = ['localhost', '127.0.0.1', '[::1]'].includes(new URL(BASE).hostname);
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const PASSWORD = 'correct horse battery';
const EVIL = 'http://evil.test';
const EVENTS = ['document.sent', 'recipient.viewed', 'recipient.signed', 'recipient.declined', 'document.completed', 'document.declined', 'document.voided', 'document.expired'];
const rnd = () => crypto.randomBytes(5).toString('hex');
const err = (r) => [r.status, r.data?.error];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let _db;
const db = () => {
  if (!_db) { _db = new DatabaseSync(path.join(DATA, 'countersign.db')); _db.exec('PRAGMA busy_timeout = 5000'); }
  return _db;
};
const keyText = () => (process.env.ENCRYPTION_KEY || fs.readFileSync(path.join(DATA, 'encryption.key'), 'utf8')).trim();
const key = () => Buffer.from(keyText(), /^[0-9a-f]{64}$/i.test(keyText()) ? 'hex' : 'base64');
const keyedHash = (info, data) => crypto.createHmac('sha256', Buffer.from(crypto.hkdfSync('sha256', key(), Buffer.alloc(0), 'countersign-' + info, 32))).update(data).digest('hex');
// Independent decrypt of lib/crypto.js text format: "enc:v1:" + base64("CSE1" | IV 12 | tag 16 | ciphertext), AES-256-GCM with AAD.
function decText(v, aad) {
  assert.ok(v.startsWith('enc:v1:'), 'enc:v1: prefix');
  const buf = Buffer.from(v.slice(7), 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', key(), buf.subarray(4, 16));
  d.setAAD(Buffer.from(aad)); d.setAuthTag(buf.subarray(16, 32));
  return Buffer.concat([d.update(buf.subarray(32)), d.final()]).toString('utf8');
}

// ---------- HTTP helpers ----------
function client() {
  const cookies = {};
  const call = async (p, { method = 'POST', body, headers = {} } = {}) => {
    const raw = body instanceof Uint8Array || typeof body === 'string';
    const cookie = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(BASE + p, {
      method, redirect: 'manual',
      headers: { ...(raw ? {} : { 'Content-Type': 'application/json' }), ...(cookie && { cookie }), ...headers },
      body: body == null ? undefined : raw ? body : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); cookies[kv.slice(0, i)] = kv.slice(i + 1); }
    const type = res.headers.get('content-type') || '';
    return { status: res.status, headers: res.headers, data: type.includes('json') ? await res.json() : Buffer.from(await res.arrayBuffer()) };
  };
  call.cookies = cookies;
  return call;
}
// A client that sends only `Authorization: Bearer <key>` (plus any extra headers, e.g. a victim's cookie or Origin).
const bearer = (k, extra = {}) => (p, opts = {}) => client()(p, { ...opts, headers: { Authorization: `Bearer ${k}`, ...extra, ...opts.headers } });
const pageHtml = async (call, p) => (await call(p, { method: 'GET' })).data.toString();
const props = async (call, p) => JSON.parse(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s.exec(await pageHtml(call, p))[1]).props.pageProps;

async function signup(name = 'Tier3 Owner') {
  const call = client();
  const email = `t3-${Date.now()}-${rnd()}@example.com`;
  const r = await call('/api/auth/signup', { body: { name, email, password: PASSWORD } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return Object.assign(call, { email, userName: name });
}
const pdf = async () => { const d = await PDFDocument.create(); d.setTitle(rnd()); d.addPage([612, 792]); return d.save(); };
const field = (recipientId, i = 0) => ({ recipientId, type: 'signature', page: 0, x: 0.1, y: 0.1 + i * 0.1, w: 0.3, h: 0.08 });
const person = (id) => ({ id, name: `Signer ${id}`, email: `${id}-${rnd()}@example.com`, role: 'signer' });

async function upload(call, template = false) {
  const up = await call('/api/documents', { body: await pdf(), headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'Tier3.pdf', ...(template && { 'x-template': '1' }) } });
  assert.equal(up.status, 201, JSON.stringify(up.data));
  return up.data.id;
}
async function draft(call, recipients, extra = {}) {
  const id = await upload(call);
  const title = extra.title ?? `Tier3 ${rnd()}`;
  const put = await call(`/api/documents/${id}`, { method: 'PUT', body: { title, recipients, fields: recipients.map((r, i) => field(r.id, i)), ...extra } });
  assert.equal(put.status, 200, JSON.stringify(put.data));
  return { id, title, ...put.data };
}
const getDoc = async (call, id) => { const r = await call(`/api/documents/${id}`, { method: 'GET' }); assert.equal(r.status, 200, JSON.stringify(r.data)); return r.data; };
async function sent(call, recipients) {
  const d = await draft(call, recipients);
  const r = await call(`/api/documents/${d.id}/send`, { body: {} });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  const g = await getDoc(call, d.id);
  return { ...d, tokens: d.recipients.map((x) => g.recipients.find((y) => y.id === x.id).token), fields: g.fields };
}
// A template whose recipients are named roles with no email.
async function template(call, roles = ['Client']) {
  const id = await upload(call, true);
  const recipients = roles.map((name, i) => ({ id: `r${i}`, name, email: '', role: 'signer' }));
  const title = `Tpl ${rnd()}`;
  const put = await call(`/api/documents/${id}`, { method: 'PUT', body: { title, recipients, fields: recipients.map((r, i) => field(r.id, i)) } });
  assert.equal(put.status, 200, JSON.stringify(put.data));
  return { id, title, ...put.data };
}
const signAll = async (call, token, fields, recipientId) =>
  call(`/api/sign/${token}`, { body: { values: Object.fromEntries(fields.filter((f) => f.recipient_id === recipientId).map((f) => [f.id, PNG])) } });
const total = async (call, qs = '') => (await call(`/api/documents${qs}`, { method: 'GET' })).data.total;

// POST /api/public-templates/<token> from a chosen source IP (see header).
const randomIp = () => `127.${crypto.randomInt(1, 255)}.${crypto.randomInt(1, 255)}.${crypto.randomInt(2, 255)}`;
function pub(token, body, ip = randomIp(), headers = {}) {
  const u = new URL(`/api/public-templates/${encodeURIComponent(token)}`, BASE);
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({
      method: 'POST', host: u.hostname.replace(/^\[|\]$/g, ''), port: u.port, path: u.pathname,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'X-Forwarded-For': ip, ...headers },
      ...(LOOPBACK && { localAddress: ip, family: 4, host: '127.0.0.1' }),
    }, (res) => {
      let b = '';
      res.on('data', (c) => { b += c; });
      res.on('end', () => { let data; try { data = JSON.parse(b); } catch { data = b; } resolve({ status: res.statusCode, headers: res.headers, data }); });
    });
    req.on('error', reject);
    req.end(payload);
  });
}

// ---------- Local webhook receiver ----------
// Paths starting /ok answer 200, /fail 500, /redirect 302 (to /ok/followed). Every request is recorded.
const received = [];
const receiver = http.createServer((req, res) => {
  let body = '';
  req.setEncoding('utf8');
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    let json = null;
    try { json = JSON.parse(body); } catch {}
    received.push({ path: req.url, method: req.method, headers: req.headers, body, json, at: Date.now() });
    if (req.url.startsWith('/fail')) { res.writeHead(500); res.end('no'); }
    else if (req.url.startsWith('/redirect')) { res.writeHead(302, { Location: '/ok/followed' }); res.end(); }
    else { res.writeHead(200); res.end('ok'); }
  });
});
await new Promise((r) => receiver.listen(0, '127.0.0.1', r));
const HOOK = `http://127.0.0.1:${receiver.address().port}`;

let WEBHOOKS_OFF;
try {
  const probe = await signup();
  const r = await probe('/api/webhooks', { body: { url: `${HOOK}/ok/probe`, events: ['document.sent'] } });
  if (r.status === 201) { WEBHOOKS_OFF = false; await probe(`/api/webhooks/${r.data.id}`, { method: 'DELETE' }); }
  else if (r.status === 400) WEBHOOKS_OFF = 'needs a server with WEBHOOK_ALLOW_PRIVATE=true WEBHOOK_ALLOW_HTTP=true';
  else WEBHOOKS_OFF = `webhook probe returned ${r.status} ${JSON.stringify(r.data)}`;
} catch (e) {
  WEBHOOKS_OFF = `server not reachable at ${BASE}: ${e.message}`;
}
test.after(() => { _db?.close(); receiver.close(); });

async function waitFor(pred, what, timeout = 90_000) {
  for (let t = Date.now(); Date.now() - t < timeout;) {
    const v = await pred();
    if (v) return v;
    await sleep(200);
  }
  assert.fail(`timed out after ${timeout / 1000} s waiting for ${what}`);
}
const hits = (p) => received.filter((x) => x.path === p);
const hookEvent = (p, event, docId) => waitFor(() => hits(p).find((x) => x.json?.event === event && (!docId || x.json?.data?.document?.id === docId)), `${event} on ${p}`);
function checkSignature(hit, secret) {
  const m = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(hit.headers['countersign-signature'] || '');
  assert.ok(m, `signature header format: ${hit.headers['countersign-signature']}`);
  assert.ok(Math.abs(Date.now() / 1000 - Number(m[1])) < 300, 'timestamp is current');
  const expected = crypto.createHmac('sha256', secret).update(`${m[1]}.${hit.body}`).digest();
  assert.ok(crypto.timingSafeEqual(expected, Buffer.from(m[2], 'hex')), 'HMAC-SHA256(secret, "<t>.<body>") matches');
  const wrong = crypto.createHmac('sha256', secret + 'x').update(`${m[1]}.${hit.body}`).digest();
  assert.ok(!crypto.timingSafeEqual(wrong, Buffer.from(m[2], 'hex')), 'a different secret does not match');
  assert.equal(hit.method, 'POST');
  assert.match(hit.headers['content-type'], /^application\/json/);
  assert.equal(hit.headers['user-agent'], 'Countersign-Webhooks');
  assert.equal(hit.headers['countersign-event'], hit.json.event);
  assert.equal(hit.headers['countersign-delivery'], hit.json.id);
  assert.deepEqual(Object.keys(hit.json).sort(), ['createdAt', 'data', 'event', 'id']);
}

// =====================================================================================================================
// Folders
// =====================================================================================================================

test('folders: create, list with counts, rename, validation 400, duplicate 409 (case-insensitive), delete unfiles; per user; 401; 403', async () => {
  const a = await signup(), b = await signup();
  const list = async (c) => { const r = await c('/api/folders', { method: 'GET' }); assert.equal(r.status, 200, JSON.stringify(r.data)); return r.data.folders; };
  assert.deepEqual(await list(a), []);
  const f1 = await a('/api/folders', { body: { name: '  Contracts  ' } });
  assert.equal(f1.status, 201);
  assert.equal(typeof f1.data.id, 'string');
  const f2 = await a('/api/folders', { body: { name: 'archive' } });
  assert.deepEqual(await list(a), [{ id: f2.data.id, name: 'archive', count: 0 }, { id: f1.data.id, name: 'Contracts', count: 0 }], 'trimmed, ordered by name');
  assert.deepEqual(err(await a('/api/folders', { body: { name: 'CONTRACTS' } })), [409, 'A folder with this name already exists']);
  for (const name of ['', '   ', undefined, 42]) assert.deepEqual(err(await a('/api/folders', { body: { name } })), [400, 'Enter a folder name'], `name ${name}`);
  assert.equal((await a('/api/folders', { body: { name: 'x'.repeat(81) } })).status, 400, '81 chars');
  assert.equal((await a('/api/folders', { body: { name: 'y'.repeat(80) } })).status, 201, '80 chars');
  assert.equal((await b('/api/folders', { body: { name: 'Contracts' } })).status, 201, 'same name for another user');
  // Rename.
  assert.deepEqual((await a(`/api/folders/${f1.data.id}`, { method: 'PUT', body: { name: 'Signed contracts' } })).data, { ok: true });
  assert.deepEqual(err(await a(`/api/folders/${f2.data.id}`, { method: 'PUT', body: { name: 'signed CONTRACTS' } })), [409, 'A folder with this name already exists']);
  assert.deepEqual(err(await a(`/api/folders/${f2.data.id}`, { method: 'PUT', body: { name: ' ' } })), [400, 'Enter a folder name']);
  assert.equal((await a(`/api/folders/${f1.data.id}`, { method: 'PUT', body: { name: 'signed contracts' } })).status, 200, 'own name in another case');
  // Cross-user and unknown ids: 404, unchanged.
  assert.equal((await b(`/api/folders/${f1.data.id}`, { method: 'PUT', body: { name: 'Hacked' } })).status, 404);
  assert.equal((await b(`/api/folders/${f1.data.id}`, { method: 'DELETE' })).status, 404);
  assert.equal((await a(`/api/folders/${crypto.randomUUID()}`, { method: 'DELETE' })).status, 404);
  assert.deepEqual((await list(b)).map((f) => f.name), ['Contracts']);
  // Delete with documents in it: they become unfiled, never deleted.
  const d = await draft(a, [person('a')]);
  assert.deepEqual((await a(`/api/documents/${d.id}/move`, { body: { folderId: f1.data.id } })).data, { ok: true });
  assert.equal((await list(a)).find((f) => f.id === f1.data.id).count, 1);
  assert.deepEqual((await a(`/api/folders/${f1.data.id}`, { method: 'DELETE' })).data, { ok: true });
  assert.ok(!(await list(a)).some((f) => f.id === f1.data.id));
  const g = await getDoc(a, d.id);
  assert.equal(g.doc.folder_id, null, 'document unfiled');
  assert.equal(g.doc.status, 'draft');
  assert.equal((await a(`/api/folders/${f1.data.id}`, { method: 'DELETE' })).status, 404, 'second delete');
  // Anonymous and cross-origin.
  const anon = client();
  assert.equal((await anon('/api/folders', { method: 'GET' })).status, 401);
  assert.equal((await anon('/api/folders', { body: { name: 'X' } })).status, 401);
  assert.equal((await a('/api/folders', { body: { name: 'Evil' }, headers: { Origin: EVIL } })).status, 403);
  assert.equal((await a(`/api/folders/${f2.data.id}`, { method: 'DELETE', headers: { Origin: EVIL } })).status, 403);
  assert.equal((await a(`/api/documents/${d.id}/move`, { body: { folderId: f2.data.id }, headers: { Origin: EVIL } })).status, 403);
  assert.ok((await list(a)).some((f) => f.id === f2.data.id), 'refused delete changed nothing');
});

test('folders: up to 200 per user, the 201st is 409', async () => {
  const a = await signup();
  for (let i = 0; i < 200; i++) assert.equal((await a('/api/folders', { body: { name: `F${i}` } })).status, 201, `folder ${i + 1}`);
  assert.deepEqual(err(await a('/api/folders', { body: { name: 'One too many' } })), [409, 'You can have up to 200 folders']);
  assert.equal((await a('/api/folders', { method: 'GET' })).data.folders.length, 200);
});

test('move: drafts, sent documents and templates; null unfiles; another user\'s folder or document is 404; ?folder= filter and counts', async () => {
  const a = await signup(), b = await signup();
  const fa = (await a('/api/folders', { body: { name: 'Mine' } })).data.id;
  const fb = (await b('/api/folders', { body: { name: 'Theirs' } })).data.id;
  const dr = await draft(a, [person('a')]);
  const se = await sent(a, [person('a')]);
  const tp = await template(a);
  for (const id of [dr.id, se.id, tp.id]) assert.deepEqual((await a(`/api/documents/${id}/move`, { body: { folderId: fa } })).data, { ok: true }, id);
  assert.equal((await a('/api/folders', { method: 'GET' })).data.folders[0].count, 3, 'count includes templates');
  const inFolder = (await a(`/api/documents?folder=${fa}`, { method: 'GET' })).data;
  assert.equal(inFolder.total, 3);
  assert.deepEqual(inFolder.documents.map((d) => d.id).sort(), [dr.id, se.id, tp.id].sort());
  assert.ok(inFolder.documents.every((d) => d.folderId === fa));
  // Another user's folder; unknown folder; non-string folderId.
  for (const folderId of [fb, crypto.randomUUID(), 42, { id: fa }]) {
    assert.equal((await a(`/api/documents/${dr.id}/move`, { body: { folderId } })).status, 404, JSON.stringify(folderId));
  }
  assert.equal((await getDoc(a, dr.id)).doc.folder_id, fa, 'refused moves changed nothing');
  // b cannot move a's document, even into b's own folder.
  assert.equal((await b(`/api/documents/${dr.id}/move`, { body: { folderId: fb } })).status, 404);
  assert.equal((await b(`/api/documents/${dr.id}/move`, { body: { folderId: null } })).status, 404);
  assert.equal((await b(`/api/documents?folder=${fa}`, { method: 'GET' })).data.total, 0, 'filter by another user\'s folder shows nothing');
  // Unfile: null and missing folderId.
  assert.deepEqual((await a(`/api/documents/${dr.id}/move`, { body: { folderId: null } })).data, { ok: true });
  assert.deepEqual((await a(`/api/documents/${se.id}/move`, { body: {} })).data, { ok: true });
  assert.equal((await getDoc(a, dr.id)).doc.folder_id, null);
  assert.equal((await getDoc(a, se.id)).doc.folder_id, null);
  assert.equal((await a(`/api/documents?folder=${fa}`, { method: 'GET' })).data.total, 1);
  assert.equal((await a('/api/folders', { method: 'GET' })).data.folders[0].count, 1);
  // A copy of a filed template lands in the same folder.
  const copy = await a(`/api/documents/${tp.id}/copy`, { body: {} });
  assert.equal(copy.status, 201);
  assert.equal((await getDoc(a, copy.data.id)).doc.folder_id, fa, 'folder_id copied');
});

// =====================================================================================================================
// GET /api/documents
// =====================================================================================================================

test('GET /api/documents: owner only, exact shape, status/template filters, limit/offset paging, total', async () => {
  const a = await signup(), b = await signup();
  const d1 = await draft(a, [person('a')]);
  const d2 = await sent(a, [person('a')]);
  const t1 = await template(a);
  await draft(b, [person('a')]);
  const all = (await a('/api/documents', { method: 'GET' })).data;
  assert.equal(all.total, 3);
  assert.deepEqual(all.documents.map((d) => d.id).sort(), [d1.id, d2.id, t1.id].sort());
  const one = all.documents.find((d) => d.id === d2.id);
  assert.deepEqual(Object.keys(one).sort(), ['completedAt', 'createdAt', 'folderId', 'id', 'isTemplate', 'ownerName', 'sentAt', 'status', 'teamShared', 'title', 'updatedAt']);
  assert.deepEqual([one.ownerName, one.teamShared], ['Tier3 Owner', false], 'wave 2 fields: own personal document');
  assert.equal(one.status, 'sent');
  assert.equal(one.isTemplate, false);
  assert.ok(one.sentAt);
  assert.equal(all.documents.find((d) => d.id === t1.id).isTemplate, true);
  assert.deepEqual((await a('/api/documents?status=sent', { method: 'GET' })).data.documents.map((d) => d.id), [d2.id]);
  assert.deepEqual((await a('/api/documents?template=1', { method: 'GET' })).data.documents.map((d) => d.id), [t1.id]);
  assert.equal((await a('/api/documents?template=0', { method: 'GET' })).data.total, 2);
  assert.equal((await a('/api/documents?status=draft&template=0', { method: 'GET' })).data.total, 1);
  const p1 = (await a('/api/documents?limit=2', { method: 'GET' })).data, p2 = (await a('/api/documents?limit=2&offset=2', { method: 'GET' })).data;
  assert.deepEqual([p1.documents.length, p2.documents.length, p1.total, p2.total], [2, 1, 3, 3]);
  assert.deepEqual([...p1.documents, ...p2.documents].map((d) => d.id).sort(), all.documents.map((d) => d.id).sort(), 'pages cover everything once');
  for (const qs of ['?limit=abc', '?limit=-1&offset=-5', '?limit=100000']) assert.equal((await a(`/api/documents${qs}`, { method: 'GET' })).status, 200, qs);
  assert.equal((await client()('/api/documents', { method: 'GET' })).status, 401);
});

// =====================================================================================================================
// API keys
// =====================================================================================================================

test('API keys: create (shown once), list without secrets, use with Bearer from another origin, session cookie ignored, revoke', async () => {
  const a = await signup(), b = await signup();
  const created = await a('/api/api-keys', { body: { name: '  CI script  ' } });
  assert.equal(created.status, 201, JSON.stringify(created.data));
  const { id, key } = created.data;
  assert.match(key, /^cs_[A-Za-z0-9_-]{43}$/);
  assert.match(created.headers.get('cache-control') || '', /no-store/);
  const listed = (await a('/api/api-keys', { method: 'GET' })).data.keys;
  assert.equal(listed.length, 1);
  assert.deepEqual(Object.keys(listed[0]).sort(), ['createdAt', 'expiresAt', 'id', 'lastUsedAt', 'name', 'prefix', 'scope']);
  assert.deepEqual([listed[0].id, listed[0].name, listed[0].prefix, listed[0].lastUsedAt], [id, 'CI script', key.slice(0, 10), null]);
  assert.ok(!JSON.stringify(listed).includes(key.slice(10)), 'key never listed');
  assert.deepEqual((await b('/api/api-keys', { method: 'GET' })).data.keys, [], 'per user');
  for (const name of ['', '  ', undefined]) assert.deepEqual(err(await a('/api/api-keys', { body: { name } })), [400, 'Enter a name for the key']);
  assert.equal((await a('/api/api-keys', { body: { name: 'k'.repeat(81) } })).status, 400);

  const k = bearer(key);
  // Read and write with the key, from another origin, with no cookie.
  assert.equal((await k('/api/documents', { method: 'GET' })).data.total, 0);
  const folder = await k('/api/folders', { body: { name: 'Via API' }, headers: { Origin: EVIL } });
  assert.equal(folder.status, 201, 'Bearer skips the same-origin check');
  assert.equal((await a('/api/folders', { body: { name: 'Via cookie' }, headers: { Origin: EVIL } })).status, 403, 'cookie requests still checked');
  const up = await k('/api/documents', { body: await pdf(), headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'Api.pdf', Origin: EVIL } });
  assert.equal(up.status, 201, JSON.stringify(up.data));
  const recipients = [person('a')];
  assert.equal((await k(`/api/documents/${up.data.id}`, { method: 'PUT', body: { title: 'Api doc', recipients, fields: [field('a')] }, headers: { Origin: EVIL } })).status, 200);
  assert.equal((await k(`/api/documents/${up.data.id}/move`, { body: { folderId: folder.data.id } })).status, 200);
  assert.equal((await k(`/api/documents/${up.data.id}/send`, { body: {} })).status, 200);
  const g = await k(`/api/documents/${up.data.id}`, { method: 'GET' });
  assert.equal(g.status, 200);
  assert.deepEqual(Object.keys(g.data).sort(), ['doc', 'fields', 'publicUrl', 'recipients']);
  assert.deepEqual([g.data.doc.status, g.data.doc.folder_id, g.data.publicUrl], ['sent', folder.data.id, null]);
  assert.ok(!('public_token_hash' in g.data.doc) && !('public_token_enc' in g.data.doc));
  // Signing tokens go to a session caller only, never to an API key.
  assert.equal(g.data.recipients.length, 1);
  assert.ok(g.data.recipients.every((r) => !('token' in r)), 'no recipient token for an API key');
  const sessionToken = (await getDoc(a, up.data.id)).recipients[0].token;
  assert.ok(typeof sessionToken === 'string' && sessionToken.length >= 20, 'session caller still gets the token');
  assert.ok(!JSON.stringify(g.data).includes(sessionToken), 'token not anywhere in the API-key response');
  const file = await k(`/api/documents/${up.data.id}/file`, { method: 'GET' });
  assert.equal(file.status, 200);
  assert.equal(file.data.subarray(0, 5).toString(), '%PDF-');
  assert.equal((await a('/api/documents', { method: 'GET' })).data.total, 1, 'the session sees the key\'s work');
  // b's session cookie next to a's key: the key wins, the cookie is ignored.
  const withCookie = bearer(key, { cookie: Object.entries(b.cookies).map(([n, v]) => `${n}=${v}`).join('; ') });
  assert.deepEqual((await withCookie('/api/documents', { method: 'GET' })).data.documents.map((d) => d.id), [up.data.id]);
  // b's key cannot reach a's documents.
  const kb = bearer((await b('/api/api-keys', { body: { name: 'b' } })).data.key);
  assert.equal((await kb(`/api/documents/${up.data.id}`, { method: 'GET' })).status, 404);
  assert.equal((await kb(`/api/documents/${up.data.id}/void`, { body: {} })).status, 404);
  assert.equal((await kb('/api/documents', { method: 'GET' })).data.total, 0);
  // lastUsedAt is set.
  assert.ok((await a('/api/api-keys', { method: 'GET' })).data.keys[0].lastUsedAt, 'lastUsedAt');
  // Keys never reach session-only routes.
  for (const [p, method, body] of [['/api/api-keys', 'GET'], ['/api/api-keys', 'POST', { name: 'x' }], [`/api/api-keys/${id}`, 'DELETE'], ['/api/webhooks', 'GET'],
    ['/api/webhooks', 'POST', { url: 'https://example.com/h', events: ['document.sent'] }], ['/api/account', 'PATCH', { name: 'Hijacked' }], ['/api/auth/logout', 'POST', {}],
    ['/api/contacts', 'GET'], ['/api/signatures', 'GET']]) {
    assert.deepEqual(err(await k(p, { method, body })), [401, 'API keys cannot be used here'], `${method} ${p}`);
  }
  // Bad keys on an API-key route: 401 "Invalid API key", never the session.
  for (const bad of ['cs_nope', key + 'x', key.slice(0, -1) + (key.at(-1) === 'A' ? 'B' : 'A'), '']) {
    const c = bearer(bad, { cookie: Object.entries(a.cookies).map(([n, v]) => `${n}=${v}`).join('; ') });
    assert.deepEqual(err(await c('/api/documents', { method: 'GET' })), [401, 'Invalid API key'], `key "${bad.slice(0, 12)}"`);
  }
  // Revoke: other user 404, then the key stops working; second revoke 404.
  assert.equal((await b(`/api/api-keys/${id}`, { method: 'DELETE' })).status, 404);
  assert.equal((await k('/api/documents', { method: 'GET' })).status, 200, 'still works after a refused revoke');
  assert.equal((await a(`/api/api-keys/${id}`, { method: 'DELETE', headers: { Origin: EVIL } })).status, 403);
  assert.deepEqual((await a(`/api/api-keys/${id}`, { method: 'DELETE' })).data, { ok: true });
  assert.deepEqual(err(await k('/api/documents', { method: 'GET' })), [401, 'Invalid API key']);
  assert.deepEqual(err(await k('/api/folders', { body: { name: 'After revoke' } })), [401, 'Invalid API key']);
  assert.equal((await a(`/api/api-keys/${id}`, { method: 'DELETE' })).status, 404);
  assert.deepEqual((await a('/api/api-keys', { method: 'GET' })).data.keys, [], 'revoked keys are not listed');
  assert.equal((await client()('/api/api-keys', { method: 'GET' })).status, 401);
});

test('API keys: stored only as keyedHash("apikey", key) with a 10-char prefix; up to 20 active keys', { skip: NEEDS_DB }, async () => {
  const a = await signup();
  const { id, key } = (await a('/api/api-keys', { body: { name: 'hashed' } })).data;
  const row = db().prepare('SELECT * FROM api_keys WHERE id = ?').get(id);
  assert.equal(row.key_hash, keyedHash('apikey', key));
  assert.equal(row.prefix, key.slice(0, 10));
  assert.ok(!Object.values(row).some((v) => typeof v === 'string' && v.includes(key.slice(10))), 'no plaintext key column');
  for (let i = 1; i < 20; i++) assert.equal((await a('/api/api-keys', { body: { name: `k${i}` } })).status, 201, `key ${i + 1}`);
  assert.deepEqual(err(await a('/api/api-keys', { body: { name: 'k21' } })), [409, 'You can have up to 20 API keys']);
  assert.equal((await a(`/api/api-keys/${id}`, { method: 'DELETE' })).status, 200);
  assert.equal((await a('/api/api-keys', { body: { name: 'after revoke' } })).status, 201, 'revoking frees a slot');
});

// =====================================================================================================================
// Bulk send
// =====================================================================================================================

const rowOf = (...people) => people.map(([name, email]) => ({ name, email }));

test('bulk send (JSON): one sent document per row, recipients in role order, same bulk id, folder copied; template unchanged', async () => {
  const a = await signup();
  const tpl = await template(a, ['Client', 'Witness']);
  const folder = (await a('/api/folders', { body: { name: 'Bulk' } })).data.id;
  assert.equal((await a(`/api/documents/${tpl.id}/move`, { body: { folderId: folder } })).status, 200);
  const rows = [rowOf(['Ann One', 'ANN1@example.com'], ['Wit One', 'wit1@example.com']), rowOf(['Ann Two', 'ann2@example.com'], ['Wit Two', 'wit2@example.com'])];
  const r = await a(`/api/documents/${tpl.id}/bulk`, { body: { rows } });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  assert.deepEqual(Object.keys(r.data).sort(), ['bulkId', 'created', 'documentIds', 'failed']);
  assert.equal(r.data.created, 2);
  assert.deepEqual(r.data.failed, []);
  assert.equal(r.data.documentIds.length, 2);
  for (const [i, id] of r.data.documentIds.entries()) {
    const g = await getDoc(a, id);
    assert.equal(g.doc.status, 'sent', `row ${i + 1}`);
    assert.equal(g.doc.is_template, 0);
    assert.equal(g.doc.bulk_id, r.data.bulkId);
    assert.equal(g.doc.folder_id, folder, 'folder copied');
    assert.equal(g.doc.title, tpl.title);
    const people = g.recipients.sort((x, y) => x.position - y.position).map((x) => [x.name, x.email]);
    assert.deepEqual(people, rows[i].map((p) => [p.name, p.email.toLowerCase()]), 'role order, email lowercased');
    assert.ok(g.recipients.every((x) => x.token), 'ready to sign');
  }
  const t = await getDoc(a, tpl.id);
  assert.equal(t.doc.is_template, 1);
  assert.deepEqual(t.recipients.map((x) => [x.name, x.email]), [['Client', ''], ['Witness', '']], 'template roles untouched');
  assert.equal(await total(a, '?template=0'), 2);
  // A second call gets its own bulk id.
  const r2 = await a(`/api/documents/${tpl.id}/bulk`, { body: { rows: rows.slice(0, 1) } });
  assert.equal(r2.status, 201);
  assert.notEqual(r2.data.bulkId, r.data.bulkId);
});

// Bulk send is limited to 10 counted calls per hour per user (400s and 409s count too), so each test stays at 9 or fewer
// counted calls per user: bulkUser() gives a fresh user with its own template.
const bulkUser = async (roles = ['Client', 'Witness']) => { const c = await signup(); return Object.assign(c, { tpl: await template(c, roles) }); };

test('bulk send: every row validated before anything is created (400 "Row <n>: ..."); not a template 409; other user 404; 403', async () => {
  const ok = rowOf(['A', 'a@example.com'], ['B', 'b@example.com']);
  const bulk = (c, rows, id = c.tpl.id, headers) => c(`/api/documents/${id}/bulk`, { body: { rows }, headers });
  const cases = [
    [[], 'Add at least one row'],
    [undefined, 'Add at least one row'],
    ['nope', 'Add at least one row'],
    [[ok, rowOf(['A', 'a@example.com'])], 'Row 2: Enter a name and email for each of the 2 roles'],
    [[ok, 'x'], 'Row 2: Enter a name and email for each of the 2 roles'],
    [[ok, ok, rowOf(['', 'c@example.com'], ['B', 'b@example.com'])], 'Row 3: Enter a name for Client (up to 200 characters)'],
    [[rowOf(['A', 'a@example.com'], ['x'.repeat(201), 'b@example.com'])], 'Row 1: Enter a name for Witness (up to 200 characters)'],
    [[ok, rowOf(['A', 'not-an-email'], ['B', 'b@example.com'])], 'Row 2: Enter a valid email for Client'],
    [[rowOf(['A', 'a@example.com'], ['B', 'x@evil.example,y.com'])], 'Row 1: Enter a valid email for Witness'],
    [[rowOf(['A', 'same@example.com'], ['B', 'SAME@example.com'])], 'Row 1: Each person in a row needs a different email'],
    [Array.from({ length: 501 }, () => ok), 'Bulk send takes up to 500 rows'],
  ];
  // 6 counted calls per user.
  for (let i = 0; i < cases.length; i += 6) {
    const u = await bulkUser();
    for (const [rows, msg] of cases.slice(i, i + 6)) assert.deepEqual(err(await bulk(u, rows)), [400, msg], msg);
    assert.equal(await total(u, '?template=0'), 0, 'nothing created by refused calls');
  }
  const a = await bulkUser(), b = await bulkUser();
  // Not a template.
  const d = await draft(a, [person('a')]);
  assert.deepEqual(err(await bulk(a, [rowOf(['A', 'a@example.com'])], d.id)), [409, 'Bulk send starts from a template']);
  // Another user's template; cross-origin; anonymous.
  assert.equal((await bulk(b, [ok], a.tpl.id)).status, 404);
  assert.equal((await bulk(a, [ok], a.tpl.id, { Origin: EVIL })).status, 403);
  assert.equal((await client()(`/api/documents/${a.tpl.id}/bulk`, { body: { rows: [ok] } })).status, 401);
  assert.equal(await total(a, '?template=0'), 1, 'only the draft above');
  assert.equal(await total(b, '?template=0'), 0);
  // Exactly 500 rows is allowed (a one-role template keeps this quick).
  const one = await template(a, ['Signer']);
  const r = await bulk(a, Array.from({ length: 500 }, (_, i) => rowOf([`P ${i}`, `p${i}@example.com`])), one.id);
  assert.equal(r.status, 201, JSON.stringify(r.data).slice(0, 300));
  assert.deepEqual([r.data.created, r.data.failed], [500, []]);
});

test('bulk send: 10 calls per hour per user (refused calls count), the 11th is 429 with Retry-After and creates nothing; other users unaffected', async () => {
  const a = await bulkUser(['Signer']);
  const bulk = (c, rows) => c(`/api/documents/${c.tpl.id}/bulk`, { body: { rows } });
  const good = () => [rowOf([`P ${rnd()}`, `p-${rnd()}@example.com`])];
  for (let i = 1; i <= 10; i++) {
    const r = await bulk(a, i % 2 ? good() : []);
    assert.equal(r.status, i % 2 ? 201 : 400, `call ${i}: ${JSON.stringify(r.data)}`);
  }
  const over = await bulk(a, good());
  assert.deepEqual(err(over), [429, 'Too many bulk sends. Try again later.'], '11th call');
  const wait = Number(over.headers.get('retry-after'));
  assert.ok(Number.isInteger(wait) && wait > 0 && wait <= 3600, `Retry-After ${over.headers.get('retry-after')}`);
  assert.deepEqual(err(await a(`/api/documents/${a.tpl.id}/bulk`, { body: 'P,p@example.com\n', headers: { 'Content-Type': 'text/csv' } })),
    [429, 'Too many bulk sends. Try again later.'], 'CSV too');
  assert.equal(await total(a, '?template=0'), 5, 'only the 5 accepted calls created documents');
  const b = await bulkUser(['Signer']);
  assert.equal((await bulk(b, good())).status, 201, 'another user');
});

test('bulk send (CSV): header optional, columns name,email per role; column count and empty file 400; 413; non-template 409', async () => {
  const a = await signup();
  const tpl = await template(a, ['Client', 'Witness']);
  const csv = (body, id = tpl.id) => a(`/api/documents/${id}/bulk`, { body, headers: { 'Content-Type': 'text/csv; charset=utf-8' } });
  let r = await csv('Client name,Client email,Witness name,Witness email\r\n"Lee, Jr.",lee@example.com,Wit,wit@example.com\r\n');
  assert.equal(r.status, 201, JSON.stringify(r.data));
  assert.equal(r.data.created, 1);
  assert.deepEqual((await getDoc(a, r.data.documentIds[0])).recipients.sort((x, y) => x.position - y.position).map((x) => [x.name, x.email]),
    [['Lee, Jr.', 'lee@example.com'], ['Wit', 'wit@example.com']], 'header skipped, quotes honoured');
  r = await csv('A1,a1@example.com,B1,b1@example.com\nA2,a2@example.com,B2,b2@example.com\n');
  assert.deepEqual([r.status, r.data.created, r.data.failed], [201, 2, []], 'no header');
  assert.deepEqual(err(await csv('A1,a1@example.com,B1\n')), [400, 'Row 1: expected 4 columns (name and email for each of 2 roles)']);
  assert.deepEqual(err(await csv('name,email,name,email\nA1,a1@example.com,B1,b1@example.com\nA2,a2@example.com,B2,b2@example.com,extra\n')),
    [400, 'Row 2: expected 4 columns (name and email for each of 2 roles)'], 'row numbers count data rows');
  assert.deepEqual(err(await csv('A1,bad-email,B1,b1@example.com\nA2,a2@example.com,B2,b2@example.com\n')), [400, 'Row 1: Enter a valid email for Client'],
    'a row with no @ in the email columns would be a header; here row 1 has one so it is data');
  assert.equal((await csv('')).status, 400, 'empty file');
  assert.deepEqual(err(await csv('name,email,name,email\n')), [400, 'The file has no rows']);
  assert.equal(await total(a, '?template=0'), 3);
  // A second user for the rest (bulk rate limit: at most 9 counted calls per user).
  const a2 = await bulkUser();
  const csv2 = (body, id) => a2(`/api/documents/${id}/bulk`, { body, headers: { 'Content-Type': 'text/csv' } });
  assert.equal((await csv2('x'.repeat(1048577), a2.tpl.id)).status, 413);
  const d = await draft(a2, [person('a')]);
  assert.deepEqual(err(await csv2('A,a@example.com\n', d.id)), [409, 'Bulk send starts from a template']);
  assert.equal(await total(a2, '?template=0'), 1, 'only the draft');
  // Neither JSON nor CSV, or no content type: 415 (checked on move, which is not rate limited, and once on bulk).
  assert.deepEqual(err(await a2(`/api/documents/${d.id}/move`, { body: 'folderId=x', headers: { 'Content-Type': 'text/plain' } })), [415, 'Send JSON or CSV']);
  assert.deepEqual(err(await a2(`/api/documents/${d.id}/move`, { body: new TextEncoder().encode('{"folderId":null}') })), [415, 'Send JSON or CSV'], 'no content type');
  assert.deepEqual(err(await a2(`/api/documents/${a2.tpl.id}/bulk`, { body: 'A,a@example.com\n', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })),
    [415, 'Send JSON or CSV'], 'bulk as a form');
  assert.equal(await total(a2, '?template=0'), 1, '415s created nothing');
});

test('bulk send: a failing row does not stop the others; failed lists it, created and documentIds count the rest', { skip: NEEDS_DB }, async () => {
  const a = await signup();
  const tpl = await template(a, ['Client']);
  const boom = `boom-${rnd()}@example.com`;
  // Throwaway DB: make inserting this one recipient fail, as a disk or DB error would.
  const trig = `qa_bulk_fail_${rnd()}`;
  db().exec(`CREATE TRIGGER ${trig} BEFORE INSERT ON recipients WHEN NEW.email = '${boom}' BEGIN SELECT RAISE(ABORT, 'qa forced failure'); END`);
  let r;
  try {
    r = await a(`/api/documents/${tpl.id}/bulk`, { body: { rows: [rowOf(['One', 'one@example.com']), rowOf(['Boom', boom]), rowOf(['Three', 'three@example.com'])] } });
  } finally {
    db().exec(`DROP TRIGGER IF EXISTS ${trig}`);
  }
  assert.equal(r.status, 201, JSON.stringify(r.data));
  assert.equal(r.data.created, 2);
  assert.deepEqual(r.data.failed, [{ row: 2, error: 'Something went wrong' }]);
  assert.equal(r.data.documentIds.length, 2);
  const people = await Promise.all(r.data.documentIds.map(async (id) => (await getDoc(a, id)).recipients[0].email));
  assert.deepEqual(people, ['one@example.com', 'three@example.com']);
  const rows = db().prepare('SELECT id, status FROM documents WHERE bulk_id = ?').all(r.data.bulkId);
  assert.deepEqual(rows.map((x) => x.status), ['sent', 'sent'], 'no half-made document for the failed row');
});

// =====================================================================================================================
// Public template link
// =====================================================================================================================

test('public link: enable, /t page, submit -> signUrl -> sign to completion; copy owned by the template owner', async () => {
  const owner = await signup('Pat Owner');
  const tpl = await template(owner, ['Signer']);
  const en = await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: true } });
  assert.equal(en.status, 200, JSON.stringify(en.data));
  assert.deepEqual(Object.keys(en.data), ['url']);
  assert.match(en.data.url, /^\/t\/[A-Za-z0-9_-]{43}$/);
  const token = en.data.url.slice(3);
  assert.equal((await getDoc(owner, tpl.id)).publicUrl, en.data.url);
  // The page.
  const page = await client()(en.data.url, { method: 'GET' });
  assert.equal(page.status, 200);
  const html = page.data.toString();
  assert.ok(html.includes(tpl.title) && html.includes('Pat Owner'), 'title and sender name');
  assert.match(html, /<input[^>]*name="website"[^>]*>/, 'honeypot field');
  const hp = /<input[^>]*name="website"[^>]*>/.exec(html)[0];
  assert.match(hp, /tabindex="-1"/i);
  assert.match(hp, /autocomplete="off"/i);
  // Validation.
  assert.deepEqual(err(await pub(token, { name: '', email: 'v@example.com' })), [400, 'Enter your name']);
  assert.deepEqual(err(await pub(token, { name: 'V', email: 'nope' })), [400, 'Enter a valid email address']);
  assert.equal((await pub(token, { name: 'V', email: 'v@example.com' }, randomIp(), { Origin: EVIL })).status, 403, 'same-origin check on');
  const before = await total(owner, '?template=0');
  assert.equal(before, 0, 'refused submissions created nothing');
  // Submit as a visitor.
  const visitorEmail = `Visitor-${rnd()}@Example.com`;
  const sub = await pub(token, { name: '  Vera Visitor ', email: visitorEmail, website: '' });
  assert.equal(sub.status, 200, JSON.stringify(sub.data));
  assert.deepEqual(Object.keys(sub.data), ['signUrl']);
  const signPath = new URL(sub.data.signUrl, BASE).pathname;
  assert.match(signPath, /^\/sign\/[A-Za-z0-9_-]+$/);
  const list = (await owner('/api/documents?template=0', { method: 'GET' })).data;
  assert.equal(list.total, 1, 'one new document, owned by the template owner');
  const g = await getDoc(owner, list.documents[0].id);
  assert.deepEqual([g.doc.status, g.doc.is_template, g.doc.title], ['sent', 0, tpl.title]);
  assert.deepEqual(g.recipients.map((r) => [r.name, r.email, r.role]), [['Vera Visitor', visitorEmail.toLowerCase(), 'signer']]);
  const visitor = client();
  const sp = await props(visitor, signPath);
  assert.equal(sp.state, 'sign');
  const signToken = signPath.slice('/sign/'.length);
  const done = await signAll(visitor, signToken, g.fields, g.recipients[0].id);
  assert.equal(done.status, 200, JSON.stringify(done.data));
  assert.equal((await getDoc(owner, g.doc.id)).doc.status, 'completed');
  const events = (await props(owner, `/app/documents/${g.doc.id}`)).events ?? [];
  const created = events.find((e) => e.action === 'Created from public link');
  assert.ok(created, `event "Created from public link"; got ${events.map((e) => e.action).join(', ')}`);
  assert.match(created.detail || '', /Signer name and email were entered by the signer/);
  // The template is still a template and the link still works for the next visitor.
  assert.equal((await getDoc(owner, tpl.id)).doc.is_template, 1);
  assert.equal((await pub(token, { name: 'Second', email: `second-${rnd()}@example.com` })).status, 200);
  assert.equal(await total(owner, '?template=0'), 2);
});

test('public link: rules (template only, exactly one signer), rotation, disable kills the link, saving a 2-signer template disables it, 404, honeypot', async () => {
  const owner = await signup(), other = await signup();
  const d = await draft(owner, [person('a')]);
  assert.deepEqual(err(await owner(`/api/documents/${d.id}/public`, { body: { enabled: true } })), [409, 'Only templates can have a public link']);
  const two = await template(owner, ['Client', 'Witness']);
  assert.deepEqual(err(await owner(`/api/documents/${two.id}/public`, { body: { enabled: true } })), [400, 'A public link needs a template with exactly one signer']);
  const tpl = await template(owner, ['Signer']);
  assert.equal((await other(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).status, 404, 'other user');
  assert.equal((await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: true }, headers: { Origin: EVIL } })).status, 403);
  assert.equal((await getDoc(owner, tpl.id)).publicUrl, null, 'refused requests enabled nothing');
  const t1 = (await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).data.url.slice(3);
  // Rotation: enabling again issues a new token; the old one is dead.
  const t2 = (await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).data.url.slice(3);
  assert.notEqual(t1, t2);
  assert.deepEqual(err(await pub(t1, { name: 'Old', email: 'old@example.com' })), [404, 'This link is not active']);
  assert.equal((await client()(`/t/${t1}`, { method: 'GET' })).status, 404);
  assert.equal((await client()(`/t/${t2}`, { method: 'GET' })).status, 200);
  // Honeypot: 200 { ok: true }, nothing created.
  const hp = await pub(t2, { name: 'Bot', email: 'bot@example.com', website: 'http://spam.example' });
  assert.deepEqual([hp.status, hp.data], [200, { ok: true }]);
  assert.equal(await total(owner, '?template=0'), 1, 'only the draft');
  // Disable.
  assert.deepEqual((await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: false } })).data, { ok: true });
  assert.equal((await getDoc(owner, tpl.id)).publicUrl, null);
  assert.deepEqual(err(await pub(t2, { name: 'Late', email: 'late@example.com' })), [404, 'This link is not active']);
  const dead = await client()(`/t/${t2}`, { method: 'GET' });
  assert.equal(dead.status, 404);
  assert.ok(dead.data.toString().includes('This link is not active'), 'calm 404 page');
  assert.deepEqual((await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: false } })).data, { ok: true }, 'disable twice');
  // Saving the template with two signers turns the link off.
  const t3 = (await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).data.url.slice(3);
  assert.equal((await client()(`/t/${t3}`, { method: 'GET' })).status, 200);
  const recipients = [{ id: 'x', name: 'Client', email: '', role: 'signer' }, { id: 'y', name: 'Witness', email: '', role: 'signer' }];
  assert.equal((await owner(`/api/documents/${tpl.id}`, { method: 'PUT', body: { recipients, fields: [field('x'), field('y', 1)] } })).status, 200);
  assert.equal((await getDoc(owner, tpl.id)).publicUrl, null, 'link off after saving a 2-signer template');
  assert.deepEqual(err(await pub(t3, { name: 'X', email: 'x@example.com' })), [404, 'This link is not active']);
  // Unknown and malformed tokens.
  for (const t of [crypto.randomBytes(32).toString('base64url'), 'x', 'a'.repeat(200)]) {
    assert.deepEqual(err(await pub(t, { name: 'X', email: 'x@example.com' })), [404, 'This link is not active'], `token ${t.slice(0, 10)}`);
    assert.equal((await client()(`/t/${t}`, { method: 'GET' })).status, 404);
  }
  // Deleting the template kills the link.
  const tpl2 = await template(owner, ['Signer']);
  const t4 = (await owner(`/api/documents/${tpl2.id}/public`, { body: { enabled: true } })).data.url.slice(3);
  assert.equal((await owner(`/api/documents/${tpl2.id}`, { method: 'DELETE' })).status, 200);
  assert.deepEqual(err(await pub(t4, { name: 'X', email: 'x@example.com' })), [404, 'This link is not active']);
});

test('public link: token stored as hash + encrypted (AAD public:<id>), never in plaintext', { skip: NEEDS_DB }, async () => {
  const owner = await signup();
  const tpl = await template(owner, ['Signer']);
  const token = (await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).data.url.slice(3);
  const row = db().prepare('SELECT public_enabled, public_token_hash, public_token_enc FROM documents WHERE id = ?').get(tpl.id);
  assert.equal(row.public_enabled, 1);
  assert.equal(row.public_token_hash, crypto.createHash('sha256').update(token).digest('hex'));
  assert.equal(decText(row.public_token_enc, `public:${tpl.id}`), token);
  assert.ok(!row.public_token_enc.includes(token));
  assert.equal((await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: false } })).status, 200);
  assert.deepEqual({ ...db().prepare('SELECT public_enabled, public_token_hash, public_token_enc FROM documents WHERE id = ?').get(tpl.id) },
    { public_enabled: 0, public_token_hash: null, public_token_enc: null });
});

test('public link: a template that cannot be sent (no signature field) cannot be enabled (400), and nothing is enabled', async () => {
  const owner = await signup();
  const id = await upload(owner, true);
  const put = await owner(`/api/documents/${id}`, { method: 'PUT', body: { title: `NoSig ${rnd()}`, recipients: [{ id: 'r0', name: 'Signer', email: '', role: 'signer' }], fields: [] } });
  assert.equal(put.status, 200, JSON.stringify(put.data));
  const r = await owner(`/api/documents/${id}/public`, { body: { enabled: true } });
  assert.equal(r.status, 400, JSON.stringify(r.data));
  assert.equal(typeof r.data.error, 'string');
  assert.equal((await getDoc(owner, id)).publicUrl, null);
});

test('public link: removing the template\'s signature field turns the link off', async () => {
  const owner = await signup();
  const tpl = await template(owner, ['Signer']);
  const token = (await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).data.url.slice(3);
  assert.equal((await client()(`/t/${token}`, { method: 'GET' })).status, 200);
  const put = await owner(`/api/documents/${tpl.id}`, { method: 'PUT', body: { recipients: [{ id: 'r0', name: 'Signer', email: '', role: 'signer' }], fields: [] } });
  assert.equal(put.status, 200, JSON.stringify(put.data));
  assert.equal((await getDoc(owner, tpl.id)).publicUrl, null);
  assert.deepEqual(err(await pub(token, { name: 'X', email: `x-${rnd()}@example.com` })), [404, 'This link is not active']);
  assert.equal((await client()(`/t/${token}`, { method: 'GET' })).status, 404);
  assert.equal(await total(owner, '?template=0'), 0);
});

test('public link: the copy expires after 1 day when the template has no expiry; a template expiry is kept', async () => {
  const owner = await signup();
  const copyOf = async (tpl) => {
    const token = (await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).data.url.slice(3);
    const t0 = Date.now();
    const sub = await pub(token, { name: 'Exp Visitor', email: `exp-${rnd()}@example.com` });
    assert.equal(sub.status, 200, JSON.stringify(sub.data));
    const list = (await owner('/api/documents?template=0', { method: 'GET' })).data.documents;
    return { t0, doc: (await getDoc(owner, list[0].id)).doc };
  };
  const none = await template(owner, ['Signer']);
  const a = await copyOf(none);
  assert.equal(a.doc.expire_days, 1);
  const left = Date.parse(a.doc.expires_at) - a.t0;
  assert.ok(left > 864e5 - 120_000 && left <= 864e5 + 120_000, `expires_at about 1 day after creation: ${a.doc.expires_at}`);
  assert.equal((await getDoc(owner, none.id)).doc.expire_days, 0, 'template itself unchanged');
  const seven = await template(owner, ['Signer']);
  assert.equal((await owner(`/api/documents/${seven.id}`, { method: 'PUT', body: { recipients: [{ id: 'r0', name: 'Signer', email: '', role: 'signer' }], fields: [field('r0')], expireDays: 7 } })).status, 200);
  const b = await copyOf(seven);
  assert.equal(b.doc.expire_days, 7);
});

test('public link: 50 documents per link per day, then 429 with Retry-After; other templates and a rotated link unaffected', { skip: !LOOPBACK && 'needs a loopback BASE_URL to pick source IPs', timeout: 120_000 }, async () => {
  const owner = await signup();
  const tpl = await template(owner, ['Signer']);
  const token = (await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).data.url.slice(3);
  for (let i = 1; i <= 50; i++) {
    const r = await pub(token, { name: `V ${i}`, email: `cap${i}-${rnd()}@example.com` });
    assert.equal(r.status, 200, `submission ${i}: ${JSON.stringify(r.data)}`);
  }
  const over = await pub(token, { name: 'V 51', email: `cap51-${rnd()}@example.com` });
  assert.deepEqual(err(over), [429, 'Too many requests. Try again later.'], '51st on this template');
  const wait = Number(over.headers['retry-after']);
  assert.ok(Number.isInteger(wait) && wait > 0 && wait <= 86400, `Retry-After ${over.headers['retry-after']}`);
  assert.equal(await total(owner, '?template=0'), 50, 'nothing created over the cap');
  const other = await template(owner, ['Signer']);
  const t2 = (await owner(`/api/documents/${other.id}/public`, { body: { enabled: true } })).data.url.slice(3);
  assert.equal((await pub(t2, { name: 'Other', email: `other-${rnd()}@example.com` })).status, 200, 'cap is per template');
  // The budget is per link: rotating the link starts a new one.
  const rotated = (await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).data.url.slice(3);
  assert.equal((await pub(rotated, { name: 'After rotate', email: `rot-${rnd()}@example.com` })).status, 200, 'new link, new budget');
  assert.deepEqual(err(await pub(token, { name: 'Old', email: `old-${rnd()}@example.com` })), [404, 'This link is not active'], 'old link dead');
});

test('bulk send Idempotency-Key: 8-64 chars [A-Za-z0-9_-]; bad key 400; reuse by the same owner 409 and creates nothing; other owners unaffected', async () => {
  const a = await signup(), b = await signup();
  const tpl = await template(a, ['Signer']);
  const tplB = await template(b, ['Signer']);
  const row = () => [rowOf([`P ${rnd()}`, `p-${rnd()}@example.com`])];
  const bulk = (c, id, k, body = { rows: row() }) => c(`/api/documents/${id}/bulk`, { body, headers: k === undefined ? {} : { 'Idempotency-Key': k } });
  // Bad keys on their own user (bulk rate limit: at most 9 counted calls per user); a then makes 7.
  const c = await bulkUser(['Signer']);
  for (const k of ['short12', 'x'.repeat(65), 'bad key!', 'has.dot1', 'key/slash1']) {
    assert.deepEqual(err(await bulk(c, c.tpl.id, k)), [400, 'Invalid Idempotency-Key'], `key "${k.slice(0, 20)}"`);
  }
  assert.equal(await total(c, '?template=0'), 0, 'bad keys created nothing');
  const k8 = `k${rnd().slice(0, 7)}`, k64 = `A-_${rnd()}`.padEnd(64, 'z');
  assert.equal(k8.length, 8);
  const first = await bulk(a, tpl.id, k8);
  assert.equal(first.status, 201, JSON.stringify(first.data));
  assert.equal((await bulk(a, tpl.id, k64)).status, 201, '64 chars');
  assert.deepEqual(err(await bulk(a, tpl.id, k8)), [409, 'This bulk send was already started']);
  const other = await template(a, ['Signer']);
  assert.deepEqual(err(await bulk(a, other.id, k8)), [409, 'This bulk send was already started'], 'same owner, another template');
  assert.deepEqual(err(await a(`/api/documents/${tpl.id}/bulk`, { body: `CSV P,csv-${rnd()}@example.com\n`, headers: { 'Content-Type': 'text/csv', 'Idempotency-Key': k8 } })),
    [409, 'This bulk send was already started'], 'CSV too');
  assert.equal(await total(a, '?template=0'), 2, 'reuses created nothing');
  assert.equal((await bulk(b, tplB.id, k8)).status, 201, 'another owner may use the same key');
  assert.equal((await bulk(a, tpl.id, undefined)).status, 201, 'no key: no idempotency check');
  assert.equal((await bulk(a, tpl.id, undefined)).status, 201);
});

test('public link: 10 submissions per hour per IP (honeypot hits count), then 429 with Retry-After; another IP still works', { skip: !LOOPBACK && 'needs a loopback BASE_URL to pick source IPs' }, async () => {
  const owner = await signup();
  const tpl = await template(owner, ['Signer']);
  const token = (await owner(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).data.url.slice(3);
  const ip = randomIp();
  for (let i = 1; i <= 10; i++) assert.equal((await pub(token, { name: 'Bot', email: 'b@example.com', website: 'x' }, ip)).status, 200, `submission ${i}`);
  const r = await pub(token, { name: 'Real', email: `real-${rnd()}@example.com` }, ip);
  assert.deepEqual(err(r), [429, 'Too many requests. Try again later.']);
  const wait = Number(r.headers['retry-after']);
  assert.ok(Number.isInteger(wait) && wait > 0 && wait <= 3600, `Retry-After ${r.headers['retry-after']}`);
  assert.equal((await pub(crypto.randomBytes(32).toString('base64url'), { name: 'P', email: 'p@example.com' }, ip)).status, 429, 'probing unknown tokens is limited too');
  assert.equal((await pub(token, { name: 'Other', email: `o-${rnd()}@example.com` })).status, 200, 'another IP');
});

// =====================================================================================================================
// Webhooks
// =====================================================================================================================

test('webhooks: create (secret once), list, validation, update, delete, per user, 10 per user, session only', async () => {
  const a = await signup(), b = await signup();
  const g = (await a('/api/webhooks', { method: 'GET' })).data;
  assert.deepEqual(g, { webhooks: [], events: EVENTS });
  const c = await a('/api/webhooks', { body: { url: 'https://example.com/hooks', events: ['document.sent', 'document.sent', 'document.completed'] } });
  assert.equal(c.status, 201, JSON.stringify(c.data));
  assert.deepEqual(Object.keys(c.data).sort(), ['id', 'secret']);
  assert.match(c.data.secret, /^whsec_[A-Za-z0-9_-]{43}$/);
  const [w] = (await a('/api/webhooks', { method: 'GET' })).data.webhooks;
  assert.deepEqual(Object.keys(w).sort(), ['active', 'createdAt', 'events', 'failureCount', 'id', 'url']);
  assert.deepEqual([w.id, w.url, w.events, w.active, w.failureCount], [c.data.id, 'https://example.com/hooks', ['document.sent', 'document.completed'], true, 0]);
  assert.ok(!JSON.stringify((await a('/api/webhooks', { method: 'GET' })).data).includes(c.data.secret.slice(6)), 'secret never listed');
  const make = (body) => a('/api/webhooks', { body });
  for (const [body, msg] of [
    [{ url: 'https://example.com/h', events: [] }, 'Choose at least one event'],
    [{ url: 'https://example.com/h' }, 'Choose at least one event'],
    [{ url: 'https://example.com/h', events: 'document.sent' }, 'Choose at least one event'],
    [{ url: 'https://example.com/h', events: ['ping'] }, 'Unknown event'],
    [{ url: 'https://example.com/h', events: ['document.sent', 'nope'] }, 'Unknown event'],
    [{ url: '', events: ['document.sent'] }, 'Enter a URL'],
    [{ events: ['document.sent'] }, 'Enter a URL'],
    [{ url: 'not a url', events: ['document.sent'] }, 'Enter a valid URL'],
    [{ url: 'https://user:pass@example.com/h', events: ['document.sent'] }, 'Remove the user name and password from the URL'],
    [{ url: `https://example.com/${'x'.repeat(490)}`, events: ['document.sent'] }, 'Use a URL of at most 500 characters'],
  ]) assert.deepEqual(err(await make(body)), [400, msg], JSON.stringify(body).slice(0, 80));
  for (const url of ['ftp://example.com/h', 'javascript:alert(1)', 'file:///etc/passwd']) assert.equal((await make({ url, events: ['document.sent'] })).status, 400, url);
  // Update.
  assert.deepEqual((await a(`/api/webhooks/${w.id}`, { method: 'PUT', body: { active: false } })).data, { ok: true });
  assert.equal((await a('/api/webhooks', { method: 'GET' })).data.webhooks[0].active, false);
  assert.deepEqual((await a(`/api/webhooks/${w.id}`, { method: 'PUT', body: { url: 'https://example.org/new', events: ['document.voided'], active: true } })).data, { ok: true });
  const w2 = (await a('/api/webhooks', { method: 'GET' })).data.webhooks[0];
  assert.deepEqual([w2.url, w2.events, w2.active], ['https://example.org/new', ['document.voided'], true]);
  assert.deepEqual(err(await a(`/api/webhooks/${w.id}`, { method: 'PUT', body: { events: [] } })), [400, 'Choose at least one event']);
  assert.equal((await a(`/api/webhooks/${w.id}`, { method: 'PUT', body: { url: 'ftp://x' } })).status, 400);
  // Per user: 404 everywhere for b; b's list is empty.
  for (const [p, method, body] of [[`/api/webhooks/${w.id}`, 'PUT', { active: false }], [`/api/webhooks/${w.id}`, 'DELETE'], [`/api/webhooks/${w.id}/test`, 'POST', {}], [`/api/webhooks/${w.id}/deliveries`, 'GET']]) {
    assert.deepEqual(err(await b(p, { method, body })), [404, 'Webhook not found'], `${method} ${p}`);
  }
  assert.deepEqual((await b('/api/webhooks', { method: 'GET' })).data.webhooks, []);
  assert.equal((await a('/api/webhooks', { method: 'GET' })).data.webhooks[0].active, true, 'b changed nothing');
  // Session only and same-origin.
  const k = bearer((await a('/api/api-keys', { body: { name: 'k' } })).data.key);
  for (const [p, method] of [[`/api/webhooks/${w.id}`, 'PUT'], [`/api/webhooks/${w.id}/test`, 'POST'], [`/api/webhooks/${w.id}/deliveries`, 'GET'], [`/api/webhooks/${w.id}`, 'DELETE']]) {
    assert.deepEqual(err(await k(p, { method, body: method === 'GET' ? undefined : {} })), [401, 'API keys cannot be used here'], `${method} ${p}`);
  }
  assert.equal((await a('/api/webhooks', { body: { url: 'https://example.com/h', events: ['document.sent'] }, headers: { Origin: EVIL } })).status, 403);
  assert.equal((await a(`/api/webhooks/${w.id}`, { method: 'DELETE', headers: { Origin: EVIL } })).status, 403);
  assert.equal((await client()('/api/webhooks', { method: 'GET' })).status, 401);
  // Cap: 10.
  for (let i = 1; i < 10; i++) assert.equal((await make({ url: `https://example.com/h${i}`, events: ['document.sent'] })).status, 201, `webhook ${i + 1}`);
  assert.deepEqual(err(await make({ url: 'https://example.com/h11', events: ['document.sent'] })), [409, 'You can have up to 10 webhooks']);
  // Delete.
  assert.deepEqual((await a(`/api/webhooks/${w.id}`, { method: 'DELETE' })).data, { ok: true });
  assert.equal((await a(`/api/webhooks/${w.id}`, { method: 'DELETE' })).status, 404);
  assert.equal((await a('/api/webhooks', { method: 'GET' })).data.webhooks.length, 9);
});

test('webhooks: secret encrypted at rest (AAD webhook:<id>); re-activating resets failureCount', { skip: NEEDS_DB }, async () => {
  const a = await signup();
  const { id, secret } = (await a('/api/webhooks', { body: { url: 'https://example.com/h', events: ['document.sent'] } })).data;
  const row = db().prepare('SELECT secret_enc FROM webhooks WHERE id = ?').get(id);
  assert.ok(!row.secret_enc.includes(secret.slice(6)));
  assert.equal(decText(row.secret_enc, `webhook:${id}`), secret);
  db().prepare('UPDATE webhooks SET active = 0, failure_count = 20 WHERE id = ?').run(id);
  assert.equal((await a('/api/webhooks', { method: 'GET' })).data.webhooks[0].failureCount, 20);
  assert.equal((await a(`/api/webhooks/${id}`, { method: 'PUT', body: { events: ['document.sent', 'document.voided'] } })).status, 200);
  assert.equal((await a('/api/webhooks', { method: 'GET' })).data.webhooks[0].failureCount, 20, 'editing an inactive webhook keeps the count');
  assert.equal((await a(`/api/webhooks/${id}`, { method: 'PUT', body: { active: true } })).status, 200);
  const w = (await a('/api/webhooks', { method: 'GET' })).data.webhooks[0];
  assert.deepEqual([w.active, w.failureCount], [true, 0]);
});

test('webhooks: signed deliveries for a full signing flow, document.sent -> recipient.viewed -> recipient.signed -> document.completed', { skip: WEBHOOKS_OFF, timeout: 400_000 }, async (t) => {
  const owner = await signup('Hook Owner');
  const p = `/ok/flow-${rnd()}`, pOther = `/ok/other-${rnd()}`, pOff = `/ok/off-${rnd()}`;
  const flow = ['document.sent', 'recipient.viewed', 'recipient.signed', 'document.completed'];
  const w = (await owner('/api/webhooks', { body: { url: HOOK + p, events: flow } })).data;
  await owner('/api/webhooks', { body: { url: HOOK + pOther, events: ['document.voided', 'recipient.declined'] } });
  const off = (await owner('/api/webhooks', { body: { url: HOOK + pOff, events: flow } })).data;
  assert.equal((await owner(`/api/webhooks/${off.id}`, { method: 'PUT', body: { active: false } })).status, 200);
  // Another user's webhook never hears about this owner's documents.
  const stranger = await signup();
  const pStranger = `/ok/stranger-${rnd()}`;
  await stranger('/api/webhooks', { body: { url: HOOK + pStranger, events: flow } });

  const d = await sent(owner, [person('a')]);
  const e1 = await hookEvent(p, 'document.sent', d.id);
  const page = await props(client(), `/sign/${d.tokens[0]}`);
  assert.equal(page.state, 'sign');
  const e2 = await hookEvent(p, 'recipient.viewed', d.id);
  const signed = await signAll(client(), d.tokens[0], d.fields, d.recipients[0].id);
  assert.equal(signed.status, 200, JSON.stringify(signed.data));
  const e3 = await hookEvent(p, 'recipient.signed', d.id);
  const e4 = await hookEvent(p, 'document.completed', d.id);
  const mine = hits(p).filter((x) => x.json?.data?.document?.id === d.id);
  assert.deepEqual(mine.map((x) => x.json.event).sort(), [...flow].sort(), 'each event exactly once');
  // Arrival order: sent and viewed were awaited one step at a time; signed and completed are queued together, so their
  // arrival order is recorded, and their payload createdAt must be in sequence.
  assert.deepEqual(mine.slice(0, 2).map((x) => x.json.event), flow.slice(0, 2));
  t.diagnostic(`arrival order: ${mine.map((x) => x.json.event).join(' -> ')}`);
  const at = [e1, e2, e3, e4].map((x) => Date.parse(x.json.createdAt));
  assert.ok(at.every((v, i) => i === 0 || v >= at[i - 1]), `createdAt in sequence: ${[e1, e2, e3, e4].map((x) => x.json.createdAt).join(', ')}`);
  for (const hit of [e1, e2, e3, e4]) {
    checkSignature(hit, w.secret);
    const { data } = hit.json;
    assert.deepEqual(data.document, { id: d.id, title: d.title, status: hit.json.event === 'document.completed' || hit.json.event === 'recipient.signed' ? 'completed' : 'sent' }, hit.json.event);
    if (hit.json.event.startsWith('recipient.')) {
      assert.deepEqual(Object.keys(data).sort(), ['document', 'recipient']);
      assert.deepEqual(data.recipient, { id: d.recipients[0].id, name: d.recipients[0].name, email: d.recipients[0].email, role: 'signer', status: hit.json.event === 'recipient.viewed' ? 'viewed' : 'signed' });
    } else assert.deepEqual(Object.keys(data), ['document']);
    assert.ok(!hit.body.includes(d.tokens[0]), 'no signing token');
    assert.ok(!hit.body.includes(PNG.slice(30)), 'no signature image');
  }
  // Unsubscribed, inactive and other owners' webhooks got nothing.
  await sleep(2000);
  assert.equal(hits(pOther).length, 0, 'not subscribed');
  assert.equal(hits(pOff).length, 0, 'inactive');
  assert.equal(hits(pStranger).length, 0, 'other owner');
  assert.deepEqual((await owner(`/api/webhooks/${off.id}/deliveries`, { method: 'GET' })).data, { deliveries: [] }, 'nothing queued for an inactive webhook');
  // Delivery log.
  const log = await waitFor(async () => {
    const r = (await owner(`/api/webhooks/${w.id}/deliveries`, { method: 'GET' })).data.deliveries;
    return r.length === 4 && r.every((x) => x.status === 'delivered') && r;
  }, 'four delivered rows in the log', 10_000);
  for (const x of log) {
    assert.deepEqual(Object.keys(x).sort(), ['attempts', 'createdAt', 'deliveredAt', 'event', 'id', 'lastError', 'lastStatusCode', 'status']);
    assert.deepEqual([x.attempts, x.lastStatusCode, x.lastError], [1, 200, null], x.event);
    assert.ok(x.deliveredAt);
  }
  assert.deepEqual(log.map((x) => x.id).sort(), mine.map((x) => x.json.id).sort(), 'log ids = Countersign-Delivery ids');
  // Void and decline on the other webhook.
  const v = await sent(owner, [person('v')]);
  assert.equal((await owner(`/api/documents/${v.id}/void`, { body: { reason: 'test' } })).status, 200);
  const ev = await hookEvent(pOther, 'document.voided', v.id);
  assert.equal(ev.json.data.document.status, 'voided');
  const dc = await sent(owner, [person('c')]);
  assert.equal((await client()(`/api/sign/${dc.tokens[0]}/decline`, { body: { reason: 'no' } })).status, 200);
  const ed = await hookEvent(pOther, 'recipient.declined', dc.id);
  assert.equal(ed.json.data.recipient.status, 'declined');
  await sleep(1500);
  assert.ok(!hits(pOther).some((x) => ['document.sent', 'document.declined'].includes(x.json?.event)), 'only subscribed events');
});

test('webhooks: test ping is signed and logged; 500 and 3xx are failures with a retry pending, redirects are not followed', { skip: WEBHOOKS_OFF, timeout: 300_000 }, async () => {
  const a = await signup();
  const p = `/ok/ping-${rnd()}`;
  const w = (await a('/api/webhooks', { body: { url: HOOK + p, events: ['document.sent'] } })).data;
  assert.deepEqual((await a(`/api/webhooks/${w.id}/test`, { body: {} })).data, { ok: true });
  const ping = await hookEvent(p, 'ping');
  checkSignature(ping, w.secret);
  assert.deepEqual(ping.json.data, {});
  const log = await waitFor(async () => {
    const r = (await a(`/api/webhooks/${w.id}/deliveries`, { method: 'GET' })).data.deliveries;
    return r[0]?.status === 'delivered' && r;
  }, 'ping delivered in the log', 10_000);
  assert.deepEqual(log.map((x) => [x.id, x.event, x.status, x.attempts, x.lastStatusCode]), [[ping.json.id, 'ping', 'delivered', 1, 200]]);
  assert.equal((await a(`/api/webhooks/${w.id}/test`, { body: {}, headers: { Origin: EVIL } })).status, 403);

  for (const [kind, code] of [['fail', 500], ['redirect', 302]]) {
    const fp = `/${kind}-${rnd()}`;
    const fw = (await a('/api/webhooks', { body: { url: HOOK + fp, events: ['document.sent'] } })).data;
    assert.equal((await a(`/api/webhooks/${fw.id}/test`, { body: {} })).status, 200);
    await hookEvent(fp, 'ping');
    const [row] = await waitFor(async () => {
      const r = (await a(`/api/webhooks/${fw.id}/deliveries`, { method: 'GET' })).data.deliveries;
      return r[0]?.attempts === 1 && r;
    }, `${kind} attempt logged`, 10_000);
    assert.deepEqual([row.status, row.attempts, row.lastStatusCode, row.lastError, row.deliveredAt], ['pending', 1, code, `HTTP ${code}`, null], kind);
    assert.equal(hits(fp).length, 1, `${kind}: one attempt, retry not yet due`);
  }
  await sleep(1000);
  assert.equal(hits('/ok/followed').length, 0, 'redirect not followed');
  if (DATA) {
    const next = db().prepare("SELECT d.next_attempt_at FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id WHERE w.url LIKE ? AND d.status = 'pending'").all(`${HOOK}/fail-%`);
    assert.ok(next.length >= 1);
    for (const n of next) {
      const wait = Date.parse(n.next_attempt_at) - Date.now();
      assert.ok(wait > 0 && wait <= 60_000, `retry after about 1 minute, got ${wait} ms`);
    }
  }
});

// =====================================================================================================================
// Pages (SSR)
// =====================================================================================================================

test('pages render: /app?folder=, /app/settings, template editor with public link, /t/<token>; no server errors logged', async () => {
  const a = await signup('Page Owner');
  const folderName = `Folder ${rnd()}`;
  const folder = (await a('/api/folders', { body: { name: folderName } })).data.id;
  const tpl = await template(a, ['Signer']);
  assert.equal((await a(`/api/documents/${tpl.id}/move`, { body: { folderId: folder } })).status, 200);
  const url = (await a(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).data.url;
  // Settings loads keys and webhooks in the browser; SSR renders the sections only.
  for (const [p, must] of [[`/app?folder=${folder}`, [folderName]], ['/app', [folderName]],
    ['/app/settings', ['API keys', 'Webhooks']], [`/app/documents/${tpl.id}/edit`, [tpl.title, url, 'Public link']], [url, [tpl.title, 'Page Owner']]]) {
    const r = await (p.startsWith('/t/') ? client() : a)(p, { method: 'GET' });
    const html = r.data.toString();
    assert.equal(r.status, 200, `${p}: status ${r.status}`);
    assert.ok(!/Internal Server Error|Application error/i.test(html), `${p}: error page`);
    for (const s of must) assert.ok(html.includes(s), `${p}: contains ${s}`);
  }
  // An unknown folder id sends the dashboard back to the unfiltered view.
  const unknown = await a(`/app?folder=${crypto.randomUUID()}`, { method: 'GET' });
  assert.deepEqual([unknown.status, unknown.headers.get('location')], [307, '/app']);
  if (process.env.SERVER_LOG) {
    const log = fs.readFileSync(process.env.SERVER_LOG, 'utf8');
    assert.ok(!/Webhook (delivery failed|event not queued|not queued)|TypeError|ReferenceError/.test(log), `server log has errors:\n${log.split('\n').filter((l) => /Error|failed/.test(l)).slice(0, 20).join('\n')}`);
  }
});
