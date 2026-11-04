// Self-check for API keys (lib/apikeys.js, api() in lib/http.js), folders (lib/folders.js), webhooks (lib/webhooks.js)
// and the bulk-send CSV mapping (csvBulkRows in lib/http.js).
// Run: node scripts/tier3-selfcheck.mjs   (uses a throwaway DATA_DIR and key; starts a local receiver on 127.0.0.1)
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-tier3-'));
process.env.DATA_DIR = dir;
process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
delete process.env.WEBHOOK_ALLOW_PRIVATE;
delete process.env.WEBHOOK_ALLOW_HTTP;
console.log = () => {}; // security-log JSON lines

const { api, csvBulkRows } = await import('../lib/http.js');
const { createKey, hashKey, listKeys, newKey, revokeKey, KEYS_MAX } = await import('../lib/apikeys.js');
const { createFolder, deleteFolder, listDocuments, listFolders, moveDocument, renameFolder } = await import('../lib/folders.js');
const wh = await import('../lib/webhooks.js');
const { createUser, startSession, purgeExpired } = await import('../lib/auth.js');
const { default: db, now } = await import('../lib/db.js');

const status = (fn) => { try { fn(); } catch (e) { return e.status; } return 0; };
const errorOf = (fn) => { try { fn(); } catch (e) { return e.message; } return null; };

// --- Blocked address ranges.
for (const ip of ['127.0.0.1', '127.255.255.254', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1',
  '100.127.255.255', '0.0.0.0', '0.1.2.3', '224.0.0.1', '239.255.255.250', '255.255.255.255', '240.0.0.1', '198.18.0.1',
  '::1', '::', '::127.0.0.1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:10.0.0.1', '::ffff:169.254.169.254', '[::1]',
  'fe80::1', 'fe80::1%eth0', 'febf::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '64:ff9b::7f00:1', '::ffff:0:7f00:1', '2002:7f00:1::1',
  '2001::1', '100::1', 'not-an-ip', '']) {
  assert.equal(wh.blockedAddress(ip), true, `${ip} must be blocked`);
}
for (const ip of ['8.8.8.8', '1.1.1.1', '172.15.255.255', '172.32.0.1', '100.63.255.255', '100.128.0.1', '192.169.0.1', '169.255.0.1',
  '::ffff:8.8.8.8', '2001:4860:4860::8888', '2606:4700:4700::1111']) {
  assert.equal(wh.blockedAddress(ip), false, `${ip} must be allowed`);
}

// --- URL validation at create.
assert.equal(wh.checkUrl('https://example.com/hook'), 'https://example.com/hook');
assert.equal(errorOf(() => wh.checkUrl('http://example.com/hook')), 'Use an https:// URL');
assert.equal(errorOf(() => wh.checkUrl('https://user:pw@example.com/')), 'Remove the user name and password from the URL');
for (const u of ['https://127.0.0.1/', 'https://[::1]/', 'https://[::ffff:127.0.0.1]/', 'https://0x7f.1/', 'https://2130706433/', 'https://169.254.169.254/latest'])
  assert.equal(errorOf(() => wh.checkUrl(u)), 'This address is not allowed', u);
assert.equal(status(() => wh.checkUrl(`https://example.com/${'a'.repeat(500)}`)), 400);
assert.equal(status(() => wh.checkUrl('ftp://example.com/')), 400);
assert.equal(status(() => wh.checkUrl('nonsense')), 400);

// --- Signature format and HMAC.
const sig = wh.signature('whsec_test', '{"a":1}', 1700000000);
assert.match(sig, /^t=1700000000,v1=[0-9a-f]{64}$/);
assert.equal(sig.split('v1=')[1], crypto.createHmac('sha256', 'whsec_test').update('1700000000.{"a":1}').digest('hex'));

// --- Key format and hashing.
const k = newKey();
assert.match(k, /^cs_[A-Za-z0-9_-]{43}$/);
assert.notEqual(newKey(), k);
assert.match(hashKey(k), /^[0-9a-f]{64}$/);
assert.equal(hashKey(k), hashKey(k));
assert.notEqual(hashKey(k), crypto.createHash('sha256').update(k).digest('hex')); // keyed, not plain SHA-256

// --- Bulk CSV row mapping.
assert.deepEqual(csvBulkRows('A,a@x.io,B,b@x.io\n', 2), [[{ name: 'A', email: 'a@x.io' }, { name: 'B', email: 'b@x.io' }]]);
assert.deepEqual(csvBulkRows('Client name,Client email\r\n" Ann ",ann@x.io\r\nBob,bob@x.io', 1),
  [[{ name: 'Ann', email: 'ann@x.io' }], [{ name: 'Bob', email: 'bob@x.io' }]]);
assert.deepEqual(csvBulkRows('Ann,ann@x.io', 1), [[{ name: 'Ann', email: 'ann@x.io' }]]); // no header
assert.equal(errorOf(() => csvBulkRows('A,a@x.io\nB,b@x.io,extra\n', 1)), 'Row 2: expected 2 columns (name and email for each of 1 roles)');
assert.equal(errorOf(() => csvBulkRows('name,email\n', 1)), 'The file has no rows');
assert.equal(errorOf(() => csvBulkRows('', 1)), 'The file has no rows');
assert.equal(csvBulkRows('A,a@x.io\n'.repeat(500), 1).length, 500);
assert.equal(csvBulkRows('name,email\n' + 'A,a@x.io\n'.repeat(500), 1).length, 500); // header doesn't count
assert.equal(status(() => csvBulkRows('A,a@x.io\n'.repeat(501), 1)), 400);

// --- DB-backed: keys, folders, documents list, webhooks.
const alice = { id: createUser({ email: 'alice@x.io', name: 'Alice', passwordHash: 'x' }), email: 'alice@x.io', name: 'Alice' };
const bob = { id: createUser({ email: 'bob@x.io', name: 'Bob', passwordHash: 'x' }), email: 'bob@x.io', name: 'Bob' };
const fakeReq = (headers = {}, method = 'GET') => ({ method, headers: { host: 'app.test', ...headers }, socket: { remoteAddress: '127.0.0.1' }, cookies: {} });
function fakeRes() {
  const r = { code: 200, headers: {}, body: null, headersSent: false };
  r.status = (c) => { r.code = c; return r; };
  r.json = (b) => { r.body = b; r.headersSent = true; return r; };
  r.setHeader = (n, v) => { r.headers[n.toLowerCase()] = v; };
  return r;
}
const call = async (route, req) => { const res = fakeRes(); await route(req, res); return res; };
const whoami = (opts) => api({ GET: (req, res, user) => res.json({ id: user.id }), POST: (req, res, user) => res.json({ id: user.id }) }, opts);

const { id: keyId, key } = createKey(alice, { name: 'CI' }, fakeReq());
assert.equal(status(() => createKey(alice, { name: '  ' }, fakeReq())), 400);
assert.equal(status(() => createKey(alice, { name: 'x'.repeat(81) }, fakeReq())), 400);
assert.deepEqual(listKeys(alice.id).map((x) => [x.id, x.prefix]), [[keyId, key.slice(0, 10)]]);
assert.equal(listKeys(bob.id).length, 0);
assert.equal(db.prepare('SELECT COUNT(*) AS n FROM api_keys WHERE key_hash = ?').get(hashKey(key)).n, 1);
assert.equal(db.prepare("SELECT COUNT(*) AS n FROM api_keys WHERE key_hash = ? OR prefix = ?").get(key, key).n, 0); // never stored in plaintext

// Bearer on an apiKey route: works with a cross-site Origin (no cookies), ignores a session cookie.
const cookieRes = fakeRes();
startSession(cookieRes, bob.id);
const bobCookie = /cs_session=([^;]+)/.exec(cookieRes.headers['set-cookie'])[1];
let r = await call(whoami({ apiKey: true }), { ...fakeReq({ authorization: `Bearer ${key}`, origin: 'https://evil.example' }, 'POST'), cookies: { cs_session: bobCookie } });
assert.deepEqual([r.code, r.body], [200, { id: alice.id }]);
r = await call(whoami({ apiKey: true }), fakeReq({ authorization: `Bearer ${key}x` }));
assert.deepEqual([r.code, r.body.error], [401, 'Invalid API key']);
r = await call(whoami({ apiKey: true }), fakeReq({ authorization: 'Bearer ' }));
assert.equal(r.code, 401);
r = await call(whoami(), fakeReq({ authorization: `Bearer ${key}` }));
assert.deepEqual([r.code, r.body.error], [401, 'API keys cannot be used here']);
r = await call(whoami({ auth: false }), fakeReq({ authorization: `Bearer ${key}` }));
assert.equal(r.code, 401);
// Without a bearer: session flow unchanged (origin check, cookie).
r = await call(whoami({ apiKey: true }), { ...fakeReq({ origin: 'https://evil.example' }, 'POST'), cookies: { cs_session: bobCookie } });
assert.equal(r.code, 403);
r = await call(whoami({ apiKey: true }), { ...fakeReq(), cookies: { cs_session: bobCookie } });
assert.deepEqual([r.code, r.body], [200, { id: bob.id }]);
r = await call(whoami({ apiKey: true }), fakeReq());
assert.equal(r.code, 401);
assert.ok(db.prepare('SELECT last_used_at FROM api_keys WHERE id = ?').get(keyId).last_used_at);
// Rate limit: 600 per hour per key.
db.prepare('UPDATE login_attempts SET count = 599 WHERE key = ?').run(`apikey:${keyId}`);
r = await call(whoami({ apiKey: true }), fakeReq({ authorization: `Bearer ${key}` }));
assert.equal(r.code, 200);
r = await call(whoami({ apiKey: true }), fakeReq({ authorization: `Bearer ${key}` }));
assert.equal(r.code, 429);
assert.ok(Number(r.headers['retry-after']) > 3500);
// Revocation.
assert.equal(status(() => revokeKey(bob, keyId, fakeReq())), 404);
revokeKey(alice, keyId, fakeReq());
assert.equal(status(() => revokeKey(alice, keyId, fakeReq())), 404);
r = await call(whoami({ apiKey: true }), fakeReq({ authorization: `Bearer ${key}` }));
assert.deepEqual([r.code, r.body.error], [401, 'Invalid API key']);
assert.equal(listKeys(alice.id).length, 0);
for (let i = 0; i < KEYS_MAX; i++) createKey(alice, { name: `k${i}` }, fakeReq());
assert.equal(status(() => createKey(alice, { name: 'one more' }, fakeReq())), 409);
assert.equal(db.prepare("SELECT COUNT(*) AS n FROM security_events WHERE type IN ('api_key_created', 'api_key_revoked')").get().n, KEYS_MAX + 2);

// Folders.
const t = now();
const addDoc = (owner, extra = {}) => {
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO documents (id, owner_id, title, status, is_template, original_sha256, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, owner, extra.title || 'Doc', extra.status || 'draft', extra.isTemplate ? 1 : 0, 'x', t, t);
  return { doc: db.prepare('SELECT * FROM documents WHERE id = ?').get(id) };
};
const f1 = createFolder(alice.id, { name: ' Clients ' });
assert.equal(errorOf(() => createFolder(alice.id, { name: 'clients' })), 'A folder with this name already exists');
assert.equal(errorOf(() => createFolder(alice.id, { name: '' })), 'Enter a folder name');
const fb = createFolder(bob.id, { name: 'Clients' }); // same name, other user: fine
const f2 = createFolder(alice.id, { name: 'HR' });
assert.equal(errorOf(() => renameFolder(alice.id, f2, { name: 'CLIENTS' })), 'A folder with this name already exists');
assert.equal(status(() => renameFolder(alice.id, fb, { name: 'Mine now' })), 404);
renameFolder(alice.id, f2, { name: 'People' });
const d1 = addDoc(alice.id, { status: 'completed' });
const tpl = addDoc(alice.id, { isTemplate: true });
addDoc(bob.id);
moveDocument(d1, f1);
moveDocument(tpl, f1);
assert.equal(status(() => moveDocument(d1, fb)), 404); // bob's folder
assert.equal(status(() => moveDocument(d1, 42)), 404);
assert.deepEqual(listFolders(alice.id).map((f) => [f.name, f.count]), [['Clients', 2], ['People', 0]]);
assert.equal(listDocuments(alice, { folder: f1 }).total, 2);
assert.equal(listDocuments(alice, { folder: fb }).total, 0);
assert.equal(listDocuments(alice, { template: '1' }).documents[0].id, tpl.doc.id);
assert.equal(listDocuments(alice, { status: 'completed' }).documents[0].folderId, f1);
assert.equal(listDocuments(alice, {}).total, 2);
assert.equal(listDocuments(alice, { limit: '1' }).documents.length, 1);
assert.equal(listDocuments(alice, { limit: '9999' }).documents.length, 2);
assert.equal(listDocuments(bob, {}).total, 1);
moveDocument(tpl, null);
assert.equal(status(() => deleteFolder(bob.id, f1)), 404);
deleteFolder(alice.id, f1);
assert.equal(db.prepare('SELECT folder_id FROM documents WHERE id = ?').get(d1.doc.id).folder_id, null); // unfiled, not deleted
for (let i = listFolders(alice.id).length; i < 200; i++) createFolder(alice.id, { name: `F${i}` });
assert.equal(errorOf(() => createFolder(alice.id, { name: 'one more' })), 'You can have up to 200 folders');

// Webhooks: CRUD, payload whitelist, delivery with signature, private-address refusal, backoff, auto-disable.
assert.equal(errorOf(() => wh.createWebhook(alice.id, { url: 'https://example.com/h', events: [] })), 'Choose at least one event');
assert.equal(status(() => wh.createWebhook(alice.id, { url: 'https://example.com/h', events: ['ping'] })), 400);
process.env.WEBHOOK_ALLOW_HTTP = 'true';
const got = [];
const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    got.push({ headers: req.headers, body });
    res.statusCode = req.url === '/fail' ? 500 : req.url === '/redirect' ? 302 : 204;
    res.end();
  });
});
await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
const base = `http://localhost:${server.address().port}`;
const { id: hookId, secret } = wh.createWebhook(alice.id, { url: `${base}/ok`, events: ['document.completed', 'document.completed'] });
assert.match(secret, /^whsec_[A-Za-z0-9_-]{43}$/);
assert.ok(!db.prepare('SELECT secret_enc FROM webhooks WHERE id = ?').get(hookId).secret_enc.includes(secret));
assert.deepEqual(wh.listWebhooks(alice.id)[0].events, ['document.completed']);
assert.equal(wh.listWebhooks(bob.id).length, 0);
assert.equal(status(() => wh.updateWebhook(bob.id, hookId, { active: false })), 404);
assert.equal(status(() => wh.listDeliveries(bob.id, hookId)), 404);

const pending = () => db.prepare('SELECT * FROM webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 1').get(hookId);
const leak = { document: { id: 'D1', title: 'NDA', status: 'completed', original_sha256: 'h', message: 'secret' }, recipient: { id: 'R1', name: 'R', email: 'r@x.io', role: 'signer', status: 'signed', token: 'TOKEN', otp_hash: 'o' } };
wh.emitEvent(alice.id, 'document.completed', leak);
wh.emitEvent(alice.id, 'document.sent', leak); // not subscribed
wh.emitEvent(bob.id, 'document.completed', leak); // no webhooks
assert.doesNotThrow(() => wh.emitEvent(null, undefined, undefined));
assert.equal(db.prepare('SELECT COUNT(*) AS n FROM webhook_deliveries').get().n, 1);
const payload = JSON.parse(pending().payload);
assert.deepEqual(Object.keys(payload).sort(), ['createdAt', 'data', 'event', 'id']);
assert.deepEqual(payload.data, { document: { id: 'D1', title: 'NDA', status: 'completed' }, recipient: { id: 'R1', name: 'R', email: 'r@x.io', role: 'signer', status: 'signed' } });

// localhost resolves to loopback: refused at delivery, without WEBHOOK_ALLOW_PRIVATE.
await wh.deliverDue();
let d = pending();
assert.deepEqual([d.status, d.attempts, d.last_error, got.length], ['pending', 1, 'This address is not allowed', 0]);
assert.ok(Date.parse(d.next_attempt_at) - Date.now() > 50e3); // 1 minute backoff
assert.deepEqual(await wh.post('http://127.0.0.1:1/', {}, ''), { error: 'This address is not allowed' });

process.env.WEBHOOK_ALLOW_PRIVATE = 'true';
db.prepare('UPDATE webhook_deliveries SET next_attempt_at = ?').run(now());
await Promise.all([wh.deliverDue(), wh.deliverDue()]); // concurrent runs: one attempt only
const run = wh.deliverDue();
assert.equal(wh.deliverDue(), run); // coalesced: one run in flight per process
await run;
d = pending();
assert.deepEqual([d.status, d.attempts, d.last_status_code, got.length], ['delivered', 2, 204, 1]);
const h = got[0].headers;
assert.equal(got[0].body, d.payload);
assert.equal(h['content-type'], 'application/json');
assert.equal(h['user-agent'], 'Countersign-Webhooks');
assert.equal(h['countersign-event'], 'document.completed');
assert.equal(h['countersign-delivery'], payload.id);
const [, ts, v1] = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(h['countersign-signature']);
assert.equal(v1, crypto.createHmac('sha256', secret).update(`${ts}.${got[0].body}`).digest('hex'));

// Ping, redirects as failures, backoff to 'failed' after 7 attempts, auto-disable at 20 failed deliveries.
wh.sendTest(alice.id, hookId);
await new Promise((ok) => setTimeout(ok, 300));
assert.equal(got.at(-1).headers['countersign-event'], 'ping');
assert.deepEqual(JSON.parse(got.at(-1).body).data, {});
wh.updateWebhook(alice.id, hookId, { url: `${base}/redirect` });
wh.emitEvent(alice.id, 'document.completed', leak);
await new Promise((ok) => setTimeout(ok, 300));
assert.deepEqual([pending().status, pending().last_status_code, pending().last_error], ['pending', 302, 'HTTP 302']);
for (let i = 2; i <= 7; i++) {
  db.prepare("UPDATE webhook_deliveries SET next_attempt_at = ? WHERE status = 'pending'").run(now());
  await wh.deliverDue();
}
assert.deepEqual([pending().status, pending().attempts], ['failed', 7]);
assert.equal(db.prepare('SELECT failure_count FROM webhooks WHERE id = ?').get(hookId).failure_count, 1);
db.prepare('UPDATE webhooks SET failure_count = 19 WHERE id = ?').run(hookId);
wh.emitEvent(alice.id, 'document.completed', leak);
db.prepare("UPDATE webhook_deliveries SET attempts = 6 WHERE status = 'pending'").run();
await new Promise((ok) => setTimeout(ok, 300));
assert.equal(wh.listWebhooks(alice.id)[0].active, false);
wh.emitEvent(alice.id, 'document.completed', leak); // inactive: nothing queued
assert.equal(db.prepare("SELECT COUNT(*) AS n FROM webhook_deliveries WHERE status = 'pending'").get().n, 0);
wh.updateWebhook(alice.id, hookId, { active: true });
assert.deepEqual([wh.listWebhooks(alice.id)[0].active, wh.listWebhooks(alice.id)[0].failureCount], [true, 0]);
assert.equal(wh.listDeliveries(alice.id, hookId).length, 4); // completed, ping, redirect, the one that disabled it

// Purge: deliveries older than 30 days; publictpl:* counters live 24 h.
db.prepare('UPDATE webhook_deliveries SET created_at = ?').run(new Date(Date.now() - 31 * 864e5).toISOString());
assert.equal(wh.purgeDeliveries(), 4);
const ago = (h) => new Date(Date.now() - h * 36e5).toISOString();
db.prepare('INSERT INTO login_attempts (key, window_start, count) VALUES (?, ?, 5), (?, ?, 5), (?, ?, 5)').run('publictpl:a', ago(2), 'publictpl:b', ago(25), 'public:x', ago(2));
purgeExpired();
assert.deepEqual(db.prepare("SELECT key FROM login_attempts WHERE key LIKE 'public%' ORDER BY key").all().map((x) => x.key), ['publictpl:a']);

wh.deleteWebhook(alice.id, hookId);
assert.equal(wh.listWebhooks(alice.id).length, 0);
server.close();
db.close();
fs.rmSync(dir, { recursive: true, force: true });
process.stdout.write('tier3 self-check passed\n');
