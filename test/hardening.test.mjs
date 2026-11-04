// Security follow-ups over HTTP: API key expiry (T3-06), revoke all keys with sign-out everywhere (T3-06),
// webhook secret rotation (T3-06) and the per-owner storage quota (T3-01).
// Needs a running FRESH server (ALLOW_SIGNUP=true, SIGNUP_MAX_PER_HOUR=1000):
//   BASE_URL=http://localhost:3492 DATA_DIR=<server's DATA_DIR> node --test test/hardening.test.mjs
// DATA_DIR enables the checks that age a key or fill the quota in the server's database; without it they skip.
// The quota test expects the default STORAGE_QUOTA_MB (1024).
// The invite email cap test needs DATA_DIR, QA_SMTP_SINK_PORT and a server with SMTP_HOST=127.0.0.1 SMTP_PORT=<same> APP_URL=<BASE_URL>.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const DATA = process.env.DATA_DIR;
const NEEDS_DB = !DATA && 'needs DATA_DIR pointing at the server data folder';
const rnd = () => crypto.randomBytes(5).toString('hex');
const err = (r) => [r.status, r.data?.error];
let _db;
const db = () => {
  if (!_db) { _db = new DatabaseSync(path.join(DATA, 'countersign.db')); _db.exec('PRAGMA busy_timeout = 5000'); }
  return _db;
};

function client() {
  const cookies = {};
  return async (p, { method = 'POST', body, headers = {} } = {}) => {
    const raw = body instanceof Uint8Array;
    const cookie = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(BASE + p, {
      method, redirect: 'manual',
      headers: { ...(raw ? {} : { 'Content-Type': 'application/json' }), ...(cookie && { cookie }), ...headers },
      body: body == null ? undefined : raw ? body : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); cookies[kv.slice(0, i)] = kv.slice(i + 1); }
    return { status: res.status, data: (res.headers.get('content-type') || '').includes('json') ? await res.json() : null };
  };
}
const bearer = (k) => (p, opts = {}) => client()(p, { ...opts, headers: { Authorization: `Bearer ${k}`, ...opts.headers } });
async function signup() {
  const call = client();
  const email = `hd-${Date.now()}-${rnd()}@example.com`;
  const r = await call('/api/auth/signup', { body: { name: 'Hardening', email, password: 'correct horse battery' } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return call;
}
const pdf = async () => { const d = await PDFDocument.create(); d.setTitle(rnd()); d.addPage([612, 792]); return d.save(); };
const uploadPdf = async (call) => call('/api/documents', { body: await pdf(), headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'H.pdf' } });
const list = (k) => k('/api/documents', { method: 'GET' });

test('API keys: expiresDays is 30, 90, 365 or null; the list shows expiresAt', async () => {
  const u = await signup();
  for (const bad of [0, 7, '30', -1, 1e9, true]) {
    assert.deepEqual(err(await u('/api/api-keys', { body: { name: 'x', expiresDays: bad } })), [400, 'expiresDays must be one of 30, 90, 365 or null'], String(bad));
  }
  const never = (await u('/api/api-keys', { body: { name: 'never' } })).data;
  assert.equal(never.expiresAt, null);
  const r = await u('/api/api-keys', { body: { name: 'soon', expiresDays: 30 } });
  assert.equal(r.status, 201);
  const days = (Date.parse(r.data.expiresAt) - Date.now()) / 864e5;
  assert.ok(days > 29.9 && days <= 30, `expires in ${days} days`);
  assert.equal((await list(bearer(r.data.key))).status, 200);
  const keys = (await u('/api/api-keys', { method: 'GET' })).data.keys;
  assert.deepEqual(keys.map((k) => [k.name, k.expiresAt]).sort(), [['never', null], ['soon', r.data.expiresAt]]);
});

test('API keys: a key past expires_at is refused', { skip: NEEDS_DB }, async () => {
  const u = await signup();
  const { id, key } = (await u('/api/api-keys', { body: { name: 'old', expiresDays: 30 } })).data;
  db().prepare('UPDATE api_keys SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), id);
  assert.deepEqual(err(await list(bearer(key))), [401, 'Invalid API key']);
});

test('sign out everywhere: keys survive by default; { apiKeys: true } revokes them all; apiKeys must be boolean', async () => {
  const a = await signup();
  const k1 = (await a('/api/api-keys', { body: { name: 'one' } })).data.key;
  assert.deepEqual(err(await a('/api/auth/logout-all', { body: { apiKeys: 'yes' } })), [400, 'apiKeys must be true or false']);
  assert.deepEqual((await a('/api/auth/logout-all', { body: {} })).data, { ok: true });
  assert.equal((await list(bearer(k1))).status, 200, 'key survives a plain sign-out');
  assert.equal((await a('/api/api-keys', { method: 'GET' })).status, 401, 'session ended');

  const b = await signup();
  const keys = [];
  for (const name of ['one', 'two']) keys.push((await b('/api/api-keys', { body: { name } })).data.key);
  assert.equal((await bearer(keys[0])('/api/auth/logout-all', { body: { apiKeys: true } })).status, 401, 'a key cannot do this');
  assert.deepEqual((await b('/api/auth/logout-all', { body: { apiKeys: true } })).data, { ok: true, keysRevoked: 2 });
  for (const k of keys) assert.deepEqual(err(await list(bearer(k))), [401, 'Invalid API key']);
  assert.equal((await b('/api/api-keys', { method: 'GET' })).status, 401);
  assert.equal((await list(bearer(k1))).status, 200, 'another user\'s key is untouched');
});

test('webhook secret rotation: owner only, session only, returns a new whsec_ secret', async () => {
  const u = await signup();
  const made = await u('/api/webhooks', { body: { url: 'https://example.com/hook', events: ['document.sent'] } });
  assert.equal(made.status, 201, JSON.stringify(made.data));
  const { id, secret } = made.data;
  const r = await u(`/api/webhooks/${id}/secret`);
  assert.equal(r.status, 200);
  assert.match(r.data.secret, /^whsec_[A-Za-z0-9_-]{43}$/);
  assert.notEqual(r.data.secret, secret);
  assert.notEqual((await u(`/api/webhooks/${id}/secret`)).data.secret, r.data.secret);
  assert.equal((await u(`/api/webhooks/${id}/secret`, { headers: { Origin: 'http://evil.test' } })).status, 403);
  const other = await signup();
  assert.deepEqual(err(await other(`/api/webhooks/${id}/secret`)), [404, 'Webhook not found']);
  const key = (await u('/api/api-keys', { body: { name: 'k' } })).data.key;
  assert.equal((await bearer(key)(`/api/webhooks/${id}/secret`)).status, 401);
});

test('storage quota: uploads and copies past STORAGE_QUOTA_MB get 413; deleting frees space', { skip: NEEDS_DB }, async () => {
  const u = await signup();
  const first = await uploadPdf(u);
  assert.equal(first.status, 201, JSON.stringify(first.data));
  const docId = first.data.id;
  assert.ok(db().prepare('SELECT original_bytes FROM documents WHERE id = ?').get(docId).original_bytes > 0, 'size recorded');
  db().prepare('UPDATE documents SET original_bytes = ? WHERE id = ?').run(1024 * 1048576, docId); // fill the default quota
  const msg = 'Storage limit reached (1024 MB). Delete documents you no longer need, or ask the admin to raise STORAGE_QUOTA_MB.';
  assert.deepEqual(err(await uploadPdf(u)), [413, msg]);
  assert.deepEqual(err(await u(`/api/documents/${docId}/copy`, { body: { asTemplate: true } })), [413, msg]);
  assert.equal((await uploadPdf(await signup())).status, 201, 'other accounts are not affected');
  assert.equal((await u(`/api/documents/${docId}`, { method: 'DELETE' })).status, 200);
  assert.equal((await uploadPdf(u)).status, 201, 'space is free again');
});

test('password change revokes every API key and keeps this session; a failed change revokes nothing', async () => {
  const u = await signup();
  const { key } = (await u('/api/api-keys', { body: { name: 'k' } })).data;
  const change = (currentPassword) => u('/api/account', { method: 'PATCH', body: { currentPassword, newPassword: `new horse battery ${rnd()}` } });
  assert.equal((await change('wrong password here')).status, 400);
  assert.equal((await list(bearer(key))).status, 200, 'a failed change leaves the key alone');
  assert.equal((await change('correct horse battery')).status, 200);
  assert.deepEqual(err(await list(bearer(key))), [401, 'Invalid API key']);
  assert.deepEqual((await u('/api/api-keys', { method: 'GET' })).data.keys, [], 'key is gone from the list; session still works');
});

test('invite email cap: past the server-wide limit the invite is created and returned, but no mail goes out', { skip: (NEEDS_DB || !process.env.QA_SMTP_SINK_PORT) && 'needs DATA_DIR, QA_SMTP_SINK_PORT and a server with SMTP' }, async (t) => {
  let mails = 0;
  // Smallest SMTP that nodemailer accepts: counts each message.
  const sink = net.createServer((c) => {
    let data = false, buf = '';
    c.on('error', () => {});
    const CRLF = String.fromCharCode(13, 10);
    c.write('220 sink' + CRLF);
    c.on('data', (d) => {
      buf += d.toString('latin1');
      if (data) {
        if (!buf.endsWith(CRLF + '.' + CRLF)) return;
        data = false; buf = ''; mails++; c.write('250 ok' + CRLF);
        return;
      }
      while (buf.includes(CRLF) && !data) {
        const i = buf.indexOf(CRLF), cmd = buf.slice(0, i).toUpperCase();
        buf = buf.slice(i + 2);
        if (cmd === 'DATA') { data = true; c.write('354 go' + CRLF); }
        else if (cmd === 'QUIT') { c.end('221 bye' + CRLF); }
        else c.write('250 ok' + CRLF);
      }
    });
  });
  await new Promise((res) => sink.listen(Number(process.env.QA_SMTP_SINK_PORT), '127.0.0.1', res));
  const unlock = () => db().prepare("DELETE FROM login_attempts WHERE key = 'team-invite-mail'").run();
  t.after(() => { unlock(); sink.close(); });
  unlock(); // other tests on this server may have used up the hour
  const u = await signup();
  assert.equal((await u('/api/teams', { body: { name: 'Cap' } })).status, 201);
  const invite = () => u('/api/teams/invites', { body: { email: `cap-${rnd()}@example.com`, role: 'member' } });
  const open = await invite();
  assert.deepEqual([open.status, open.data.emailed, mails], [201, true, 1]);
  const t0 = new Date().toISOString();
  db().prepare('INSERT OR REPLACE INTO login_attempts (key, window_start, count, locked_until) VALUES (?, ?, ?, ?)').run('team-invite-mail', t0, 100, new Date(Date.now() + 36e5).toISOString());
  const capped = await invite();
  assert.deepEqual([capped.status, capped.data.emailed, mails], [201, false, 1]);
  assert.ok(capped.data.url.startsWith('/join/'), 'the link is still returned to copy');
});

test('password change: parallel wrong guesses cannot pass the limit of 5', async () => {
  const u = await signup();
  const all = await Promise.all(Array.from({ length: 20 }, () => u('/api/account', { method: 'PATCH', body: { currentPassword: 'wrong password here', newPassword: 'another long password' } })));
  const count = (code) => all.filter((r) => r.status === code).length;
  assert.equal(count(200), 0);
  assert.equal(count(400), 5);
  assert.equal(count(429), 15);
});
