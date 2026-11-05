// Password reset over HTTP. Needs a running FRESH server (ALLOW_SIGNUP=true, SIGNUP_MAX_PER_HOUR=1000):
//   BASE_URL=http://localhost:3492 DATA_DIR=<server's DATA_DIR> node --test test/reset.test.mjs
// The email tests also need QA_SMTP_SINK_PORT and a server with SMTP_HOST=127.0.0.1 SMTP_PORT=<same> APP_URL=<BASE_URL>.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import net from 'node:net';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const DATA = process.env.DATA_DIR;
const SINK = Number(process.env.QA_SMTP_SINK_PORT) || 0;
const NEEDS_DB = !DATA && 'needs DATA_DIR pointing at the server data folder';
const NEEDS_MAIL = (NEEDS_DB || !SINK) && 'needs DATA_DIR, QA_SMTP_SINK_PORT and a server with SMTP';
const OLD = 'correct horse battery';
const NEW = 'a brand new long password';
const DEAD = 'This link has expired or was already used. Ask for a new one.';
const SETTLE = 3500; // forgot works at a random moment up to 3 s after answering, so a check that nothing happened must wait this long
const rnd = () => crypto.randomBytes(5).toString('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let _db;
const db = () => {
  if (!_db) { _db = new DatabaseSync(path.join(DATA, 'countersign.db')); _db.exec('PRAGMA busy_timeout = 5000'); }
  return _db;
};

function client() {
  const cookies = {};
  return async (p, { method = 'POST', body } = {}) => {
    const cookie = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(BASE + p, { method, redirect: 'manual', headers: { 'Content-Type': 'application/json', ...(cookie && { cookie }) }, body: body == null ? undefined : JSON.stringify(body) });
    for (const c of res.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); cookies[kv.slice(0, i)] = kv.slice(i + 1); }
    return { status: res.status, data: (res.headers.get('content-type') || '').includes('json') ? await res.json() : null };
  };
}
async function signup() {
  const call = client();
  const email = `rs-${Date.now()}-${rnd()}@example.com`;
  assert.equal((await call('/api/auth/signup', { body: { name: 'Reset', email, password: OLD } })).status, 200);
  return { call, email };
}
const login = (email, password) => client()('/api/auth/login', { body: { email, password } });
const reset = (token, password = NEW) => client()('/api/auth/reset', { body: { token, password } });
const script = (...args) => spawnSync(process.execPath, ['scripts/reset-link.mjs', ...args], { env: { ...process.env, DATA_DIR: DATA, APP_URL: 'http://cs.example/' }, encoding: 'utf8' });
const linkFor = (email) => {
  const r = script(email);
  assert.equal(r.status, 0, r.stderr);
  const m = r.stdout.trim().match(/^http:\/\/cs\.example\/reset#([\w-]+)$/);
  assert.ok(m, r.stdout);
  return m[1];
};

// Smallest SMTP that nodemailer accepts: keeps each message.
function sink(mails) {
  const CRLF = '\r\n';
  const server = net.createServer((c) => {
    let data = false, buf = '', to = '';
    c.on('error', () => {});
    c.write('220 sink' + CRLF);
    c.on('data', (d) => {
      buf += d.toString('latin1');
      if (data) {
        if (!buf.endsWith(CRLF + '.' + CRLF)) return;
        mails.push({ to, text: buf.replace(/=\r\n/g, '').replace(/=3D/g, '=') });
        data = false; buf = ''; c.write('250 ok' + CRLF);
        return;
      }
      while (buf.includes(CRLF) && !data) {
        const i = buf.indexOf(CRLF), line = buf.slice(0, i), cmd = line.toUpperCase();
        buf = buf.slice(i + 2);
        if (cmd.startsWith('RCPT TO')) to = line;
        if (cmd === 'DATA') { data = true; c.write('354 go' + CRLF); }
        else if (cmd === 'QUIT') c.end('221 bye' + CRLF);
        else c.write('250 ok' + CRLF);
      }
    });
  });
  return new Promise((res) => server.listen(SINK, '127.0.0.1', () => res(server)));
}
async function mailTo(mails, email, after = 0) {
  for (let i = 0; i < 100; i++) {
    const found = mails.slice(after).find((m) => m.to.includes(email));
    if (found) return found;
    await sleep(50);
  }
  assert.fail(`no mail to ${email}`);
}
const tokenIn = (mail) => mail.text.match(/\/reset#([\w-]+)/)?.[1];

test('a reset link changes the password, ends everything else and works once', { skip: NEEDS_DB }, async () => {
  const { call, email } = await signup();
  const key = (await call('/api/api-keys', { body: { name: 'k' } })).data.key;
  const token = linkFor(email);
  assert.equal(db().prepare('SELECT COUNT(*) AS n FROM password_resets WHERE token_hash = ?').get(token).n, 0, 'the token is stored only as a hash');

  // Bad passwords do not use up the link.
  assert.deepEqual([(await reset(token, 'short')).status, (await reset(token, email)).status], [400, 400]);
  assert.equal((await login(email, OLD)).status, 200, 'the password has not changed yet');

  assert.equal((await reset(token)).status, 200);
  assert.equal((await login(email, OLD)).status, 401);
  assert.equal((await login(email, NEW)).status, 200);
  assert.equal((await call('/api/account', { method: 'PATCH', body: { name: 'x' } })).status, 401, 'the old session is gone');
  const viaKey = await fetch(`${BASE}/api/documents`, { headers: { Authorization: `Bearer ${key}` } });
  assert.equal(viaKey.status, 401, 'API keys are revoked');

  const again = await reset(token, 'yet another long password');
  assert.deepEqual([again.status, again.data.error], [400, DEAD]);
  assert.equal((await login(email, NEW)).status, 200);
  const types = db().prepare('SELECT type FROM security_events WHERE email = ?').all(email).map((e) => e.type);
  assert.ok(types.includes('password_reset') && types.includes('password_reset_request'), types.join());
});

test('dead links are refused the same way: unknown, not a string, expired, empty', { skip: NEEDS_DB }, async () => {
  const { email } = await signup();
  const token = linkFor(email);
  db().prepare("UPDATE password_resets SET expires_at = '2000-01-01T00:00:00.000Z' WHERE user_id = (SELECT id FROM users WHERE email = ?)").run(email);
  for (const bad of [token, 'nope', '', null, 7, { a: 1 }, ['x']]) {
    const r = await reset(bad);
    assert.deepEqual([r.status, r.data.error], [400, DEAD], JSON.stringify(bad));
  }
  assert.equal((await login(email, OLD)).status, 200);
});

test('using one link spends the others, and parallel use lets one through', { skip: NEEDS_DB }, async () => {
  const { email } = await signup();
  const [a, b] = [linkFor(email), linkFor(email)];
  assert.equal((await reset(a)).status, 200);
  assert.equal((await reset(b)).status, 400);

  const c = linkFor(email);
  const all = await Promise.all(Array.from({ length: 5 }, (_, i) => reset(c, `parallel password number ${i}`)));
  assert.deepEqual(all.map((r) => r.status).sort(), [200, 400, 400, 400, 400]);
});

test('a password change kills links already sent', { skip: NEEDS_DB }, async () => {
  const { call, email } = await signup();
  const token = linkFor(email);
  assert.equal((await call('/api/account', { method: 'PATCH', body: { currentPassword: OLD, newPassword: NEW } })).status, 200);
  assert.equal((await reset(token, 'third long password here')).status, 400);
});

test('a reset clears the lockout from someone else\'s guesses', { skip: NEEDS_DB }, async () => {
  const { email } = await signup();
  for (let i = 0; i < 5; i++) await login(email, 'wrong password here');
  assert.equal((await login(email, OLD)).status, 429);
  assert.equal((await reset(linkFor(email))).status, 200);
  assert.equal((await login(email, NEW)).status, 200);
});

test('an address in mail group syntax cannot be registered', async () => {
  const r = await client()('/api/auth/signup', { body: { name: 'G', email: `team:rs-${rnd()}@example.com`, password: OLD } });
  assert.equal(r.status, 400);
});

test('the script refuses an unknown email and a missing one', { skip: NEEDS_DB }, () => {
  assert.equal(script(`nobody-${rnd()}@example.com`).status, 1);
  assert.equal(script().status, 2);
});

test('without email: the form says so and the route is off', { skip: SINK ? 'server has email' : false }, async () => {
  const r = await client()('/api/auth/forgot', { body: { email: 'a@example.com' } });
  assert.equal(r.status, 404);
  assert.match(await (await fetch(`${BASE}/forgot`)).text(), /doesn’t send email/);
});

test('email: known and unknown addresses get the same answer, and only the known one gets mail', { skip: NEEDS_MAIL }, async (t) => {
  const mails = [];
  const server = await sink(mails);
  t.after(() => server.close());
  db().prepare("DELETE FROM login_attempts WHERE key LIKE 'forgot%'").run();
  const { email } = await signup();
  const forgot = (e) => client()('/api/auth/forgot', { body: { email: e } });

  const unknown = `nobody-${rnd()}@example.com`;
  const typedPassword = `my secret ${rnd()}`;
  const answers = [await forgot(unknown), await forgot(typedPassword), await forgot(email.toUpperCase())];
  for (const r of answers) assert.deepEqual([r.status, r.data], [200, { ok: true }]);

  const mail = await mailTo(mails, email);
  await sleep(SETTLE);
  assert.equal(mails.length, 1, 'no mail for unknown addresses');
  assert.match(mail.text, new RegExp(`${BASE.replace(/[/.]/g, '\\$&')}/reset#[\\w-]+`), 'the link uses APP_URL');
  assert.equal(db().prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE key LIKE ?').get(`%${typedPassword}%`).n, 0, 'what was typed is not stored');
  assert.equal(db().prepare('SELECT COUNT(*) AS n FROM security_events WHERE detail LIKE ? OR email = ?').get(`%${typedPassword}%`, typedPassword).n, 0, 'nor logged');

  assert.equal((await reset(tokenIn(mail))).status, 200);
  assert.equal((await login(email, NEW)).status, 200);
});

test('email: limited to 3 mails an hour per account, and earlier links keep working', { skip: NEEDS_MAIL }, async (t) => {
  const mails = [];
  const server = await sink(mails);
  t.after(() => server.close());
  db().prepare("DELETE FROM login_attempts WHERE key LIKE 'forgot%'").run();
  const { email } = await signup();
  for (let i = 0; i < 6; i++) {
    assert.equal((await client()('/api/auth/forgot', { body: { email } })).status, 200);
    await sleep(100);
  }
  await mailTo(mails, email, 2);
  await sleep(SETTLE);
  const mine = mails.filter((m) => m.to.includes(email)); // the last test's reset notice may land here
  assert.equal(mine.length, 3);
  assert.equal((await reset(tokenIn(mine[0]))).status, 200);
});

test('email: past 20 requests an hour from one address the answer is 429', { skip: NEEDS_MAIL }, async (t) => {
  t.after(() => db().prepare("DELETE FROM login_attempts WHERE key LIKE 'forgot%'").run());
  db().prepare("DELETE FROM login_attempts WHERE key LIKE 'forgot%'").run();
  const statuses = [];
  for (let i = 0; i < 21; i++) statuses.push((await client()('/api/auth/forgot', { body: {} })).status);
  assert.deepEqual([statuses.filter((s) => s === 200).length, statuses.at(-1)], [20, 429]);
});
