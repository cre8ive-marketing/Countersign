// Security review of password reset. Needs FRESH disposable servers. Without RST_BASE_URL every test skips.
// Common server env: ALLOW_SIGNUP=true SIGNUP_MAX_PER_HOUR=1000 ENCRYPTION_KEY=<64 hex> TRUST_PROXY=true APP_URL=<its own url> SMTP_HOST=127.0.0.1
//   TRUST_PROXY lets X-Forwarded-For stand in for separate client addresses.
// RST_BASE_URL, RST_DATA_DIR, RST_SMTP_PORT: that env, SMTP_PORT=<RST_SMTP_PORT>. RST_SERVER_LOG: optional, its stdout file.
// RST_SSO_BASE_URL, RST_SSO_DATA_DIR, RST_REQUIRED_BASE_URL, RST_REQUIRED_DATA_DIR, RST_SSO_SMTP_PORT, RST_MOCK_PORT: two more servers,
//   SMTP_PORT=<RST_SSO_SMTP_PORT> OIDC_ISSUER=http://127.0.0.1:<RST_MOCK_PORT> OIDC_ALLOW_HTTP=true OIDC_CLIENT_ID=cs-sec
//   OIDC_CLIENT_SECRET=cs-sec-secret OIDC_ALLOWED_DOMAINS=allowed.test, the second with OIDC_REQUIRED=true.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const BASE = process.env.RST_BASE_URL;
const DATA = process.env.RST_DATA_DIR;
const SMTP = Number(process.env.RST_SMTP_PORT) || 0;
const SERVER_LOG = process.env.RST_SERVER_LOG;
const SSO = process.env.RST_SSO_BASE_URL;
const SSO_DATA = process.env.RST_SSO_DATA_DIR;
const REQUIRED = process.env.RST_REQUIRED_BASE_URL;
const REQUIRED_DATA = process.env.RST_REQUIRED_DATA_DIR;
const SSO_SMTP = Number(process.env.RST_SSO_SMTP_PORT) || 0;
const MOCK = Number(process.env.RST_MOCK_PORT) || 0;
const NEEDS = (!BASE || !DATA || !SMTP) && 'needs RST_BASE_URL, RST_DATA_DIR and RST_SMTP_PORT';
const NEEDS_SSO = (!SSO || !SSO_DATA || !REQUIRED || !REQUIRED_DATA || !SSO_SMTP || !MOCK) && 'needs the RST_SSO_* and RST_REQUIRED_* servers and RST_MOCK_PORT';
const ROOT = path.resolve(import.meta.dirname, '..', '..');
const SCRIPT = path.join(ROOT, 'scripts', 'reset-link.mjs');
const OLD = 'correct horse battery';
const NEW = 'a brand new long password';
const DEAD = 'This link has expired or was already used. Ask for a new one.';
const ISSUER = `http://127.0.0.1:${MOCK}`;
const rnd = () => crypto.randomBytes(5).toString('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const newIp = () => `10.${crypto.randomInt(255)}.${crypto.randomInt(255)}.${crypto.randomInt(1, 255)}`;
const median = (a) => [...a].sort((x, y) => x - y)[a.length >> 1];

function client(base, ip = newIp()) {
  const jar = {};
  const call = async (p, { method = 'POST', body, headers = {}, raw } = {}) => {
    const cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(base + p, { method, redirect: 'manual', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip, ...(cookie && { cookie }), ...headers }, body: raw ?? (body == null ? undefined : JSON.stringify(body)) });
    const set = res.headers.getSetCookie();
    for (const c of set) {
      const [kv] = c.split(';');
      const i = kv.indexOf('=');
      if (/Max-Age=0/.test(c)) delete jar[kv.slice(0, i)]; else jar[kv.slice(0, i)] = kv.slice(i + 1);
    }
    const text = await res.text();
    let data = text;
    try { data = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, data, set, location: res.headers.get('location') };
  };
  call.jar = jar;
  return call;
}
async function signup(base = BASE, email = `rst-${rnd()}@example.com`) {
  const call = client(base);
  const r = await call('/api/auth/signup', { body: { name: 'Reset', email, password: OLD } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return { call, email };
}
const login = (email, password, base = BASE, ip) => client(base, ip)('/api/auth/login', { body: { email, password } });
const forgot = (email, base = BASE, headers) => client(base)('/api/auth/forgot', { body: { email }, headers });
const reset = (token, password = NEW, base = BASE) => client(base)('/api/auth/reset', { body: { token, password } });
const live = async (call) => (await call('/api/account', { method: 'PATCH', body: { name: 'still here' } })).status;

function withDb(fn, dir = DATA) {
  const db = new DatabaseSync(path.join(dir, 'countersign.db'));
  db.exec('PRAGMA busy_timeout = 5000');
  try { return fn(db); } finally { db.close(); }
}
function runScript(args, dir = DATA, { script = SCRIPT, cwd = ROOT, appUrl = 'http://cs.example' } = {}) {
  return spawnSync(process.execPath, ['--no-warnings', script, ...args], { cwd, encoding: 'utf8', env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, DATA_DIR: dir, APP_URL: appUrl } });
}
function linkFor(email, dir = DATA) {
  const r = runScript([email], dir);
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim().split('#')[1];
}

// Smallest SMTP that nodemailer accepts. While `hang` is set a new connection never gets a greeting.
function startSink(port) {
  const CRLF = '\r\n';
  const state = { mails: [], hang: false, open: new Set() };
  const server = net.createServer((c) => {
    state.open.add(c);
    c.on('close', () => state.open.delete(c));
    c.on('error', () => {});
    if (state.hang) return;
    let data = false, buf = '', to = [];
    c.write('220 sink' + CRLF);
    c.on('data', (d) => {
      buf += d.toString('latin1');
      if (data) {
        if (!buf.endsWith(CRLF + '.' + CRLF)) return;
        state.mails.push({ to, text: buf.replace(/=\r\n/g, '').replace(/=3D/g, '=') });
        data = false; buf = ''; to = [];
        c.write('250 ok' + CRLF);
        return;
      }
      while (buf.includes(CRLF) && !data) {
        const i = buf.indexOf(CRLF), line = buf.slice(0, i), cmd = line.toUpperCase();
        buf = buf.slice(i + 2);
        if (cmd.startsWith('RCPT TO')) to.push(line.toLowerCase());
        if (cmd === 'DATA') { data = true; c.write('354 go' + CRLF); }
        else if (cmd === 'QUIT') c.end('221 bye' + CRLF);
        else c.write('250 ok' + CRLF);
      }
    });
  });
  state.close = () => { for (const s of state.open) s.destroy(); server.close(); };
  return new Promise((res) => server.listen(port, '127.0.0.1', () => res(state)));
}
const sink = NEEDS ? null : await startSink(SMTP);
const ssoSink = NEEDS_SSO ? null : await startSink(SSO_SMTP);
const SETTLE = 3500; // forgot works at a random moment up to 3 s after answering, so a check that nothing happened must wait this long
const mailsTo = (email, box = sink) => box.mails.filter((m) => m.to.some((t) => t.includes(email.toLowerCase())));
async function nextMail(email, box = sink, after = mailsTo(email, box).length - 1) {
  for (let i = 0; i < 100; i++) {
    const m = mailsTo(email, box)[after];
    if (m) return m;
    await sleep(50);
  }
  return assert.fail(`no mail to ${email}`);
}
const tokenIn = (m) => m.text.match(/\/reset#([\w-]+)/)?.[1];

// Mock provider, as in oidc-round2.test.mjs.
const codes = new Map();
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
let mock;
if (!NEEDS_SSO) {
  mock = http.createServer((req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    if (req.url === '/.well-known/openid-configuration') return send(200, { issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token` });
    if (req.url !== '/token') return send(404, {});
    let raw = '';
    req.on('data', (d) => { raw += d; });
    req.on('end', () => {
      const entry = codes.get(new URLSearchParams(raw).get('code'));
      if (!entry) return send(400, { error: 'invalid_grant' });
      return send(200, { id_token: `${b64({ alg: 'RS256' })}.${b64({ iss: ISSUER, aud: 'cs-sec', exp: Math.floor(Date.now() / 1000) + 300, nonce: entry.nonce, email_verified: true, ...entry.claims })}.sig` });
    });
    return undefined;
  });
  await new Promise((r) => mock.listen(MOCK, '127.0.0.1', r));
}
test.after(() => { sink?.close(); ssoSink?.close(); mock?.close(); });

async function ssoSignIn(call, claims) {
  const start = await call('/api/auth/oidc/start', { method: 'GET' });
  assert.equal(start.status, 302);
  const auth = new URL(start.location).searchParams;
  const code = rnd();
  codes.set(code, { claims, nonce: auth.get('nonce') });
  return (await call(`/api/auth/oidc/callback?code=${code}&state=${encodeURIComponent(auth.get('state'))}`, { method: 'GET' })).location;
}
const newSsoUser = () => ({ sub: `sub-${rnd()}`, email: `u-${rnd()}@allowed.test` });
const leftIssuer = (dir, email) => withDb((db) => db.prepare("UPDATE oidc_identities SET issuer = 'https://old-provider.invalid' WHERE user_id = (SELECT id FROM users WHERE email = ?)").run(email), dir);

// ---- 1. Forgot: same answer, work after the answer ----

test('forgot: known and unknown addresses get byte-identical answers', { skip: NEEDS }, async () => {
  const { email } = await signup();
  const [a, b] = [await forgot(email), await forgot(`nobody-${rnd()}@example.com`)];
  assert.deepEqual([a.status, a.data, b.status, b.data], [200, { ok: true }, 200, { ok: true }]);
});

test('forgot: a throw after the answer stops nothing, wherever it happens', { skip: NEEDS }, async () => {
  const { email } = await signup();
  const { email: other } = await signup();
  const third = `nobody-${rnd()}@example.com`;
  const triggers = [
    ['CREATE TRIGGER rst_a BEFORE INSERT ON password_resets BEGIN SELECT RAISE(ABORT, \'rst\'); END', 'rst_a', email],
    ["CREATE TRIGGER rst_b BEFORE INSERT ON security_events WHEN NEW.type = 'password_reset_request' BEGIN SELECT RAISE(ABORT, 'rst'); END", 'rst_b', other],
    ["CREATE TRIGGER rst_c BEFORE INSERT ON login_attempts WHEN NEW.key LIKE 'forgot:%' BEGIN SELECT RAISE(ABORT, 'rst'); END", 'rst_c', third],
  ];
  for (const [create, name, address] of triggers) {
    withDb((db) => db.exec(create));
    try {
      const r = await forgot(address);
      assert.deepEqual([r.status, r.data], [200, { ok: true }]);
      await sleep(SETTLE);
    } finally {
      withDb((db) => db.exec(`DROP TRIGGER ${name}`));
    }
    assert.equal((await client(BASE)('/api/auth/session', { method: 'GET' })).status < 500, true, 'the server still answers');
  }
});

test('forgot: an SMTP server that never answers delays no later request', { skip: NEEDS }, async () => {
  const { email } = await signup();
  sink.hang = true;
  try {
    const before = sink.open.size;
    assert.equal((await forgot(email)).status, 200);
    for (let i = 0; i < SETTLE / 25 && sink.open.size === before; i++) await sleep(25);
    assert.ok(sink.open.size > before, 'the mail attempt reached the sink');
    const times = [];
    for (let i = 0; i < 15; i++) {
      const t = performance.now();
      await client(BASE)('/api/auth/session', { method: 'GET' });
      times.push(performance.now() - t);
    }
    assert.ok(median(times) < 100, `median ${median(times)} ms`);
  } finally {
    sink.hang = false;
    for (const s of sink.open) s.destroy();
  }
});

test('RST-1: the request after a forgot takes no longer for a known address', { skip: NEEDS }, async (t) => {
  const url = new URL(BASE);
  const agents = [new http.Agent({ keepAlive: true, maxSockets: 1 }), new http.Agent({ keepAlive: true, maxSockets: 1 })];
  t.after(() => agents.forEach((a) => a.destroy()));
  const time = (agent, method, p, body) => new Promise((res, rej) => {
    const t0 = performance.now();
    const data = body && JSON.stringify(body);
    const r = http.request({ agent, host: '127.0.0.1', port: url.port, method, path: p, headers: { 'X-Forwarded-For': newIp(), ...(data && { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }) } }, (m) => {
      m.resume();
      m.on('end', () => res(performance.now() - t0));
    });
    r.on('error', rej);
    r.end(data);
  });
  const known = [];
  for (let i = 0; i < 25; i++) known.push((await signup()).email);
  const order = [...known.map((e) => ['known', e]), ...known.map(() => ['unknown', `nobody-${rnd()}@example.com`])].sort(() => Math.random() - 0.5);
  const after = { known: [], unknown: [] };
  await time(agents[1], 'GET', '/api/auth/session');
  for (const [kind, email] of order) {
    await time(agents[0], 'POST', '/api/auth/forgot', { email });
    after[kind].push(await time(agents[1], 'GET', '/api/auth/session'));
    await sleep(30);
  }
  const diff = median(after.known) - median(after.unknown);
  t.diagnostic(`median next-request time: known ${median(after.known).toFixed(2)} ms, unknown ${median(after.unknown).toFixed(2)} ms`);
  // Noise measured on the fixed code: up to 0.9 ms either way. The bug it guards against measured 1.9 to 3 ms.
  assert.ok(diff < 1.5, `known is slower by ${diff.toFixed(2)} ms`);
});

// ---- 2. The link ----

test('link: forged Host and X-Forwarded-Host never reach the mail, even with TRUST_PROXY', { skip: NEEDS }, async () => {
  const { email } = await signup();
  assert.equal((await forgot(email, BASE, { 'X-Forwarded-Host': 'evil.example', 'X-Forwarded-Proto': 'http' })).status, 200);
  assert.match((await nextMail(email, sink, 0)).text, new RegExp(`${BASE.replace(/[/.]/g, '\\$&')}/reset#[\\w-]+`));

  const { email: raw } = await signup();
  await new Promise((res, rej) => {
    const body = JSON.stringify({ email: raw });
    const c = net.connect(Number(new URL(BASE).port), '127.0.0.1', () => c.write(`POST /api/auth/forgot HTTP/1.1\r\nHost: evil.example\r\nX-Forwarded-For: ${newIp()}\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`));
    c.on('data', () => {});
    c.on('end', res);
    c.on('error', rej);
  });
  const mail = await nextMail(raw, sink, 0);
  assert.ok(!mail.text.includes('evil.example'));
  assert.ok(mail.text.includes(`${BASE}/reset#`));
});

test('link: the token is stored only as its SHA-256, lasts one hour, and is not in the database files or the server log', { skip: NEEDS }, async () => {
  const { email } = await signup();
  assert.equal((await forgot(email)).status, 200);
  const token = tokenIn(await nextMail(email, sink, 0));
  assert.equal(Buffer.from(token, 'base64url').length, 24);
  const row = withDb((db) => db.prepare('SELECT r.* FROM password_resets r JOIN users u ON u.id = r.user_id WHERE u.email = ?').get(email));
  assert.equal(row.token_hash, crypto.createHash('sha256').update(token).digest('hex'));
  assert.equal(Date.parse(row.expires_at) - Date.parse(row.created_at), 36e5);
  for (const f of fs.readdirSync(DATA).filter((n) => n.startsWith('countersign.db'))) assert.ok(!fs.readFileSync(path.join(DATA, f)).includes(token), f);
  if (SERVER_LOG) assert.ok(!fs.readFileSync(SERVER_LOG, 'utf8').includes(token), 'server log');
});

test('link: twelve parallel uses let one through, and it is that password that works', { skip: NEEDS }, async () => {
  const { email } = await signup();
  const token = linkFor(email);
  const all = await Promise.all(Array.from({ length: 12 }, (_, i) => reset(token, `parallel password number ${i}`)));
  const won = all.flatMap((r, i) => (r.status === 200 ? [i] : []));
  assert.equal(won.length, 1, all.map((r) => r.status).join());
  for (const r of all) if (r.status !== 200) assert.deepEqual([r.status, r.data.error], [400, DEAD]);
  assert.equal((await login(email, `parallel password number ${won[0]}`)).status, 200);
});

test('link: past its hour the link is refused and the password stays', { skip: NEEDS }, async () => {
  const { email } = await signup();
  const token = linkFor(email);
  withDb((db) => db.prepare("UPDATE password_resets SET expires_at = '2000-01-01T00:00:00.000Z' WHERE token_hash = ?").run(crypto.createHash('sha256').update(token).digest('hex')));
  assert.deepEqual((await reset(token)).status, 400);
  assert.equal((await login(email, OLD)).status, 200);
});

// ---- 3. Mail bombing and look-alikes ----

test('mail limit: every spelling that reaches an account shares one count of 3', { skip: NEEDS }, async () => {
  const email = `kirs-${rnd()}@example.com`;
  await signup(BASE, email);
  const spellings = [email, email.toUpperCase(), `  ${email}  `, `\u00a0${email}\u00a0`, `\ufeff${email}`, `\t${email}\n`, email.replace('k', '\u212a'), email.replace('k', '\u212a').toUpperCase()];
  for (const s of spellings) {
    assert.equal((await forgot(s)).status, 200);
    await sleep(120);
  }
  await sleep(SETTLE);
  assert.equal(mailsTo(email).length, 3);
});

test('look-alikes: no other spelling reaches an account, and mail goes only to the stored address', { skip: NEEDS }, async () => {
  const email = `kirs-${rnd()}@example.com`;
  await signup(BASE, email);
  const before = sink.mails.length;
  const attacks = [
    email.replace('s', '\u017f'), email.replace('i', '\u0130'), email.replace('i', '\u0456'), email.replace('e', '\uff45'), `\u200b${email}`,
    `${email}\u0000`, `${email}\u0000x`, `${email}.`, email.replace('@', '+x@'), `"${email}"`, `<${email}>`,
    `${email},attacker@evil.example`, `${email};attacker@evil.example`, `attacker@evil.example,${email}`, `${email}\r\nBcc: attacker@evil.example`, `Team:${email}`,
  ];
  for (const a of attacks) assert.deepEqual((await forgot(a)).data, { ok: true }, JSON.stringify(a));
  await sleep(SETTLE);
  const toVictimOrEvil = sink.mails.slice(before).filter((m) => m.to.some((t) => t.includes(email) || t.includes('evil.example')));
  assert.deepEqual(toVictimOrEvil, []);
});

test('request limit: 20 an hour per address and per /64, then 429 for known and unknown alike', { skip: NEEDS }, async () => {
  const send = async (ip, email) => (await client(BASE, ip)('/api/auth/forgot', { body: { email } })).status;
  const prefix = `2001:db8:${crypto.randomInt(65535).toString(16)}:${crypto.randomInt(65535).toString(16)}`;
  const statuses = [];
  for (let i = 0; i < 21; i++) statuses.push(await send(`${prefix}::${(i + 1).toString(16)}`, `nobody-${rnd()}@example.com`));
  assert.deepEqual([statuses.filter((s) => s === 200).length, statuses.at(-1)], [20, 429]);
  const { email } = await signup();
  assert.equal(await send(`${prefix}::ffff`, email), 429);
  assert.equal(await send(`${prefix}::fffe`, `nobody-${rnd()}@example.com`), 429);
});

test('RST-11: an address in mail group syntax cannot be registered, so it cannot get round the mail limit', { skip: NEEDS }, async () => {
  const target = `group-target-${rnd()}@example.com`;
  for (const prefix of ['team', 'team2']) {
    const address = `${prefix}:${target}`;
    await client(BASE)('/api/auth/signup', { body: { name: 'G', email: address, password: OLD } });
    await forgot(address);
  }
  await sleep(SETTLE);
  assert.equal(mailsTo(target).length, 0);
});

// ---- 4. What was typed ----

test('typed text: a password typed into the email box reaches no database file and no log', { skip: NEEDS }, async () => {
  const secret = `TypedSecret${rnd()}`;
  for (const s of [secret, `${secret}@example.com`]) assert.equal((await forgot(s)).status, 200);
  await sleep(SETTLE);
  for (const f of fs.readdirSync(DATA).filter((n) => n.startsWith('countersign.db'))) assert.ok(!fs.readFileSync(path.join(DATA, f)).includes(secret), f);
  if (SERVER_LOG) assert.ok(!fs.readFileSync(SERVER_LOG, 'utf8').includes(secret), 'server log');
});

// ---- 5. What a reset ends, and what it leaves ----

test('reset: ends sessions, revokes keys, pauses webhooks, clears the caller\'s cookie, and spends every link', { skip: NEEDS }, async () => {
  const { call, email } = await signup();
  const key = (await call('/api/api-keys', { body: { name: 'k' } })).data.key;
  assert.ok(key);
  const hook = await call('/api/webhooks', { body: { url: 'https://hook.example.test/x', events: ['document.completed'] } });
  assert.equal(hook.status, 201, JSON.stringify(hook.data));
  const [a, b] = [linkFor(email), linkFor(email)];
  const second = client(BASE);
  assert.equal((await second('/api/auth/login', { body: { email, password: OLD } })).status, 200);

  const r = await call('/api/auth/reset', { body: { token: a, password: NEW } });
  assert.equal(r.status, 200);
  assert.ok(r.set.some((c) => c.startsWith('cs_session=;') && /Max-Age=0/.test(c)), 'the caller\'s cookie is cleared');
  assert.equal(await live(second), 401);
  assert.equal((await fetch(`${BASE}/api/documents`, { headers: { Authorization: `Bearer ${key}` } })).status, 401);
  assert.equal(withDb((db) => db.prepare('SELECT active FROM webhooks WHERE id = ?').get(hook.data.id)).active, 0);
  assert.equal((await reset(b, 'yet another long password')).status, 400);
  assert.equal((await login(email, OLD)).status, 401);
  assert.equal((await login(email, NEW)).status, 200);
});

test('reset: a session of another account sent along with the request survives server side and gains nothing', { skip: NEEDS }, async () => {
  const { call } = await signup();
  const { email: victim } = await signup();
  const stale = call.jar.cs_session;
  assert.equal((await call('/api/auth/reset', { body: { token: linkFor(victim), password: NEW } })).status, 200);
  const other = client(BASE);
  other.jar.cs_session = stale;
  assert.equal(await live(other), 200);
});

// RST-6: the same key also keeps the owner locked at that address. The server can't tell a guesser from the owner's laptop.
test('lockouts: a reset gives an outside guesser nothing: their own lock stays', { skip: NEEDS }, async () => {
  const { email } = await signup();
  const guesser = newIp();
  for (let i = 0; i < 5; i++) await login(email, 'a wrong guess here', BASE, guesser);
  assert.equal((await login(email, 'a wrong guess here', BASE, guesser)).status, 429);
  assert.equal((await reset(linkFor(email))).status, 200);
  assert.equal((await login(email, 'a wrong guess here', BASE, guesser)).status, 429);
});

test('RST-2: a sign-in already in flight with the old password gets no session after a reset', { skip: NEEDS }, async (t) => {
  const { email } = await signup();
  // Thirty wrong guesses from anywhere make the next attempt wait 5 seconds, holding the old hash.
  const pumps = Array.from({ length: 30 }, () => login(email, 'a wrong guess here'));
  await sleep(500);
  const attacker = client(BASE);
  const inFlight = attacker('/api/auth/login', { body: { email, password: OLD } });
  await sleep(300);
  assert.equal((await reset(linkFor(email))).status, 200);
  assert.equal((await login(email, OLD)).status, 401, 'the old password is dead by now');
  const r = await inFlight;
  await Promise.all(pumps);
  t.diagnostic(`login begun before the reset answered ${r.status}, its session answers ${await live(attacker)}`);
  assert.notEqual(r.status, 200);
  assert.equal(await live(attacker), 401);
});

test('RST-3: an invite planted before the reset stops working', { skip: NEEDS }, async () => {
  const { call, email: victim } = await signup();
  assert.equal((await call('/api/teams', { body: { name: `T ${rnd()}` } })).status, 201);
  const invite = await call('/api/teams/invites', { body: { email: `accomplice-${rnd()}@example.com`, role: 'admin' } });
  assert.equal(invite.status, 201, JSON.stringify(invite.data));
  const accomplice = withDb((db) => db.prepare('SELECT email FROM team_invites WHERE id = ?').get(invite.data.id)).email;
  assert.equal((await reset(linkFor(victim))).status, 200);
  const { call: other } = await signup(BASE, accomplice);
  const joined = await other('/api/teams/join', { body: { token: invite.data.url.split('/join/')[1] } });
  assert.notEqual(joined.status, 200, 'the accomplice joined as admin after the reset');
});

test('RST-4: a half-finished reset does not leave API keys alive with the link spent', { skip: NEEDS }, async (t) => {
  const { call, email } = await signup();
  const key = (await call('/api/api-keys', { body: { name: 'k' } })).data.key;
  const token = linkFor(email);
  withDb((db) => db.exec("CREATE TRIGGER rst_k BEFORE UPDATE ON api_keys BEGIN SELECT RAISE(ABORT, 'rst'); END"));
  let r;
  try {
    r = await reset(token);
  } finally {
    withDb((db) => db.exec('DROP TRIGGER rst_k'));
  }
  const oldPassword = (await login(email, OLD)).status;
  const viaKey = (await fetch(`${BASE}/api/documents`, { headers: { Authorization: `Bearer ${key}` } })).status;
  const again = (await reset(token, 'one more long password')).status;
  t.diagnostic(`reset answered ${r.status}; afterwards old password ${oldPassword}, API key ${viaKey}, same link ${again}`);
  assert.equal(r.status, 500);
  // Either the whole reset rolled back (old password, link still good) or it finished. Not password changed, key alive, link gone.
  assert.deepEqual([oldPassword, viaKey, again], [200, 200, 200]);
});

test('RST-5: the owner hears about a completed reset', { skip: NEEDS }, async () => {
  const { email } = await signup();
  assert.equal((await reset(linkFor(email))).status, 200);
  await sleep(500);
  assert.equal(mailsTo(email).length, 1);
});

test('password change: links already out die, and a new password is required to be valid before it spends anything', { skip: NEEDS }, async () => {
  const { call, email } = await signup();
  const token = linkFor(email);
  assert.equal((await reset(token, 'short')).status, 400);
  assert.equal((await reset(token, email)).status, 400);
  assert.equal((await call('/api/account', { method: 'PATCH', body: { currentPassword: OLD, newPassword: NEW } })).status, 200);
  assert.equal((await reset(token, 'third long password here')).status, 400);
});

// ---- 6. Single sign-on ----

test('OIDC_REQUIRED: a connected account gets no link, the mail says so, and a link made by hand is refused', { skip: NEEDS_SSO }, async () => {
  const u = newSsoUser();
  const call = client(REQUIRED);
  assert.match(await ssoSignIn(call, u), /\/app/);
  assert.equal((await forgot(u.email, REQUIRED)).status, 200);
  const mail = await nextMail(u.email, ssoSink, 0);
  assert.equal(tokenIn(mail), undefined);
  assert.match(mail.text, /no password to reset/);
  const r = await reset(linkFor(u.email, REQUIRED_DATA), NEW, REQUIRED);
  assert.equal(r.status, 403);
  assert.equal((await login(u.email, NEW, REQUIRED)).status, 401);
  assert.equal(await live(call), 200, 'a refused reset ends nothing');
});

test('OIDC_REQUIRED: a link sent before the account connected is refused once it has', { skip: NEEDS_SSO }, async () => {
  const u = newSsoUser();
  assert.match(await ssoSignIn(client(REQUIRED), u), /\/app/);
  leftIssuer(REQUIRED_DATA, u.email); // not connected to the current issuer while the link is made
  const token = linkFor(u.email, REQUIRED_DATA);
  withDb((db) => db.prepare('UPDATE oidc_identities SET issuer = ? WHERE user_id = (SELECT id FROM users WHERE email = ?)').run(ISSUER, u.email), REQUIRED_DATA);
  assert.equal((await reset(token, NEW, REQUIRED)).status, 403);
});

test('RST-7: under OIDC_REQUIRED a changed issuer does not hand a password to someone removed at the provider', { skip: NEEDS_SSO }, async (t) => {
  const u = newSsoUser();
  const first = client(REQUIRED);
  assert.match(await ssoSignIn(first, u), /\/app/);
  assert.equal((await login(u.email, OLD, REQUIRED)).status, 401, 'an account made by SSO has no known password');
  // The operator moves provider. This person was not carried over, but their mailbox still reads.
  leftIssuer(REQUIRED_DATA, u.email);
  assert.equal((await forgot(u.email, REQUIRED)).status, 200);
  const token = tokenIn(await nextMail(u.email, ssoSink, 0));
  t.diagnostic(`mail held a link: ${Boolean(token)}`);
  const r = await reset(token ?? linkFor(u.email, REQUIRED_DATA), NEW, REQUIRED);
  const signIn = await login(u.email, NEW, REQUIRED);
  t.diagnostic(`reset answered ${r.status}, password sign-in answered ${signIn.status}`);
  assert.notEqual(signIn.status, 200);
});

test('RST-8: an address that moved at the provider cannot be used to take the old account', { skip: NEEDS_SSO }, async (t) => {
  const first = newSsoUser();
  const owner = client(SSO);
  assert.match(await ssoSignIn(owner, first), /\/app/);
  const renamed = `renamed-${rnd()}@allowed.test`;
  assert.match(await ssoSignIn(client(SSO), { sub: first.sub, email: renamed }), /\/app/);
  // The provider now gives the old address to somebody else. SSO refuses them, which is the part SSO-16 called fail closed.
  assert.doesNotMatch((await ssoSignIn(client(SSO), { sub: `sub-${rnd()}`, email: first.email })) || '', /\/app/);
  assert.equal((await forgot(first.email, SSO)).status, 200);
  const mail = await nextMail(first.email, ssoSink, 0);
  const token = tokenIn(mail);
  t.diagnostic(`the mail to the old address held a link: ${Boolean(token)}`);
  if (token) {
    const used = await reset(token, NEW, SSO);
    const signIn = await login(first.email, NEW, SSO);
    t.diagnostic(`the new holder of the address: reset ${used.status}, password sign-in ${signIn.status}, the first person's session ${await live(owner)}`);
  }
  assert.equal(token, undefined);
});

test('reset does not touch identities: the same provider subject still opens the account afterwards', { skip: NEEDS_SSO }, async () => {
  const u = newSsoUser();
  assert.match(await ssoSignIn(client(SSO), u), /\/app/);
  leftIssuer(SSO_DATA, u.email);
  assert.equal((await reset(linkFor(u.email, SSO_DATA), NEW, SSO)).status, 200);
  withDb((db) => db.prepare('UPDATE oidc_identities SET issuer = ? WHERE user_id = (SELECT id FROM users WHERE email = ?)').run(ISSUER, u.email), SSO_DATA);
  assert.match(await ssoSignIn(client(SSO), u), /\/app/);
  // A stolen session can't plant another person's subject: the claim must carry this account's email.
  const stolen = client(SSO);
  assert.equal((await stolen('/api/auth/login', { body: { email: u.email, password: NEW } })).status, 200);
  const connect = await stolen('/api/auth/oidc/connect', { body: {} });
  assert.equal(connect.status, 200, JSON.stringify(connect.data));
  const auth = new URL(connect.data.url).searchParams;
  const code = rnd();
  codes.set(code, { claims: { sub: `attacker-${rnd()}`, email: `attacker-${rnd()}@allowed.test` }, nonce: auth.get('nonce') });
  await stolen(`/api/auth/oidc/callback?code=${code}&state=${encodeURIComponent(auth.get('state'))}`, { method: 'GET' });
  assert.equal(withDb((db) => db.prepare('SELECT COUNT(*) AS n FROM oidc_identities i JOIN users u ON u.id = i.user_id WHERE u.email = ?').get(u.email), SSO_DATA).n, 1);
});

// ---- 7. The script ----

test('script: runs with built-ins only from a folder with no node_modules, and its link works', { skip: NEEDS }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rst-script-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, 'scripts'));
  fs.copyFileSync(SCRIPT, path.join(dir, 'scripts', 'reset-link.mjs'));
  const { email } = await signup();
  const r = runScript([email], DATA, { script: 'scripts/reset-link.mjs', cwd: dir });
  assert.equal(r.status, 0, r.stderr);
  const token = r.stdout.trim().match(/^http:\/\/cs\.example\/reset#([\w-]+)$/)?.[1];
  assert.ok(token, r.stdout);
  const row = withDb((db) => db.prepare('SELECT r.* FROM password_resets r JOIN users u ON u.id = r.user_id WHERE u.email = ?').get(email));
  assert.equal(row.token_hash, crypto.createHash('sha256').update(token).digest('hex'));
  assert.equal(Date.parse(row.expires_at) - Date.parse(row.created_at), 36e5);
  const event = withDb((db) => db.prepare("SELECT * FROM security_events WHERE type = 'password_reset_request' AND email = ?").get(email));
  assert.ok(event?.user_id);
  assert.ok(!event.detail.includes(token));
  assert.equal((await reset(token)).status, 200);
});

test('script: matches case only, as SQLite NOCASE does, and refuses anything else with no row', { skip: NEEDS }, async () => {
  const { email } = await signup();
  assert.equal(runScript([email.toUpperCase()]).status, 0);
  const rows = () => withDb((db) => db.prepare('SELECT COUNT(*) AS n FROM password_resets r JOIN users u ON u.id = r.user_id WHERE u.email = ?').get(email)).n;
  assert.equal(rows(), 1);
  for (const bad of [` ${email}`, `${email} `, email.replace('e', '\uff45'), '%', `${email}' OR '1'='1`]) assert.equal(runScript([bad]).status, 1, bad);
  assert.equal(rows(), 1);
});

test('RST-9: the script leaves no database behind when DATA_DIR is wrong', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rst-empty-'));
  try {
    const r = runScript(['a@example.com'], dir);
    assert.ok(!fs.readdirSync(dir).includes('countersign.db'), 'an empty database was created');
    assert.ok(!/at .*reset-link\.mjs/.test(r.stderr), r.stderr);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---- 8. Same origin and odd bodies ----

test('both POSTs: another origin is refused even with a valid token, in JSON and as a form', { skip: NEEDS }, async () => {
  const { email } = await signup();
  const token = linkFor(email);
  for (const origin of ['http://evil.example', 'null', `${BASE}.evil.example`]) {
    const form = await client(BASE)('/api/auth/reset', { raw: `token=${token}&password=${encodeURIComponent(NEW)}`, headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' } });
    assert.equal(form.status, 403, origin);
    assert.equal((await client(BASE)('/api/auth/reset', { body: { token, password: NEW }, headers: { Origin: origin } })).status, 403, origin);
    assert.equal((await client(BASE)('/api/auth/forgot', { body: { email }, headers: { Origin: origin } })).status, 403, origin);
  }
  assert.equal((await login(email, OLD)).status, 200);
  assert.equal((await reset(token)).status, 200, 'none of that spent the link');
});

test('both POSTs: odd bodies get a clean answer, never a 500', { skip: NEEDS }, async () => {
  const bodies = [{}, { raw: 'null' }, { raw: '[1]' }, { raw: '5' }, { raw: '"x"' }, { raw: '{' }, { body: { email: { $ne: 1 }, token: { a: 1 }, password: {} } }, { body: { email: ['a@b.c'], token: ['x'], password: ['y'] } },
    { raw: '{"__proto__":{"email":"x@y.z"},"constructor":{"prototype":{"polluted":1}}}' }, { raw: '{"email":"a@b.c"}', headers: { 'Content-Type': 'text/plain' } }, { body: { email: 'a'.repeat(400000), token: 'b'.repeat(400000) } }];
  for (const b of bodies) {
    const [f, r] = [await client(BASE)('/api/auth/forgot', b), await client(BASE)('/api/auth/reset', b)];
    assert.ok([200, 400].includes(f.status), `forgot ${JSON.stringify(b).slice(0, 60)}: ${f.status}`);
    assert.equal(r.status, 400, `reset ${JSON.stringify(b).slice(0, 60)}: ${r.status}`);
  }
  for (const [method, status] of [['GET', 405], ['PUT', 405]]) assert.equal((await client(BASE)('/api/auth/reset', { method })).status, status);
  assert.equal((await client(BASE)('/api/auth/reset', { body: {}, headers: { Authorization: 'Bearer cs_x' } })).status, 401);
});

// ---- 9. Copy ----

test('copy: no compliance or legal claim in anything this change added', () => {
  const files = ['pages/api/auth/forgot.js', 'pages/api/auth/reset.js', 'pages/forgot.js', 'pages/reset.js', 'scripts/reset-link.mjs', 'test/reset.test.mjs'];
  for (const f of files) {
    const text = fs.readFileSync(path.join(ROOT, f), 'utf8');
    assert.doesNotMatch(text, /complian|legally|binding|certified|eidas|\bueta\b|\besign\b/i, f);
  }
});
