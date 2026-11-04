// P0 security controls over HTTP: password policy, login rate limit, hashed sessions with timeouts,
// logout-all, hashed/expiring/revocable signing tokens, links after completion, hash-chained audit trail.
// Needs a running server (fresh DATA_DIR, ALLOW_SIGNUP=true, default TOKEN_TTL_DAYS / LOGIN_MAX_ATTEMPTS):
//   BASE_URL=http://localhost:3127 DATA_DIR=<the server's DATA_DIR> node --test test/p0.test.mjs
// DB checks need DATA_DIR and are skipped without it; chain checks also need the key (ENCRYPTION_KEY in the test env, or
// DATA_DIR/encryption.key). SERVER_LOG=<server stdout file> enables the audit_head log-anchor check.
// Start the server with SIGNUP_MAX_PER_HOUR=1000: this file signs up about 20 accounts from one IP.
// Remind test: also start the server with SMTP_HOST=127.0.0.1 SMTP_PORT=<P> APP_URL=<BASE_URL> and set QA_SMTP_SINK_PORT=<P>.
// Each run adds 10 failed logins from this IP (per-IP lock LOGIN_IP_MAX_ATTEMPTS, default 50 per 15 minutes).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const DATA = process.env.DATA_DIR;
const NEEDS_DB = !DATA && 'needs DATA_DIR pointing at the server data folder';
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const PASSWORD = 'correct horse battery';
const DAY = 864e5;
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const uniq = (p) => `${p}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;

let _db;
const db = () => (_db ??= new DatabaseSync(path.join(DATA, 'countersign.db')));
test.after(() => _db?.close());

function key() {
  const s = (process.env.ENCRYPTION_KEY || fs.readFileSync(path.join(DATA, 'encryption.key'), 'utf8')).trim();
  return Buffer.from(s, /^[0-9a-f]{64}$/i.test(s) ? 'hex' : 'base64');
}
function decText(v, aad) {
  const b = Buffer.from(v.slice('enc:v1:'.length), 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', key(), b.subarray(4, 16));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(b.subarray(16, 32));
  return Buffer.concat([d.update(b.subarray(32)), d.final()]).toString('utf8');
}
// Independent copy of the documented chain link (lib/crypto.js auditHash): hex HMAC-SHA256 under an HKDF subkey of the encryption key.
let _auditKey;
const auditKey = () => (_auditKey ??= Buffer.from(crypto.hkdfSync('sha256', key(), Buffer.alloc(0), 'countersign-audit-v1', 32)));
const link = (prev, e) => crypto.createHmac('sha256', auditKey()).update((prev || '') + JSON.stringify({ document_id: e.document_id, actor: e.actor, action: e.action, detail: e.detail ?? '', ip: e.ip ?? null, user_agent: e.user_agent ?? null, created_at: e.created_at })).digest('hex');
const eventsOf = (id) => db().prepare('SELECT * FROM events WHERE document_id = ? ORDER BY created_at, id').all(id);
function chainHead(id) {
  let prev = null;
  for (const e of eventsOf(id)) {
    if ((e.prev_hash ?? null) !== prev || e.hash !== link(prev, e)) return false;
    prev = e.hash;
  }
  return prev;
}
// All PDF content streams inflated, lowercased; pdf-lib writes text as hex strings.
function pdfText(buf) {
  const b = buf.toString('latin1');
  let out = b;
  for (const m of b.matchAll(/stream\r?\n/g)) {
    const start = m.index + m[0].length;
    try { out += zlib.inflateSync(Buffer.from(b.slice(start, b.indexOf('endstream', start)), 'latin1')).toString('latin1'); } catch {}
  }
  return out.toLowerCase();
}
const hex = (s) => Buffer.from(s, 'latin1').toString('hex');

function client() {
  let cookie = '';
  const call = async (p, { method = 'POST', body, headers = {} } = {}) => {
    const raw = body instanceof Uint8Array;
    const res = await fetch(BASE + p, {
      method,
      headers: { ...(raw ? {} : { 'Content-Type': 'application/json' }), ...(cookie && { cookie }), ...headers },
      body: body == null ? undefined : raw ? body : JSON.stringify(body),
    });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    const type = res.headers.get('content-type') || '';
    return { status: res.status, headers: res.headers, data: type.includes('json') ? await res.json() : Buffer.from(await res.arrayBuffer()) };
  };
  call.cookie = () => cookie.split('=').slice(1).join('=');
  call.me = async () => (await call('/api/auth/session', { method: 'GET' })).data.user;
  return call;
}

async function signup(email = uniq('p0'), password = PASSWORD) {
  const call = client();
  const r = await call('/api/auth/signup', { body: { name: 'P0 Owner', email, password } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return Object.assign(call, { email });
}
async function login(email, password = PASSWORD) {
  const call = client();
  const r = await call('/api/auth/login', { body: { email, password } });
  return Object.assign(call, { res: r });
}
const securityEvents = (type, email) => db().prepare('SELECT * FROM security_events WHERE type = ? AND email = ?').all(type, email);

const anon = client();
const sigId = async (t) => (await anon(`/sign/${t}`, { method: 'GET' })).data.toString().match(/"id":"([\w-]+)","type":"signature"[^}]*"mine":true/)[1];
const sign = async (t) => (await anon(`/api/sign/${t}`, { body: { values: { [await sigId(t)]: PNG } } })).data;

// Two sequential signers (Ana, Ben) and a cc (Cat). Tokens and DB rows in that order.
async function sentDoc(call, title = 'P0') {
  const pdf = await PDFDocument.create(); pdf.addPage([612, 792]); pdf.addPage([612, 792]);
  const up = await call('/api/documents', { body: await pdf.save(), headers: { 'Content-Type': 'application/pdf', 'x-file-name': `${title}.pdf` } });
  assert.equal(up.status, 201);
  const id = up.data.id;
  const draft = {
    title, sequential: true,
    recipients: [{ id: 'a', name: 'Ana', email: 'ana@example.com', role: 'signer' }, { id: 'b', name: 'Ben', email: 'ben@example.com', role: 'signer' }, { id: 'c', name: 'Cat', email: 'cat@example.com', role: 'cc' }],
    fields: [{ recipientId: 'a', type: 'signature', page: 0, x: 0.1, y: 0.8, w: 0.3, h: 0.06 }, { recipientId: 'b', type: 'signature', page: 1, x: 0.1, y: 0.8, w: 0.3, h: 0.06 }],
  };
  assert.equal((await call(`/api/documents/${id}`, { method: 'PUT', body: draft })).status, 200);
  assert.equal((await call(`/api/documents/${id}/send`)).status, 200);
  const html = (await call(`/app/documents/${id}`, { method: 'GET' })).data.toString();
  const tokens = [...html.matchAll(/"token":"([\w-]+)"/g)].map((m) => m[1]);
  assert.equal(tokens.length, 3, 'owner page exposes the three links');
  const recips = DATA ? db().prepare('SELECT * FROM recipients WHERE document_id = ? ORDER BY position').all(id) : [];
  return { id, tokens, recips };
}

// ---------- Passwords ----------

test('password policy on signup: 12..256 chars, not the email; existing short passwords are not tested here', async () => {
  const call = client();
  const email = uniq('pw');
  const r = await call('/api/auth/signup', { body: { name: 'P', email, password: 'elevenchars' } });
  assert.equal(r.status, 400);
  assert.equal(r.data.error, 'Password must be at least 12 characters');
  assert.equal((await call('/api/auth/signup', { body: { name: 'P', email, password: 'x'.repeat(257) } })).status, 400);
  assert.equal((await call('/api/auth/signup', { body: { name: 'P', email, password: email.toUpperCase() } })).status, 400, 'password equal to email');
  assert.equal((await call('/api/auth/signup', { body: { name: 'P', email, password: 'twelve chars' } })).status, 200, 'exactly 12 is allowed');
});

test('password change: needs the current password, enforces policy, revokes other sessions only', async () => {
  const a = await signup();
  const b = await login(a.email);
  assert.equal(b.res.status, 200);
  assert.equal((await a('/api/account', { method: 'PATCH', body: { currentPassword: 'wrong password!', newPassword: 'another long password' } })).status, 400);
  const short = await a('/api/account', { method: 'PATCH', body: { currentPassword: PASSWORD, newPassword: 'short' } });
  assert.equal(short.status, 400);
  assert.equal(short.data.error, 'Password must be at least 12 characters');
  assert.ok(await b.me(), 'failed changes revoke nothing');
  assert.equal((await a('/api/account', { method: 'PATCH', body: { currentPassword: PASSWORD, newPassword: 'another long password' } })).status, 200);
  assert.ok(await a.me(), 'the session that changed the password stays signed in');
  assert.equal(await b.me(), null, 'other sessions are revoked');
  assert.equal((await login(a.email)).res.status, 401, 'old password no longer works');
  assert.equal((await login(a.email, 'another long password')).res.status, 200);
  if (DATA) {
    const ev = securityEvents('password_change', a.email);
    assert.equal(ev.length, 1);
    assert.match(ev[0].detail, /^1 other sessions and 0 API keys revoked$/);
  }
});

// ---------- Login ----------

test('login: same generic 401 for unknown email and wrong password', async () => {
  const a = await signup();
  const unknown = (await login(uniq('nobody'), 'whatever password')).res;
  const wrong = (await login(a.email, 'wrong password!')).res;
  assert.equal(unknown.status, 401);
  assert.equal(wrong.status, 401);
  assert.deepEqual(unknown.data, wrong.data);
  assert.deepEqual(wrong.data, { error: 'Email or password is incorrect' });
});

test('login: 5 failures lock the account (429 + Retry-After), even for the right password; failures are logged without the password', async () => {
  const a = await signup();
  const bad = 'wrong password QA-SECRET-9921';
  for (let i = 1; i <= 5; i++) assert.equal((await login(a.email, bad)).res.status, 401, `attempt ${i}`);
  const locked = (await login(a.email)).res;
  assert.equal(locked.status, 429);
  assert.equal(locked.data.error, 'Too many sign-in attempts. Try again later.');
  const retry = Number(locked.headers.get('retry-after'));
  assert.ok(retry > 0 && retry <= 15 * 60, `Retry-After ${retry}`);
  assert.ok(await a.me(), 'existing sessions are not affected by the lock');
  if (!DATA) return;
  assert.equal(securityEvents('login_failure', a.email).length, 5);
  assert.ok(securityEvents('login_locked', a.email).length >= 2, 'lock reached + locked attempt');
  assert.equal(securityEvents('login_success', a.email).length, 0);
  const dump = JSON.stringify(db().prepare('SELECT * FROM security_events WHERE email = ?').all(a.email));
  assert.ok(!dump.includes('QA-SECRET') && !dump.includes(PASSWORD), 'no password in security_events');
});

test('login success clears the account counter and is logged', { skip: NEEDS_DB }, async () => {
  const a = await signup();
  for (let i = 0; i < 2; i++) assert.equal((await login(a.email, 'wrong password!')).res.status, 401);
  assert.equal((await login(a.email)).res.status, 200);
  assert.equal(db().prepare('SELECT COUNT(*) n FROM login_attempts WHERE key = ?').get(`acct:${a.email}`).n, 0);
  assert.equal(securityEvents('login_success', a.email).length, 1);
  assert.equal(securityEvents('signup', a.email).length, 1);
});

// ---------- Sessions ----------

test('sessions: DB stores only sha256 of the cookie; idle and absolute timeouts end the session', { skip: NEEDS_DB }, async () => {
  const a = await signup();
  const cookie = a.cookie();
  assert.ok(cookie.length >= 32);
  const row = db().prepare('SELECT * FROM sessions WHERE id_hash = ?').get(sha(cookie));
  assert.ok(row, 'session found by hash');
  assert.notEqual(row.id, cookie);
  assert.equal(db().prepare('SELECT COUNT(*) n FROM sessions WHERE id = ?').get(cookie).n, 0, 'cookie value not stored');
  assert.ok(Date.parse(row.expires_at) <= Date.now() + 7 * DAY + 6e4, 'absolute expiry <= 7 days');

  db().prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(new Date(Date.now() - 61 * 6e4).toISOString(), row.id);
  assert.equal(await a.me(), null, 'idle > 60 min ends the session');
  assert.equal(db().prepare('SELECT COUNT(*) n FROM sessions WHERE id = ?').get(row.id).n, 0, 'expired row deleted');
  assert.equal(db().prepare("SELECT COUNT(*) n FROM security_events WHERE type = 'session_expired' AND email = ?").get(a.email).n, 1);

  const b = await login(a.email);
  const rowB = db().prepare('SELECT id FROM sessions WHERE id_hash = ?').get(sha(b.cookie()));
  db().prepare('UPDATE sessions SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), rowB.id);
  assert.equal(await b.me(), null, 'absolute timeout ends the session even when active');
  assert.equal((await b('/api/documents/nope/file', { method: 'GET' })).status, 401);
});

test('POST /api/auth/logout-all ends every session including this one and clears the cookie', async () => {
  const a = await signup();
  const b = await login(a.email);
  const r = await a('/api/auth/logout-all');
  assert.equal(r.status, 200);
  assert.deepEqual(r.data, { ok: true });
  assert.match(r.headers.get('set-cookie') || '', /cs_session=;.*Max-Age=0/);
  assert.equal(await b.me(), null);
  const stale = client();
  assert.equal((await stale('/api/auth/session', { method: 'GET', headers: { cookie: `cs_session=${b.cookie()}` } })).data.user, null);
  assert.equal((await client()('/api/auth/logout-all')).status, 401, 'requires a session');
  const c = await login(a.email);
  assert.equal((await c('/api/auth/logout-all', { headers: { Origin: 'https://evil.example' } })).status, 403, 'same-origin check');
  assert.ok(await c.me());
  if (DATA) assert.equal(securityEvents('logout_all', a.email)[0]?.detail, '2 sessions');
});

// ---------- Signing tokens ----------

test('signing tokens: only hash + ciphertext stored, ~30 day expiry; unknown token is 404 on API and page', async () => {
  const call = await signup();
  const d = await sentDoc(call);
  assert.equal((await anon('/api/sign/nope-not-a-token/file', { method: 'GET' })).status, 404);
  assert.equal((await anon('/api/sign/nope-not-a-token', { body: { values: {} } })).status, 404);
  assert.equal((await anon('/sign/nope-not-a-token', { method: 'GET' })).status, 404);
  if (!DATA) return;
  for (const [i, r] of d.recips.entries()) {
    assert.equal(r.token, null, 'no plaintext token column value');
    assert.equal(r.token_hash, sha(d.tokens[i]));
    assert.equal(decText(r.token_enc, `token:${r.id}`), d.tokens[i]);
    const ttl = Date.parse(r.token_expires_at) - Date.now();
    assert.ok(ttl > 29.9 * DAY && ttl <= 30 * DAY, 'expires in 30 days');
    assert.equal(r.token_revoked_at, null);
  }
});

test('expired link: 410 on file, sign, decline and the /sign page; nothing changes; token_expired logged', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const d = await sentDoc(call);
  const [ta] = d.tokens;
  db().prepare('UPDATE recipients SET token_expires_at = ? WHERE id = ?').run('2000-01-01T00:00:00.000Z', d.recips[0].id);
  const file = await anon(`/api/sign/${ta}/file`, { method: 'GET' });
  assert.equal(file.status, 410);
  assert.equal(file.data.error, 'This signing link has expired.');
  assert.equal((await anon(`/api/sign/${ta}`, { body: { values: {} } })).status, 410);
  assert.equal((await anon(`/api/sign/${ta}/decline`, { body: { reason: 'x' } })).status, 410);
  const page = await anon(`/sign/${ta}`, { method: 'GET' });
  assert.equal(page.status, 410);
  const html = page.data.toString();
  assert.match(html, /This signing link has expired/);
  // Next echoes the URL's own query in __NEXT_DATA__ (requester already holds it, no-store); the page props must not carry it.
  assert.match(html, /"pageProps":{"token":null,"state":"link-expired"/);
  assert.equal(db().prepare('SELECT status FROM recipients WHERE id = ?').get(d.recips[0].id).status, 'sent');
  assert.ok(db().prepare("SELECT COUNT(*) n FROM security_events WHERE type = 'token_expired' AND detail = ?").get(`recipient ${d.recips[0].id}`).n >= 1);
  const sec = JSON.stringify(db().prepare("SELECT * FROM security_events WHERE type = 'token_expired'").all());
  assert.ok(!sec.includes(ta), 'token never logged');
});

test('void revokes every link (410 "no longer valid" on API and page); no remind after void', async () => {
  const call = await signup();
  const d = await sentDoc(call);
  assert.equal((await call(`/api/documents/${d.id}/void`, { body: { reason: 'test' } })).status, 200);
  for (const t of d.tokens) {
    const r = await anon(`/api/sign/${t}/file`, { method: 'GET' });
    assert.equal(r.status, 410);
    assert.equal(r.data.error, 'This signing link is no longer valid.');
    const page = await anon(`/sign/${t}`, { method: 'GET' });
    assert.equal(page.status, 410);
    assert.match(page.data.toString(), /This signing link no longer works/);
  }
  assert.equal((await call(`/api/documents/${d.id}/void`, { body: {} })).status, 409);
  if (DATA) {
    assert.ok(db().prepare('SELECT * FROM recipients WHERE document_id = ?').all(d.id).every((x) => x.token_revoked_at));
    assert.equal((await call(`/api/documents/${d.id}/remind`, { body: { recipientId: d.recips[0].id } })).status, 409);
  }
});

test('decline revokes every link of the document', async () => {
  const call = await signup();
  const d = await sentDoc(call);
  assert.equal((await anon(`/api/sign/${d.tokens[0]}/decline`, { body: { reason: 'no' } })).status, 200);
  assert.equal((await anon(`/api/sign/${d.tokens[0]}/decline`, { body: { reason: 'again' } })).status, 410);
  for (const t of d.tokens) assert.equal((await anon(`/api/sign/${t}/file`, { method: 'GET' })).status, 410);
  if (DATA) assert.ok(db().prepare('SELECT * FROM recipients WHERE document_id = ?').all(d.id).every((x) => x.token_revoked_at));
});

// ---------- After completion: every link still opens the completed page and downloads the signed PDF ----------

test('after completion every signer and cc link loads the completed page and downloads the signed PDF', async () => {
  const call = await signup();
  const d = await sentDoc(call, 'P0 Complete');
  assert.deepEqual(await sign(d.tokens[0]), { status: 'sent' });
  assert.deepEqual(await sign(d.tokens[1]), { status: 'completed' });
  const owned = await call(`/api/documents/${d.id}/file?kind=signed`, { method: 'GET' });
  assert.equal(owned.status, 200);
  for (const [i, t] of d.tokens.entries()) {
    const who = ['Ana (signer 1)', 'Ben (signer 2)', 'Cat (cc)'][i];
    const page = await anon(`/sign/${t}`, { method: 'GET' });
    assert.equal(page.status, 200, `${who}: /sign page`);
    const html = page.data.toString();
    assert.match(html, /Everyone has signed/, `${who}: completed state`);
    assert.ok(html.includes(`/api/sign/${t}/file?download=1`), `${who}: download button points at own link`);
    const dl = await anon(`/api/sign/${t}/file?download=1`, { method: 'GET' });
    assert.equal(dl.status, 200, `${who}: download`);
    assert.equal(dl.headers.get('content-type'), 'application/pdf');
    assert.match(dl.headers.get('content-disposition'), /^attachment; filename\*=UTF-8''P0%20Complete%20\(signed\)\.pdf$/);
    assert.ok(dl.data.equals(owned.data), `${who}: same bytes as the owner's signed PDF`);
    const inline = await anon(`/api/sign/${t}/file`, { method: 'GET' });
    assert.equal(inline.status, 200);
    assert.match(inline.headers.get('content-disposition'), /^inline/);
  }
  assert.equal((await anon(`/api/sign/${d.tokens[0]}`, { body: { values: {} } })).status, 409, 'cannot sign a completed document');
  assert.equal((await anon(`/api/sign/${d.tokens[0]}/decline`, { body: {} })).status, 409, 'cannot decline a completed document');
  if (!DATA) return;
  for (const r of db().prepare('SELECT * FROM recipients WHERE document_id = ?').all(d.id)) {
    assert.equal(r.token_revoked_at, null, `${r.name}: not revoked on completion`);
    assert.ok(Date.parse(r.token_expires_at) > Date.now() + 29.9 * DAY, `${r.name}: expiry reset on completion`);
  }
});

test('a signer whose link expired while waiting gets it back on completion; expiry still applies afterwards', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const d = await sentDoc(call);
  assert.deepEqual(await sign(d.tokens[0]), { status: 'sent' });
  db().prepare('UPDATE recipients SET token_expires_at = ? WHERE id = ?').run('2000-01-01T00:00:00.000Z', d.recips[0].id);
  assert.equal((await anon(`/sign/${d.tokens[0]}`, { method: 'GET' })).status, 410);
  assert.deepEqual(await sign(d.tokens[1]), { status: 'completed' });
  assert.equal((await anon(`/api/sign/${d.tokens[0]}/file?download=1`, { method: 'GET' })).status, 200, 'completion re-extends');
  db().prepare('UPDATE recipients SET token_expires_at = ? WHERE id = ?').run('2000-01-01T00:00:00.000Z', d.recips[1].id);
  assert.equal((await anon(`/api/sign/${d.tokens[1]}/file?download=1`, { method: 'GET' })).status, 410, 'completed links still expire');
});

// ---------- Remind (needs SMTP sink) ----------

function smtpSink(port) {
  const server = net.createServer((s) => {
    let data = false, buf = '';
    s.write('220 sink\r\n');
    s.on('data', (c) => {
      buf += c.toString('latin1');
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0 || (data && buf.includes('\r\n.\r\n'))) {
        if (data) { const end = buf.indexOf('\r\n.\r\n'); if (end < 0) break; buf = buf.slice(end + 5); data = false; s.write('250 ok\r\n'); continue; }
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === 'EHLO' || cmd === 'HELO') s.write('250 sink\r\n');
        else if (cmd === 'DATA') { data = true; s.write('354 go\r\n'); }
        else if (cmd === 'QUIT') s.end('221 bye\r\n');
        else s.write('250 ok\r\n');
      }
    });
    s.on('error', () => {});
  });
  return new Promise((r) => server.listen(port, '127.0.0.1', () => r(server)));
}

test('remind extends an expired link by TOKEN_TTL_DAYS', {
  skip: (NEEDS_DB || !process.env.QA_SMTP_SINK_PORT) && 'needs DATA_DIR, QA_SMTP_SINK_PORT and a server with SMTP_HOST=127.0.0.1 SMTP_PORT=<same> APP_URL=<BASE_URL>',
}, async () => {
  const sink = await smtpSink(Number(process.env.QA_SMTP_SINK_PORT));
  try {
    const call = await signup();
    const d = await sentDoc(call);
    db().prepare('UPDATE recipients SET token_expires_at = ? WHERE id = ?').run('2000-01-01T00:00:00.000Z', d.recips[0].id);
    assert.equal((await anon(`/api/sign/${d.tokens[0]}/file`, { method: 'GET' })).status, 410);
    const r = await call(`/api/documents/${d.id}/remind`, { body: { recipientId: d.recips[0].id } });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.ok(Date.parse(db().prepare('SELECT token_expires_at e FROM recipients WHERE id = ?').get(d.recips[0].id).e) > Date.now() + 29.9 * DAY);
    assert.equal((await anon(`/api/sign/${d.tokens[0]}/file`, { method: 'GET' })).status, 200, 'link works again');
  } finally { sink.close(); }
});

// ---------- Audit chain ----------

test('audit chain: every event links to the previous one; certificate prints head and count', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const d = await sentDoc(call, 'P0 Chain');
  await sign(d.tokens[0]);
  await sign(d.tokens[1]);
  const evs = eventsOf(d.id);
  assert.ok(evs.length >= 5, `events: ${evs.map((e) => e.action).join(', ')}`);
  assert.equal(evs[0].prev_hash, null, 'chain starts at null');
  assert.ok(chainHead(d.id), 'HMAC chain verifies independently');
  const plainSha = (prev, e) => sha((prev || '') + JSON.stringify({ document_id: e.document_id, actor: e.actor, action: e.action, detail: e.detail ?? '', ip: e.ip ?? null, user_agent: e.user_agent ?? null, created_at: e.created_at }));
  assert.notEqual(evs[1].hash, plainSha(evs[1].prev_hash, evs[1]), 'links are keyed, not plain SHA-256');
  const completed = evs.at(-1);
  assert.equal(completed.action, 'Completed');
  const signed = (await call(`/api/documents/${d.id}/file?kind=signed`, { method: 'GET' })).data;
  assert.ok(completed.detail.includes(sha(signed)), 'Completed event binds the signed PDF hash into the chain');
  // The certificate cannot contain its own hash: it shows the chain up to the last Signed event.
  const text = pdfText(signed);
  assert.ok(text.includes(hex('Audit chain head').toLowerCase()), 'certificate label');
  assert.ok(text.includes(hex(completed.prev_hash)), 'certificate head = Completed.prev_hash');
  assert.ok(text.includes(hex(String(evs.length - 1))), 'certificate count excludes Completed');
  assert.ok(!text.includes(hex('chain broken')), 'no break reported');
  if (process.env.SERVER_LOG) {
    await new Promise((r) => setTimeout(r, 300)); // let stdout reach the log file
    const heads = fs.readFileSync(process.env.SERVER_LOG, 'utf8').split(/\r?\n/).filter((l) => l.startsWith('{"audit_head"'))
      .map((l) => JSON.parse(l).audit_head).filter((h) => h.document_id === d.id);
    assert.ok(heads.length, 'audit_head lines logged');
    assert.equal(heads.at(-1).count, evs.length, 'logged count = stored count');
    assert.equal(heads.at(-1).head, completed.hash, 'logged head = stored head');
  }
});

test('audit chain: an edited event is detected and the certificate says where the chain broke', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const d = await sentDoc(call, 'P0 Tamper');
  const victim = eventsOf(d.id).find((e) => e.action === 'Sent');
  assert.ok(victim);
  db().prepare("UPDATE events SET detail = '99 signer(s)' WHERE id = ?").run(victim.id);
  assert.equal(chainHead(d.id), false);
  await sign(d.tokens[0]);
  await sign(d.tokens[1]);
  const text = pdfText((await call(`/api/documents/${d.id}/file?kind=signed`, { method: 'GET' })).data);
  assert.ok(text.includes(hex(`chain broken at event ${victim.id}`)), 'brokenAt is the tampered row');
});

test('delete writes an encrypted audit tombstone with the final chain head before removing events', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const d = await sentDoc(call, 'P0 Tomb');
  assert.equal((await call(`/api/documents/${d.id}`, { method: 'DELETE' })).status, 409, 'sent documents cannot be deleted');
  assert.equal((await call(`/api/documents/${d.id}/void`, { body: { reason: 'test' } })).status, 200);
  const head = chainHead(d.id);
  const count = eventsOf(d.id).length;
  assert.ok(head);
  assert.equal((await call(`/api/documents/${d.id}`, { method: 'DELETE' })).status, 200);
  const tomb = db().prepare('SELECT * FROM audit_tombstones WHERE document_id = ?').get(d.id);
  assert.ok(tomb, 'tombstone written');
  assert.equal(tomb.final_hash, head);
  assert.equal(tomb.event_count, count);
  assert.equal(tomb.status, 'voided');
  assert.equal(tomb.title, 'P0 Tomb');
  assert.ok(tomb.events_json.startsWith('enc:v1:'));
  const kept = JSON.parse(decText(tomb.events_json, `tombstone:${d.id}`));
  assert.equal(kept.length, count);
  assert.equal(kept.at(-1).hash, head);
  assert.equal(eventsOf(d.id).length, 0, 'events removed with the document');
});

// ---------- H1: emails are unverified, so a matching account must not see another owner's links ----------

test('an account signed up with a recipient email sees no signing link of another owner on /app', async () => {
  const owner = await signup();
  const victim = uniq('victim');
  const pdf = await PDFDocument.create(); pdf.addPage([612, 792]);
  const up = await owner('/api/documents', { body: await pdf.save(), headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'H1.pdf' } });
  const id = up.data.id;
  await owner(`/api/documents/${id}`, { method: 'PUT', body: { title: 'H1 Secret Title', recipients: [{ id: 'v', name: 'Victim', email: victim, role: 'signer' }], fields: [{ recipientId: 'v', type: 'signature', page: 0, x: 0.1, y: 0.8, w: 0.3, h: 0.06 }] } });
  assert.equal((await owner(`/api/documents/${id}/send`)).status, 200);
  const html = (await owner(`/app/documents/${id}`, { method: 'GET' })).data.toString();
  const [token] = [...html.matchAll(/"token":"([\w-]+)"/g)].map((m) => m[1]);
  assert.ok(token);

  const attacker = await signup(victim);
  const page = await attacker('/app', { method: 'GET' });
  assert.equal(page.status, 200);
  const body = page.data.toString();
  assert.ok(!body.includes(token), 'victim token not rendered');
  assert.ok(!body.includes('H1 Secret Title'), 'other owner document not listed');
  assert.match(body, /"action":\[\]/, 'Needs your signature list is empty');

  // Owner signing their own document still gets it in the list.
  const self = await signup();
  const up2 = await self('/api/documents', { body: await pdf.save(), headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'Self.pdf' } });
  await self(`/api/documents/${up2.data.id}`, { method: 'PUT', body: { title: 'Self sign', recipients: [{ id: 's', name: 'Me', email: self.email, role: 'signer' }], fields: [{ recipientId: 's', type: 'signature', page: 0, x: 0.1, y: 0.8, w: 0.3, h: 0.06 }] } });
  assert.equal((await self(`/api/documents/${up2.data.id}/send`)).status, 200);
  assert.match((await self('/app', { method: 'GET' })).data.toString(), /"action":\[\{"id":"[\w-]+","title":"Self sign"/);
});
