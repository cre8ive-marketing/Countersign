// Self-check for the P0 security controls: migration, audit hash, password policy, login rate limit, sessions.
// Run: node scripts/security-selfcheck.mjs
// With BASE_URL=http://localhost:PORT (a disposable server, ALLOW_SIGNUP=true) it also checks the HTTP routes.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-sec-'));
process.env.DATA_DIR = dir;
process.env.ENCRYPTION_KEY = 'cd'.repeat(32);
for (const k of ['TOKEN_TTL_DAYS', 'SESSION_IDLE_MINUTES', 'SESSION_MAX_DAYS', 'LOGIN_MAX_ATTEMPTS', 'LOGIN_IP_MAX_ATTEMPTS', 'SIGNUP_MAX_PER_HOUR']) delete process.env[k];
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const auditKey = Buffer.from(crypto.hkdfSync('sha256', Buffer.from('cd'.repeat(32), 'hex'), Buffer.alloc(0), 'countersign-audit-v1', 32));
const hmac = (s) => crypto.createHmac('sha256', auditKey).update(s).digest('hex');
const canon = (prev, e) => (prev || '') + JSON.stringify({ document_id: e.document_id, actor: e.actor, action: e.action, detail: e.detail ?? '', ip: e.ip ?? null, user_agent: e.user_agent ?? null, created_at: e.created_at });

// A database in the pre-P0 shape, with plaintext tokens, a plaintext session and unhashed events.
fs.mkdirSync(path.join(dir, 'files'), { recursive: true });
const raw = new DatabaseSync(path.join(dir, 'countersign.db'));
raw.exec(`
CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE recipients (id TEXT PRIMARY KEY, document_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'signer', routing_order INTEGER NOT NULL DEFAULT 1, position INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending', token TEXT UNIQUE, viewed_at TEXT, signed_at TEXT, declined_reason TEXT, last_notified_at TEXT);
CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, document_id TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', ip TEXT, user_agent TEXT, created_at TEXT NOT NULL, prev_hash TEXT, hash TEXT);
INSERT INTO users VALUES ('u1', 'old@example.com', 'Old', 'x', '2026-01-01T00:00:00.000Z');
INSERT INTO sessions VALUES ('plaintext-cookie', 'u1', '2099-01-01T00:00:00.000Z');
INSERT INTO recipients (id, document_id, status, token) VALUES ('r1', 'd1', 'sent', 'tok-sent'), ('r2', 'd1', 'signed', 'tok-signed'), ('r3', 'd1', 'pending', NULL);
INSERT INTO events (document_id, actor, action, detail, ip, user_agent, created_at) VALUES
  ('d1', 'Old', 'created', '', '1.2.3.4', 'UA', '2026-01-01T00:00:02.000Z'),
  ('d1', 'Old', 'sent', 'to r1', NULL, NULL, '2026-01-01T00:00:01.000Z'),
  ('d2', 'Old', 'created', '', NULL, NULL, '2026-01-01T00:00:00.000Z');`);
// Chains hashed with the old unkeyed SHA-256: d3 intact, d4 edited after hashing.
const addLegacy = (doc, rows, editLast) => {
  let prev = null;
  rows.forEach((e, i) => {
    const row = { document_id: doc, actor: 'Old', action: e, detail: '', ip: null, user_agent: null, created_at: `2026-01-02T00:00:0${i}.000Z` };
    const hash = sha(canon(prev, row));
    raw.prepare('INSERT INTO events (document_id, actor, action, detail, created_at, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(doc, 'Old', editLast && i === rows.length - 1 ? 'Edited' : e, '', row.created_at, prev, hash);
    prev = hash;
  });
};
addLegacy('d3', ['created', 'sent', 'viewed'], false);
addLegacy('d4', ['created', 'sent'], true);
raw.close();

const c = await import('../lib/crypto.js');
const { default: db } = await import('../lib/db.js');
const auth = await import('../lib/auth.js');
const { logSecurity } = await import('../lib/security-log.js');

// auditHash: HMAC-SHA256 under the HKDF audit subkey, over the canonical form.
const ev = { document_id: 'd', actor: 'a', action: 'x', detail: 'y', ip: null, user_agent: null, created_at: 't', id: 9, hash: 'ignored' };
assert.equal(c.auditHash(null, ev), hmac('{"document_id":"d","actor":"a","action":"x","detail":"y","ip":null,"user_agent":null,"created_at":"t"}'));
assert.equal(c.auditHash('p', ev), hmac('p{"document_id":"d","actor":"a","action":"x","detail":"y","ip":null,"user_agent":null,"created_at":"t"}'));
assert.notEqual(c.auditHash(null, ev), sha(canon(null, ev)), 'not the unkeyed hash');
assert.equal(c.auditKeyId(), sha(auditKey).slice(0, 8));
const logKey = Buffer.from(crypto.hkdfSync('sha256', Buffer.from('cd'.repeat(32), 'hex'), Buffer.alloc(0), 'countersign-log-v1', 32));
assert.equal(c.logId('typed@x.co'), crypto.createHmac('sha256', logKey).update('typed@x.co').digest('hex').slice(0, 16), 'logId is a keyed HMAC prefix (L8)');
assert.notEqual(c.logId('typed@x.co'), sha('typed@x.co').slice(0, 16));
assert.equal(c.auditHash(null, { ...ev, ip: undefined, detail: undefined }), c.auditHash(null, { ...ev, ip: null, detail: '' }));

// Migration: tokens hashed + encrypted + plaintext NULLed; expiry only for sent/viewed.
const r = Object.fromEntries(db.prepare('SELECT * FROM recipients').all().map((x) => [x.id, x]));
assert.equal(r.r1.token, null);
assert.equal(r.r1.token_hash, sha('tok-sent'));
assert.equal(c.decryptText(r.r1.token_enc, 'token:r1'), 'tok-sent');
assert.throws(() => c.decryptText(r.r1.token_enc, 'token:r2'), 'token ciphertext bound to recipient id');
assert.ok(Math.abs(Date.parse(r.r1.token_expires_at) - (Date.now() + 30 * 864e5)) < 60e3, 'sent token expires in 30 days');
assert.ok(r.r2.token_expires_at, 'legacy tokens of every status get an expiry (L2)');
assert.equal(r.r2.token_hash, sha('tok-signed'));
assert.equal(r.r3.token_hash, null);
assert.equal(r.r1.token_revoked_at, null);
assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0, 'plaintext sessions invalidated');
for (const t of ['security_events', 'login_attempts', 'audit_tombstones']) db.prepare(`SELECT * FROM ${t} LIMIT 0`).all();

// Migration: events chained per document in created_at, id order.
const chainOf = (doc) => db.prepare('SELECT * FROM events WHERE document_id = ? ORDER BY created_at, id').all(doc);
let prev = null;
const d1 = chainOf('d1');
assert.equal(d1[0].action, 'sent');
for (const e of d1) {
  assert.equal(e.prev_hash, prev);
  assert.equal(e.hash, c.auditHash(prev, e));
  prev = e.hash;
}
assert.equal(chainOf('d2')[0].prev_hash, null);
// d3 (intact under the old scheme) is re-keyed; d4 (already broken) is left broken and reported.
const verifies = (doc) => { let p = null; return chainOf(doc).every((e) => { const ok = e.prev_hash === p && e.hash === c.auditHash(p, e); p = e.hash; return ok; }); };
assert.ok(verifies('d3'), 'intact legacy chain re-keyed');
assert.ok(!verifies('d4'), 'broken legacy chain stays broken');
assert.match(db.prepare("SELECT detail FROM security_events WHERE type = 'audit_chain_broken'").get().detail, /document d4/);
assert.equal(db.prepare("SELECT value FROM meta WHERE key = 'audit_hmac'").get().value, '1');

// Idempotent: a second open changes nothing.
const snapshot = () => JSON.stringify([db.prepare('SELECT * FROM recipients ORDER BY id').all(), db.prepare('SELECT * FROM events ORDER BY id').all()]);
const before = snapshot();
globalThis.__countersignDb.close();
globalThis.__countersignDb = undefined;
assert.equal(snapshot(), before, 'second open is a no-op');

// Password policy.
assert.equal(auth.passwordProblem('short', 'a@b.co'), 'Password must be at least 12 characters');
assert.equal(auth.passwordProblem(undefined, 'a@b.co'), 'Password must be at least 12 characters');
assert.equal(auth.passwordProblem('x'.repeat(257), 'a@b.co'), 'Password must be at most 256 characters');
assert.equal(auth.passwordProblem('Long@Example.com', 'long@example.com'), 'Password must not be your email address');
assert.equal(auth.passwordProblem('x'.repeat(12), 'a@b.co'), null);
assert.equal(auth.passwordProblem('x'.repeat(256), 'a@b.co'), null);

// Login verification never short-circuits for unknown accounts.
const h = await auth.hashPassword('correct horse battery');
assert.equal(await auth.verifyLogin('correct horse battery', h), true);
assert.equal(await auth.verifyLogin('wrong', h), false);
assert.equal(await auth.verifyLogin('anything', undefined), false);

// Login limits (M3): the pair account+IP locks after 5; failures from elsewhere never lock the account.
const P = '9.9.9.9';
for (let i = 1; i <= 4; i++) assert.equal(auth.recordLoginFailure('v@x.co', P), false, `failure ${i}`);
assert.equal(auth.loginLockedFor('v@x.co', P), 0);
assert.equal(auth.recordLoginFailure('v@x.co', P), true);
const wait = auth.loginLockedFor('v@x.co', P);
assert.ok(wait > 890 && wait <= 900, `pair locked ~15 min, got ${wait}`);
assert.equal(auth.loginLockedFor('v@x.co', '8.8.8.8'), 0, 'the owner on another IP is not locked out');
assert.equal(auth.loginLockedFor('other@x.co', P), 0, 'other accounts on that IP are not locked');
assert.equal(auth.loginDelayMs('v@x.co'), 0);
for (let i = 0; i < 6; i++) auth.recordLoginFailure('v@x.co', `10.0.0.${i}`);
assert.equal(auth.loginDelayMs('v@x.co'), 500, 'past 10 failures an hour the account is slowed, not locked');
assert.equal(auth.loginLockedFor('v@x.co', '8.8.8.8'), 0);
auth.recordLoginSuccess('v@x.co', '8.8.8.8');
assert.equal(auth.loginDelayMs('v@x.co'), 0, 'success clears the account counter');
assert.ok(auth.loginLockedFor('v@x.co', P) > 0, 'but not the attacker pair');
// Per-IP: 50 failures lock the IP for new accounts; an account known on that IP still gets in.
const S = '7.7.7.7';
auth.recordLoginSuccess('regular@x.co', S);
let ipLocked = false;
for (let i = 0; i < 50; i++) ipLocked = auth.recordLoginFailure(`spray${i}@x.co`, S) || ipLocked;
assert.ok(ipLocked);
assert.ok(auth.loginLockedFor('fresh@x.co', S) > 0, 'IP locked after 50 failures');
assert.equal(auth.loginLockedFor('regular@x.co', S), 0, 'known-good account on that IP is not blocked');
auth.recordLoginFailure('regular@x.co', S); // real logins reserve first
auth.recordLoginSuccess('regular@x.co', S);
assert.ok(auth.loginLockedFor('fresh@x.co', S) > 0, 'a success does not reset the IP counter');
// N2: the attempt is reserved up front; a correct password undoes its own reservation.
for (let i = 1; i <= 4; i++) auth.recordLoginFailure('res@x.co', '3.3.3.3');
assert.equal(auth.recordLoginFailure('res@x.co', '3.3.3.3'), true, 'the 5th reservation locks the pair');
auth.recordLoginSuccess('res@x.co', '3.3.3.3');
assert.equal(auth.loginLockedFor('res@x.co', '3.3.3.3'), 0, 'a correct 5th attempt is not blocked by its own reservation');
for (let i = 0; i < 49; i++) auth.recordLoginFailure(`ipres${i}@x.co`, '2.2.2.2');
assert.equal(auth.recordLoginFailure('good@x.co', '2.2.2.2'), true, 'the 50th reservation locks the IP');
auth.recordLoginSuccess('good@x.co', '2.2.2.2');
assert.equal(auth.loginLockedFor('fresh2@x.co', '2.2.2.2'), 0, 'a success refunds the IP counter, removing the lock it set');
assert.equal(db.prepare("SELECT count FROM login_attempts WHERE key = 'ip:2.2.2.2'").get().count, 49);
// Signup (L4): 10 per IP per hour.
for (let i = 1; i <= 10; i++) assert.equal(auth.signupThrottle('6.6.6.6'), 0, `signup ${i}`);
assert.ok(auth.signupThrottle('6.6.6.6') > 0, '11th signup throttled');
assert.equal(auth.signupThrottle('5.5.5.5'), 0);
// Password change current-password check (L5).
for (let i = 1; i <= 4; i++) assert.equal(auth.recordPasswordCheckFailure('u1'), false);
assert.equal(auth.passwordCheckLockedFor('u1'), 0);
assert.equal(auth.recordPasswordCheckFailure('u1'), true);
assert.ok(auth.passwordCheckLockedFor('u1') > 0);
auth.clearPasswordCheckFailures('u1');
assert.equal(auth.passwordCheckLockedFor('u1'), 0);
db.prepare("UPDATE login_attempts SET window_start = '2000-01-01T00:00:00.000Z', locked_until = '2000-01-01T00:15:00.000Z' WHERE key NOT LIKE 'ok:%'").run();
auth.purgeExpired();
assert.deepEqual(db.prepare('SELECT key FROM login_attempts ORDER BY key').all().map((x) => x.key), ['ok:good@x.co|2.2.2.2', 'ok:regular@x.co|7.7.7.7', 'ok:res@x.co|3.3.3.3', 'ok:v@x.co|8.8.8.8'], 'stale counters purged, recent known-good kept');

// Sessions: hashed at rest, idle and absolute timeouts, revoke others, logout-all.
const fakeRes = () => ({ headers: {}, setHeader(k, v) { this.headers[k] = v; } });
const login = () => { const res = fakeRes(); auth.startSession(res, 'u1', { ip: '1.1.1.1', userAgent: 'UA' }); return res.headers['Set-Cookie'].split(';')[0].split('=')[1]; };
const req = (cookie) => ({ cookies: { cs_session: cookie }, headers: { 'user-agent': 'UA-test' }, socket: { remoteAddress: '4.4.4.4' } });
const a = login();
const s = db.prepare('SELECT * FROM sessions').get();
assert.equal(s.id_hash, sha(a));
assert.notEqual(s.id, a);
assert.ok(!JSON.stringify(db.prepare('SELECT * FROM sessions').all()).includes(a), 'cookie value not stored');
assert.ok(Math.abs(Date.parse(s.expires_at) - (Date.now() + 7 * 864e5)) < 60e3, 'absolute 7 days');
assert.equal(auth.getUser(req(a)).id, 'u1');
assert.equal(auth.getUser(req('nope')), null);
db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?').run(new Date(Date.now() - 61 * 6e4).toISOString(), sha(a));
assert.equal(auth.getUser(req(a)), null, 'idle timeout');
assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0, 'expired session deleted');
const b = login();
db.prepare('UPDATE sessions SET expires_at = ? WHERE id_hash = ?').run(new Date(Date.now() - 1000).toISOString(), sha(b));
assert.equal(auth.getUser(req(b)), null, 'absolute timeout');
const old = new Date(Date.now() - 30 * 6e4).toISOString();
const t1 = login();
db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?').run(old, sha(t1));
auth.getUser(req(t1));
assert.notEqual(db.prepare('SELECT last_seen_at FROM sessions WHERE id_hash = ?').get(sha(t1)).last_seen_at, old, 'sliding window touched');
const t2 = login();
assert.equal(auth.revokeOtherSessions(req(t1), 'u1'), 1);
assert.ok(auth.getUser(req(t1)) && !auth.getUser(req(t2)), 'password change keeps only the current session');
login();
const res = fakeRes();
auth.endAllSessions(res, { id: 'u1', email: 'old@example.com' }, {});
assert.match(res.headers['Set-Cookie'], /Max-Age=0/);
assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0, 'logout-all removes every session');

// Security log row.
logSecurity('login_failure', { email: 'z@x.co', ip: '1.1.1.1', userAgent: 'UA' });
const types = db.prepare('SELECT type FROM security_events').all().map((x) => x.type);
assert.ok(types.includes('session_expired') && types.includes('logout_all') && types.includes('login_failure'));
assert.deepEqual({ ...db.prepare("SELECT ip, user_agent FROM security_events WHERE type = 'session_expired'").get() }, { ip: '4.4.4.4', user_agent: 'UA-test' }, 'session_expired has IP and UA (L6)');

globalThis.__countersignDb.close();
fs.rmSync(dir, { recursive: true, force: true });
console.log('security self-check (unit): all assertions passed');

// HTTP checks against a disposable server.
const BASE = process.env.BASE_URL;
if (BASE) {
  const call = async (p, { body, cookie, method = 'POST' } = {}) => {
    const r = await fetch(BASE + p, { method, headers: { 'Content-Type': 'application/json', ...(cookie && { cookie }) }, body: body && JSON.stringify(body) });
    return { status: r.status, headers: r.headers, body: await r.json().catch(() => null), cookie: r.headers.get('set-cookie')?.split(';')[0] };
  };
  const email = `sec-${Date.now()}@example.com`;
  const pw = 'correct horse battery';
  const short = await call('/api/auth/signup', { body: { name: 'S', email, password: 'elevenchars' } });
  assert.equal(short.status, 400);
  assert.equal(short.body.error, 'Password must be at least 12 characters');
  assert.equal((await call('/api/auth/signup', { body: { name: 'S', email, password: email } })).status, 400);
  const su = await call('/api/auth/signup', { body: { name: 'S', email, password: pw } });
  assert.equal(su.status, 200);
  assert.equal((await call('/api/auth/logout-all')).status, 401, 'logout-all needs a session');
  assert.equal((await call('/api/auth/logout-all', { method: 'GET', cookie: su.cookie })).status, 405);
  const second = await call('/api/auth/login', { body: { email, password: pw } });
  assert.equal(second.status, 200);
  assert.equal((await call('/api/account', { method: 'PATCH', cookie: su.cookie, body: { currentPassword: pw, newPassword: 'short' } })).status, 400);
  assert.equal((await call('/api/account', { method: 'PATCH', cookie: su.cookie, body: { currentPassword: pw, newPassword: pw + '!' } })).status, 200);
  assert.equal((await call('/api/auth/session', { method: 'GET', cookie: second.cookie })).body.user, null, 'other session revoked by password change');
  assert.equal((await call('/api/auth/session', { method: 'GET', cookie: su.cookie })).body.user.email, email, 'current session kept');
  const all = await call('/api/auth/logout-all', { cookie: su.cookie });
  assert.equal(all.status, 200);
  assert.deepEqual(all.body, { ok: true });
  assert.equal((await call('/api/auth/session', { method: 'GET', cookie: su.cookie })).body.user, null, 'logout-all ends this session too');
  for (let i = 0; i < 5; i++) assert.equal((await call('/api/auth/login', { body: { email, password: 'wrong password' } })).status, 401);
  const locked = await call('/api/auth/login', { body: { email, password: pw + '!' } });
  assert.equal(locked.status, 429, 'locked even with the right password');
  assert.ok(Number(locked.headers.get('retry-after')) > 0);
  console.log('security self-check (HTTP): all assertions passed');
}
