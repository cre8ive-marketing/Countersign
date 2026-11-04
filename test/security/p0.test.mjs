// P0 security controls and encryption at rest (Raymond). Run against a FRESH disposable server:
//   ENCRYPTION_KEY=<same as server> DATA_DIR=<server's DATA_DIR> SERVER_LOG=<server stdout file> \
//   BASE_URL=http://localhost:3128 node --test test/security/
// Server: ALLOW_SIGNUP=true, SIGNUP_MAX_PER_HOUR=1000, explicit ENCRYPTION_KEY, no TRUST_PROXY.
// DATA_DIR enables the disk/DB checks (they read and, for tamper tests, modify that throwaway DB). ENCRYPTION_KEY enables the
// keyed audit-chain recompute and the "valid ciphertext, wrong content" test. SERVER_LOG enables log checks. Otherwise they skip.
// Other client IPs are simulated with loopback source addresses 127.0.0.2-9 (works on Windows and Linux; skipped if refused).
// Login failures from 127.0.0.1 in this file: 12 (per-IP limit 50 per 15 min), so re-running against the same server is fine
// a few times; per account+IP the limit is LOGIN_MAX_ATTEMPTS and every test uses fresh accounts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import zlib from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';

const BASE = new URL(process.env.BASE_URL || 'http://localhost:3000');
const DATA_DIR = process.env.DATA_DIR;
const KEY = process.env.ENCRYPTION_KEY;
const LOG = process.env.SERVER_LOG;
const MAX = Number(process.env.LOGIN_MAX_ATTEMPTS) || 5;
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const noDb = !DATA_DIR && 'needs DATA_DIR of the server under test';
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const rnd = () => crypto.randomBytes(6).toString('hex');
const secrets = []; // every password, cookie and token used here; none may appear in logs

let _db;
const db = () => {
  if (!_db) { _db = new DatabaseSync(path.join(DATA_DIR, 'countersign.db')); _db.exec('PRAGMA busy_timeout = 5000'); }
  return _db;
};
const filesDir = () => path.join(DATA_DIR, 'files');

// `from` = loopback source address, to act as a different client IP.
function call(p, { method = 'GET', cookie, body, headers = {}, from } = {}) {
  const h = { ...headers };
  if (cookie) h.cookie = cookie;
  let b = body;
  if (b !== undefined && !Buffer.isBuffer(b)) { b = JSON.stringify(b); h['content-type'] = 'application/json'; }
  return new Promise((resolve, reject) => {
    const req = http.request({ host: BASE.hostname === 'localhost' ? '127.0.0.1' : BASE.hostname, port: BASE.port, path: p, method, headers: h, localAddress: from }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        let json; try { json = JSON.parse(buf.toString()); } catch {}
        const set = (res.headers['set-cookie'] || []).find((c) => c.startsWith('cs_session='));
        resolve({ status: res.statusCode, headers: res.headers, buf, json, text: buf.toString('latin1'), cookie: set && set.split(';')[0] });
      });
    });
    req.on('error', reject);
    req.end(b);
  });
}
const me = async (cookie) => (await call('/api/auth/session', { cookie })).json.user;

let altIps;
async function canUseAltIps() {
  if (altIps === undefined) altIps = await call('/api/auth/session', { from: '127.0.0.2' }).then(() => true, () => false);
  return altIps;
}

async function signup(prefix = 'p0') {
  const email = `${prefix}-${rnd()}@example.com`;
  const password = `pw-${rnd()}-${rnd()}`;
  const r = await call('/api/auth/signup', { method: 'POST', body: { name: 'P0 Owner', email, password } });
  assert.equal(r.status, 200, r.text);
  secrets.push(password, r.cookie.split('=')[1]);
  return { email, password, cookie: r.cookie };
}
async function login(email, password, opts = {}) {
  const r = await call('/api/auth/login', { method: 'POST', body: { email, password }, ...opts });
  if (r.cookie) secrets.push(r.cookie.split('=')[1]);
  return r;
}

async function pdfBytes(label) {
  const pdf = await PDFDocument.create();
  pdf.addPage([612, 792]).drawText(label, { x: 50, y: 700 });
  return Buffer.from(await pdf.save());
}
// Owner + sent document with `n` signers (sequential when n > 1). Returns ids, tokens and the uploaded bytes.
async function sentDoc({ n = 1, emails, bytes, owner } = {}) {
  const o = owner || await signup();
  bytes ??= await pdfBytes(`doc ${rnd()}`);
  const up = await call('/api/documents', { method: 'POST', cookie: o.cookie, body: bytes, headers: { 'content-type': 'application/pdf', 'x-file-name': 'P0.pdf' } });
  assert.equal(up.status, 201, up.text);
  const id = up.json.id;
  const recipients = Array.from({ length: n }, (_, i) => ({ id: `r${i}`, name: `Signer ${i}`, email: emails?.[i] || `s${i}-${rnd()}@example.com`, role: 'signer' }));
  const fields = recipients.map((r, i) => ({ recipientId: r.id, type: 'signature', page: 0, x: 0.1, y: 0.1 + i * 0.1, w: 0.3, h: 0.06 }));
  assert.equal((await call(`/api/documents/${id}`, { method: 'PUT', cookie: o.cookie, body: { title: 'P0', sequential: n > 1, recipients, fields } })).status, 200);
  assert.equal((await call(`/api/documents/${id}/send`, { method: 'POST', cookie: o.cookie })).status, 200);
  const html = (await call(`/app/documents/${id}`, { cookie: o.cookie })).text;
  const tokens = [...html.matchAll(/"token":"([\w-]+)"/g)].map((m) => m[1]);
  assert.equal(tokens.length, n);
  secrets.push(...tokens);
  return { ...o, id, bytes, tokens };
}
async function sigField(token) {
  const fid = (await call(`/sign/${token}`)).text.match(/"id":"([\w-]+)","type":"signature"[^}]*"mine":true/)?.[1];
  assert.ok(fid, 'signature field on the signing page');
  return fid;
}
const sign = async (token, value = PNG) => call(`/api/sign/${token}`, { method: 'POST', body: { values: { [await sigField(token)]: value } } });
const sign0 = (t) => call(`/api/sign/${t}`, { method: 'POST', body: { values: {} } });
const docStatus = async (d) => (await call(`/app/documents/${d.id}`, { cookie: d.cookie })).text.match(/"status":"(\w+)"/)?.[1];

// Independent re-implementation of the documented chain (lib/crypto.js auditCanonical/auditHash).
const canonical = (prev, e) => (prev || '') + JSON.stringify({ document_id: e.document_id, actor: e.actor, action: e.action, detail: e.detail ?? '', ip: e.ip ?? null, user_agent: e.user_agent ?? null, created_at: e.created_at });
const keyBytes = () => (/^[0-9a-fA-F]{64}$/.test(KEY.trim()) ? Buffer.from(KEY.trim(), 'hex') : Buffer.from(KEY.trim(), 'base64'));
const auditKey = () => Buffer.from(crypto.hkdfSync('sha256', keyBytes(), Buffer.alloc(0), 'countersign-audit-v1', 32));
const hmacLink = (prev, e) => crypto.createHmac('sha256', auditKey()).update(canonical(prev, e)).digest('hex');
const shaLink = (prev, e) => sha(canonical(prev, e));
function verifyChain(rows, link = hmacLink) {
  let prev = null;
  for (const e of rows) {
    const h = link(prev, e);
    if ((e.prev_hash ?? null) !== prev || e.hash !== h) return { ok: false, brokenAt: e.id };
    prev = h;
  }
  return { ok: true, head: prev, count: rows.length };
}
const eventRows = (id) => db().prepare('SELECT * FROM events WHERE document_id = ? ORDER BY created_at, id').all(id);
// Rewrites every link of a document's chain with `link` (what a DB writer would do).
function rewriteChain(id, link) {
  let prev = null;
  for (const e of eventRows(id)) { const h = link(prev, e); db().prepare('UPDATE events SET prev_hash = ?, hash = ? WHERE id = ?').run(prev, h, e.id); prev = h; }
}
const auditHeads = (id) => fs.readFileSync(LOG, 'utf8').split(/\r?\n/).filter((l) => l.startsWith('{"audit_head"'))
  .map((l) => JSON.parse(l).audit_head).filter((a) => a.document_id === id);

// Text drawn by pdf-lib: Flate content streams with hex-string Tj operands.
function pdfText(buf) {
  const s = buf.toString('latin1');
  let out = '';
  for (const m of s.matchAll(/stream\r?\n([\s\S]*?)\nendstream/g)) {
    let c; try { c = zlib.inflateSync(Buffer.from(m[1], 'latin1')).toString('latin1'); } catch { c = m[1]; }
    for (const t of c.matchAll(/<([0-9A-Fa-f]+)>\s*Tj/g)) out += Buffer.from(t[1], 'hex').toString('latin1') + '\n';
  }
  return out;
}
// Encrypts like lib/crypto.js (CSE1 | IV | tag | ct) with the server's key.
function cse1(buf, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', keyBytes(), iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(buf), c.final()]);
  return Buffer.concat([Buffer.from('CSE1'), iv, c.getAuthTag(), ct]);
}

// ---------- Login: rate limit, enumeration, password policy ----------

test(`account+IP lock: ${MAX} failures from one IP lock that pair (429 + Retry-After), even for the right password`, async () => {
  const o = await signup();
  const spoof = '203.0.113.' + (1 + crypto.randomInt(250));
  for (let i = 1; i <= MAX; i++) {
    const r = await login(o.email, 'wrong-password-xx', { headers: { 'X-Forwarded-For': spoof } });
    assert.equal(r.status, 401, `attempt ${i}`);
    assert.equal(r.json.error, 'Email or password is incorrect');
  }
  const locked = await login(o.email, o.password);
  assert.equal(locked.status, 429);
  const wait = Number(locked.headers['retry-after']);
  assert.ok(wait > 0 && wait <= 900, `Retry-After ${wait}`);
  assert.equal(locked.cookie, undefined, 'no session while locked');
  if (DATA_DIR && process.env.TRUST_PROXY !== 'true') {
    const ips = db().prepare("SELECT DISTINCT ip FROM security_events WHERE email = ? AND type = 'login_failure'").all(o.email).map((r) => r.ip);
    assert.ok(ips.length && !ips.includes(spoof), `X-Forwarded-For must be ignored without TRUST_PROXY, got ${ips}`);
    assert.ok(db().prepare("SELECT 1 FROM security_events WHERE email = ? AND type = 'login_locked'").get(o.email));
    assert.equal(db().prepare('SELECT 1 FROM login_attempts WHERE key LIKE ?').get(`%${spoof}%`), undefined, 'no counter keyed on the spoofed IP');
  }
});

test('failures from an attacker IP do not lock the victim out of their correct login from another IP', async (t) => {
  if (!(await canUseAltIps())) return t.skip('loopback alias 127.0.0.2 not usable here');
  const v = await signup();
  for (let i = 0; i < MAX; i++) assert.equal((await login(v.email, 'attacker-guess-xx', { from: '127.0.0.2' })).status, 401);
  assert.equal((await login(v.email, v.password, { from: '127.0.0.2' })).status, 429, 'attacker IP is locked for this account');
  const ok = await login(v.email, v.password);
  assert.equal(ok.status, 200, 'victim from their own IP still signs in');
  assert.ok(await me(ok.cookie));
});

test('N2: parallel guesses cannot exceed the per account+IP limit once the account-wide delay is active', async (t) => {
  if (!(await canUseAltIps())) return t.skip('loopback aliases not usable here');
  const v = await signup();
  // 2 x MAX failures from two IPs push the account counter past the delay threshold (10) without locking any pair early.
  for (const ip of ['127.0.0.3', '127.0.0.4']) for (let i = 0; i < MAX; i++) await login(v.email, 'attacker-guess-xx', { from: ip });
  const burst = await Promise.all(Array.from({ length: 20 }, () => login(v.email, 'attacker-guess-xx', { from: '127.0.0.5' })));
  const evaluated = burst.filter((r) => r.status === 401).length;
  assert.ok(evaluated <= MAX, `${evaluated} of 20 parallel guesses from one IP were checked (limit ${MAX})`);
});

test('login does not reveal whether an account exists (same answer, comparable time)', async () => {
  const o = await signup();
  const known = [], unknown = [];
  for (let i = 0; i < 3; i++) {
    let t = performance.now();
    const a = await login(o.email, 'wrong-password-xx');
    known.push(performance.now() - t);
    t = performance.now();
    const b = await login(`nobody-${rnd()}@example.com`, 'wrong-password-xx');
    unknown.push(performance.now() - t);
    assert.equal(a.status, b.status);
    assert.deepEqual(a.json, b.json);
  }
  const med = (xs) => xs.sort((x, y) => x - y)[1];
  // Without the dummy scrypt an unknown email answers ~10x faster; allow wide jitter.
  assert.ok(med(unknown) > med(known) * 0.4, `unknown ${med(unknown).toFixed(1)}ms vs known ${med(known).toFixed(1)}ms`);
});

test('password policy on signup and change: at least 12, at most 256, not the email', async () => {
  const email = `pol-${rnd()}@example.com`;
  for (const [pw, msg] of [['elevenchars', /at least 12/], ['x'.repeat(257), /at most 256/], [email, /email/], [email.toUpperCase(), /email/]]) {
    const r = await call('/api/auth/signup', { method: 'POST', body: { name: 'Pol', email, password: pw } });
    assert.equal(r.status, 400, pw.slice(0, 20));
    assert.match(r.json.error, msg);
  }
  const o = await signup();
  const r = await call('/api/account', { method: 'PATCH', cookie: o.cookie, body: { currentPassword: o.password, newPassword: 'short' } });
  assert.equal(r.status, 400);
  assert.equal((await login(o.email, o.password)).status, 200, 'old password still valid after rejected change');
});

test(`password change: ${MAX} wrong current passwords lock the check (429), even for the right one`, async () => {
  const o = await signup();
  for (let i = 0; i < MAX; i++) {
    const r = await call('/api/account', { method: 'PATCH', cookie: o.cookie, body: { currentPassword: `wrong-${i}-xxxxxx`, newPassword: `new-${rnd()}-${rnd()}` } });
    assert.equal(r.status, 400, `attempt ${i + 1}`);
  }
  const r = await call('/api/account', { method: 'PATCH', cookie: o.cookie, body: { currentPassword: o.password, newPassword: `new-${rnd()}-${rnd()}` } });
  assert.equal(r.status, 429);
  assert.ok(Number(r.headers['retry-after']) > 0);
  assert.equal((await login(o.email, o.password)).status, 200, 'password unchanged');
});

// ---------- Sessions ----------

test('session cookie is stored only as SHA-256', { skip: noDb }, async () => {
  const o = await signup();
  const v = o.cookie.split('=')[1];
  assert.equal(db().prepare('SELECT 1 FROM sessions WHERE id = ? OR id_hash = ?').get(v, v), undefined, 'plaintext cookie in DB');
  assert.ok(db().prepare('SELECT 1 FROM sessions WHERE id_hash = ?').get(sha(v)));
});

test('logout revokes the session server-side (replayed cookie is dead)', async () => {
  const o = await signup();
  assert.ok(await me(o.cookie));
  assert.equal((await call('/api/auth/logout', { method: 'POST', cookie: o.cookie })).status, 200);
  assert.equal(await me(o.cookie), null);
});

test('logout-all ends every session incl. the current one; needs auth and same origin', async () => {
  const o = await signup();
  const b = (await login(o.email, o.password)).cookie;
  assert.equal((await call('/api/auth/logout-all', { method: 'POST' })).status, 401);
  assert.equal((await call('/api/auth/logout-all', { method: 'POST', cookie: b, headers: { Origin: 'https://evil.example' } })).status, 403);
  assert.ok(await me(o.cookie));
  const r = await call('/api/auth/logout-all', { method: 'POST', cookie: b });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { ok: true });
  assert.match((r.headers['set-cookie'] || []).join(), /cs_session=;.*Max-Age=0/);
  assert.equal(await me(o.cookie), null);
  assert.equal(await me(b), null);
});

test('password change keeps the current session and revokes all others', async () => {
  const o = await signup();
  const other = (await login(o.email, o.password)).cookie;
  const pw = `new-${rnd()}-${rnd()}`;
  secrets.push(pw);
  assert.equal((await call('/api/account', { method: 'PATCH', cookie: o.cookie, body: { currentPassword: o.password, newPassword: pw } })).status, 200);
  assert.ok(await me(o.cookie), 'current session survives');
  assert.equal(await me(other), null, 'other session revoked');
  assert.equal((await login(o.email, pw)).status, 200);
});

test('idle and absolute session timeouts are enforced server-side', { skip: noDb }, async () => {
  const idle = await signup();
  const abs = await signup();
  const old = new Date(Date.now() - 24 * 3600e3).toISOString();
  db().prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?').run(old, sha(idle.cookie.split('=')[1]));
  db().prepare('UPDATE sessions SET expires_at = ? WHERE id_hash = ?').run(new Date(Date.now() - 1000).toISOString(), sha(abs.cookie.split('=')[1]));
  assert.equal(await me(idle.cookie), null, 'idle session');
  assert.equal(await me(abs.cookie), null, 'expired session');
  assert.equal(db().prepare('SELECT COUNT(*) n FROM sessions WHERE id_hash IN (?, ?)').get(sha(idle.cookie.split('=')[1]), sha(abs.cookie.split('=')[1])).n, 0, 'rows deleted');
});

// ---------- Signing tokens ----------

test('signing tokens: stored as hash + ciphertext only; unknown token is 404', async () => {
  const d = await sentDoc();
  assert.equal((await call(`/api/sign/${'x'.repeat(32)}/file`)).status, 404);
  assert.equal((await call(`/sign/${'x'.repeat(32)}`)).status, 404);
  if (!DATA_DIR) return;
  const r = db().prepare('SELECT * FROM recipients WHERE document_id = ?').get(d.id);
  assert.equal(r.token, null, 'plaintext token column');
  assert.equal(r.token_hash, sha(d.tokens[0]));
  assert.match(r.token_enc, /^enc:v1:/);
  assert.ok(!r.token_enc.includes(d.tokens[0]));
  assert.ok(Date.parse(r.token_expires_at) > Date.now() + 86400e3, 'expiry is set');
});

test('void revokes every signing link (page and API answer 410, token not in props)', async () => {
  const d = await sentDoc({ n: 2 });
  assert.equal((await call(`/api/documents/${d.id}/void`, { method: 'POST', cookie: d.cookie, body: { reason: 'test' } })).status, 200);
  for (const t of d.tokens) {
    const page = await call(`/sign/${t}`);
    assert.equal(page.status, 410);
    // Next echoes the request URL itself (query, relative links); only the page props must drop the token.
    assert.match(page.text, /"pageProps":\{"token":null,/, 'token returned in dead-link page props');
    assert.equal((await call(`/api/sign/${t}/file`)).status, 410);
    assert.equal((await sign0(t)).status, 410);
  }
});

test('decline revokes the other signers\' links', async () => {
  const d = await sentDoc({ n: 2 });
  assert.equal((await call(`/api/sign/${d.tokens[0]}/decline`, { method: 'POST', body: { reason: 'no' } })).status, 200);
  assert.equal((await call(`/api/sign/${d.tokens[1]}/file`)).status, 410);
  assert.equal((await call(`/api/sign/${d.tokens[0]}/decline`, { method: 'POST', body: {} })).status, 410);
});

test('expired signing link answers 410 and is logged as token_expired', { skip: noDb }, async () => {
  const d = await sentDoc();
  db().prepare('UPDATE recipients SET token_expires_at = ? WHERE token_hash = ?').run(new Date(Date.now() - 1000).toISOString(), sha(d.tokens[0]));
  const page = await call(`/sign/${d.tokens[0]}`);
  assert.equal(page.status, 410);
  assert.match(page.text, /expired/i);
  const api = await call(`/api/sign/${d.tokens[0]}/file`);
  assert.equal(api.status, 410);
  assert.match(api.json.error, /expired/);
  assert.equal((await sign0(d.tokens[0])).status, 410);
  const rid = db().prepare('SELECT id FROM recipients WHERE token_hash = ?').get(sha(d.tokens[0])).id;
  assert.ok(db().prepare("SELECT 1 FROM security_events WHERE type = 'token_expired' AND detail LIKE ?").get('%' + rid));
});

test('H1: an account with an unverified email cannot obtain another owner\'s signing link for that email', async () => {
  const victim = `victim-${rnd()}@example.com`;
  const d = await sentDoc({ emails: [victim] });
  const attacker = await call('/api/auth/signup', { method: 'POST', body: { name: 'Mallory', email: victim, password: `mallory-${rnd()}-pw` } });
  assert.equal(attacker.status, 200);
  for (const view of ['', '?view=action']) {
    const html = (await call(`/app${view}`, { cookie: attacker.cookie })).text;
    assert.ok(!html.includes(d.tokens[0]), `victim signing token rendered on /app${view}`);
  }
  // The owner still sees their own pending signature.
  const own = await signup();
  const mine = await sentDoc({ owner: own, emails: [own.email] });
  assert.ok((await call('/app?view=action', { cookie: own.cookie })).text.includes(mine.tokens[0]), 'own document still listed');
});

// ---------- Signature upload handling ----------

// A PNG header claiming the given size, with nothing behind it.
const pngHeader = (w, h) => {
  const b = Buffer.alloc(33);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b, 0);
  b.writeUInt32BE(13, 8); b.write('IHDR', 12, 'latin1'); b.writeUInt32BE(w, 16); b.writeUInt32BE(h, 20); b[24] = 8; b[25] = 6;
  return 'data:image/png;base64,' + b.toString('base64');
};

test('signature values: only decodable PNG data URLs, bounded in size and dimensions', async () => {
  const d = await sentDoc();
  const bad = ['data:image/jpeg;base64,/9j/4AAQ', 'data:image/svg+xml;base64,PHN2Zz4=', 'javascript:alert(1)',
    PNG + 'A'.repeat(400_001 - PNG.length), { a: 1 }, 123, 'data:image/png;base64,AAAAAAAA', 'data:image/png;base64,not base64!',
    pngHeader(5000, 10), pngHeader(3000, 3000), pngHeader(100, 100) /* header only, no image data */];
  for (const v of bad) {
    const r = await sign(d.tokens[0], v);
    assert.equal(r.status, 400, String(v).slice(0, 40));
  }
  assert.equal(await docStatus(d), 'sent', 'rejected images leave the document untouched');
  assert.equal((await sign(d.tokens[0])).status, 200, 'a valid PNG still works');
  assert.equal(await docStatus(d), 'completed');
  assert.equal((await call(`/api/documents/${d.id}/file?kind=signed`, { cookie: d.cookie })).status, 200);
});

test('N1: concurrent submissions by the last signer cannot leave a completed document without its signed PDF', async () => {
  const pdf = await PDFDocument.create();
  for (let i = 0; i < 150; i++) pdf.addPage().drawText(`page ${i} ${'x'.repeat(60)}`, { x: 20, y: 400, size: 8 }); // slow enough to overlap
  const d = await sentDoc({ bytes: Buffer.from(await pdf.save()) });
  const fid = await sigField(d.tokens[0]);
  const rs = await Promise.all(Array.from({ length: 6 }, () => call(`/api/sign/${d.tokens[0]}`, { method: 'POST', body: { values: { [fid]: PNG } } })));
  assert.equal(rs.filter((r) => r.status === 200).length, 1, 'exactly one submission wins');
  assert.equal(await docStatus(d), 'completed');
  assert.equal((await call(`/api/documents/${d.id}/file?kind=signed`, { cookie: d.cookie })).status, 200, 'signed PDF of a completed document is missing');
});

// ---------- Encryption at rest ----------

test('PDFs and field values are AES-256-GCM at rest; downloads decrypt to the hashed plaintext', { skip: noDb }, async () => {
  const d = await sentDoc();
  const orig = fs.readFileSync(path.join(filesDir(), `${d.id}.original.pdf`));
  assert.equal(orig.subarray(0, 4).toString(), 'CSE1');
  assert.ok(!orig.includes(Buffer.from('%PDF')), 'plaintext PDF marker on disk');
  const dl = await call(`/api/documents/${d.id}/file`, { cookie: d.cookie });
  assert.equal(dl.status, 200);
  assert.ok(dl.buf.equals(d.bytes), 'download equals the uploaded bytes');
  assert.equal(sha(dl.buf), db().prepare('SELECT original_sha256 h FROM documents WHERE id = ?').get(d.id).h);
  assert.equal((await sign(d.tokens[0])).status, 200);
  const signed = fs.readFileSync(path.join(filesDir(), `${d.id}.signed.pdf`));
  assert.equal(signed.subarray(0, 4).toString(), 'CSE1');
  const sdl = await call(`/api/sign/${d.tokens[0]}/file?download=1`);
  assert.equal(sdl.status, 200);
  assert.equal(sha(sdl.buf), db().prepare('SELECT signed_sha256 h FROM documents WHERE id = ?').get(d.id).h);
  for (const f of db().prepare('SELECT value FROM fields WHERE document_id = ? AND value IS NOT NULL').all(d.id)) {
    assert.match(f.value, /^enc:v1:/);
    assert.ok(!f.value.includes('iVBOR'), 'PNG visible in ciphertext');
  }
  assert.ok(db().prepare("SELECT 1 FROM meta WHERE key = 'encryption_migrated'").get(), 'one-time migration marker');
  if (!KEY && process.platform !== 'win32') {
    assert.equal(fs.statSync(path.join(DATA_DIR, 'encryption.key')).mode & 0o077, 0, 'key file readable by group/other');
  }
});

test('ciphertext moved to another document or tampered with fails closed (AAD binds file to its id)', { skip: noDb }, async () => {
  const a = await sentDoc();
  const b = await sentDoc();
  const pb = path.join(filesDir(), `${b.id}.original.pdf`);
  const keep = fs.readFileSync(pb);
  try {
    fs.copyFileSync(path.join(filesDir(), `${a.id}.original.pdf`), pb);
    const r = await call(`/api/documents/${b.id}/file`, { cookie: b.cookie });
    assert.equal(r.status, 500);
    assert.ok(!r.buf.equals(a.bytes));
    const flipped = Buffer.from(keep); flipped[flipped.length - 1] ^= 1;
    fs.writeFileSync(pb, flipped);
    assert.equal((await call(`/api/documents/${b.id}/file`, { cookie: b.cookie })).status, 500, 'tampered ciphertext');
  } finally { fs.writeFileSync(pb, keep); }
  assert.equal((await call(`/api/documents/${b.id}/file`, { cookie: b.cookie })).status, 200, 'restored file serves again');
});

test('M1: a plaintext PDF written over an encrypted one is never served or signed (no legacy downgrade)', { skip: noDb }, async () => {
  const d = await sentDoc();
  const p = path.join(filesDir(), `${d.id}.original.pdf`);
  const keep = fs.readFileSync(p);
  const forged = await pdfBytes('forged by someone with disk access but no key');
  try {
    fs.writeFileSync(p, forged);
    const owner = await call(`/api/documents/${d.id}/file`, { cookie: d.cookie });
    const signer = await call(`/api/sign/${d.tokens[0]}/file`);
    assert.ok(!owner.buf.equals(forged) && owner.status >= 500, `owner got ${owner.status}`);
    assert.ok(!signer.buf.equals(forged) && signer.status >= 500, `signer got ${signer.status}`);
    assert.notEqual((await sign(d.tokens[0])).status, 200, 'completion must not stamp a plaintext file');
    assert.equal(await docStatus(d), 'sent');
  } finally { fs.writeFileSync(p, keep); }
  assert.equal((await sign(d.tokens[0])).status, 200, 'restored file signs normally');
});

test('M1: correctly encrypted but different content (key holder without DB access) fails the SHA-256 check', { skip: (!DATA_DIR || !KEY) && 'needs DATA_DIR and ENCRYPTION_KEY' }, async () => {
  const d = await sentDoc();
  const p = path.join(filesDir(), `${d.id}.original.pdf`);
  const keep = fs.readFileSync(p);
  const forged = await pdfBytes('forged with the key');
  try {
    fs.writeFileSync(p, cse1(forged, `file:${d.id}.original`));
    const r = await call(`/api/documents/${d.id}/file`, { cookie: d.cookie });
    assert.equal(r.status, 500);
    assert.ok(!r.buf.equals(forged));
    assert.equal((await call(`/api/sign/${d.tokens[0]}/file`)).status, 500);
    assert.ok(db().prepare("SELECT 1 FROM security_events WHERE type = 'file_integrity_failure' AND detail LIKE ?").get(`%${d.id}%`));
  } finally { fs.writeFileSync(p, keep); }
});

test('field values stored as plaintext are refused, not used', { skip: noDb }, async () => {
  const d = await sentDoc({ n: 2 });
  assert.equal((await sign(d.tokens[0])).status, 200);
  const f = db().prepare('SELECT id, value FROM fields WHERE document_id = ? AND value IS NOT NULL').get(d.id);
  try {
    db().prepare('UPDATE fields SET value = ? WHERE id = ?').run(PNG, f.id);
    const r = await call(`/app/documents/${d.id}`, { cookie: d.cookie });
    assert.equal(r.status, 500, 'plaintext field value must fail closed');
    assert.ok(!r.text.includes('iVBOR'));
  } finally { db().prepare('UPDATE fields SET value = ? WHERE id = ?').run(f.value, f.id); }
});

// ---------- Audit chain and tombstones ----------

test('audit chain is HMAC-keyed; certificate shows the Signed head; Completed binds both file hashes', { skip: (!DATA_DIR || !KEY) && 'needs DATA_DIR and ENCRYPTION_KEY' }, async () => {
  const d = await sentDoc();
  assert.equal((await sign(d.tokens[0])).status, 200);
  const rows = eventRows(d.id);
  const v = verifyChain(rows);
  assert.ok(v.ok, `keyed chain broken at ${v.brokenAt}`);
  assert.equal(verifyChain(rows, shaLink).ok, false, 'links must not be plain SHA-256');
  const completed = rows.at(-1), signed = rows.at(-2);
  assert.equal(completed.action, 'Completed');
  assert.equal(signed.action, 'Signed');
  assert.equal(completed.prev_hash, signed.hash);
  const doc = db().prepare('SELECT original_sha256 o, signed_sha256 s FROM documents WHERE id = ?').get(d.id);
  assert.ok(completed.detail.includes(doc.o) && completed.detail.includes(doc.s), 'Completed event carries both hashes');
  const pdf = (await call(`/api/documents/${d.id}/file?kind=signed`, { cookie: d.cookie })).buf;
  assert.equal(sha(pdf), doc.s);
  const cert = pdfText(pdf);
  assert.ok(cert.includes(signed.hash), 'certificate shows the chain head at signing');
  assert.ok(cert.includes('Audit events') && cert.includes(String(rows.length - 1)));
});

test('audit chain: an edited event is reported as broken on the certificate', { skip: noDb }, async () => {
  const d = await sentDoc();
  const first = eventRows(d.id)[0];
  db().prepare('UPDATE events SET detail = ? WHERE id = ?').run('rewritten by a DB attacker', first.id);
  assert.equal((await sign(d.tokens[0])).status, 200);
  const cert = pdfText((await call(`/api/documents/${d.id}/file?kind=signed`, { cookie: d.cookie })).buf);
  assert.match(cert, new RegExp(`chain broken at event ${first.id}\\b`));
});

test('M4: a DB writer without the key who rewrites the whole chain (unkeyed SHA-256) is detected', { skip: noDb }, async () => {
  const d = await sentDoc();
  const first = eventRows(d.id)[0];
  db().prepare('UPDATE events SET detail = ? WHERE id = ?').run('rewritten, chain recomputed', first.id);
  rewriteChain(d.id, shaLink);
  assert.ok(verifyChain(eventRows(d.id), shaLink).ok, 'precondition: the forged chain is self-consistent');
  assert.equal((await sign(d.tokens[0])).status, 200);
  const cert = pdfText((await call(`/api/documents/${d.id}/file?kind=signed`, { cookie: d.cookie })).buf);
  assert.match(cert, new RegExp(`chain broken at event ${first.id}\\b`));
});

test('M4: tail truncation is detectable against the audit_head anchor on stdout', { skip: (!DATA_DIR || !LOG) && 'needs DATA_DIR and SERVER_LOG' }, async () => {
  const d = await sentDoc();
  await call(`/sign/${d.tokens[0]}`); // adds "Viewed"
  await new Promise((r) => setTimeout(r, 200));
  const rows = eventRows(d.id);
  const anchor = auditHeads(d.id).at(-1);
  assert.ok(anchor, 'audit_head line logged');
  assert.equal(anchor.count, rows.length);
  assert.equal(anchor.head, rows.at(-1).hash);
  if (KEY) assert.equal(anchor.key_id, sha(auditKey()).slice(0, 8));
  db().prepare('DELETE FROM events WHERE id = ?').run(rows.at(-1).id);
  const after = eventRows(d.id);
  if (KEY) assert.ok(verifyChain(after).ok, 'a truncated chain is still internally valid; only the anchor reveals it');
  assert.ok(after.length !== anchor.count && after.at(-1).hash !== anchor.head, 'truncation visible against the last logged head');
});

test('deleting a document keeps an encrypted audit tombstone with the chain head', { skip: noDb }, async () => {
  const d = await sentDoc();
  assert.equal((await call(`/api/documents/${d.id}/void`, { method: 'POST', cookie: d.cookie, body: { reason: 'x' } })).status, 200);
  const rows = eventRows(d.id);
  const head = rows.at(-1).hash;
  if (KEY) assert.ok(verifyChain(rows).ok);
  assert.equal((await call(`/api/documents/${d.id}`, { method: 'DELETE', cookie: d.cookie })).status, 200);
  assert.equal(eventRows(d.id).length, 0);
  const t = db().prepare('SELECT * FROM audit_tombstones WHERE document_id = ?').get(d.id);
  assert.ok(t, 'tombstone row');
  assert.equal(t.final_hash, head);
  assert.equal(t.event_count, rows.length);
  assert.match(t.events_json, /^enc:v1:/);
  assert.ok(!t.events_json.includes('Voided'));
  assert.equal(fs.existsSync(path.join(filesDir(), `${d.id}.original.pdf`)), false);
});

// ---------- Logs ----------

test('security log rows and server stdout contain no passwords, cookies or signing tokens', { skip: !LOG && !DATA_DIR && 'needs SERVER_LOG or DATA_DIR' }, async () => {
  // A password typed into the email box (unknown account) must not be logged verbatim.
  const typo = `Tr0ub4dor-${rnd()}-secret`;
  secrets.push(typo);
  assert.equal((await login(typo, 'whatever-xxxxxx')).status, 401);
  await new Promise((r) => setTimeout(r, 300)); // let stdout flush
  const sources = [];
  if (LOG) sources.push(['stdout', fs.readFileSync(LOG, 'utf8')]);
  if (DATA_DIR) {
    sources.push(['security_events', JSON.stringify(db().prepare('SELECT * FROM security_events').all())]);
    sources.push(['events', JSON.stringify(db().prepare('SELECT * FROM events').all())]);
  }
  assert.ok(secrets.length > 20);
  for (const [name, text] of sources) for (const s of secrets) assert.ok(!text.includes(s), `${name} contains a secret (${s.slice(0, 4)}...)`);
  if (KEY) assert.ok(!sources.some(([, text]) => text.includes(KEY.trim())), 'encryption key logged');
});
