// Tier 1 security regressions (Raymond): email code (OTP), seal, expiry, self-sign, new field types.
// Run against a FRESH disposable server (ALLOW_SIGNUP=true, SIGNUP_MAX_PER_HOUR=1000, explicit ENCRYPTION_KEY, no SMTP, no APP_URL):
//   ENCRYPTION_KEY=<same as server> DATA_DIR=<server's DATA_DIR> BASE_URL=http://localhost:3417 node --test test/security/
// Without SMTP the server refuses to send a document with require_otp, so OTP tests send without it and set
// documents.require_otp = 1 in the throwaway DB, then plant a code hash exactly as POST /otp {action:'send'} would
// (keyedHash('otp', recipientId + ':' + code), see lib/crypto.js). They need DATA_DIR and ENCRYPTION_KEY, else they skip.
// Tests marked `todo` document open findings (T1-*) and assert the SECURE behaviour; they do not fail the suite.
// Tests that need SMTP (SMTP_HOST and APP_URL in the env) skip without it; the full T1-1 test also needs QA_SMTP_SINK_PORT and starts its own sink there.
import { test } from 'node:test';
import { spawn } from 'node:child_process';
import os from 'node:os';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import zlib from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';
import forge from 'node-forge';

const BASE = new URL(process.env.BASE_URL || 'http://localhost:3000');
const DATA_DIR = process.env.DATA_DIR;
const KEY = process.env.ENCRYPTION_KEY;
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const needDb = !(DATA_DIR && KEY) && 'needs DATA_DIR and ENCRYPTION_KEY of the server under test';
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const rnd = () => crypto.randomBytes(5).toString('hex');

let _db;
const db = () => {
  if (!_db) { _db = new DatabaseSync(path.join(DATA_DIR, 'countersign.db')); _db.exec('PRAGMA busy_timeout = 5000'); }
  return _db;
};
const keyBytes = () => (/^[0-9a-fA-F]{64}$/.test(KEY.trim()) ? Buffer.from(KEY.trim(), 'hex') : Buffer.from(KEY.trim(), 'base64'));
// Independent re-implementation of lib/crypto.js keyedHash.
const keyedHash = (info, data) => crypto.createHmac('sha256', Buffer.from(crypto.hkdfSync('sha256', keyBytes(), Buffer.alloc(0), 'countersign-' + info, 32))).update(data).digest('hex');
function decryptCse1(buf, aad) {
  assert.equal(buf.subarray(0, 4).toString(), 'CSE1');
  const d = crypto.createDecipheriv('aes-256-gcm', keyBytes(), buf.subarray(4, 16));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(buf.subarray(16, 32));
  return Buffer.concat([d.update(buf.subarray(32)), d.final()]);
}

function call(p, { method = 'GET', cookie, body, headers = {} } = {}) {
  const h = { ...headers };
  if (cookie) h.cookie = cookie;
  let b = body;
  if (b !== undefined && !Buffer.isBuffer(b)) { b = JSON.stringify(b); h['content-type'] = 'application/json'; }
  return new Promise((resolve, reject) => {
    const req = http.request({ host: BASE.hostname === 'localhost' ? '127.0.0.1' : BASE.hostname, port: BASE.port, path: p, method, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        let json; try { json = JSON.parse(buf.toString()); } catch {}
        resolve({ status: res.statusCode, headers: res.headers, buf, json, text: buf.toString('latin1'), setCookie: res.headers['set-cookie'] || [] });
      });
    });
    req.on('error', reject);
    req.end(b);
  });
}
const props = (html) => JSON.parse(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s.exec(html)[1]).props.pageProps;

async function signup(email = `t1-${rnd()}@example.com`) {
  const r = await call('/api/auth/signup', { method: 'POST', body: { name: 'T1 Owner', email, password: `pw-${rnd()}-${rnd()}` } });
  assert.equal(r.status, 200, r.text);
  return { email: email.toLowerCase(), cookie: r.setCookie.find((c) => c.startsWith('cs_session=')).split(';')[0] };
}
async function pdfBytes(extra) {
  const pdf = await PDFDocument.create();
  pdf.addPage([612, 792]).drawText(`t1 ${rnd()}`, { x: 50, y: 700 });
  if (extra) extra(pdf);
  return Buffer.from(await pdf.save({ useObjectStreams: false }));
}
const sigF = (rid, y = 0.1) => ({ recipientId: rid, type: 'signature', page: 0, x: 0.1, y, w: 0.3, h: 0.06 });
// Draft with recipients/fields as the editor sends them. Returns { id, put } (put = PUT response).
async function draft(o, recipients, fields, extra = {}, bytes) {
  const up = await call('/api/documents', { method: 'POST', cookie: o.cookie, body: bytes || await pdfBytes(), headers: { 'content-type': 'application/pdf', 'x-file-name': 'T1.pdf' } });
  assert.equal(up.status, 201, up.text);
  const put = await call(`/api/documents/${up.json.id}`, { method: 'PUT', cookie: o.cookie, body: { title: 'T1', recipients, fields, ...extra } });
  assert.equal(put.status, 200, put.text);
  return { id: up.json.id, put: put.json };
}
const send = (o, id, body = {}) => call(`/api/documents/${id}/send`, { method: 'POST', cookie: o.cookie, body });
async function tokens(o, id) {
  const p = props((await call(`/app/documents/${id}`, { cookie: o.cookie })).text);
  return Object.fromEntries(p.recipients.map((r) => [r.email, { rid: r.id, token: r.token }]));
}
const plantCode = (rid, code, exp = Date.now() + 600_000) => db().prepare('UPDATE recipients SET otp_hash = ?, otp_expires_at = ?, otp_attempts = 0 WHERE id = ?')
  .run(keyedHash('otp', `${rid}:${code}`), new Date(exp).toISOString(), rid);
const verify = (token, code, cookie) => call(`/api/sign/${token}/otp`, { method: 'POST', body: { action: 'verify', code }, cookie });
const submit = (token, values, cookie) => call(`/api/sign/${token}`, { method: 'POST', body: { values }, cookie });
const docRow = (id) => db().prepare('SELECT * FROM documents WHERE id = ?').get(id);
const recRow = (rid) => db().prepare('SELECT * FROM recipients WHERE id = ?').get(rid);

// One signer, sent without OTP, then require_otp switched on in the DB (what a server with SMTP stores at send).
async function otpDoc({ message = `MSG-${rnd()}`, label = `LABEL-${rnd()}` } = {}) {
  const o = await signup();
  const email = `otp-${rnd()}@example.com`;
  const { id, put } = await draft(o, [{ id: 'a', name: 'Otp Signer', email, role: 'signer' }],
    [sigF('a'), { recipientId: 'a', type: 'text', page: 0, x: 0.1, y: 0.3, w: 0.3, h: 0.05, label, required: false }], { message });
  assert.equal((await send(o, id)).status, 200);
  db().prepare('UPDATE documents SET require_otp = 1 WHERE id = ?').run(id);
  const { rid, token } = (await tokens(o, id))[email];
  return { o, id, put, email, rid, token, message, label, sigId: put.fields.find((f) => f.type === 'signature').id };
}
const otpCookie = (res, rid) => res.setCookie.find((c) => c.startsWith(`cs_otp_${rid}=`));

// ---------- OTP: gating, cookie, replay, single session ----------

test('OTP: nothing about the document leaks before verification (page, file, submit, decline)', { skip: needDb }, async () => {
  const d = await otpDoc();
  const page = await call(`/sign/${d.token}`);
  assert.equal(page.status, 200);
  const p = props(page.text);
  assert.equal(p.state, 'verify');
  assert.deepEqual(p.fields, []);
  for (const secret of [d.message, d.label, d.email, d.sigId]) assert.ok(!page.text.includes(secret), `page leaks ${secret}`);
  assert.equal(p.maskedEmail, `o***@example.com`);
  assert.equal(recRow(d.rid).status, 'sent', 'an unverified visit is not recorded as Viewed');
  for (const r of [
    await call(`/api/sign/${d.token}/file`), await call(`/api/sign/${d.token}/file?download=1`),
    await submit(d.token, { [d.sigId]: PNG }), await call(`/api/sign/${d.token}/decline`, { method: 'POST', body: { reason: 'x' } }),
  ]) {
    assert.deepEqual([r.status, r.json?.error], [403, 'Verify your email first']);
    assert.ok(!r.text.includes('%PDF'));
  }
  // An owner session is not a signer verification.
  assert.equal((await call(`/api/sign/${d.token}/file`, { cookie: d.o.cookie })).status, 403);
  assert.equal(docRow(d.id).status, 'sent');
});

test('OTP: verify sets a scoped HttpOnly cookie, stores only a keyed hash, and the code cannot be replayed', { skip: needDb }, async () => {
  const d = await otpDoc();
  plantCode(d.rid, '424242');
  const ok = await verify(d.token, ' 424242 ');
  assert.equal(ok.status, 200, ok.text);
  const c = otpCookie(ok, d.rid);
  assert.ok(c, 'cs_otp_<recipient id> cookie');
  const attrs = c.split(';').map((s) => s.trim().toLowerCase());
  for (const a of ['httponly', 'samesite=lax', 'path=/', 'max-age=43200']) assert.ok(attrs.includes(a), `${a} in ${c}`);
  if (BASE.protocol === 'http:' && !process.env.APP_URL) assert.ok(!attrs.includes('secure'), 'no Secure on plain http');
  const value = c.split(';')[0].split('=')[1];
  assert.ok(Buffer.from(value, 'base64url').length >= 32, 'session value has at least 256 bits');
  const row = recRow(d.rid);
  assert.equal(row.otp_session_hash, keyedHash('otp-session', value), 'session stored as keyedHash, not plaintext');
  assert.ok(!JSON.stringify(row).includes(value));
  assert.equal(row.otp_hash, null, 'code burned on success');
  assert.ok(row.otp_verified_at);
  const replay = await verify(d.token, '424242');
  assert.deepEqual([replay.status, replay.json.error], [400, 'Send a code first.']);
  assert.equal(otpCookie(replay, d.rid), undefined);
  // With the cookie the signer gets the document.
  const cookie = c.split(';')[0];
  assert.equal(props((await call(`/sign/${d.token}`, { cookie })).text).state, 'sign');
  assert.equal((await call(`/api/sign/${d.token}/file`, { cookie })).status, 200);
});

test('OTP: a new verification ends the previous session; an expired session is refused', { skip: needDb }, async () => {
  const d = await otpDoc();
  plantCode(d.rid, '111111');
  const first = otpCookie(await verify(d.token, '111111'), d.rid).split(';')[0];
  plantCode(d.rid, '222222');
  const second = otpCookie(await verify(d.token, '222222'), d.rid).split(';')[0];
  assert.equal((await call(`/api/sign/${d.token}/file`, { cookie: first })).status, 403, 'old session dead');
  assert.equal((await call(`/api/sign/${d.token}/file`, { cookie: second })).status, 200);
  db().prepare('UPDATE recipients SET otp_session_expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), d.rid);
  assert.equal((await call(`/api/sign/${d.token}/file`, { cookie: second })).status, 403, 'expired session');
  assert.equal(props((await call(`/sign/${d.token}`, { cookie: second })).text).state, 'verify');
});

test('OTP: a session or code of one recipient does not work for another recipient', { skip: needDb }, async () => {
  const o = await signup();
  const [ea, eb] = [`a-${rnd()}@example.com`, `b-${rnd()}@example.com`];
  const { id } = await draft(o, [{ id: 'a', name: 'A', email: ea, role: 'signer' }, { id: 'b', name: 'B', email: eb, role: 'signer' }], [sigF('a'), sigF('b', 0.3)]);
  assert.equal((await send(o, id)).status, 200);
  db().prepare('UPDATE documents SET require_otp = 1 WHERE id = ?').run(id);
  const t = await tokens(o, id);
  const A = t[ea], B = t[eb];
  plantCode(A.rid, '333333');
  const value = otpCookie(await verify(A.token, '333333'), A.rid).split(';')[0].split('=')[1];
  assert.equal((await call(`/api/sign/${B.token}/file`, { cookie: `cs_otp_${A.rid}=${value}` })).status, 403, "A's cookie on B's link");
  assert.equal((await call(`/api/sign/${B.token}/file`, { cookie: `cs_otp_${B.rid}=${value}` })).status, 403, "A's value under B's name");
  // A code hash bound to A's id does not verify for B.
  db().prepare('UPDATE recipients SET otp_hash = ?, otp_expires_at = ?, otp_attempts = 0 WHERE id = ?')
    .run(keyedHash('otp', `${A.rid}:444444`), new Date(Date.now() + 600_000).toISOString(), B.rid);
  assert.deepEqual([(await verify(B.token, '444444')).json.error], ['That code is not right']);
});

test('OTP brute force: 20 parallel guesses burn the code after 5; the right code then fails too', { skip: needDb }, async () => {
  const d = await otpDoc();
  plantCode(d.rid, '987654');
  const guesses = await Promise.all(Array.from({ length: 20 }, (_, i) => verify(d.token, String(100000 + i))));
  const wrong = guesses.filter((r) => r.status === 400 && r.json.error === 'That code is not right').length;
  const locked = guesses.filter((r) => r.status === 429 && r.json.error === 'Too many attempts. Send a new code.').length;
  assert.equal(wrong, 4, `${wrong} evaluated as wrong (4 + the 5th locks)`);
  assert.equal(locked, 16);
  assert.equal(recRow(d.rid).otp_hash, null, 'code burned');
  const late = await verify(d.token, '987654');
  assert.equal(late.status, 429, 'the correct code no longer works');
  assert.equal(otpCookie(late, d.rid), undefined);
  const types = db().prepare("SELECT type, COUNT(*) AS n FROM security_events WHERE detail = ? GROUP BY type").all(`recipient ${d.rid}`);
  const n = Object.fromEntries(types.map((r) => [r.type, r.n]));
  assert.equal(n.otp_failure, 4);
  assert.equal(n.otp_locked, 1);
  assert.ok(!JSON.stringify(db().prepare('SELECT * FROM security_events WHERE detail = ?').all(`recipient ${d.rid}`)).includes('987654'));
});

test('OTP: non-string or malformed codes never verify', { skip: needDb }, async () => {
  const d = await otpDoc();
  plantCode(d.rid, '012345');
  for (const code of [12345, ['012345'], { code: '012345' }]) {
    const r = await verify(d.token, code);
    assert.equal(r.status, 400, JSON.stringify(code));
    assert.equal(otpCookie(r, d.rid), undefined);
  }
  assert.equal((await verify(d.token, '012345')).status, 200, 'still verifies with 2 wrong attempts used');
});

test('OTP: an expired code is refused', { skip: needDb }, async () => {
  const d = await otpDoc();
  plantCode(d.rid, '555555', Date.now() - 1000);
  assert.deepEqual([(await verify(d.token, '555555')).json.error], ['That code has expired. Send a new one.']);
});

test('OTP: unknown and revoked links answer like every other token route (no oracle)', { skip: needDb }, async () => {
  const unknown = await call(`/api/sign/${crypto.randomBytes(24).toString('base64url')}/otp`, { method: 'POST', body: { action: 'verify', code: '000000' } });
  const unknownFile = await call(`/api/sign/${crypto.randomBytes(24).toString('base64url')}/file`);
  assert.deepEqual([unknown.status, unknown.json.error], [unknownFile.status, unknownFile.json.error]);
  const d = await otpDoc();
  assert.equal((await call(`/api/documents/${d.id}/void`, { method: 'POST', cookie: d.o.cookie, body: { reason: 'x' } })).status, 200);
  const rev = await verify(d.token, '000000');
  assert.deepEqual([rev.status, rev.json.error], [410, 'This signing link is no longer valid.']);
});

test('OTP: the completed signed PDF is not downloadable without verification', { skip: needDb }, async () => {
  const o = await signup();
  const email = `c-${rnd()}@example.com`;
  const { id, put } = await draft(o, [{ id: 'a', name: 'C', email, role: 'signer' }], [sigF('a')]);
  assert.equal((await send(o, id)).status, 200);
  const { token } = (await tokens(o, id))[email];
  assert.equal((await submit(token, { [put.fields[0].id]: PNG })).json.status, 'completed');
  db().prepare('UPDATE documents SET require_otp = 1 WHERE id = ?').run(id);
  assert.equal((await call(`/api/sign/${token}/file?download=1`)).status, 403);
  assert.equal(props((await call(`/sign/${token}`)).text).state, 'verify');
});

test('T1-3 OTP: a queued signer or cc sees only the title before verification and is not recorded as Viewed', { skip: needDb }, async () => {
  const o = await signup();
  const [ea, eb, ec] = [`qa-${rnd()}@example.com`, `qb-${rnd()}@example.com`, `qc-${rnd()}@example.com`];
  const message = `QUEUED-MSG-${rnd()}`;
  const { id } = await draft(o, [{ id: 'a', name: 'A', email: ea, role: 'signer' }, { id: 'b', name: 'B', email: eb, role: 'signer' }, { id: 'c', name: 'C', email: ec, role: 'cc' }],
    [sigF('a'), sigF('b', 0.3)], { message, sequential: true });
  assert.equal((await send(o, id)).status, 200);
  db().prepare('UPDATE documents SET require_otp = 1 WHERE id = ?').run(id);
  const t = await tokens(o, id);
  for (const e of [eb, ec]) {
    const before = recRow(t[e].rid).status;
    const html = (await call(`/sign/${t[e].token}`)).text;
    assert.ok(!html.includes(message), `message shown to unverified ${e}`);
    assert.ok(!html.includes(e), `full email shown to unverified ${e}`);
    const p = props(html);
    assert.deepEqual([p.me, p.fields, Object.keys(p.doc)], [null, [], ['title']]);
    assert.equal(recRow(t[e].rid).status, before, `unverified visit changed the status of ${e}`);
  }
  assert.equal(db().prepare("SELECT COUNT(*) AS n FROM events WHERE document_id = ? AND action = 'Viewed'").get(id).n, 0);
});

// ---------- Expiry ----------

test('expiry: past expires_at blocks sign, decline, file and code on every route, revokes links once', { skip: needDb }, async () => {
  const o = await signup();
  const email = `e-${rnd()}@example.com`;
  const { id, put } = await draft(o, [{ id: 'a', name: 'E', email, role: 'signer' }], [sigF('a')], { expireDays: 7 });
  assert.equal((await send(o, id)).status, 200);
  const { token } = (await tokens(o, id))[email];
  db().prepare('UPDATE documents SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), id);
  assert.equal(docRow(id).status, 'sent', 'not expired until something looks');
  const tries = [
    await submit(token, { [put.fields[0].id]: PNG }),
    await call(`/api/sign/${token}/decline`, { method: 'POST', body: { reason: 'x' } }),
    await call(`/api/sign/${token}/file`),
    await call(`/api/sign/${token}/otp`, { method: 'POST', body: { action: 'send' } }),
  ];
  for (const r of tries) {
    assert.equal(r.status, 410, r.text);
    assert.match(r.json.error, /^This document expired on /);
  }
  const page = await call(`/sign/${token}`);
  assert.equal(page.status, 410);
  const p = props(page.text);
  assert.equal(p.state, 'expired');
  assert.equal(p.token, null, 'dead page does not echo the token');
  assert.equal(docRow(id).status, 'expired');
  assert.equal(db().prepare("SELECT COUNT(*) AS n FROM recipients WHERE document_id = ? AND token_revoked_at IS NULL").get(id).n, 0);
  assert.equal(db().prepare("SELECT COUNT(*) AS n FROM events WHERE document_id = ? AND action = 'Expired'").get(id).n, 1);
  assert.equal((await call(`/api/documents/${id}/remind`, { method: 'POST', cookie: o.cookie, body: { recipientId: put.recipients[0].id } })).status, 409);
  assert.equal((await call(`/api/documents/${id}`, { method: 'DELETE', cookie: o.cookie })).status, 200, 'owner may delete an expired document');
});

test('T1-5 expiry: remind on an overdue document expires it and refuses, even before any link lookup', { skip: needDb }, async () => {
  const o = await signup();
  const email = `r-${rnd()}@example.com`;
  const { id, put } = await draft(o, [{ id: 'a', name: 'R', email, role: 'signer' }], [sigF('a')], { expireDays: 7 });
  assert.equal((await send(o, id)).status, 200);
  const rid = put.recipients[0].id;
  const tokenExp = recRow(rid).token_expires_at;
  db().prepare('UPDATE documents SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), id);
  const remindIt = () => call(`/api/documents/${id}/remind`, { method: 'POST', cookie: o.cookie, body: { recipientId: rid } });
  const r = await remindIt();
  assert.deepEqual([r.status, r.json.error], [409, 'This document has expired']);
  assert.equal(docRow(id).status, 'expired');
  assert.ok(recRow(rid).token_revoked_at, 'link revoked');
  assert.equal(recRow(rid).token_expires_at, tokenExp, 'token not extended');
  const n = (a) => db().prepare('SELECT COUNT(*) AS n FROM events WHERE document_id = ? AND action = ?').get(id, a).n;
  assert.deepEqual([n('Expired'), n('Reminded')], [1, 0]);
  assert.equal((await remindIt()).status, 409);
  assert.equal(n('Expired'), 1, 'a second remind adds no second Expired event');
});

// ---------- T1-1: remind resets the email-code send cap ----------

const needSmtp = !(process.env.SMTP_HOST && process.env.APP_URL) && 'needs SMTP_HOST and APP_URL set on the server AND in this test process env; left to the QA SMTP sink run';
const capCode = (rid) => db().prepare('UPDATE recipients SET otp_send_count = 10, otp_attempts = 5, otp_sent_at = NULL WHERE id = ?').run(rid);

test('T1-1 OTP: a reminder that was not delivered does not reset the send cap', { skip: needDb || (!needSmtp && 'SMTP configured: the full T1-1 test covers it') }, async () => {
  const d = await otpDoc();
  capCode(d.rid);
  const r = await call(`/api/documents/${d.id}/remind`, { method: 'POST', cookie: d.o.cookie, body: { recipientId: d.rid } });
  assert.equal(r.status, 400, r.text);
  assert.deepEqual([recRow(d.rid).otp_send_count, recRow(d.rid).otp_attempts], [10, 5], 'cap reset without a delivered reminder');
  assert.equal(db().prepare("SELECT COUNT(*) AS n FROM events WHERE document_id = ? AND action = 'Reminded'").get(d.id).n, 0);
});

// Minimal in-process SMTP sink (copied from test/p0.test.mjs), so this file does not depend on QA's sink being up.
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
const needSink = !process.env.QA_SMTP_SINK_PORT && 'needs QA_SMTP_SINK_PORT (server SMTP_HOST=127.0.0.1 SMTP_PORT=<same> APP_URL=<BASE_URL>)';

test('T1-1 OTP: at the cap a send is refused; the owner reminder resets it and logs the reset', { skip: needDb || needSmtp || needSink }, async () => {
  const sink = await smtpSink(Number(process.env.QA_SMTP_SINK_PORT));
  try {
  const d = await otpDoc();
  capCode(d.rid);
  const refused = await call(`/api/sign/${d.token}/otp`, { method: 'POST', body: { action: 'send' } });
  assert.deepEqual([refused.status, refused.json.error], [429, 'Too many codes were sent for this link. Contact the sender.']);
  const other = await signup();
  assert.equal((await call(`/api/documents/${d.id}/remind`, { method: 'POST', cookie: other.cookie, body: { recipientId: d.rid } })).status, 404, 'another user cannot reset it');
  assert.equal(recRow(d.rid).otp_send_count, 10);
  const r = await call(`/api/documents/${d.id}/remind`, { method: 'POST', cookie: d.o.cookie, body: { recipientId: d.rid } });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual([recRow(d.rid).otp_send_count, recRow(d.rid).otp_attempts], [0, 0]);
  const ev = db().prepare("SELECT detail FROM events WHERE document_id = ? AND action = 'Reminded'").all(d.id);
  assert.deepEqual(ev.map((e) => e.detail), ['Otp Signer. Email code limit reset']);
  assert.equal((await call(`/api/sign/${d.token}/otp`, { method: 'POST', body: { action: 'send' } })).status, 200);
  } finally { sink.close(); }
});

test('expiry: expireDays is clamped to 0-365 at save', { skip: needDb }, async () => {
  const o = await signup();
  for (const [input, want] of [[9999, 365], [-5, 0], ['abc', 0], [7.9, 7], [null, 0]]) {
    const { id } = await draft(o, [{ id: 'a', name: 'E', email: `x-${rnd()}@example.com`, role: 'signer' }], [sigF('a')], { expireDays: input });
    assert.equal(docRow(id).expire_days, want, `expireDays ${JSON.stringify(input)}`);
  }
});

test('expiry: a completed document stays downloadable after its deadline', { skip: needDb }, async () => {
  const o = await signup();
  const email = `ce-${rnd()}@example.com`;
  const { id, put } = await draft(o, [{ id: 'a', name: 'E', email, role: 'signer' }], [sigF('a')], { expireDays: 1 });
  assert.equal((await send(o, id)).status, 200);
  const { token } = (await tokens(o, id))[email];
  assert.equal((await submit(token, { [put.fields[0].id]: PNG })).json.status, 'completed');
  db().prepare('UPDATE documents SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), id);
  assert.equal((await call(`/api/sign/${token}/file`)).status, 200);
  assert.equal(docRow(id).status, 'completed');
});

// ---------- Self-sign ----------

test('self-sign: only the owner as the sole signer; case-insensitive; OTP stored as off; failure leaves a draft', { skip: needDb }, async () => {
  const o = await signup(`Self-${rnd()}@Example.COM`);
  const sig = [sigF('m')];
  const cases = [
    [[{ id: 'm', name: 'Other', email: `other-${rnd()}@example.com`, role: 'signer' }], sig],
    [[{ id: 'm', name: 'Me', email: o.email, role: 'signer' }, { id: 'c', name: 'Cc', email: `cc-${rnd()}@example.com`, role: 'cc' }], sig],
    [[{ id: 'm', name: 'Me', email: o.email, role: 'signer' }, { id: 'x', name: 'X', email: `x-${rnd()}@example.com`, role: 'signer' }], [sigF('m'), sigF('x', 0.3)]],
    [[{ id: 'm', name: 'Me', email: `${o.email}.evil.example`, role: 'signer' }], sig],
  ];
  for (const [recipients, fields] of cases) {
    const { id } = await draft(o, recipients, fields);
    const r = await send(o, id, { selfSign: true });
    assert.deepEqual([r.status, r.json.error], [400, 'Sign yourself needs you as the only signer'], JSON.stringify(recipients.map((x) => x.email)));
    assert.equal(docRow(id).status, 'draft');
    assert.equal(db().prepare('SELECT COUNT(*) AS n FROM recipients WHERE document_id = ? AND token_hash IS NOT NULL').get(id).n, 0, 'no token minted');
  }
  const { id, put } = await draft(o, [{ id: 'm', name: 'Me', email: o.email.toUpperCase(), role: 'signer' }], sig, { requireOtp: true });
  const r = await send(o, id, { selfSign: true });
  assert.equal(r.status, 200, r.text);
  assert.match(r.json.signUrl, /^\/sign\/[\w-]{32}$/);
  assert.equal(docRow(id).require_otp, 0);
  // Another user cannot self-sign someone else's document.
  const other = await signup();
  const { id: id2 } = await draft(o, [{ id: 'm', name: 'Me', email: o.email, role: 'signer' }], sig);
  assert.equal((await send(other, id2, { selfSign: true })).status, 404);
  assert.equal((await submit(r.json.signUrl.slice(6), { [put.fields[0].id]: PNG })).json.status, 'completed');
});

// ---------- New field types ----------

test('fields: dropdown/radio options are cleaned at save; invalid option lists drop the field', { skip: needDb }, async () => {
  const o = await signup();
  const f = (type, options, y) => ({ recipientId: 'a', type, page: 0, x: 0.1, y, w: 0.3, h: 0.05, options });
  const { put } = await draft(o, [{ id: 'a', name: 'F', email: `f-${rnd()}@example.com`, role: 'signer' }], [
    sigF('a'),
    f('dropdown', [' A ', 'B'], 0.2), // kept, trimmed
    f('dropdown', Array.from({ length: 21 }, (_, i) => `o${i}`), 0.3),
    f('radio', ['x'.repeat(61)], 0.35),
    f('radio', ['a', ' a'], 0.4),
    f('dropdown', ['ok', 5], 0.45),
    f('dropdown', 'A,B', 0.5),
    f('radio', [], 0.55),
    f('text', ['should', 'vanish'], 0.6), // kept, options ignored
  ]);
  const types = put.fields.map((x) => x.type).sort();
  assert.deepEqual(types, ['dropdown', 'signature', 'text']);
  assert.deepEqual(put.fields.find((x) => x.type === 'dropdown').options, ['A', 'B']);
  assert.equal(put.fields.find((x) => x.type === 'text').options, null);
});

test('fields: submitted values are validated (choice, number, stamp image)', { skip: needDb }, async () => {
  const o = await signup();
  const email = `v-${rnd()}@example.com`;
  const f = (type, y, extra = {}) => ({ recipientId: 'a', type, page: 0, x: 0.1, y, w: 0.3, h: 0.05, ...extra });
  const { id, put } = await draft(o, [{ id: 'a', name: 'V', email, role: 'signer' }],
    [sigF('a'), f('dropdown', 0.2, { options: ['Red', 'Blue'] }), f('radio', 0.3, { options: ['Yes', 'No'] }), f('number', 0.4), f('stamp', 0.5, { required: false })]);
  assert.equal((await send(o, id)).status, 200);
  const { token } = (await tokens(o, id))[email];
  const by = Object.fromEntries(put.fields.map((x) => [x.type, x.id]));
  const good = { [by.signature]: PNG, [by.dropdown]: 'Blue', [by.radio]: 'No', [by.number]: '-12.5' };
  const bad = async (override, error) => {
    const r = await submit(token, { ...good, ...override });
    assert.deepEqual([r.status, r.json.error], [400, error], JSON.stringify(override));
  };
  for (const v of ['blue', 'Green', '__proto__', 'constructor', 'Red,Blue']) await bad({ [by.dropdown]: v }, 'Choose one of the options');
  await bad({ [by.radio]: ['Yes'] }, 'Fill in every required field');
  await bad({ [by.radio]: { toString: 'Yes' } }, 'Fill in every required field');
  for (const n of ['1e5', '+1', '1.1234567', '0x10', '1 000', '12.', 'NaN', '1'.repeat(16), '١٢']) await bad({ [by.number]: n }, 'Enter a number');
  // Stamp: same strict PNG checks as signatures (dimensions, size, data URL).
  const ihdr = (w, h) => { const b = Buffer.alloc(33); Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b); b.writeUInt32BE(13, 8); b.write('IHDR', 12, 'latin1'); b.writeUInt32BE(w, 16); b.writeUInt32BE(h, 20); return 'data:image/png;base64,' + b.toString('base64'); };
  await bad({ [by.stamp]: ihdr(5000, 10) }, 'Invalid signature image');
  await bad({ [by.stamp]: 'data:image/png;base64,' + 'A'.repeat(400_001) }, 'Invalid signature image');
  await bad({ [by.stamp]: 'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=' }, 'Invalid signature image');
  assert.equal(docRow(id).status, 'sent');
  assert.equal((await submit(token, { ...good, [by.stamp]: PNG })).json.status, 'completed');
});

test('fields: HTML in options and labels is escaped on the signing page and the editor', { skip: needDb }, async () => {
  const o = await signup();
  const email = `x-${rnd()}@example.com`;
  const evil = ['<img src=x onerror=alert(1)>', '</script><script>alert(2)</script>'];
  const { id } = await draft(o, [{ id: 'a', name: '<b>N</b>', email, role: 'signer' }], [
    sigF('a'),
    { recipientId: 'a', type: 'dropdown', page: 0, x: 0.1, y: 0.2, w: 0.3, h: 0.05, options: evil, label: evil[0] },
    { recipientId: 'a', type: 'radio', page: 0, x: 0.1, y: 0.3, w: 0.3, h: 0.1, options: evil, label: evil[1] },
  ]);
  const edit = (await call(`/app/documents/${id}/edit`, { cookie: o.cookie })).text;
  assert.equal((await send(o, id)).status, 200);
  const { token } = (await tokens(o, id))[email];
  const sign = (await call(`/sign/${token}`)).text;
  assert.equal(props(sign).fields.filter((f) => f.options).length, 2, 'options reached the page (as data)');
  for (const html of [edit, sign]) {
    assert.ok(!html.includes('<img src=x'), 'raw <img> in HTML');
    assert.ok(!html.includes('<script>alert(2)'), 'script breakout in HTML');
  }
});

// ---------- Seal ----------

function sealOf(bytes) {
  const s = bytes.toString('latin1');
  const ranges = [...s.matchAll(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g)];
  assert.equal(ranges.length, 1, 'exactly one signature');
  const br = ranges[0].slice(1).map(Number);
  assert.equal(br[0], 0, 'covers from byte 0');
  assert.equal(br[2] + br[3], bytes.length, 'covers to end of file');
  const gap = s.slice(br[1], br[2]);
  assert.match(gap, /^<[0-9a-fA-F]+>$/, 'the only uncovered bytes are the /Contents hex string');
  assert.ok(/\/Contents\s*$/.test(s.slice(br[1] - 12, br[1])), 'gap is the /Contents value');
  const covered = Buffer.concat([bytes.subarray(0, br[1]), bytes.subarray(br[2])]);
  // The DER is followed by zero padding; parse one value and ignore the rest (stripping 00s can eat a real trailing 0x00).
  const p7 = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(forge.util.hexToBytes(gap.slice(1, -1)), { parseAllBytes: false }));
  const md = p7.rawCapture.authenticatedAttributes.map((a) => (forge.asn1.derToOid(a.value[0].value) === forge.pki.oids.messageDigest ? a.value[1].value[0].value : null)).find(Boolean);
  const cert = p7.certificates[0];
  const attrsDer = forge.asn1.toDer(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, p7.rawCapture.authenticatedAttributes)).getBytes();
  const sigOk = cert.publicKey.verify(forge.md.sha256.create().update(attrsDer).digest().bytes(), p7.rawCapture.signature);
  const fp = sha(Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary'));
  return { br, covered, digestOk: Buffer.from(md, 'binary').toString('hex') === sha(covered), sigOk, fp, cert };
}
function pdfText(buf) {
  let out = '';
  for (const m of buf.toString('latin1').matchAll(/stream\r?\n([\s\S]*?)\r?\nendstream/g)) {
    let c; try { c = zlib.inflateSync(Buffer.from(m[1], 'latin1')).toString('latin1'); } catch { c = m[1]; }
    for (const t of c.matchAll(/<([0-9A-Fa-f]+)>\s*Tj/g)) out += Buffer.from(t[1], 'hex').toString('latin1') + '\n';
  }
  return out;
}
async function completed(bytes) {
  const o = await signup();
  const email = `s-${rnd()}@example.com`;
  const { id, put } = await draft(o, [{ id: 'a', name: 'S', email, role: 'signer' }], [sigF('a')], {}, bytes);
  assert.equal((await send(o, id)).status, 200);
  const { token } = (await tokens(o, id))[email];
  return { id, token, res: await submit(token, { [put.fields[0].id]: PNG }) };
}

test('seal: one PKCS#7 signature covering every byte but its own; signed_sha256 is over the final bytes', { skip: needDb }, async () => {
  const { id, token, res } = await completed();
  assert.equal(res.json.status, 'completed');
  const bytes = (await call(`/api/sign/${token}/file?download=1`)).buf;
  const seal = sealOf(bytes);
  assert.ok(seal.digestOk, 'messageDigest = SHA-256 of the covered bytes');
  assert.ok(seal.sigOk, 'RSA signature over the signed attributes verifies');
  assert.equal(docRow(id).signed_sha256, sha(bytes));
  // The certificate page names the same certificate.
  const text = pdfText(bytes).replace(/\n/g, '');
  assert.ok(text.includes(seal.fp), 'certificate page shows the seal fingerprint');
  // Any change to covered bytes breaks the digest.
  const tampered = Buffer.from(bytes); tampered[100] ^= 1;
  assert.ok(!sealOf(tampered).digestOk);
});

test('seal: the self-signed key is stored encrypted under AAD signing-p12 and matches the PDF certificate', { skip: needDb || (process.env.SIGNING_P12_BASE64 && 'operator P12 configured') }, async () => {
  const { token, res } = await completed();
  assert.equal(res.json.status, 'completed');
  const file = path.join(DATA_DIR, 'signing.p12');
  const stored = fs.readFileSync(file);
  assert.equal(stored.subarray(0, 4).toString(), 'CSE1', 'not a plaintext PKCS#12');
  assert.throws(() => decryptCse1(stored, 'file:signing.p12'), 'wrong AAD must fail');
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(decryptCse1(stored, 'signing-p12').toString('binary')), '');
  const cert = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag][0].cert;
  const key = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0].key;
  assert.ok(key.n.bitLength() >= 2048, 'RSA >= 2048');
  assert.equal(cert.siginfo.algorithmOid, forge.pki.oids.sha256WithRSAEncryption);
  const fp = sha(Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary'));
  assert.equal(sealOf((await call(`/api/sign/${token}/file`)).buf).fp, fp);
  assert.ok(!fs.existsSync(file + '.tmp'));
});

const withPlaceholder = (text) => pdfBytes((pdf) => {
  const ref = pdf.context.register(pdf.context.stream(text));
  pdf.catalog.set(pdf.context.obj('Junk'), ref); // referenced, so every writer keeps it
});
const upload = (o, body) => call('/api/documents', { method: 'POST', cookie: o.cookie, body, headers: { 'content-type': 'application/pdf', 'x-file-name': 'T1.pdf' } });

test('T1-4 upload: a PDF with an unfinished @signpdf ByteRange placeholder is refused with 400', { skip: needDb }, async () => {
  const o = await signup();
  const count = () => db().prepare('SELECT COUNT(*) AS n FROM documents WHERE owner_id = (SELECT id FROM users WHERE email = ?)').get(o.email).n;
  for (const text of ['/ByteRange [0 /********** /********** /**********]', '/ByteRange[ 0  /********** /********** /**********]']) {
    const r = await upload(o, await withPlaceholder(text));
    assert.deepEqual([r.status, r.json?.error], [400, 'This PDF contains an unfinished signature placeholder. Export it again and upload the new file.'], text);
  }
  assert.equal(count(), 0, 'no document created');
});

// T1-10: the upload regex is narrower than @signpdf's parser (it takes the next '[' after '/ByteRange', whatever lies between).
// Such a file passes upload; completion must then fail cleanly (422, document stays sent), never 500 or half-complete.
test('T1-10 seal: a placeholder that slips past the upload check fails completion cleanly with 422', { skip: needDb }, async (t) => {
  const bytes = await withPlaceholder('/ByteRange (x) [0 /********** /********** /**********]');
  const up = await upload(await signup(), bytes);
  if (up.status === 400) return t.skip('upload check now refuses this variant too');
  assert.equal(up.status, 201, up.text);
  const { id, res } = await completed(bytes);
  assert.equal(res.status, 422, res.text);
  assert.match(res.json.error, /cannot be sealed/);
  assert.equal(docRow(id).status, 'sent');
  assert.equal(docRow(id).signed_sha256, null);
});

// ---------- T1-6: operator seal certificate checked at boot ----------

function expiredP12() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 2 * 864e5);
  cert.validity.notAfter = new Date(Date.now() - 864e5);
  cert.setSubject([{ name: 'commonName', value: 'expired' }]);
  cert.setIssuer([{ name: 'commonName', value: 'expired' }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return Buffer.from(forge.asn1.toDer(forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], '', { algorithm: '3des' })).getBytes(), 'binary').toString('base64');
}
// Boots `next start` from the existing build in a fresh temp DATA_DIR; resolves with the exit code, or 'running' after 60 s.
function boot(env) {
  const dir = fs.mkdtempSync(path.join(process.env.SCRATCH_DIR || os.tmpdir(), 't1-boot-'));
  const port = String(20000 + crypto.randomInt(20000));
  const child = spawn(process.execPath, [path.resolve('node_modules/next/dist/bin/next'), 'start', '-p', port],
    { env: { ...process.env, DATA_DIR: dir, ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex'), SMTP_HOST: '', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (c) => { out += c; });
  child.stderr.on('data', (c) => { out += c; });
  return new Promise((resolve) => {
    const t = setTimeout(() => { child.kill(); resolve({ code: 'running', out }); }, 60_000);
    child.on('exit', (code) => { clearTimeout(t); try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} resolve({ code, out }); });
  });
}

test('T1-6 boot: an unreadable or expired SIGNING_P12_BASE64 stops the server with exit 1', { skip: !fs.existsSync('.next/BUILD_ID') && 'needs a build (.next) in the cwd' }, async () => {
  for (const [name, p12] of [['garbage', Buffer.from('not a p12 at all').toString('base64')], ['expired', expiredP12()]]) {
    const r = await boot({ SIGNING_P12_BASE64: p12 });
    assert.equal(r.code, 1, `${name}: ${r.out.slice(-500)}`);
    assert.match(r.out, /Startup check failed: .*SIGNING_P12_BASE64/, name);
    assert.ok(!r.out.includes(p12.slice(0, 40)), 'P12 not echoed');
  }
});
