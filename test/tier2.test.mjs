// Tier 2 over HTTP: saved signature, contacts (+ CSV import, auto-add on send), public verify, redirect after signing,
// editable email templates, certificate "Check this copy" line, plus Elon's unit self-check (scripts/tier2-selfcheck.mjs).
// Needs a running FRESH server (ALLOW_SIGNUP=true, SIGNUP_MAX_PER_HOUR=1000, explicit ENCRYPTION_KEY):
//   BASE_URL=http://localhost:3521 DATA_DIR=<server's DATA_DIR> ENCRYPTION_KEY=<same as server> node --test test/tier2.test.mjs
// DATA_DIR (+ ENCRYPTION_KEY or DATA_DIR/encryption.key) enables at-rest checks, injected OTP codes and the reminder job.
// APP_URL in the test env must equal the server's APP_URL (or be unset when the server has none): the certificate test
// expects the "Check this copy at <APP_URL>/verify" line exactly when it is set.
// Mail: (a) server without working email: leave QA_SMTP_SINK_PORT unset, the email-template delivery tests skip; or
//       (b) server with SMTP_HOST=127.0.0.1 SMTP_PORT=<P> APP_URL=<BASE_URL>, test env QA_SMTP_SINK_PORT=<P> APP_URL=<BASE_URL>.
// Verify rate limit (60/hour per IP): without TRUST_PROXY the server keys on the socket address, so this file sends verify
// requests from random 127.x.y.z source addresses (works when BASE_URL is loopback); it also sends X-Forwarded-For with the
// same address, which is used instead when the server runs with TRUST_PROXY=true. Other suites' lookups never share a key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const DATA = process.env.DATA_DIR;
const APP_URL = process.env.APP_URL?.replace(/\/+$/, '') || '';
const SINK_PORT = Number(process.env.QA_SMTP_SINK_PORT) || 0;
const ROOT = path.resolve(import.meta.dirname, '..');
const NEEDS_DB = !DATA && 'needs DATA_DIR pointing at the server data folder';
const NEEDS_SMTP = (!DATA || !SINK_PORT) && 'needs DATA_DIR, QA_SMTP_SINK_PORT and a server with SMTP_HOST=127.0.0.1 SMTP_PORT=<same> APP_URL=<BASE_URL>';
const LOOPBACK = ['localhost', '127.0.0.1', '[::1]'].includes(new URL(BASE).hostname);
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const PASSWORD = 'correct horse battery';
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const rnd = () => crypto.randomBytes(5).toString('hex');
const err = (r) => [r.status, r.data?.error];

// A real RGBA PNG of w x h (distinct from PNG, so it can be searched for in page HTML).
function makePng(w, h) {
  const chunk = (type, data) => {
    const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
    const out = Buffer.alloc(12 + data.length);
    out.writeUInt32BE(data.length, 0); td.copy(out, 4); out.writeUInt32BE(zlib.crc32(td), 8 + data.length);
    return out;
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 6;
  const raw = Buffer.alloc(h * (1 + 4 * w));
  for (let i = 0; i < raw.length; i++) raw[i] = i % (1 + 4 * w) === 0 ? 0 : crypto.randomInt(256);
  const png = Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
  return 'data:image/png;base64,' + png.toString('base64');
}
// Only the 8-byte magic + IHDR declaring w x h (no image data).
const headerPng = (w, h) => {
  const b = Buffer.alloc(33);
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(b);
  b.writeUInt32BE(13, 8); b.write('IHDR', 12, 'latin1'); b.writeUInt32BE(w, 16); b.writeUInt32BE(h, 20); b[24] = 8; b[25] = 6;
  return 'data:image/png;base64,' + b.toString('base64');
};

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
  assert.equal(buf.subarray(0, 4).toString(), 'CSE1');
  const d = crypto.createDecipheriv('aes-256-gcm', key(), buf.subarray(4, 16));
  d.setAAD(Buffer.from(aad)); d.setAuthTag(buf.subarray(16, 32));
  return Buffer.concat([d.update(buf.subarray(32)), d.final()]).toString('utf8');
}
function pdfText(buf) {
  const b = buf.toString('latin1');
  let out = b;
  for (const m of b.matchAll(/stream\r?\n/g)) {
    const start = m.index + m[0].length;
    try { out += zlib.inflateSync(Buffer.from(b.slice(start, b.indexOf('endstream', start)), 'latin1')).toString('latin1'); } catch {}
  }
  return out.toLowerCase();
}
const hasText = (text, s) => text.includes(Buffer.from(s, 'latin1').toString('hex'));

// ---------- In-process SMTP sink (only when QA_SMTP_SINK_PORT is set) ----------
const mails = [];
let sink;
if (SINK_PORT) {
  sink = net.createServer((s) => {
    let data = false, buf = '', rcpt = [];
    s.write('220 sink\r\n');
    s.on('data', (c) => {
      buf += c.toString('latin1');
      for (;;) {
        if (data) {
          const end = buf.indexOf('\r\n.\r\n');
          if (end < 0) break;
          const msg = buf.slice(0, end);
          const split = msg.indexOf('\r\n\r\n');
          const qp = (x) => x.replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
          const head = msg.slice(0, split).replace(/\r\n[ \t]+/g, ' ').replace(/\?=\s+=\?/g, '?==?')
            .replace(/=\?UTF-8\?([QB])\?([^?]*)\?=/gi, (_, enc, t) => (enc.toUpperCase() === 'B' ? Buffer.from(t, 'base64').toString('latin1') : qp(t.replace(/_/g, ' '))));
          const raw = (head + '\r\n\r\n' + qp(msg.slice(split + 4).replace(/=\r\n/g, ''))).replace(/\r\n/g, '\n');
          mails.push({ to: rcpt, subject: /^Subject: (.*)$/mi.exec(head)?.[1] ?? '', raw });
          buf = buf.slice(end + 5); data = false; rcpt = []; s.write('250 ok\r\n');
          continue;
        }
        const i = buf.indexOf('\r\n');
        if (i < 0) break;
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === 'EHLO' || cmd === 'HELO') s.write('250 sink\r\n');
        else if (cmd === 'RCPT') { rcpt.push(/<([^>]+)>/.exec(line)?.[1].toLowerCase()); s.write('250 ok\r\n'); }
        else if (cmd === 'DATA') { data = true; s.write('354 go\r\n'); }
        else if (cmd === 'QUIT') s.end('221 bye\r\n');
        else s.write('250 ok\r\n');
      }
    });
    s.on('error', () => {});
  });
  await new Promise((r) => sink.listen(SINK_PORT, '127.0.0.1', r));
}
test.after(() => { _db?.close(); sink?.close(); });
async function mailTo(addr, pred, what, timeout = 6000) {
  for (let t = 0; t < timeout; t += 100) {
    const m = mails.find((x) => x.to.includes(addr.toLowerCase()) && pred(x));
    if (m) return m;
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.fail(`no email to ${addr}: ${what}; got: ${mails.map((x) => `${x.to} | ${x.subject}`).join(' || ')}`);
}
const textPart = (m) => m.raw.split(/Content-Type: text\/html/i)[0];
const htmlPart = (m) => m.raw.split(/Content-Type: text\/html/i)[1] || '';

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
const pageHtml = async (call, p) => (await call(p, { method: 'GET' })).data.toString();
const props = async (call, p) => JSON.parse(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s.exec(await pageHtml(call, p))[1]).props.pageProps;

async function signup(email = `t2-${Date.now()}-${rnd()}@example.com`, name = 'Tier2 Owner') {
  const call = client();
  const r = await call('/api/auth/signup', { body: { name, email, password: PASSWORD } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return Object.assign(call, { email: email.toLowerCase(), userName: name });
}
// Unique bytes per call, so verify lookups never collide with other documents.
const pdf = async () => { const d = await PDFDocument.create(); d.setTitle(rnd()); d.addPage([612, 792]); return d.save(); };
const field = (recipientId, type = 'signature', extra = {}) => ({ recipientId, type, page: 0, x: 0.1, y: 0.1, w: 0.3, h: 0.08, ...extra });
const person = (id, extra = {}) => ({ id, name: `Signer ${id}`, email: `${id}-${rnd()}@example.com`, role: 'signer', ...extra });
const sigs = (recipients) => recipients.filter((r) => r.role !== 'cc').map((r, i) => field(r.id, 'signature', { y: 0.1 + i * 0.1 }));

async function draft(call, recipients, extra = {}, bytes) {
  const up = await call('/api/documents', { body: bytes ?? await pdf(), headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'Tier2.pdf' } });
  assert.equal(up.status, 201, JSON.stringify(up.data));
  const title = extra.title ?? `Tier2 ${rnd()}`;
  const put = await call(`/api/documents/${up.data.id}`, { method: 'PUT', body: { title, recipients, fields: sigs(recipients), ...extra } });
  assert.equal(put.status, 200, JSON.stringify(put.data));
  return { id: up.data.id, title, ...put.data };
}
async function sent(call, recipients, extra = {}, sendBody = {}) {
  const d = await draft(call, recipients, extra);
  const r = await call(`/api/documents/${d.id}/send`, { body: sendBody });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  const p = await props(call, `/app/documents/${d.id}`);
  return { ...d, doc: p.doc, tokens: d.recipients.map((x) => p.recipients.find((y) => y.id === x.id).token) };
}
const fieldOf = (d, i) => d.fields.find((f) => f.recipient_id === d.recipients[i].id).id;
const submit = (d, i, call = client(), value = PNG) => call(`/api/sign/${d.tokens[i]}`, { body: { values: { [fieldOf(d, i)]: value } } });
const inject = (rid, code) => db().prepare('UPDATE recipients SET otp_hash = ?, otp_expires_at = ?, otp_attempts = 0 WHERE id = ?')
  .run(keyedHash('otp', `${rid}:${code}`), new Date(Date.now() + 600_000).toISOString(), rid);
// A sent document that requires an email code: with mail on it is sent with requireOtp; without mail the server refuses
// that, so require_otp is set in the DB (the state a server with SMTP would have produced).
async function otpDoc(call, recipients) {
  if (SINK_PORT) return sent(call, recipients, { requireOtp: true });
  const d = await sent(call, recipients);
  db().prepare('UPDATE documents SET require_otp = 1 WHERE id = ?').run(d.id);
  return d;
}

// GET /api/verify from a chosen source IP (see header).
const randomIp = () => `127.${crypto.randomInt(1, 255)}.${crypto.randomInt(1, 255)}.${crypto.randomInt(2, 255)}`;
function verifyGet(query, ip, method = 'GET') {
  const u = new URL('/api/verify' + query, BASE);
  return new Promise((resolve, reject) => {
    const req = http.request({
      method, host: u.hostname.replace(/^\[|\]$/g, ''), port: u.port, path: u.pathname + u.search, headers: { 'X-Forwarded-For': ip },
      ...(LOOPBACK && { localAddress: ip, family: 4, host: '127.0.0.1' }),
    }, (res) => {
      let b = '';
      res.on('data', (c) => { b += c; });
      res.on('end', () => { let data; try { data = JSON.parse(b); } catch { data = b; } resolve({ status: res.statusCode, headers: res.headers, data }); });
    });
    req.on('error', reject);
    req.end();
  });
}

// =====================================================================================================================
// Saved signature
// =====================================================================================================================

test('signatures: GET/PUT/DELETE for signature and initials, per user, private no-store; anonymous 401; cross-origin 403', async () => {
  const a = await signup(), b = await signup();
  const s1 = makePng(3, 2), s2 = makePng(5, 1), i1 = makePng(2, 2);
  const get = async (c) => { const r = await c('/api/signatures', { method: 'GET' }); assert.equal(r.status, 200); return r; };
  assert.deepEqual((await get(a)).data, { signature: null, initials: null });
  assert.match((await get(a)).headers.get('cache-control'), /private.*no-store|no-store.*private/);
  assert.deepEqual((await a('/api/signatures', { method: 'PUT', body: { kind: 'signature', value: s1 } })).data, { ok: true });
  assert.deepEqual((await a('/api/signatures', { method: 'PUT', body: { kind: 'initials', value: i1 } })).data, { ok: true });
  assert.deepEqual((await get(a)).data, { signature: s1, initials: i1 });
  assert.deepEqual((await get(b)).data, { signature: null, initials: null }, 'other user sees nothing');
  // Replace.
  assert.equal((await a('/api/signatures', { method: 'PUT', body: { kind: 'signature', value: s2 } })).status, 200);
  assert.deepEqual((await get(a)).data, { signature: s2, initials: i1 });
  // Delete one kind; deleting again is still ok.
  assert.deepEqual((await a('/api/signatures?kind=initials', { method: 'DELETE' })).data, { ok: true });
  assert.deepEqual((await get(a)).data, { signature: s2, initials: null });
  assert.equal((await a('/api/signatures?kind=initials', { method: 'DELETE' })).status, 200);
  // Bad kind.
  for (const kind of [undefined, 'stamp', 'Signature', '']) {
    assert.deepEqual(err(await a('/api/signatures', { method: 'PUT', body: { kind, value: s1 } })), [400, 'Choose signature or initials'], `PUT kind ${kind}`);
  }
  assert.deepEqual(err(await a('/api/signatures?kind=both', { method: 'DELETE' })), [400, 'Choose signature or initials']);
  assert.deepEqual(err(await a('/api/signatures', { method: 'DELETE' })), [400, 'Choose signature or initials']);
  // Anonymous and cross-origin.
  const anon = client();
  assert.equal((await anon('/api/signatures', { method: 'GET' })).status, 401);
  assert.equal((await anon('/api/signatures', { method: 'PUT', body: { kind: 'signature', value: s1 } })).status, 401);
  assert.equal((await anon('/api/signatures?kind=signature', { method: 'DELETE' })).status, 401);
  assert.equal((await a('/api/signatures', { method: 'PUT', body: { kind: 'signature', value: s1 }, headers: { Origin: 'http://evil.test' } })).status, 403);
  assert.equal((await a('/api/signatures?kind=signature', { method: 'DELETE', headers: { Origin: 'http://evil.test' } })).status, 403);
  assert.deepEqual((await get(a)).data, { signature: s2, initials: null }, 'refused requests changed nothing');
});

test('signatures: invalid PNGs are refused 400 "Invalid signature image" and change nothing', async () => {
  const a = await signup();
  const keep = makePng(4, 4);
  assert.equal((await a('/api/signatures', { method: 'PUT', body: { kind: 'signature', value: keep } })).status, 200);
  const longOk = 'data:image/png;base64,' + 'A'.repeat(400_000);
  const bad = {
    'not a string': 42, 'no value': undefined, 'jpeg data URL': PNG.replace('image/png', 'image/jpeg'), 'plain base64': PNG.slice(22),
    'bad base64 chars': PNG + '!', 'too short': 'data:image/png;base64,AAAA', 'not a PNG': 'data:image/png;base64,' + Buffer.from('GIF89a'.repeat(10)).toString('base64'),
    'over 400,000 chars': longOk, 'side > 4000 px': headerPng(4001, 1), 'height > 4000 px': headerPng(1, 4001), 'over 4M pixels': headerPng(2001, 2000),
    'zero width': headerPng(0, 1), 'header only (no image data)': headerPng(10, 10), 'svg': 'data:image/svg+xml;base64,' + Buffer.from('<svg/>').toString('base64'),
  };
  for (const [label, value] of Object.entries(bad)) {
    assert.deepEqual(err(await a('/api/signatures', { method: 'PUT', body: { kind: 'signature', value } })), [400, 'Invalid signature image'], label);
  }
  assert.equal((await a('/api/signatures', { method: 'GET' })).data.signature, keep);
  // Boundaries that must pass: 4000 x 1 and 2000 x 2000 (exactly 4M pixels).
  assert.equal((await a('/api/signatures', { method: 'PUT', body: { kind: 'initials', value: makePng(4000, 1) } })).status, 200, '4000 px side');
  assert.equal((await a('/api/signatures', { method: 'PUT', body: { kind: 'initials', value: makePng(1, 4000) } })).status, 200, '4000 px height');
});

test('signatures: encrypted at rest under AAD usersig:<user id>:<kind>; a row moved to another user is never served', { skip: NEEDS_DB }, async () => {
  const a = await signup(), b = await signup();
  const s = makePng(3, 3), i = makePng(2, 1);
  await a('/api/signatures', { method: 'PUT', body: { kind: 'signature', value: s } });
  await a('/api/signatures', { method: 'PUT', body: { kind: 'initials', value: i } });
  const uid = (c) => db().prepare('SELECT id FROM users WHERE email = ?').get(c.email).id;
  const rows = db().prepare('SELECT kind, value, updated_at FROM user_signatures WHERE user_id = ? ORDER BY kind').all(uid(a));
  assert.deepEqual(rows.map((r) => r.kind), ['initials', 'signature']);
  for (const r of rows) {
    assert.ok(r.updated_at);
    assert.ok(!r.value.includes(s.slice(22, 60)) && !r.value.includes(i.slice(22, 60)) && !r.value.includes('data:image'), 'no plaintext');
    assert.equal(decText(r.value, `usersig:${uid(a)}:${r.kind}`), r.kind === 'signature' ? s : i);
    assert.throws(() => decText(r.value, `usersig:${uid(b)}:${r.kind}`), 'AAD binds the user');
  }
  assert.throws(() => decText(rows[1].value, `usersig:${uid(a)}:initials`), 'AAD binds the kind');
  // Copy a's signature ciphertext into b's row: b must not get a's image.
  db().prepare("INSERT INTO user_signatures (user_id, kind, value, updated_at) VALUES (?, 'signature', ?, ?)").run(uid(b), rows[1].value, rows[1].updated_at);
  const r = await b('/api/signatures', { method: 'GET' });
  assert.ok(!JSON.stringify(r.data).includes(s.slice(22, 60)), `moved ciphertext not served (status ${r.status})`);
  db().prepare("DELETE FROM user_signatures WHERE user_id = ?").run(uid(b));
});

test('sign page: saved signature/initials offered only to the signed-in user whose email matches the recipient (case-insensitive), only while signing', async () => {
  const owner = await signup();
  const signerEmail = `saved-${Date.now()}-${rnd()}@example.com`;
  const signer = await signup(signerEmail, 'Saved Signer');
  const stranger = await signup();
  const s = makePng(6, 2), i = makePng(3, 1);
  assert.equal((await signer('/api/signatures', { method: 'PUT', body: { kind: 'signature', value: s } })).status, 200);
  assert.equal((await signer('/api/signatures', { method: 'PUT', body: { kind: 'initials', value: i } })).status, 200);
  await stranger('/api/signatures', { method: 'PUT', body: { kind: 'signature', value: makePng(7, 1) } });
  const d = await sent(owner, [person('a', { email: signerEmail.toUpperCase() }), person('b')]);
  const leaks = (html) => html.includes(s.slice(22, 80)) || html.includes(i.slice(22, 80));

  for (const [label, c] of [['anonymous', client()], ['owner (other email)', owner], ['stranger (signed in, other email)', stranger]]) {
    const html = await pageHtml(c, `/sign/${d.tokens[0]}`);
    assert.ok(!leaks(html), `${label}: page HTML has no saved image`);
    const p = await props(c, `/sign/${d.tokens[0]}`);
    assert.equal(p.state, 'sign', label);
    assert.equal(p.savedSignature ?? null, null, label);
    assert.equal(p.savedInitials ?? null, null, label);
  }
  // The matching user signed in on someone else's link (b's token) gets nothing.
  const pb = await props(signer, `/sign/${d.tokens[1]}`);
  assert.equal(pb.savedSignature ?? null, null, 'not on another recipient\'s link');
  assert.ok(!leaks(await pageHtml(signer, `/sign/${d.tokens[1]}`)));

  const p = await props(signer, `/sign/${d.tokens[0]}`);
  assert.equal(p.state, 'sign');
  assert.equal(p.savedSignature, s);
  assert.equal(p.savedInitials, i);
  // After signing (state 'waiting') nothing is offered.
  assert.equal((await submit(d, 0, signer, s)).status, 200);
  const after = await props(signer, `/sign/${d.tokens[0]}`);
  assert.equal(after.state, 'waiting');
  assert.equal(after.savedSignature ?? null, null);
  assert.ok(!leaks(await pageHtml(signer, `/sign/${d.tokens[0]}`)), 'nor in the HTML');
  // A user without a saved signature gets nulls (and the page still works).
  await signer('/api/signatures?kind=signature', { method: 'DELETE' });
  await signer('/api/signatures?kind=initials', { method: 'DELETE' });
  const d2 = await sent(owner, [person('a', { email: signerEmail })]);
  const p2 = await props(signer, `/sign/${d2.tokens[0]}`);
  assert.equal(p2.state, 'sign');
  assert.equal(p2.savedSignature, null);
  assert.equal(p2.savedInitials, null);
});

test('sign page with an email code: no saved signature before verification, offered after', { skip: NEEDS_DB }, async () => {
  const owner = await signup();
  const signerEmail = `saved-otp-${Date.now()}-${rnd()}@example.com`;
  const signer = await signup(signerEmail, 'Otp Signer');
  const s = makePng(4, 3);
  assert.equal((await signer('/api/signatures', { method: 'PUT', body: { kind: 'signature', value: s } })).status, 200);
  const d = await otpDoc(owner, [person('o', { email: signerEmail })]);
  const before = await props(signer, `/sign/${d.tokens[0]}`);
  assert.equal(before.state, 'verify');
  assert.equal(before.savedSignature ?? null, null);
  assert.ok(!(await pageHtml(signer, `/sign/${d.tokens[0]}`)).includes(s.slice(22, 80)), 'unverified HTML has no saved image');
  inject(d.recipients[0].id, '135790');
  assert.equal((await signer(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'verify', code: '135790' } })).status, 200);
  const p = await props(signer, `/sign/${d.tokens[0]}`);
  assert.equal(p.state, 'sign');
  assert.equal(p.savedSignature, s);
  // A verified-but-anonymous browser (code verified, not signed in) gets nothing.
  const anon = client();
  inject(d.recipients[0].id, '246801');
  assert.equal((await anon(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'verify', code: '246801' } })).status, 200);
  const pa = await props(anon, `/sign/${d.tokens[0]}`);
  assert.equal(pa.state, 'sign');
  assert.equal(pa.savedSignature ?? null, null);
});

// =====================================================================================================================
// Contacts
// =====================================================================================================================

test('contacts: create, list, update, delete; validation 400; duplicate email 409 (case-insensitive); 404 cross-owner; 401; 403', async () => {
  const a = await signup(), b = await signup();
  const list = async (c, qs = '') => { const r = await c(`/api/contacts${qs}`, { method: 'GET' }); assert.equal(r.status, 200, JSON.stringify(r.data)); return r.data; };
  assert.deepEqual(await list(a), { contacts: [], total: 0 });
  const c1 = await a('/api/contacts', { body: { name: '  Ann Lee  ', email: ' ann@example.com ' } });
  assert.equal(c1.status, 201);
  assert.equal(typeof c1.data.id, 'string');
  assert.deepEqual((await list(a)).contacts, [{ id: c1.data.id, name: 'Ann Lee', email: 'ann@example.com' }], 'trimmed');
  assert.deepEqual(err(await a('/api/contacts', { body: { name: 'Dup', email: 'ANN@Example.com' } })), [409, 'A contact with this email already exists']);
  assert.deepEqual(err(await a('/api/contacts', { body: { name: '', email: 'x@example.com' } })), [400, 'Enter a name']);
  assert.deepEqual(err(await a('/api/contacts', { body: { name: '   ', email: 'x@example.com' } })), [400, 'Enter a name']);
  assert.deepEqual(err(await a('/api/contacts', { body: { email: 'x@example.com' } })), [400, 'Enter a name']);
  for (const email of ['nope', '', 'a@b', 'a b@example.com', undefined, `${'x'.repeat(250)}@example.com`,
    // Header-injection and list separators: , ; < > " ( ) [ ] \ and whitespace inside the address.
    'x@evil.example,y.com', 'x@evil.example;y.com', 'x<y@example.com', 'x@example.com>', '"x"@example.com', 'x(y)@example.com',
    'x@[example].com', 'x\\y@example.com', 'x@exa\tmple.com', 'x@exa\nmple.com', 'a@example.com, b@example.com']) {
    assert.deepEqual(err(await a('/api/contacts', { body: { name: 'X', email } })), [400, 'Enter a valid email address'], `email ${email}`);
  }
  // The same email under another owner is fine.
  assert.equal((await b('/api/contacts', { body: { name: 'Ann (b)', email: 'ann@example.com' } })).status, 201);
  const c2 = await a('/api/contacts', { body: { name: 'Bob', email: 'bob@example.com' } });
  // Update.
  assert.deepEqual((await a(`/api/contacts/${c1.data.id}`, { method: 'PUT', body: { name: 'Ann Smith', email: 'ann.smith@example.com' } })).data, { ok: true });
  assert.deepEqual(err(await a(`/api/contacts/${c2.data.id}`, { method: 'PUT', body: { name: 'Bob', email: 'ANN.SMITH@example.com' } })), [409, 'A contact with this email already exists']);
  assert.deepEqual(err(await a(`/api/contacts/${c2.data.id}`, { method: 'PUT', body: { name: '', email: 'bob@example.com' } })), [400, 'Enter a name']);
  assert.deepEqual(err(await a(`/api/contacts/${c2.data.id}`, { method: 'PUT', body: { name: 'Bob', email: 'bob' } })), [400, 'Enter a valid email address']);
  assert.deepEqual(err(await a(`/api/contacts/${c2.data.id}`, { method: 'PUT', body: { name: 'Bob', email: 'bob@example.com,evil@example.com' } })), [400, 'Enter a valid email address']);
  // Cross-owner and unknown ids: 404, nothing changes.
  assert.deepEqual(err(await b(`/api/contacts/${c1.data.id}`, { method: 'PUT', body: { name: 'Hacked', email: 'h@example.com' } })), [404, 'Contact not found']);
  assert.deepEqual(err(await b(`/api/contacts/${c1.data.id}`, { method: 'DELETE' })), [404, 'Contact not found']);
  assert.deepEqual(err(await a(`/api/contacts/${crypto.randomUUID()}`, { method: 'PUT', body: { name: 'X', email: 'x@example.com' } })), [404, 'Contact not found']);
  assert.deepEqual(err(await a(`/api/contacts/${crypto.randomUUID()}`, { method: 'DELETE' })), [404, 'Contact not found']);
  assert.deepEqual((await list(a)).contacts.map((c) => [c.name, c.email]), [['Ann Smith', 'ann.smith@example.com'], ['Bob', 'bob@example.com']]);
  assert.deepEqual((await list(b)).contacts.map((c) => c.name), ['Ann (b)'], 'owners never see each other');
  // Delete.
  assert.deepEqual((await a(`/api/contacts/${c2.data.id}`, { method: 'DELETE' })).data, { ok: true });
  assert.deepEqual(err(await a(`/api/contacts/${c2.data.id}`, { method: 'DELETE' })), [404, 'Contact not found']);
  assert.equal((await list(a)).total, 1);
  // Anonymous and cross-origin.
  const anon = client();
  assert.equal((await anon('/api/contacts', { method: 'GET' })).status, 401);
  assert.equal((await anon('/api/contacts', { body: { name: 'X', email: 'x@example.com' } })).status, 401);
  assert.equal((await anon(`/api/contacts/${c1.data.id}`, { method: 'DELETE' })).status, 401);
  assert.equal((await anon('/api/contacts/import', { body: 'X,x@example.com', headers: { 'Content-Type': 'text/csv' } })).status, 401);
  assert.equal((await a('/api/contacts', { body: { name: 'X', email: 'x2@example.com' }, headers: { Origin: 'http://evil.test' } })).status, 403);
  assert.equal((await a(`/api/contacts/${c1.data.id}`, { method: 'DELETE', headers: { Origin: 'http://evil.test' } })).status, 403);
  assert.equal((await a('/api/contacts/import', { body: 'X,x3@example.com', headers: { 'Content-Type': 'text/csv', Origin: 'http://evil.test' } })).status, 403);
  assert.equal((await list(a)).total, 1, 'refused requests added nothing');
});

test('contacts: 10,000 per owner; POST over the cap is 400 and adds nothing; other owners unaffected', { skip: NEEDS_DB }, async () => {
  const a = await signup(), b = await signup();
  const uid = db().prepare('SELECT id FROM users WHERE email = ?').get(a.email).id;
  // Fill to 9,999 directly in the throwaway DB (cheap), then the API adds the 10,000th.
  const ins = db().prepare('INSERT INTO contacts (id, owner_id, name, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)');
  const t = new Date().toISOString();
  db().exec('BEGIN');
  try { for (let i = 0; i < 9999; i++) ins.run(crypto.randomUUID(), uid, `Cap ${i}`, `cap${i}@example.com`, t, t); db().exec('COMMIT'); } catch (e) { db().exec('ROLLBACK'); throw e; }
  assert.equal((await a('/api/contacts', { body: { name: 'Ten Thousand', email: 'cap-last@example.com' } })).status, 201, '10,000th allowed');
  assert.equal((await a('/api/contacts', { method: 'GET' })).data.total, 10000);
  assert.deepEqual(err(await a('/api/contacts', { body: { name: 'Over', email: 'cap-over@example.com' } })), [400, 'You have reached the limit of 10,000 contacts']);
  assert.equal((await a('/api/contacts', { method: 'GET' })).data.total, 10000, 'nothing added');
  assert.equal((await b('/api/contacts', { body: { name: 'B', email: 'cap-over@example.com' } })).status, 201, 'cap is per owner');
});

test('contacts: search (name or email, case-insensitive, LIKE wildcards literal), paging, ordering, limit clamped to 200', async () => {
  const a = await signup();
  for (const [name, email] of [['Charlie', 'c@example.com'], ['alice', 'zed@example.com'], ['Bob 100%', 'bob@corp.test'], ['Dora_X', 'dora@example.com'], ['Eve', 'eve@corp.test']]) {
    assert.equal((await a('/api/contacts', { body: { name, email } })).status, 201);
  }
  const get = async (qs) => (await a(`/api/contacts${qs}`, { method: 'GET' })).data;
  assert.deepEqual((await get('')).contacts.map((c) => c.name), ['alice', 'Bob 100%', 'Charlie', 'Dora_X', 'Eve'], 'ordered by name, case-insensitive');
  assert.deepEqual((await get('?q=CORP')).contacts.map((c) => c.name), ['Bob 100%', 'Eve'], 'matches email');
  assert.deepEqual((await get('?q=ALI')).contacts.map((c) => c.name), ['alice'], 'matches name');
  assert.deepEqual(await get('?q=%25'), { contacts: [(await get('?q=bob')).contacts[0]], total: 1 }, '% is literal');
  assert.deepEqual((await get('?q=_')).contacts.map((c) => c.name), ['Dora_X'], '_ is literal');
  assert.equal((await get('?q=nomatch')).total, 0);
  // Paging: total is the full count.
  const p1 = await get('?limit=2'), p2 = await get('?limit=2&offset=2'), p3 = await get('?limit=2&offset=4'), p4 = await get('?limit=2&offset=6');
  assert.deepEqual([p1, p2, p3, p4].map((p) => p.total), [5, 5, 5, 5]);
  assert.deepEqual([...p1.contacts, ...p2.contacts, ...p3.contacts].map((c) => c.name), ['alice', 'Bob 100%', 'Charlie', 'Dora_X', 'Eve']);
  assert.deepEqual(p4.contacts, []);
  assert.deepEqual((await get('?q=corp&limit=1&offset=1')).contacts.map((c) => c.name), ['Eve']);
  // Garbage limit/offset fall back to defaults instead of erroring.
  for (const qs of ['?limit=abc', '?limit=-5&offset=-3', '?offset=xyz']) {
    const r = await a(`/api/contacts${qs}`, { method: 'GET' });
    assert.equal(r.status, 200, qs);
    assert.ok(r.data.contacts.length >= 1 && r.data.contacts.length <= 5, qs);
  }
  // Clamp: 205 contacts, default 50, limit=500 -> 200.
  const csv = Array.from({ length: 200 }, (_, n) => `Bulk ${String(n).padStart(3, '0')},bulk${n}@example.com`).join('\n');
  assert.deepEqual((await a('/api/contacts/import', { body: csv, headers: { 'Content-Type': 'text/csv' } })).data, { added: 200, updated: 0, skipped: 0 });
  assert.equal((await get('')).contacts.length, 50);
  const big = await get('?limit=500');
  assert.equal(big.contacts.length, 200);
  assert.equal(big.total, 205);
  assert.equal((await get('?limit=200&offset=200')).contacts.length, 5);
});

test('contacts CSV import: counts, header order, RFC 4180 quotes, BOM/CRLF, 415, 413, row limit, unclosed quote', async () => {
  const a = await signup(), b = await signup();
  const imp = (body, type = 'text/csv') => a('/api/contacts/import', { body, headers: type ? { 'Content-Type': type } : {} });
  const names = async () => Object.fromEntries((await a('/api/contacts?limit=200', { method: 'GET' })).data.contacts.map((c) => [c.email, c.name]));
  let r = await imp('name,email\n"Lee, Jr.",lee@example.com\n"Quote ""Q"" Person",q@example.com\n"Multi\nLine",m@example.com\nbad,not-an-email\n,noname@example.com\n\n\n');
  assert.deepEqual([r.status, r.data], [200, { added: 3, updated: 0, skipped: 2 }]);
  assert.deepEqual(await names(), { 'lee@example.com': 'Lee, Jr.', 'q@example.com': 'Quote "Q" Person', 'm@example.com': 'Multi\nLine' });
  // Rows whose email has a separator or other forbidden character are skipped, the rest still import.
  r = await imp('name,email\n"Inj","x@evil.example,y.com"\nSemi,x@evil.example;y.com\nAngle,<x@example.com>\n"Quo","""q""@example.com"\nBack,x\\y@example.com\nBrk,x@[example].com\n"Sp","a b@example.com"\nFine,fine@example.com\n');
  assert.deepEqual([r.status, r.data], [200, { added: 1, updated: 0, skipped: 7 }]);
  assert.deepEqual(Object.keys(await names()).sort(), ['fine@example.com', 'lee@example.com', 'm@example.com', 'q@example.com'], 'no forbidden address stored');
  // Header says email first; BOM and CRLF; existing email in another case is updated, same name skipped, new added.
  r = await imp('﻿Email,Name\r\nLEE@example.com,Lee Senior\r\nq@example.com,"Quote ""Q"" Person"\r\nnew@example.com,New Person\r\n', 'text/csv; charset=utf-8');
  assert.deepEqual([r.status, r.data], [200, { added: 1, updated: 1, skipped: 1 }]);
  assert.equal((await names())['lee@example.com'], 'Lee Senior');
  assert.equal(Object.keys(await names()).filter((e) => e.toLowerCase() === 'lee@example.com').length, 1, 'no duplicate');
  // No header: column 1 name, column 2 email; extra columns ignored.
  r = await imp('Ann,ann@example.com,extra,cols\nZed,zed@example.com');
  assert.deepEqual(r.data, { added: 2, updated: 0, skipped: 0 });
  assert.equal((await names())['ann@example.com'], 'Ann');
  // Header without a name column: rows have no name and are skipped.
  assert.deepEqual((await imp('email\nnn@example.com\n')).data, { added: 0, updated: 0, skipped: 1 });
  // Header only / empty file.
  assert.deepEqual((await imp('name,email\n')).data, { added: 0, updated: 0, skipped: 0 });
  assert.deepEqual((await imp('')).data, { added: 0, updated: 0, skipped: 0 });
  // Wrong or missing content type: 415.
  assert.deepEqual(err(await imp('X,x@example.com', 'application/json')), [415, 'Upload a CSV file']);
  assert.deepEqual(err(await imp('X,x@example.com', 'text/plain')), [415, 'Upload a CSV file']);
  assert.equal((await imp(new TextEncoder().encode('X,x@example.com'), 'application/octet-stream')).status, 415);
  // Over 1 MB: 413.
  assert.equal((await imp('x'.repeat(1048577))).status, 413);
  // 2000 data rows (+ header) are accepted; 2001 are refused 400 and nothing is added.
  const rows = (n, p) => Array.from({ length: n }, (_, i) => `R ${i},${p}${i}@example.com`).join('\n');
  const before = (await a('/api/contacts', { method: 'GET' })).data.total;
  assert.equal((await imp('name,email\n' + rows(2001, 'over'))).status, 400, 'with header');
  assert.deepEqual(err(await imp(rows(2001, 'over'))), [400, 'The file has more than 2000 rows'], 'without header');
  assert.equal((await a('/api/contacts', { method: 'GET' })).data.total, before, 'refused import added nothing');
  r = await imp('name,email\n' + rows(2000, 'max'));
  assert.deepEqual([r.status, r.data], [200, { added: 2000, updated: 0, skipped: 0 }]);
  // Unclosed quote: 400, nothing added.
  assert.deepEqual(err(await imp('name,email\n"Open,open@example.com\n')), [400, 'The file has a quote that is never closed']);
  assert.equal((await a('/api/contacts?q=open', { method: 'GET' })).data.total, 0);
  // Owner isolation.
  assert.equal((await b('/api/contacts', { method: 'GET' })).data.total, 0);
});

test('contacts CSV import: header + 2001 data rows names the real limit ("more than 2000 rows")', async () => {
  const a = await signup();
  const rows = Array.from({ length: 2001 }, (_, i) => `R ${i},over${i}@example.com`).join('\n');
  const r = await a('/api/contacts/import', { body: 'name,email\n' + rows, headers: { 'Content-Type': 'text/csv' } });
  assert.deepEqual(err(r), [400, 'The file has more than 2000 rows']);
});

test('contacts on send: new recipients (signers and cc) are added; an existing contact is never renamed or duplicated; self-sign adds none', async () => {
  const a = await signup();
  assert.equal((await a('/api/contacts', { body: { name: 'Hand Edited', email: 'known@example.com' } })).status, 201);
  const list = async () => (await a('/api/contacts?limit=200', { method: 'GET' })).data;
  // A draft alone adds nothing.
  const d = await draft(a, [person('a', { name: 'New Signer', email: 'new.signer@example.com' }), person('b', { name: 'Other Name', email: 'KNOWN@example.com' }),
    { id: 'c', name: 'Copy Person', email: 'cc.person@example.com', role: 'cc' }]);
  assert.equal((await list()).total, 1, 'draft adds no contacts');
  assert.equal((await a(`/api/documents/${d.id}/send`, { body: {} })).status, 200);
  const after = await list();
  assert.deepEqual(after.contacts.map((c) => [c.name, c.email.toLowerCase()]).sort(),
    [['Copy Person', 'cc.person@example.com'], ['Hand Edited', 'known@example.com'], ['New Signer', 'new.signer@example.com']]);
  // Sending again to the same people does not rename them either.
  await sent(a, [person('a', { name: 'Renamed Signer', email: 'new.signer@example.com' })]);
  assert.equal((await list()).contacts.find((c) => c.email === 'new.signer@example.com').name, 'New Signer');
  assert.equal((await list()).total, 3);
  // Self-sign: no contact (owner's own address).
  const self = await draft(a, [person('a', { name: a.userName, email: a.email })]);
  const r = await a(`/api/documents/${self.id}/send`, { body: { selfSign: true } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.ok(r.data.signUrl);
  assert.equal((await list()).total, 3, 'self-sign adds none');
  if (process.env.SERVER_LOG) assert.ok(!fs.readFileSync(process.env.SERVER_LOG, 'utf8').includes('Contacts not updated after send'), 'no contact failure logged');
});

// =====================================================================================================================
// Public verify
// =====================================================================================================================

test('verify: signed copy of a completed document -> title, completedAt, signers (no cc, no emails), exactly; original -> { match: original } only; none -> null', async () => {
  const ip = randomIp();
  const a = await signup();
  const bytes = await pdf();
  const recipients = [person('a', { name: 'Ada Signer' }), person('b', { name: 'Ben Signer' }), { id: 'c', name: 'Cc Watcher', email: `cc-${rnd()}@example.com`, role: 'cc' }];
  const d = await draft(a, recipients, {}, bytes);
  const osha = sha(bytes);
  assert.deepEqual((await verifyGet(`?sha256=${osha}`, ip)).data, { match: 'original' });
  assert.equal((await a(`/api/documents/${d.id}/send`, { body: {} })).status, 200);
  const p = await props(a, `/app/documents/${d.id}`);
  d.tokens = d.recipients.map((x) => p.recipients.find((y) => y.id === x.id).token);
  assert.deepEqual((await verifyGet(`?sha256=${osha}`, ip)).data, { match: 'original' });
  assert.equal((await submit(d, 0)).status, 200);
  assert.equal((await submit(d, 1)).status, 200);
  const signed = await a(`/api/documents/${d.id}/file?kind=signed`, { method: 'GET' });
  assert.equal(signed.status, 200);
  const done = await props(a, `/app/documents/${d.id}`);
  assert.equal(done.doc.status, 'completed');
  const r = await verifyGet(`?sha256=${sha(signed.data)}`, ip);
  assert.equal(r.status, 200);
  assert.match(String(r.headers['cache-control']), /no-store/);
  const signedAt = (name) => done.recipients.find((x) => x.name === name).signed_at;
  assert.deepEqual(r.data, {
    match: 'signed', title: d.title, completedAt: done.doc.completed_at,
    signers: [{ name: 'Ada Signer', signedAt: signedAt('Ada Signer') }, { name: 'Ben Signer', signedAt: signedAt('Ben Signer') }],
  });
  assert.ok(!JSON.stringify(r.data).includes('@'), 'no email addresses');
  // Uppercase and surrounding spaces are accepted.
  assert.equal((await verifyGet(`?sha256=${encodeURIComponent(' ' + sha(signed.data).toUpperCase() + ' ')}`, ip)).data.match, 'signed');
  assert.deepEqual((await verifyGet(`?sha256=${osha}`, ip)).data, { match: 'original' });
  assert.deepEqual((await verifyGet(`?sha256=${sha(await pdf())}`, ip)).data, { match: null });
  // A voided document's original reports only that it matched (no status).
  const v = await sent(a, [person('a')]);
  assert.equal((await a(`/api/documents/${v.id}/void`, { body: {} })).status, 200);
  assert.deepEqual((await verifyGet(`?sha256=${v.doc.original_sha256}`, ip)).data, { match: 'original' });
  // Anonymous access (no session needed) was used throughout; bad input is 400.
  for (const q of ['', '?sha256=', '?sha256=xyz', `?sha256=${'a'.repeat(63)}`, `?sha256=${'a'.repeat(65)}`, `?sha256=${'g'.repeat(64)}`, `?sha256=${'a'.repeat(64)}&sha256=${'b'.repeat(64)}`]) {
    assert.deepEqual(err(await verifyGet(q, ip)), [400, 'Enter a SHA-256 hash'], q);
  }
  assert.notEqual((await verifyGet(`?sha256=${osha}`, ip, 'POST')).status, 200, 'POST is not a lookup');
});

test('verify: only completed documents match their signed hash; deleted documents and templates never match', { skip: NEEDS_DB }, async () => {
  const ip = randomIp();
  const a = await signup();
  // signed_sha256 on a non-completed document (e.g. voided after a failure) never matches as signed.
  const d = await sent(a, [person('a', { name: 'Only Signer' })]);
  const fake = crypto.randomBytes(32).toString('hex');
  db().prepare("UPDATE documents SET signed_sha256 = ?, completed_at = ? WHERE id = ?").run(fake, new Date().toISOString(), d.id);
  assert.deepEqual((await verifyGet(`?sha256=${fake}`, ip)).data, { match: null }, 'sent');
  db().prepare("UPDATE documents SET status = 'voided' WHERE id = ?").run(d.id);
  assert.deepEqual((await verifyGet(`?sha256=${fake}`, ip)).data, { match: null }, 'voided');
  db().prepare("UPDATE documents SET status = 'completed' WHERE id = ?").run(d.id);
  assert.equal((await verifyGet(`?sha256=${fake}`, ip)).data.match, 'signed', 'completed');
  db().prepare("UPDATE documents SET status = 'voided', signed_sha256 = NULL, completed_at = NULL WHERE id = ?").run(d.id);
  // A deleted draft no longer matches; a template made from it does not count as an original.
  const bytes = await pdf();
  const dr = await draft(a, [person('a')], {}, bytes);
  const tpl = await a(`/api/documents/${dr.id}/copy`, { body: { asTemplate: true } });
  assert.equal(tpl.status, 201);
  assert.equal((await verifyGet(`?sha256=${sha(bytes)}`, ip)).data.match, 'original');
  assert.equal((await a(`/api/documents/${dr.id}`, { method: 'DELETE' })).status, 200);
  assert.deepEqual((await verifyGet(`?sha256=${sha(bytes)}`, ip)).data, { match: null }, 'deleted draft (template remains) does not match');
  // A deleted voided document does not match either.
  const vb = await pdf();
  const v = await draft(a, [person('a')], {}, vb);
  assert.equal((await a(`/api/documents/${v.id}/send`, { body: {} })).status, 200);
  assert.equal((await a(`/api/documents/${v.id}/void`, { body: {} })).status, 200);
  assert.equal((await a(`/api/documents/${v.id}`, { method: 'DELETE' })).status, 200);
  assert.deepEqual((await verifyGet(`?sha256=${sha(vb)}`, ip)).data, { match: null }, 'deleted voided');
});

test('verify: 60 lookups per hour per IP, then 429 with Retry-After (also for bad input); other IPs unaffected', { skip: !LOOPBACK && 'needs a loopback BASE_URL to pick source IPs' }, async () => {
  const ip = randomIp();
  const q = `?sha256=${'0'.repeat(64)}`;
  for (let i = 1; i <= 60; i++) {
    const r = await verifyGet(i % 10 === 0 ? '?sha256=bad' : q, ip);
    assert.equal(r.status, i % 10 === 0 ? 400 : 200, `lookup ${i}`);
  }
  for (const query of [q, '?sha256=bad']) {
    const r = await verifyGet(query, ip);
    assert.deepEqual([r.status, r.data.error], [429, 'Too many checks. Try again later.'], query);
    const wait = Number(r.headers['retry-after']);
    assert.ok(Number.isInteger(wait) && wait > 3500 && wait <= 3600, `Retry-After ${r.headers['retry-after']}`);
  }
  assert.equal((await verifyGet(q, randomIp())).status, 200, 'another IP still works');
});

test('verify page and sitemap: /verify renders publicly and is listed in /sitemap.xml', async () => {
  const r = await client()('/verify', { method: 'GET' });
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /text\/html/);
  const sm = (await client()('/sitemap.xml', { method: 'GET' })).data.toString();
  assert.match(sm, /<loc>[^<]*\/verify<\/loc>/);
});

// =====================================================================================================================
// Redirect after signing
// =====================================================================================================================

test('redirect URL: validation, trimming, keep when absent, clear when empty, copy and template keep it, never on the sign page', async () => {
  const a = await signup();
  const R = [person('a'), person('b')];
  const MSG = 'Enter a full web address starting with https://';
  for (const bad of ['javascript:alert(1)', 'JAVASCRIPT:alert(1)', 'data:text/html,hi', 'ftp://example.com/x', 'mailto:a@example.com', 'https://user:pass@example.com/',
    'https://u@example.com/', 'example.com', '//example.com/x', '/relative', 'https://', `https://example.com/${'a'.repeat(482)}`,
    'http://example.com/x', 'HTTP://example.com/x', 'http://intranet.local/done', 42, {}, [], true, { href: 'https://example.com/' }]) {
    const up = await a('/api/documents', { body: await pdf(), headers: { 'Content-Type': 'application/pdf' } });
    const put = await a(`/api/documents/${up.data.id}`, { method: 'PUT', body: { title: 't', recipients: R, fields: sigs(R), redirectUrl: bad } });
    assert.deepEqual(err(put), [400, MSG], JSON.stringify(bad));
  }
  // 500 chars accepted.
  const max = `https://example.com/${'a'.repeat(480)}`;
  assert.equal(max.length, 500);
  const edge = await draft(a, R, { redirectUrl: max });
  assert.equal((await props(a, `/app/documents/${edge.id}/edit`)).doc.redirectUrl, max);
  // Trimmed and normalised (https only; http is refused above).
  const d = await draft(a, R, { redirectUrl: '  https://Example.com/thanks?x=1  ' });
  const stored = async (id) => (await props(a, `/app/documents/${id}/edit`)).doc.redirectUrl;
  assert.equal(await stored(d.id), 'https://example.com/thanks?x=1');
  // A refused value on an existing draft changes nothing.
  const fieldsOf = (x) => x.fields.map((f) => ({ ...f, recipientId: ['a', 'b'][x.recipients.findIndex((r) => r.id === f.recipient_id)] }));
  for (const bad of ['http://example.com/x', 42, {}, [], true]) {
    assert.deepEqual(err(await a(`/api/documents/${d.id}`, { method: 'PUT', body: { title: d.title, recipients: R, fields: fieldsOf(d), redirectUrl: bad } })), [400, MSG], JSON.stringify(bad));
  }
  assert.equal(await stored(d.id), 'https://example.com/thanks?x=1', 'refused PUTs kept the URL');
  // PUT without the key keeps it; copy and template keep it.
  const fields = (x) => x.fields.map((f) => ({ ...f, recipientId: ['a', 'b'][x.recipients.findIndex((r) => r.id === f.recipient_id)] }));
  const keep = await a(`/api/documents/${d.id}`, { method: 'PUT', body: { title: d.title, recipients: R, fields: fields(d) } });
  assert.equal(keep.status, 200);
  assert.equal(await stored(d.id), 'https://example.com/thanks?x=1');
  const copy = (await a(`/api/documents/${d.id}/copy`, { body: {} })).data.id;
  const tpl = (await a(`/api/documents/${d.id}/copy`, { body: { asTemplate: true } })).data.id;
  assert.equal(await stored(copy), 'https://example.com/thanks?x=1');
  assert.equal(await stored(tpl), 'https://example.com/thanks?x=1');
  assert.equal(await stored((await a(`/api/documents/${tpl}/copy`, { body: {} })).data.id), 'https://example.com/thanks?x=1', 'document from template');
  // Empty string, whitespace and null clear it (non-strings are refused 400 above).
  for (const v of ['', '   ', null]) {
    const c = (await a(`/api/documents/${d.id}/copy`, { body: {} })).data.id;
    assert.equal((await a(`/api/documents/${c}`, { method: 'PUT', body: { title: 'x', recipients: [], fields: [], redirectUrl: v } })).status, 200);
    assert.equal(await stored(c), '', `cleared by ${JSON.stringify(v)}`);
  }
  // Sent: the sign page (signing and status states) never carries the URL.
  assert.equal((await a(`/api/documents/${d.id}/send`, { body: {} })).status, 200);
  const p = await props(a, `/app/documents/${d.id}`);
  const tokens = p.recipients.map((y) => y.token); // the PUT above re-created the recipients
  assert.equal(tokens.length, 2);
  for (const t of tokens) assert.ok(!(await pageHtml(client(), `/sign/${t}`)).includes('example.com/thanks'), 'not in sign page HTML');
});

test('redirect URL: submit returns { status, redirectUrl } for middle and final signers, exactly { status } without one', async () => {
  const a = await signup();
  const d = await sent(a, [person('a'), person('b')], { redirectUrl: 'https://example.com/after' });
  const r1 = await submit(d, 0);
  assert.deepEqual([r1.status, r1.data], [200, { status: 'sent', redirectUrl: 'https://example.com/after' }]);
  assert.ok(!(await pageHtml(client(), `/sign/${d.tokens[1]}`)).includes('example.com/after'));
  const r2 = await submit(d, 1);
  assert.deepEqual([r2.status, r2.data], [200, { status: 'completed', redirectUrl: 'https://example.com/after' }]);
  assert.equal((await submit(d, 1)).status, 409, 'duplicate submit');
  const plain = await sent(a, [person('a')]);
  const r3 = await submit(plain, 0);
  assert.deepEqual([r3.status, r3.data], [200, { status: 'completed' }]);
  // Self-sign with a redirect also returns it.
  const self = await draft(a, [person('a', { name: a.userName, email: a.email })], { redirectUrl: 'https://example.com/self' });
  const s = await a(`/api/documents/${self.id}/send`, { body: { selfSign: true } });
  const token = s.data.signUrl.split('/').pop();
  const r4 = await a(`/api/sign/${token}`, { body: { values: { [self.fields[0].id]: PNG } } });
  assert.deepEqual([r4.status, r4.data], [200, { status: 'completed', redirectUrl: 'https://example.com/self' }]);
});

test('redirect URL with an email code: unverified submit is 403 and does not reveal the URL', { skip: NEEDS_DB }, async () => {
  const a = await signup();
  const d = SINK_PORT ? await sent(a, [person('o')], { requireOtp: true, redirectUrl: 'https://example.com/secret-after' })
    : await sent(a, [person('o')], { redirectUrl: 'https://example.com/secret-after' });
  if (!SINK_PORT) db().prepare('UPDATE documents SET require_otp = 1 WHERE id = ?').run(d.id);
  const anon = client();
  const r = await submit(d, 0, anon);
  assert.equal(r.status, 403);
  assert.ok(!JSON.stringify(r.data).includes('secret-after'));
  assert.ok(!(await pageHtml(anon, `/sign/${d.tokens[0]}`)).includes('secret-after'));
  inject(d.recipients[0].id, '112233');
  assert.equal((await anon(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'verify', code: '112233' } })).status, 200);
  assert.deepEqual((await submit(d, 0, anon)).data, { status: 'completed', redirectUrl: 'https://example.com/secret-after' });
});

// =====================================================================================================================
// Email templates
// =====================================================================================================================

const DEFAULTS = {
  invite: { subject: '{{sender_name}} sent you "{{document_title}}" to sign', body: '{{document_title}}{{message_block}}\n\nNo account needed. Review the document and sign in a couple of minutes.', custom: false },
  completed: { subject: 'Completed: {{document_title}}', body: '{{document_title}} is complete. Download the signed copy with its certificate of completion.', custom: false },
};
const VARIABLES = ['sender_name', 'sender_email', 'receiver_name', 'document_title', 'message', 'message_block', 'expires_on'];

test('email templates: GET defaults, PUT (CR/LF, limits, validation), per user, DELETE resets; 401; 403', async () => {
  const a = await signup(), b = await signup();
  const get = async (c) => { const r = await c('/api/email-templates', { method: 'GET' }); assert.equal(r.status, 200); return r.data; };
  assert.deepEqual(await get(a), { ...DEFAULTS, variables: VARIABLES });
  const put = (body, c = a) => c('/api/email-templates', { method: 'PUT', body });
  assert.deepEqual((await put({ kind: 'invite', subject: ' Hi\r\n{{receiver_name}}\n ', body: '\r\nLine 1\r\nLine 2\rLine 3 {{message}}\n' })).data, { ok: true });
  const g = await get(a);
  assert.deepEqual(g.invite, { subject: 'Hi {{receiver_name}}', body: 'Line 1\nLine 2\nLine 3 {{message}}', custom: true });
  assert.deepEqual(g.completed, DEFAULTS.completed, 'other kind untouched');
  assert.deepEqual((await get(b)).invite, DEFAULTS.invite, 'other user keeps defaults');
  // Boundaries: subject 200 / body 4000 accepted, one more refused.
  assert.equal((await put({ kind: 'completed', subject: 's'.repeat(200), body: 'b'.repeat(4000) })).status, 200);
  assert.deepEqual((await get(a)).completed, { subject: 's'.repeat(200), body: 'b'.repeat(4000), custom: true });
  assert.deepEqual(err(await put({ kind: 'completed', subject: 's'.repeat(201), body: 'b' })), [400, 'Subject must be at most 200 characters']);
  assert.deepEqual(err(await put({ kind: 'completed', subject: 's', body: 'b'.repeat(4001) })), [400, 'Message must be at most 4000 characters']);
  assert.deepEqual(err(await put({ kind: 'completed', subject: '', body: 'b' })), [400, 'Enter a subject']);
  assert.deepEqual(err(await put({ kind: 'completed', subject: ' \r\n ', body: 'b' })), [400, 'Enter a subject']);
  assert.deepEqual(err(await put({ kind: 'completed', subject: 's', body: '  \n ' })), [400, 'Enter a message']);
  assert.deepEqual(err(await put({ kind: 'completed', subject: 's', body: 7 })), [400, 'Enter a message']);
  for (const kind of ['reminder', '', undefined, 'INVITE']) assert.deepEqual(err(await put({ kind, subject: 's', body: 'b' })), [400, 'Choose invite or completed'], `kind ${kind}`);
  assert.deepEqual((await get(a)).completed.subject, 's'.repeat(200), 'refused PUTs changed nothing');
  // DELETE resets one kind.
  assert.deepEqual((await a('/api/email-templates?kind=completed', { method: 'DELETE' })).data, { ok: true });
  assert.deepEqual((await get(a)).completed, DEFAULTS.completed);
  assert.deepEqual((await get(a)).invite.custom, true);
  assert.deepEqual(err(await a('/api/email-templates?kind=nope', { method: 'DELETE' })), [400, 'Choose invite or completed']);
  assert.equal((await a('/api/email-templates?kind=invite', { method: 'DELETE' })).status, 200);
  assert.deepEqual(await get(a), { ...DEFAULTS, variables: VARIABLES });
  // Anonymous and cross-origin.
  const anon = client();
  assert.equal((await anon('/api/email-templates', { method: 'GET' })).status, 401);
  assert.equal((await put({ kind: 'invite', subject: 's', body: 'b' }, anon)).status, 401);
  assert.equal((await a('/api/email-templates', { method: 'PUT', body: { kind: 'invite', subject: 's', body: 'b' }, headers: { Origin: 'http://evil.test' } })).status, 403);
  assert.equal((await a('/api/email-templates?kind=invite', { method: 'DELETE', headers: { Origin: 'http://evil.test' } })).status, 403);
  assert.equal((await get(a)).invite.custom, false);
});

test('email templates in mail: invite, manual reminder ("Reminder: "), completed for recipients; owner email and action links unchanged; HTML escaped', { skip: NEEDS_SMTP }, async () => {
  const a = await signup(`tpl-${Date.now()}-${rnd()}@example.com`, 'Tess Owner');
  assert.equal((await a('/api/email-templates', { method: 'PUT', body: { kind: 'invite', subject: 'Sign {{document_title}} for {{sender_name}} {{bogus}}',
    body: 'Hello {{receiver_name}},<b>bold</b> from {{sender_email}}.{{message_block}}\nMsg={{message}} Exp={{expires_on}} {{unknown}}' } })).status, 200);
  assert.equal((await a('/api/email-templates', { method: 'PUT', body: { kind: 'completed', subject: 'Done: {{document_title}}', body: 'All done, {{receiver_name}}.' } })).status, 200);
  const ra = person('a', { name: 'Ada Recipient' }), rb = person('b', { name: 'Ben Recipient' });
  const cc = { id: 'c', name: 'Cee Copy', email: `cc-${rnd()}@example.com`, role: 'cc' };
  const d = await sent(a, [ra, rb, cc], { message: 'Please review', expireDays: 30 });
  const inv = await mailTo(ra.email, (m) => m.subject.startsWith('Sign '), 'custom invite');
  assert.equal(inv.subject, `Sign ${d.title} for Tess Owner {{bogus}}`);
  const text = textPart(inv);
  assert.match(text, new RegExp(`Hello Ada Recipient,<b>bold</b> from ${a.email.replace(/[.]/g, '\\.')}\\.\\n\\n"Please review"\\nMsg=Please review Exp=[A-Z][a-z]+ \\d{1,2}, \\d{4} \\{\\{unknown\\}\\}`), text);
  assert.ok(text.includes(`Review and sign: ${APP_URL}/sign/${d.tokens[0]}`), 'system action link always added');
  assert.ok(htmlPart(inv).includes('&#60;b&#62;bold&#60;/b&#62;') && !htmlPart(inv).includes('<b>bold'), 'template HTML is escaped');
  assert.ok(htmlPart(inv).includes(`href="${APP_URL}/sign/${d.tokens[0]}"`));
  await mailTo(rb.email, (m) => m.subject.startsWith('Sign '), 'invite b (parallel)');
  // Manual reminder.
  const before = mails.length;
  assert.equal((await a(`/api/documents/${d.id}/remind`, { body: { recipientId: d.recipients[0].id } })).status, 200);
  const rem = await mailTo(ra.email, (m) => mails.indexOf(m) >= before && m.subject.startsWith('Reminder: '), 'reminder');
  assert.equal(rem.subject, `Reminder: Sign ${d.title} for Tess Owner {{bogus}}`);
  assert.ok(textPart(rem).includes('Hello Ada Recipient') && textPart(rem).includes(`Review and sign: ${APP_URL}/sign/`));
  // Complete: recipients (incl. cc) get the custom completed template; the owner keeps "Completed: <title>".
  assert.equal((await submit(d, 0)).status, 200);
  assert.equal((await submit(d, 1)).status, 200);
  for (const [r, name] of [[ra, 'Ada Recipient'], [rb, 'Ben Recipient'], [cc, 'Cee Copy']]) {
    const m = await mailTo(r.email, (x) => x.subject === `Done: ${d.title}`, `completed to ${name}`);
    assert.ok(textPart(m).includes(`All done, ${name}.`) && textPart(m).includes(`Download signed PDF: ${APP_URL}/sign/`), textPart(m));
  }
  const own = await mailTo(a.email, (m) => m.subject.startsWith('Completed'), 'owner completed');
  assert.equal(own.subject, `Completed: ${d.title}`);
  assert.ok(textPart(own).includes(`${d.title} is complete.`) && textPart(own).includes(`Open document: ${APP_URL}/app/documents/${d.id}`));
});

test('email templates in mail: the hourly reminder job uses "Reminder: " + the custom invite subject', { skip: (NEEDS_SMTP || typeof (await import('node:module')).registerHooks !== 'function') && 'needs SMTP sink, DATA_DIR and module.registerHooks' }, async () => {
  const a = await signup(`job-${Date.now()}-${rnd()}@example.com`, 'Job Owner');
  assert.equal((await a('/api/email-templates', { method: 'PUT', body: { kind: 'invite', subject: 'Job {{document_title}}', body: 'Hi {{receiver_name}}' } })).status, 200);
  const r = person('a', { name: 'Job Signer' });
  const d = await sent(a, [r], { reminderDays: 1 });
  await mailTo(r.email, (m) => m.subject === `Job ${d.title}`, 'invite');
  db().prepare('UPDATE recipients SET last_notified_at = ? WHERE id = ?').run(new Date(Date.now() - 2 * 864e5).toISOString(), d.recipients[0].id);
  const code = `
    import { registerHooks } from 'node:module';
    registerHooks({ resolve(s, c, next) {
      try { return next(s, c); } catch (e) { if (/^\\.\\.?\\//.test(s) && !/\\.[cm]?js$/.test(s)) return next(s + '.js', c); throw e; }
    } });
    const { sendDueReminders } = await import(${JSON.stringify(pathToFileURL(path.join(ROOT, 'lib', 'documents.js')).href)});
    await sendDueReminders();
    console.log('DONE');`;
  const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, DATA_DIR: DATA, ENCRYPTION_KEY: keyText(), NODE_NO_WARNINGS: '1',
    SMTP_HOST: '127.0.0.1', SMTP_PORT: String(SINK_PORT), APP_URL: APP_URL || BASE };
  // Async: the sink runs in this process, so the child must not block the event loop.
  const { execFile } = await import('node:child_process');
  const out = await new Promise((res, rej) => execFile(process.execPath, ['--input-type=module', '-e', code], { cwd: ROOT, env, encoding: 'utf8', timeout: 60_000 }, (e, so, se) => (e ? rej(new Error(se || e.message)) : res(so))));
  assert.match(out, /DONE/);
  const rem = await mailTo(r.email, (m) => m.subject === `Reminder: Job ${d.title}`, 'job reminder');
  assert.ok(textPart(rem).includes('Hi Job Signer'));
});

test('email templates in mail: defaults (and after reset) are the previous hard-coded texts', { skip: NEEDS_SMTP }, async () => {
  const a = await signup(`def-${Date.now()}-${rnd()}@example.com`, 'Dee Owner');
  await a('/api/email-templates', { method: 'PUT', body: { kind: 'invite', subject: 'Custom', body: 'Custom' } });
  assert.equal((await a('/api/email-templates?kind=invite', { method: 'DELETE' })).status, 200);
  const r1 = person('a', { name: 'Def One' });
  const d = await sent(a, [r1], { message: 'Please' });
  const inv = await mailTo(r1.email, () => true, 'default invite');
  assert.equal(inv.subject, `Dee Owner sent you "${d.title}" to sign`);
  assert.ok(textPart(inv).includes(`${d.title}\n\n"Please"\n\nNo account needed. Review the document and sign in a couple of minutes.\n\nReview and sign: ${APP_URL}/sign/`), textPart(inv));
  const r2 = person('a', { name: 'Def Two' });
  const d2 = await sent(a, [r2]);
  const inv2 = await mailTo(r2.email, () => true, 'default invite without message');
  assert.ok(textPart(inv2).includes(`${d2.title}\n\nNo account needed.`), 'no message block');
  assert.equal((await submit(d2, 0)).status, 200);
  const done = await mailTo(r2.email, (m) => m.subject.startsWith('Completed'), 'default completed');
  assert.equal(done.subject, `Completed: ${d2.title}`);
  assert.ok(textPart(done).includes(`${d2.title} is complete. Download the signed copy with its certificate of completion.\n\nDownload signed PDF: ${APP_URL}/sign/`));
});

// =====================================================================================================================
// Certificate verify line
// =====================================================================================================================

test(`certificate: "Check this copy at <APP_URL>/verify" ${APP_URL ? 'is present' : 'is absent (no APP_URL)'}`, async () => {
  const a = await signup();
  const d = await sent(a, [person('a')]);
  assert.equal((await submit(d, 0)).status, 200);
  const signed = await a(`/api/documents/${d.id}/file?kind=signed`, { method: 'GET' });
  assert.equal(signed.status, 200);
  const text = pdfText(signed.data);
  assert.ok(hasText(text, 'Certificate of completion'),'certificate text is searchable');
  if (APP_URL) assert.ok(hasText(text, `Check this copy at ${APP_URL}/verify`), 'verify line with APP_URL');
  else assert.ok(!hasText(text, 'Check this copy at'), 'no verify line without APP_URL');
});

// =====================================================================================================================
// Unit self-check (no server): CSV parser, import, renderEmail, signature storage
// =====================================================================================================================

test('scripts/tier2-selfcheck.mjs passes', () => {
  const env = Object.fromEntries(Object.entries({ PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, TEMP: process.env.TEMP, TMP: process.env.TMP, TMPDIR: process.env.TMPDIR, NODE_NO_WARNINGS: '1' })
    .filter(([, v]) => v !== undefined));
  const out = execFileSync(process.execPath, [path.join(ROOT, 'scripts', 'tier2-selfcheck.mjs')], { cwd: ROOT, env, encoding: 'utf8', timeout: 60_000 });
  assert.match(out, /tier2 self-check passed/);
});
