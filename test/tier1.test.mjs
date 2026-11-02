// Tier 1 over HTTP: digital seal, new field types, sign yourself, per-document expiry, signer email codes (OTP).
// Needs a running FRESH server (ALLOW_SIGNUP=true, SIGNUP_MAX_PER_HOUR=1000, explicit ENCRYPTION_KEY):
//   BASE_URL=http://localhost:3127 DATA_DIR=<server's DATA_DIR> ENCRYPTION_KEY=<same as server> node --test test/tier1.test.mjs
// DATA_DIR (+ the key: ENCRYPTION_KEY or DATA_DIR/encryption.key) enables DB checks, injected OTP codes and the hourly
// expiry job (run in a child process on the same DATA_DIR; SQLite WAL + busy_timeout make that safe beside the server).
// Mail: the server is either
//   (a) without working email (no SMTP_HOST, or SMTP_HOST without APP_URL): leave QA_SMTP_SINK_PORT unset; the
//       "no SMTP" refusals are tested and the SMTP tests skip; or
//   (b) SMTP_HOST=127.0.0.1 SMTP_PORT=<P> APP_URL=<BASE_URL>, with QA_SMTP_SINK_PORT=<P> in the test env: this file runs
//       an in-process SMTP sink on P and tests the real invitation, code, cooldown and expiry emails.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';
import forge from 'node-forge';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const DATA = process.env.DATA_DIR;
const SINK_PORT = Number(process.env.QA_SMTP_SINK_PORT) || 0;
const ROOT = path.resolve(import.meta.dirname, '..');
const NEEDS_DB = !DATA && 'needs DATA_DIR pointing at the server data folder';
const NEEDS_SMTP = (!DATA || !SINK_PORT) && 'needs DATA_DIR, QA_SMTP_SINK_PORT and a server with SMTP_HOST=127.0.0.1 SMTP_PORT=<same> APP_URL=<BASE_URL>';
const NEEDS_NO_MAIL = !!SINK_PORT && 'server has email set up (QA_SMTP_SINK_PORT); this checks the refusal without email';
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const PASSWORD = 'correct horse battery';
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const rnd = () => crypto.randomBytes(5).toString('hex');
const DATE_MSG = /^This document expired on [A-Z][a-z]+ \d{1,2}, \d{4}\.$/;

let _db;
const db = () => {
  if (!_db) { _db = new DatabaseSync(path.join(DATA, 'countersign.db')); _db.exec('PRAGMA busy_timeout = 5000'); }
  return _db;
};
const keyText = () => (process.env.ENCRYPTION_KEY || fs.readFileSync(path.join(DATA, 'encryption.key'), 'utf8')).trim();
const key = () => Buffer.from(keyText(), /^[0-9a-f]{64}$/i.test(keyText()) ? 'hex' : 'base64');
// Independent copy of lib/crypto.js keyedHash: HMAC-SHA256 under an HKDF subkey 'countersign-' + info.
const keyedHash = (info, data) => crypto.createHmac('sha256', Buffer.from(crypto.hkdfSync('sha256', key(), Buffer.alloc(0), 'countersign-' + info, 32))).update(data).digest('hex');
// "CSE1" | IV 12 | tag 16 | ciphertext (AES-256-GCM, AAD).
function dec(buf, aad) {
  assert.equal(buf.subarray(0, 4).toString(), 'CSE1');
  const d = crypto.createDecipheriv('aes-256-gcm', key(), buf.subarray(4, 16));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(buf.subarray(16, 32));
  return Buffer.concat([d.update(buf.subarray(32)), d.final()]);
}
// All PDF content streams inflated, lowercased; pdf-lib writes text as hex strings, so search for hex(s).
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
const has = (text, s) => text.includes(hex(s));

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
          const qp = (s) => s.replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
          // Headers: unfold, then decode RFC 2047 Q/B words. Body: undo quoted-printable so codes and links can be matched.
          const head = msg.slice(0, split).replace(/\r\n[ \t]+/g, ' ').replace(/\?=\s+=\?/g, '?==?')
            .replace(/=\?UTF-8\?([QB])\?([^?]*)\?=/gi, (_, enc, t) => (enc.toUpperCase() === 'B' ? Buffer.from(t, 'base64').toString('latin1') : qp(t.replace(/_/g, ' '))));
          const raw = head + '\r\n\r\n' + qp(msg.slice(split + 4).replace(/=\r\n/g, ''));
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
async function mailTo(addr, subject, timeout = 5000) {
  for (let t = 0; t < timeout; t += 100) {
    const m = mails.find((x) => x.to.includes(addr.toLowerCase()) && x.subject.includes(subject));
    if (m) return m;
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.fail(`no email to ${addr} with subject containing "${subject}"; got: ${mails.map((x) => `${x.to} ${x.subject}`).join(' | ')}`);
}

// ---------- HTTP helpers ----------
// Cookie jar client; extra cookies can be forced with headers.cookie.
function client() {
  const cookies = {};
  const call = async (p, { method = 'POST', body, headers = {} } = {}) => {
    const raw = body instanceof Uint8Array;
    const cookie = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(BASE + p, {
      method, redirect: 'manual',
      headers: { ...(raw ? {} : { 'Content-Type': 'application/json' }), ...(cookie && { cookie }), ...headers },
      body: body == null ? undefined : raw ? body : JSON.stringify(body),
    });
    const setCookie = res.headers.getSetCookie();
    for (const c of setCookie) { const [kv] = c.split(';'); const i = kv.indexOf('='); cookies[kv.slice(0, i)] = kv.slice(i + 1); }
    const type = res.headers.get('content-type') || '';
    return { status: res.status, headers: res.headers, setCookie, data: type.includes('json') ? await res.json() : Buffer.from(await res.arrayBuffer()) };
  };
  call.cookies = cookies;
  return call;
}
const props = async (call, p) => {
  const html = (await call(p, { method: 'GET' })).data.toString();
  return JSON.parse(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s.exec(html)[1]).props.pageProps;
};

async function signup(email = `t1-${Date.now()}-${rnd()}@example.com`) {
  const call = client();
  const r = await call('/api/auth/signup', { body: { name: 'Tier1 Owner', email, password: PASSWORD } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return Object.assign(call, { email: email.toLowerCase() });
}
const pdf = async () => { const d = await PDFDocument.create(); d.addPage([612, 792]); d.addPage([612, 792]); return d.save(); };
const field = (recipientId, type, extra = {}) => ({ recipientId, type, page: 0, x: 0.1, y: 0.1, w: 0.3, h: 0.08, ...extra });
const sig = (rid) => [field(rid, 'signature')];
const person = (id, extra = {}) => ({ id, name: `Signer ${id}`, email: `${id}-${rnd()}@example.com`, role: 'signer', ...extra });

async function draft(call, recipients, fields, extra = {}, bytes) {
  const up = await call('/api/documents', { body: bytes ?? await pdf(), headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'Tier1.pdf' } });
  assert.equal(up.status, 201, JSON.stringify(up.data));
  const title = `Tier1 ${rnd()}`;
  const put = await call(`/api/documents/${up.data.id}`, { method: 'PUT', body: { title, recipients, fields, ...extra } });
  assert.equal(put.status, 200, JSON.stringify(put.data));
  return { id: up.data.id, title, ...put.data };
}
async function sent(call, recipients, fields, extra = {}, bytes) {
  const d = await draft(call, recipients, fields, extra, bytes);
  const r = await call(`/api/documents/${d.id}/send`, { body: {} });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  const p = await props(call, `/app/documents/${d.id}`);
  return { ...d, doc: p.doc, tokens: d.recipients.map((x) => p.recipients.find((y) => y.id === x.id).token) };
}
// A sent document that requires an email code. Without email the server refuses to send one, so it is sent plainly and
// require_otp is set in the DB (the state a server with SMTP would have produced).
async function otpDoc(call, recipients, fields, extra = {}) {
  if (SINK_PORT) return sent(call, recipients, fields, { ...extra, requireOtp: true });
  const d = await sent(call, recipients, fields, extra);
  db().prepare('UPDATE documents SET require_otp = 1 WHERE id = ?').run(d.id);
  return d;
}
// Store a code as POST /otp {action:'send'} would.
const inject = (rid, code, exp = Date.now() + 600_000) => db().prepare('UPDATE recipients SET otp_hash = ?, otp_expires_at = ?, otp_attempts = 0 WHERE id = ?')
  .run(keyedHash('otp', `${rid}:${code}`), new Date(exp).toISOString(), rid);
const err = (r) => [r.status, r.data?.error];
const eventsOf = (id) => db().prepare('SELECT action, detail FROM events WHERE document_id = ? ORDER BY created_at, id').all(id);

// ---------- (5) New field types ----------

test('new field types: options are trimmed, invalid choice fields are dropped, options round-trip through PUT, edit page and copy', async () => {
  const call = await signup();
  const d = await draft(call, [person('a')], [
    field('a', 'signature'), field('a', 'company'), field('a', 'jobtitle'), field('a', 'number'), field('a', 'stamp'),
    field('a', 'dropdown', { options: [' Red ', 'Blue'] }), field('a', 'radio', { options: ['Yes', 'No', 'Maybe'] }),
    field('a', 'dropdown', { options: ['dup', 'dup'] }), field('a', 'radio', { options: [] }), field('a', 'dropdown'),
    field('a', 'radio', { options: ['x'.repeat(61)] }), field('a', 'dropdown', { options: Array.from({ length: 21 }, (_, i) => `o${i}`) }),
    field('a', 'dropdown', { options: ['ok', '   '] }), field('a', 'radio', { options: ['ok', 7] }), field('a', 'nonsense'),
  ]);
  assert.deepEqual(d.fields.map((f) => f.type).sort(), ['company', 'dropdown', 'jobtitle', 'number', 'radio', 'signature', 'stamp']);
  const opts = (fields) => Object.fromEntries(fields.map((f) => [f.type, f.options]));
  assert.deepEqual(opts(d.fields), { signature: null, company: null, jobtitle: null, number: null, stamp: null, dropdown: ['Red', 'Blue'], radio: ['Yes', 'No', 'Maybe'] });
  // Boundaries that must be kept: 20 options, 60 chars.
  const edge = await draft(call, [person('a')], [field('a', 'signature'), field('a', 'dropdown', { options: Array.from({ length: 20 }, (_, i) => `o${i}`) }), field('a', 'radio', { options: ['y'.repeat(60)] })]);
  assert.equal(edge.fields.find((f) => f.type === 'dropdown').options.length, 20);
  assert.deepEqual(edge.fields.find((f) => f.type === 'radio').options, ['y'.repeat(60)]);
  // Options on a non-choice field are ignored.
  const extra = await draft(call, [person('a')], [field('a', 'signature', { options: ['a'] }), field('a', 'text', { options: ['a'] })]);
  assert.ok(extra.fields.every((f) => f.options === null));

  // PUT again with what the server returned: unchanged.
  const again = await call(`/api/documents/${d.id}`, { method: 'PUT', body: { title: d.title, recipients: [{ ...d.recipients[0], id: 'a' }], fields: d.fields.map((f) => ({ ...f, recipientId: 'a' })) } });
  assert.equal(again.status, 200);
  assert.deepEqual(opts(again.data.fields), opts(d.fields));
  const editor = await props(call, `/app/documents/${d.id}/edit`);
  assert.deepEqual(opts(editor.initialFields), opts(d.fields), 'editor receives options');
  const copy = await call(`/api/documents/${d.id}/copy`, { body: {} });
  assert.equal(copy.status, 201);
  assert.deepEqual(opts((await props(call, `/app/documents/${copy.data.id}/edit`)).initialFields), opts(d.fields), 'copy keeps options');
  const tpl = await call(`/api/documents/${d.id}/copy`, { body: { asTemplate: true } });
  assert.deepEqual(opts((await props(call, `/app/documents/${tpl.data.id}/edit`)).initialFields), opts(d.fields), 'template keeps options');
});

async function allTypesSent(call) {
  const d = await sent(call, [person('a')], [
    field('a', 'signature'), field('a', 'company', { y: 0.2 }), field('a', 'jobtitle', { y: 0.3 }), field('a', 'number', { y: 0.4 }),
    field('a', 'dropdown', { y: 0.5, options: ['Red', 'Blue'] }), field('a', 'radio', { y: 0.6, h: 0.12, options: ['Yes', 'No', 'Maybe'] }), field('a', 'stamp', { y: 0.75 }),
  ]);
  const id = Object.fromEntries(d.fields.map((f) => [f.type, f.id]));
  const values = (o = {}) => ({ [id.signature]: PNG, [id.company]: 'Acme Ltd', [id.jobtitle]: 'Finance Lead', [id.number]: '-12,50', [id.dropdown]: 'Blue', [id.radio]: 'No', [id.stamp]: PNG, ...o });
  return { ...d, id: d.id, ids: id, values };
}

test('new field types: the signing page gets options; submit rejects bad values with 400 and changes nothing', async () => {
  const call = await signup();
  const d = await allTypesSent(call);
  const signer = client();
  const page = await props(signer, `/sign/${d.tokens[0]}`);
  assert.deepEqual(page.fields.find((f) => f.type === 'radio').options, ['Yes', 'No', 'Maybe']);
  const submit = (o) => signer(`/api/sign/${d.tokens[0]}`, { body: { values: d.values(o) } });
  for (const n of ['1e5', 'abc', '12.', '.5', '1'.repeat(16), '1.1234567', '1,2,3', '+1', '1 000']) {
    assert.deepEqual(err(await submit({ [d.ids.number]: n })), [400, 'Enter a number'], `number ${JSON.stringify(n)}`);
  }
  for (const v of ['Green', 'blue', 'Red,Blue']) assert.deepEqual(err(await submit({ [d.ids.dropdown]: v })), [400, 'Choose one of the options'], `dropdown ${v}`);
  for (const v of ['yes', 'Yes,No', 'Perhaps']) assert.deepEqual(err(await submit({ [d.ids.radio]: v })), [400, 'Choose one of the options'], `radio ${v}`);
  assert.deepEqual(err(await submit({ [d.ids.stamp]: 'data:image/png;base64,AAAA' })), [400, 'Invalid signature image']);
  assert.deepEqual(err(await submit({ [d.ids.stamp]: 'data:image/jpeg;base64,/9j/4AAQ' })), [400, 'Invalid signature image']);
  assert.deepEqual(err(await submit({ [d.ids.stamp]: 'data:image/png;base64,' + 'A'.repeat(400_000) })), [400, 'Invalid signature image'], 'stamp over 400,000 chars');
  for (const t of ['company', 'jobtitle', 'number', 'dropdown', 'radio', 'stamp']) {
    assert.deepEqual(err(await submit({ [d.ids[t]]: '' })), [400, 'Fill in every required field'], `${t} is required by default`);
  }
  assert.equal((await props(call, `/app/documents/${d.id}`)).doc.status, 'sent', 'rejections change nothing');
  for (const n of ['0', '-12,50', '3.14', '123456789012345', '1.123456']) {
    assert.ok(/^-?\d{1,15}([.,]\d{1,6})?$/.test(n), n); // the documented format, so the accepted list stays honest
  }
});

test('new field types: a full submission completes, values are drawn on the PDF, duplicate submission is 409', async () => {
  const call = await signup();
  const d = await allTypesSent(call);
  const signer = client();
  let r = await signer(`/api/sign/${d.tokens[0]}`, { body: { values: d.values({ [d.ids.company]: '  Acme Ltd  ' }) } });
  assert.deepEqual([r.status, r.data.status], [200, 'completed'], JSON.stringify(r.data));
  r = await signer(`/api/sign/${d.tokens[0]}`, { body: { values: d.values() } });
  assert.equal(r.status, 409);
  const signed = (await call(`/api/documents/${d.id}/file?kind=signed`, { method: 'GET' })).data;
  const text = pdfText(signed);
  for (const s of ['Acme Ltd', 'Finance Lead', '-12,50', 'Blue', 'Yes', 'No', 'Maybe']) assert.ok(has(text, s), `PDF shows ${s}`);
  if (DATA) {
    const stored = db().prepare("SELECT type, value FROM fields WHERE document_id = ? AND type IN ('company','number','dropdown','radio')").all(d.id);
    assert.ok(stored.every((f) => f.value.startsWith('enc:v1:')), 'new field values are encrypted at rest');
  }
});

// ---------- (1) Digital seal ----------

// Parses the seal: returns the byte range, the covered bytes, the PKCS#7 message and its messageDigest (hex).
// many: the input PDF already carried a signature; use the one whose range ends at EOF (the Countersign seal).
function readSeal(bytes, { many = false } = {}) {
  const s = bytes.toString('latin1');
  const all = [...s.matchAll(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g)].map((m) => m.slice(1).map(Number));
  if (!many) assert.equal(all.length, 1, 'exactly one signature');
  const br = all.find((x) => x[2] + x[3] === bytes.length) ?? all[0];
  const covered = Buffer.concat([bytes.subarray(br[0], br[0] + br[1]), bytes.subarray(br[2], br[2] + br[3])]);
  const gap = s.slice(br[0] + br[1], br[2]);
  assert.match(gap, /^<[0-9a-fA-F]+>$/, 'the only uncovered bytes are the /Contents hex string');
  // The placeholder is zero-padded after the DER; parse one DER value and ignore the padding.
  const p7 = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(forge.util.hexToBytes(gap.slice(1, -1)), { parseAllBytes: false }));
  const attrs = p7.rawCapture.authenticatedAttributes;
  const md = attrs.map((a) => (forge.asn1.derToOid(a.value[0].value) === forge.pki.oids.messageDigest ? a.value[1].value[0].value : null)).find(Boolean);
  return { br, covered, p7, attrs, digest: Buffer.from(md, 'binary').toString('hex') };
}
const certDerSha = (cert) => sha(Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary'));

test('seal: /ByteRange covers the whole file except /Contents, PKCS#7 parses and verifies, signed_sha256 = download hash', async () => {
  const call = await signup();
  const d = await allTypesSent(call);
  assert.equal((await client()(`/api/sign/${d.tokens[0]}`, { body: { values: d.values() } })).data.status, 'completed');
  const viaSigner = (await client()(`/api/sign/${d.tokens[0]}/file?download=1`, { method: 'GET' }));
  assert.equal(viaSigner.status, 200);
  const bytes = viaSigner.data;
  const viaOwner = (await call(`/api/documents/${d.id}/file?kind=signed`, { method: 'GET' })).data;
  assert.ok(bytes.equals(viaOwner), 'owner and signer download the same bytes');

  const { br, covered, p7, attrs, digest } = readSeal(bytes);
  assert.equal(br[0], 0, 'range starts at byte 0');
  assert.equal(br[2] + br[3], bytes.length, 'range ends at EOF');
  assert.equal(covered.length + (br[2] - br[1]), bytes.length);
  assert.equal(digest, sha(covered), 'messageDigest = SHA-256 of the covered bytes');
  const cert = p7.certificates[0];
  assert.ok(cert, 'certificate embedded');
  const signedAttrs = forge.asn1.toDer(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, attrs)).getBytes();
  assert.ok(cert.publicKey.verify(forge.md.sha256.create().update(signedAttrs).digest().bytes(), p7.rawCapture.signature), 'RSA signature over signed attributes verifies');
  assert.match(cert.subject.getField('CN').value, /^Countersign seal \(.+\)$/);
  assert.ok(bytes.toString('latin1').includes('Sealed by Countersign at completion'), 'reason');

  // The verifier is not vacuous: one changed covered byte breaks the digest.
  const tampered = Buffer.from(bytes);
  const at = Math.floor(br[1] / 2);
  tampered[at] ^= 0x01;
  assert.notEqual(readSeal(tampered).digest, sha(Buffer.concat([tampered.subarray(0, br[1]), tampered.subarray(br[2])])), 'tampering is detectable');

  const text = pdfText(bytes);
  assert.ok(has(text, 'Digital seal'), 'certificate page has the seal block');
  assert.ok(has(text, certDerSha(cert)), 'certificate page prints the SHA-256 fingerprint of the embedded certificate');
  assert.ok(has(text, 'Self-signed certificate generated by this server'));
  for (const claim of ['legally binding', 'eIDAS', 'ESIGN', 'UETA', 'compliant']) assert.ok(!text.includes(hex(claim.toLowerCase())) && !has(text, claim), `no "${claim}" claim`);
  assert.ok((await PDFDocument.load(bytes)).getPageCount() >= 3, 'certificate page appended');

  if (DATA) {
    const row = db().prepare('SELECT original_sha256, signed_sha256 FROM documents WHERE id = ?').get(d.id);
    assert.equal(row.signed_sha256, sha(bytes), 'signed_sha256 is over the final sealed bytes');
    assert.ok(eventsOf(d.id).find((e) => e.action === 'Completed').detail.includes(sha(bytes)));
    const orig = (await call(`/api/documents/${d.id}/file`, { method: 'GET' })).data;
    assert.equal(sha(orig), row.original_sha256, 'original unchanged');
  }
});

test('seal key: DATA_DIR/signing.p12 is encrypted at rest and is the certificate in every seal', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const certs = [];
  for (let i = 0; i < 2; i++) {
    const d = await sent(call, [person('a')], sig('a'));
    assert.equal((await client()(`/api/sign/${d.tokens[0]}`, { body: { values: { [d.fields[0].id]: PNG } } })).data.status, 'completed');
    certs.push(readSeal((await call(`/api/documents/${d.id}/file?kind=signed`, { method: 'GET' })).data).p7.certificates[0]);
  }
  assert.equal(certDerSha(certs[0]), certDerSha(certs[1]), 'one seal certificate per server');
  const file = fs.readFileSync(path.join(DATA, 'signing.p12'));
  assert.equal(file.subarray(0, 4).toString(), 'CSE1', 'not stored as a plaintext PKCS#12');
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(dec(file, 'signing-p12').toString('binary')), '');
  const stored = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag][0].cert;
  assert.equal(certDerSha(stored), certDerSha(certs[0]), 'stored key is the one used to seal');
  const days = (stored.validity.notAfter - stored.validity.notBefore) / 864e5;
  assert.ok(days > 3650 - 2 && days < 3660, `about 10 years validity (${days})`);
  assert.equal(stored.publicKey.n.bitLength(), 2048);
});

// ---------- (3) Sign yourself ----------

test('sign yourself: owner as the only signer gets a signUrl, no code, no invitation, and can complete', async () => {
  const email = `Self-${Date.now()}-${rnd()}@Example.COM`;
  const call = await signup(email);
  // Different case than the signup email; requireOtp is ignored for self-sign.
  const d = await draft(call, [{ id: 'm', name: 'Me', email: email.toUpperCase(), role: 'signer' }], [...sig('m'), field('m', 'company', { y: 0.3 })], { requireOtp: true });
  const r = await call(`/api/documents/${d.id}/send`, { body: { selfSign: true } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.deepEqual(Object.keys(r.data).sort(), ['ok', 'signUrl']);
  assert.match(r.data.signUrl, /^\/sign\/[\w-]+$/);
  const p = await props(call, `/app/documents/${d.id}`);
  assert.equal(p.doc.status, 'sent');
  assert.equal(p.doc.require_otp, 0, 'self-sign stores require_otp 0');
  assert.equal(`/sign/${p.recipients[0].token}`, r.data.signUrl, 'signUrl is the recipient link');
  assert.ok(p.events.some((e) => e.action === 'Sent to self'));
  assert.equal((await call(`/api/documents/${d.id}/send`, { body: { selfSign: true } })).status, 409, 'second send rejected');
  if (SINK_PORT) {
    await new Promise((res) => setTimeout(res, 1000));
    assert.ok(!mails.some((m) => m.to.includes(email.toLowerCase())), 'no invitation email for self-sign');
  }
  const page = await props(client(), r.data.signUrl);
  assert.equal(page.state, 'sign', 'no verify step');
  const done = await client()(`/api/sign/${p.recipients[0].token}`, { body: { values: { [d.fields[0].id]: PNG, [d.fields[1].id]: 'Me Ltd' } } });
  assert.deepEqual([done.status, done.data.status], [200, 'completed'], JSON.stringify(done.data));
  if (SINK_PORT) await mailTo(email, 'Completed:');
});

test('sign yourself: 400 unless the owner is the one and only signer; a refused send changes nothing', async () => {
  const call = await signup();
  const me = { id: 'm', name: 'Me', email: call.email, role: 'signer' };
  const cases = {
    'someone else': [[person('x')], sig('x')],
    'owner + another signer': [[me, person('x')], [...sig('m'), ...sig('x')]],
    'owner + cc': [[me, person('c', { role: 'cc' })], sig('m')],
    'owner only as cc': [[{ ...me, role: 'cc' }, person('x')], sig('x')],
  };
  for (const [name, [recipients, fields]] of Object.entries(cases)) {
    const d = await draft(call, recipients, fields);
    assert.deepEqual(err(await call(`/api/documents/${d.id}/send`, { body: { selfSign: true } })), [400, 'Sign yourself needs you as the only signer'], name);
    assert.ok((await props(call, `/app/documents/${d.id}/edit`)).doc, `${name}: still a draft`);
  }
  // Another account cannot self-sign the owner's document.
  const other = await signup();
  const d = await draft(call, [me], sig('m'));
  assert.equal((await other(`/api/documents/${d.id}/send`, { body: { selfSign: true } })).status, 404);
});

// ---------- (4) Expiry ----------

test('expiry: expireDays is clamped to 0..365 and expires_at is set at send only when > 0', async () => {
  const call = await signup();
  for (const [input, want] of [[7, 7], [0, 0], [999, 365], [-5, 0], ['abc', 0], [2.9, 2], [undefined, 0]]) {
    const d = await draft(call, [person('a')], sig('a'), { expireDays: input });
    assert.equal((await props(call, `/app/documents/${d.id}/edit`)).doc.expireDays, want, `expireDays ${input}`);
  }
  const t = Date.now();
  const d7 = await sent(call, [person('a')], sig('a'), { expireDays: 7 });
  assert.ok(Math.abs(Date.parse(d7.doc.expires_at) - t - 7 * 864e5) < 60_000, `expires_at ${d7.doc.expires_at}`);
  const d0 = await sent(call, [person('a')], sig('a'));
  assert.equal(d0.doc.expires_at, null);
  assert.equal((await props(client(), `/sign/${d7.tokens[0]}`)).state, 'sign', 'not yet expired: signable');
});

test('expiry (lazy): first access after expires_at expires the document, 410 everywhere, delete allowed, void 409, copy keeps it', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const d = await sent(call, [person('a'), person('b')], [...sig('a'), ...sig('b')], { expireDays: 3 });
  assert.equal((await client()(`/api/sign/${d.tokens[1]}`, { body: { values: { [d.fields[1].id]: PNG } } })).data.status, 'sent', 'b signs in time');
  db().prepare('UPDATE documents SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), d.id);
  const anon = client();
  let r = await anon(`/api/sign/${d.tokens[0]}/file`, { method: 'GET' });
  assert.equal(r.status, 410); assert.match(r.data.error, DATE_MSG);
  const row = db().prepare('SELECT status FROM documents WHERE id = ?').get(d.id);
  assert.equal(row.status, 'expired', 'the lazy check moved it to expired');
  assert.ok(db().prepare('SELECT token_revoked_at FROM recipients WHERE document_id = ?').all(d.id).every((x) => x.token_revoked_at), 'links revoked');
  // After revocation the signer still learns why.
  r = await anon(`/api/sign/${d.tokens[0]}`, { body: { values: { [d.fields[0].id]: PNG } } });
  assert.equal(r.status, 410); assert.match(r.data.error, DATE_MSG);
  r = await anon(`/api/sign/${d.tokens[0]}/decline`, { body: { reason: 'late' } });
  assert.equal(r.status, 410); assert.match(r.data.error, DATE_MSG);
  r = await anon(`/api/sign/${d.tokens[1]}/file`, { method: 'GET' });
  assert.equal(r.status, 410, 'also for a signer who already signed');
  const page = await anon(`/sign/${d.tokens[0]}`, { method: 'GET' });
  assert.equal(page.status, 410);
  const pp = JSON.parse(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s.exec(page.data.toString())[1]).props.pageProps;
  assert.equal(pp.state, 'expired'); assert.match(pp.notice, DATE_MSG); assert.equal(pp.token, null);
  assert.equal(eventsOf(d.id).filter((e) => e.action === 'Expired').length, 1, 'one Expired event');
  if (SINK_PORT) await mailTo(call.email, `Expired: ${d.title}`);

  const p = await props(call, `/app/documents/${d.id}`);
  assert.equal(p.doc.status, 'expired');
  assert.equal((await call(`/api/documents/${d.id}/void`, { body: {} })).status, 409);
  assert.equal((await call(`/api/documents/${d.id}/remind`, { body: { recipientId: d.recipients[0].id } })).status, 409);
  assert.equal((await call(`/api/documents/${d.id}/send`, { body: {} })).status, 409);
  const copy = await call(`/api/documents/${d.id}/copy`, { body: {} });
  assert.equal(copy.status, 201);
  assert.equal((await props(call, `/app/documents/${copy.data.id}/edit`)).doc.expireDays, 3, 'copy keeps expire_days');
  assert.equal(db().prepare('SELECT expires_at FROM documents WHERE id = ?').get(copy.data.id).expires_at, null, 'copy is not pre-expired');
  assert.equal((await call(`/api/documents/${d.id}`, { method: 'DELETE' })).status, 200, 'expired can be deleted');
});

test('expiry: completed, declined and voided documents never become expired', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const done = await sent(call, [person('a')], sig('a'), { expireDays: 1 });
  assert.equal((await client()(`/api/sign/${done.tokens[0]}`, { body: { values: { [done.fields[0].id]: PNG } } })).data.status, 'completed');
  const voided = await sent(call, [person('a')], sig('a'), { expireDays: 1 });
  assert.equal((await call(`/api/documents/${voided.id}/void`, { body: {} })).status, 200);
  for (const x of [done, voided]) db().prepare('UPDATE documents SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), x.id);
  assert.equal((await client()(`/api/sign/${done.tokens[0]}/file?download=1`, { method: 'GET' })).status, 200, 'completed stays downloadable');
  assert.equal((await client()(`/api/sign/${voided.tokens[0]}/file`, { method: 'GET' })).status, 410);
  assert.deepEqual(db().prepare('SELECT status FROM documents WHERE id IN (?, ?) ORDER BY status').all(done.id, voided.id).map((x) => x.status), ['completed', 'voided']);
});

// Runs lib/documents.js expireDueDocuments() in a child process on the server's DATA_DIR, as the hourly job would.
// Extensionless relative imports ('./db') are resolved to .js, which Next does at build time. No SMTP env: no emails.
function runExpiryJob() {
  const code = `
    import { registerHooks } from 'node:module';
    registerHooks({ resolve(s, c, next) {
      try { return next(s, c); } catch (e) { if (/^\\.\\.?\\//.test(s) && !/\\.[cm]?js$/.test(s)) return next(s + '.js', c); throw e; }
    } });
    const { expireDueDocuments } = await import(${JSON.stringify(pathToFileURL(path.join(ROOT, 'lib', 'documents.js')).href)});
    console.log('EXPIRED=' + await expireDueDocuments());`;
  const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, DATA_DIR: DATA, ENCRYPTION_KEY: keyText(), NODE_NO_WARNINGS: '1' };
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', code], { cwd: ROOT, env, encoding: 'utf8', timeout: 60_000 });
  return Number(/EXPIRED=(\d+)/.exec(out)[1]);
}

test('expiry (hourly job): expireDueDocuments() expires only due sent documents, once, without any link being opened', { skip: (NEEDS_DB || typeof (await import('node:module')).registerHooks !== 'function') && 'needs DATA_DIR and Node with module.registerHooks' }, async () => {
  const call = await signup();
  const due = await sent(call, [person('a')], sig('a'), { expireDays: 2 });
  const later = await sent(call, [person('a')], sig('a'), { expireDays: 2 });
  const never = await sent(call, [person('a')], sig('a'));
  db().prepare('UPDATE documents SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 5000).toISOString(), due.id);
  const n = runExpiryJob();
  assert.ok(n >= 1, `job expired ${n}`);
  const status = (x) => db().prepare('SELECT status FROM documents WHERE id = ?').get(x.id).status;
  assert.deepEqual([status(due), status(later), status(never)], ['expired', 'sent', 'sent']);
  assert.ok(db().prepare('SELECT token_revoked_at FROM recipients WHERE document_id = ?').get(due.id).token_revoked_at, 'links revoked');
  assert.equal(eventsOf(due.id).filter((e) => e.action === 'Expired').length, 1);
  assert.equal(runExpiryJob(), 0, 'second run finds nothing');
  assert.equal(eventsOf(due.id).filter((e) => e.action === 'Expired').length, 1, 'no second Expired event');
  const r = await client()(`/api/sign/${due.tokens[0]}/file`, { method: 'GET' });
  assert.equal(r.status, 410); assert.match(r.data.error, DATE_MSG);
  // The audit chain written by the job process is intact: the server still builds the owner page and accepts the document's lifecycle.
  assert.equal((await props(call, `/app/documents/${due.id}`)).doc.status, 'expired');
  assert.equal((await props(client(), `/sign/${later.tokens[0]}`)).state, 'sign');
});

// ---------- (2) Email one-time code ----------

test('OTP without email: send with requireOtp is refused 400 and the document stays a draft', { skip: NEEDS_NO_MAIL }, async () => {
  const call = await signup();
  const d = await draft(call, [person('a')], sig('a'), { requireOtp: true });
  assert.equal((await props(call, `/app/documents/${d.id}/edit`)).doc.requireOtp, true, 'requireOtp is saved');
  assert.deepEqual(err(await call(`/api/documents/${d.id}/send`, { body: {} })), [400, 'Email codes need email (SMTP and APP_URL) to be set up on this server']);
  assert.ok((await props(call, `/app/documents/${d.id}/edit`)).doc, 'still a draft');
});

test('OTP gating: until verified the page has no fields and file, submit, decline answer 403', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const d = await otpDoc(call, [person('o', { email: `otp-${rnd()}@example.com` })], [...sig('o'), field('o', 'company', { y: 0.3 })]);
  const s = client();
  const page = await s(`/sign/${d.tokens[0]}`, { method: 'GET' });
  const html = page.data.toString();
  const pp = JSON.parse(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s.exec(html)[1]).props.pageProps;
  assert.equal(pp.state, 'verify');
  assert.deepEqual(pp.fields, []);
  assert.equal(pp.me, null);
  assert.equal(pp.maskedEmail, `o***@${d.recipients[0].email.split('@')[1]}`);
  for (const f of d.fields) assert.ok(!html.includes(f.id), 'no field ids before verify');
  assert.ok(!html.includes(d.recipients[0].email), 'full email not on the page');
  assert.deepEqual(err(await s(`/api/sign/${d.tokens[0]}/file`, { method: 'GET' })), [403, 'Verify your email first']);
  assert.deepEqual(err(await s(`/api/sign/${d.tokens[0]}/file?download=1`, { method: 'GET' })), [403, 'Verify your email first']);
  assert.deepEqual(err(await s(`/api/sign/${d.tokens[0]}`, { body: { values: { [d.fields[0].id]: PNG, [d.fields[1].id]: 'x' } } })), [403, 'Verify your email first']);
  assert.deepEqual(err(await s(`/api/sign/${d.tokens[0]}/decline`, { body: { reason: 'x' } })), [403, 'Verify your email first']);
  assert.equal(db().prepare('SELECT status FROM recipients WHERE id = ?').get(d.recipients[0].id).status, 'sent', 'not marked viewed before verify');
  assert.equal((await props(call, `/app/documents/${d.id}`)).doc.status, 'sent', 'nothing changed');
  // Forged cookies do not count.
  const forged = { cookie: `cs_otp_${d.recipients[0].id}=${crypto.randomBytes(32).toString('base64url')}` };
  assert.equal((await client()(`/api/sign/${d.tokens[0]}/file`, { method: 'GET', headers: forged })).status, 403);
  assert.equal((await client()(`/api/sign/${d.tokens[0]}/file`, { method: 'GET', headers: { cookie: `cs_otp_${d.recipients[0].id}=` } })).status, 403);
  if (!SINK_PORT) assert.deepEqual(err(await s(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'send' } })), [400, 'Email codes need email (SMTP and APP_URL) to be set up on this server']);
  assert.deepEqual(err(await s(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'nope' } })), [400, 'Unknown action']);
});

test('OTP verify: wrong x4 = 400, 5th = 429 and burns the code, expired = 400, success sets a scoped cookie and is single-use', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const d = await otpDoc(call, [person('o')], sig('o'));
  const rid = d.recipients[0].id, tok = d.tokens[0];
  const s = client();
  const verify = (code) => s(`/api/sign/${tok}/otp`, { body: { action: 'verify', code } });
  assert.deepEqual(err(await verify('123456')), [400, 'Send a code first.']);
  inject(rid, '424242');
  for (const c of ['000000', '42424', 'abcdef', '']) assert.deepEqual(err(await verify(c)), [400, 'That code is not right'], `guess ${c}`);
  assert.deepEqual(err(await verify('000000')), [429, 'Too many attempts. Send a new code.'], '5th wrong guess');
  assert.deepEqual(err(await verify('424242')), [429, 'Too many attempts. Send a new code.'], 'burned code no longer works');
  inject(rid, '424242', Date.now() - 1000);
  assert.deepEqual(err(await verify('424242')), [400, 'That code has expired. Send a new one.']);
  inject(rid, '424242');
  const ok = await verify(' 424242 ');
  assert.equal(ok.status, 200, JSON.stringify(ok.data));
  assert.deepEqual(ok.data, { ok: true });
  const set = ok.setCookie.find((c) => c.startsWith(`cs_otp_${rid}=`));
  assert.match(set, new RegExp(`^cs_otp_${rid}=[\\w-]{43}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200$`), 'no Secure on http');
  const value = s.cookies[`cs_otp_${rid}`];
  assert.deepEqual(err(await verify('424242')), [400, 'Send a code first.'], 'code is single-use');
  const row = db().prepare('SELECT otp_hash, otp_session_hash, otp_session_expires_at, otp_verified_at FROM recipients WHERE id = ?').get(rid);
  assert.equal(row.otp_hash, null);
  assert.equal(row.otp_session_hash, keyedHash('otp-session', value), 'only the keyed hash of the session is stored');
  assert.ok(!JSON.stringify(row).includes(value));
  assert.ok(Math.abs(Date.parse(row.otp_session_expires_at) - Date.now() - 12 * 3600e3) < 60_000, '12 h session');
  assert.ok(row.otp_verified_at);
  assert.equal((await client()(`/api/sign/${tok}/file`, { method: 'GET' })).status, 403, 'another browser is still blocked');
  assert.equal((await s(`/api/sign/${tok}/file`, { method: 'GET' })).status, 200, 'verified browser gets the file');
  assert.equal((await props(s, `/sign/${tok}`)).state, 'sign', 'verified page shows fields');
  const done = await s(`/api/sign/${tok}`, { body: { values: { [d.fields[0].id]: PNG } } });
  assert.deepEqual([done.status, done.data.status], [200, 'completed']);
  assert.ok(has(pdfText((await s(`/api/sign/${tok}/file?download=1`, { method: 'GET' })).data), 'Email verified by one-time code at'), 'certificate notes the verification');
  const evs = eventsOf(d.id).map((e) => e.action);
  assert.ok(evs.includes('Email verified'), evs.join(','));
  const sec = db().prepare("SELECT type, detail FROM security_events WHERE type LIKE 'otp_%' AND detail = ?").all(`recipient ${rid}`).map((e) => e.type);
  for (const t of ['otp_failure', 'otp_locked', 'otp_verified']) assert.ok(sec.includes(t), `${t} logged: ${sec.join(',')}`);
  assert.ok(!JSON.stringify(db().prepare("SELECT * FROM security_events WHERE type LIKE 'otp_%'").all()).includes('424242'), 'code never logged');
  // An expired OTP session no longer unlocks.
  db().prepare('UPDATE recipients SET otp_session_expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), rid);
  assert.deepEqual(err(await s(`/api/sign/${tok}/file?download=1`, { method: 'GET' })), [403, 'Verify your email first']);
});

test('OTP: one recipient\'s cookie never unlocks another recipient; queued signers cannot request or verify codes', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  // a and b sign in parallel; c is a later signer in a sequential copy below.
  const d = await otpDoc(call, [person('a'), person('b')], [...sig('a'), ...sig('b')]);
  const [ra, rb] = d.recipients.map((r) => r.id);
  const s = client();
  inject(ra, '111111');
  assert.equal((await s(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'verify', code: '111111' } })).status, 200);
  const value = s.cookies[`cs_otp_${ra}`];
  assert.equal((await s(`/api/sign/${d.tokens[0]}/file`, { method: 'GET' })).status, 200, 'a is verified');
  assert.deepEqual(err(await s(`/api/sign/${d.tokens[1]}/file`, { method: 'GET' })), [403, 'Verify your email first'], 'a\'s cookie on b\'s link');
  assert.deepEqual(err(await client()(`/api/sign/${d.tokens[1]}/file`, { method: 'GET', headers: { cookie: `cs_otp_${rb}=${value}` } })), [403, 'Verify your email first'], 'a\'s value under b\'s cookie name');
  assert.deepEqual(err(await s(`/api/sign/${d.tokens[1]}`, { body: { values: { [d.fields[1].id]: PNG } } })), [403, 'Verify your email first']);
  inject(rb, '111111');
  assert.deepEqual(err(await s(`/api/sign/${d.tokens[1]}/otp`, { body: { action: 'verify', code: '222222' } })), [400, 'That code is not right'], 'a code is per recipient');
  // Cross-document: the same cookie on another OTP document's link.
  const other = await otpDoc(call, [person('z')], sig('z'));
  assert.equal((await client()(`/api/sign/${other.tokens[0]}/file`, { method: 'GET', headers: { cookie: `cs_otp_${other.recipients[0].id}=${value}` } })).status, 403);

  const q = await otpDoc(call, [person('p'), person('q')], [...sig('p'), ...sig('q')]);
  db().prepare('UPDATE documents SET sequential = 1 WHERE id = ?').run(q.id);
  db().prepare("UPDATE recipients SET routing_order = 2, status = 'pending' WHERE id = ?").run(q.recipients[1].id);
  assert.deepEqual(err(await client()(`/api/sign/${q.tokens[1]}/otp`, { body: { action: 'verify', code: '000000' } })), [409, 'This document is not available to you right now']);
  assert.deepEqual(err(await client()(`/api/sign/${q.tokens[1]}/otp`, { body: { action: 'send' } })), [409, 'This document is not available to you right now']);
  // A document without require_otp has no code step.
  const plain = await sent(call, [person('n')], sig('n'));
  assert.deepEqual(err(await client()(`/api/sign/${plain.tokens[0]}/otp`, { body: { action: 'send' } })), [400, 'This document does not need an email code']);
  assert.equal((await client()('/api/sign/not-a-token/otp', { body: { action: 'send' } })).status, 404);
});

test('OTP: a verified signer can decline; declining revokes the link', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const d = await otpDoc(call, [person('o')], sig('o'));
  const s = client();
  inject(d.recipients[0].id, '135790');
  assert.equal((await s(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'verify', code: '135790' } })).status, 200);
  assert.equal((await s(`/api/sign/${d.tokens[0]}/decline`, { body: { reason: 'Not today' } })).status, 200);
  assert.equal((await props(call, `/app/documents/${d.id}`)).doc.status, 'declined');
  assert.equal((await s(`/api/sign/${d.tokens[0]}/file`, { method: 'GET' })).status, 410);
});

// ---------- (2) with real email ----------

test('OTP with email: invitation link, code email, 60 s cooldown 429 + Retry-After, verify the emailed code, sign', { skip: NEEDS_SMTP }, async () => {
  const call = await signup();
  const addr = `mail-${rnd()}@example.com`;
  const d = await sent(call, [person('o', { email: addr })], sig('o'), { requireOtp: true });
  assert.equal(d.doc.require_otp, 1);
  const invite = await mailTo(addr, d.title);
  const link = new RegExp(`${BASE.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}/sign/([\\w-]+)`).exec(invite.raw);
  assert.ok(link, 'invitation carries an APP_URL signing link');
  assert.equal(link[1], d.tokens[0]);
  const s = client();
  assert.equal((await props(s, `/sign/${link[1]}`)).state, 'verify');
  const r = await s(`/api/sign/${link[1]}/otp`, { body: { action: 'send' } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.deepEqual(r.data, { ok: true, sentTo: `m***@example.com` });
  const codeMail = await mailTo(addr, `Your signing code for ${d.title}`);
  const code = /Your code is (\d{6})/.exec(codeMail.raw)?.[1];
  assert.ok(code, 'code in the email');
  const again = await s(`/api/sign/${link[1]}/otp`, { body: { action: 'send' } });
  assert.equal(again.status, 429);
  assert.match(again.data.error, /^Wait \d+ seconds before sending another code\.$/);
  const retry = Number(again.headers.get('retry-after'));
  assert.ok(retry >= 1 && retry <= 60, `Retry-After ${retry}`);
  assert.equal(mails.filter((m) => m.to.includes(addr) && m.subject.includes('Your signing code')).length, 1, 'no second code email during cooldown');
  assert.ok(eventsOf(d.id).some((e) => e.action === 'Email code sent' && !e.detail.includes(addr)), 'event with masked address');
  assert.equal((await s(`/api/sign/${link[1]}/otp`, { body: { action: 'verify', code } })).status, 200);
  const done = await s(`/api/sign/${link[1]}`, { body: { values: { [d.fields[0].id]: PNG } } });
  assert.deepEqual([done.status, done.data.status], [200, 'completed']);
  await mailTo(addr, 'Completed:');
});

test('OTP with email: after the cooldown a new code replaces the old one; at most 10 sends per recipient', { skip: NEEDS_SMTP }, async () => {
  const call = await signup();
  const addr = `cap-${rnd()}@example.com`;
  const d = await sent(call, [person('o', { email: addr })], sig('o'), { requireOtp: true });
  const rid = d.recipients[0].id, s = client();
  const send = () => s(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'send' } });
  const ago = () => db().prepare('UPDATE recipients SET otp_sent_at = ? WHERE id = ?').run(new Date(Date.now() - 61_000).toISOString(), rid);
  assert.equal((await send()).status, 200);
  const first = /Your code is (\d{6})/.exec((await mailTo(addr, 'Your signing code')).raw)[1];
  ago();
  mails.length = 0;
  assert.equal((await send()).status, 200, 'allowed after 60 s');
  const second = /Your code is (\d{6})/.exec((await mailTo(addr, 'Your signing code')).raw)[1];
  if (first !== second) assert.deepEqual(err(await s(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'verify', code: first } })), [400, 'That code is not right'], 'old code replaced');
  db().prepare('UPDATE recipients SET otp_send_count = 10 WHERE id = ?').run(rid);
  ago();
  mails.length = 0;
  assert.deepEqual(err(await send()), [429, 'Too many codes were sent for this link. Contact the sender.']);
  await new Promise((r) => setTimeout(r, 500));
  assert.equal(mails.length, 0, 'no email when capped');
  assert.equal((await s(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'verify', code: second } })).status, 200, 'the last code still works');
});

// ---------- Fix round: remind, placeholder uploads, unverified status pages ----------

test('remind on a sent document past expires_at: 409 "This document has expired" and it becomes expired', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const d = await sent(call, [person('a')], sig('a'), { expireDays: 5 });
  db().prepare('UPDATE documents SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), d.id);
  const remind = () => call(`/api/documents/${d.id}/remind`, { body: { recipientId: d.recipients[0].id } });
  assert.deepEqual(err(await remind()), [409, 'This document has expired']);
  assert.equal((await props(call, `/app/documents/${d.id}`)).doc.status, 'expired');
  assert.equal(eventsOf(d.id).filter((e) => e.action === 'Expired').length, 1);
  assert.ok(db().prepare('SELECT token_revoked_at FROM recipients WHERE id = ?').get(d.recipients[0].id).token_revoked_at, 'links revoked, not extended');
  assert.ok(!eventsOf(d.id).some((e) => e.action === 'Reminded'));
  assert.deepEqual(err(await remind()), [409, 'This recipient is not waiting to sign'], 'second remind on the expired document');
  const r = await client()(`/api/sign/${d.tokens[0]}/file`, { method: 'GET' });
  assert.equal(r.status, 410); assert.match(r.data.error, DATE_MSG);
});

test('remind lifts the email-code send cap and attempt lock: the 11th code send after a reminder works', { skip: NEEDS_SMTP }, async () => {
  const call = await signup();
  const addr = `rem-${rnd()}@example.com`;
  const d = await sent(call, [person('o', { email: addr })], sig('o'), { requireOtp: true });
  const rid = d.recipients[0].id, s = client();
  const send = () => s(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'send' } });
  const verify = (code) => s(`/api/sign/${d.tokens[0]}/otp`, { body: { action: 'verify', code } });
  // State after 10 sends and a burned code; the last send was over 60 s ago.
  db().prepare('UPDATE recipients SET otp_send_count = 10, otp_attempts = 5, otp_hash = NULL, otp_sent_at = ? WHERE id = ?').run(new Date(Date.now() - 61_000).toISOString(), rid);
  assert.deepEqual(err(await send()), [429, 'Too many codes were sent for this link. Contact the sender.']);
  assert.deepEqual(err(await verify('000000')), [429, 'Too many attempts. Send a new code.']);
  mails.length = 0;
  const r = await call(`/api/documents/${d.id}/remind`, { body: { recipientId: rid } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  await mailTo(addr, 'to sign');
  assert.deepEqual({ ...db().prepare('SELECT otp_send_count, otp_attempts FROM recipients WHERE id = ?').get(rid) }, { otp_send_count: 0, otp_attempts: 0 });
  assert.ok(eventsOf(d.id).some((e) => e.action === 'Reminded' && e.detail.includes('Email code limit reset')));
  assert.equal((await send()).status, 200, '11th send');
  const code = /Your code is (\d{6})/.exec((await mailTo(addr, 'Your signing code')).raw)[1];
  assert.equal((await verify(code)).status, 200);
  assert.equal(db().prepare('SELECT otp_send_count FROM recipients WHERE id = ?').get(rid).otp_send_count, 1, 'the cap applies again from here');
});

test('upload: an unfinished signature placeholder is refused 400; a sealed Countersign PDF can be uploaded and sealed again', async () => {
  const call = await signup();
  const base = Buffer.from(await pdf());
  const upload = (b) => call('/api/documents', { body: b, headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'P.pdf' } });
  for (const ph of ['/ByteRange [0 /********** /********** /**********]', '/ByteRange[0 /**********/**********/**********]']) {
    assert.deepEqual(err(await upload(new Uint8Array(Buffer.concat([base, Buffer.from(`\n%${ph}\n`)])))),
      [400, 'This PDF contains an unfinished signature placeholder. Export it again and upload the new file.'], ph);
  }
  const first = await sent(call, [person('a')], sig('a'));
  assert.equal((await client()(`/api/sign/${first.tokens[0]}`, { body: { values: { [first.fields[0].id]: PNG } } })).data.status, 'completed');
  const sealed = (await call(`/api/documents/${first.id}/file?kind=signed`, { method: 'GET' })).data;
  const again = await sent(call, [person('b')], sig('b'), {}, new Uint8Array(sealed));
  const r = await client()(`/api/sign/${again.tokens[0]}`, { body: { values: { [again.fields[0].id]: PNG } } });
  assert.deepEqual([r.status, r.data.status], [200, 'completed'], JSON.stringify(r.data));
  const bytes = (await call(`/api/documents/${again.id}/file?kind=signed`, { method: 'GET' })).data;
  const seal = readSeal(bytes, { many: true });
  assert.equal(seal.br[2] + seal.br[3], bytes.length, 'new seal covers the file to the end');
  assert.equal(seal.digest, sha(seal.covered), 'new seal digest matches');
});

test('OTP status pages: unverified queued signer, cc and waiting signer see no message, name or email; unverified cc is not marked Viewed', { skip: NEEDS_DB }, async () => {
  const call = await signup();
  const msg = `QA-MSG-${rnd()}`;
  const recips = [person('a', { name: `Ana ${rnd()}` }), person('b', { name: `Ben ${rnd()}` }), person('c', { name: `Cat ${rnd()}`, role: 'cc' })];
  const d = await otpDoc(call, recips, [...sig('a'), ...sig('b')], { sequential: true, message: msg });
  const [ta, tb, tc] = d.tokens;
  const check = async (tok, state, r) => {
    const html = (await client()(`/sign/${tok}`, { method: 'GET' })).data.toString();
    const pp = JSON.parse(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s.exec(html)[1]).props.pageProps;
    assert.equal(pp.state, state);
    assert.equal(pp.me, null);
    assert.deepEqual(pp.fields, []);
    for (const x of [msg, r.name, r.email]) assert.ok(!html.includes(x), `${state}: "${x}" not on the page`);
  };
  await check(tb, 'queued', recips[1]);
  await check(tc, 'cc', recips[2]);
  const cc = d.recipients[2];
  assert.notEqual(db().prepare('SELECT status FROM recipients WHERE id = ?').get(cc.id).status, 'viewed', 'unverified cc not marked viewed');
  assert.ok(!eventsOf(d.id).some((e) => e.action === 'Viewed'), 'no Viewed event before verification');
  inject(d.recipients[0].id, '246810');
  const sa = client();
  assert.equal((await sa(`/api/sign/${ta}/otp`, { body: { action: 'verify', code: '246810' } })).status, 200);
  assert.equal((await sa(`/api/sign/${ta}`, { body: { values: { [d.fields[0].id]: PNG } } })).data.status, 'sent');
  await check(ta, 'waiting', recips[0]);
  assert.equal((await props(sa, `/sign/${ta}`)).state, 'waiting', 'verified browser sees its own status page');
});
