// AES-256-GCM encryption at rest, checked over HTTP and on disk. Needs a running server:
//   BASE_URL=http://localhost:3127 DATA_DIR=<the server's DATA_DIR> node --test test/encryption.test.mjs
// Disk and DB checks need DATA_DIR (same folder the server uses) and are skipped without it.
// The key is read from ENCRYPTION_KEY if the test env has it, otherwise from DATA_DIR/encryption.key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const DATA = process.env.DATA_DIR;
const NEEDS_DISK = !DATA && 'needs DATA_DIR pointing at the server data folder';
const FILES = DATA && path.join(DATA, 'files');
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

function key() {
  const s = (process.env.ENCRYPTION_KEY || fs.readFileSync(path.join(DATA, 'encryption.key'), 'utf8')).trim();
  return Buffer.from(s, /^[0-9a-f]{64}$/i.test(s) ? 'hex' : 'base64');
}
// Independent AES-256-GCM decrypt of the documented layout: "CSE1" | IV 12 | tag 16 | ciphertext.
function dec(buf, aad) {
  assert.equal(buf.subarray(0, 4).toString(), 'CSE1');
  const d = crypto.createDecipheriv('aes-256-gcm', key(), buf.subarray(4, 16));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(buf.subarray(16, 32));
  return Buffer.concat([d.update(buf.subarray(32)), d.final()]);
}
function enc(buf, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key(), iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(buf), c.final()]);
  return Buffer.concat([Buffer.from('CSE1'), iv, c.getAuthTag(), ct]);
}
// A real, decodable PNG (random 300x320 RGB pixels, so it barely compresses) padded with a private
// ancillary chunk so its data URL is exactly `len` chars. len must be 22 + a multiple of 4.
function pngDataUrl(len) {
  const chunk = (type, data) => {
    const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
    const out = Buffer.alloc(12 + data.length);
    out.writeUInt32BE(data.length, 0); td.copy(out, 4); out.writeUInt32BE(zlib.crc32(td), 8 + data.length);
    return out;
  };
  const w = 300, h = 320;
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2;
  const rows = Buffer.alloc((1 + w * 3) * h);
  crypto.randomFillSync(rows);
  for (let y = 0; y < h; y++) rows[y * (1 + w * 3)] = 0; // filter type None
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const head = Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(rows))]);
  const iend = chunk('IEND', Buffer.alloc(0));
  const bytes = ((len - 22) / 4) * 3; // base64 of n bytes is 4*ceil(n/3) chars
  const pad = bytes - head.length - iend.length - 12;
  assert.ok(Number.isInteger(bytes) && pad >= 0, `cannot build a ${len}-char PNG data URL`);
  return 'data:image/png;base64,' + Buffer.concat([head, chunk('qaPd', Buffer.alloc(pad)), iend]).toString('base64');
}
const decText = (v, aad) => dec(Buffer.from(v.slice('enc:v1:'.length), 'base64'), aad).toString('utf8');
const db = () => new DatabaseSync(path.join(DATA, 'countersign.db'));

function client() {
  let cookie = '';
  return async (p, { method = 'POST', body, headers = {} } = {}) => {
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
}

async function owner() {
  const call = client();
  const email = `enc-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  assert.equal((await call('/api/auth/signup', { body: { name: 'Enc Owner', email, password: 'correct horse battery' } })).status, 200);
  return call;
}

async function pdfBytes() {
  const pdf = await PDFDocument.create();
  pdf.addPage([612, 792]); pdf.addPage([612, 792]);
  pdf.setTitle('Plaintext marker QA-ENC-7731');
  return Buffer.from(await pdf.save());
}

async function upload(call, bytes) {
  const up = await call('/api/documents', { body: bytes, headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'Enc.pdf' } });
  assert.equal(up.status, 201);
  return up.data.id;
}

// Two signers in order (Ana: signature + text, Ben: signature) plus a cc; returns tokens in that order.
async function sendTwoSigner(call, id) {
  const draft = {
    title: 'Enc', sequential: true,
    recipients: [{ id: 'a', name: 'Ana', email: 'ana@example.com', role: 'signer' }, { id: 'b', name: 'Ben', email: 'ben@example.com', role: 'signer' }, { id: 'c', name: 'Cat', email: 'cat@example.com', role: 'cc' }],
    fields: [{ recipientId: 'a', type: 'signature', page: 0, x: 0.1, y: 0.8, w: 0.3, h: 0.06 }, { recipientId: 'a', type: 'text', page: 1, x: 0.1, y: 0.7, w: 0.3, h: 0.03 }, { recipientId: 'b', type: 'signature', page: 1, x: 0.1, y: 0.8, w: 0.3, h: 0.06 }],
  };
  assert.equal((await call(`/api/documents/${id}`, { method: 'PUT', body: draft })).status, 200);
  assert.equal((await call(`/api/documents/${id}/send`)).status, 200);
  const html = (await call(`/app/documents/${id}`, { method: 'GET' })).data.toString();
  const tokens = [...html.matchAll(/"token":"([\w-]+)"/g)].map((m) => m[1]);
  assert.equal(tokens.length, 3);
  return tokens;
}
const signer = client();
const signPage = async (t) => (await signer(`/sign/${t}`, { method: 'GET' })).data.toString();
const mineId = (html, type) => html.match(new RegExp(`"id":"([\\w-]+)","type":"${type}"[^}]*"mine":true`))[1];

test('upload and download round-trip byte for byte; template copies decrypt to the same bytes', async () => {
  const call = await owner();
  const orig = await pdfBytes();
  const id = await upload(call, orig);
  const dl = await call(`/api/documents/${id}/file`, { method: 'GET' });
  assert.equal(dl.status, 200);
  assert.equal(dl.headers.get('content-type'), 'application/pdf');
  assert.equal(Number(dl.headers.get('content-length')), orig.length, 'Content-Length is the plaintext size');
  assert.ok(dl.data.equals(orig), 'download equals upload');
  const tpl = await call(`/api/documents/${id}/copy`, { body: { asTemplate: true } });
  assert.equal(tpl.status, 201);
  assert.ok((await call(`/api/documents/${tpl.data.id}/file`, { method: 'GET' })).data.equals(orig), 'template decrypts');
  const fromTpl = await call(`/api/documents/${tpl.data.id}/copy`, { body: { asTemplate: false } });
  assert.equal(fromTpl.status, 201);
  assert.ok((await call(`/api/documents/${fromTpl.data.id}/file`, { method: 'GET' })).data.equals(orig), 'doc from template decrypts');
});

test('PDFs on disk are CSE1 ciphertext bound to their own id; copies get their own IV', { skip: NEEDS_DISK }, async () => {
  const call = await owner();
  const orig = await pdfBytes();
  const id = await upload(call, orig);
  const disk = fs.readFileSync(path.join(FILES, `${id}.original.pdf`));
  assert.equal(disk.subarray(0, 4).toString(), 'CSE1');
  assert.ok(!disk.includes(Buffer.from('%PDF')) && !disk.includes(Buffer.from('QA-ENC-7731')), 'no plaintext on disk');
  assert.ok(dec(disk, `file:${id}.original`).equals(orig), 'decrypts with AAD file:<id>.original');
  assert.throws(() => dec(disk, `file:${id}.signed`), 'wrong AAD must fail authentication');
  const tid = (await call(`/api/documents/${id}/copy`, { body: { asTemplate: true } })).data.id;
  const tdisk = fs.readFileSync(path.join(FILES, `${tid}.original.pdf`));
  assert.notDeepEqual(tdisk.subarray(4, 16), disk.subarray(4, 16), 'fresh IV');
  assert.ok(dec(tdisk, `file:${tid}.original`).equals(orig), 'copy re-encrypted under its own id');
});

test('tampered or swapped ciphertext is refused (500), never served as garbage', { skip: NEEDS_DISK }, async () => {
  const call = await owner();
  const orig = await pdfBytes();
  const a = await upload(call, orig);
  const b = await upload(call, orig);
  const fa = path.join(FILES, `${a}.original.pdf`);
  const flipped = Buffer.from(fs.readFileSync(fa));
  flipped[flipped.length - 10] ^= 0xff;
  fs.writeFileSync(fa, flipped);
  const ra = await call(`/api/documents/${a}/file`, { method: 'GET' });
  assert.equal(ra.status, 500);
  assert.equal(ra.data.error, 'Something went wrong');
  // Ciphertext of document A copied over document B: AAD mismatch.
  fs.writeFileSync(path.join(FILES, `${b}.original.pdf`), flipped);
  assert.equal((await call(`/api/documents/${b}/file`, { method: 'GET' })).status, 500);
});

test('signing: field values stored as enc:v1:, signed PDF encrypted, hashes over plaintext, other signers see plaintext values', async (t) => {
  const call = await owner();
  const orig = await pdfBytes();
  const id = await upload(call, orig);
  const [ta, tb, tc] = await sendTwoSigner(call, id);
  const anaPage = await signPage(ta);
  const secret = 'Secret Text Ü QA-FIELD-5521';
  assert.deepEqual((await signer(`/api/sign/${ta}`, { body: { values: { [mineId(anaPage, 'signature')]: PNG, [mineId(anaPage, 'text')]: secret } } })).data, { status: 'sent' });
  // Ben's page shows Ana's finished values read-only: they must come back decrypted.
  const benPage = await signPage(tb);
  assert.ok(benPage.includes('QA-FIELD-5521'), "Ana's text value decrypted for Ben");
  assert.ok(benPage.includes(PNG), "Ana's signature image decrypted for Ben");
  assert.ok(!benPage.includes('enc:v1:'), 'no ciphertext leaks to the page');
  assert.deepEqual((await signer(`/api/sign/${tb}`, { body: { values: { [mineId(benPage, 'signature')]: PNG } } })).data, { status: 'completed' });

  const signed = await call(`/api/documents/${id}/file?kind=signed`, { method: 'GET' });
  assert.equal(signed.status, 200);
  const pages = (await PDFDocument.load(signed.data)).getPageCount();
  assert.ok(pages >= 2 + 1, `2 original pages + at least 1 certificate page, got ${pages}`);
  assert.ok((await signer(`/api/sign/${tc}/file`, { method: 'GET' })).data.equals(signed.data), 'cc download equals owner download');
  assert.ok((await call(`/api/documents/${id}/file`, { method: 'GET' })).data.equals(orig), 'original intact after signing');
  if (!DATA) return t.diagnostic('disk/DB assertions skipped: DATA_DIR unset');

  const d = db();
  try {
    const doc = d.prepare('SELECT * FROM documents WHERE id = ?').get(id);
    assert.equal(doc.original_sha256, sha(orig), 'original hash over plaintext');
    assert.equal(doc.signed_sha256, sha(signed.data), 'signed hash over plaintext');
    const vals = d.prepare('SELECT id, type, value FROM fields WHERE document_id = ? AND value IS NOT NULL').all(id);
    assert.equal(vals.length, 3);
    for (const v of vals) {
      assert.ok(v.value.startsWith('enc:v1:'), `${v.type} field encrypted`);
      assert.ok(!v.value.includes('QA-FIELD') && !v.value.includes('data:image'), 'no plaintext in the column');
      const plain = decText(v.value, `field:${v.id}`);
      assert.equal(plain, v.type === 'text' ? secret : PNG);
    }
  } finally { d.close(); }
  const sdisk = fs.readFileSync(path.join(FILES, `${id}.signed.pdf`));
  assert.ok(dec(sdisk, `file:${id}.signed`).equals(signed.data), 'signed file on disk is CSE1 ciphertext of the served bytes');
  assert.ok(!fs.readdirSync(FILES).some((f) => f.startsWith(id) && f.endsWith('.tmp')), 'atomic write leaves no .tmp');
});

test('signature images: PNG data URLs up to 400,000 chars accepted, longer or non-PNG rejected', async () => {
  const call = await owner();
  const id = await upload(call, await pdfBytes());
  const [ta] = await sendTwoSigner(call, id);
  const page = await signPage(ta);
  const sig = mineId(page, 'signature');
  const text = mineId(page, 'text'); // required by default
  const big = pngDataUrl(399_998); // largest length a PNG data URL can have at or under 400,000 (22 + 4k chars)
  const over = pngDataUrl(400_002); // smallest above the limit; a valid PNG, rejected for size alone
  assert.equal(big.length, 399_998);
  assert.equal(over.length, 400_002);
  assert.equal((await signer(`/api/sign/${ta}`, { body: { values: { [sig]: over, [text]: 'x' } } })).status, 400);
  assert.equal((await signer(`/api/sign/${ta}`, { body: { values: { [sig]: 'data:image/jpeg;base64,/9j/', [text]: 'x' } } })).status, 400);
  assert.equal((await signer(`/api/sign/${ta}`, { body: { values: { [sig]: PNG + 'A'.repeat(1000), [text]: 'x' } } })).status, 400, 'padded fake PNG');
  // Upload-tab output is converted to PNG in the browser; the server only ever sees PNG.
  assert.deepEqual((await signer(`/api/sign/${ta}`, { body: { values: { [sig]: big, [text]: 'x' } } })).data, { status: 'sent' });
});

test('malformed PNG from the last signer is a 400, the document stays sent, and a valid retry completes it', async (t) => {
  const call = await owner();
  const id = await upload(call, await pdfBytes());
  const [ta, tb, tc] = await sendTwoSigner(call, id);
  const anaPage = await signPage(ta);
  assert.deepEqual((await signer(`/api/sign/${ta}`, { body: { values: { [mineId(anaPage, 'signature')]: PNG, [mineId(anaPage, 'text')]: 'x' } } })).data, { status: 'sent' });
  const benSig = mineId(await signPage(tb), 'signature');
  const good = Buffer.from(PNG.split(',')[1], 'base64');
  for (const [label, v] of [['not a PNG', 'data:image/png;base64,AAAA'], ['truncated', 'data:image/png;base64,' + good.subarray(0, 40).toString('base64')]]) {
    const r = await signer(`/api/sign/${tb}`, { body: { values: { [benSig]: v } } });
    assert.equal(r.status, 400, label);
    assert.equal(r.data.error, 'Invalid signature image', label);
  }
  const notYet = await call(`/api/documents/${id}/file?kind=signed`, { method: 'GET' });
  assert.equal(notYet.status, 404, 'no signed PDF yet');
  assert.match(await signPage(tb), /"state":"sign"/, 'Ben can still sign');
  if (DATA) {
    const d = db();
    try {
      assert.equal(d.prepare('SELECT status FROM documents WHERE id = ?').get(id).status, 'sent');
      assert.equal(d.prepare("SELECT status FROM recipients WHERE document_id = ? AND name = 'Ben'").get(id).status, 'viewed');
    } finally { d.close(); }
    assert.ok(!fs.existsSync(path.join(FILES, `${id}.signed.pdf`)), 'no signed file left behind');
  } else t.diagnostic('DB assertions skipped: DATA_DIR unset');
  assert.deepEqual((await signer(`/api/sign/${tb}`, { body: { values: { [benSig]: PNG } } })).data, { status: 'completed' });
  const signed = await call(`/api/documents/${id}/file?kind=signed`, { method: 'GET' });
  assert.equal(signed.status, 200);
  for (const tok of [ta, tb, tc]) assert.ok((await signer(`/api/sign/${tok}/file?download=1`, { method: 'GET' })).data.equals(signed.data));
});

test('a validly encrypted but substituted file fails the integrity check for owner and signer (500)', { skip: NEEDS_DISK }, async () => {
  const call = await owner();
  const id = await upload(call, await pdfBytes());
  const [ta] = await sendTwoSigner(call, id);
  const other = await PDFDocument.create(); other.addPage([612, 792]); other.setTitle('Forged');
  fs.writeFileSync(path.join(FILES, `${id}.original.pdf`), enc(Buffer.from(await other.save()), `file:${id}.original`));
  const own = await call(`/api/documents/${id}/file`, { method: 'GET' });
  assert.equal(own.status, 500);
  assert.equal(own.data.error, 'File integrity check failed');
  const sig = await signer(`/api/sign/${ta}/file`, { method: 'GET' });
  assert.equal(sig.status, 500);
  assert.equal(sig.data.error, 'File integrity check failed');
  const d = db();
  try {
    assert.ok(d.prepare("SELECT COUNT(*) n FROM security_events WHERE type = 'file_integrity_failure' AND detail = ?").get(`document ${id} original`).n >= 2);
  } finally { d.close(); }
});

test('delete removes the encrypted files and .tmp leftovers', { skip: NEEDS_DISK }, async () => {
  const call = await owner();
  const id = await upload(call, await pdfBytes());
  const f = path.join(FILES, `${id}.original.pdf`);
  fs.writeFileSync(f + '.tmp', 'leftover');
  assert.equal((await call(`/api/documents/${id}`, { method: 'DELETE' })).status, 200);
  assert.ok(!fs.existsSync(f) && !fs.existsSync(f + '.tmp'));
});
