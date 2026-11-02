// End-to-end check of the signing workflow over HTTP. Needs a running server:
//   BASE_URL=http://localhost:3000 npm test   (use a throwaway DATA_DIR with ALLOW_SIGNUP=true)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PDFDocument } from 'pdf-lib';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

function client() {
  let cookie = '';
  return async (path, { method = 'POST', body, headers = {} } = {}) => {
    const raw = body instanceof Uint8Array;
    const res = await fetch(BASE + path, {
      method,
      headers: { ...(raw ? {} : { 'Content-Type': 'application/json' }), ...(cookie && { cookie }), ...headers },
      body: body == null ? undefined : raw ? body : JSON.stringify(body),
    });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    const type = res.headers.get('content-type') || '';
    return { status: res.status, data: type.includes('json') ? await res.json() : Buffer.from(await res.arrayBuffer()) };
  };
}

async function samplePdf(pages = 2) {
  const pdf = await PDFDocument.create();
  for (let i = 0; i < pages; i++) pdf.addPage([612, 792]);
  return pdf.save();
}

test('upload, route to two signers in order, sign, complete', async () => {
  const call = client();
  const email = `owner-${Date.now()}@example.com`;
  assert.equal((await call('/api/auth/signup', { body: { name: 'Owner One', email, password: 'correct horse' } })).status, 200);

  // Rejects non-PDF uploads
  const bad = await call('/api/documents', { body: new TextEncoder().encode('hello'), headers: { 'Content-Type': 'application/pdf' } });
  assert.equal(bad.status, 400);

  const up = await call('/api/documents', { body: await samplePdf(), headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'NDA.pdf' } });
  assert.equal(up.status, 201);
  const id = up.data.id;

  // Send fails without a signature field for each signer
  const draft = {
    title: 'NDA', sequential: true,
    recipients: [{ id: 'a', name: 'Ana Signer', email: 'ana@example.com', role: 'signer' }, { id: 'b', name: 'Ben Signer', email: 'ben@example.com', role: 'signer' }, { id: 'c', name: 'Cat Copy', email: 'cat@example.com', role: 'cc' }],
    fields: [{ recipientId: 'a', type: 'signature', page: 0, x: 0.1, y: 0.8, w: 0.3, h: 0.06 }, { recipientId: 'a', type: 'date', page: 0, x: 0.5, y: 0.8, w: 0.2, h: 0.03 }],
  };
  assert.equal((await call(`/api/documents/${id}`, { method: 'PUT', body: draft })).status, 200);
  const early = await call(`/api/documents/${id}/send`);
  assert.equal(early.status, 400);
  assert.match(early.data.error, /Ben Signer/);

  draft.fields.push({ recipientId: 'b', type: 'signature', page: 1, x: 0.1, y: 0.8, w: 0.3, h: 0.06 }, { recipientId: 'b', type: 'text', page: 1, x: 0.1, y: 0.7, w: 0.3, h: 0.03, required: true });
  await call(`/api/documents/${id}`, { method: 'PUT', body: draft });
  assert.equal((await call(`/api/documents/${id}/send`)).status, 200);

  // Read tokens through the detail page props is UI-only; pull them from the sign pages via the owner's HTML.
  const html = (await call(`/app/documents/${id}`, { method: 'GET' })).data.toString();
  const tokens = [...html.matchAll(/"token":"([\w-]+)"/g)].map((m) => m[1]);
  assert.equal(tokens.length, 3);
  const [ta, tb] = tokens;
  const signer = client();

  // Ben is second in order: cannot sign or see the file yet
  assert.equal((await signer(`/api/sign/${tb}/file`, { method: 'GET' })).status, 403);
  assert.equal((await signer(`/api/sign/${tb}`, { body: { values: {} } })).status, 409);

  // Ana must fill required fields
  assert.equal((await signer(`/api/sign/${ta}`, { body: { values: {} } })).status, 400);
  const anaPage = (await signer(`/sign/${ta}`, { method: 'GET' })).data.toString();
  const anaSig = anaPage.match(/"id":"([\w-]+)","type":"signature"[^}]*"mine":true/)[1];
  const r1 = await signer(`/api/sign/${ta}`, { body: { values: { [anaSig]: PNG } } });
  assert.deepEqual(r1.data, { status: 'sent' });

  const benPage = (await signer(`/sign/${tb}`, { method: 'GET' })).data.toString();
  const benSig = benPage.match(/"id":"([\w-]+)","type":"signature"[^}]*"mine":true/)[1];
  const benText = benPage.match(/"id":"([\w-]+)","type":"text"[^}]*"mine":true/)[1];
  // Signature must be a PNG data URL
  assert.equal((await signer(`/api/sign/${tb}`, { body: { values: { [benSig]: 'javascript:alert(1)', [benText]: 'x' } } })).status, 400);
  const r2 = await signer(`/api/sign/${tb}`, { body: { values: { [benSig]: PNG, [benText]: 'Acme Ltd' } } });
  assert.deepEqual(r2.data, { status: 'completed' });

  // Signed PDF has the original pages plus a certificate page
  const signed = await call(`/api/documents/${id}/file?kind=signed`, { method: 'GET' });
  assert.equal(signed.status, 200);
  // The certificate can span pages (seal block, long audit trail): 2 original pages + at least 1.
  const pages = (await PDFDocument.load(signed.data)).getPageCount();
  assert.ok(pages >= 2 + 1, `page count ${pages}`);

  // Another user cannot read the document
  const other = client();
  await other('/api/auth/signup', { body: { name: 'Other', email: `other-${Date.now()}@example.com`, password: 'correct horse' } });
  assert.equal((await other(`/api/documents/${id}/file`, { method: 'GET' })).status, 404);
});

test('cross-origin writes are rejected', async () => {
  const res = await fetch(`${BASE}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' }, body: '{}' });
  assert.equal(res.status, 403);
});
