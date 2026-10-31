// Security regression tests (Raymond). Needs a running server with a throwaway DATA_DIR and ALLOW_SIGNUP=true:
//   BASE_URL=http://localhost:3401 node --test test/security/
// Optional: SMTP_SINK_PORT=<port> when the server runs with SMTP_HOST=127.0.0.1 SMTP_PORT=<port> and no APP_URL.
// Each test asserts the secure behaviour; the Host-header tests are regressions for fixed issues.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { PDFDocument } from 'pdf-lib';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const U = new URL(BASE);
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

// node:http so Host and Origin can be set exactly as an attacker would.
function raw(path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: U.hostname, port: U.port, path, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.end(body);
  });
}
const json = (o, extra = {}) => ({ headers: { 'Content-Type': 'application/json', ...extra }, body: JSON.stringify(o) });

async function owner() {
  const email = `sec-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  const r = await raw('/api/auth/signup', { method: 'POST', ...json({ name: 'Sec Owner', email, password: 'correct horse' }) });
  assert.equal(r.status, 200);
  return { email, cookie: r.headers['set-cookie'][0].split(';')[0] };
}

// Owner with a sent two-signer sequential document; returns ids and tokens.
async function sentDoc() {
  const o = await owner();
  const pdf = await PDFDocument.create(); pdf.addPage([612, 792]);
  const up = await raw('/api/documents', { method: 'POST', headers: { cookie: o.cookie, 'Content-Type': 'application/pdf', 'x-file-name': 'Sec.pdf' }, body: Buffer.from(await pdf.save()) });
  assert.equal(up.status, 201);
  const id = JSON.parse(up.body).id;
  const draft = {
    title: 'Sec', sequential: true,
    recipients: [{ id: 'a', name: 'Ana', email: 'ana@example.com', role: 'signer' }, { id: 'b', name: 'Ben', email: 'ben@example.com', role: 'signer' }],
    fields: [{ recipientId: 'a', type: 'signature', page: 0, x: 0.1, y: 0.8, w: 0.3, h: 0.06 }, { recipientId: 'b', type: 'signature', page: 0, x: 0.5, y: 0.8, w: 0.3, h: 0.06 }],
  };
  assert.equal((await raw(`/api/documents/${id}`, { method: 'PUT', ...json(draft, { cookie: o.cookie }) })).status, 200);
  assert.equal((await raw(`/api/documents/${id}/send`, { method: 'POST', headers: { cookie: o.cookie } })).status, 200);
  const html = (await raw(`/app/documents/${id}`, { headers: { cookie: o.cookie } })).body.toString();
  const tokens = [...html.matchAll(/"token":"([\w-]+)"/g)].map((m) => m[1]);
  assert.equal(tokens.length, 2);
  return { ...o, id, tokens };
}

const BASELINE = { 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'same-origin', 'cross-origin-opener-policy': 'same-origin' };
function assertHeaders(h, label) {
  for (const [k, v] of Object.entries(BASELINE)) assert.equal(h[k], v, `${label}: ${k}`);
  assert.match(h['content-security-policy'] || '', /frame-ancestors 'none'/, `${label}: frame-ancestors`);
  assert.match(h['content-security-policy'] || '', /object-src 'none'/, `${label}: object-src`);
  assert.equal(h['x-powered-by'], undefined, `${label}: x-powered-by`);
}

test('security headers on HTML, API, sign page and both PDF endpoints; PDFs are private, no-store', async () => {
  const d = await sentDoc();
  for (const p of ['/', '/login', '/robots.txt', '/api/auth/session', `/sign/${d.tokens[0]}`]) assertHeaders((await raw(p)).headers, p);
  const own = await raw(`/api/documents/${d.id}/file`, { headers: { cookie: d.cookie } });
  assert.equal(own.status, 200);
  assert.equal(own.headers['content-type'], 'application/pdf');
  assert.match(own.headers['cache-control'], /no-store/);
  assertHeaders(own.headers, 'owner pdf');
  const sig = await raw(`/api/sign/${d.tokens[0]}/file`);
  assert.equal(sig.status, 200);
  assert.match(sig.headers['cache-control'], /no-store/);
  assertHeaders(sig.headers, 'signer pdf');
});

test('session endpoint exposes only {user:{name,email}|null, signupOpen}, is not cacheable, and is no email oracle', async () => {
  const anon = await raw('/api/auth/session?email=ana@example.com');
  assert.deepEqual(Object.keys(JSON.parse(anon.body)).sort(), ['signupOpen', 'user']);
  assert.equal(JSON.parse(anon.body).user, null, 'query parameters do not affect the answer');
  assert.match(anon.headers['cache-control'], /private/);
  assert.match(anon.headers['cache-control'], /no-store/);
  const o = await owner();
  const me = JSON.parse((await raw('/api/auth/session', { headers: { cookie: o.cookie } })).body);
  assert.deepEqual(Object.keys(me.user).sort(), ['email', 'name']);
  assert.equal((await raw('/api/auth/session', { method: 'POST', headers: { cookie: o.cookie } })).status, 405);
});

test('CSRF: writes with a foreign, null or malformed Origin are rejected; same origin is not', async () => {
  const body = json({ email: 'nobody@example.com', password: 'x' });
  for (const origin of ['https://evil.example', 'null', 'not a url', `http://${U.host}.evil.example`, 'http://evil.example:' + U.port]) {
    const r = await raw('/api/auth/login', { method: 'POST', ...body, headers: { ...body.headers, Origin: origin } });
    assert.equal(r.status, 403, origin);
  }
  const same = await raw('/api/auth/login', { method: 'POST', ...body, headers: { ...body.headers, Origin: BASE } });
  assert.notEqual(same.status, 403);
  // Authenticated write from a foreign origin, plus a spoofed X-Forwarded-Host (ignored unless TRUST_PROXY=true).
  const o = await owner();
  const r = await raw('/api/auth/logout', { method: 'POST', headers: { cookie: o.cookie, Origin: 'https://evil.example', 'X-Forwarded-Host': 'evil.example' } });
  // With TRUST_PROXY=true a direct client can forge X-Forwarded-Host; a browser cannot (custom header, CORS preflight).
  if (process.env.TRUST_PROXY === 'true') return;
  assert.equal(r.status, 403);
  assert.ok(JSON.parse((await raw('/api/auth/session', { headers: { cookie: o.cookie } })).body).user, 'session survives the blocked request');
});

test('X-Forwarded-Host / -Proto are ignored by robots.txt and sitemap.xml when TRUST_PROXY is not set', { skip: process.env.TRUST_PROXY === 'true' }, async () => {
  const h = { 'X-Forwarded-Host': 'evil.example', 'X-Forwarded-Proto': 'https' };
  const robots = (await raw('/robots.txt', { headers: h })).body.toString();
  const sitemap = (await raw('/sitemap.xml', { headers: h })).body.toString();
  assert.ok(!robots.includes('evil.example') && !sitemap.includes('evil.example'));
  assert.ok(!robots.includes('https://') && !sitemap.includes('<loc>https://'));
});

test('sitemap escapes a hostile Host header (no XML injection)', async () => {
  const r = await raw('/sitemap.xml', { headers: { Host: 'a&b' } });
  if (r.status !== 200) return; // Node rejected the Host itself, which is also fine
  assert.ok(!r.body.toString().includes('a&b/'), 'raw & must be escaped');
});

test('robots.txt/sitemap.xml never reflect an arbitrary Host into a publicly cacheable response', async () => {
  if (process.env.APP_URL_SET === 'true') return;
  const r = await raw('/robots.txt', { headers: { Host: 'evil.example' } });
  assert.ok(!(r.body.toString().includes('evil.example') && /public/.test(r.headers['cache-control'] || '')));
});

// Minimal SMTP sink: accepts any message and keeps the DATA payload.
function smtpSink(port) {
  const messages = [];
  const server = net.createServer((s) => {
    let data = false, buf = '';
    s.write('220 sink\r\n');
    s.on('data', (c) => {
      buf += c.toString('latin1');
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0 || (data && buf.includes('\r\n.\r\n'))) {
        if (data) { const end = buf.indexOf('\r\n.\r\n'); if (end < 0) break; messages.push(buf.slice(0, end)); buf = buf.slice(end + 5); data = false; s.write('250 ok\r\n'); continue; }
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === 'EHLO' || cmd === 'HELO') s.write('250 sink\r\n');
        else if (cmd === 'DATA') { data = true; s.write('354 go\r\n'); }
        else if (cmd === 'QUIT') { s.end('221 bye\r\n'); }
        else s.write('250 ok\r\n');
      }
    });
    s.on('error', () => {});
  });
  return new Promise((r) => server.listen(port, '127.0.0.1', () => r({ messages, close: () => server.close() })));
}

test('a signer cannot poison the next signer\'s emailed link via the Host header', {
  skip: !process.env.SMTP_SINK_PORT && 'needs SMTP_SINK_PORT and a server with SMTP_HOST=127.0.0.1, no APP_URL',
}, async () => {
  const sink = await smtpSink(Number(process.env.SMTP_SINK_PORT));
  try {
    const d = await sentDoc();
    const page = (await raw(`/sign/${d.tokens[0]}`)).body.toString();
    const sig = page.match(/"id":"([\w-]+)","type":"signature"[^}]*"mine":true/)[1];
    sink.messages.length = 0;
    // No Origin header: a non-browser client, so the origin check does not apply.
    const r = await raw(`/api/sign/${d.tokens[0]}`, { method: 'POST', ...json({ values: { [sig]: PNG } }, { Host: 'attacker.example' }) });
    assert.equal(r.status, 200);
    for (let i = 0; i < 50 && !sink.messages.length; i++) await new Promise((res) => setTimeout(res, 100));
    const mail = sink.messages.join('\n').replace(/=\r\n/g, '');
    // Without APP_URL the server refuses to email links at all (lib/mail.js), so nothing may reach the sink.
    assert.ok(!mail.includes('attacker.example'), 'emailed signing link must not use the attacker-supplied Host');
  } finally { sink.close(); }
});
