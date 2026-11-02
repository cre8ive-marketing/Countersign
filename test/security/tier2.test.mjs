// Tier 2 security regressions (Raymond): contacts, CSV import, saved signatures, public verify, redirect after signing, email templates.
// Run against a FRESH disposable server (ALLOW_SIGNUP=true, SIGNUP_MAX_PER_HOUR=1000, explicit ENCRYPTION_KEY, no TRUST_PROXY):
//   ENCRYPTION_KEY=<same as server> DATA_DIR=<server's DATA_DIR> BASE_URL=http://localhost:3511 node --test test/security/tier2.test.mjs
// Email tests need SMTP_HOST, APP_URL and QA_SMTP_SINK_PORT in this env (server: SMTP_HOST=127.0.0.1 SMTP_PORT=<sink> APP_URL=<BASE_URL>);
// this file starts its own capturing sink on that port, so run it on a port nobody else uses. Without them they skip.
// The verify rate-limit test spends this client IP's 60 lookups per hour; it runs last.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import zlib from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';

const BASE = new URL(process.env.BASE_URL || 'http://localhost:3000');
const DATA_DIR = process.env.DATA_DIR;
const KEY = process.env.ENCRYPTION_KEY;
const needDb = !(DATA_DIR && KEY) && 'needs DATA_DIR and ENCRYPTION_KEY of the server under test';
const needMail = !(process.env.SMTP_HOST && process.env.APP_URL && process.env.QA_SMTP_SINK_PORT)
  && 'needs SMTP_HOST, APP_URL and QA_SMTP_SINK_PORT (server SMTP_HOST=127.0.0.1 SMTP_PORT=<sink> APP_URL=<BASE_URL>)';
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const rnd = () => crypto.randomBytes(5).toString('hex');

let _db;
const db = () => {
  if (!_db) { _db = new DatabaseSync(path.join(DATA_DIR, 'countersign.db')); _db.exec('PRAGMA busy_timeout = 5000'); }
  return _db;
};
const keyBytes = () => (/^[0-9a-fA-F]{64}$/.test(KEY.trim()) ? Buffer.from(KEY.trim(), 'hex') : Buffer.from(KEY.trim(), 'base64'));
const keyedHash = (info, data) => crypto.createHmac('sha256', Buffer.from(crypto.hkdfSync('sha256', keyBytes(), Buffer.alloc(0), 'countersign-' + info, 32))).update(data).digest('hex');

// Valid RGB PNG of w x h, distinct per seed, so two users' signatures are distinguishable.
function png(w = 2, h = 1, seed = 0) {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(zlib.crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2;
  const raw = Buffer.alloc((w * 3 + 1) * h, seed & 0xff);
  for (let y = 0; y < h; y++) raw[y * (w * 3 + 1)] = 0;
  const bytes = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
  return `data:image/png;base64,${bytes.toString('base64')}`;
}
const PNG = png(1, 1, 7);

function call(p, { method = 'GET', cookie, body, headers = {} } = {}) {
  const h = { ...headers };
  if (cookie) h.cookie = cookie;
  let b = body;
  if (b !== undefined && !Buffer.isBuffer(b) && typeof b !== 'string') { b = JSON.stringify(b); h['content-type'] = 'application/json'; }
  return new Promise((resolve, reject) => {
    const req = http.request({ host: BASE.hostname === 'localhost' ? '127.0.0.1' : BASE.hostname, port: BASE.port, path: p, method, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        let json; try { json = JSON.parse(buf.toString()); } catch {}
        resolve({ status: res.statusCode, headers: res.headers, buf, json, text: buf.toString('utf8'), setCookie: res.headers['set-cookie'] || [] });
      });
    });
    req.on('error', reject);
    req.end(b);
  });
}
const props = (html) => JSON.parse(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s.exec(html)[1]).props.pageProps;

async function signup(email = `t2-${rnd()}@example.com`, name = 'T2 Owner') {
  const r = await call('/api/auth/signup', { method: 'POST', body: { name, email, password: `pw-${rnd()}-${rnd()}` } });
  assert.equal(r.status, 200, r.text);
  return { email: email.toLowerCase(), name, cookie: r.setCookie.find((c) => c.startsWith('cs_session=')).split(';')[0] };
}
async function pdfBytes() {
  const pdf = await PDFDocument.create();
  pdf.addPage([612, 792]).drawText(`t2 ${rnd()}`, { x: 50, y: 700 });
  return Buffer.from(await pdf.save({ useObjectStreams: false }));
}
const sigF = (rid) => ({ recipientId: rid, type: 'signature', page: 0, x: 0.1, y: 0.1, w: 0.3, h: 0.06 });
async function upload(o, bytes, template = false) {
  const up = await call('/api/documents', { method: 'POST', cookie: o.cookie, body: bytes, headers: { 'content-type': 'application/pdf', 'x-file-name': 'T2.pdf', ...(template && { 'x-template': '1' }) } });
  assert.equal(up.status, 201, up.text);
  return up.json.id;
}
const save = (o, id, body) => call(`/api/documents/${id}`, { method: 'PUT', cookie: o.cookie, body: { title: 'T2', ...body } });
// One-signer draft; returns { id, sigId, bytes }.
async function draft(o, email, extra = {}) {
  const bytes = await pdfBytes();
  const id = await upload(o, bytes);
  const put = await save(o, id, { recipients: [{ id: 'a', name: 'Signer One', email, role: 'signer' }], fields: [sigF('a')], ...extra });
  assert.equal(put.status, 200, put.text);
  return { id, bytes, sigId: put.json.fields[0].id };
}
const send = (o, id) => call(`/api/documents/${id}/send`, { method: 'POST', cookie: o.cookie, body: {} });
async function tokenOf(o, id, email) {
  const p = props((await call(`/app/documents/${id}`, { cookie: o.cookie })).text);
  const r = p.recipients.find((x) => x.email === email.toLowerCase());
  return { rid: r.id, token: r.token };
}
const submit = (token, values, cookie) => call(`/api/sign/${token}`, { method: 'POST', body: { values }, cookie });
const signPage = (token, cookie) => call(`/sign/${token}`, { cookie });

// ---------- Contacts ----------

const contacts = (o, q = '', extra = '') => call(`/api/contacts?q=${encodeURIComponent(q)}${extra}`, { cookie: o.cookie });
const addContact = (o, name, email) => call('/api/contacts', { method: 'POST', cookie: o.cookie, body: { name, email } });
const importCsv = (o, text, headers = {}) => call('/api/contacts/import', { method: 'POST', cookie: o.cookie, body: Buffer.from(text), headers: { 'content-type': 'text/csv', ...headers } });

test('contacts: another owner cannot list, edit or delete them (IDOR); anonymous gets 401', async () => {
  const a = await signup(), b = await signup();
  const made = await addContact(a, 'Alice Private', 'alice.private@example.com');
  assert.equal(made.status, 201, made.text);
  const id = made.json.id;
  assert.equal((await contacts(b, 'alice')).json.total, 0);
  assert.equal((await contacts(b)).json.contacts.some((c) => c.id === id), false);
  const put = await call(`/api/contacts/${id}`, { method: 'PUT', cookie: b.cookie, body: { name: 'Owned', email: 'owned@example.com' } });
  const del = await call(`/api/contacts/${id}`, { method: 'DELETE', cookie: b.cookie });
  assert.deepEqual([put.status, del.status], [404, 404]);
  assert.deepEqual((await contacts(a, 'alice')).json.contacts, [{ id, name: 'Alice Private', email: 'alice.private@example.com' }]);
  // B's import of the same email lands in B's book only.
  assert.deepEqual((await importCsv(b, 'Mallory,alice.private@example.com\n')).json, { added: 1, updated: 0, skipped: 0 });
  assert.equal((await contacts(a, 'alice')).json.contacts[0].name, 'Alice Private');
  for (const [m, p] of [['GET', '/api/contacts'], ['POST', '/api/contacts'], ['PUT', `/api/contacts/${id}`], ['DELETE', `/api/contacts/${id}`], ['POST', '/api/contacts/import']]) {
    assert.equal((await call(p, { method: m, body: m === 'GET' || m === 'DELETE' ? undefined : {} })).status, 401, `${m} ${p}`);
  }
});

test('contacts: q is a literal substring (LIKE wildcards and escapes are escaped); limit and offset are clamped', async () => {
  const a = await signup();
  for (const [n, e] of [['100% Corp', 'pct@example.com'], ['Plain Co', 'plain@example.com'], ['Under_score', 'u_s@example.com'], ['UnderXscore', 'uxs@example.com'], ['Back\\slash', 'bs@example.com']]) {
    assert.equal((await addContact(a, n, e)).status, 201);
  }
  const names = async (q) => (await contacts(a, q)).json.contacts.map((c) => c.name).sort();
  assert.deepEqual(await names('%'), ['100% Corp']);
  assert.deepEqual(await names('_'), ['Under_score']);
  assert.deepEqual(await names('r_s'), ['Under_score']);
  assert.deepEqual(await names('\\'), ['Back\\slash']);
  assert.deepEqual(await names("' OR 1=1 --"), []);
  assert.equal((await contacts(a, '', '&limit=100000')).json.contacts.length, 5);
  for (const extra of ['&limit=-5&offset=-9', '&limit=abc&offset=abc', '&limit=1e309', '&q=a&q=b']) {
    assert.equal((await call(`/api/contacts?${extra.slice(1)}`, { cookie: a.cookie })).status, 200, extra);
  }
  assert.equal((await contacts(a, 'x'.repeat(5000))).status, 200);
});

test('contacts: email is unique per owner ignoring case, on create, edit and import', async () => {
  const a = await signup();
  const first = await addContact(a, 'Case One', 'Case.Mix@Example.com');
  assert.equal(first.status, 201);
  const dup = await addContact(a, 'Case Two', 'case.mix@example.COM');
  assert.deepEqual([dup.status, dup.json.error], [409, 'A contact with this email already exists']);
  const other = await addContact(a, 'Other', 'other@example.com');
  const clash = await call(`/api/contacts/${other.json.id}`, { method: 'PUT', cookie: a.cookie, body: { name: 'Other', email: 'CASE.MIX@example.com' } });
  assert.equal(clash.status, 409);
  assert.deepEqual((await importCsv(a, 'name,email\nRenamed,CASE.MIX@EXAMPLE.COM\nRenamed again,case.mix@example.com\n')).json, { added: 0, updated: 2, skipped: 0 });
  assert.equal((await contacts(a, 'case.mix')).json.total, 1);
  // T2-4: ,;<>"()[]\ and whitespace are refused (x@evil.example,y.com would be read by nodemailer as another address).
  const badEmails = ['x@evil.example,y.com', 'x;y@example.com', 'x<y>@example.com', '"x"@example.com', 'x(y)@example.com', 'x[y]@example.com', 'x\\y@example.com', 'x y@example.com', 'x@exa\tmple.com'];
  for (const bad of [{ name: '', email: 'x@example.com' }, { name: 'X', email: 'not-an-email' }, { name: ['X'], email: 'x@example.com' }, { name: 'X', email: { $ne: 1 } }, ...badEmails.map((email) => ({ name: 'X', email }))]) {
    assert.equal((await call('/api/contacts', { method: 'POST', cookie: a.cookie, body: bad })).status, 400, JSON.stringify(bad));
  }
  assert.deepEqual((await importCsv(a, 'name,email\nComma,"x@evil.example,y.com"\n')).json, { added: 0, updated: 0, skipped: 1 });
});

test('contacts: at most 10,000 per owner (T2-7), on create and import; other owners unaffected', async () => {
  const a = await signup(), b = await signup();
  for (let batch = 0; batch < 5; batch++) {
    const csv = Array.from({ length: 2000 }, (_, i) => `N${batch}-${i},cap${batch}-${i}@example.com`).join('\n');
    assert.deepEqual((await importCsv(a, csv)).json, { added: 2000, updated: 0, skipped: 0 }, `batch ${batch}`);
  }
  assert.equal((await contacts(a)).json.total, 10000);
  const over = await addContact(a, 'One Too Many', 'over@example.com');
  assert.deepEqual([over.status, over.json.error], [400, 'You have reached the limit of 10,000 contacts']);
  // Import over the cap: refused (400) or nothing added; either way the total stays at 10,000.
  const overImport = await importCsv(a, 'Over,over2@example.com\n');
  assert.ok(overImport.status === 400 || overImport.json?.added === 0, `${overImport.status} ${overImport.text}`);
  assert.equal((await contacts(a)).json.total, 10000);
  assert.equal((await addContact(b, 'Fine', 'fine@example.com')).status, 201);
});

test('CSV import: size, row and quote limits; wrong type and cross-origin refused; hostile inputs finish fast', async () => {
  const a = await signup();
  assert.equal((await importCsv(a, 'a,b@example.com', { 'content-type': 'text/plain' })).status, 415);
  assert.equal((await importCsv(a, 'a,b@example.com', { origin: 'https://evil.example' })).status, 403);
  assert.equal((await importCsv(a, 'x'.repeat(1048577))).status, 413);
  const rows = (n) => Array.from({ length: n }, (_, i) => `N${i},r${i}@example.com`).join('\n');
  assert.equal((await importCsv(a, rows(2001))).status, 400);
  assert.equal((await importCsv(a, `name,email\n${rows(2000)}`)).json.added, 2000);
  assert.equal((await importCsv(a, 'Open,"never@closed.example\n')).status, 400);
  const hostile = [
    '"'.repeat(1048000), // quote bomb: alternating open/escaped quotes
    `"${'""'.repeat(500000)}",q@example.com`, // one huge quoted field
    ','.repeat(1048000), // one row with a million columns
    '\n'.repeat(1048000), // only blank lines
    `${'n'.repeat(1040000)},huge@example.com`, // huge unquoted name
  ];
  for (const h of hostile) {
    const t0 = Date.now();
    const r = await importCsv(a, h);
    assert.ok([200, 400].includes(r.status), `${r.status} ${r.text.slice(0, 120)}`);
    assert.ok(Date.now() - t0 < 5000, `took ${Date.now() - t0} ms`);
  }
  // The huge name is cut to 120 characters, not stored whole.
  const huge = (await contacts(a, 'huge@example.com')).json.contacts[0];
  assert.equal(huge.name.length, 120);
  // Header in either order; column mapping is by header name.
  assert.deepEqual((await importCsv(a, 'Email,Name\nswap@example.com,Swapped\n')).json, { added: 1, updated: 0, skipped: 0 });
  assert.equal((await contacts(a, 'swap@')).json.contacts[0].name, 'Swapped');
});

// ---------- Saved signatures ----------

test('saved signature: PUT runs the full PNG checks; GET is private, no-store and per user', async () => {
  const a = await signup(), b = await signup();
  const bad = [
    'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=',
    'data:image/png;base64,' + Buffer.from('<script>alert(1)</script>').toString('base64'),
    png(4001, 1),
    png(2001, 2001),
    'data:image/png;base64,' + 'A'.repeat(400_001),
    PNG.replace('iVBOR', 'iVBOR%%'),
    { toString: () => PNG },
  ];
  for (const value of bad) assert.equal((await call('/api/signatures', { method: 'PUT', cookie: a.cookie, body: { kind: 'signature', value } })).status, 400, String(value).slice(0, 40));
  assert.equal((await call('/api/signatures', { method: 'PUT', cookie: a.cookie, body: { kind: '__proto__', value: PNG } })).status, 400);
  assert.equal((await call('/api/signatures', { method: 'PUT', cookie: a.cookie, body: { kind: 'signature', value: PNG } })).status, 200);
  const mine = await call('/api/signatures', { cookie: a.cookie });
  assert.equal(mine.json.signature, PNG);
  assert.match(mine.headers['cache-control'], /no-store/);
  assert.deepEqual((await call('/api/signatures', { cookie: b.cookie })).json, { signature: null, initials: null });
  assert.equal((await call('/api/signatures', { method: 'PUT', body: { kind: 'signature', value: PNG } })).status, 401);
  assert.equal((await call('/api/signatures', { method: 'DELETE', cookie: a.cookie, headers: { origin: 'https://evil.example' } })).status, 403);
});

test('saved signature: stored encrypted; AAD binds it to user and kind (a moved ciphertext is refused, not shown)', { skip: needDb }, async () => {
  const a = await signup(), b = await signup();
  const sigA = png(3, 1, 11);
  assert.equal((await call('/api/signatures', { method: 'PUT', cookie: a.cookie, body: { kind: 'signature', value: sigA } })).status, 200);
  assert.equal((await call('/api/signatures', { method: 'PUT', cookie: b.cookie, body: { kind: 'signature', value: png(3, 1, 22) } })).status, 200);
  const uid = (o) => db().prepare('SELECT id FROM users WHERE email = ?').get(o.email).id;
  const rowA = db().prepare("SELECT value FROM user_signatures WHERE user_id = ? AND kind = 'signature'").get(uid(a));
  assert.ok(!rowA.value.includes(sigA.slice(22)), 'stored in plaintext');
  db().prepare("UPDATE user_signatures SET value = ? WHERE user_id = ? AND kind = 'signature'").run(rowA.value, uid(b));
  const moved = await call('/api/signatures', { cookie: b.cookie });
  assert.notEqual(moved.status, 200, 'B decrypted A\'s ciphertext');
  assert.ok(!moved.text.includes(sigA));
  db().prepare("INSERT INTO user_signatures (user_id, kind, value, updated_at) VALUES (?, 'initials', ?, ?)").run(uid(a), rowA.value, new Date().toISOString());
  assert.notEqual((await call('/api/signatures', { cookie: a.cookie })).status, 200, 'signature ciphertext accepted as initials');
});

test('saved signature on the sign page: only to the signed-in account with the recipient email, verified, while signing', { skip: needDb }, async () => {
  const a = await signup(`T2-Match-${rnd()}@Example.com`), b = await signup(), c = await signup();
  const sigA = png(3, 1, 33), sigB = png(3, 1, 44);
  await call('/api/signatures', { method: 'PUT', cookie: a.cookie, body: { kind: 'signature', value: sigA } });
  await call('/api/signatures', { method: 'PUT', cookie: b.cookie, body: { kind: 'signature', value: sigB } });
  // B (another account) sends to A's address in different case: the cross-account case. A sees only A's own data.
  const d = await draft(b, a.email.toUpperCase());
  assert.equal((await send(b, d.id)).status, 200);
  const { rid, token } = await tokenOf(b, d.id, a.email);
  const saved = async (cookie) => { const r = await signPage(token, cookie); assert.equal(r.status, 200); const p = props(r.text); return [p.savedSignature ?? null, r.text.includes(sigB)]; };
  assert.deepEqual(await saved(a.cookie), [sigA, false]);
  assert.deepEqual(await saved(b.cookie), [null, false], 'the sender (not the recipient) gets nothing, not even their own');
  assert.deepEqual(await saved(c.cookie), [null, false]);
  assert.deepEqual(await saved(undefined), [null, false]);
  assert.match((await signPage(token, a.cookie)).headers['cache-control'] || '', /no-store|private/);
  // Email code required and not verified: nothing, even for the matching account.
  db().prepare('UPDATE documents SET require_otp = 1 WHERE id = ?').run(d.id);
  const gated = props((await signPage(token, a.cookie)).text);
  assert.deepEqual([gated.state, gated.savedSignature ?? null], ['verify', null]);
  db().prepare('UPDATE recipients SET otp_hash = ?, otp_expires_at = ?, otp_attempts = 0 WHERE id = ?').run(keyedHash('otp', `${rid}:123456`), new Date(Date.now() + 6e5).toISOString(), rid);
  const v = await call(`/api/sign/${token}/otp`, { method: 'POST', body: { action: 'verify', code: '123456' } });
  assert.equal(v.status, 200, v.text);
  const otp = v.setCookie.find((x) => x.startsWith(`cs_otp_${rid}=`)).split(';')[0];
  assert.equal(props((await signPage(token, `${a.cookie}; ${otp}`)).text).savedSignature, sigA);
  assert.equal(props((await signPage(token, `${c.cookie}; ${otp}`)).text).savedSignature ?? null, null);
  // After signing, status pages carry no saved signature.
  assert.equal((await submit(token, { [d.sigId]: sigA }, otp)).status, 200);
  assert.equal(props((await signPage(token, `${a.cookie}; ${otp}`)).text).savedSignature ?? null, null);
});

// ---------- Redirect after signing ----------

test('redirect URL: only https without credentials, 500 chars max, strings only; IDN shown as punycode', async () => {
  const o = await signup();
  const id = await upload(o, await pdfBytes());
  const stored = async (redirectUrl) => {
    const r = await save(o, id, { redirectUrl });
    return r.status === 200 ? db().prepare('SELECT redirect_url FROM documents WHERE id = ?').get(id).redirect_url : r.status;
  };
  for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'java\tscript:alert(1)', ' javascript:alert(1)', 'data:text/html,<script>alert(1)</script>',
    'vbscript:x', 'file:///etc/passwd', '//evil.example/x', '/relative', 'evil.example', 'https://user:pass@evil.example/', 'https://user@evil.example/',
    'https://%75ser@evil.example/', 'ftp://evil.example/', 'blob:https://x/1', `https://example.com/${'a'.repeat(490)}`,
    'http://evil.example/', 'HTTP://evil.example/', ' http://evil.example/', // T2-1: https only
    ['https://example.com/'], { href: 'https://example.com/' }, 42, true]) { // T2-1: non-string is 400, never cleared or stored
    assert.equal(needDb ? (await save(o, id, { redirectUrl: bad })).status : await stored(bad), 400, JSON.stringify(bad));
  }
  if (needDb) return;
  assert.equal(await stored('  HTTPS://Example.COM/Done?x=1#f  '), 'https://example.com/Done?x=1#f');
  assert.equal(await stored('https://еxample.com/'), 'https://xn--xample-2of.com/'); // Cyrillic "е": the page shows the punycode host
  assert.equal(await stored(['javascript:alert(1)']), 400);
  assert.equal(db().prepare('SELECT redirect_url FROM documents WHERE id = ?').get(id).redirect_url, 'https://xn--xample-2of.com/', 'a refused non-string changed the stored value');
  assert.equal(await stored(''), null);
});

test('redirect URL: never revealed before the email code; only in the submit response; referrer is not leaked', { skip: needDb }, async () => {
  const o = await signup();
  const email = `r-${rnd()}@example.com`;
  const host = `after-${rnd()}.example`;
  const d = await draft(o, email, { redirectUrl: `https://${host}/thanks` });
  assert.equal((await send(o, d.id)).status, 200);
  const { rid, token } = await tokenOf(o, d.id, email);
  db().prepare('UPDATE documents SET require_otp = 1 WHERE id = ?').run(d.id);
  const page = await signPage(token);
  assert.equal(page.text.includes(host), false, 'redirect host in the page before verification');
  assert.equal(page.headers['referrer-policy'], 'same-origin'); // the token in /sign/<token> never goes to the redirect host
  const early = await submit(token, { [d.sigId]: PNG });
  assert.equal(early.status, 403);
  assert.equal(early.text.includes(host), false);
  db().prepare('UPDATE recipients SET otp_hash = ?, otp_expires_at = ?, otp_attempts = 0 WHERE id = ?').run(keyedHash('otp', `${rid}:654321`), new Date(Date.now() + 6e5).toISOString(), rid);
  const otp = (await call(`/api/sign/${token}/otp`, { method: 'POST', body: { action: 'verify', code: '654321' } })).setCookie.find((x) => x.startsWith(`cs_otp_${rid}=`)).split(';')[0];
  assert.equal((await signPage(token, otp)).text.includes(host), false, 'redirect host in the verified page props');
  const ok = await submit(token, { [d.sigId]: PNG }, otp);
  assert.deepEqual(ok.json, { status: 'completed', redirectUrl: `https://${host}/thanks` });
  // Without a redirect the old shape is unchanged.
  const e2 = `n-${rnd()}@example.com`;
  const d2 = await draft(o, e2);
  await send(o, d2.id);
  assert.deepEqual((await submit((await tokenOf(o, d2.id, e2)).token, { [d2.sigId]: PNG })).json, { status: 'completed' });
});

// ---------- Email templates (storage) ----------

test('email templates: CR/LF stripped from subject, lengths enforced, per user, reset works, auth and origin enforced', async () => {
  const a = await signup(), b = await signup();
  const put = (o, body, headers) => call('/api/email-templates', { method: 'PUT', cookie: o.cookie, body, headers });
  assert.equal((await put(a, { kind: 'invite', subject: 'Hi\r\nBcc: victim@example.com\n\nX', body: 'Body' })).status, 200);
  const got = (await call('/api/email-templates', { cookie: a.cookie })).json;
  assert.equal(/[\r\n]/.test(got.invite.subject), false);
  assert.equal(got.invite.custom, true);
  assert.equal((await call('/api/email-templates', { cookie: b.cookie })).json.invite.custom, false, 'A\'s template visible to B');
  for (const bad of [{ kind: 'invite', subject: 'x'.repeat(201), body: 'b' }, { kind: 'invite', subject: 's', body: 'b'.repeat(4001) },
    { kind: 'invite', subject: ' \r\n ', body: 'b' }, { kind: 'invite', subject: 's', body: ['b'] }, { kind: 'owner', subject: 's', body: 'b' }, { kind: 'constructor', subject: 's', body: 'b' }]) {
    assert.equal((await put(a, bad)).status, 400, JSON.stringify(bad).slice(0, 60));
  }
  assert.equal((await put(a, { kind: 'completed', subject: 's', body: 'b' }, { origin: 'https://evil.example' })).status, 403);
  assert.equal((await call('/api/email-templates', { method: 'PUT', body: { kind: 'invite', subject: 's', body: 'b' } })).status, 401);
  assert.equal((await call('/api/email-templates?kind=invite', { method: 'DELETE', cookie: a.cookie })).status, 200);
  assert.equal((await call('/api/email-templates', { cookie: a.cookie })).json.invite.custom, false);
});

// ---------- Email templates (rendered mail, SMTP sink) ----------

// Capturing SMTP sink: records envelope recipients and the raw DATA of each message.
function smtpSink(port) {
  const mails = [];
  const server = net.createServer((s) => {
    let data = false, buf = '', cur = { rcpt: [], raw: '' };
    s.write('220 sink\r\n');
    s.on('data', (c) => {
      buf += c.toString('latin1');
      for (;;) {
        if (data) {
          const end = buf.indexOf('\r\n.\r\n'); if (end < 0) break;
          cur.raw = buf.slice(0, end); buf = buf.slice(end + 5); data = false; mails.push(cur); cur = { rcpt: [], raw: '' }; s.write('250 ok\r\n'); continue;
        }
        const i = buf.indexOf('\r\n'); if (i < 0) break;
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === 'EHLO' || cmd === 'HELO') s.write('250 sink\r\n');
        else if (cmd === 'RCPT') { cur.rcpt.push(line.slice(8).trim()); s.write('250 ok\r\n'); }
        else if (cmd === 'DATA') { data = true; s.write('354 go\r\n'); }
        else if (cmd === 'QUIT') s.end('221 bye\r\n');
        else s.write('250 ok\r\n');
      }
    });
    s.on('error', () => {});
  });
  return new Promise((r) => server.listen(port, '127.0.0.1', () => r({ mails, close: () => server.close() })));
}
// Headers unfolded; bodies decoded from quoted-printable or base64 so assertions see the real text.
function parseMail(raw) {
  const [head, ...rest] = raw.split('\r\n\r\n');
  const headers = head.replace(/\r\n[ \t]+/g, ' ').split('\r\n');
  const decodeWords = (v) => v.replace(/=\?utf-8\?([QB])\?([^?]*)\?=/gi, (_, enc, t) => (enc.toUpperCase() === 'B' ? Buffer.from(t, 'base64').toString() : Buffer.from(t.replace(/_/g, ' ').replace(/=([0-9A-F]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))), 'latin1').toString()));
  const subject = decodeWords(headers.find((h) => /^subject:/i.test(h))?.slice(8).trim() || '').replace(/\?=\s+=\?/g, '');
  const parts = rest.join('\r\n\r\n').split(/\r\n--[^\r\n]+/).map((p) => {
    const [ph, ...pb] = p.split('\r\n\r\n');
    let body = pb.join('\r\n\r\n');
    if (/content-transfer-encoding:\s*quoted-printable/i.test(ph)) body = Buffer.from(body.replace(/=\r\n/g, '').replace(/=([0-9A-F]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))), 'latin1').toString();
    else if (/content-transfer-encoding:\s*base64/i.test(ph)) body = Buffer.from(body.replace(/\s+/g, ''), 'base64').toString();
    return { type: /content-type:\s*([^;\r\n]+)/i.exec(ph)?.[1]?.toLowerCase(), body };
  });
  return { headers, subject, html: parts.find((p) => p.type === 'text/html')?.body || '', text: parts.find((p) => p.type === 'text/plain')?.body || '' };
}

test('email templates: no header injection, HTML escaped, no variable re-expansion, button always added, templates never cross owners', { skip: needDb || needMail }, async () => {
  const sink = await smtpSink(Number(process.env.QA_SMTP_SINK_PORT));
  try {
    const a = await signup(undefined, 'Alice <b>Sender</b>'), b = await signup(undefined, 'Bob Plain');
    const tpl = { kind: 'invite', subject: 'TPL-A {{document_title}} {{constructor}} {{__proto__}}', body: '<a href="https://evil.example">click</a> {{message}} {{receiver_name}} {{sender_name}}' };
    assert.equal((await call('/api/email-templates', { method: 'PUT', cookie: a.cookie, body: tpl })).status, 200);
    assert.equal((await call('/api/email-templates', { method: 'PUT', cookie: a.cookie, body: { kind: 'completed', subject: 'DONE-A {{document_title}}', body: 'Finished.' } })).status, 200);
    const victim = `victim-${rnd()}@example.com`, to = `inv-${rnd()}@example.com`;
    const d = await draft(a, to, { title: `T\r\nBcc: ${victim}\r\n{{sender_email}}`, message: '<img src=x onerror=alert(1)> {{sender_email}}' });
    db().prepare("UPDATE recipients SET name = '<script>alert(2)</script>' WHERE document_id = ?").run(d.id);
    assert.equal((await send(a, d.id)).status, 200);
    const inv = sink.mails.filter((m) => m.rcpt.some((r) => r.includes(to)));
    assert.equal(inv.length, 1, 'one invitation');
    assert.equal(sink.mails.some((m) => m.rcpt.some((r) => r.includes(victim)) || m.raw.includes(victim) && /^bcc:/im.test(m.raw)), false, 'header injection reached a Bcc');
    const m = parseMail(inv[0].raw);
    assert.equal(m.headers.some((h) => /^bcc:/i.test(h)), false);
    assert.match(m.subject, /^TPL-A T /);
    assert.ok(m.subject.includes('{{sender_email}}') && m.subject.includes('{{constructor}}') && m.subject.includes('{{__proto__}}'), m.subject);
    assert.equal(m.subject.includes(a.email), false, 're-expanded a variable inside a value');
    for (const raw of ['<a href="https://evil.example">', '<img src=x', '<script>', '<b>Sender</b>']) assert.equal(m.html.includes(raw), false, `unescaped ${raw}`);
    assert.ok(m.html.includes('&#60;img src=x onerror=alert(1)&#62;'), 'message not escaped as expected');
    const { token } = await tokenOf(a, d.id, to);
    assert.ok(m.html.includes(`/sign/${token}`) && m.text.includes(`/sign/${token}`), 'action link missing');
    // B's invitation uses the default, never A's template.
    const toB = `invb-${rnd()}@example.com`;
    const db2 = await draft(b, toB, { title: 'Bob Doc' });
    assert.equal((await send(b, db2.id)).status, 200);
    const mb = parseMail(sink.mails.find((x) => x.rcpt.some((r) => r.includes(toB))).raw);
    assert.equal(mb.subject, 'Bob Plain sent you "Bob Doc" to sign');
    // Completion mail for A's recipient uses A's completed template plus the system download button.
    sink.mails.length = 0;
    assert.equal((await submit(token, { [d.sigId]: PNG })).status, 200);
    const done = sink.mails.find((x) => x.rcpt.some((r) => r.includes(to)));
    const md = parseMail(done.raw);
    assert.match(md.subject, /^DONE-A T /);
    assert.ok(md.html.includes(`/sign/${token}`), 'download link missing');
  } finally { sink.close(); }
});

// ---------- Public verify (rate-limit test last) ----------

const verifyHash = (h, headers) => call(`/api/verify?sha256=${encodeURIComponent(h)}`, { headers });

test('verify: a signed copy shows title, date and signer names only; an original only that it matched; templates, deleted and unknown never match', { skip: needDb }, async () => {
  for (const bad of ['', 'abc', 'g'.repeat(64), `${'a'.repeat(64)}0`, "' OR 1=1 --"]) assert.equal((await verifyHash(bad)).status, 400, bad);
  assert.equal((await call('/api/verify?sha256=a&sha256=b')).status, 400);
  const o = await signup();
  const email = `v-${rnd()}@example.com`;
  const d = await draft(o, email, { title: 'Verify Title', message: 'Secret message' });
  assert.equal((await send(o, d.id)).status, 200);
  const { token } = await tokenOf(o, d.id, email);
  const sentOrig = await verifyHash(sha(d.bytes).toUpperCase());
  assert.deepEqual(sentOrig.json, { match: 'original' }); // T2-3: no status
  assert.match(sentOrig.headers['cache-control'], /no-store/);
  assert.equal((await submit(token, { [d.sigId]: PNG })).status, 200);
  const signedSha = db().prepare('SELECT signed_sha256 FROM documents WHERE id = ?').get(d.id).signed_sha256;
  const v = (await verifyHash(signedSha)).json;
  assert.deepEqual(Object.keys(v).sort(), ['completedAt', 'match', 'signers', 'title']); // T2-9: no constant sealed flag
  assert.deepEqual(v.signers.map((s) => Object.keys(s).sort()), [['name', 'signedAt']]);
  const flat = JSON.stringify(v);
  for (const secret of [email, o.email, d.id, token, 'Secret message']) assert.equal(flat.includes(secret), false, `leaks ${secret}`);
  assert.deepEqual((await verifyHash(sha(d.bytes))).json, { match: 'original' });
  // Template originals are excluded; a deleted draft no longer matches.
  const tb = await pdfBytes();
  await upload(o, tb, true);
  assert.deepEqual((await verifyHash(sha(tb))).json, { match: null });
  const gone = await pdfBytes();
  const gid = await upload(o, gone);
  assert.deepEqual((await verifyHash(sha(gone))).json, { match: 'original' });
  assert.equal((await call(`/api/documents/${gid}`, { method: 'DELETE', cookie: o.cookie })).status, 200);
  assert.deepEqual((await verifyHash(sha(gone))).json, { match: null });
  assert.deepEqual((await verifyHash(sha(Buffer.from(rnd())))).json, { match: null });
});

test('verify: 60 lookups per hour per client IP, then 429 with Retry-After; X-Forwarded-For does not reset it without TRUST_PROXY', async () => {
  let r;
  for (let i = 0; i < 70; i++) {
    r = await verifyHash(sha(Buffer.from(String(i))));
    if (r.status === 429) break;
  }
  assert.equal(r.status, 429, 'never limited');
  assert.ok(Number(r.headers['retry-after']) > 0);
  const spoof = await verifyHash(sha(Buffer.from('x')), { 'x-forwarded-for': `203.0.113.${Math.floor(Math.random() * 250)}` });
  assert.equal(spoof.status, 429, 'X-Forwarded-For bypassed the limit');
});
