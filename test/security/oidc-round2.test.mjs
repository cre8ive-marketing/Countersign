// Second-round review of the SSO fixes: connect flow, OIDC_REQUIRED, webhook pause, public-copy cleanup.
// Needs FRESH disposable servers on one mock provider in this process. Without SSO2_BASE_URL and SSO2_MOCK_PORT every test skips.
// Common server env: OIDC_ISSUER=http://127.0.0.1:<P> OIDC_ALLOW_HTTP=true OIDC_CLIENT_ID=cs-sec OIDC_CLIENT_SECRET=cs-sec-secret
//   OIDC_ALLOWED_DOMAINS=allowed.test ALLOW_SIGNUP=true SIGNUP_MAX_PER_HOUR=1000 APP_URL=<its own url> ENCRYPTION_KEY=<64 hex>
// SSO2_BASE_URL: that env. SSO2_DATA_DIR and SSO2_ENCRYPTION_KEY: its DATA_DIR and key.
// SSO2_REQUIRED_BASE_URL: fresh server, plus OIDC_REQUIRED=true.
// SSO2_QUOTA_BASE_URL and SSO2_QUOTA_DATA_DIR: fresh server, plus STORAGE_QUOTA_MB=1, same key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';

const BASE = process.env.SSO2_BASE_URL;
const PORT = Number(process.env.SSO2_MOCK_PORT) || 0;
const DATA = process.env.SSO2_DATA_DIR;
const KEY = process.env.SSO2_ENCRYPTION_KEY;
const REQUIRED = process.env.SSO2_REQUIRED_BASE_URL;
const QUOTA = process.env.SSO2_QUOTA_BASE_URL;
const QUOTA_DATA = process.env.SSO2_QUOTA_DATA_DIR;
const NEEDS = (!BASE || !PORT) && 'needs SSO2_BASE_URL and SSO2_MOCK_PORT';
const NEEDS_DB = NEEDS || ((!DATA || !KEY) && 'needs SSO2_DATA_DIR and SSO2_ENCRYPTION_KEY');
const NEEDS_REQUIRED = NEEDS || (!REQUIRED && 'needs SSO2_REQUIRED_BASE_URL');
const NEEDS_QUOTA = NEEDS || ((!QUOTA || !QUOTA_DATA || !KEY) && 'needs SSO2_QUOTA_BASE_URL, SSO2_QUOTA_DATA_DIR and SSO2_ENCRYPTION_KEY');
const ISSUER = `http://127.0.0.1:${PORT}`;
const PASSWORD = 'correct horse battery';
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const JSON_HEADERS = { 'Content-Type': 'application/json' };
const rnd = () => crypto.randomBytes(5).toString('hex');
const newEmail = () => `u-${rnd()}@allowed.test`;
const newSub = () => `sub-${rnd()}`;
const codes = new Map();
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

let mock;
if (!NEEDS) {
  mock = http.createServer((req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    if (req.url === '/.well-known/openid-configuration') return send(200, { issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token` });
    if (req.url !== '/token') return send(404, {});
    tokenRequests += 1;
    let raw = '';
    req.on('data', (d) => { raw += d; });
    req.on('end', () => {
      const entry = codes.get(new URLSearchParams(raw).get('code'));
      if (!entry) return send(400, { error: 'invalid_grant' });
      return send(200, { id_token: `${b64({ alg: 'RS256' })}.${b64({ iss: ISSUER, aud: 'cs-sec', exp: Math.floor(Date.now() / 1000) + 300, nonce: entry.nonce, email_verified: true, ...entry.claims })}.sig` });
    });
    return undefined;
  });
  await new Promise((r) => mock.listen(PORT, '127.0.0.1', r));
}
test.after(() => mock?.close());
let tokenRequests = 0;

function browser(base = BASE) {
  const jar = {};
  const request = async (p, init = {}) => {
    const cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(base + p, { redirect: 'manual', ...init, headers: { ...(cookie ? { cookie } : {}), ...init.headers } });
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(';');
      const i = kv.indexOf('=');
      if (/Max-Age=0/.test(c)) delete jar[kv.slice(0, i)]; else jar[kv.slice(0, i)] = kv.slice(i + 1);
    }
    return res;
  };
  const json = async (p, method, body) => {
    const r = await request(p, { method, headers: JSON_HEADERS, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
  };
  return { jar, request, json };
}
async function signIn(b, claims) {
  const r = await b.request('/api/auth/oidc/start');
  assert.equal(r.status, 302);
  const auth = new URL(r.headers.get('location')).searchParams;
  const code = rnd();
  codes.set(code, { claims, nonce: auth.get('nonce') });
  return (await b.request(`/api/auth/oidc/callback?code=${code}&state=${encodeURIComponent(auth.get('state'))}`)).headers.get('location');
}
// Settings' Connect: a same-origin POST starts the flow.
async function connect(b, claims) {
  const auth = new URL((await b.json('/api/auth/oidc/connect', 'POST', {})).data.url).searchParams;
  const code = rnd();
  codes.set(code, { claims, nonce: auth.get('nonce') });
  return (await b.request(`/api/auth/oidc/callback?code=${code}&state=${encodeURIComponent(auth.get('state'))}`)).headers.get('location');
}
async function signUp(email = newEmail(), base = BASE) {
  const b = browser(base);
  const r = await b.json('/api/auth/signup', 'POST', { name: 'Someone', email, password: PASSWORD });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return Object.assign(b, { email });
}

// `pad` bytes of incompressible data, so copies reach a small quota quickly.
async function pdf(pad = 0) {
  const d = await PDFDocument.create();
  d.setTitle(rnd());
  d.addPage([612, 792]);
  if (pad) await d.attach(crypto.randomBytes(pad), 'pad.bin', { mimeType: 'application/octet-stream' });
  return d.save();
}
async function upload(b, { template = false, pad = 0 } = {}) {
  const r = await b.request('/api/documents', { method: 'POST', body: await pdf(pad), headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'S.pdf', ...(template && { 'x-template': '1' }) } });
  return { status: r.status, id: (await r.json()).id };
}
const fieldFor = (recipientId) => ({ recipientId, type: 'signature', page: 0, x: 0.1, y: 0.1, w: 0.3, h: 0.08 });
async function publicTemplate(b, pad = 0) {
  const { id, status } = await upload(b, { template: true, pad });
  assert.equal(status, 201);
  const put = await b.json(`/api/documents/${id}`, 'PUT', { title: `Tpl ${rnd()}`, recipients: [{ id: 'r0', name: 'Client', email: '', role: 'signer' }], fields: [fieldFor('r0')] });
  assert.equal(put.status, 200, JSON.stringify(put.data));
  const link = await b.json(`/api/documents/${id}/public`, 'POST', { enabled: true });
  assert.equal(link.status, 200, JSON.stringify(link.data));
  return { id, token: link.data.url.slice(3) };
}
const docIds = async (b) => (await b.json('/api/documents?template=0', 'GET')).data.documents.map((d) => d.id);
async function publicCopy(b, tpl, base = BASE) {
  const before = new Set(await docIds(b));
  const r = await fetch(`${base}/api/public-templates/${encodeURIComponent(tpl.token)}`, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ name: 'Visitor', email: `v-${rnd()}@example.com`, website: '' }) });
  const data = await r.json();
  assert.equal(r.status, 200, JSON.stringify(data));
  return { id: (await docIds(b)).find((d) => !before.has(d)), signToken: data.signUrl.split('/sign/')[1] };
}
const decline = (base, c) => fetch(`${base}/api/sign/${c.signToken}/decline`, { method: 'POST', headers: JSON_HEADERS, body: '{"reason":"no"}' });
async function sign(base, owner, c) {
  const { fields } = (await owner.json(`/api/documents/${c.id}`, 'GET')).data;
  return fetch(`${base}/api/sign/${c.signToken}`, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ values: Object.fromEntries(fields.map((f) => [f.id, PNG])) }) });
}
function withDb(fn, dir = DATA) {
  const db = new DatabaseSync(path.join(dir, 'countersign.db'));
  try { return fn(db); } finally { db.close(); }
}
// The hourly job's two steps, in a child process on the server's DATA_DIR. Returns the error text if the job threw.
function runJob(dir = DATA) {
  const root = path.resolve(import.meta.dirname, '..', '..');
  const code = `
    import { registerHooks } from 'node:module';
    registerHooks({ resolve(s, c, next) {
      try { return next(s, c); } catch (e) { if (/^\\.\\.?\\//.test(s) && !/\\.[cm]?js$/.test(s)) return next(s + '.js', c); throw e; }
    } });
    const d = await import(${JSON.stringify(pathToFileURL(path.join(root, 'lib', 'documents.js')).href)});
    await d.expireDueDocuments();
    d.deleteExpiredPublicCopies();`;
  try {
    execFileSync(process.execPath, ['--input-type=module', '-e', code], { cwd: root, encoding: 'utf8', timeout: 60_000, stdio: 'pipe',
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, DATA_DIR: dir, ENCRYPTION_KEY: KEY, NODE_NO_WARNINGS: '1' } });
    return null;
  } catch (e) {
    return String(e.stderr || e.message);
  }
}
const expire = (ids, dir) => withDb((db) => {
  const past = new Date(Date.now() - 5000).toISOString();
  for (const id of ids) db.prepare('UPDATE documents SET expires_at = ? WHERE id = ?').run(past, id);
}, dir);

// ---- Connect flow ----

test('SSO-1 holds: a session that has ended does not count as live for linking', { skip: NEEDS }, async () => {
  const email = newEmail();
  const owner = await signUp(email);
  const stale = owner.jar.cs_session;
  assert.equal((await owner.json('/api/auth/logout-all', 'POST', {})).status, 200);
  const b = browser();
  b.jar.cs_session = stale;
  assert.equal(await signIn(b, { sub: newSub(), email }), '/login?error=sso_link');
});

test('SSO-1 holds: an identity connected from a session opens that same account afterwards', { skip: NEEDS_DB }, async () => {
  const email = newEmail();
  const sub = newSub();
  const owner = await signUp(email);
  assert.equal(await connect(owner, { sub, email }), '/app/settings');
  const later = browser();
  assert.equal(await signIn(later, { sub, email }), '/app');
  const hash = crypto.createHash('sha256').update(later.jar.cs_session).digest('hex');
  assert.equal(withDb((db) => db.prepare('SELECT u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?').get(hash)?.email), email);
});

test('SSO-17: Connect with a provider address that has no account here does not move the person into a new account', { skip: NEEDS }, async () => {
  const a = await signUp();
  const session = a.jar.cs_session;
  assert.equal(await signIn(a, { sub: newSub(), email: newEmail() }), '/app/settings?sso=failed');
  assert.equal(a.jar.cs_session, session);
});

test('SSO-17: Connect with a provider identity already tied to another account does not switch accounts', { skip: NEEDS }, async () => {
  const sub = newSub();
  const email = newEmail();
  await signIn(browser(), { sub, email });
  const a = await signUp();
  const session = a.jar.cs_session;
  assert.equal(await signIn(a, { sub, email }), '/app/settings?sso=failed');
  assert.equal(a.jar.cs_session, session);
});

test('SSO-22: a sign-in flow any site can start does not connect a signed-in account', { skip: NEEDS }, async () => {
  const a = await signUp();
  const session = a.jar.cs_session;
  assert.equal(await signIn(a, { sub: newSub(), email: a.email }), '/app/settings?sso=failed');
  assert.equal(a.jar.cs_session, session);
  assert.equal((await browser().json('/api/auth/login', 'POST', { email: a.email, password: PASSWORD })).status, 200, 'still not connected');
});

test('SSO-22: Connect refuses another origin, no session and API keys, and sets no flow cookie', { skip: NEEDS }, async () => {
  const a = await signUp();
  const post = (headers, b = a) => b.request('/api/auth/oidc/connect', { method: 'POST', headers: { ...JSON_HEADERS, ...headers }, body: '{}' });
  const refused = await post({ Origin: 'https://evil.test' });
  assert.equal(refused.status, 403);
  assert.equal(refused.headers.getSetCookie().length, 0);
  assert.equal((await post({}, browser())).status, 401);
  assert.equal((await fetch(`${BASE}/api/auth/oidc/connect`, { method: 'POST', headers: { ...JSON_HEADERS, Authorization: 'Bearer cs_x' }, body: '{}' })).status, 401);
});

test('SSO-22: a Connect flow belongs to the account that began it', { skip: NEEDS }, async () => {
  const [a, b] = [await signUp(), await signUp()];
  const auth = new URL((await a.json('/api/auth/oidc/connect', 'POST', {})).data.url).searchParams;
  const finish = async (who) => {
    const code = rnd();
    codes.set(code, { claims: { sub: newSub(), email: b.email }, nonce: auth.get('nonce') });
    who.jar.cs_oidc = a.jar.cs_oidc;
    return (await who.request(`/api/auth/oidc/callback?code=${code}&state=${encodeURIComponent(auth.get('state'))}`)).headers.get('location');
  };
  assert.equal(await finish(browser()), '/login?error=sso_link', 'flow with no session');
  assert.equal(await finish(b), '/app/settings?sso=failed', 'flow begun by a, session of b');
  assert.equal(await signIn(browser(), { sub: newSub(), email: b.email }), '/login?error=sso_link', 'b is still not connected');
});

test('SSO-17 through the real Connect flow: a stranger\'s address or a taken identity stays in the same account', { skip: NEEDS }, async () => {
  const [sub, email] = [newSub(), newEmail()];
  await signIn(browser(), { sub, email });
  const a = await signUp();
  const session = a.jar.cs_session;
  assert.equal(await connect(a, { sub: newSub(), email: newEmail() }), '/app/settings?sso=failed');
  assert.equal(await connect(a, { sub, email }), '/app/settings?sso=failed');
  assert.equal(a.jar.cs_session, session);
});

// ---- SSO-3: what the no-cookie check leaves ----

test('SSO-3 holds: a callback with no flow cookie writes no log row and uses no bucket', { skip: NEEDS_DB }, async () => {
  const read = () => withDb((db) => [db.prepare('SELECT COUNT(*) AS n FROM security_events').get().n, db.prepare("SELECT COUNT(*) AS n FROM login_attempts WHERE key LIKE 'oidc:%'").get().n]);
  const before = read();
  for (let i = 0; i < 25; i++) assert.equal((await fetch(`${BASE}/api/auth/oidc/callback?code=x&state=y`, { redirect: 'manual' })).headers.get('location'), '/login?error=sso');
  assert.deepEqual(read(), before);
});

test('SSO-18: a junk flow cookie writes no security log row', { skip: NEEDS_DB }, async () => {
  const count = () => withDb((db) => db.prepare("SELECT COUNT(*) AS n FROM security_events WHERE type = 'login_failure'").get().n);
  const before = count();
  for (let i = 0; i < 25; i++) await fetch(`${BASE}/api/auth/oidc/callback?state=x`, { redirect: 'manual', headers: { cookie: 'cs_oidc=junk' } });
  assert.equal(count() - before, 0);
});

// ---- OIDC_REQUIRED ----

let connected = null;
test('OIDC_REQUIRED holds: invite sign-up is refused; a connected account has no password route', { skip: NEEDS_REQUIRED }, async () => {
  const first = await signUp(newEmail(), REQUIRED);
  assert.equal((await first.json('/api/teams', 'POST', { name: 'T' })).status, 201);
  const invited = newEmail();
  const inv = await first.json('/api/teams/invites', 'POST', { email: invited, role: 'member' });
  assert.equal(inv.status, 201, JSON.stringify(inv.data));
  const refused = await browser(REQUIRED).json('/api/auth/signup', 'POST', { name: 'I', email: invited, password: PASSWORD, inviteToken: inv.data.url.split('/join/')[1] });
  assert.equal(refused.status, 403);
  const device2 = browser(REQUIRED);
  assert.equal((await device2.json('/api/auth/login', 'POST', { email: first.email, password: PASSWORD })).status, 200);
  const passwordSession = first.jar.cs_session;
  assert.equal(await connect(first, { sub: newSub(), email: first.email }), '/app/settings');
  assert.equal((await browser(REQUIRED).json('/api/auth/login', 'POST', { email: first.email, password: PASSWORD })).status, 403);
  connected = Object.assign(first, { device2, passwordSession });
});

test('SSO-19: a correct password refused by OIDC_REQUIRED is not counted as a failed guess', { skip: NEEDS_REQUIRED }, async () => {
  assert.ok(connected, 'needs the test above');
  const statuses = [];
  for (let i = 0; i < 6; i++) statuses.push((await browser(REQUIRED).json('/api/auth/login', 'POST', { email: connected.email, password: PASSWORD })).status);
  assert.deepEqual(statuses, [403, 403, 403, 403, 403, 403]);
});

test('SSO-19 holds: correct passwords on a connected account do not lift the guess limit on another address', { skip: NEEDS_REQUIRED }, async () => {
  assert.ok(connected, 'needs the test above');
  const other = newEmail();
  const statuses = [];
  for (let i = 0; i < 6; i++) {
    statuses.push((await browser(REQUIRED).json('/api/auth/login', 'POST', { email: other, password: 'wrong password here' })).status);
    assert.equal((await browser(REQUIRED).json('/api/auth/login', 'POST', { email: connected.email, password: PASSWORD })).status, 403);
  }
  assert.deepEqual(statuses, [401, 401, 401, 401, 401, 429]);
});

const live = async (cookie) => (await fetch(`${REQUIRED}/api/documents?template=0`, { headers: { cookie: `cs_session=${cookie}` } })).status;

test('SSO-23 holds: connecting under OIDC_REQUIRED ends the other device\'s session; the new one works', { skip: NEEDS_REQUIRED }, async () => {
  assert.ok(connected, 'needs the test above');
  assert.equal(await live(connected.device2.jar.cs_session), 401);
  assert.equal(await live(connected.jar.cs_session), 200);
});

test('SSO-23: the session the password opened ends too', { skip: NEEDS_REQUIRED }, async () => {
  assert.ok(connected, 'needs the test above');
  assert.equal(await live(connected.passwordSession), 401);
});

// ---- SSO-13 ----

test('SSO-13 holds: API keys cannot pause or re-enable webhooks, nor can another account', { skip: NEEDS_DB }, async () => {
  const a = await signUp();
  const hook = await a.json('/api/webhooks', 'POST', { url: 'https://example.com/hook', events: ['document.sent'] });
  assert.ok(hook.status < 300, JSON.stringify(hook.data));
  const id = hook.data.id ?? hook.data.webhook?.id;
  const key = await a.json('/api/api-keys', 'POST', { name: 'k', expiresDays: null, scope: 'write' });
  assert.ok(key.status < 300, JSON.stringify(key.data));
  const bearer = { Authorization: `Bearer ${key.data.key}`, ...JSON_HEADERS };
  assert.equal((await fetch(`${BASE}/api/auth/logout-all`, { method: 'POST', headers: bearer, body: JSON.stringify({ apiKeys: true }) })).status, 401);
  assert.equal((await a.json('/api/auth/logout-all', 'POST', { apiKeys: true })).status, 200);
  assert.equal(withDb((db) => db.prepare('SELECT active FROM webhooks WHERE id = ?').get(id).active), 0);
  assert.equal((await fetch(`${BASE}/api/webhooks/${id}`, { method: 'PUT', headers: bearer, body: JSON.stringify({ active: true }) })).status, 401);
  assert.equal((await (await signUp()).json(`/api/webhooks/${id}`, 'PUT', { active: true })).status, 404);
  assert.equal(withDb((db) => db.prepare('SELECT active FROM webhooks WHERE id = ?').get(id).active), 0);
});

// ---- SSO-9: what the job may and may not delete ----

test('SSO-9 holds: the job deletes only expired public copies nobody signed', { skip: NEEDS_DB }, async () => {
  const owner = await signUp();
  const tpl = await publicTemplate(owner);
  const [abandoned, viewedOnly, declined, completed, stillOpen, twoPeople, voided] = [
    await publicCopy(owner, tpl), await publicCopy(owner, tpl), await publicCopy(owner, tpl), await publicCopy(owner, tpl),
    await publicCopy(owner, tpl), await publicCopy(owner, tpl), await publicCopy(owner, tpl),
  ];
  assert.equal((await fetch(`${BASE}/sign/${viewedOnly.signToken}`)).status, 200);
  assert.equal((await decline(BASE, declined)).status, 200);
  assert.equal((await sign(BASE, owner, completed)).status, 200);
  assert.equal((await owner.json(`/api/documents/${voided.id}/void`, 'POST', { reason: 'x' })).status, 200);
  // Not reachable through the API today: a second recipient who signed. The query must still keep the copy.
  withDb((db) => db.prepare("INSERT INTO recipients (id, document_id, name, email, role, routing_order, position, status) VALUES (?, ?, 'Two', 'two@example.com', 'signer', 1, 1, 'signed')").run(`x${rnd()}`, twoPeople.id));
  // An ordinary document with the marker text in its title and signer name, and a bulk copy of the same template.
  const titled = await upload(owner);
  assert.equal((await owner.json(`/api/documents/${titled.id}`, 'PUT', { title: 'Created from public link', recipients: [{ id: 'a', name: 'Created from public link', email: `a-${rnd()}@example.com`, role: 'signer' }], fields: [fieldFor('a')] })).status, 200);
  assert.equal((await owner.json(`/api/documents/${titled.id}/send`, 'POST', {})).status, 200);
  const bulk = await owner.json(`/api/documents/${tpl.id}/bulk`, 'POST', { rows: [[{ name: 'B', email: `b-${rnd()}@example.com` }]] });
  assert.equal(bulk.status, 201, JSON.stringify(bulk.data));

  expire([abandoned.id, viewedOnly.id, declined.id, completed.id, twoPeople.id, voided.id, titled.id, ...bulk.data.documentIds, tpl.id]);
  assert.equal(runJob(), null);
  const status = (id) => withDb((db) => db.prepare('SELECT status FROM documents WHERE id = ?').get(id)?.status);
  assert.equal(status(abandoned.id), undefined, 'abandoned');
  assert.equal(status(viewedOnly.id), undefined, 'viewed, not signed');
  assert.equal(status(declined.id), 'declined');
  assert.equal(status(completed.id), 'completed');
  assert.equal(status(twoPeople.id), 'expired', 'someone signed');
  assert.equal(status(voided.id), 'voided');
  assert.equal(status(titled.id), 'expired', 'marker text in a title or name is not the marker');
  assert.equal(status(stillOpen.id), 'sent', 'not yet due');
  for (const id of bulk.data.documentIds) assert.equal(status(id), 'expired', 'bulk copy');
  assert.equal(status(tpl.id), 'draft', 'the template, even with a past expires_at');
  assert.equal(withDb((db) => db.prepare('SELECT COUNT(*) AS n FROM audit_tombstones WHERE document_id = ?').get(abandoned.id).n), 1);
});

test('SSO-20: one document the job cannot load does not stop the others being deleted', { skip: NEEDS_DB }, async () => {
  const owner = await signUp();
  const tpl = await publicTemplate(owner);
  const ids = [(await publicCopy(owner, tpl)).id, (await publicCopy(owner, tpl)).id];
  withDb((db) => {
    const past = new Date(Date.now() - 5000).toISOString();
    for (const id of ids) db.prepare("UPDATE documents SET status = 'expired', expires_at = ? WHERE id = ?").run(past, id);
    // The row the job's query reaches first. One unreadable ciphertext is enough, for example after a partial restore.
    const first = db.prepare(`SELECT d.id FROM documents d WHERE d.status = 'expired'
      AND EXISTS (SELECT 1 FROM events e WHERE e.document_id = d.id AND e.action = 'Created from public link')
      AND NOT EXISTS (SELECT 1 FROM recipients r WHERE r.document_id = d.id AND r.status = 'signed')`).get().id;
    db.prepare("UPDATE fields SET value = 'not-encrypted' WHERE document_id = ?").run(first);
  });
  const err = runJob();
  const left = withDb((db) => ids.filter((id) => db.prepare('SELECT 1 FROM documents WHERE id = ?').get(id)).length);
  assert.equal(left, 1, `only the unreadable one stays; job said: ${err?.split('\n').find((l) => /Error/.test(l))}`);
});

test('SSO-9 reopened: a visitor cannot fill the owner\'s quota by declining or signing copies', { skip: NEEDS_QUOTA }, async () => {
  const owner = await signUp(newEmail(), QUOTA);
  const tpl = await publicTemplate(owner, 250 * 1024);
  const a = await publicCopy(owner, tpl, QUOTA);
  const b = await publicCopy(owner, tpl, QUOTA);
  const c = await publicCopy(owner, tpl, QUOTA);
  assert.equal((await decline(QUOTA, a)).status, 200);
  assert.equal((await decline(QUOTA, b)).status, 200);
  assert.equal((await sign(QUOTA, owner, c)).status, 200);
  expire([a.id, b.id, c.id], QUOTA_DATA);
  assert.equal(runJob(QUOTA_DATA), null);
  assert.equal((await upload(owner, { pad: 250 * 1024 })).status, 201, 'the owner can still upload after the cleanup job');
});

// Allows twice the quota: uploads and public copies may have a bucket each, so a visitor can only stop the link.
test('SSO-9: passing files through a public link cannot keep more than twice the quota', { skip: NEEDS_QUOTA }, async () => {
  const owner = await signUp(newEmail(), QUOTA);
  const kept = [];
  for (let i = 0; i < 6; i++) {
    const tpl = await publicTemplate(owner, 400 * 1024);
    let copy;
    try { copy = await publicCopy(owner, tpl, QUOTA); } catch (e) { if (e.actual === 413) break; throw e; }
    assert.equal((await decline(QUOTA, copy)).status, 200);
    assert.equal((await owner.json(`/api/documents/${tpl.id}`, 'DELETE')).status, 200);
    kept.push(copy.id);
  }
  expire(kept, QUOTA_DATA);
  assert.equal(runJob(QUOTA_DATA), null);
  const stored = withDb((db) => kept.reduce((n, id) => n + (db.prepare('SELECT original_bytes FROM documents WHERE id = ?').get(id)?.original_bytes ?? 0), 0), QUOTA_DATA);
  assert.ok(stored <= 2 * 1048576, `${stored} bytes kept under a 1 MB quota`);
});

// Last in this file: it fills the bucket for a minute.
test('SSO-3: a script with no account gets at most 60 provider requests a minute, and writes no log rows once limited', { skip: NEEDS_DB }, async () => {
  const before = tokenRequests;
  const rows = () => withDb((db) => db.prepare('SELECT COUNT(*) AS n FROM security_events').get().n);
  const hit = async () => {
    const b = browser();
    const auth = new URL((await b.request('/api/auth/oidc/start')).headers.get('location')).searchParams;
    await b.request(`/api/auth/oidc/callback?code=junk&state=${encodeURIComponent(auth.get('state'))}`);
  };
  for (let i = 0; i < 70; i++) await hit();
  assert.ok(tokenRequests - before <= 60, `${tokenRequests - before} provider requests`);
  const limited = rows();
  for (let i = 0; i < 5; i++) await hit();
  assert.equal(rows(), limited, 'no rows once limited');
});

test('SSO-3: a locked address gets in again after the minute, and a script can lock it again at once', { skip: NEEDS_DB }, async (t) => {
  const person = { sub: newSub(), email: newEmail() };
  assert.equal(await signIn(browser(), person), '/login?error=sso', 'locked by the test above');
  await new Promise((r) => { setTimeout(r, 61_000); });
  assert.equal(await signIn(browser(), person), '/app', 'free again');
  const t0 = Date.now();
  for (let i = 0; i < 60; i++) await signIn(browser(), { sub: 'x', email: 'bad' });
  t.diagnostic(`re-locked in ${Date.now() - t0} ms`);
  assert.equal(await signIn(browser(), person), '/login?error=sso', 'locked again');
});
