// Single sign-on security regressions, over HTTP against a mock OpenID Connect provider in this test process.
// Needs a FRESH disposable server (the provider tests skip without SSO_BASE_URL and SSO_MOCK_PORT):
//   OIDC_ISSUER=http://127.0.0.1:<P> OIDC_ALLOW_HTTP=true OIDC_CLIENT_ID=cs-sec OIDC_CLIENT_SECRET=cs-sec-secret
//   OIDC_ALLOWED_DOMAINS=allowed.test OIDC_TRUST_EMAIL=false OIDC_AUTO_CREATE=false ALLOW_SIGNUP=true
//   SIGNUP_MAX_PER_HOUR=1000 APP_URL=<SSO_BASE_URL>
// Test env: SSO_BASE_URL=<APP_URL> SSO_MOCK_PORT=<P>. Optional: SSO_SERVER_LOG=<server stdout and stderr file>, SSO_DATA_DIR=<its DATA_DIR>.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const BASE = process.env.SSO_BASE_URL;
const PORT = Number(process.env.SSO_MOCK_PORT) || 0;
const LOG = process.env.SSO_SERVER_LOG;
const DATA_DIR = process.env.SSO_DATA_DIR;
const NEEDS = (!BASE || !PORT) && 'needs SSO_BASE_URL and SSO_MOCK_PORT with a server set up for the mock provider';
const ISSUER = `http://127.0.0.1:${PORT}`;
const CLIENT = 'cs-sec';
const SECRET = 'cs-sec-secret';
const FAILED = '/login?error=sso';
const DENIED = '/login?error=sso_denied';
const LINK = '/login?error=sso_link';
const rnd = () => crypto.randomBytes(5).toString('hex');
const newEmail = (domain = 'allowed.test') => `u-${rnd()}@${domain}`;
const newSub = () => `sub-${rnd()}`;

const codes = new Map();
const issued = []; // every id_token the mock handed out, for the log check
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
let mock;
if (!NEEDS) {
  mock = http.createServer((req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    if (req.url === '/.well-known/openid-configuration') return send(200, { issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token` });
    if (req.url === '/token' && req.method === 'POST') {
      let raw = '';
      req.on('data', (d) => { raw += d; });
      req.on('end', () => {
        const form = new URLSearchParams(raw);
        const entry = codes.get(form.get('code'));
        codes.delete(form.get('code')); // one use, as OAuth 2.0 requires of a provider
        if (!entry) return send(400, { error: 'invalid_grant' });
        if (crypto.createHash('sha256').update(form.get('code_verifier') || '').digest('base64url') !== entry.challenge) return send(400, { error: 'invalid_grant' });
        if (entry.tokenStatus) return send(entry.tokenStatus, { error: 'server_error' });
        const idToken = `${b64({ alg: 'RS256' })}.${b64({ iss: ISSUER, aud: CLIENT, exp: Math.floor(Date.now() / 1000) + 300, nonce: entry.nonce, email_verified: true, ...entry.claims })}.sig`;
        issued.push(idToken);
        return send(200, { id_token: idToken });
      });
      return undefined;
    }
    return send(404, {});
  });
  await new Promise((r) => mock.listen(PORT, '127.0.0.1', r));
}
test.after(() => mock?.close());

function browser() {
  const jar = {};
  const request = async (p, init = {}) => {
    const cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(BASE + p, { redirect: 'manual', ...init, headers: { ...(cookie ? { cookie } : {}), ...init.headers } });
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(';');
      const i = kv.indexOf('=');
      if (/Max-Age=0/.test(c)) delete jar[kv.slice(0, i)]; else jar[kv.slice(0, i)] = kv.slice(i + 1);
    }
    return res;
  };
  const json = (p, method, body) => request(p, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return { jar, request, json };
}

async function begin(b, next) {
  const r = await b.request(`/api/auth/oidc/start${next === undefined ? '' : `?next=${encodeURIComponent(next)}`}`);
  assert.equal(r.status, 302);
  return new URL(r.headers.get('location')).searchParams;
}
async function signIn(claims, { next, tokenStatus, b = browser() } = {}) {
  const auth = await begin(b, next);
  const code = rnd();
  codes.set(code, { claims, tokenStatus, challenge: auth.get('code_challenge'), nonce: auth.get('nonce') });
  const r = await b.request(`/api/auth/oidc/callback?code=${code}&state=${encodeURIComponent(auth.get('state'))}`);
  return { status: r.status, to: r.headers.get('location'), b, code, auth };
}
const PASSWORD = 'correct horse battery';
async function signUp(email) {
  const b = browser();
  const r = await b.json('/api/auth/signup', 'POST', { name: 'Someone', email, password: PASSWORD });
  assert.equal(r.status, 200);
  return b;
}

test('flow cookie: scoped to the SSO routes, HttpOnly, SameSite=Lax, ten minutes; state and nonce are not readable in it', { skip: NEEDS }, async () => {
  const res = await browser().request('/api/auth/oidc/start');
  const set = res.headers.getSetCookie().find((c) => c.startsWith('cs_oidc='));
  for (const attr of ['Path=/api/auth/oidc', 'HttpOnly', 'SameSite=Lax', 'Max-Age=600']) assert.ok(set.includes(attr), attr);
  const q = new URL(res.headers.get('location')).searchParams;
  for (const k of ['state', 'nonce']) assert.ok(!decodeURIComponent(set).includes(q.get(k)), k);
});

test('callback: no state, a repeated state and another flow\'s state give no session', { skip: NEEDS }, async () => {
  const b = browser();
  const auth = await begin(b);
  const code = rnd();
  codes.set(code, { claims: { sub: newSub(), email: newEmail() }, challenge: auth.get('code_challenge'), nonce: auth.get('nonce') });
  const flow = b.jar.cs_oidc;
  for (const q of [`code=${code}`, `code=${code}&state=a&state=b`, `code=${code}&state=${encodeURIComponent((await begin(browser())).get('state'))}`]) {
    b.jar.cs_oidc = flow;
    assert.equal((await b.request(`/api/auth/oidc/callback?${q}`)).headers.get('location'), FAILED, q);
    assert.equal(b.jar.cs_session, undefined, q);
  }
});

test('a saved flow cookie replayed with its used code gets no session, because the provider refuses the code', { skip: NEEDS }, async () => {
  const b = browser();
  const auth = await begin(b);
  const saved = b.jar.cs_oidc;
  const code = rnd();
  codes.set(code, { claims: { sub: newSub(), email: newEmail() }, challenge: auth.get('code_challenge'), nonce: auth.get('nonce') });
  const url = `/api/auth/oidc/callback?code=${code}&state=${encodeURIComponent(auth.get('state'))}`;
  assert.equal((await b.request(url)).headers.get('location'), '/app');
  const replay = browser();
  replay.jar.cs_oidc = saved;
  assert.equal((await replay.request(url)).headers.get('location'), FAILED);
  assert.equal(replay.jar.cs_session, undefined);
});

test('next: nothing a browser could resolve to another origin survives the sign-in', { skip: NEEDS }, async () => {
  const hostile = ['//evil.test', '///evil.test', '/\\evil.test', '\\/evil.test', '/\t/evil.test', '/\n/evil.test', '/\r/evil.test', '\t//evil.test', ' //evil.test', 'https://evil.test', 'https:evil.test', 'javascript:alert(1)', '/..//evil.test', '/.//evil.test', '/%2F/evil.test', '/%5Cevil.test', '/%09/evil.test', '/@evil.test'];
  for (const next of hostile) {
    const { to, status } = await signIn({ sub: newSub(), email: newEmail() }, { next });
    assert.equal(status, 302, JSON.stringify(next));
    assert.equal(new URL(to, BASE).origin, new URL(BASE).origin, JSON.stringify(next));
  }
});

test('logs: no client secret, code, state, nonce, flow cookie or id token in server output or the security log', { skip: NEEDS || ((!LOG || !DATA_DIR) && 'needs SSO_SERVER_LOG and SSO_DATA_DIR') }, async () => {
  const runs = [
    await signIn({ sub: newSub(), email: newEmail() }),
    await signIn({ sub: newSub(), email: newEmail(), email_verified: false }),
    await signIn({ sub: newSub(), email: newEmail() }, { tokenStatus: 500 }),
    await signIn({ sub: newSub(), email: newEmail(), iss: 'https://evil.test' }),
  ];
  const b = browser();
  const auth = await begin(b);
  const flow = decodeURIComponent(b.jar.cs_oidc);
  await new Promise((r) => setTimeout(r, 300));
  const db = new DatabaseSync(path.join(DATA_DIR, 'countersign.db'), { readOnly: true });
  const stored = JSON.stringify(db.prepare('SELECT * FROM security_events').all());
  db.close();
  const output = fs.readFileSync(LOG, 'utf8');
  const secrets = [SECRET, flow, auth.get('state'), auth.get('nonce'), ...issued];
  for (const r of runs) secrets.push(r.code, r.auth.get('state'), r.auth.get('nonce'), r.auth.get('code_challenge'));
  for (const s of secrets) {
    assert.ok(!output.includes(s), `server output holds ${s.slice(0, 12)}`);
    assert.ok(!stored.includes(s), `security log holds ${s.slice(0, 12)}`);
  }
});

test('SSO-1: an email match alone never opens an existing account; only that account\'s own session can connect it', { skip: NEEDS }, async () => {
  const email = newEmail();
  const sub = newSub();
  const owner = await signUp(email);
  const stranger = await signIn({ sub, email, name: 'Real Owner' });
  assert.equal(stranger.to, LINK);
  assert.equal(stranger.b.jar.cs_session, undefined);
  const other = await signUp(newEmail());
  const session = other.jar.cs_session;
  assert.equal((await signIn({ sub, email }, { b: other })).to, '/app/settings?sso=failed', 'another account\'s session does not count');
  assert.equal(other.jar.cs_session, session);
  assert.equal((await signIn({ sub, email }, { b: owner })).to, '/app');
  assert.equal((await signIn({ sub, email })).to, '/app', 'connected: SSO alone works now');
});

test('SSO-5: a domain list cannot be passed with an address cut at 254 characters', { skip: NEEDS }, async () => {
  const email = `${'a'.repeat(254 - '@allowed.test'.length)}@allowed.test.evil.test`;
  const r = await signIn({ sub: newSub(), email });
  assert.equal(r.to, DENIED);
  assert.equal(r.b.jar.cs_session, undefined);
});

test('SSO-6: a next path outside Latin-1 still ends in a redirect', { skip: NEEDS }, async () => {
  const r = await signIn({ sub: newSub(), email: newEmail() }, { next: '/app/日本' });
  assert.equal(r.status, 302);
});

test('SSO-7: the login page takes only its own error keys', { skip: !(BASE || process.env.BASE_URL) && 'needs SSO_BASE_URL or BASE_URL' }, async () => {
  const base = BASE || process.env.BASE_URL;
  for (const error of ['__proto__', 'constructor', 'toString']) assert.equal((await fetch(`${base}/login?error=${error}`)).status, 200, error);
});

test('SSO-8: an account created or linked by SSO leaves its own security event', { skip: NEEDS || (!DATA_DIR && 'needs SSO_DATA_DIR') }, async () => {
  const created = newEmail();
  await signIn({ sub: newSub(), email: created });
  const linked = newEmail();
  await signIn({ sub: newSub(), email: linked }, { b: await signUp(linked) });
  const db = new DatabaseSync(path.join(DATA_DIR, 'countersign.db'), { readOnly: true });
  const types = (email) => db.prepare('SELECT type FROM security_events WHERE email = ?').all(email).map((e) => e.type);
  const [a, b] = [types(created), types(linked)];
  db.close();
  assert.ok(a.includes('signup'), `created: ${a}`);
  assert.ok(b.includes('sso_linked'), `linked: ${b}`);
});
