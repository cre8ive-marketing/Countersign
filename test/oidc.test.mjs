// Single sign-on over HTTP against a mock OpenID Connect provider that runs in this test process.
// Needs its own FRESH closed server:
//   OIDC_ISSUER=http://127.0.0.1:<P> OIDC_ALLOW_HTTP=true OIDC_CLIENT_ID=cs-test OIDC_CLIENT_SECRET=cs-secret OIDC_NAME=Acme
//   OIDC_ALLOWED_DOMAINS=allowed.test OIDC_AUTO_CREATE=true ALLOW_SIGNUP=false APP_URL=<BASE_URL>
// Test env: OIDC_BASE_URL=<BASE_URL> OIDC_MOCK_PORT=<P>. Without them the provider tests skip.
// The last test runs against BASE_URL, a server without OIDC settings. Optional OIDC_NODOMAIN_BASE_URL: a fresh server
// on the same mock with no OIDC_ALLOWED_DOMAINS and no users.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';

const BASE = process.env.OIDC_BASE_URL;
const PORT = Number(process.env.OIDC_MOCK_PORT) || 0;
const NEEDS = (!BASE || !PORT) && 'needs OIDC_BASE_URL and OIDC_MOCK_PORT with a server set up for the mock provider';
const ISSUER = `http://127.0.0.1:${PORT}`;
const CLIENT = 'cs-test';
const rnd = () => crypto.randomBytes(5).toString('hex');

// --- Mock provider. Each code maps to the claims and behaviour of one sign-in.
const codes = new Map();
const seen = [];
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
let mock;
if (PORT) {
  mock = http.createServer((req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    if (req.url === '/.well-known/openid-configuration') {
      return send(200, { issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token` });
    }
    if (req.url === '/token' && req.method === 'POST') {
      let raw = '';
      req.on('data', (d) => { raw += d; });
      req.on('end', () => {
        const form = new URLSearchParams(raw);
        const entry = codes.get(form.get('code'));
        seen.push({ form, auth: req.headers.authorization });
        if (!entry) return send(400, { error: 'invalid_grant' });
        const challenge = crypto.createHash('sha256').update(form.get('code_verifier') || '').digest('base64url');
        if (challenge !== entry.challenge) return send(400, { error: 'invalid_grant', error_description: 'bad PKCE' });
        if (entry.tokenStatus) return send(entry.tokenStatus, { error: 'server_error' });
        const claims = { iss: ISSUER, aud: CLIENT, exp: Math.floor(Date.now() / 1000) + 300, nonce: entry.nonce, email_verified: true, ...entry.claims };
        return send(200, { id_token: `${b64({ alg: 'RS256' })}.${b64(claims)}.sig` });
      });
      return undefined;
    }
    return send(404, {});
  });
  await new Promise((r) => mock.listen(PORT, '127.0.0.1', r));
}
test.after(() => mock?.close());

// --- A browser: a cookie jar that follows nothing by itself.
function browser(base = BASE) {
  const jar = {};
  const go = async (p) => {
    const cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(base + p, { redirect: 'manual', headers: cookie ? { cookie } : {} });
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(';');
      const i = kv.indexOf('=');
      if (/Max-Age=0/.test(c)) delete jar[kv.slice(0, i)]; else jar[kv.slice(0, i)] = kv.slice(i + 1);
    }
    return res;
  };
  return { go, jar };
}
const start = async (b, next) => {
  const r = await b.go(`/api/auth/oidc/start${next === undefined ? '' : `?next=${encodeURIComponent(next)}`}`);
  assert.equal(r.status, 302);
  return new URL(r.headers.get('location'));
};
// One full sign-in. opts: next, tokenStatus, state and nonce overrides, and an existing browser.
async function signIn(claims, { next, tokenStatus, state, nonce, b = browser() } = {}) {
  const auth = await start(b, next);
  const code = rnd();
  codes.set(code, { claims, tokenStatus, challenge: auth.searchParams.get('code_challenge'), nonce: nonce ?? auth.searchParams.get('nonce') });
  const r = await b.go(`/api/auth/oidc/callback?code=${code}&state=${encodeURIComponent(state ?? auth.searchParams.get('state'))}`);
  return { status: r.status, to: r.headers.get('location'), b };
}
const emailOf = async (b) => { const s = await (await b.go('/api/auth/session')).json(); return s.user?.email ?? s.email ?? null; };
const newEmail = (domain = 'allowed.test') => `u-${rnd()}@${domain}`;
const newSub = () => `sub-${rnd()}`;
const FAILED = '/login?error=sso';
const DENIED = '/login?error=sso_denied';
const LINK = '/login?error=sso_link';

let first; // the server's first account, with a password
test('no users yet: without a domain list SSO does not create the first account', { skip: NEEDS || (!process.env.OIDC_NODOMAIN_BASE_URL && 'needs OIDC_NODOMAIN_BASE_URL') }, async () => {
  const r = await signIn({ sub: newSub(), email: newEmail() }, { b: browser(process.env.OIDC_NODOMAIN_BASE_URL) });
  assert.equal(r.to, DENIED);
  assert.equal(r.b.jar.cs_session, undefined);
});

test('setup: the first account signs up with a password', { skip: NEEDS }, async () => {
  first = { email: newEmail(), password: 'correct horse battery' };
  const r = await fetch(`${BASE}/api/auth/signup`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'First', ...first }) });
  assert.equal(r.status, 200, await r.text());
});

test('start: sends the browser to the provider with PKCE, state, nonce and the APP_URL redirect; the flow cookie is HttpOnly and encrypted', { skip: NEEDS }, async () => {
  const res = await browser().go('/api/auth/oidc/start?next=%2Fapp%2Fteam');
  const u = new URL(res.headers.get('location'));
  assert.equal(u.origin + u.pathname, `${ISSUER}/authorize`);
  const q = Object.fromEntries(u.searchParams);
  assert.deepEqual([q.response_type, q.client_id, q.redirect_uri, q.scope, q.code_challenge_method], ['code', CLIENT, `${BASE}/api/auth/oidc/callback`, 'openid email profile', 'S256']);
  for (const k of ['state', 'nonce', 'code_challenge']) assert.ok(q[k]?.length >= 40, k);
  const set = res.headers.getSetCookie()[0];
  assert.match(set, /^cs_oidc=/);
  assert.match(set, /HttpOnly/);
  assert.match(set, /SameSite=Lax/);
  assert.ok(!set.includes(q.state) && !set.includes(q.nonce), 'flow is encrypted');
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('new person in an allowed domain: account created, signed in, flow cookie gone; the same sub returns to the same account', { skip: NEEDS }, async () => {
  const email = newEmail();
  const sub = newSub();
  const r = await signIn({ sub, email, name: 'New Person' });
  assert.deepEqual([r.status, r.to], [302, '/app']);
  assert.equal(r.b.jar.cs_oidc, undefined);
  assert.equal(await emailOf(r.b), email);
  const again = await signIn({ sub, email: newEmail(), name: 'Renamed' });
  assert.equal(again.to, '/app');
  assert.equal(await emailOf(again.b), email, 'the account follows sub, not the email');
});

test('code exchange: client secret, redirect and PKCE verifier reach the token endpoint', { skip: NEEDS }, async () => {
  await signIn({ sub: newSub(), email: newEmail() });
  const { form, auth } = seen.at(-1);
  assert.equal(auth, `Basic ${Buffer.from(`${CLIENT}:cs-secret`).toString('base64')}`);
  assert.deepEqual([form.get('grant_type'), form.get('redirect_uri')], ['authorization_code', `${BASE}/api/auth/oidc/callback`]);
  assert.ok(form.get('code_verifier')?.length >= 43);
});

test('existing password account: SSO alone is refused; its live session connects it; a different sub is refused afterwards', { skip: NEEDS }, async () => {
  const sub = newSub();
  const alone = await signIn({ sub, email: first.email });
  assert.equal(alone.to, LINK, 'someone else may have made this account, so an email match is not enough');
  assert.equal(alone.b.jar.cs_session, undefined);
  const login = await fetch(`${BASE}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(first) });
  assert.equal(login.status, 200);
  const b = browser();
  const [name, value] = login.headers.getSetCookie()[0].split(';')[0].split('=');
  b.jar[name] = value;
  assert.ok((await (await b.go('/app/settings')).text()).includes('/api/auth/oidc/start?next=%2Fapp%2Fsettings'), 'Settings offers Connect');
  assert.equal((await signIn({ sub, email: first.email.toUpperCase(), name: 'Other Name' }, { b, next: '/app/settings' })).to, '/app/settings');
  assert.ok((await (await b.go('/app/settings')).text()).includes('is connected to'), 'Settings shows it connected');
  const later = await signIn({ sub, email: first.email });
  assert.equal(later.to, '/app', 'connected: SSO alone works now');
  assert.equal(await emailOf(later.b), first.email);
  assert.equal((await signIn({ sub: newSub(), email: first.email })).to, DENIED, 'address reassigned at the provider');
  assert.equal((await fetch(`${BASE}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(first) })).status, 200, 'password still works');
});

test('refused people get no session: other domain, unverified email, no email', { skip: NEEDS }, async () => {
  for (const claims of [
    { sub: newSub(), email: newEmail('other.test') },
    { sub: newSub(), email: newEmail(), email_verified: false },
    { sub: newSub(), email: newEmail(), email_verified: null },
    { sub: newSub() },
    { sub: newSub(), email: 'not an email' },
    { sub: newSub(), email: `${'a'.repeat(240)}@allowed.test.evil.test` },
  ]) {
    const r = await signIn(claims);
    assert.equal(r.to, DENIED, JSON.stringify(claims));
    assert.equal(r.b.jar.cs_session, undefined);
  }
});

test('broken tokens are refused: wrong issuer, audience, azp, expired, nonce, no subject', { skip: NEEDS }, async () => {
  const email = newEmail();
  const sub = newSub();
  for (const claims of [
    { sub, email, iss: 'https://evil.test' },
    { sub, email, aud: 'someone-else' },
    { sub, email, aud: [CLIENT, 'someone-else'] },
    { sub, email, exp: Math.floor(Date.now() / 1000) - 1 },
    { sub, email, exp: 'soon' },
    { sub, email, azp: 'someone-else' },
    { email },
  ]) {
    const r = await signIn(claims);
    assert.equal(r.to, FAILED, JSON.stringify(claims));
    assert.equal(r.b.jar.cs_session, undefined);
  }
  assert.equal((await signIn({ sub, email }, { nonce: 'wrong' })).to, FAILED, 'nonce');
  assert.equal((await signIn({ sub, email }, { tokenStatus: 500 })).to, FAILED, 'token endpoint error');
  assert.equal((await signIn({ sub, email, aud: [CLIENT, 'x'], azp: CLIENT })).to, '/app', 'many audiences with the right azp are fine');
});

test('callback is tied to the browser: wrong state, no cookie, tampered cookie, provider error', { skip: NEEDS }, async () => {
  const claims = { sub: newSub(), email: newEmail() };
  assert.equal((await signIn(claims, { state: 'wrong' })).to, FAILED);
  // Login CSRF: the attacker's code and state in a victim's browser, which has no flow cookie.
  const attacker = browser();
  const auth = await start(attacker);
  const code = rnd();
  codes.set(code, { claims, challenge: auth.searchParams.get('code_challenge'), nonce: auth.searchParams.get('nonce') });
  const url = `/api/auth/oidc/callback?code=${code}&state=${encodeURIComponent(auth.searchParams.get('state'))}`;
  const victim = browser();
  assert.equal((await victim.go(url)).headers.get('location'), FAILED);
  assert.equal(victim.jar.cs_session, undefined);
  const tampered = browser();
  tampered.jar.cs_oidc = `${attacker.jar.cs_oidc.slice(0, -6)}AAAAAA`;
  assert.equal((await tampered.go(url)).headers.get('location'), FAILED);
  assert.equal((await attacker.go(`/api/auth/oidc/callback?error=access_denied&state=${encodeURIComponent(auth.searchParams.get('state'))}`)).headers.get('location'), FAILED);
  // The flow cookie is gone after any callback, so the code can't be tried again.
  assert.equal(attacker.jar.cs_oidc, undefined);
  assert.equal((await attacker.go(url)).headers.get('location'), FAILED);
});

test('next: same-origin paths are kept, anything else goes to /app', { skip: NEEDS }, async () => {
  const claims = () => ({ sub: newSub(), email: newEmail() });
  assert.equal((await signIn(claims(), { next: '/join/abc?x=1' })).to, '/join/abc?x=1');
  for (const next of ['//evil.test', 'https://evil.test', '/\\evil.test', '\\\\evil.test', '/\t/evil.test', 'javascript:alert(1)', '', '/app/日本']) {
    assert.equal((await signIn(claims(), { next })).to, '/app', JSON.stringify(next));
  }
});

test('an SSO account has no usable password; the login page shows the button and fixed error texts only', { skip: NEEDS }, async () => {
  const email = newEmail();
  await signIn({ sub: newSub(), email });
  for (const password of ['', 'correct horse battery']) {
    assert.equal((await fetch(`${BASE}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) })).status, 401);
  }
  const html = await (await fetch(`${BASE}/login`)).text();
  assert.ok(html.includes('Continue with') && html.includes('Acme') && html.includes('/api/auth/oidc/start?next=%2Fapp'), 'button');
  assert.ok((await (await fetch(`${BASE}/login?error=sso_denied`)).text()).includes('sign in here'));
  assert.ok(!(await (await fetch(`${BASE}/login?error=%3Cscript%3Ealert(1)`)).text()).includes('<script>alert(1)'), 'the error text never comes from the URL');
});

test('a callback with no flow cookie makes no provider request', { skip: NEEDS }, async () => {
  const before = seen.length;
  assert.equal((await browser().go('/api/auth/oidc/callback?code=x&state=y')).headers.get('location'), FAILED);
  assert.equal(seen.length, before);
});

test('without OIDC settings the routes are 404 and the login page has no button', { skip: !process.env.BASE_URL && 'needs BASE_URL' }, async () => {
  const B = process.env.BASE_URL;
  for (const p of ['start', 'callback']) assert.equal((await fetch(`${B}/api/auth/oidc/${p}`, { redirect: 'manual' })).status, 404);
  assert.ok(!(await (await fetch(`${B}/login`)).text()).includes('/api/auth/oidc/start'));
});
