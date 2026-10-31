// Marketing pages, public session endpoint, robots/sitemap and security headers. Needs a running server:
//   BASE_URL=http://localhost:3000 node --test test/marketing.test.mjs   (throwaway DATA_DIR, ALLOW_SIGNUP=true)
import { test } from 'node:test';
import assert from 'node:assert/strict';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const PAGES = ['/', '/product', '/use-cases', '/self-host', '/security'];
const get = (path, opts = {}) => fetch(BASE + path, { redirect: 'manual', ...opts });

test('every marketing page returns 200 HTML', async () => {
  for (const p of PAGES) {
    const res = await get(p);
    assert.equal(res.status, 200, p);
    assert.match(res.headers.get('content-type'), /text\/html/, p);
    assert.match(await res.text(), /<html/i, p);
  }
});

test('session endpoint: null without cookie, name and email only when signed in, no-store, 405 on POST', async () => {
  const anon = await get('/api/auth/session');
  assert.equal(anon.status, 200);
  assert.match(anon.headers.get('cache-control'), /no-store/);
  assert.match(anon.headers.get('cache-control'), /private/);
  const a = await anon.json();
  assert.equal(a.user, null);
  assert.equal(typeof a.signupOpen, 'boolean');

  const head = await get('/api/auth/session', { method: 'HEAD' });
  assert.equal(head.status, 200);

  const email = `mk-${Date.now()}@example.com`;
  const signup = await get('/api/auth/signup', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Mark Eting', email, password: 'correct horse' }),
  });
  assert.equal(signup.status, 200);
  const cookie = signup.headers.get('set-cookie').split(';')[0];

  const me = await get('/api/auth/session', { headers: { cookie } });
  assert.equal(me.status, 200);
  assert.match(me.headers.get('cache-control'), /no-store/);
  const body = await me.json();
  assert.deepEqual(body.user, { name: 'Mark Eting', email });
  assert.equal(typeof body.signupOpen, 'boolean');
  assert.ok(!/password|hash|"id"/i.test(JSON.stringify(body)), 'no id or password fields leak');

  for (const method of ['POST', 'PUT', 'DELETE']) {
    assert.equal((await get('/api/auth/session', { method, headers: { cookie } })).status, 405, method);
  }
});

test('robots.txt: plain text, disallows private paths, absolute Sitemap line', async () => {
  const res = await get('/robots.txt');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /^text\/plain/);
  const lines = (await res.text()).split(/\r?\n/);
  for (const p of ['/api/', '/app', '/sign/', '/login', '/signup']) assert.ok(lines.includes(`Disallow: ${p}`), p);
  const sitemap = lines.find((l) => l.startsWith('Sitemap:'));
  assert.ok(sitemap, 'Sitemap line present');
  assert.match(sitemap, /^Sitemap: https?:\/\/[^/\s]+\/sitemap\.xml$/);
});

test('sitemap.xml lists exactly the five public pages as absolute URLs', async () => {
  const res = await get('/sitemap.xml');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /xml/);
  const xml = await res.text();
  assert.match(xml, /^<\?xml version="1\.0"/);
  assert.match(xml, /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">[\s\S]*<\/urlset>/);
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  assert.equal(locs.length, 5);
  const urls = locs.map((l) => new URL(l)); // throws if any loc is not absolute
  assert.equal(new Set(urls.map((u) => u.origin)).size, 1);
  assert.deepEqual(urls.map((u) => u.pathname).sort(), [...PAGES].sort());
  for (const u of urls) assert.ok(!/^\/(app|sign|api)(\/|$)/.test(u.pathname), u.pathname);
});

test('security headers on /', async () => {
  const h = (await get('/')).headers;
  assert.equal(h.get('x-content-type-options'), 'nosniff');
  assert.equal(h.get('x-frame-options'), 'DENY');
  assert.equal(h.get('referrer-policy'), 'same-origin');
  assert.equal(h.get('cross-origin-opener-policy'), 'same-origin');
  for (const f of ['camera=()', 'microphone=()', 'geolocation=()', 'payment=()']) assert.ok(h.get('permissions-policy')?.includes(f), f);
  const csp = h.get('content-security-policy') || '';
  for (const d of ["frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'", "object-src 'none'"]) assert.ok(csp.includes(d), d);
  assert.equal(h.get('x-powered-by'), null);
  // Report-Only is production-only; `next start` runs with NODE_ENV=production.
  assert.match(h.get('content-security-policy-report-only') || '', /default-src 'self'/);
});

test('/signup?email= prefills the email field, escaped', async () => {
  const html = await (await get('/signup?email=x%40y.co')).text();
  assert.match(html, /id="email"[^>]*value="x@y\.co"/);
  const evil = await (await get(`/signup?email=${encodeURIComponent('"><script>alert(1)</script>')}`)).text();
  assert.ok(!evil.includes('<script>alert(1)</script>'), 'query value is not injected as markup');
});

test('app routes still require a session', async () => {
  const res = await get('/app');
  assert.ok([302, 307].includes(res.status), String(res.status));
  assert.match(res.headers.get('location'), /\/login\?next=%2Fapp$/);
  assert.equal((await get('/api/documents/nope/file')).status, 401); // GET route that requires a session
  assert.equal((await get('/app/settings')).status, 307);
});
