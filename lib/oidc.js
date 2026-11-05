import crypto from 'node:crypto';
import db, { now, tx } from './db.js';
import { decryptText, encryptText } from './crypto.js';
import { createUser, hashPassword, ipPrefix, rateLimit, signupOpen } from './auth.js';
import { EMAIL, fail, str } from './http.js';

// Single sign-on: OpenID Connect authorization code flow with PKCE, one provider per server, set by environment.
const FLOW_AAD = 'oidc-flow';
const FLOW_MS = 10 * 6e4;
const DISCOVERY_MS = 36e5;
const TIMEOUT_MS = 10000;
const EXCHANGES_PER_MINUTE = 60;
export const FLOW_COOKIE = 'cs_oidc';

// APP_URL is required: the redirect address must never come from a Host header.
function config() {
  const { OIDC_ISSUER: issuer, OIDC_CLIENT_ID: clientId, OIDC_CLIENT_SECRET: clientSecret, APP_URL } = process.env;
  if (!issuer || !clientId || !clientSecret || !APP_URL) return null;
  return { issuer, clientId, clientSecret, redirectUri: `${APP_URL.replace(/\/$/, '')}/api/auth/oidc/callback` };
}

export const oidcEnabled = () => Boolean(config());
export const oidcName = () => (config() ? str(process.env.OIDC_NAME, 40) || 'SSO' : null);
export const oidcRequired = () => oidcEnabled() && process.env.OIDC_REQUIRED === 'true';
// The first account may still use a password, so a server can't start out locked.
export const passwordSignupOff = () => oidcRequired() && Boolean(db.prepare('SELECT 1 FROM users LIMIT 1').get());

// Same-origin paths only. Browsers treat a backslash as a slash and strip tabs and newlines, and a Location header takes
// printable ASCII only, so anything else is refused.
export function safePath(next) {
  if (typeof next !== 'string' || next[0] !== '/' || next[1] === '/' || /[^\x21-\x7e]|\\/.test(next)) return '/app';
  return next;
}
export const startHref = (next) => (oidcEnabled() ? `/api/auth/oidc/start?next=${encodeURIComponent(safePath(next))}` : null);

function checkEndpoint(url) {
  const u = new URL(url);
  // Skipping the ID token signature rests on TLS, so an https server never talks to its provider over http.
  const allowHttp = process.env.OIDC_ALLOW_HTTP === 'true' && !process.env.APP_URL.startsWith('https://');
  if (u.protocol !== 'https:' && !(allowHttp && u.protocol === 'http:')) throw new Error('OIDC endpoints must use https');
}

let discovered = null;
async function discover({ issuer }) {
  if (discovered?.issuer === issuer && discovered.until > Date.now()) return discovered;
  checkEndpoint(issuer);
  const res = await fetch(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`, { redirect: 'error', signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!res.ok) throw new Error(`OIDC discovery returned ${res.status}`);
  const doc = await res.json();
  if (doc.issuer !== issuer) throw new Error('OIDC discovery issuer does not match OIDC_ISSUER');
  checkEndpoint(doc.authorization_endpoint);
  checkEndpoint(doc.token_endpoint);
  discovered = { issuer, authorization: doc.authorization_endpoint, token: doc.token_endpoint, until: Date.now() + DISCOVERY_MS };
  return discovered;
}

const random = () => crypto.randomBytes(32).toString('base64url');
const sameText = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(), crypto.createHash('sha256').update(String(b)).digest());

// Returns where to send the browser and the encrypted flow to keep in its cookie, which ties the callback to this browser.
// connect: the signed-in user's id, set only by the same-origin POST route, so a cross-site link can't connect an account.
export async function beginLogin(next, connect) {
  const cfg = config();
  const { authorization } = await discover(cfg);
  const state = random();
  const nonce = random();
  const verifier = random();
  const url = new URL(authorization);
  for (const [k, v] of Object.entries({
    response_type: 'code', client_id: cfg.clientId, redirect_uri: cfg.redirectUri, scope: 'openid email profile', state, nonce,
    code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
  })) url.searchParams.set(k, v);
  const flow = encryptText(JSON.stringify({ state, nonce, verifier, next: safePath(next), connect, until: Date.now() + FLOW_MS }), FLOW_AAD);
  return { url: url.href, flow };
}

export const flowCookie = (flow) => `${FLOW_COOKIE}=${encodeURIComponent(flow)}; Path=/api/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=600${process.env.APP_URL.startsWith('https://') ? '; Secure' : ''}`;

function readFlow(cookie, state) {
  let flow;
  try { flow = JSON.parse(decryptText(cookie, FLOW_AAD)); } catch { fail(400, 'SSO: missing or invalid flow cookie'); }
  if (flow.until <= Date.now()) fail(400, 'SSO: the sign-in took too long');
  if (typeof state !== 'string' || !sameText(state, flow.state)) fail(400, 'SSO: state does not match');
  return flow;
}

async function redeemCode(cfg, code, verifier) {
  const { token } = await discover(cfg);
  const res = await fetch(token, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json',
      Authorization: `Basic ${Buffer.from(`${encodeURIComponent(cfg.clientId)}:${encodeURIComponent(cfg.clientSecret)}`).toString('base64')}`,
    },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: cfg.redirectUri, code_verifier: verifier }),
  });
  if (!res.ok) fail(400, `SSO: token endpoint returned ${res.status}`);
  const idToken = (await res.json()).id_token;
  if (typeof idToken !== 'string') fail(400, 'SSO: no id_token');
  return idToken;
}

// OIDC Core 3.1.3.7: an ID token received directly from the token endpoint over TLS may skip the signature check.
// Everything else about it is checked.
function checkIdToken(idToken, cfg, nonce) {
  let claims;
  try { claims = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64url').toString('utf8')); } catch { fail(400, 'SSO: unreadable id_token'); }
  const aud = [claims.aud].flat();
  if (claims.iss !== cfg.issuer) fail(400, 'SSO: wrong issuer');
  if (!aud.includes(cfg.clientId) || ((aud.length > 1 || claims.azp !== undefined) && claims.azp !== cfg.clientId)) fail(400, 'SSO: wrong audience');
  if (typeof claims.exp !== 'number' || claims.exp * 1000 <= Date.now()) fail(400, 'SSO: id_token expired');
  if (typeof claims.nonce !== 'string' || !sameText(claims.nonce, nonce)) fail(400, 'SSO: nonce does not match');
  if (typeof claims.sub !== 'string' || !claims.sub) fail(400, 'SSO: no subject');
  return claims;
}

const allowedDomains = () => (process.env.OIDC_ALLOWED_DOMAINS || '').split(',').map((d) => d.trim().toLowerCase()).filter(Boolean);

// A provider can vouch for any address, so an unverified one could take over the matching account here.
function checkEmail(claims) {
  // Refused, not cut: a cut address could end in an allowed domain it doesn't have.
  const email = typeof claims.email === 'string' && claims.email.length <= 254 ? claims.email.trim().toLowerCase() : '';
  if (!EMAIL.test(email)) fail(403, 'SSO: the provider sent no usable email');
  if (claims.email_verified !== true && claims.email_verified !== 'true' && process.env.OIDC_TRUST_EMAIL !== 'true') fail(403, `SSO: ${email} is not verified by the provider`);
  const domains = allowedDomains();
  if (domains.length && !domains.includes(email.split('@').pop())) fail(403, `SSO: ${email} is not in an allowed domain`);
  return email;
}

// New accounts: while sign-ups are open, or by OIDC_AUTO_CREATE, which needs a domain list so a public provider can't admit anyone.
// The first account can run a closed server, so with no users yet SSO always needs the domain list.
export function oidcCanCreate() {
  const domains = allowedDomains().length > 0;
  if (!db.prepare('SELECT 1 FROM users LIMIT 1').get()) return domains;
  return signupOpen() || (process.env.OIDC_AUTO_CREATE === 'true' && domains);
}

// Current issuer only: after OIDC_ISSUER changes, an old identity must not block the password that connects the new one.
export const otherIssuerIdentities = () => db.prepare('SELECT COUNT(*) AS n FROM oidc_identities WHERE issuer <> ?').get(config()?.issuer ?? '').n;
export const hasIdentity = (userId) => Boolean(db.prepare('SELECT 1 FROM oidc_identities WHERE issuer = ? AND user_id = ?').get(config()?.issuer ?? '', userId));

// With a live session nothing here switches accounts: the person stays who they are, or gets an error.
function linkOrCreate(cfg, sub, email, name, passwordHash, sessionUserId, connect) {
  return tx(() => {
    const known = db.prepare('SELECT user_id FROM oidc_identities WHERE issuer = ? AND subject = ?').get(cfg.issuer, sub);
    if (known) {
      if (sessionUserId && known.user_id !== sessionUserId) fail(409, 'SSO: this provider account belongs to another account here');
      return { userId: known.user_id };
    }
    let userId = db.prepare('SELECT id FROM users WHERE email = ?').get(email)?.id;
    const linked = Boolean(userId);
    if (linked) {
      // The provider gave this address to someone else: never hand them the first person's account.
      if (db.prepare('SELECT 1 FROM oidc_identities WHERE issuer = ? AND user_id = ?').get(cfg.issuer, userId)) fail(403, `SSO: ${email} is linked to a different person at the provider`);
      // Sign-up doesn't verify emails, so whoever made this account may not own the address. Only its live session may connect it.
      if (userId !== sessionUserId || connect !== sessionUserId) fail(409, `SSO: ${email} has an account here; sign in to it first, then connect`);
    } else {
      if (sessionUserId) fail(409, `SSO: signed in, and ${email} has no account here`);
      if (!oidcCanCreate()) fail(403, `SSO: no account for ${email} and new accounts are off`);
      userId = createUser({ email, name, passwordHash });
    }
    db.prepare('INSERT INTO oidc_identities (issuer, subject, user_id, created_at) VALUES (?, ?, ?, ?)').run(cfg.issuer, sub, userId, now());
    return { userId, linked, created: !linked };
  });
}

// Returns { userId, email, next, linked, created }. Throws 403 for a refused person, 409 for an account that must connect first,
// 429 past the limit and 400 for a broken flow.
export async function finishLogin(query, cookie, ip, sessionUserId) {
  const cfg = config();
  let flow;
  // No log row for these: anyone can send them, with no account.
  try { flow = readFlow(cookie, query.state); } catch (e) { e.quiet = true; throw e; }
  // Anyone can get a valid state from start, so this bounds provider requests rather than proving anything. The short
  // window means filling it costs a script a minute of its own address, not an hour of everyone's.
  if (rateLimit(`oidc:${ipPrefix(ip)}`, EXCHANGES_PER_MINUTE, 6e4)) fail(429, 'SSO: too many attempts');
  if (query.error) fail(400, `SSO: provider said ${str(query.error, 60)}`);
  if (typeof query.code !== 'string' || !query.code) fail(400, 'SSO: no code');
  const claims = checkIdToken(await redeemCode(cfg, query.code, flow.verifier), cfg, flow.nonce);
  const email = checkEmail(claims);
  // scrypt stays outside the write lock. The password is random and never shown, so a new account signs in by SSO only.
  const passwordHash = await hashPassword(random());
  return { ...linkOrCreate(cfg, claims.sub, email, str(claims.name, 120) || email, passwordHash, sessionUserId, flow.connect), email, next: flow.next };
}
