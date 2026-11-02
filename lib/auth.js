import crypto from 'node:crypto';
import { isIPv6 } from 'node:net';
import db, { now, newId, newToken, LOGIN_IP_MAX_ATTEMPTS, LOGIN_MAX_ATTEMPTS, SESSION_IDLE_MINUTES, SESSION_MAX_DAYS, SIGNUP_MAX_PER_HOUR } from './db.js';
import { sha256hex } from './crypto.js';
import { logSecurity } from './security-log.js';
import { clientInfo } from './http.js'; // circular with http.js; used only inside functions

const COOKIE = 'cs_session';
const IDLE_MS = SESSION_IDLE_MINUTES * 6e4;
const TOUCH_MS = 6e4; // write last_seen_at at most once a minute

export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export function verifyPassword(password, stored) {
  const [, salt, hash] = stored.split('$');
  const expected = Buffer.from(hash, 'base64');
  const actual = crypto.scryptSync(password, Buffer.from(salt, 'base64'), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

// Always runs scrypt, against a dummy hash for unknown accounts, so timing doesn't reveal which emails exist.
let dummyHash;
export function verifyLogin(password, stored) {
  const ok = verifyPassword(password, stored || (dummyHash ??= hashPassword(crypto.randomBytes(16).toString('hex'))));
  return Boolean(stored) && ok;
}

// Signup and password change only; existing passwords keep working. Returns an error message or null.
export function passwordProblem(password, email) {
  if (typeof password !== 'string' || password.length < 12) return 'Password must be at least 12 characters';
  if (password.length > 256) return 'Password must be at most 256 characters';
  if (email && password.trim().toLowerCase() === String(email).trim().toLowerCase()) return 'Password must not be your email address';
  return null;
}

// Rate limits, all in login_attempts (one row per key, survives restarts).
//   pair:<email>|<ip>  login failures for this account from this IP: LOGIN_MAX_ATTEMPTS per 15 min, then a 15-minute lock.
//   ip:<ip>            login failures from this IP over all accounts: LOGIN_IP_MAX_ATTEMPTS per 15 min, then a 15-minute lock
//                      that does not apply to an account that signed in successfully from this IP in the last 30 days.
//   acct:<email>       login failures for the account from anywhere, per hour: never locks (anyone could trigger it),
//                      adds a growing delay instead.
//   ok:<email>|<ip>    last successful sign-in of the account from this IP.
//   signup:<ip>        signup attempts per hour.  verify:<ip>  public /api/verify lookups per hour.  pw:<user id>  wrong current passwords in password change, per 15 min.
const LOGIN_WINDOW_MS = 15 * 6e4;
const ACCT_WINDOW_MS = 60 * 6e4;
const ACCT_DELAY_AFTER = 10;
const KNOWN_GOOD_MS = 30 * 864e5;
const ipOf = (ip) => ip || 'unknown';

// IPv6 clients usually hold a whole /64, so key them on that prefix. IPv4 and IPv4-mapped IPv6 stay per address.
export function ipPrefix(ip) {
  const a = String(ip || '').split('%')[0];
  if (!isIPv6(a) || /^::ffff:[\d.]+$/i.test(a)) return ipOf(ip);
  const v6 = a.replace(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/, (m, p, q, r, s) => `${((p << 8) | q).toString(16)}:${((r << 8) | s).toString(16)}`);
  const [head, tail] = v6.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  return `${groups.slice(0, 4).map((g) => parseInt(g, 16).toString(16)).join(':')}::/64`;
}

function lockedFor(key) {
  const until = Date.parse(db.prepare('SELECT locked_until FROM login_attempts WHERE key = ?').get(key)?.locked_until) || 0;
  return Math.max(0, Math.ceil((until - Date.now()) / 1000));
}

// Counts one hit; returns true when this hit reached the limit and locked the key for windowMs.
function bump(key, max, windowMs) {
  const t = Date.now();
  const row = db.prepare('SELECT window_start, count, locked_until FROM login_attempts WHERE key = ?').get(key);
  const fresh = !row || Date.parse(row.window_start) + windowMs <= t;
  const count = fresh ? 1 : row.count + 1;
  const lockedUntil = count >= max ? new Date(t + windowMs).toISOString() : fresh ? null : row.locked_until;
  db.prepare(`INSERT INTO login_attempts (key, window_start, count, locked_until) VALUES (?, ?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET window_start = excluded.window_start, count = excluded.count, locked_until = excluded.locked_until`)
    .run(key, fresh ? new Date(t).toISOString() : row.window_start, count, lockedUntil);
  return count >= max;
}

const clearKey = (key) => db.prepare('DELETE FROM login_attempts WHERE key = ?').run(key);

function knownGood(email, ip) {
  const at = db.prepare('SELECT window_start FROM login_attempts WHERE key = ?').get(`ok:${email}|${ipOf(ip)}`)?.window_start;
  return Boolean(at) && Date.parse(at) + KNOWN_GOOD_MS > Date.now();
}

// Seconds the caller must wait before this login attempt is evaluated; 0 when allowed.
export function loginLockedFor(email, ip) {
  const pair = lockedFor(`pair:${email}|${ipOf(ip)}`);
  if (pair) return pair;
  const perIp = lockedFor(`ip:${ipOf(ip)}`);
  return perIp && !knownGood(email, ip) ? perIp : 0;
}

// Delay (ms) to apply before checking the password once an account sees many failures from anywhere.
export function loginDelayMs(email) {
  const row = db.prepare('SELECT window_start, count FROM login_attempts WHERE key = ?').get(`acct:${email}`);
  if (!row || Date.parse(row.window_start) + ACCT_WINDOW_MS <= Date.now() || row.count < ACCT_DELAY_AFTER) return 0;
  return Math.min(5000, 250 * (row.count - ACCT_DELAY_AFTER + 1));
}

// Counts an attempt as a failure up front (call it synchronously, before any await, so a parallel burst can't
// pass the lock check together). Returns true when it locked the account+IP pair or the IP.
export function recordLoginFailure(email, ip) {
  bump(`acct:${email}`, Infinity, ACCT_WINDOW_MS);
  const pair = bump(`pair:${email}|${ipOf(ip)}`, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_MS);
  const perIp = bump(`ip:${ipOf(ip)}`, LOGIN_IP_MAX_ATTEMPTS, LOGIN_WINDOW_MS);
  return pair || perIp;
}

// After a correct password: clears this account's counters (including its own reservation), refunds the IP
// counter for this one attempt, and remembers the IP. Other accounts' counters are kept.
export function recordLoginSuccess(email, ip) {
  clearKey(`pair:${email}|${ipOf(ip)}`);
  clearKey(`acct:${email}`);
  // A lock is only set when count reaches the limit, so dropping below it means this reservation set it.
  db.prepare(`UPDATE login_attempts SET count = MAX(count - 1, 0), locked_until = CASE WHEN count - 1 < ? THEN NULL ELSE locked_until END
    WHERE key = ?`).run(LOGIN_IP_MAX_ATTEMPTS, `ip:${ipOf(ip)}`);
  db.prepare(`INSERT INTO login_attempts (key, window_start, count) VALUES (?, ?, 0)
    ON CONFLICT(key) DO UPDATE SET window_start = excluded.window_start`).run(`ok:${email}|${ipOf(ip)}`, now());
}

// Signup: SIGNUP_MAX_PER_HOUR attempts per IP. Returns seconds to wait, counting this attempt when allowed.
export function signupThrottle(ip) {
  const wait = lockedFor(`signup:${ipOf(ip)}`);
  if (!wait) bump(`signup:${ipOf(ip)}`, SIGNUP_MAX_PER_HOUR, ACCT_WINDOW_MS);
  return wait;
}

// Public verify lookups: 60 per hour per IP (per /64 for IPv6). Same contract as signupThrottle.
export function verifyThrottle(ip) {
  const key = `verify:${ipPrefix(ip)}`;
  const wait = lockedFor(key);
  if (!wait) bump(key, 60, ACCT_WINDOW_MS);
  return wait;
}

// Password change: LOGIN_MAX_ATTEMPTS wrong current passwords per 15 minutes per user, then a 15-minute lock.
export const passwordCheckLockedFor = (userId) => lockedFor(`pw:${userId}`);
export const recordPasswordCheckFailure = (userId) => bump(`pw:${userId}`, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_MS);
export const clearPasswordCheckFailures = (userId) => clearKey(`pw:${userId}`);

const secure = () => (process.env.APP_URL || '').startsWith('https://');
const cookieHash = (req) => { const id = req.cookies?.[COOKIE]; return id ? sha256hex(id) : null; };
const clearCookie = (res) => res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);

// The cookie carries a random token; the DB stores only its SHA-256.
export function startSession(res, userId, { ip = null, userAgent = null } = {}) {
  const token = newToken();
  const expires = new Date(Date.now() + SESSION_MAX_DAYS * 864e5);
  db.prepare('INSERT INTO sessions (id, id_hash, user_id, expires_at, last_seen_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(newId(), sha256hex(token), userId, expires.toISOString(), now(), ip, userAgent);
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Expires=${expires.toUTCString()}${secure() ? '; Secure' : ''}`);
}

export function endSession(req, res, info = {}) {
  const hash = cookieHash(req);
  const row = hash && db.prepare('SELECT s.user_id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?').get(hash);
  if (row) {
    db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(hash);
    logSecurity('logout', { ...info, userId: row.user_id, email: row.email });
  }
  clearCookie(res);
}

export function endAllSessions(res, user, info = {}) {
  const { changes } = db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
  logSecurity('logout_all', { ...info, userId: user.id, email: user.email, detail: `${changes} sessions` });
  clearCookie(res);
}

export const revokeOtherSessions = (req, userId) =>
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND id_hash IS NOT ?').run(userId, cookieHash(req)).changes;

export function getUser(req) {
  const hash = cookieHash(req);
  if (!hash) return null;
  const s = db.prepare(
    `SELECT s.id AS sid, s.expires_at, s.last_seen_at, u.id, u.email, u.name FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.id_hash = ?`
  ).get(hash);
  if (!s) return null;
  const t = Date.now();
  const seen = Date.parse(s.last_seen_at) || 0;
  if (Date.parse(s.expires_at) <= t || seen + IDLE_MS <= t) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(s.sid);
    logSecurity('session_expired', { ...clientInfo(req), userId: s.id, email: s.email });
    return null;
  }
  if (seen + TOUCH_MS <= t) db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(now(), s.sid);
  return { id: s.id, email: s.email, name: s.name };
}

// Hourly job: drop expired sessions and stale rate-limit counters.
export function purgeExpired() {
  const t = now();
  const idleCutoff = new Date(Date.now() - IDLE_MS).toISOString();
  const windowCutoff = new Date(Date.now() - ACCT_WINDOW_MS).toISOString();
  const okCutoff = new Date(Date.now() - KNOWN_GOOD_MS).toISOString();
  db.prepare('DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at IS NULL OR last_seen_at <= ?').run(t, idleCutoff);
  db.prepare("DELETE FROM login_attempts WHERE key NOT LIKE 'ok:%' AND window_start <= ? AND (locked_until IS NULL OR locked_until <= ?)").run(windowCutoff, t);
  db.prepare("DELETE FROM login_attempts WHERE key LIKE 'ok:%' AND window_start <= ?").run(okCutoff);
}

export function signupOpen() {
  const { n } = db.prepare('SELECT COUNT(*) AS n FROM users').get();
  return n === 0 || process.env.ALLOW_SIGNUP === 'true';
}

export function createUser({ email, name, password }) {
  const id = newId();
  db.prepare('INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, email, name, hashPassword(password), now());
  return id;
}

// getServerSideProps helper: redirect to /login when signed out.
export function withUser(handler) {
  return async (ctx) => {
    const user = getUser(ctx.req);
    if (!user) return { redirect: { destination: `/login?next=${encodeURIComponent(ctx.resolvedUrl)}`, permanent: false } };
    return handler(ctx, { ...user });
  };
}
