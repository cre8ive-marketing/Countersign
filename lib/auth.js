import crypto from 'node:crypto';
import db, { now, newId, newToken } from './db';

const COOKIE = 'cs_session';
const SESSION_DAYS = 30;

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

const secure = () => (process.env.APP_URL || '').startsWith('https://');

export function startSession(res, userId) {
  const id = newToken();
  const expires = new Date(Date.now() + SESSION_DAYS * 864e5);
  db.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').run(id, userId, expires.toISOString());
  res.setHeader('Set-Cookie', `${COOKIE}=${id}; Path=/; HttpOnly; SameSite=Lax; Expires=${expires.toUTCString()}${secure() ? '; Secure' : ''}`);
}

export function endSession(req, res) {
  const id = req.cookies?.[COOKIE];
  if (id) db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

export function getUser(req) {
  const id = req.cookies?.[COOKIE];
  if (!id) return null;
  return db.prepare(
    `SELECT u.id, u.email, u.name FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.id = ? AND s.expires_at > ?`
  ).get(id, now()) ?? null;
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
