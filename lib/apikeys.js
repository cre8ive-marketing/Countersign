import crypto from 'node:crypto';
import db, { newId, now } from './db.js';
import { keyedHash } from './crypto.js';
import { logSecurity } from './security-log.js';
import { rateLimit } from './auth.js';
import { clientInfo, fail } from './http.js'; // circular with http.js; used only inside functions

// Personal API keys: `cs_` + 32 random bytes base64url, shown once, stored only as keyedHash('apikey', key).
export const KEYS_MAX = 20;
const KEY_FORMAT = /^cs_[A-Za-z0-9_-]{43}$/;
const RATE_MAX = 600; // requests per hour per key
const TOUCH_MS = 6e4;

export const hashKey = (key) => keyedHash('apikey', key);
export const newKey = () => `cs_${crypto.randomBytes(32).toString('base64url')}`;

export function cleanName(v, missing) {
  const name = typeof v === 'string' ? v.trim() : '';
  if (!name) fail(400, missing);
  if (name.length > 80) fail(400, 'Use at most 80 characters');
  return name;
}

export function listKeys(userId) {
  return db.prepare('SELECT id, name, prefix, created_at, last_used_at FROM api_keys WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC')
    .all(userId).map((k) => ({ id: k.id, name: k.name, prefix: k.prefix, createdAt: k.created_at, lastUsedAt: k.last_used_at }));
}

export function createKey(user, input, req) {
  const name = cleanName(input?.name, 'Enter a name for the key');
  const { n } = db.prepare('SELECT COUNT(*) AS n FROM api_keys WHERE user_id = ? AND revoked_at IS NULL').get(user.id);
  if (n >= KEYS_MAX) fail(409, `You can have up to ${KEYS_MAX} API keys`);
  const id = newId();
  const key = newKey();
  db.prepare('INSERT INTO api_keys (id, user_id, name, key_hash, prefix, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, user.id, name, hashKey(key), key.slice(0, 10), now());
  logSecurity('api_key_created', { ...clientInfo(req), userId: user.id, email: user.email, detail: `key ${id} (${key.slice(0, 10)})` });
  return { id, key };
}

export function revokeKey(user, id, req) {
  const { changes } = db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL').run(now(), String(id), user.id);
  if (!changes) fail(404, 'API key not found');
  logSecurity('api_key_revoked', { ...clientInfo(req), userId: user.id, email: user.email, detail: `key ${id}` });
}

// Resolves `Authorization: Bearer cs_...` to its user, or throws 401/429. Session cookies are never consulted here.
export function userForApiKey(req, res) {
  const key = /^Bearer\s+(\S+)\s*$/i.exec(req.headers.authorization || '')?.[1] || '';
  const row = KEY_FORMAT.test(key) && db.prepare(
    `SELECT k.id AS kid, k.last_used_at, u.id, u.email, u.name FROM api_keys k JOIN users u ON u.id = k.user_id
     WHERE k.key_hash = ? AND k.revoked_at IS NULL`).get(hashKey(key));
  if (!row) fail(401, 'Invalid API key');
  const wait = rateLimit(`apikey:${row.kid}`, RATE_MAX, 36e5);
  if (wait) {
    res.setHeader('Retry-After', String(wait));
    fail(429, 'Too many requests for this API key. Try again later.');
  }
  if ((Date.parse(row.last_used_at) || 0) + TOUCH_MS <= Date.now()) db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(now(), row.kid);
  return { id: row.id, email: row.email, name: row.name, apiKeyId: row.kid };
}
