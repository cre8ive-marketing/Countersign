import db, { now } from './db.js';
import { decryptText, encryptText } from './crypto.js';

// A user's adopted signature and initials, encrypted at rest (AAD binds the value to user and kind).
export const SIGNATURE_KINDS = ['signature', 'initials'];
const aad = (userId, kind) => `usersig:${userId}:${kind}`;

export function savedSignatures(userId) {
  const out = { signature: null, initials: null };
  for (const r of db.prepare('SELECT kind, value FROM user_signatures WHERE user_id = ?').all(userId)) {
    if (SIGNATURE_KINDS.includes(r.kind)) out[r.kind] = decryptText(r.value, aad(userId, r.kind));
  }
  return out;
}

// `value` must already have passed checkSignaturePng.
export function saveSignature(userId, kind, value) {
  db.prepare(`INSERT INTO user_signatures (user_id, kind, value, updated_at) VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, kind) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
    .run(userId, kind, encryptText(value, aad(userId, kind)), now());
}

export const deleteSignature = (userId, kind) => db.prepare('DELETE FROM user_signatures WHERE user_id = ? AND kind = ?').run(userId, kind);
