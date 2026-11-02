import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DATA_DIR } from './db.js'; // circular with db.js; safe because both sides use the other only inside functions

// AES-256-GCM at rest. Layout: "CSE1" | IV (12) | tag (16) | ciphertext.
const MAGIC = Buffer.from('CSE1');
const TEXT_PREFIX = 'enc:v1:';

let key = null;
let auditKey = null;

const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function parseKey(raw, source) {
  const s = raw.trim();
  const buf = /^[0-9a-fA-F]{64}$/.test(s) ? Buffer.from(s, 'hex')
    : /^[A-Za-z0-9+/_-]+={0,2}$/.test(s) ? Buffer.from(s, 'base64') : null;
  if (!buf || buf.length !== 32) throw new Error(`${source} must be 32 bytes as 64 hex characters or base64`);
  return buf;
}

// Loaded on first use, never at import, so `next build` does not create a key file.
function getKey() {
  if (key) return key;
  if (process.env.ENCRYPTION_KEY !== undefined && process.env.ENCRYPTION_KEY !== '') {
    return (key = parseKey(process.env.ENCRYPTION_KEY, 'ENCRYPTION_KEY'));
  }
  const file = path.join(DATA_DIR, 'encryption.key');
  fs.mkdirSync(DATA_DIR, { recursive: true });
  try {
    fs.writeFileSync(file, crypto.randomBytes(32).toString('hex') + '\n', { flag: 'wx', mode: 0o600 });
  } catch (e) {
    if (e.code !== 'EEXIST') throw e;
  }
  // Another process may have created the file but not finished writing it yet.
  let raw = fs.readFileSync(file, 'utf8');
  for (let i = 0; i < 40 && raw.trim().length < 44; i++) { sleepSync(25); raw = fs.readFileSync(file, 'utf8'); }
  key = parseKey(raw, file);
  if (!globalThis.__countersignKeyWarned) {
    globalThis.__countersignKeyWarned = true;
    console.warn(`Encryption key is stored at ${file}, beside the data it protects. Back it up separately and move it to ENCRYPTION_KEY for real protection.`);
    // shortcut: 0o600 is ignored on Windows (the file inherits the folder ACL); restrict DATA_DIR there by hand.
    if (process.platform !== 'win32' && fs.statSync(file).mode & 0o077) console.warn(`${file} is readable by group or others; run chmod 600 on it.`);
  }
  return key;
}

export const isEncrypted = (buf) => buf.subarray(0, 4).equals(MAGIC);

export function encryptBuffer(buf, aad) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  cipher.setAAD(Buffer.from(String(aad)));
  const ct = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([MAGIC, iv, cipher.getAuthTag(), ct]);
}

// Strict: anything not in CSE1 format, a wrong key, a wrong AAD or tampering throws. Only the one-time
// migration in db.js handles legacy plaintext, by checking isEncrypted itself.
export function decryptBuffer(buf, aad) {
  if (!isEncrypted(buf)) throw new Error('Data is not encrypted');
  if (buf.length < 32) throw new Error('Encrypted data is truncated');
  const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), buf.subarray(4, 16));
  decipher.setAAD(Buffer.from(String(aad)));
  decipher.setAuthTag(buf.subarray(16, 32));
  return Buffer.concat([decipher.update(buf.subarray(32)), decipher.final()]);
}

export const encryptText = (str, aad) => TEXT_PREFIX + encryptBuffer(Buffer.from(String(str), 'utf8'), aad).toString('base64');

export const isEncryptedText = (v) => typeof v === 'string' && v.startsWith(TEXT_PREFIX);

// null/undefined pass through (empty field); any other value must be enc:v1: ciphertext.
export function decryptText(v, aad) {
  if (v === null || v === undefined) return v;
  if (!isEncryptedText(v)) throw new Error('Value is not encrypted');
  return decryptBuffer(Buffer.from(v.slice(TEXT_PREFIX.length), 'base64'), aad).toString('utf8');
}

// Atomic: fsync a sibling .tmp then rename over the target, so a crash never leaves a half-written file.
export function writeEncrypted(file, buf, aad) {
  const tmp = file + '.tmp';
  const fd = fs.openSync(tmp, 'w', 0o600);
  try {
    fs.writeSync(fd, encryptBuffer(buf, aad));
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
}

export const readDecrypted = (file, aad) => decryptBuffer(fs.readFileSync(file), aad);

// AAD for a stored PDF, derived from its name "<id>.<kind>.pdf".
export function fileAad(file) {
  const m = /^(.+)\.(original|signed)\.pdf$/.exec(path.basename(file));
  if (!m) throw new Error(`Not a document file: ${path.basename(file)}`);
  return `file:${m[1]}.${m[2]}`;
}

export const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

const getAuditKey = () => (auditKey ??= Buffer.from(crypto.hkdfSync('sha256', getKey(), Buffer.alloc(0), 'countersign-audit-v1', 32)));

// Short public id of the audit subkey, for display on certificates; reveals nothing usable about the key.
export const auditKeyId = () => sha256hex(getAuditKey()).slice(0, 8);

// Canonical message: (prevHash || '') + JSON of these keys in this order; detail defaults to '', ip/user_agent to null.
export const auditCanonical = (prevHash, e) => (prevHash || '') + JSON.stringify({
  document_id: e.document_id, actor: e.actor, action: e.action, detail: e.detail ?? '',
  ip: e.ip ?? null, user_agent: e.user_agent ?? null, created_at: e.created_at,
});

// Audit chain link (shared by the db.js migration and logEvent, do not change):
// hex HMAC-SHA256(auditKey, auditCanonical(prevHash, e)); auditKey = HKDF-SHA256(encryption key, salt empty, info 'countersign-audit-v1', 32 bytes).
export const auditHash = (prevHash, e) => crypto.createHmac('sha256', getAuditKey()).update(auditCanonical(prevHash, e)).digest('hex');

let logKey = null;
// Keyed, non-reversible identifier for values that must not appear in logs (e.g. an unknown login name).
export const logId = (value) => crypto.createHmac('sha256', (logKey ??= Buffer.from(crypto.hkdfSync('sha256', getKey(), Buffer.alloc(0), 'countersign-log-v1', 32))))
  .update(String(value)).digest('hex').slice(0, 16);

// Key-check value stored in meta, so a wrong key fails at startup instead of as 500s on read.
export const keyCheck = () => crypto.createHmac('sha256', getKey()).update('countersign-key-check-v1').digest('hex');
