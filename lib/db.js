import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { auditCanonical, auditHash, decryptText, encryptText, fileAad, isEncrypted, keyCheck, readDecrypted, sha256hex, writeEncrypted } from './crypto.js';

// shortcut: the build tracer may still copy a local ./data into .next/standalone; Docker excludes it (.dockerignore + rm in Dockerfile).
export const DATA_DIR = path.resolve(process.env.DATA_DIR || [process.cwd(), 'data'].join(path.sep));
export const FILES_DIR = path.join(DATA_DIR, 'files');

const envNumber = (name, def) => { const n = Number(process.env[name]); return Number.isFinite(n) && n > 0 ? n : def; };
export const TOKEN_TTL_DAYS = envNumber('TOKEN_TTL_DAYS', 30);
export const SESSION_IDLE_MINUTES = envNumber('SESSION_IDLE_MINUTES', 60);
export const SESSION_MAX_DAYS = envNumber('SESSION_MAX_DAYS', 7);
export const LOGIN_MAX_ATTEMPTS = envNumber('LOGIN_MAX_ATTEMPTS', 5);
export const LOGIN_IP_MAX_ATTEMPTS = envNumber('LOGIN_IP_MAX_ATTEMPTS', 50);
export const SIGNUP_MAX_PER_HOUR = envNumber('SIGNUP_MAX_PER_HOUR', 10);

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  message TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'draft',
  is_template INTEGER NOT NULL DEFAULT 0,
  sequential INTEGER NOT NULL DEFAULT 0,
  reminder_days INTEGER NOT NULL DEFAULT 0,
  page_count INTEGER NOT NULL DEFAULT 0,
  original_sha256 TEXT NOT NULL,
  signed_sha256 TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  sent_at TEXT,
  completed_at TEXT
);
CREATE TABLE IF NOT EXISTS recipients (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'signer',
  routing_order INTEGER NOT NULL DEFAULT 1,
  position INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  token TEXT UNIQUE,
  viewed_at TEXT,
  signed_at TEXT,
  declined_reason TEXT,
  last_notified_at TEXT
);
CREATE TABLE IF NOT EXISTS fields (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  recipient_id TEXT NOT NULL REFERENCES recipients(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  page INTEGER NOT NULL,
  x REAL NOT NULL, y REAL NOT NULL, w REAL NOT NULL, h REAL NOT NULL,
  required INTEGER NOT NULL DEFAULT 1,
  label TEXT NOT NULL DEFAULT '',
  value TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  ip TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  type TEXT NOT NULL,
  user_id TEXT,
  email TEXT,
  ip TEXT,
  user_agent TEXT,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS login_attempts (
  key TEXT PRIMARY KEY,
  window_start TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT
);
CREATE TABLE IF NOT EXISTS audit_tombstones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id TEXT NOT NULL,
  title TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  status TEXT NOT NULL,
  deleted_at TEXT NOT NULL,
  deleted_by TEXT,
  final_hash TEXT,
  event_count INTEGER NOT NULL DEFAULT 0,
  events_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_signatures (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, kind)
);
CREATE TABLE IF NOT EXISTS contacts (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  email TEXT NOT NULL COLLATE NOCASE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (owner_id, email)
);
CREATE TABLE IF NOT EXISTS email_templates (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_docs_signed_sha ON documents(signed_sha256);
CREATE INDEX IF NOT EXISTS idx_docs_original_sha ON documents(original_sha256);
CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner_id);
CREATE INDEX IF NOT EXISTS idx_recipients_doc ON recipients(document_id);
CREATE INDEX IF NOT EXISTS idx_fields_doc ON fields(document_id);
CREATE INDEX IF NOT EXISTS idx_events_doc ON events(document_id);
CREATE INDEX IF NOT EXISTS idx_security_events_at ON security_events(at);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_tombstones_doc ON audit_tombstones(document_id);
`;

function open() {
  fs.mkdirSync(FILES_DIR, { recursive: true });
  const db = new DatabaseSync(path.join(DATA_DIR, 'countersign.db'));
  db.exec('PRAGMA busy_timeout = 5000;');
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  try {
    // Legacy plaintext is encrypted only on the first open of pre-encryption data: never once a key check or
    // any ciphertext file exists, so deleting the marker row can't get a planted plaintext file re-encrypted.
    const legacy = !getMeta(db, 'encryption_migrated') && !getMeta(db, 'key_check') && !anyEncryptedFile();
    if (legacy) encryptLegacyFiles();
    inTx(db, () => {
      migrate(db);
      if (legacy) encryptLegacyFields(db);
      setMeta(db, 'encryption_migrated', '1');
    });
  } catch (e) {
    db.close(); // open() is retried on the next access; don't leak a handle per attempt
    throw e;
  }
  return db;
}

const anyEncryptedFile = () => fs.readdirSync(FILES_DIR).some((n) => /^.+\.(original|signed)\.pdf$/.test(n) && isEncrypted(fs.readFileSync(path.join(FILES_DIR, n))));
const getMeta = (db, key) => db.prepare('SELECT value FROM meta WHERE key = ?').get(key)?.value;
const setMeta = (db, key, value) => db.prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value);

// Startup-time security event (the db proxy and logSecurity aren't usable inside open()).
function logStartup(db, type, detail) {
  const event = { at: new Date().toISOString(), type, user_id: null, email: null, ip: null, user_agent: null, detail };
  db.prepare('INSERT INTO security_events (at, type, detail) VALUES (?, ?, ?)').run(event.at, type, detail);
  console.warn(JSON.stringify({ security_event: event }));
}

// Fail fast on a wrong key. The first open with this check stores an HMAC of a constant; when existing
// ciphertext is present, one sample must decrypt before that value is trusted.
function checkKey(db) {
  const mismatch = () => new Error('ENCRYPTION_KEY does not match this data (key check failed). Start with the key this data was encrypted with.');
  const stored = getMeta(db, 'key_check');
  if (stored) {
    if (stored !== keyCheck()) throw mismatch();
    return;
  }
  const sample = db.prepare(`SELECT 'field:' || id AS aad, value AS v FROM fields WHERE value LIKE 'enc:v1:%'
    UNION ALL SELECT 'token:' || id, token_enc FROM recipients WHERE token_enc IS NOT NULL LIMIT 1`).get();
  const file = fs.readdirSync(FILES_DIR).find((n) => /^.+\.(original|signed)\.pdf$/.test(n) && isEncrypted(fs.readFileSync(path.join(FILES_DIR, n))));
  try {
    if (sample) decryptText(sample.v, sample.aad);
    if (file) readDecrypted(path.join(FILES_DIR, file), fileAad(file));
  } catch {
    throw mismatch();
  }
  setMeta(db, 'key_check', keyCheck());
}

function inTx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    fn();
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

// Additive, idempotent migrations, in one IMMEDIATE transaction so two processes can't both ALTER.
function migrate(db) {
  const addColumns = (table, cols) => {
    const have = new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name));
    for (const [name, type] of Object.entries(cols)) if (!have.has(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
  };
  addColumns('recipients', { token_hash: 'TEXT', token_enc: 'TEXT', token_expires_at: 'TEXT', token_revoked_at: 'TEXT' });
  addColumns('sessions', { id_hash: 'TEXT', last_seen_at: 'TEXT', ip: 'TEXT', user_agent: 'TEXT' });
  addColumns('events', { prev_hash: 'TEXT', hash: 'TEXT' });
  addColumns('documents', { require_otp: 'INTEGER NOT NULL DEFAULT 0', expire_days: 'INTEGER NOT NULL DEFAULT 0', expires_at: 'TEXT', redirect_url: 'TEXT' });
  addColumns('recipients', {
    otp_hash: 'TEXT', otp_expires_at: 'TEXT', otp_attempts: 'INTEGER NOT NULL DEFAULT 0', otp_sent_at: 'TEXT',
    otp_send_count: 'INTEGER NOT NULL DEFAULT 0', otp_session_hash: 'TEXT', otp_session_expires_at: 'TEXT', otp_verified_at: 'TEXT',
  });
  addColumns('fields', { options: 'TEXT' }); // JSON array of strings, dropdown/radio only
  db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_recipients_token_hash ON recipients(token_hash) WHERE token_hash IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_id_hash ON sessions(id_hash);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_docs_expires ON documents(status, expires_at) WHERE expires_at IS NOT NULL;`);
  checkKey(db);

  // Signing tokens are credentials: keep a SHA-256 for lookup and a ciphertext for the owner's copy-link UI, drop the plaintext.
  const expires = new Date(Date.now() + TOKEN_TTL_DAYS * 864e5).toISOString();
  const setToken = db.prepare('UPDATE recipients SET token_hash = ?, token_enc = ?, token_expires_at = COALESCE(token_expires_at, ?), token = NULL WHERE id = ?');
  for (const r of db.prepare('SELECT id, token, status FROM recipients WHERE token IS NOT NULL').all()) {
    setToken.run(sha256hex(r.token), encryptText(r.token, `token:${r.id}`), expires, r.id);
  }
  // Every live token expires; legacy rows migrated without an expiry get one now.
  db.prepare('UPDATE recipients SET token_expires_at = ? WHERE token_hash IS NOT NULL AND token_expires_at IS NULL').run(expires);

  // Pre-hash sessions stored the cookie value as the id: invalidate them (users sign in again once).
  db.exec('DELETE FROM sessions WHERE id_hash IS NULL');

  // Audit chain, ordered by created_at then id. Once: re-key chains from unkeyed SHA-256 to HMAC, but only
  // chains that still verify under the old scheme; a broken chain stays broken (evidence) and is logged.
  const chain = db.prepare('SELECT * FROM events WHERE document_id = ? ORDER BY created_at, id');
  const setHash = db.prepare('UPDATE events SET prev_hash = ?, hash = ? WHERE id = ?');
  if (!getMeta(db, 'audit_hmac')) {
    const legacyLink = (prev, e) => sha256hex(auditCanonical(prev, e));
    for (const { document_id } of db.prepare('SELECT DISTINCT document_id FROM events').all()) {
      const rows = chain.all(document_id);
      let prev = null;
      const broken = rows.find((e) => {
        if (e.hash && ((e.prev_hash ?? null) !== prev || e.hash !== legacyLink(prev, e))) return true;
        prev = e.hash || legacyLink(prev, e);
        return false;
      });
      if (broken) {
        logStartup(db, 'audit_chain_broken', `document ${document_id}: chain broken at event ${broken.id} before re-keying; left as is`);
        continue;
      }
      prev = null;
      for (const e of rows) {
        const hash = auditHash(prev, e);
        setHash.run(prev, hash, e.id);
        prev = hash;
      }
    }
    setMeta(db, 'audit_hmac', '1');
  }
  // Backfill rows without a hash (keyed).
  for (const { document_id } of db.prepare('SELECT DISTINCT document_id FROM events WHERE hash IS NULL').all()) {
    let prev = null;
    for (const e of chain.all(document_id)) {
      const hash = e.hash || auditHash(prev, e);
      if (!e.hash) setHash.run(prev, hash, e.id);
      prev = hash;
    }
  }
}

// Encrypts plaintext left from before encryption at rest. Runs until the encryption_migrated marker is set.
function encryptLegacyFiles() {
  for (const name of fs.readdirSync(FILES_DIR)) {
    const m = /^(.+)\.(original|signed)\.pdf$/.exec(name); // skips .tmp leftovers
    if (!m) continue;
    const file = path.join(FILES_DIR, name);
    const bytes = fs.readFileSync(file);
    if (!isEncrypted(bytes)) writeEncrypted(file, bytes, `file:${m[1]}.${m[2]}`);
  }
}

function encryptLegacyFields(db) {
  const update = db.prepare('UPDATE fields SET value = ? WHERE id = ? AND value = ?');
  for (const r of db.prepare("SELECT id, value FROM fields WHERE value IS NOT NULL AND value NOT LIKE 'enc:v1:%'").all()) {
    update.run(encryptText(r.value, `field:${r.id}`), r.id, r.value);
  }
}

// Opened on first use (not at import, so `next build` never touches it); one connection per process, kept across dev reloads.
const db = new Proxy({}, {
  get(_, key) {
    const real = (globalThis.__countersignDb ??= open());
    const value = real[key];
    return typeof value === 'function' ? value.bind(real) : value;
  },
});
export default db;

export const now = () => new Date().toISOString();
export const newId = () => crypto.randomUUID();
export const newToken = () => crypto.randomBytes(24).toString('base64url');

export function tx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}
