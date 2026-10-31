import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

// shortcut: the build tracer may still copy a local ./data into .next/standalone; Docker excludes it (.dockerignore + rm in Dockerfile).
export const DATA_DIR = path.resolve(process.env.DATA_DIR || [process.cwd(), 'data'].join(path.sep));
export const FILES_DIR = path.join(DATA_DIR, 'files');

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
CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_recipients_doc ON recipients(document_id);
CREATE INDEX IF NOT EXISTS idx_fields_doc ON fields(document_id);
CREATE INDEX IF NOT EXISTS idx_events_doc ON events(document_id);
`;

function open() {
  fs.mkdirSync(FILES_DIR, { recursive: true });
  const db = new DatabaseSync(path.join(DATA_DIR, 'countersign.db'));
  db.exec('PRAGMA busy_timeout = 5000;');
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  return db;
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
