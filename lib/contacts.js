import db, { newId, now, tx } from './db.js';
import { EMAIL, fail, str } from './http.js';

// Per-owner address book. Every query is scoped by owner_id.
const UPSERT_MAX = 50;
export const CONTACTS_MAX = 10000;
const countOf = (ownerId) => db.prepare('SELECT COUNT(*) AS n FROM contacts WHERE owner_id = ?').get(ownerId).n;
const isUnique = (e) => e?.errcode === 2067 || /UNIQUE constraint/.test(e?.message || '');

function clean(input) {
  const name = str(input?.name, 120);
  const email = str(input?.email, 255);
  return { name, email, valid: Boolean(name) && email.length <= 254 && EMAIL.test(email) };
}

function checked(input) {
  const c = clean(input);
  if (!c.name) fail(400, 'Enter a name');
  if (!c.valid) fail(400, 'Enter a valid email address');
  return c;
}

export function listContacts(ownerId, { q = '', limit = 50, offset = 0 } = {}) {
  const like = `%${String(q).trim().slice(0, 200).replace(/[\\%_]/g, '\\$&')}%`;
  const where = "owner_id = ? AND (name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')";
  const n = Math.min(Math.max(Math.trunc(Number(limit)) || 50, 1), 200);
  const skip = Math.max(Math.trunc(Number(offset)) || 0, 0);
  const contacts = db.prepare(`SELECT id, name, email FROM contacts WHERE ${where} ORDER BY name COLLATE NOCASE, email LIMIT ? OFFSET ?`)
    .all(ownerId, like, like, n, skip);
  const { total } = db.prepare(`SELECT COUNT(*) AS total FROM contacts WHERE ${where}`).get(ownerId, like, like);
  return { contacts, total };
}

export function createContact(ownerId, input) {
  const { name, email } = checked(input);
  if (countOf(ownerId) >= CONTACTS_MAX) fail(400, 'You have reached the limit of 10,000 contacts');
  const id = newId();
  const t = now();
  try {
    db.prepare('INSERT INTO contacts (id, owner_id, name, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, ownerId, name, email, t, t);
  } catch (e) {
    if (isUnique(e)) fail(409, 'A contact with this email already exists');
    throw e;
  }
  return id;
}

export function updateContact(ownerId, id, input) {
  const { name, email } = checked(input);
  let changes;
  try {
    ({ changes } = db.prepare('UPDATE contacts SET name = ?, email = ?, updated_at = ? WHERE id = ? AND owner_id = ?').run(name, email, now(), String(id), ownerId));
  } catch (e) {
    if (isUnique(e)) fail(409, 'A contact with this email already exists');
    throw e;
  }
  if (!changes) fail(404, 'Contact not found');
}

export function deleteContact(ownerId, id) {
  if (!db.prepare('DELETE FROM contacts WHERE id = ? AND owner_id = ?').run(String(id), ownerId).changes) fail(404, 'Contact not found');
}

// Inserts new emails, renames existing ones. Invalid rows, unchanged names and new emails past CONTACTS_MAX count as
// skipped. Caller wraps in tx.
function upsertMany(ownerId, list) {
  const out = { added: 0, updated: 0, skipped: 0 };
  const find = db.prepare('SELECT id, name FROM contacts WHERE owner_id = ? AND email = ?');
  const insert = db.prepare('INSERT INTO contacts (id, owner_id, name, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)');
  const rename = db.prepare('UPDATE contacts SET name = ?, updated_at = ? WHERE id = ?');
  let room = CONTACTS_MAX - countOf(ownerId);
  for (const item of list) {
    const { name, email, valid } = clean(item);
    const row = valid && find.get(ownerId, email);
    const t = now();
    if (!valid || (!row && room <= 0)) out.skipped++;
    else if (!row) { room--; insert.run(newId(), ownerId, name, email, t, t); out.added++; }
    else if (row.name !== name) { rename.run(name, t, row.id); out.updated++; }
    else out.skipped++;
  }
  return out;
}

// For sendDocument: remembers recipients. At most 50 per call; the rest are ignored.
export const upsertContacts = (ownerId, list) => tx(() => upsertMany(ownerId, (Array.isArray(list) ? list : []).slice(0, UPSERT_MAX)));

// RFC 4180: comma separated, CRLF or LF rows, "quoted" fields with "" for a quote. Blank lines are dropped.
// Bounded: input size is capped by the caller, rows by maxRows (400 beyond it, naming `limit`).
export function parseCsv(text, maxRows, limit = maxRows) {
  const s = String(text).replace(/^﻿/, '');
  const rows = [];
  let row = [], field = '', quoted = false, wasQuoted = false;
  const endRow = () => {
    row.push(field);
    if (row.length > 1 || row[0] !== '' || wasQuoted) {
      if (rows.length >= maxRows) fail(400, `The file has more than ${limit} rows`);
      rows.push(row);
    }
    row = []; field = ''; wasQuoted = false;
  };
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quoted) {
      if (c !== '"') field += c;
      else if (s[i + 1] === '"') { field += '"'; i++; }
      else quoted = false;
    } else if (c === '"' && field === '' && !wasQuoted) { quoted = true; wasQuoted = true; }
    else if (c === ',') { row.push(field); field = ''; wasQuoted = false; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && s[i + 1] === '\n') i++; endRow(); }
    else field += c;
  }
  if (quoted) fail(400, 'The file has a quote that is never closed');
  if (field !== '' || row.length || wasQuoted) endRow();
  return rows;
}

// CSV import: optional header row naming the name and email columns; otherwise column 1 is the name, column 2 the email.
export function importContacts(ownerId, text, maxRows = 2000) {
  const rows = parseCsv(text, maxRows + 1, maxRows); // +1 leaves room for a header row
  const head = (rows[0] || []).map((h) => h.trim().toLowerCase());
  const hasHeader = head.includes('email');
  let ni = 0, ei = 1;
  if (hasHeader) { ei = head.indexOf('email'); ni = head.indexOf('name'); rows.shift(); }
  if (rows.length > maxRows) fail(400, `The file has more than ${maxRows} rows`);
  return tx(() => upsertMany(ownerId, rows.map((r) => ({ name: ni >= 0 ? r[ni] : '', email: r[ei] }))));
}
