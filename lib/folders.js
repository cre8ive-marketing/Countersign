import db, { newId, now, tx } from './db.js';
import { fail } from './http.js';
import { cleanName } from './apikeys.js';

// Flat, per-user folders. Every query is scoped by owner_id; deleting a folder unfiles its documents.
export const FOLDERS_MAX = 200;
const isUnique = (e) => e?.errcode === 2067 || /UNIQUE constraint/.test(e?.message || '');
const DUPLICATE = 'A folder with this name already exists';

export function listFolders(ownerId) {
  return db.prepare(`SELECT f.id, f.name, (SELECT COUNT(*) FROM documents d WHERE d.folder_id = f.id AND d.owner_id = f.owner_id) AS count
    FROM folders f WHERE f.owner_id = ? ORDER BY f.name COLLATE NOCASE`).all(ownerId).map((f) => ({ ...f }));
}

export function createFolder(ownerId, input) {
  const name = cleanName(input?.name, 'Enter a folder name');
  return tx(() => {
    if (db.prepare('SELECT COUNT(*) AS n FROM folders WHERE owner_id = ?').get(ownerId).n >= FOLDERS_MAX) fail(409, `You can have up to ${FOLDERS_MAX} folders`);
    const id = newId();
    const t = now();
    try {
      db.prepare('INSERT INTO folders (id, owner_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)').run(id, ownerId, name, t, t);
    } catch (e) {
      if (isUnique(e)) fail(409, DUPLICATE);
      throw e;
    }
    return id;
  });
}

export function renameFolder(ownerId, id, input) {
  const name = cleanName(input?.name, 'Enter a folder name');
  let changes;
  try {
    ({ changes } = db.prepare('UPDATE folders SET name = ?, updated_at = ? WHERE id = ? AND owner_id = ?').run(name, now(), String(id), ownerId));
  } catch (e) {
    if (isUnique(e)) fail(409, DUPLICATE);
    throw e;
  }
  if (!changes) fail(404, 'Folder not found');
}

export function deleteFolder(ownerId, id) {
  tx(() => {
    if (!db.prepare('DELETE FROM folders WHERE id = ? AND owner_id = ?').run(String(id), ownerId).changes) fail(404, 'Folder not found');
    db.prepare('UPDATE documents SET folder_id = NULL WHERE folder_id = ? AND owner_id = ?').run(String(id), ownerId);
  });
}

// `full` comes from ownedDocument; folderId null unfiles. Any status, templates too.
export function moveDocument(full, folderId) {
  if (folderId != null && (typeof folderId !== 'string' || !db.prepare('SELECT 1 FROM folders WHERE id = ? AND owner_id = ?').get(folderId, full.doc.owner_id))) {
    fail(404, 'Folder not found');
  }
  db.prepare('UPDATE documents SET folder_id = ? WHERE id = ? AND owner_id = ?').run(folderId ?? null, full.doc.id, full.doc.owner_id);
}

// GET /api/documents: the owner's documents, newest first.
export function listDocuments(ownerId, q = {}) {
  const where = ['owner_id = ?'];
  const args = [ownerId];
  if (typeof q.status === 'string' && q.status) { where.push('status = ?'); args.push(q.status); }
  if (q.template === '0' || q.template === '1') { where.push('is_template = ?'); args.push(Number(q.template)); }
  if (typeof q.folder === 'string' && q.folder) { where.push('folder_id = ?'); args.push(q.folder); }
  const limit = Math.min(Math.max(Math.trunc(Number(q.limit)) || 50, 1), 200);
  const offset = Math.max(Math.trunc(Number(q.offset)) || 0, 0);
  const sql = where.join(' AND ');
  const documents = db.prepare(`SELECT id, title, status, is_template, folder_id, created_at, updated_at, sent_at, completed_at FROM documents
    WHERE ${sql} ORDER BY updated_at DESC, id LIMIT ? OFFSET ?`).all(...args, limit, offset).map((d) => ({
    id: d.id, title: d.title, status: d.status, isTemplate: Boolean(d.is_template), folderId: d.folder_id,
    createdAt: d.created_at, updatedAt: d.updated_at, sentAt: d.sent_at, completedAt: d.completed_at,
  }));
  return { documents, total: db.prepare(`SELECT COUNT(*) AS total FROM documents WHERE ${sql}`).get(...args).total };
}
