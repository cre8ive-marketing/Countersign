import db, { newId, now, tx } from './db.js';
import { fail } from './http.js';
import { cleanName } from './apikeys.js';
import { teamOf } from './teams.js';

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

// GET /api/documents: the user's documents plus their team's shared documents, newest first.
// scope=mine|team narrows it; the folder filter only matches the user's own folders.
export function listDocuments(user, q = {}) {
  const teamId = teamOf(user.id)?.teamId ?? null;
  const where = [q.scope === 'mine' ? 'd.owner_id = ?' : q.scope === 'team' ? 'd.team_id = ?' : '(d.owner_id = ? OR d.team_id = ?)'];
  const args = q.scope === 'mine' ? [user.id] : q.scope === 'team' ? [teamId] : [user.id, teamId];
  if (typeof q.status === 'string' && q.status) { where.push('d.status = ?'); args.push(q.status); }
  if (q.template === '0' || q.template === '1') { where.push('d.is_template = ?'); args.push(Number(q.template)); }
  if (typeof q.folder === 'string' && q.folder) { where.push('d.folder_id = ? AND d.owner_id = ?'); args.push(q.folder, user.id); }
  const limit = Math.min(Math.max(Math.trunc(Number(q.limit)) || 50, 1), 200);
  const offset = Math.max(Math.trunc(Number(q.offset)) || 0, 0);
  const sql = where.join(' AND ');
  const documents = db.prepare(`SELECT d.id, d.title, d.status, d.is_template, d.folder_id, d.team_id, d.owner_id, u.name AS owner_name,
    d.created_at, d.updated_at, d.sent_at, d.completed_at FROM documents d JOIN users u ON u.id = d.owner_id
    WHERE ${sql} ORDER BY d.updated_at DESC, d.id LIMIT ? OFFSET ?`).all(...args, limit, offset).map((d) => ({
    id: d.id, title: d.title, status: d.status, isTemplate: Boolean(d.is_template),
    folderId: d.owner_id === user.id ? d.folder_id : null, // others' folder ids mean nothing to this user
    ownerName: d.owner_name, teamShared: Boolean(d.team_id),
    createdAt: d.created_at, updatedAt: d.updated_at, sentAt: d.sent_at, completedAt: d.completed_at,
  }));
  return { documents, total: db.prepare(`SELECT COUNT(*) AS total FROM documents d WHERE ${sql}`).get(...args).total };
}
