import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import db, { FILES_DIR, TOKEN_TTL_DAYS, now, newId, newToken, tx } from './db';
import { fail, str, EMAIL, clientInfo } from './http';
import { sendMail } from './mail';
import { buildSignedPdf } from './stamp';
import * as cryptoLib from './crypto.js';
import { logSecurity } from './security-log.js';
import { PDFDocument } from 'pdf-lib';

const { auditHash, decryptText, encryptText, readDecrypted, sha256hex, writeEncrypted } = cryptoLib;

export const FIELD_TYPES = ['signature', 'initials', 'date', 'name', 'email', 'text', 'checkbox'];
const AUTO_FIELDS = new Set(['date', 'name', 'email']);
const SIGNATURE_MAX = 400_000;

export const filePath = (id, kind = 'original') => path.join(FILES_DIR, `${id}.${kind}.pdf`);
export const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const fileAad = (id, kind = 'original') => `file:${id}.${kind}`;
// PDFs and field values are AES-256-GCM encrypted at rest; hashes stay over the plaintext bytes.
const readFile = (id, kind) => readDecrypted(filePath(id, kind), fileAad(id, kind));
const writeFile = (id, kind, bytes) => writeEncrypted(filePath(id, kind), bytes, fileAad(id, kind));

// Decrypts a stored PDF and checks it against the hash recorded at upload or completion. Use for every read.
export function readVerified(doc, kind = 'original') {
  if (!fs.existsSync(filePath(doc.id, kind))) fail(404, 'File not found');
  const bytes = readFile(doc.id, kind);
  const expected = kind === 'signed' ? doc.signed_sha256 : doc.original_sha256;
  if (!expected || sha256(bytes) !== expected) {
    logSecurity('file_integrity_failure', { userId: doc.owner_id, detail: `document ${doc.id} ${kind}` });
    fail(500, 'File integrity check failed');
  }
  return bytes;
}

export function loadDocument(id) {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(id);
  if (!doc) return null;
  const recipients = db.prepare('SELECT * FROM recipients WHERE document_id = ? ORDER BY position').all(id).map(withToken);
  const fields = db.prepare('SELECT * FROM fields WHERE document_id = ?').all(id)
    .map((f) => ({ ...f, value: decryptText(f.value, `field:${f.id}`) }));
  return { doc, recipients, fields };
}

// Signing tokens are stored as SHA-256 (lookup) plus an encrypted copy (owner's copy-link UI); never in plaintext.
export const signingToken = (r) => (r?.token_enc ? decryptText(r.token_enc, `token:${r.id}`) : null);
// Callers keep seeing r.token (plaintext, owner-side only); the hash and ciphertext stay server-internal.
function withToken(r) {
  const { token_hash, token_enc, ...rest } = r;
  return { ...rest, token: signingToken(r) };
}
const tokenExpiry = () => new Date(Date.now() + TOKEN_TTL_DAYS * 864e5).toISOString();
const extendToken = (id) => db.prepare('UPDATE recipients SET token_expires_at = ? WHERE id = ? AND token_revoked_at IS NULL').run(tokenExpiry(), id);
const revokeTokens = (docId) => db.prepare('UPDATE recipients SET token_revoked_at = ? WHERE document_id = ? AND token_revoked_at IS NULL').run(now(), docId);

export function ownedDocument(id, userId) {
  const full = loadDocument(String(id));
  if (!full || full.doc.owner_id !== userId) fail(404, 'Document not found');
  return full;
}

// Chain order is (created_at, id), the same order the db.js backfill used.
export function events(docId) {
  return db.prepare('SELECT * FROM events WHERE document_id = ? ORDER BY created_at, id').all(docId);
}

const chainTip = (docId) => db.prepare('SELECT hash, created_at FROM events WHERE document_id = ? ORDER BY created_at DESC, id DESC LIMIT 1').get(docId) ?? null;

// Builds (does not store) the next chained event after `tip`, so it can be printed on a certificate before it is committed.
function draftEvent(docId, actor, action, { detail = '', req } = {}, tip = chainTip(docId)) {
  const { ip = null, userAgent = null } = req ? clientInfo(req) : {};
  const t = now();
  // A clock step backwards must not reorder the chain.
  const e = { document_id: docId, actor, action, detail, ip, user_agent: userAgent, created_at: tip && tip.created_at > t ? tip.created_at : t };
  return { ...e, prev_hash: tip?.hash ?? null, hash: auditHash(tip?.hash ?? null, e) };
}

// Documents whose chain grew inside the current atomic() block; their heads are logged after COMMIT.
const grown = new Set();
function putEvent(e) {
  db.prepare('INSERT INTO events (document_id, actor, action, detail, ip, user_agent, created_at, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(e.document_id, e.actor, e.action, e.detail, e.ip, e.user_agent, e.created_at, e.prev_hash, e.hash);
  grown.add(e.document_id);
}

// Appends one hash-chained audit event. Must run inside atomic() so reading the tip and inserting are one transaction.
const insertEvent = (docId, actor, action, opts) => putEvent(draftEvent(docId, actor, action, opts));

// tx() plus an external anchor: one stdout line per new chain head, so truncating the tail is detectable against the logs.
function atomic(fn) {
  grown.clear();
  try {
    const out = tx(fn);
    for (const id of grown) {
      const { n } = db.prepare('SELECT COUNT(*) AS n FROM events WHERE document_id = ?').get(id);
      const keyId = cryptoLib.auditKeyId?.();
      console.log(JSON.stringify({ audit_head: { document_id: id, count: n, head: chainTip(id)?.hash ?? null, ...(keyId && { key_id: keyId }), at: now() } }));
    }
    return out;
  } finally {
    grown.clear();
  }
}

export function logEvent(docId, actor, action, opts) {
  atomic(() => insertEvent(docId, actor, action, opts));
}

// Recomputes a chain. brokenAt is the id of the first event whose link or content does not match.
function chainOf(rows) {
  let prev = null;
  for (const e of rows) {
    if ((e.prev_hash ?? null) !== prev || e.hash !== auditHash(prev, e)) return { ok: false, count: rows.length, head: rows.at(-1).hash, brokenAt: e.id };
    prev = e.hash;
  }
  return { ok: true, count: rows.length, head: prev, brokenAt: null };
}
export const verifyAuditChain = (docId) => chainOf(events(docId));

export function createDocument({ ownerId, ownerName, title, bytes, pageCount, isTemplate, req }) {
  const id = newId();
  const t = now();
  writeFile(id, 'original', bytes);
  atomic(() => {
    db.prepare(`INSERT INTO documents (id, owner_id, title, is_template, page_count, original_sha256, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(id, ownerId, title, isTemplate ? 1 : 0, pageCount, sha256(bytes), t, t);
    insertEvent(id, ownerName, 'Uploaded', { detail: `${title}. Original SHA-256 ${sha256(bytes)}`, req });
  });
  return id;
}

// Replaces recipients and fields of a draft or template with the editor's state.
export function saveDraft(full, input) {
  const { doc } = full;
  if (doc.status !== 'draft') fail(409, 'Only drafts can be edited');
  const recipientsIn = Array.isArray(input.recipients) ? input.recipients.slice(0, 50) : [];
  const fieldsIn = Array.isArray(input.fields) ? input.fields.slice(0, 1000) : [];
  const sequential = input.sequential ? 1 : 0;

  atomic(() => {
    db.prepare('UPDATE documents SET title = ?, message = ?, sequential = ?, reminder_days = ?, updated_at = ? WHERE id = ?')
      .run(str(input.title, 200) || doc.title, str(input.message, 2000), sequential,
        Math.max(0, Math.min(30, Number(input.reminderDays) || 0)), now(), doc.id);
    db.prepare('DELETE FROM fields WHERE document_id = ?').run(doc.id);
    db.prepare('DELETE FROM recipients WHERE document_id = ?').run(doc.id);

    const idMap = new Map();
    const insR = db.prepare(`INSERT INTO recipients (id, document_id, name, email, role, routing_order, position) VALUES (?, ?, ?, ?, ?, ?, ?)`);
    let order = 0;
    recipientsIn.forEach((r, i) => {
      const id = newId();
      idMap.set(String(r.id), id);
      const role = r.role === 'cc' ? 'cc' : 'signer';
      if (role === 'signer') order += 1;
      insR.run(id, doc.id, str(r.name, 120), str(r.email, 254).toLowerCase(), role, sequential ? order : 1, i);
    });

    const insF = db.prepare(`INSERT INTO fields (id, document_id, recipient_id, type, page, x, y, w, h, required, label) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    for (const f of fieldsIn) {
      const rid = idMap.get(String(f.recipientId));
      if (!rid || !FIELD_TYPES.includes(f.type)) continue;
      const page = Math.trunc(Number(f.page));
      if (!(page >= 0 && page < doc.page_count)) continue;
      const clamp = (n) => Math.max(0, Math.min(1, Number(n) || 0));
      insF.run(newId(), doc.id, rid, f.type, page, clamp(f.x), clamp(f.y), clamp(f.w), clamp(f.h),
        f.type === 'checkbox' ? (f.required ? 1 : 0) : (f.required === false ? 0 : 1), str(f.label, 80));
    }
  });
  return loadDocument(doc.id);
}

export function validateForSend(full) {
  const { doc, recipients, fields } = full;
  if (doc.is_template) fail(409, 'Templates cannot be sent. Use the template to create a document first.');
  if (doc.status !== 'draft') fail(409, 'This document was already sent');
  const signers = recipients.filter((r) => r.role === 'signer');
  if (!signers.length) fail(400, 'Add at least one signer');
  for (const r of recipients) {
    if (!r.name) fail(400, 'Every recipient needs a name');
    if (!EMAIL.test(r.email)) fail(400, `${r.name} needs a valid email address`);
  }
  for (const s of signers) {
    if (!fields.some((f) => f.recipient_id === s.id && f.type === 'signature')) {
      fail(400, `Place at least one signature field for ${s.name}`);
    }
  }
}

function notify(baseUrl, doc, owner, r) {
  return sendMail({
    to: r.email,
    subject: `${owner.name} sent you "${doc.title}" to sign`,
    heading: `${owner.name} needs your signature`,
    body: `${doc.title}${doc.message ? `\n\n"${doc.message}"` : ''}\n\nNo account needed. Review the document and sign in a couple of minutes.`,
    actionLabel: 'Review and sign',
    actionUrl: `${baseUrl}/sign/${r.token}`,
  });
}

function owner(doc) {
  return db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(doc.owner_id);
}

async function activate(docId, order, baseUrl) {
  const { doc, recipients } = loadDocument(docId);
  const o = owner(doc);
  const batch = recipients.filter((r) => r.role === 'signer' && r.routing_order === order && r.status === 'pending');
  const t = now();
  for (const r of batch) {
    // The TTL starts when it is this signer's turn, not when the envelope was sent.
    db.prepare("UPDATE recipients SET status = 'sent', last_notified_at = ? WHERE id = ?").run(t, r.id);
    extendToken(r.id);
    const mailed = await notify(baseUrl, doc, o, r);
    logEvent(docId, 'Countersign', mailed ? 'Emailed' : 'Ready to sign', { detail: `${r.name} <${r.email}>` });
  }
}

export async function sendDocument(full, user, req, baseUrl) {
  validateForSend(full);
  const { doc, recipients } = full;
  atomic(() => {
    const setToken = db.prepare('UPDATE recipients SET token = NULL, token_hash = ?, token_enc = ?, token_expires_at = ?, token_revoked_at = NULL WHERE id = ?');
    for (const r of recipients) {
      const token = newToken();
      setToken.run(sha256hex(token), encryptText(token, `token:${r.id}`), tokenExpiry(), r.id);
    }
    db.prepare("UPDATE documents SET status = 'sent', sent_at = ?, updated_at = ? WHERE id = ?").run(now(), now(), doc.id);
    insertEvent(doc.id, user.name, 'Sent', { detail: `${recipients.filter((r) => r.role === 'signer').length} signer(s)`, req });
  });
  const first = Math.min(...recipients.filter((r) => r.role === 'signer').map((r) => r.routing_order));
  await activate(doc.id, first, baseUrl);
}

// Resolves a signing link or throws: 404 unknown, 410 revoked or expired. Pass req to record expiries in the security log.
export function signerByToken(token, req) {
  const r = typeof token === 'string' && token ? db.prepare('SELECT * FROM recipients WHERE token_hash = ?').get(sha256hex(token)) : null;
  if (!r) fail(404, 'Signing link not found');
  if (r.token_revoked_at) fail(410, 'This signing link is no longer valid.');
  if (r.token_expires_at && r.token_expires_at <= now()) {
    const { ip, userAgent } = req ? clientInfo(req) : {};
    logSecurity('token_expired', { email: r.email, ip, userAgent, detail: `recipient ${r.id}` });
    fail(410, 'This signing link has expired.');
  }
  return { recipient: withToken(r), ...loadDocument(r.document_id) };
}

// Old shape: null instead of throwing.
export function recipientByToken(token) {
  try {
    return signerByToken(token);
  } catch (e) {
    if (e.status === 404 || e.status === 410) return null;
    throw e;
  }
}

export function markViewed(r, req) {
  if (r.status !== 'sent') return;
  atomic(() => {
    db.prepare("UPDATE recipients SET status = 'viewed', viewed_at = ? WHERE id = ?").run(now(), r.id);
    insertEvent(r.document_id, r.name, 'Viewed', { req });
  });
}

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const PNG_MAX_SIDE = 4000;
const PNG_MAX_PIXELS = 4_000_000; // decoded RGBA stays under ~16 MB per image

// Decodes the PNG the way stamping will, so a bad image is a 400 now rather than a failed completion later.
async function checkSignaturePng(v) {
  const prefix = 'data:image/png;base64,';
  const bad = () => fail(400, 'Invalid signature image');
  if (typeof v !== 'string' || !v.startsWith(prefix) || v.length > SIGNATURE_MAX) bad();
  const b64 = v.slice(prefix.length);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) bad();
  const png = Buffer.from(b64, 'base64');
  // Signature, then IHDR (length 13) with width and height as big-endian uint32.
  if (png.length < 33 || !png.subarray(0, 8).equals(PNG_MAGIC) || png.readUInt32BE(8) !== 13 || png.toString('latin1', 12, 16) !== 'IHDR') bad();
  const w = png.readUInt32BE(16), h = png.readUInt32BE(20);
  if (!w || !h || w > PNG_MAX_SIDE || h > PNG_MAX_SIDE || w * h > PNG_MAX_PIXELS) bad();
  try {
    await (await PDFDocument.create()).embedPng(png);
  } catch {
    bad();
  }
}

export async function submitSignature(token, values, req, baseUrl) {
  const { recipient: r, doc, recipients, fields } = signerByToken(token, req);
  if (doc.status !== 'sent') fail(409, `This document is ${doc.status}`);
  if (!['sent', 'viewed'].includes(r.status)) fail(409, r.status === 'signed' ? 'You already signed this document' : 'It is not your turn to sign yet');

  const mine = fields.filter((f) => f.recipient_id === r.id);
  const date = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  const resolved = new Map();
  for (const f of mine) {
    let v = values?.[f.id];
    if (f.type === 'date') v = date;
    else if (f.type === 'name') v = r.name;
    else if (f.type === 'email') v = r.email;
    else if (f.type === 'signature' || f.type === 'initials') {
      if (v != null && v !== '') await checkSignaturePng(v);
    } else if (f.type === 'checkbox') v = v === true || v === 'true' ? 'true' : '';
    else v = str(v, 500);
    if (f.required && !v) fail(400, 'Fill in every required field');
    resolved.set(f.id, v || null);
  }

  const signedAt = now();
  const signedEvent = draftEvent(doc.id, r.name, 'Signed', { req });
  const last = !recipients.some((x) => x.role === 'signer' && x.id !== r.id && x.status !== 'signed');

  // Last signature: build and write the signed PDF first, then commit signature + completion + hash in one transaction.
  // Any failure before COMMIT leaves the document 'sent' and this signer able to submit again.
  let signedSha = null;
  if (last) {
    const completedAt = now();
    const certEvents = [...events(doc.id), signedEvent];
    const bytes = await buildSignedPdf({
      original: readVerified(doc, 'original'),
      doc: { ...doc, status: 'completed', completed_at: completedAt },
      recipients: recipients.map((x) => (x.id === r.id ? { ...x, status: 'signed', signed_at: signedAt } : x)),
      fields: fields.map((f) => (resolved.has(f.id) ? { ...f, value: resolved.get(f.id) } : f)),
      events: certEvents,
      chain: chainOf(certEvents),
    });
    // Each request writes its own candidate; only the transaction winner moves it into place, so a loser never touches the winner's file.
    const candidate = `${filePath(doc.id, 'signed')}.${crypto.randomUUID()}.tmp`;
    writeEncrypted(candidate, bytes, fileAad(doc.id, 'signed'));
    signedSha = { sha: sha256(bytes), completedAt, candidate };
  }
  try {
    atomic(() => {
      // Re-check under the write lock: the PDF build awaited, so another request may have changed the document.
      const cur = db.prepare('SELECT d.status AS ds, r.status AS rs, r.token_revoked_at FROM recipients r JOIN documents d ON d.id = r.document_id WHERE r.id = ?').get(r.id);
      if (!cur || cur.ds !== 'sent' || !['sent', 'viewed'].includes(cur.rs) || cur.token_revoked_at) fail(409, 'This document changed while you were signing. Reload the page.');
      if ((chainTip(doc.id)?.hash ?? null) !== signedEvent.prev_hash) fail(409, 'This document changed while you were signing. Try again.');
      // A parallel signer finished meanwhile: this submission is now the last one and must take the completion path.
      const others = db.prepare("SELECT COUNT(*) AS n FROM recipients WHERE document_id = ? AND role = 'signer' AND id != ? AND status != 'signed'").get(doc.id, r.id).n;
      if ((others === 0) !== last) fail(409, 'This document changed while you were signing. Try again.');
      const setV = db.prepare('UPDATE fields SET value = ? WHERE id = ?');
      for (const [id, v] of resolved) setV.run(v == null ? null : encryptText(v, `field:${id}`), id);
      db.prepare("UPDATE recipients SET status = 'signed', signed_at = ? WHERE id = ?").run(signedAt, r.id);
      putEvent(signedEvent);
      if (signedSha) {
        db.prepare("UPDATE documents SET status = 'completed', completed_at = ?, signed_sha256 = ?, updated_at = ? WHERE id = ?")
          .run(signedSha.completedAt, signedSha.sha, now(), doc.id);
        db.prepare("UPDATE recipients SET status = 'sent' WHERE document_id = ? AND role = 'cc'").run(doc.id);
        // L3 (approved): completion does not revoke links. Every recipient's link is re-extended so the completion
        // email's "Download signed PDF" works; signing through it is impossible because the status is now 'completed'.
        db.prepare('UPDATE recipients SET token_expires_at = ? WHERE document_id = ? AND token_revoked_at IS NULL').run(tokenExpiry(), doc.id);
        // Not on the certificate (it cannot contain its own hash); this event binds both file hashes into the chain.
        insertEvent(doc.id, 'Countersign', 'Completed', { detail: `All signers finished. Original SHA-256 ${doc.original_sha256}. Signed SHA-256 ${signedSha.sha}` });
        // Last statement before COMMIT, inside the write lock: committed 'completed' always has its file.
        fs.renameSync(signedSha.candidate, filePath(doc.id, 'signed'));
      }
    });
  } catch (e) {
    if (signedSha) fs.rmSync(signedSha.candidate, { force: true });
    throw e;
  }
  if (signedSha) await mailCompleted(doc.id, baseUrl);
  else await advance(doc.id, baseUrl);
  return loadDocument(doc.id).doc.status;
}

// Starts the next routing order once nobody in the current one is still waiting. Completion happens in submitSignature.
async function advance(docId, baseUrl) {
  const signers = loadDocument(docId).recipients.filter((r) => r.role === 'signer');
  if (signers.some((r) => r.status === 'sent' || r.status === 'viewed')) return;
  const pending = signers.filter((r) => r.status === 'pending');
  if (pending.length) await activate(docId, Math.min(...pending.map((r) => r.routing_order)), baseUrl);
}

async function mailCompleted(docId, baseUrl) {
  const { doc, recipients } = loadDocument(docId);
  for (const r of recipients) {
    await sendMail({
      to: r.email, subject: `Completed: ${doc.title}`, heading: 'Everyone has signed',
      body: `${doc.title} is complete. Download the signed copy with its certificate of completion.`,
      actionLabel: 'Download signed PDF', actionUrl: `${baseUrl}/sign/${r.token}`,
    });
  }
  await sendMail({
    to: owner(doc).email, subject: `Completed: ${doc.title}`, heading: 'Everyone has signed',
    body: `${doc.title} is complete.`, actionLabel: 'Open document', actionUrl: `${baseUrl}/app/documents/${doc.id}`,
  });
}

export async function declineDocument(token, reason, req) {
  const { recipient: r, doc } = signerByToken(token, req);
  if (doc.status !== 'sent' || !['sent', 'viewed'].includes(r.status)) fail(409, 'This document can no longer be declined');
  const why = str(reason, 500) || 'No reason given';
  atomic(() => {
    db.prepare("UPDATE recipients SET status = 'declined', declined_reason = ? WHERE id = ?").run(why, r.id);
    db.prepare("UPDATE documents SET status = 'declined', updated_at = ? WHERE id = ?").run(now(), doc.id);
    revokeTokens(doc.id);
    insertEvent(doc.id, r.name, 'Declined', { detail: why, req });
  });
  const o = owner(doc);
  await sendMail({
    to: o.email, subject: `Declined: ${doc.title}`, heading: `${r.name} declined to sign`,
    body: `Reason: ${why}`, actionLabel: 'Open document', actionUrl: `${process.env.APP_URL || ''}/app/documents/${doc.id}`,
  });
}

export function voidDocument(full, user, reason, req) {
  if (full.doc.status !== 'sent') fail(409, 'Only documents out for signature can be voided');
  atomic(() => {
    db.prepare("UPDATE documents SET status = 'voided', updated_at = ? WHERE id = ?").run(now(), full.doc.id);
    revokeTokens(full.doc.id);
    insertEvent(full.doc.id, user.name, 'Voided', { detail: str(reason, 500), req });
  });
}

export async function remind(full, recipientId, user, req, baseUrl) {
  const r = full.recipients.find((x) => x.id === recipientId);
  if (full.doc.status !== 'sent' || !r || !['sent', 'viewed'].includes(r.status)) fail(409, 'This recipient is not waiting to sign');
  const mailed = await notify(baseUrl, full.doc, owner(full.doc), r);
  if (!mailed) fail(400, 'Email is not configured on this server. Copy the signing link instead.');
  atomic(() => {
    db.prepare('UPDATE recipients SET last_notified_at = ? WHERE id = ?').run(now(), r.id);
    extendToken(r.id);
    insertEvent(full.doc.id, user.name, 'Reminded', { detail: r.name, req });
  });
}

// Copies a document's file, recipients (as roles) and fields into a new draft or template.
export function copyDocument(full, user, { asTemplate }) {
  const { doc, recipients, fields } = full;
  const id = newId();
  const t = now();
  writeFile(id, 'original', readVerified(doc, 'original')); // re-encrypted: the AAD binds the ciphertext to its document id
  atomic(() => {
    db.prepare(`INSERT INTO documents (id, owner_id, title, message, is_template, sequential, reminder_days, page_count, original_sha256, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id, user.id, doc.title, doc.message, asTemplate ? 1 : 0, doc.sequential, doc.reminder_days, doc.page_count, doc.original_sha256, t, t);
    const map = new Map();
    for (const r of recipients) {
      const rid = newId();
      map.set(r.id, rid);
      // Templates keep recipients as named roles ("Client") with no email.
      db.prepare('INSERT INTO recipients (id, document_id, name, email, role, routing_order, position) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(rid, id, r.name, asTemplate ? '' : r.email, r.role, r.routing_order, r.position);
    }
    for (const f of fields) {
      db.prepare('INSERT INTO fields (id, document_id, recipient_id, type, page, x, y, w, h, required, label) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(newId(), id, map.get(f.recipient_id), f.type, f.page, f.x, f.y, f.w, f.h, f.required, f.label);
    }
    insertEvent(id, user.name, asTemplate ? 'Template created' : 'Created from template', { detail: `${doc.title}. Original SHA-256 ${doc.original_sha256}` });
  });
  return id;
}

// deletedBy defaults to the owner: ownedDocument() already restricts delete to them.
export function deleteDocument(full, deletedBy = full.doc.owner_id) {
  const { doc } = full;
  if (!['draft', 'voided', 'declined'].includes(doc.status) && !doc.is_template) fail(409, 'Void the document before deleting it');
  atomic(() => {
    // The audit trail outlives the document: chain head, count and the encrypted events are kept.
    const chain = verifyAuditChain(doc.id);
    db.prepare(`INSERT INTO audit_tombstones (document_id, title, owner_id, status, deleted_at, deleted_by, final_hash, event_count, events_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(doc.id, doc.title, doc.owner_id, doc.status, now(), deletedBy, chain.head, chain.count,
      encryptText(JSON.stringify(events(doc.id)), `tombstone:${doc.id}`));
    db.prepare('DELETE FROM documents WHERE id = ?').run(doc.id);
  });
  // The PDFs plus any .tmp leftovers, including unclaimed signed-PDF candidates.
  for (const name of fs.readdirSync(FILES_DIR)) {
    if (name.startsWith(`${doc.id}.`) && (name.endsWith('.pdf') || name.endsWith('.tmp'))) fs.rmSync(path.join(FILES_DIR, name), { force: true });
  }
}

// Recipient-facing shape: never includes tokens of other recipients.
export function publicRecipient(r, includeToken = false) {
  const { token, token_hash, token_enc, ...rest } = r;
  return includeToken ? { ...rest, token } : rest;
}

// Hourly job: re-send links to signers who have waited reminder_days since the last email.
export async function sendDueReminders() {
  const base = process.env.APP_URL?.replace(/\/$/, '');
  if (!base) return;
  const due = db.prepare(`SELECT r.*, d.reminder_days FROM recipients r JOIN documents d ON d.id = r.document_id
    WHERE d.status = 'sent' AND d.reminder_days > 0 AND r.status IN ('sent', 'viewed')
      AND julianday('now') - julianday(r.last_notified_at) >= d.reminder_days`).all();
  for (const row of due) {
    const r = withToken(row);
    if (!r.token || r.token_revoked_at) continue;
    const full = loadDocument(r.document_id);
    if (await notify(base, full.doc, owner(full.doc), r)) {
      atomic(() => {
        db.prepare('UPDATE recipients SET last_notified_at = ? WHERE id = ?').run(now(), r.id);
        extendToken(r.id);
        insertEvent(r.document_id, 'Countersign', 'Reminder sent', { detail: r.name });
      });
    }
  }
}
