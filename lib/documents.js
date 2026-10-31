import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import db, { FILES_DIR, now, newId, newToken, tx } from './db';
import { fail, str, EMAIL, clientInfo } from './http';
import { sendMail } from './mail';
import { buildSignedPdf } from './stamp';

export const FIELD_TYPES = ['signature', 'initials', 'date', 'name', 'email', 'text', 'checkbox'];
const AUTO_FIELDS = new Set(['date', 'name', 'email']);
const SIGNATURE_MAX = 400_000;

export const filePath = (id, kind = 'original') => path.join(FILES_DIR, `${id}.${kind}.pdf`);
export const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

export function loadDocument(id) {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(id);
  if (!doc) return null;
  const recipients = db.prepare('SELECT * FROM recipients WHERE document_id = ? ORDER BY position').all(id);
  const fields = db.prepare('SELECT * FROM fields WHERE document_id = ?').all(id);
  return { doc, recipients, fields };
}

export function ownedDocument(id, userId) {
  const full = loadDocument(String(id));
  if (!full || full.doc.owner_id !== userId) fail(404, 'Document not found');
  return full;
}

export function events(docId) {
  return db.prepare('SELECT * FROM events WHERE document_id = ? ORDER BY id').all(docId);
}

export function logEvent(docId, actor, action, { detail = '', req } = {}) {
  const { ip, userAgent } = req ? clientInfo(req) : {};
  db.prepare('INSERT INTO events (document_id, actor, action, detail, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(docId, actor, action, detail, ip ?? null, userAgent ?? null, now());
}

export function createDocument({ ownerId, ownerName, title, bytes, pageCount, isTemplate, req }) {
  const id = newId();
  const t = now();
  fs.writeFileSync(filePath(id), bytes);
  db.prepare(`INSERT INTO documents (id, owner_id, title, is_template, page_count, original_sha256, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(id, ownerId, title, isTemplate ? 1 : 0, pageCount, sha256(bytes), t, t);
  logEvent(id, ownerName, 'Uploaded', { detail: title, req });
  return id;
}

// Replaces recipients and fields of a draft or template with the editor's state.
export function saveDraft(full, input) {
  const { doc } = full;
  if (doc.status !== 'draft') fail(409, 'Only drafts can be edited');
  const recipientsIn = Array.isArray(input.recipients) ? input.recipients.slice(0, 50) : [];
  const fieldsIn = Array.isArray(input.fields) ? input.fields.slice(0, 1000) : [];
  const sequential = input.sequential ? 1 : 0;

  tx(() => {
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
    db.prepare("UPDATE recipients SET status = 'sent', last_notified_at = ? WHERE id = ?").run(t, r.id);
    const mailed = await notify(baseUrl, doc, o, r);
    logEvent(docId, 'Countersign', mailed ? 'Emailed' : 'Ready to sign', { detail: `${r.name} <${r.email}>` });
  }
}

export async function sendDocument(full, user, req, baseUrl) {
  validateForSend(full);
  const { doc, recipients } = full;
  tx(() => {
    const setToken = db.prepare('UPDATE recipients SET token = ? WHERE id = ?');
    for (const r of recipients) setToken.run(newToken(), r.id);
    db.prepare("UPDATE documents SET status = 'sent', sent_at = ?, updated_at = ? WHERE id = ?").run(now(), now(), doc.id);
  });
  logEvent(doc.id, user.name, 'Sent', { detail: `${recipients.filter((r) => r.role === 'signer').length} signer(s)`, req });
  const first = Math.min(...recipients.filter((r) => r.role === 'signer').map((r) => r.routing_order));
  await activate(doc.id, first, baseUrl);
}

export function recipientByToken(token) {
  const r = db.prepare('SELECT * FROM recipients WHERE token = ?').get(String(token));
  if (!r) return null;
  return { recipient: r, ...loadDocument(r.document_id) };
}

export function markViewed(r, req) {
  if (r.status !== 'sent') return;
  db.prepare("UPDATE recipients SET status = 'viewed', viewed_at = ? WHERE id = ?").run(now(), r.id);
  logEvent(r.document_id, r.name, 'Viewed', { req });
}

export async function submitSignature(token, values, req, baseUrl) {
  const found = recipientByToken(token);
  if (!found) fail(404, 'Signing link not found');
  const { recipient: r, doc, fields } = found;
  if (doc.status !== 'sent') fail(409, `This document is ${doc.status}`);
  if (!['sent', 'viewed'].includes(r.status)) fail(409, r.status === 'signed' ? 'You already signed this document' : 'It is not your turn to sign yet');

  const mine = fields.filter((f) => f.recipient_id === r.id);
  const date = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  const resolved = mine.map((f) => {
    let v = values?.[f.id];
    if (f.type === 'date') v = date;
    else if (f.type === 'name') v = r.name;
    else if (f.type === 'email') v = r.email;
    else if (f.type === 'signature' || f.type === 'initials') {
      if (v != null && (typeof v !== 'string' || !v.startsWith('data:image/png;base64,') || v.length > SIGNATURE_MAX)) fail(400, 'Invalid signature image');
    } else if (f.type === 'checkbox') v = v === true || v === 'true' ? 'true' : '';
    else v = str(v, 500);
    if (f.required && !v) fail(400, 'Fill in every required field');
    return [f.id, v || null];
  });

  tx(() => {
    const setV = db.prepare('UPDATE fields SET value = ? WHERE id = ?');
    for (const [id, v] of resolved) setV.run(v, id);
    db.prepare("UPDATE recipients SET status = 'signed', signed_at = ? WHERE id = ?").run(now(), r.id);
  });
  logEvent(doc.id, r.name, 'Signed', { req });
  await advance(doc.id, baseUrl);
  return loadDocument(doc.id).doc.status;
}

async function advance(docId, baseUrl) {
  const { recipients } = loadDocument(docId);
  const signers = recipients.filter((r) => r.role === 'signer');
  if (signers.some((r) => r.status === 'sent' || r.status === 'viewed')) return;
  const pending = signers.filter((r) => r.status === 'pending');
  if (pending.length) return activate(docId, Math.min(...pending.map((r) => r.routing_order)), baseUrl);
  await complete(docId, baseUrl);
}

async function complete(docId, baseUrl) {
  db.prepare("UPDATE documents SET status = 'completed', completed_at = ?, updated_at = ? WHERE id = ?").run(now(), now(), docId);
  logEvent(docId, 'Countersign', 'Completed', { detail: 'All signers finished' });
  const { doc, recipients, fields } = loadDocument(docId);
  const bytes = await buildSignedPdf({ original: fs.readFileSync(filePath(docId)), doc, recipients, fields, events: events(docId) });
  fs.writeFileSync(filePath(docId, 'signed'), bytes);
  db.prepare('UPDATE documents SET signed_sha256 = ? WHERE id = ?').run(sha256(bytes), docId);

  const o = owner(doc);
  for (const r of recipients) {
    if (r.role === 'cc') db.prepare("UPDATE recipients SET status = 'sent' WHERE id = ?").run(r.id);
    await sendMail({
      to: r.email, subject: `Completed: ${doc.title}`, heading: 'Everyone has signed',
      body: `${doc.title} is complete. Download the signed copy with its certificate of completion.`,
      actionLabel: 'Download signed PDF', actionUrl: `${baseUrl}/sign/${r.token}`,
    });
  }
  await sendMail({
    to: o.email, subject: `Completed: ${doc.title}`, heading: 'Everyone has signed',
    body: `${doc.title} is complete.`, actionLabel: 'Open document', actionUrl: `${baseUrl}/app/documents/${doc.id}`,
  });
}

export async function declineDocument(token, reason, req) {
  const found = recipientByToken(token);
  if (!found) fail(404, 'Signing link not found');
  const { recipient: r, doc } = found;
  if (doc.status !== 'sent' || !['sent', 'viewed'].includes(r.status)) fail(409, 'This document can no longer be declined');
  const why = str(reason, 500) || 'No reason given';
  db.prepare("UPDATE recipients SET status = 'declined', declined_reason = ? WHERE id = ?").run(why, r.id);
  db.prepare("UPDATE documents SET status = 'declined', updated_at = ? WHERE id = ?").run(now(), doc.id);
  logEvent(doc.id, r.name, 'Declined', { detail: why, req });
  const o = owner(doc);
  await sendMail({
    to: o.email, subject: `Declined: ${doc.title}`, heading: `${r.name} declined to sign`,
    body: `Reason: ${why}`, actionLabel: 'Open document', actionUrl: `${process.env.APP_URL || ''}/app/documents/${doc.id}`,
  });
}

export function voidDocument(full, user, reason, req) {
  if (full.doc.status !== 'sent') fail(409, 'Only documents out for signature can be voided');
  db.prepare("UPDATE documents SET status = 'voided', updated_at = ? WHERE id = ?").run(now(), full.doc.id);
  logEvent(full.doc.id, user.name, 'Voided', { detail: str(reason, 500), req });
}

export async function remind(full, recipientId, user, req, baseUrl) {
  const r = full.recipients.find((x) => x.id === recipientId);
  if (full.doc.status !== 'sent' || !r || !['sent', 'viewed'].includes(r.status)) fail(409, 'This recipient is not waiting to sign');
  const mailed = await notify(baseUrl, full.doc, owner(full.doc), r);
  if (!mailed) fail(400, 'Email is not configured on this server. Copy the signing link instead.');
  db.prepare('UPDATE recipients SET last_notified_at = ? WHERE id = ?').run(now(), r.id);
  logEvent(full.doc.id, user.name, 'Reminded', { detail: r.name, req });
}

// Copies a document's file, recipients (as roles) and fields into a new draft or template.
export function copyDocument(full, user, { asTemplate }) {
  const { doc, recipients, fields } = full;
  const id = newId();
  const t = now();
  fs.copyFileSync(filePath(doc.id), filePath(id));
  tx(() => {
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
  });
  logEvent(id, user.name, asTemplate ? 'Template created' : 'Created from template', { detail: doc.title });
  return id;
}

export function deleteDocument(full) {
  if (!['draft', 'voided', 'declined'].includes(full.doc.status) && !full.doc.is_template) fail(409, 'Void the document before deleting it');
  db.prepare('DELETE FROM documents WHERE id = ?').run(full.doc.id);
  for (const kind of ['original', 'signed']) fs.rmSync(filePath(full.doc.id, kind), { force: true });
}

// Recipient-facing shape: never includes tokens of other recipients.
export function publicRecipient(r, withToken = false) {
  const { token, ...rest } = r;
  return withToken ? r : rest;
}

// Hourly job: re-send links to signers who have waited reminder_days since the last email.
export async function sendDueReminders() {
  const base = process.env.APP_URL?.replace(/\/$/, '');
  if (!base) return;
  const due = db.prepare(`SELECT r.*, d.reminder_days FROM recipients r JOIN documents d ON d.id = r.document_id
    WHERE d.status = 'sent' AND d.reminder_days > 0 AND r.status IN ('sent', 'viewed')
      AND julianday('now') - julianday(r.last_notified_at) >= d.reminder_days`).all();
  for (const r of due) {
    const full = loadDocument(r.document_id);
    if (await notify(base, full.doc, owner(full.doc), r)) {
      db.prepare('UPDATE recipients SET last_notified_at = ? WHERE id = ?').run(now(), r.id);
      logEvent(r.document_id, 'Countersign', 'Reminder sent', { detail: r.name });
    }
  }
}
