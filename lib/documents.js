import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import db, { FILES_DIR, TOKEN_TTL_DAYS, now, newId, newToken, tx } from './db';
import { fail, str, EMAIL, clientInfo, appUrl } from './http';
import { mailEnabled, renderEmail, sendMail } from './mail';
import { upsertContacts } from './contacts';
import { buildSignedPdf } from './stamp';
import * as cryptoLib from './crypto.js';
import { logSecurity } from './security-log.js';
import { emitEvent } from './webhooks';
import { teamOf } from './teams';
import { PDFDocument } from 'pdf-lib';

const { auditHash, decryptText, encryptText, keyedHash, readDecrypted, sha256hex, writeEncrypted } = cryptoLib;

// Queues a webhook after commit. Payload is ids, names, emails and statuses only: never tokens, field values, OTP data or files.
function hook(event, docId, recipientId = null) {
  try {
    const d = db.prepare('SELECT id, owner_id, title, status FROM documents WHERE id = ?').get(docId);
    if (!d) return;
    const r = recipientId && db.prepare('SELECT id, name, email, role, status FROM recipients WHERE id = ?').get(recipientId);
    emitEvent(d.owner_id, event, { document: { id: d.id, title: d.title, status: d.status }, ...(r && { recipient: { ...r } }) });
  } catch (e) {
    console.error('Webhook not queued:', e.message);
  }
}

export const FIELD_TYPES = ['signature', 'initials', 'date', 'name', 'email', 'text', 'checkbox', 'company', 'jobtitle', 'number', 'dropdown', 'radio', 'stamp'];
const AUTO_FIELDS = new Set(['date', 'name', 'email']);
const IMAGE_FIELDS = new Set(['signature', 'initials', 'stamp']);
const CHOICE_FIELDS = new Set(['dropdown', 'radio']);
const NUMBER = /^-?\d{1,15}([.,]\d{1,6})?$/;
const SIGNATURE_MAX = 400_000;

// Dropdown/radio options: 1-20 unique trimmed strings of 1-60 chars, else null (the field is dropped).
function cleanOptions(list) {
  if (!Array.isArray(list) || list.length < 1 || list.length > 20) return null;
  const out = list.map((o) => (typeof o === 'string' ? o.trim() : ''));
  if (out.some((o) => !o || o.length > 60) || new Set(out).size !== out.length) return null;
  return out;
}

export const filePath = (id, kind = 'original') => path.join(FILES_DIR, `${id}.${kind}.pdf`);
export const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const fileAad = (id, kind = 'original') => `file:${id}.${kind}`;
// PDFs and field values are AES-256-GCM encrypted at rest; hashes stay over the plaintext bytes.
const readFile = (id, kind) => readDecrypted(filePath(id, kind), fileAad(id, kind));
// Per-owner storage quota (STORAGE_QUOTA_MB, default 1024, 0 = off) on original PDFs.
// shortcut: documents from before original_bytes existed count as 0 and signed PDFs are not counted; concurrent uploads may overshoot by one file.
export function checkQuota(userId, addBytes) {
  const mb = Number(process.env.STORAGE_QUOTA_MB ?? 1024);
  if (!(mb > 0)) return;
  const { used } = db.prepare('SELECT COALESCE(SUM(original_bytes), 0) AS used FROM documents WHERE owner_id = ?').get(userId);
  if (used + addBytes > mb * 1048576) fail(413, `Storage limit reached (${mb} MB). Delete documents you no longer need, or ask the admin to raise STORAGE_QUOTA_MB.`);
}

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
    .map((f) => ({ ...f, value: decryptText(f.value, `field:${f.id}`), options: f.options ? JSON.parse(f.options) : null }));
  return { doc, recipients, fields };
}

// Signing tokens are stored as SHA-256 (lookup) plus an encrypted copy (owner's copy-link UI); never in plaintext.
export const signingToken = (r) => (r?.token_enc ? decryptText(r.token_enc, `token:${r.id}`) : null);
// Callers keep seeing r.token (plaintext, owner-side only); the hash and ciphertext stay server-internal.
function withToken(r) {
  // OTP code and session hashes never leave the engine; signerVerified reads them from the DB.
  const { token_hash, token_enc, otp_hash, otp_session_hash, ...rest } = r;
  return { ...rest, token: signingToken(r) };
}
const tokenExpiry = () => new Date(Date.now() + TOKEN_TTL_DAYS * 864e5).toISOString();
const extendToken = (id) => db.prepare('UPDATE recipients SET token_expires_at = ? WHERE id = ? AND token_revoked_at IS NULL').run(tokenExpiry(), id);
const revokeTokens = (docId) => db.prepare('UPDATE recipients SET token_revoked_at = ? WHERE document_id = ? AND token_revoked_at IS NULL').run(now(), docId);

// own: owner only. write: owner, or owner/admin of the document's team. read: owner, or any member of its team.
// Refusals are 404, so other users' document ids are not confirmed. team_id NULL is owner-only in every mode.
export function ownedDocument(id, userId, mode = 'write') {
  if (!['own', 'write', 'read'].includes(mode)) throw new Error(`Unknown access mode ${mode}`);
  const full = loadDocument(String(id));
  if (!full || !canAccess(full.doc, userId, mode)) fail(404, 'Document not found');
  return full;
}

function canAccess(doc, userId, mode) {
  if (doc.owner_id === userId) return true;
  if (mode === 'own' || !doc.team_id) return false;
  const t = teamOf(userId);
  return Boolean(t) && t.teamId === doc.team_id && (mode === 'read' || t.role === 'owner' || t.role === 'admin');
}

const teamIdOf = (userId) => teamOf(userId)?.teamId ?? null;

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
  checkQuota(ownerId, bytes.length);
  writeFile(id, 'original', bytes);
  atomic(() => {
    db.prepare(`INSERT INTO documents (id, owner_id, team_id, title, is_template, page_count, original_sha256, original_bytes, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, ownerId, teamIdOf(ownerId), title, isTemplate ? 1 : 0, pageCount, sha256(bytes), bytes.length, t, t);
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
  const expireDays = Math.max(0, Math.min(365, Math.trunc(Number(input.expireDays)) || 0));
  // Absent key keeps the saved address, so older clients do not clear it.
  const redirectUrl = input.redirectUrl === undefined ? doc.redirect_url : cleanRedirectUrl(input.redirectUrl);
  const requireOtp = input.requireOtp === true ? 1 : 0;

  atomic(() => {
    db.prepare('UPDATE documents SET title = ?, message = ?, sequential = ?, reminder_days = ?, require_otp = ?, expire_days = ?, redirect_url = ?, updated_at = ? WHERE id = ?')
      .run(str(input.title, 200) || doc.title, str(input.message, 2000), sequential,
        Math.max(0, Math.min(30, Number(input.reminderDays) || 0)), requireOtp, expireDays, redirectUrl, now(), doc.id);
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

    const insF = db.prepare(`INSERT INTO fields (id, document_id, recipient_id, type, page, x, y, w, h, required, label, options) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    for (const f of fieldsIn) {
      const rid = idMap.get(String(f.recipientId));
      if (!rid || !FIELD_TYPES.includes(f.type)) continue;
      const options = CHOICE_FIELDS.has(f.type) ? cleanOptions(f.options) : null;
      if (CHOICE_FIELDS.has(f.type) && !options) continue;
      const page = Math.trunc(Number(f.page));
      if (!(page >= 0 && page < doc.page_count)) continue;
      const clamp = (n) => Math.max(0, Math.min(1, Number(n) || 0));
      insF.run(newId(), doc.id, rid, f.type, page, clamp(f.x), clamp(f.y), clamp(f.w), clamp(f.h),
        f.type === 'checkbox' ? (f.required ? 1 : 0) : (f.required === false ? 0 : 1), str(f.label, 80), options && JSON.stringify(options));
    }
    // Judged on what was saved, not the raw input.
    if (doc.public_enabled) {
      const saved = loadDocument(doc.id);
      let problem = publicLinkProblem(saved.recipients, requireOtp);
      // Same send checks setPublicLink runs, e.g. the signature field was removed.
      if (!problem) try { checkFilled(saved, [{ name: 'x', email: 'x@example.com' }]); } catch (e) { if (!e.status) throw e; problem = e.message; }
      if (problem) clearPublicLink(doc.id, 'Countersign', `The template no longer qualifies for a public link: ${problem}`);
    }
  });
  return loadDocument(doc.id);
}

// ---- Public template link ----
const PUBLIC_RULE = 'A public link needs a template with exactly one signer';
const OTP_NEEDS_MAIL = 'Email codes need email (SMTP and APP_URL) to be set up on this server';
const publicAad = (id) => `public:${id}`;

// The one eligibility rule for a public link: the error message, or null when the template qualifies.
function publicLinkProblem(recipients, requireOtp) {
  if (!(recipients.length === 1 && recipients[0].role === 'signer')) return PUBLIC_RULE;
  if (requireOtp && !mailEnabled()) return OTP_NEEDS_MAIL;
  return null;
}

// Inside atomic(). Clearing both columns makes every earlier link stop working.
function clearPublicLink(docId, actor, detail = '', req) {
  db.prepare('UPDATE documents SET public_enabled = 0, public_token_hash = NULL, public_token_enc = NULL, updated_at = ? WHERE id = ?').run(now(), docId);
  insertEvent(docId, actor, 'Public link disabled', { detail, req });
}

// Enabling always issues a new token (rotation); returns { url } or { ok: true }.
export function setPublicLink(full, user, enabled, req) {
  const { doc, recipients } = full;
  if (!doc.is_template) fail(409, 'Only templates can have a public link');
  if (!enabled) {
    if (doc.public_enabled || doc.public_token_hash) atomic(() => clearPublicLink(doc.id, user.name, '', req));
    return { ok: true };
  }
  const problem = publicLinkProblem(recipients, doc.require_otp);
  if (problem) fail(400, problem);
  // A template that can never be sent gets no link.
  checkFilled(full, [{ name: 'x', email: 'x@example.com' }]);
  const token = crypto.randomBytes(32).toString('base64url');
  atomic(() => {
    db.prepare('UPDATE documents SET public_enabled = 1, public_token_hash = ?, public_token_enc = ?, updated_at = ? WHERE id = ?')
      .run(sha256hex(token), encryptText(token, publicAad(doc.id)), now(), doc.id);
    insertEvent(doc.id, user.name, 'Public link enabled', { detail: doc.public_enabled ? 'New link; the previous one no longer works' : '', req });
  });
  return { url: `/t/${token}` };
}

// `full` comes from ownedDocument(id, userId, 'own'). A real change is written to the audit trail.
export function shareDocument(full, user, shared, req) {
  const { doc } = full;
  const teamId = shared ? teamIdOf(user.id) : null;
  if (shared && !teamId) fail(409, 'Join a team first');
  atomic(() => {
    const { changes } = db.prepare('UPDATE documents SET team_id = ?, updated_at = ? WHERE id = ? AND owner_id = ? AND team_id IS NOT ?')
      .run(teamId, now(), doc.id, doc.owner_id, teamId);
    if (changes) insertEvent(doc.id, user.name, teamId ? 'Shared with team' : 'Made private', { req });
  });
  return { teamShared: Boolean(teamId) };
}

// Owner-only (document GET): the live link, or null.
export const publicUrlFor = (doc) => (doc?.public_enabled && doc.public_token_enc ? `/t/${decryptText(doc.public_token_enc, publicAad(doc.id))}` : null);

function publicTemplateRow(token) {
  if (typeof token !== 'string' || !token || token.length > 100) return null;
  return db.prepare(`SELECT d.id, d.title, d.require_otp, d.page_count, u.name AS owner_name FROM documents d JOIN users u ON u.id = d.owner_id
    WHERE d.public_token_hash = ? AND d.public_enabled = 1 AND d.is_template = 1`).get(sha256hex(token)) ?? null;
}

export function publicTemplateByToken(token) {
  const d = publicTemplateRow(token);
  return d && { id: d.id, title: d.title, ownerName: d.owner_name, requireOtp: Boolean(d.require_otp), pageCount: d.page_count };
}

// Visitor fills the single signer role. Rate limits and the honeypot are applied by the route before this runs.
export async function createFromPublicLink(token, input, req, baseUrl) {
  const tpl = publicTemplateRow(token);
  if (!tpl) fail(404, 'This link is not active');
  const name = typeof input?.name === 'string' ? input.name.trim() : '';
  const email = typeof input?.email === 'string' ? input.email.trim().toLowerCase() : '';
  if (!name || name.length > 200) fail(400, 'Enter your name');
  if (!EMAIL.test(email) || email.length > 254) fail(400, 'Enter a valid email address');
  const full = loadDocument(tpl.id);
  if (publicLinkProblem(full.recipients, full.doc.require_otp)) fail(404, 'This link is not active');
  checkFilled(full, [{ name, email }]);
  // The template owner owns the copy; the visitor is the actor, since they started it.
  const actor = { id: full.doc.owner_id, name };
  const id = copyDocument(full, actor, {
    // Anonymous copies always expire (1 day when the template has no expiry), so unsigned ones do not pile up.
    asTemplate: false, people: [{ name, email }], expireDays: full.doc.expire_days > 0 ? full.doc.expire_days : 1, action: 'Created from public link', note: '. Signer name and email were entered by the signer', req,
  });
  return sendDocument(loadDocument(id), actor, req, baseUrl, { publicLink: true });
}

// Runs the send checks on the copy that `people` would produce, so nothing is created for a template that cannot be sent.
function checkFilled(full, people) {
  validateForSend({ ...full, doc: { ...full.doc, is_template: 0, status: 'draft' }, recipients: full.recipients.map((r, i) => ({ ...r, ...people[i] })) });
  if (full.doc.require_otp && !mailEnabled()) fail(400, OTP_NEEDS_MAIL);
}

// ---- Bulk send ----
export const BULK_MAX_ROWS = 500;

// Every row is checked before anything is created. Returns rows of { name, email } in role order.
export function bulkRows(roles, rows) {
  if (!Array.isArray(rows) || !rows.length) fail(400, 'Add at least one row');
  if (rows.length > BULK_MAX_ROWS) fail(400, `Bulk send takes up to ${BULK_MAX_ROWS} rows`);
  return rows.map((row, i) => {
    const n = i + 1;
    if (!Array.isArray(row) || row.length !== roles.length) fail(400, `Row ${n}: Enter a name and email for each of the ${roles.length} roles`);
    const seen = new Set();
    return row.map((p, j) => {
      const role = roles[j].name || `recipient ${j + 1}`;
      const name = typeof p?.name === 'string' ? p.name.trim() : '';
      const email = typeof p?.email === 'string' ? p.email.trim().toLowerCase() : '';
      if (!name || name.length > 200) fail(400, `Row ${n}: Enter a name for ${role} (up to 200 characters)`);
      if (!EMAIL.test(email) || email.length > 254) fail(400, `Row ${n}: Enter a valid email for ${role}`);
      if (seen.has(email)) fail(400, `Row ${n}: Each person in a row needs a different email`);
      seen.add(email);
      return { name, email };
    });
  });
}

// shortcut: rows run in the request; fine up to 500, move to a job queue if users need more.
// requestId (Idempotency-Key) becomes the bulk_id. The check below and row 1's copy run before the first await,
// so a concurrent retry in this process sees row 1 and gets 409.
export async function bulkSend(full, user, req, baseUrl, rows, { requestId } = {}) {
  if (!full.doc.is_template) fail(409, 'Bulk send starts from a template');
  if (!full.recipients.length) fail(400, 'Add recipients to the template first');
  if (requestId != null && !(typeof requestId === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(requestId))) fail(400, 'Invalid Idempotency-Key');
  const clean = bulkRows(full.recipients, rows);
  checkFilled(full, clean[0]);
  const bulkId = requestId ?? newId();
  if (requestId && db.prepare('SELECT 1 FROM documents WHERE bulk_id = ? AND owner_id = ?').get(bulkId, user.id)) {
    fail(409, 'This bulk send was already started');
  }
  const bytes = readVerified(full.doc, 'original'); // once, not per row
  checkQuota(user.id, bytes.length * clean.length); // refuse up front rather than fail halfway
  const documentIds = [];
  const failed = [];
  for (const [i, people] of clean.entries()) {
    try {
      const id = copyDocument(full, user, { asTemplate: false, people, bulkId, action: 'Created by bulk send', note: `. Bulk ${bulkId}, row ${i + 1}`, req, bytes });
      await sendDocument(loadDocument(id), user, req, baseUrl);
      documentIds.push(id);
    } catch (e) {
      if (!e.status) console.error(`Bulk send row ${i + 1}:`, e);
      failed.push({ row: i + 1, error: e.status ? e.message : 'Something went wrong' });
    }
  }
  return { bulkId, created: documentIds.length, failed, documentIds };
}

// "After signing" address: null/blank string -> null; otherwise an https URL without user:pass@, at most 500 chars.
// Any other type is rejected rather than silently clearing the saved address.
function cleanRedirectUrl(v) {
  const bad = () => fail(400, 'Enter a full web address starting with https://');
  if (v === null) return null;
  if (typeof v !== 'string') bad();
  const raw = v.trim();
  if (!raw) return null;
  let u = null;
  try { u = new URL(raw); } catch { /* not a URL */ }
  if (!u || u.protocol !== 'https:' || u.username || u.password || raw.length > 500 || u.href.length > 500) bad();
  return u.href;
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

const mailVars = (doc, owner, r) => ({
  sender_name: owner.name, sender_email: owner.email, receiver_name: r.name, document_title: doc.title,
  message: doc.message || '', expires_on: doc.expires_at ? expiryDate(doc.expires_at) : '',
});

// Invitation or reminder from the owner's invite template. The button is always added here, never by the template.
function notify(baseUrl, doc, owner, r, { reminder = false } = {}) {
  const { subject, body } = renderEmail(owner.id, 'invite', mailVars(doc, owner, r));
  return sendMail({
    to: r.email,
    subject: reminder ? `Reminder: ${subject}` : subject,
    heading: `${owner.name} needs your signature`,
    body,
    actionLabel: 'Review and sign',
    actionUrl: `${baseUrl}/sign/${r.token}`,
  });
}

function owner(doc) {
  return db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(doc.owner_id);
}

async function activate(docId, order, baseUrl, { mail = true } = {}) {
  const { doc, recipients } = loadDocument(docId);
  const o = owner(doc);
  const batch = recipients.filter((r) => r.role === 'signer' && r.routing_order === order && r.status === 'pending');
  const t = now();
  for (const r of batch) {
    // The TTL starts when it is this signer's turn, not when the envelope was sent.
    db.prepare("UPDATE recipients SET status = 'sent', last_notified_at = ? WHERE id = ?").run(t, r.id);
    extendToken(r.id);
    const mailed = mail && await notify(baseUrl, doc, o, r);
    logEvent(docId, 'Countersign', mailed ? 'Emailed' : 'Ready to sign', { detail: `${r.name} <${r.email}>` });
  }
}

// selfSign: the owner is the only signer and signs right away; returns { signUrl }. No invitation email is sent.
// publicLink: the visitor who filled a public template link signs right away; same, but the email code still applies.
export async function sendDocument(full, user, req, baseUrl, { selfSign = false, publicLink = false } = {}) {
  validateForSend(full);
  const { doc, recipients } = full;
  if (selfSign && !(recipients.length === 1 && recipients[0].role === 'signer' && recipients[0].email === String(user.email).toLowerCase())) {
    fail(400, 'Sign yourself needs you as the only signer');
  }
  // Self-sign skips the code: the owner is signed in.
  const requireOtp = selfSign ? 0 : doc.require_otp ? 1 : 0;
  if (requireOtp && !mailEnabled()) fail(400, 'Email codes need email (SMTP and APP_URL) to be set up on this server');
  const expiresAt = doc.expire_days > 0 ? new Date(Date.now() + doc.expire_days * 864e5).toISOString() : null;
  let selfToken = null;
  atomic(() => {
    const setToken = db.prepare('UPDATE recipients SET token = NULL, token_hash = ?, token_enc = ?, token_expires_at = ?, token_revoked_at = NULL WHERE id = ?');
    for (const r of recipients) {
      const token = newToken();
      selfToken = token;
      setToken.run(sha256hex(token), encryptText(token, `token:${r.id}`), tokenExpiry(), r.id);
    }
    // status = 'draft' guard: a concurrent second send changes nothing.
    const sent = db.prepare("UPDATE documents SET status = 'sent', sent_at = ?, require_otp = ?, expires_at = ?, updated_at = ? WHERE id = ? AND status = 'draft'")
      .run(now(), requireOtp, expiresAt, now(), doc.id);
    if (!sent.changes) fail(409, 'This document was already sent');
    insertEvent(doc.id, user.name, selfSign ? 'Sent to self' : 'Sent', {
      detail: `${recipients.filter((r) => r.role === 'signer').length} signer(s)${expiresAt ? `. Expires ${expiresAt}` : ''}${requireOtp ? '. Email code required' : ''}`, req,
    });
  });
  hook('document.sent', doc.id);
  // Visitor-typed addresses are not added to the owner's contacts.
  if (!selfSign && !publicLink) rememberContacts(doc.owner_id, recipients);
  const first = Math.min(...recipients.filter((r) => r.role === 'signer').map((r) => r.routing_order));
  await activate(doc.id, first, baseUrl, { mail: !selfSign && !publicLink });
  return selfSign || publicLink ? { signUrl: `/sign/${selfToken}` } : {};
}

// Adds new recipients to the owner's contacts, outside the send transaction. Never renames an existing contact; never fails the send.
function rememberContacts(ownerId, recipients) {
  try {
    const known = db.prepare('SELECT 1 FROM contacts WHERE owner_id = ? AND email = ?');
    const seen = new Set();
    const fresh = recipients.filter((r) => r.email && !seen.has(r.email) && seen.add(r.email) && !known.get(ownerId, r.email));
    if (fresh.length) upsertContacts(ownerId, fresh.map((r) => ({ name: r.name, email: r.email })));
  } catch (e) {
    console.error('Contacts not updated after send:', e.message);
  }
}

const expiryDate = (iso) => new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

// Moves a sent document to 'expired' and revokes its links. Returns false if it was no longer sent.
// The DB change is synchronous; the returned promise is only the owner email.
export function expireDocument(docId) {
  const done = atomic(() => {
    const res = db.prepare("UPDATE documents SET status = 'expired', updated_at = ? WHERE id = ? AND status = 'sent'").run(now(), docId);
    if (!res.changes) return false;
    revokeTokens(docId);
    insertEvent(docId, 'Countersign', 'Expired', { detail: 'The signing deadline passed before every signer finished' });
    return true;
  });
  if (!done) return Promise.resolve(false);
  hook('document.expired', docId);
  const { doc } = loadDocument(docId);
  return sendMail({
    to: owner(doc).email, subject: `Expired: ${doc.title}`, heading: 'A document expired before everyone signed',
    body: `${doc.title} expired on ${expiryDate(doc.expires_at)}. Its signing links no longer work. Send a new copy if you still need signatures.`,
    actionLabel: 'Open document', actionUrl: `${process.env.APP_URL?.replace(/\/$/, '') || ''}/app/documents/${doc.id}`,
  }).then(() => true, (e) => { console.error('Expiry email failed:', e); return true; });
}

// Hourly job.
export async function expireDueDocuments() {
  const due = db.prepare("SELECT id FROM documents WHERE status = 'sent' AND expires_at IS NOT NULL AND expires_at <= ?").all(now());
  for (const { id } of due) await expireDocument(id);
  return due.length;
}

// Resolves a signing link or throws: 404 unknown, 410 revoked or expired. Pass req to record expiries in the security log.
export function signerByToken(token, req) {
  const r = typeof token === 'string' && token ? db.prepare('SELECT * FROM recipients WHERE token_hash = ?').get(sha256hex(token)) : null;
  if (!r) fail(404, 'Signing link not found');
  // Before the revoked check: an expired document's links are revoked, and the signer should learn why.
  const d = db.prepare('SELECT status, expires_at FROM documents WHERE id = ?').get(r.document_id);
  if (d?.status === 'sent' && d.expires_at && d.expires_at <= now()) expireDocument(r.document_id);
  if ((d?.status === 'sent' || d?.status === 'expired') && d.expires_at && d.expires_at <= now()) fail(410, `This document expired on ${expiryDate(d.expires_at)}.`);
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

// ---- Email one-time code (documents.require_otp) ----
const OTP_TTL_MS = 10 * 60_000;
const OTP_COOLDOWN_S = 60;
const OTP_MAX_SENDS = 10;
const OTP_MAX_ATTEMPTS = 5;
const OTP_SESSION_S = 12 * 3600;
const otpCookie = (r) => `cs_otp_${r.id}`;
const cookieValue = (req, name) => (req?.headers?.cookie || '').split(/;\s*/).find((c) => c.startsWith(`${name}=`))?.slice(name.length + 1) || null;
const hexEqual = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));

export function maskEmail(email) {
  const [local, domain] = String(email || '').split('@');
  return domain ? `${local.slice(0, 1)}***@${domain}` : '***';
}

// True when no code is required, or the request carries this recipient's live OTP session cookie.
export function signerVerified(found, req) {
  const { doc, recipient } = found;
  if (!doc.require_otp) return true;
  const value = cookieValue(req, otpCookie(recipient));
  if (!value) return false;
  const row = db.prepare('SELECT otp_session_hash, otp_session_expires_at FROM recipients WHERE id = ?').get(recipient.id);
  return Boolean(row?.otp_session_expires_at > now()) && hexEqual(keyedHash('otp-session', value), row.otp_session_hash);
}

const requireVerified = (found, req) => { if (!signerVerified(found, req)) fail(403, 'Verify your email first'); };

// Same audience as GET /file: a signer whose turn has come, or any recipient once completed.
function otpTarget(token, req) {
  const found = signerByToken(token, req);
  const { doc, recipient: r } = found;
  if (!doc.require_otp) fail(400, 'This document does not need an email code');
  if (!(doc.status === 'completed' || (doc.status === 'sent' && r.status !== 'pending'))) fail(409, 'This document is not available to you right now');
  return found;
}

export async function sendSignerCode(token, req, res) {
  const { doc, recipient: r } = otpTarget(token, req);
  if (!mailEnabled()) fail(400, 'Email codes need email (SMTP and APP_URL) to be set up on this server');
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  const t = Date.now();
  const sentAt = new Date(t).toISOString();
  // Reserve the cooldown and count synchronously so parallel requests cannot both send; undone below if delivery fails.
  const outcome = atomic(() => {
    const cur = db.prepare('SELECT otp_hash, otp_expires_at, otp_attempts, otp_sent_at, otp_send_count FROM recipients WHERE id = ?').get(r.id);
    const wait = cur.otp_sent_at ? Math.ceil(OTP_COOLDOWN_S - (t - Date.parse(cur.otp_sent_at)) / 1000) : 0;
    if (wait > 0) return { wait };
    if (cur.otp_send_count >= OTP_MAX_SENDS) return { capped: true };
    db.prepare('UPDATE recipients SET otp_hash = ?, otp_expires_at = ?, otp_attempts = 0, otp_sent_at = ?, otp_send_count = otp_send_count + 1 WHERE id = ?')
      .run(keyedHash('otp', `${r.id}:${code}`), new Date(t + OTP_TTL_MS).toISOString(), sentAt, r.id);
    return { prev: cur };
  });
  if (outcome.wait) {
    res.setHeader('Retry-After', String(outcome.wait));
    fail(429, `Wait ${outcome.wait} seconds before sending another code.`);
  }
  if (outcome.capped) fail(429, 'Too many codes were sent for this link. Contact the sender.');
  const mailed = await sendMail({
    to: r.email, subject: `Your signing code for ${doc.title}`, heading: 'Your signing code',
    body: `Your code is ${code}\n\nIt works for 10 minutes. If you did not ask for it, you can ignore this email.`,
  });
  if (!mailed) {
    // Restore the previous code and counters, but only if no later send has replaced our reservation.
    const p = outcome.prev;
    db.prepare('UPDATE recipients SET otp_hash = ?, otp_expires_at = ?, otp_attempts = ?, otp_sent_at = ?, otp_send_count = ? WHERE id = ? AND otp_sent_at = ?')
      .run(p.otp_hash, p.otp_expires_at, p.otp_attempts, p.otp_sent_at, p.otp_send_count, r.id, sentAt);
    fail(502, 'The code email could not be sent. Try again in a minute.');
  }
  logEvent(doc.id, 'Countersign', 'Email code sent', { detail: `${r.name} <${maskEmail(r.email)}>`, req });
  return { sentTo: maskEmail(r.email) };
}

export function verifySignerCode(token, code, req, res) {
  const { doc, recipient: r } = otpTarget(token, req);
  const info = req ? clientInfo(req) : {};
  const sec = (type) => logSecurity(type, { email: r.email, ip: info.ip, userAgent: info.userAgent, detail: `recipient ${r.id}` });
  const guess = typeof code === 'string' ? code.trim() : '';
  const session = crypto.randomBytes(32).toString('base64url');
  // Outcomes are returned, not thrown: a throw would roll back the attempt counter.
  const outcome = atomic(() => {
    const cur = db.prepare('SELECT otp_hash, otp_expires_at, otp_attempts FROM recipients WHERE id = ?').get(r.id);
    if (!cur.otp_hash) return cur.otp_attempts >= OTP_MAX_ATTEMPTS ? 'locked' : 'none';
    if (!(cur.otp_expires_at > now())) return 'expired';
    if (/^\d{6}$/.test(guess) && hexEqual(keyedHash('otp', `${r.id}:${guess}`), cur.otp_hash)) {
      db.prepare('UPDATE recipients SET otp_hash = NULL, otp_expires_at = NULL, otp_attempts = 0, otp_session_hash = ?, otp_session_expires_at = ?, otp_verified_at = ? WHERE id = ?')
        .run(keyedHash('otp-session', session), new Date(Date.now() + OTP_SESSION_S * 1000).toISOString(), now(), r.id);
      insertEvent(doc.id, r.name, 'Email verified', { detail: maskEmail(r.email), req });
      return 'ok';
    }
    const attempts = cur.otp_attempts + 1;
    // The fifth wrong guess burns the code.
    db.prepare('UPDATE recipients SET otp_attempts = ?, otp_hash = CASE WHEN ? >= ? THEN NULL ELSE otp_hash END WHERE id = ?').run(attempts, attempts, OTP_MAX_ATTEMPTS, r.id);
    return attempts >= OTP_MAX_ATTEMPTS ? 'just-locked' : 'wrong';
  });
  if (outcome === 'ok') {
    sec('otp_verified');
    const secure = appUrl(req).startsWith('https://') ? '; Secure' : '';
    res.setHeader('Set-Cookie', `${otpCookie(r)}=${session}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${OTP_SESSION_S}${secure}`);
    return;
  }
  if (outcome === 'just-locked') sec('otp_locked');
  if (outcome === 'wrong') sec('otp_failure');
  if (outcome === 'locked' || outcome === 'just-locked') fail(429, 'Too many attempts. Send a new code.');
  if (outcome === 'expired') fail(400, 'That code has expired. Send a new one.');
  if (outcome === 'none') fail(400, 'Send a code first.');
  fail(400, 'That code is not right');
}

export function markViewed(r, req) {
  if (r.status !== 'sent') return;
  atomic(() => {
    db.prepare("UPDATE recipients SET status = 'viewed', viewed_at = ? WHERE id = ?").run(now(), r.id);
    insertEvent(r.document_id, r.name, 'Viewed', { req });
  });
  hook('recipient.viewed', r.document_id, r.id);
}

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const PNG_MAX_SIDE = 4000;
const PNG_MAX_PIXELS = 4_000_000; // decoded RGBA stays under ~16 MB per image

// Decodes the PNG the way stamping will, so a bad image is a 400 now rather than a failed completion later.
export async function checkSignaturePng(v) {
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
  const found = signerByToken(token, req);
  requireVerified(found, req);
  const { recipient: r, doc, recipients, fields } = found;
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
    else if (IMAGE_FIELDS.has(f.type)) {
      if (v != null && v !== '') await checkSignaturePng(v);
    } else if (f.type === 'checkbox') v = v === true || v === 'true' ? 'true' : '';
    else if (f.type === 'company' || f.type === 'jobtitle') v = str(v, 200);
    else if (f.type === 'number') {
      v = str(v, 30);
      if (v && !NUMBER.test(v)) fail(400, 'Enter a number');
    } else if (CHOICE_FIELDS.has(f.type)) {
      v = str(v, Infinity); // uncut: a cut value could match an option it does not equal
      if (v && !f.options?.includes(v)) fail(400, 'Choose one of the options');
    } else v = str(v, 500);
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
      const cur = db.prepare('SELECT d.status AS ds, d.expires_at, r.status AS rs, r.token_revoked_at FROM recipients r JOIN documents d ON d.id = r.document_id WHERE r.id = ?').get(r.id);
      if (cur?.ds === 'sent' && cur.expires_at && cur.expires_at <= now()) fail(410, `This document expired on ${expiryDate(cur.expires_at)}.`);
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
  hook('recipient.signed', doc.id, r.id);
  if (signedSha) hook('document.completed', doc.id);
  if (signedSha) await mailCompleted(doc.id, baseUrl);
  else await advance(doc.id, baseUrl);
  const after = loadDocument(doc.id).doc;
  return { status: after.status, redirectUrl: after.redirect_url || null };
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
  const o = owner(doc);
  // T3-03: a public-link signer without an email code typed an unverified address; the done page offers the download instead.
  const unverifiedPublic = !doc.require_otp && db.prepare("SELECT 1 FROM events WHERE document_id = ? AND action = 'Created from public link'").get(doc.id);
  for (const r of unverifiedPublic ? [] : recipients) {
    const { subject, body } = renderEmail(o.id, 'completed', mailVars(doc, o, r));
    await sendMail({
      to: r.email, subject, heading: 'Everyone has signed', body,
      actionLabel: 'Download signed PDF', actionUrl: `${baseUrl}/sign/${r.token}`,
    });
  }
  await sendMail({
    to: o.email, subject: `Completed: ${doc.title}`, heading: 'Everyone has signed',
    body: `${doc.title} is complete.`, actionLabel: 'Open document', actionUrl: `${baseUrl}/app/documents/${doc.id}`,
  });
}

export async function declineDocument(token, reason, req) {
  const found = signerByToken(token, req);
  requireVerified(found, req);
  const { recipient: r, doc } = found;
  if (doc.status !== 'sent' || !['sent', 'viewed'].includes(r.status)) fail(409, 'This document can no longer be declined');
  const why = str(reason, 500) || 'No reason given';
  atomic(() => {
    db.prepare("UPDATE recipients SET status = 'declined', declined_reason = ? WHERE id = ?").run(why, r.id);
    db.prepare("UPDATE documents SET status = 'declined', updated_at = ? WHERE id = ?").run(now(), doc.id);
    revokeTokens(doc.id);
    insertEvent(doc.id, r.name, 'Declined', { detail: why, req });
  });
  hook('recipient.declined', doc.id, r.id);
  hook('document.declined', doc.id);
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
  hook('document.voided', full.doc.id);
}

export async function remind(full, recipientId, user, req, baseUrl) {
  if (full.doc.status === 'sent' && full.doc.expires_at && full.doc.expires_at <= now()) {
    await expireDocument(full.doc.id);
    fail(409, 'This document has expired');
  }
  const r = full.recipients.find((x) => x.id === recipientId);
  if (full.doc.status !== 'sent' || !r || !['sent', 'viewed'].includes(r.status)) fail(409, 'This recipient is not waiting to sign');
  const mailed = await notify(baseUrl, full.doc, owner(full.doc), r, { reminder: true });
  if (!mailed) fail(400, 'Email is not configured on this server. Copy the signing link instead.');
  atomic(() => {
    db.prepare('UPDATE recipients SET last_notified_at = ? WHERE id = ?').run(now(), r.id);
    extendToken(r.id);
    // T1-1: a reminder lifts the per-recipient email-code send cap and attempt lock; the cap still applies between reminders.
    db.prepare('UPDATE recipients SET otp_send_count = 0, otp_attempts = 0 WHERE id = ?').run(r.id);
    insertEvent(full.doc.id, user.name, 'Reminded', { detail: `${r.name}${full.doc.require_otp ? '. Email code limit reset' : ''}`, req });
  });
}

// Copies a document's file, recipients (as roles) and fields into a new draft or template.
// people[i] ({ name, email }) fills recipient i in position order (bulk send, public link).
// bytes: the already verified original (bulk send reads it once for all rows).
export function copyDocument(full, user, { asTemplate, people = null, bulkId = null, expireDays = full.doc.expire_days, action = null, note = '', req, bytes = null } = {}) {
  const { doc, recipients, fields } = full;
  const id = newId();
  const t = now();
  const original = bytes ?? readVerified(doc, 'original');
  checkQuota(user.id, original.length);
  writeFile(id, 'original', original); // re-encrypted: the AAD binds the ciphertext to its document id
  try {
    atomic(() => {
      // The copy joins the copier's team. Folders are per user, so a teammate's folder is not carried over.
      db.prepare(`INSERT INTO documents (id, owner_id, team_id, title, message, is_template, sequential, reminder_days, require_otp, expire_days, redirect_url, page_count, original_sha256, original_bytes, folder_id, bulk_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(id, user.id, teamIdOf(user.id), doc.title, doc.message, asTemplate ? 1 : 0, doc.sequential, doc.reminder_days, doc.require_otp, expireDays, doc.redirect_url, doc.page_count, doc.original_sha256, original.length,
          doc.owner_id === user.id ? doc.folder_id ?? null : null, bulkId, t, t);
      const map = new Map();
      recipients.forEach((r, i) => {
        const rid = newId();
        map.set(r.id, rid);
        const p = people?.[i];
        // Templates keep recipients as named roles ("Client") with no email.
        db.prepare('INSERT INTO recipients (id, document_id, name, email, role, routing_order, position) VALUES (?, ?, ?, ?, ?, ?, ?)')
          .run(rid, id, p ? p.name : r.name, p ? p.email : asTemplate ? '' : r.email, r.role, r.routing_order, r.position);
      });
      for (const f of fields) {
        db.prepare('INSERT INTO fields (id, document_id, recipient_id, type, page, x, y, w, h, required, label, options) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .run(newId(), id, map.get(f.recipient_id), f.type, f.page, f.x, f.y, f.w, f.h, f.required, f.label, f.options ? JSON.stringify(f.options) : null);
      }
      insertEvent(id, user.name, action || (asTemplate ? 'Template created' : 'Created from template'), { detail: `${doc.title}. Original SHA-256 ${doc.original_sha256}${note}`, req });
    });
  } catch (e) {
    fs.rmSync(filePath(id, 'original'), { force: true }); // no row points at it
    throw e;
  }
  return id;
}

// Routes pass the acting user's id as deletedBy (a team admin may delete a member's document); the default is the owner.
export function deleteDocument(full, deletedBy = full.doc.owner_id) {
  const { doc } = full;
  if (!['draft', 'voided', 'declined', 'expired'].includes(doc.status) && !doc.is_template) fail(409, 'Void the document before deleting it');
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
      AND (d.expires_at IS NULL OR d.expires_at > ?)
      AND julianday('now') - julianday(r.last_notified_at) >= d.reminder_days`).all(now());
  for (const row of due) {
    const r = withToken(row);
    if (!r.token || r.token_revoked_at) continue;
    const full = loadDocument(r.document_id);
    if (await notify(base, full.doc, owner(full.doc), r, { reminder: true })) {
      atomic(() => {
        db.prepare('UPDATE recipients SET last_notified_at = ? WHERE id = ?').run(now(), r.id);
        extendToken(r.id);
        insertEvent(r.document_id, 'Countersign', 'Reminder sent', { detail: r.name });
      });
    }
  }
}
