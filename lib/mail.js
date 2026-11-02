import nodemailer from 'nodemailer';
import db from './db.js';

const configured = () => Boolean(process.env.SMTP_HOST);
// Matches sendMail: without APP_URL nothing is sent, so the UI must not offer email features.
export const mailEnabled = () => configured() && Boolean(process.env.APP_URL);

let transport;
function getTransport() {
  transport ??= nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === 'true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
  return transport;
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// Returns true when sent. Without SMTP the sender copies links from the document page instead.
export async function sendMail({ to, subject, heading, body, actionLabel, actionUrl }) {
  if (!configured()) return false;
  // Without APP_URL, links would come from the request's Host header, which a client can forge.
  if (!process.env.APP_URL) {
    console.error('Email not sent: APP_URL must be set when SMTP is configured.');
    return false;
  }
  // Brand palette only: #0B132B ink, #3A506B muted; #fcf3e7 is 30% #F4D6B0, #d8dce1 is 20% #3A506B (email clients lack color-mix).
  const html = `<!doctype html><body style="margin:0;background:#fcf3e7;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#0B132B">
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 16px">
  <table width="520" cellpadding="0" cellspacing="0" style="max-width:520px;background:#fff;border:1px solid #d8dce1;border-radius:12px">
  <tr><td style="padding:32px 32px 8px;font-weight:700;font-size:15px">Countersign</td></tr>
  <tr><td style="padding:8px 32px 0;font-size:20px;font-weight:600;line-height:1.3">${esc(heading)}</td></tr>
  <tr><td style="padding:12px 32px 0;font-size:15px;line-height:1.6;color:#3A506B;white-space:pre-line">${esc(body)}</td></tr>
  ${actionUrl ? `<tr><td style="padding:24px 32px 0"><a href="${esc(actionUrl)}" style="display:inline-block;background:#0B132B;color:#fff;text-decoration:none;font-weight:600;font-size:15px;padding:12px 20px;border-radius:8px">${esc(actionLabel)}</a></td></tr>` : ''}
  <tr><td style="padding:28px 32px 32px;font-size:12px;color:#3A506B">Sent by a self-hosted Countersign server. If you did not expect this, you can ignore it.</td></tr>
  </table></td></tr></table></body>`;
  try {
    await getTransport().sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to, subject, html,
      text: `${heading}\n\n${body}${actionUrl ? `\n\n${actionLabel}: ${actionUrl}` : ''}`,
    });
    return true;
  } catch (e) {
    console.error('Email failed:', e.message);
    return false;
  }
}

// Editable invitation and completion text. The action button is always added by the caller, never by a template.
export const EMAIL_KINDS = ['invite', 'completed'];
export const EMAIL_VARIABLES = ['sender_name', 'sender_email', 'receiver_name', 'document_title', 'message', 'message_block', 'expires_on'];
export const EMAIL_SUBJECT_MAX = 200;
export const EMAIL_BODY_MAX = 4000;
export const EMAIL_DEFAULTS = {
  invite: {
    subject: '{{sender_name}} sent you "{{document_title}}" to sign',
    body: '{{document_title}}{{message_block}}\n\nNo account needed. Review the document and sign in a couple of minutes.',
  },
  completed: {
    subject: 'Completed: {{document_title}}',
    body: '{{document_title}} is complete. Download the signed copy with its certificate of completion.',
  },
};

export function emailTemplate(userId, kind) {
  if (!EMAIL_KINDS.includes(kind)) throw new Error(`Unknown email template ${kind}`);
  const row = db.prepare('SELECT subject, body FROM email_templates WHERE user_id = ? AND kind = ?').get(userId, kind);
  return row ? { subject: row.subject, body: row.body, custom: true } : { ...EMAIL_DEFAULTS[kind], custom: false };
}

// Plain-text substitution in one pass (values containing {{x}} are not expanded again); unknown variables stay as typed.
// sendMail escapes the HTML; the subject loses CR/LF so no value can add a header line.
export function renderEmail(userId, kind, vars = {}) {
  const t = emailTemplate(userId, kind);
  const v = { ...vars, message_block: vars.message ? `\n\n"${vars.message}"` : '' };
  const fill = (s) => s.replace(/\{\{(\w+)\}\}/g, (m, k) => (EMAIL_VARIABLES.includes(k) ? String(v[k] ?? '') : m));
  return { subject: fill(t.subject).replace(/[\r\n]+/g, ' ').trim().slice(0, EMAIL_SUBJECT_MAX), body: fill(t.body) };
}
