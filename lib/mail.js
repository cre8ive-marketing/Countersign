import nodemailer from 'nodemailer';

const configured = () => Boolean(process.env.SMTP_HOST);
export const mailEnabled = configured;

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
  const html = `<!doctype html><body style="margin:0;background:#f4f5f7;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#14161b">
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 16px">
  <table width="520" cellpadding="0" cellspacing="0" style="max-width:520px;background:#fff;border:1px solid #e3e5ea;border-radius:12px">
  <tr><td style="padding:32px 32px 8px;font-weight:700;font-size:15px">Countersign</td></tr>
  <tr><td style="padding:8px 32px 0;font-size:20px;font-weight:600;line-height:1.3">${esc(heading)}</td></tr>
  <tr><td style="padding:12px 32px 0;font-size:15px;line-height:1.6;color:#4a4f5c;white-space:pre-line">${esc(body)}</td></tr>
  ${actionUrl ? `<tr><td style="padding:24px 32px 0"><a href="${esc(actionUrl)}" style="display:inline-block;background:#1e3a5f;color:#fff;text-decoration:none;font-weight:600;font-size:15px;padding:12px 20px;border-radius:8px">${esc(actionLabel)}</a></td></tr>` : ''}
  <tr><td style="padding:28px 32px 32px;font-size:12px;color:#7b8190">Sent by a self-hosted Countersign server. If you did not expect this, you can ignore it.</td></tr>
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
