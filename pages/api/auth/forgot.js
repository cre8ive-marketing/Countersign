import { api, appUrl, clientInfo, fail, str } from '../../../lib/http';
import { ipPrefix, newResetToken, rateLimit } from '../../../lib/auth';
import { logId } from '../../../lib/crypto';
import { mailEnabled, sendMail } from '../../../lib/mail';
import { oidcName, resetRefused } from '../../../lib/oidc';
import { logSecurity } from '../../../lib/security-log';
import db from '../../../lib/db';

const REQUESTS_PER_IP_HOUR = 20;
const MAILS_PER_ACCOUNT_HOUR = 3; // bounds mail to a victim's inbox; earlier links keep working, so this can't take a reset away
const HOUR = 36e5;
const MAX_WAIT_MS = 3000;

async function sendLink(email, base, info) {
  // Keyed on a hash of what was typed, known or not: a password typed into the email box must not reach the database.
  if (rateLimit(`forgot:${logId(email)}`, MAILS_PER_ACCOUNT_HOUR, HOUR)) return;
  const user = db.prepare('SELECT id, email FROM users WHERE email = ?').get(email);
  if (!user) return;
  const subject = 'Reset your Countersign password';
  logSecurity('password_reset_request', { ...info, userId: user.id, email: user.email });
  if (resetRefused(user.id)) {
    await sendMail({ to: user.email, subject, heading: 'Your account has no password to reset', body: `This account signs in with ${oidcName()}.` });
    return;
  }
  await sendMail({
    to: user.email, subject, heading: 'Reset your password',
    body: 'Someone asked to reset the password for this account. The link works once, for one hour. If it wasn\'t you, ignore this email and your password stays the same.',
    actionLabel: 'Choose a new password',
    actionUrl: `${base}/reset#${newResetToken(user.id)}`,
  });
}

export default api({
  POST(req, res) {
    if (!mailEnabled()) fail(404, 'This server does not send email');
    const info = clientInfo(req);
    const wait = rateLimit(`forgot-ip:${ipPrefix(info.ip)}`, REQUESTS_PER_IP_HOUR, HOUR);
    if (wait) {
      res.setHeader('Retry-After', String(wait));
      fail(429, 'Too many requests. Try again later.');
    }
    const email = str(req.body?.email, 254).toLowerCase();
    const base = appUrl(req);
    res.json({ ok: true });
    // After the response, at a random moment, so neither this answer nor the next request's timing shows whether the account exists.
    if (email) setTimeout(() => sendLink(email, base, info).catch((e) => console.error('Password reset email failed:', e.message)), Math.random() * MAX_WAIT_MS);
  },
}, { auth: false });
