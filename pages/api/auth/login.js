import { api, clientInfo, fail, str } from '../../../lib/http';
import { loginDelayMs, loginLockedFor, recordLoginFailure, recordLoginSuccess, startSession, verifyLogin } from '../../../lib/auth';
import { logSecurity } from '../../../lib/security-log';
import { logId } from '../../../lib/crypto';
import db from '../../../lib/db';

export default api({
  async POST(req, res) {
    const email = str(req.body?.email, 254).toLowerCase();
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const info = clientInfo(req);
    const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(email);
    // Log the typed email only when it is a real account: a password typed into the email box must not reach the log.
    const who = user ? { email, userId: user.id } : { email: null, detail: `unknown account ${logId(email)}` };
    const wait = loginLockedFor(email, info.ip);
    if (wait) {
      logSecurity('login_locked', { ...info, ...who });
      res.setHeader('Retry-After', String(wait));
      fail(429, 'Too many sign-in attempts. Try again later.');
    }
    // Reserve the attempt before the await below; a correct password undoes it in recordLoginSuccess.
    const delay = loginDelayMs(email);
    const locked = recordLoginFailure(email, info.ip);
    if (delay) await new Promise((r) => setTimeout(r, delay));
    if (!verifyLogin(password, user?.password_hash)) {
      logSecurity('login_failure', { ...info, ...who });
      if (locked) logSecurity('login_locked', { ...info, ...who, detail: `${who.detail ? who.detail + '; ' : ''}limit reached` });
      fail(401, 'Email or password is incorrect');
    }
    recordLoginSuccess(email, info.ip);
    startSession(res, user.id, info);
    logSecurity('login_success', { ...info, ...who });
    res.json({ ok: true });
  },
}, { auth: false });
