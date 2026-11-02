import { api, clientInfo, fail, str, EMAIL } from '../../../lib/http';
import { createUser, passwordProblem, signupOpen, signupThrottle, startSession } from '../../../lib/auth';
import { logSecurity } from '../../../lib/security-log';
import db from '../../../lib/db';

export default api({
  POST(req, res) {
    if (!signupOpen()) fail(403, 'Sign-ups are closed on this server. Ask the admin for an account.');
    const info = clientInfo(req);
    // Throttled per IP: the 409 below would otherwise be an unlimited account-existence oracle.
    const wait = signupThrottle(info.ip);
    if (wait) {
      res.setHeader('Retry-After', String(wait));
      fail(429, 'Too many sign-up attempts. Try again later.');
    }
    const email = str(req.body?.email, 254).toLowerCase();
    const name = str(req.body?.name, 120);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!name) fail(400, 'Enter your name');
    if (!EMAIL.test(email)) fail(400, 'Enter a valid email address');
    const problem = passwordProblem(password, email);
    if (problem) fail(400, problem);
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) fail(409, 'An account with this email already exists');
    const userId = createUser({ email, name, password });
    startSession(res, userId, info);
    logSecurity('signup', { ...info, email, userId });
    res.json({ ok: true });
  },
}, { auth: false });
