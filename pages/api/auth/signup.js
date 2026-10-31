import { api, fail, str, EMAIL } from '../../../lib/http';
import { createUser, signupOpen, startSession } from '../../../lib/auth';
import db from '../../../lib/db';

export default api({
  POST(req, res) {
    if (!signupOpen()) fail(403, 'Sign-ups are closed on this server. Ask the admin for an account.');
    const email = str(req.body?.email, 254).toLowerCase();
    const name = str(req.body?.name, 120);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!name) fail(400, 'Enter your name');
    if (!EMAIL.test(email)) fail(400, 'Enter a valid email address');
    if (password.length < 8 || password.length > 200) fail(400, 'Use a password of at least 8 characters');
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) fail(409, 'An account with this email already exists');
    startSession(res, createUser({ email, name, password }));
    res.json({ ok: true });
  },
}, { auth: false });
