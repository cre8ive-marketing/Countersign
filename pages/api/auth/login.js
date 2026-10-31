import { api, fail, str } from '../../../lib/http';
import { startSession, verifyPassword } from '../../../lib/auth';
import db from '../../../lib/db';

export default api({
  POST(req, res) {
    const email = str(req.body?.email, 254).toLowerCase();
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(email);
    if (!user || !verifyPassword(password, user.password_hash)) fail(401, 'Email or password is incorrect');
    startSession(res, user.id);
    res.json({ ok: true });
  },
}, { auth: false });
