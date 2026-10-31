import { api, fail, str } from '../../lib/http';
import { hashPassword, verifyPassword } from '../../lib/auth';
import db from '../../lib/db';

export default api({
  PATCH(req, res, user) {
    const name = str(req.body?.name, 120);
    if (name) db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, user.id);
    const { currentPassword, newPassword } = req.body ?? {};
    if (newPassword) {
      const row = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(user.id);
      if (typeof currentPassword !== 'string' || !verifyPassword(currentPassword, row.password_hash)) fail(400, 'Current password is incorrect');
      if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 200) fail(400, 'Use a new password of at least 8 characters');
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), user.id);
    }
    res.json({ ok: true });
  },
});
