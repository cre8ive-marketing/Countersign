import { api, clientInfo, fail, str } from '../../lib/http';
import {
  clearPasswordCheckFailures, hashPassword, passwordCheckLockedFor, passwordProblem, recordPasswordCheckFailure, revokeOtherSessions, verifyPassword,
} from '../../lib/auth';
import { revokeAllKeys } from '../../lib/apikeys';
import { logSecurity } from '../../lib/security-log';
import db from '../../lib/db';

export default api({
  PATCH(req, res, user) {
    const name = str(req.body?.name, 120);
    if (name) db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, user.id);
    const { currentPassword, newPassword } = req.body ?? {};
    if (newPassword) {
      const info = clientInfo(req);
      const wait = passwordCheckLockedFor(user.id);
      if (wait) {
        res.setHeader('Retry-After', String(wait));
        fail(429, 'Too many attempts. Try again later.');
      }
      const row = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(user.id);
      if (typeof currentPassword !== 'string' || !verifyPassword(currentPassword, row.password_hash)) {
        if (recordPasswordCheckFailure(user.id)) logSecurity('login_locked', { ...info, userId: user.id, email: user.email, detail: 'password change: current password limit reached' });
        fail(400, 'Current password is incorrect');
      }
      clearPasswordCheckFailures(user.id);
      const problem = passwordProblem(newPassword, user.email);
      if (problem) fail(400, problem);
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), user.id);
      const revoked = revokeOtherSessions(req, user.id);
      const keys = revokeAllKeys(user, info);
      logSecurity('password_change', { ...info, userId: user.id, email: user.email, detail: `${revoked} other sessions and ${keys} API keys revoked` });
    }
    res.json({ ok: true });
  },
});
