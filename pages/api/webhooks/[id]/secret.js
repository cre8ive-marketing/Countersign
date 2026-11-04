import { api, clientInfo } from '../../../../lib/http';
import { rotateSecret } from '../../../../lib/webhooks';
import { logSecurity } from '../../../../lib/security-log';

// Session only. Returns the new signing secret once.
export default api({
  POST(req, res, user) {
    const out = rotateSecret(user.id, req.query.id);
    logSecurity('webhook_secret_rotated', { ...clientInfo(req), userId: user.id, email: user.email, detail: `webhook ${req.query.id}` });
    res.setHeader('Cache-Control', 'private, no-store');
    res.json(out);
  },
});
