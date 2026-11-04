import { api, clientInfo, fail } from '../../../lib/http';
import { endAllSessions } from '../../../lib/auth';
import { revokeAllKeys } from '../../../lib/apikeys';

// Signs the user out everywhere, including this browser. { apiKeys: true } also revokes every API key.
export default api({
  POST(req, res, user) {
    const apiKeys = req.body?.apiKeys ?? false;
    if (typeof apiKeys !== 'boolean') fail(400, 'apiKeys must be true or false');
    const info = clientInfo(req);
    const keysRevoked = apiKeys ? revokeAllKeys(user, info) : 0;
    endAllSessions(res, user, info);
    res.json(apiKeys ? { ok: true, keysRevoked } : { ok: true });
  },
});
