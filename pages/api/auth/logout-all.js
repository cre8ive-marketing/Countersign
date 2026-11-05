import { api, clientInfo, fail } from '../../../lib/http';
import { endAllSessions } from '../../../lib/auth';
import { revokeAllKeys } from '../../../lib/apikeys';
import { pauseAllWebhooks } from '../../../lib/webhooks';

// Signs the user out everywhere, including this browser. { apiKeys: true } also revokes every API key and pauses every webhook.
export default api({
  POST(req, res, user) {
    const apiKeys = req.body?.apiKeys ?? false;
    if (typeof apiKeys !== 'boolean') fail(400, 'apiKeys must be true or false');
    const info = clientInfo(req);
    const keysRevoked = apiKeys ? revokeAllKeys(user, info) : 0;
    if (apiKeys) pauseAllWebhooks(user, info);
    endAllSessions(res, user, info);
    res.json(apiKeys ? { ok: true, keysRevoked } : { ok: true });
  },
});
