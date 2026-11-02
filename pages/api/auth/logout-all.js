import { api, clientInfo } from '../../../lib/http';
import { endAllSessions } from '../../../lib/auth';

// Signs the user out everywhere, including this browser.
export default api({
  POST(req, res, user) {
    endAllSessions(res, user, clientInfo(req));
    res.json({ ok: true });
  },
});
