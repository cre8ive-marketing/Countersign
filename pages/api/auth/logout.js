import { api, clientInfo } from '../../../lib/http';
import { endSession } from '../../../lib/auth';

export default api({
  POST(req, res) {
    endSession(req, res, clientInfo(req));
    res.json({ ok: true });
  },
}, { auth: false });
