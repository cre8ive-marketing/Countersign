import { api } from '../../../lib/http';
import { endSession } from '../../../lib/auth';

export default api({
  POST(req, res) {
    endSession(req, res);
    res.json({ ok: true });
  },
}, { auth: false });
