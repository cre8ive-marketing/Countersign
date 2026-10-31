import { api } from '../../../../lib/http';
import { declineDocument } from '../../../../lib/documents';

export default api({
  async POST(req, res) {
    await declineDocument(req.query.token, req.body?.reason, req);
    res.json({ ok: true });
  },
}, { auth: false });
