import { api, fail } from '../../../../lib/http';
import { sendSignerCode, verifySignerCode } from '../../../../lib/documents';

// Body { action: 'send' } or { action: 'verify', code }.
export default api({
  async POST(req, res) {
    const action = req.body?.action;
    if (action === 'send') return res.json({ ok: true, ...(await sendSignerCode(req.query.token, req, res)) });
    if (action === 'verify') {
      verifySignerCode(req.query.token, req.body?.code, req, res);
      return res.json({ ok: true });
    }
    fail(400, 'Unknown action');
  },
}, { auth: false });
