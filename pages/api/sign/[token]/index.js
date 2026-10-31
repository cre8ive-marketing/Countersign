import { api, appUrl } from '../../../../lib/http';
import { submitSignature } from '../../../../lib/documents';

export const config = { api: { bodyParser: { sizeLimit: '8mb' } } };

export default api({
  async POST(req, res) {
    const status = await submitSignature(req.query.token, req.body?.values, req, appUrl(req));
    res.json({ status });
  },
}, { auth: false });
