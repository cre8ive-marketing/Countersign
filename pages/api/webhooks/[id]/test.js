import { api } from '../../../../lib/http';
import { sendTest } from '../../../../lib/webhooks';

export default api({
  POST(req, res, user) {
    sendTest(user.id, req.query.id);
    res.json({ ok: true });
  },
});
