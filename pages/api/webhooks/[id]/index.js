import { api } from '../../../../lib/http';
import { deleteWebhook, updateWebhook } from '../../../../lib/webhooks';

export default api({
  PUT(req, res, user) {
    updateWebhook(user.id, req.query.id, req.body ?? {});
    res.json({ ok: true });
  },
  DELETE(req, res, user) {
    deleteWebhook(user.id, req.query.id);
    res.json({ ok: true });
  },
});
