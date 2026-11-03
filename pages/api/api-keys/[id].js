import { api } from '../../../lib/http';
import { revokeKey } from '../../../lib/apikeys';

export default api({
  DELETE(req, res, user) {
    revokeKey(user, req.query.id, req);
    res.json({ ok: true });
  },
});
