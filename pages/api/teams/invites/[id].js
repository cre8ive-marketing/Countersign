import { api } from '../../../../lib/http';
import { revokeInvite } from '../../../../lib/teams';

export default api({
  DELETE(req, res, user) {
    revokeInvite(user, req.query.id);
    res.json({ ok: true });
  },
});
