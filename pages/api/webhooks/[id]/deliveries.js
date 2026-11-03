import { api } from '../../../../lib/http';
import { listDeliveries } from '../../../../lib/webhooks';

export default api({
  GET(req, res, user) {
    res.json({ deliveries: listDeliveries(user.id, req.query.id) });
  },
});
