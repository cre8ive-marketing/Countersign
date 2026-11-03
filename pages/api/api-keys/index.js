import { api } from '../../../lib/http';
import { createKey, listKeys } from '../../../lib/apikeys';

// Session only: an API key can never list or create keys.
export default api({
  GET(req, res, user) {
    res.setHeader('Cache-Control', 'private, no-store');
    res.json({ keys: listKeys(user.id) });
  },
  POST(req, res, user) {
    res.setHeader('Cache-Control', 'private, no-store');
    res.status(201).json(createKey(user, req.body, req));
  },
});
