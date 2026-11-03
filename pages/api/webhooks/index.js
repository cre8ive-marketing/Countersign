import { api } from '../../../lib/http';
import { createWebhook, EVENTS, listWebhooks } from '../../../lib/webhooks';

// Session only (no apiKey option): API keys can't manage webhooks.
export default api({
  GET(req, res, user) {
    res.json({ webhooks: listWebhooks(user.id), events: EVENTS });
  },
  POST(req, res, user) {
    res.setHeader('Cache-Control', 'private, no-store');
    res.status(201).json(createWebhook(user.id, req.body));
  },
});
