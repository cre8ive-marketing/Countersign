import { api, appUrl, clientInfo, fail } from '../../../lib/http';
import { ipPrefix, rateLimit } from '../../../lib/auth';
import { createFromPublicLink, publicTemplateByToken } from '../../../lib/documents';
import { sha256hex } from '../../../lib/crypto.js';

const HOUR = 36e5;

function limit(res, key, max, windowMs) {
  const wait = rateLimit(key, max, windowMs);
  if (wait) {
    res.setHeader('Retry-After', String(wait));
    fail(429, 'Too many requests. Try again later.');
  }
}

// Public template link: a visitor types their name and email, gets their own copy and signs it. Same-origin check stays on.
export default api({
  async POST(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    // Per IP first, so probing tokens costs the same as using one.
    limit(res, `public:${ipPrefix(clientInfo(req).ip)}`, 10, HOUR);
    // Honeypot: real visitors never see the `website` field.
    if (req.body?.website) return res.json({ ok: true });
    const tpl = publicTemplateByToken(req.query.token);
    if (!tpl) fail(404, 'This link is not active');
    // Keyed on the token, so rotating the link starts a fresh budget.
    limit(res, `publictpl:${sha256hex(req.query.token)}`, 50, 24 * HOUR);
    res.json(await createFromPublicLink(req.query.token, req.body, req, appUrl(req)));
  },
}, { auth: false });
