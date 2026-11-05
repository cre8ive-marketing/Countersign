import { api, fail } from '../../../../lib/http';
import { beginLogin, flowCookie, oidcEnabled } from '../../../../lib/oidc';

export default api({
  async GET(req, res) {
    if (!oidcEnabled()) fail(404, 'Single sign-on is not set up on this server');
    res.setHeader('Cache-Control', 'no-store');
    try {
      const { url, flow } = await beginLogin(req.query.next);
      res.setHeader('Set-Cookie', flowCookie(flow));
      res.redirect(302, url);
    } catch (e) {
      console.error('SSO start failed:', e.message);
      res.redirect(302, '/login?error=sso');
    }
  },
}, { auth: false });
