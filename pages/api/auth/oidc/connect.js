import { api, fail } from '../../../../lib/http';
import { beginLogin, flowCookie, oidcEnabled } from '../../../../lib/oidc';

// Settings' Connect button. A POST, so api()'s same-origin check stops another site starting it for a signed-in person.
// Returns the address instead of redirecting: the page navigates there itself.
export default api({
  async POST(req, res, user) {
    if (!oidcEnabled()) fail(404, 'Single sign-on is not set up on this server');
    const { url, flow } = await beginLogin('/app/settings', user.id).catch((e) => {
      console.error('SSO connect failed:', e.message);
      fail(502, 'Could not reach the sign-in provider. Try again later.');
    });
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Set-Cookie', flowCookie(flow));
    res.json({ url });
  },
});
