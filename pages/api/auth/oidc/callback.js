import { api, clientInfo, fail } from '../../../../lib/http';
import { getUser, startSession } from '../../../../lib/auth';
import { logSecurity } from '../../../../lib/security-log';
import { finishLogin, FLOW_COOKIE, oidcEnabled } from '../../../../lib/oidc';

export default api({
  async GET(req, res) {
    if (!oidcEnabled()) fail(404, 'Single sign-on is not set up on this server');
    res.setHeader('Cache-Control', 'no-store');
    // No flow cookie means no sign-in in progress: no provider request, no log row.
    const cookie = req.cookies?.[FLOW_COOKIE];
    if (!cookie) return res.redirect(302, '/login?error=sso');
    const info = clientInfo(req);
    const sessionUserId = getUser(req)?.id;
    let target;
    try {
      const { userId, email, next, created, linked } = await finishLogin(req.query, cookie, info.ip, sessionUserId);
      startSession(res, userId, info);
      if (created) logSecurity('signup', { ...info, userId, email, detail: 'via sso' });
      if (linked) logSecurity('sso_linked', { ...info, userId, email });
      logSecurity('login_success', { ...info, userId, email, detail: 'sso' });
      target = next;
    } catch (e) {
      if (!e.status) console.error('SSO callback failed:', e.message);
      if (e.status !== 429) logSecurity('login_failure', { ...info, detail: e.status ? e.message : 'SSO: provider request failed' });
      // The login page sends a signed-in person away, so a failed Connect reports in Settings.
      if (sessionUserId) target = '/app/settings?sso=failed';
      else target = { 403: '/login?error=sso_denied', 409: '/login?error=sso_link' }[e.status] ?? '/login?error=sso';
    }
    // appendHeader: startSession has already set this response's session cookie.
    res.appendHeader('Set-Cookie', `${FLOW_COOKIE}=; Path=/api/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=0`);
    return res.redirect(302, target);
  },
}, { auth: false });
