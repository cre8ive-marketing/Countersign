import { api, clientInfo, fail } from '../../../lib/http';
import { clearLoginFailures, endAllSessions, hashPassword, passwordProblem, resetTokenUser, useResetToken } from '../../../lib/auth';
import { revokeAllKeys } from '../../../lib/apikeys';
import { pauseAllWebhooks } from '../../../lib/webhooks';
import { mailEnabled, sendMail } from '../../../lib/mail';
import { oidcName, resetRefused } from '../../../lib/oidc';
import { logSecurity } from '../../../lib/security-log';
import db, { now, tx } from '../../../lib/db';

const DEAD = 'This link has expired or was already used. Ask for a new one.';

export default api({
  async POST(req, res) {
    const { token, password } = req.body ?? {};
    const user = resetTokenUser(token);
    if (!user) fail(400, DEAD);
    // Checked again here: the account may have connected SSO after the link went out.
    if (resetRefused(user.id)) fail(403, `This account signs in with ${oidcName()}.`);
    const problem = passwordProblem(password, user.email); // a mistyped password does not use up the link
    if (problem) fail(400, problem);
    const hash = await hashPassword(password);
    const info = clientInfo(req);
    tx(() => {
      if (!useResetToken(token, user.id)) fail(400, DEAD); // two parallel requests: only one gets past this
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
      // The person may be locking someone else out, so nothing an intruder left behind stays alive.
      endAllSessions(res, user, info);
      const keys = revokeAllKeys(user, info);
      pauseAllWebhooks(user, info);
      const invites = db.prepare('UPDATE team_invites SET revoked_at = ? WHERE created_by = ? AND accepted_at IS NULL AND revoked_at IS NULL').run(now(), user.id).changes;
      clearLoginFailures(user, info.ip);
      logSecurity('password_reset', { ...info, userId: user.id, email: user.email, detail: `all sessions, ${keys} API keys and ${invites} invites revoked` });
    });
    if (mailEnabled()) {
      sendMail({
        to: user.email, subject: 'Your Countersign password was changed', heading: 'Your password was changed',
        body: 'Someone used a reset link to change the password for this account. Every device was signed out, API keys were revoked, webhooks were paused and pending team invites you sent were cancelled. If it wasn\'t you, reset your password again and tell the person who runs this server.',
      });
    }
    res.json({ ok: true });
  },
}, { auth: false });
