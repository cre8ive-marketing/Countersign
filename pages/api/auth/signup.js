import { api, clientInfo, fail, str, EMAIL } from '../../../lib/http';
import { createUser, hashPassword, passwordProblem, signupOpen, signupThrottle, startSession } from '../../../lib/auth';
import { logSecurity } from '../../../lib/security-log';
import db, { tx } from '../../../lib/db';
import { inviteByToken, joinWithInvite } from '../../../lib/teams';
import { oidcName, passwordSignupOff } from '../../../lib/oidc';

export default api({
  async POST(req, res) {
    const info = clientInfo(req);
    // Throttled per IP: the 409 below would otherwise be an unlimited account-existence oracle.
    const wait = signupThrottle(info.ip);
    if (wait) {
      res.setHeader('Retry-After', String(wait));
      fail(429, 'Too many sign-up attempts. Try again later.');
    }
    const noPassword = () => passwordSignupOff() && fail(403, `This server creates accounts through ${oidcName()}.`);
    noPassword();
    const email = str(req.body?.email, 254).toLowerCase();
    // A valid team invite for this exact email opens sign-up even when it is closed, and is accepted in the same request.
    const inviteToken = req.body?.inviteToken;
    const invite = inviteToken && inviteByToken(inviteToken);
    const viaInvite = Boolean(invite) && invite.email.toLowerCase() === email;
    if (!signupOpen() && !viaInvite) fail(403, 'Sign-ups are closed on this server. Ask the admin for an account.');
    const name = str(req.body?.name, 120);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!name) fail(400, 'Enter your name');
    if (!EMAIL.test(email)) fail(400, 'Enter a valid email address');
    const problem = passwordProblem(password, email);
    if (problem) fail(400, problem);
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) fail(409, 'An account with this email already exists');
    const passwordHash = await hashPassword(password); // scrypt outside the write lock
    const userId = tx(() => {
      // Re-checked under the lock: closed sign-up only admits invites to a team owned by the first account.
      noPassword();
      const open = signupOpen();
      if (!open && !viaInvite) fail(403, 'Sign-ups are closed on this server. Ask the admin for an account.');
      if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) fail(409, 'An account with this email already exists');
      const id = createUser({ email, name, passwordHash });
      if (viaInvite) joinWithInvite({ id, email }, inviteToken, { signupClosed: !open });
      return id;
    });
    startSession(res, userId, info);
    logSecurity('signup', { ...info, email, userId, detail: viaInvite ? 'via team invite' : '' });
    if (viaInvite) logSecurity('team_joined', { ...info, email, userId, detail: `role ${invite.role}` });
    res.json({ ok: true });
  },
}, { auth: false });
