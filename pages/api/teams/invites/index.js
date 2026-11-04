import { api, appUrl, clientInfo, fail } from '../../../../lib/http';
import { createInvite, getTeam } from '../../../../lib/teams';
import { rateLimit } from '../../../../lib/auth';
import { sendMail } from '../../../../lib/mail';
import { logSecurity } from '../../../../lib/security-log';

export default api({
  GET(req, res, user) {
    const { team, invites } = getTeam(user);
    if (!team) fail(409, 'Join a team first');
    if (!invites) fail(403, 'Only team owners and admins can do this');
    res.setHeader('Cache-Control', 'private, no-store');
    res.json({ invites });
  },
  // Returns the join link once ({ id, url: '/join/<token>', emailed }); it is also emailed when SMTP is configured.
  async POST(req, res, user) {
    const wait = rateLimit(`team-invite:${user.id}`, 30, 36e5);
    if (wait) {
      res.setHeader('Retry-After', String(wait));
      fail(429, 'Too many invites. Try again later.');
    }
    const { id, url, email, role, teamName } = createInvite(user, req.body);
    logSecurity('team_invite_created', { ...clientInfo(req), userId: user.id, email: user.email, detail: `invite ${id} for ${email} as ${role}` });
    res.setHeader('Cache-Control', 'private, no-store');
    // Server-wide cap so an open server can't be used as a mail relay; past it the link is still returned to copy.
    const capped = Boolean(rateLimit('team-invite-mail', Number(process.env.INVITE_EMAILS_PER_HOUR) || 100, 36e5));
    const emailed = !capped && await sendMail({
      to: email,
      subject: `${user.name} invited you to ${teamName} on Countersign`,
      heading: `Join ${teamName}`,
      body: `${user.name} (${user.email}) invited you to join the team "${teamName}" as ${role === 'admin' ? 'an admin' : 'a member'}. The link works for 7 days and only for ${email}.`,
      actionLabel: 'Join team',
      actionUrl: appUrl(req) + url,
    });
    res.status(201).json({ id, url, emailed });
  },
});
