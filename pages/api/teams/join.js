import { api, clientInfo } from '../../../lib/http';
import { acceptInvite } from '../../../lib/teams';
import { logSecurity } from '../../../lib/security-log';

// Accepting needs a signed-in account whose email matches the invite (403 otherwise).
export default api({
  POST(req, res, user) {
    const { teamId, role } = acceptInvite(user, req.body?.token);
    logSecurity('team_joined', { ...clientInfo(req), userId: user.id, email: user.email, detail: `team ${teamId} as ${role}` });
    res.json({ ok: true, teamId, role });
  },
});
