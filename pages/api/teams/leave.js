import { api, clientInfo } from '../../../lib/http';
import { leaveTeam } from '../../../lib/teams';
import { logSecurity } from '../../../lib/security-log';

// The user's documents shared with the team become personal again.
export default api({
  POST(req, res, user) {
    const { teamId, deleted } = leaveTeam(user);
    logSecurity('team_left', { ...clientInfo(req), userId: user.id, email: user.email, detail: `team ${teamId}${deleted ? ' (last member, team deleted)' : ''}` });
    res.json({ ok: true, deleted });
  },
});
