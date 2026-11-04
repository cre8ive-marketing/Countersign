import { api, clientInfo } from '../../../lib/http';
import { createTeam, deleteTeam, getTeam, renameTeam, teamOf } from '../../../lib/teams';
import { logSecurity } from '../../../lib/security-log';

// Session only (no API keys): team membership controls who can see and manage documents.
export default api({
  GET(req, res, user) {
    res.setHeader('Cache-Control', 'private, no-store');
    res.json(getTeam(user));
  },
  POST(req, res, user) {
    res.status(201).json({ id: createTeam(user, req.body) });
  },
  PUT(req, res, user) {
    renameTeam(user, req.body);
    res.json({ ok: true });
  },
  DELETE(req, res, user) {
    const teamId = teamOf(user.id)?.teamId;
    deleteTeam(user);
    logSecurity('team_deleted', { ...clientInfo(req), userId: user.id, email: user.email, detail: `team ${teamId}` });
    res.json({ ok: true });
  },
});
