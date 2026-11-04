import { api, clientInfo } from '../../../../lib/http';
import { removeMember, setRole, teamOf } from '../../../../lib/teams';
import { logSecurity } from '../../../../lib/security-log';

export default api({
  PUT(req, res, user) {
    const role = req.body?.role;
    setRole(user, req.query.userId, role);
    logSecurity('team_role_changed', { ...clientInfo(req), userId: user.id, email: user.email, detail: `team ${teamOf(user.id).teamId}: user ${req.query.userId} -> ${role}` });
    res.json({ ok: true });
  },
  DELETE(req, res, user) {
    removeMember(user, req.query.userId);
    logSecurity('team_member_removed', { ...clientInfo(req), userId: user.id, email: user.email, detail: `team ${teamOf(user.id).teamId}: user ${req.query.userId}` });
    res.json({ ok: true });
  },
});
