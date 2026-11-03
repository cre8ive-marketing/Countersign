import { api } from '../../../lib/http';
import { deleteFolder, renameFolder } from '../../../lib/folders';

export default api({
  PUT(req, res, user) {
    renameFolder(user.id, req.query.id, req.body);
    res.json({ ok: true });
  },
  DELETE(req, res, user) {
    deleteFolder(user.id, req.query.id);
    res.json({ ok: true });
  },
}, { apiKey: true });
