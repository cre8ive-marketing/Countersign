import { api } from '../../../lib/http';
import { createFolder, listFolders } from '../../../lib/folders';

export default api({
  GET(req, res, user) {
    res.json({ folders: listFolders(user.id) });
  },
  POST(req, res, user) {
    res.status(201).json({ id: createFolder(user.id, req.body) });
  },
}, { apiKey: true });
