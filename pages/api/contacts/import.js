import { api, fail, readRaw } from '../../../lib/http';
import { importContacts } from '../../../lib/contacts';

export const config = { api: { bodyParser: false } };

export default api({
  async POST(req, res, user) {
    if (!/^text\/csv\b/i.test(String(req.headers['content-type']))) fail(415, 'Upload a CSV file');
    const bytes = await readRaw(req, 1048576);
    res.json(importContacts(user.id, bytes.toString('utf8')));
  },
});
