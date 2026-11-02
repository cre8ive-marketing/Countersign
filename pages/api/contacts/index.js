import { api } from '../../../lib/http';
import { createContact, listContacts } from '../../../lib/contacts';

export default api({
  GET(req, res, user) {
    const { q = '', limit, offset } = req.query;
    res.json(listContacts(user.id, { q: String(q), limit, offset }));
  },
  POST(req, res, user) {
    res.status(201).json({ id: createContact(user.id, req.body) });
  },
});
