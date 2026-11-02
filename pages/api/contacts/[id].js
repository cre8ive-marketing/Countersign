import { api } from '../../../lib/http';
import { deleteContact, updateContact } from '../../../lib/contacts';

export default api({
  PUT(req, res, user) {
    updateContact(user.id, req.query.id, req.body);
    res.json({ ok: true });
  },
  DELETE(req, res, user) {
    deleteContact(user.id, req.query.id);
    res.json({ ok: true });
  },
});
