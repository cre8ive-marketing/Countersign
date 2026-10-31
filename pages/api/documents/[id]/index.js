import { api } from '../../../../lib/http';
import { deleteDocument, ownedDocument, saveDraft } from '../../../../lib/documents';

export default api({
  PUT(req, res, user) {
    const full = saveDraft(ownedDocument(req.query.id, user.id), req.body ?? {});
    res.json({ recipients: full.recipients, fields: full.fields });
  },
  DELETE(req, res, user) {
    deleteDocument(ownedDocument(req.query.id, user.id));
    res.json({ ok: true });
  },
});
