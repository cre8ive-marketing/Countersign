import { api } from '../../../../lib/http';
import { deleteDocument, ownedDocument, publicRecipient, publicUrlFor, saveDraft } from '../../../../lib/documents';

export default api({
  // Owner view (session or API key). Session callers get signing tokens (the document page uses them); API-key callers don't.
  GET(req, res, user) {
    const { doc, recipients, fields } = ownedDocument(req.query.id, user.id);
    const { public_token_hash, public_token_enc, ...rest } = doc;
    res.setHeader('Cache-Control', 'private, no-store');
    res.json({ doc: { ...rest }, recipients: recipients.map((r) => publicRecipient(r, !user.apiKeyId)), fields, publicUrl: publicUrlFor(doc) });
  },
  PUT(req, res, user) {
    const full = saveDraft(ownedDocument(req.query.id, user.id), req.body ?? {});
    res.json({ recipients: full.recipients, fields: full.fields });
  },
  DELETE(req, res, user) {
    deleteDocument(ownedDocument(req.query.id, user.id));
    res.json({ ok: true });
  },
}, { apiKey: true });
