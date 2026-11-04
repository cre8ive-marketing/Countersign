import { api } from '../../../../lib/http';
import { deleteDocument, ownedDocument, publicRecipient, publicUrlFor, saveDraft } from '../../../../lib/documents';

const canWrite = (id, userId) => { try { ownedDocument(id, userId, 'write'); return true; } catch { return false; } };

export default api({
  // Read view (session or API key). Signing tokens only go to session callers who can also write: team members who can only read never get them.
  GET(req, res, user) {
    const { doc, recipients, fields } = ownedDocument(req.query.id, user.id, 'read');
    const { public_token_hash, public_token_enc, ...rest } = doc;
    const withTokens = !user.apiKeyId && canWrite(req.query.id, user.id);
    res.setHeader('Cache-Control', 'private, no-store');
    res.json({ doc: { ...rest }, recipients: recipients.map((r) => publicRecipient(r, withTokens)), fields, publicUrl: doc.owner_id === user.id && user.apiKeyScope !== 'read' ? publicUrlFor(doc) : null });
  },
  PUT(req, res, user) {
    const full = saveDraft(ownedDocument(req.query.id, user.id, 'write'), req.body ?? {});
    res.json({ recipients: full.recipients, fields: full.fields });
  },
  DELETE(req, res, user) {
    deleteDocument(ownedDocument(req.query.id, user.id, 'write'), user.id);
    res.json({ ok: true });
  },
}, { apiKey: true });
