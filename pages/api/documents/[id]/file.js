import { api, fail, sendPdfBytes } from '../../../../lib/http';
import { ownedDocument, readVerified } from '../../../../lib/documents';

export default api({
  GET(req, res, user) {
    const { doc } = ownedDocument(req.query.id, user.id, 'read');
    const signed = req.query.kind === 'signed';
    if (signed && doc.status !== 'completed') fail(404, 'Not signed yet');
    const kind = signed ? 'signed' : 'original';
    sendPdfBytes(res, readVerified(doc, kind), signed ? `${doc.title} (signed)` : doc.title, req.query.download === '1');
  },
}, { apiKey: true });
