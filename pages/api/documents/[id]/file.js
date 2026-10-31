import { api, fail, sendPdf } from '../../../../lib/http';
import { filePath, ownedDocument } from '../../../../lib/documents';

export default api({
  GET(req, res, user) {
    const { doc } = ownedDocument(req.query.id, user.id);
    const signed = req.query.kind === 'signed';
    if (signed && doc.status !== 'completed') fail(404, 'Not signed yet');
    sendPdf(res, filePath(doc.id, signed ? 'signed' : 'original'), signed ? `${doc.title} (signed)` : doc.title, req.query.download === '1');
  },
});
