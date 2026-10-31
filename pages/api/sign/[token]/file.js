import { api, fail, sendPdf } from '../../../../lib/http';
import { filePath, recipientByToken } from '../../../../lib/documents';

export default api({
  GET(req, res) {
    const found = recipientByToken(req.query.token);
    if (!found) fail(404, 'Signing link not found');
    const { recipient: r, doc } = found;
    if (doc.status === 'completed') return sendPdf(res, filePath(doc.id, 'signed'), `${doc.title} (signed)`, req.query.download === '1');
    if (doc.status !== 'sent' || r.status === 'pending') fail(403, 'This document is not available to you right now');
    sendPdf(res, filePath(doc.id), doc.title, false);
  },
}, { auth: false });
