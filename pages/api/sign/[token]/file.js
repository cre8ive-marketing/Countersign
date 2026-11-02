import { api, fail, sendPdfBytes } from '../../../../lib/http';
import { readVerified, signerByToken, signerVerified } from '../../../../lib/documents';

export default api({
  GET(req, res) {
    const found = signerByToken(req.query.token, req);
    const { recipient: r, doc } = found;
    if (!signerVerified(found, req)) fail(403, 'Verify your email first');
    if (doc.status === 'completed') return sendPdfBytes(res, readVerified(doc, 'signed'), `${doc.title} (signed)`, req.query.download === '1');
    if (doc.status !== 'sent' || r.status === 'pending') fail(403, 'This document is not available to you right now');
    sendPdfBytes(res, readVerified(doc, 'original'), doc.title, false);
  },
}, { auth: false });
