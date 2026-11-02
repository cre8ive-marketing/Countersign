import { api, fail } from '../../lib/http';
import { checkSignaturePng } from '../../lib/documents';
import { SIGNATURE_KINDS, deleteSignature, saveSignature, savedSignatures } from '../../lib/signatures';

const kindOf = (v) => (SIGNATURE_KINDS.includes(v) ? v : fail(400, 'Choose signature or initials'));

export default api({
  GET(req, res, user) {
    res.setHeader('Cache-Control', 'private, no-store');
    res.json(savedSignatures(user.id));
  },
  async PUT(req, res, user) {
    const kind = kindOf(req.body?.kind);
    await checkSignaturePng(req.body?.value);
    saveSignature(user.id, kind, req.body.value);
    res.json({ ok: true });
  },
  DELETE(req, res, user) {
    deleteSignature(user.id, kindOf(req.query.kind));
    res.json({ ok: true });
  },
});
