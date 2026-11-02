import { api, appUrl, fail } from '../../../../lib/http';
import { copyDocument, ownedDocument, remind, sendDocument, voidDocument } from '../../../../lib/documents';

const actions = {
  async send(req, res, user, full) {
    const out = await sendDocument(full, user, req, appUrl(req), { selfSign: Boolean(req.body?.selfSign) });
    res.json(out?.signUrl ? { ok: true, signUrl: out.signUrl } : { ok: true });
  },
  void(req, res, user, full) {
    voidDocument(full, user, req.body?.reason, req);
    res.json({ ok: true });
  },
  async remind(req, res, user, full) {
    await remind(full, req.body?.recipientId, user, req, appUrl(req));
    res.json({ ok: true });
  },
  copy(req, res, user, full) {
    res.status(201).json({ id: copyDocument(full, user, { asTemplate: Boolean(req.body?.asTemplate) }) });
  },
};

export default api({
  async POST(req, res, user) {
    const action = actions[req.query.action];
    if (!action) fail(404, 'Unknown action');
    await action(req, res, user, ownedDocument(req.query.id, user.id));
  },
});
