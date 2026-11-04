import { api, appUrl, csvBulkRows, fail, readRaw } from '../../../../lib/http';
import { bulkSend, copyDocument, ownedDocument, remind, sendDocument, setPublicLink, shareDocument, voidDocument } from '../../../../lib/documents';
import { moveDocument } from '../../../../lib/folders';
import { rateLimit } from '../../../../lib/auth';

// Parsed here (not by Next) so bulk can take text/csv; JSON bodies keep their 1 MB limit.
export const config = { api: { bodyParser: false } };

async function readBody(req) {
  const text = (await readRaw(req, 1048576)).toString('utf8');
  const type = String(req.headers['content-type'] || '');
  if (/^text\/csv\b/i.test(type)) return text;
  if (!text.trim()) return {};
  if (!/^application\/json\b/i.test(type)) fail(415, 'Send JSON or CSV');
  try { return JSON.parse(text); } catch { fail(400, 'Invalid JSON'); }
}

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
  move(req, res, user, full) {
    moveDocument(full, req.body?.folderId ?? null);
    res.json({ ok: true });
  },
  async bulk(req, res, user, full) {
    const wait = rateLimit(`bulk:${user.id}`, 10, 36e5);
    if (wait) {
      res.setHeader('Retry-After', String(wait));
      fail(429, 'Too many bulk sends. Try again later.');
    }
    let rows = req.body?.rows;
    if (typeof req.body === 'string') {
      if (!full.doc.is_template) fail(409, 'Bulk send starts from a template');
      rows = csvBulkRows(req.body, full.recipients.length);
    }
    res.status(201).json(await bulkSend(full, user, req, appUrl(req), rows, { requestId: req.headers['idempotency-key'] }));
  },
  public(req, res, user, full) {
    res.json(setPublicLink(full, user, Boolean(req.body?.enabled), req));
  },
  share(req, res, user, full) {
    if (typeof req.body?.shared !== 'boolean') fail(400, 'Send shared: true or false');
    res.json(shareDocument(full, user, req.body.shared, req));
  },
};

// Access mode per action (see ownedDocument). copy and bulk need only read on a template; copying a non-template needs write.
const modes = { send: 'write', void: 'write', remind: 'write', copy: 'template', bulk: 'read', move: 'own', public: 'own', share: 'own' };

export default api({
  async POST(req, res, user) {
    const action = Object.hasOwn(actions, req.query.action) && actions[req.query.action];
    if (!action) fail(404, 'Unknown action');
    req.body = await readBody(req);
    const mode = modes[req.query.action];
    let full = ownedDocument(req.query.id, user.id, mode === 'template' ? 'read' : mode);
    if (mode === 'template' && !full.doc.is_template) full = ownedDocument(req.query.id, user.id, 'write');
    await action(req, res, user, full);
  },
}, { apiKey: true });
