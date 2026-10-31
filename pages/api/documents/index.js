import { api, fail, readRaw } from '../../../lib/http';
import { createDocument } from '../../../lib/documents';
import { countPages } from '../../../lib/stamp';

export const config = { api: { bodyParser: false } };

const MAX_BYTES = 25 * 1048576;

export default api({
  async POST(req, res, user) {
    if (!String(req.headers['content-type']).startsWith('application/pdf')) fail(415, 'Upload a PDF file');
    const bytes = await readRaw(req, MAX_BYTES);
    if (bytes.subarray(0, 5).toString() !== '%PDF-') fail(400, 'This file is not a PDF');
    let pageCount;
    try {
      pageCount = await countPages(bytes);
    } catch {
      fail(400, 'This PDF could not be read. It may be password-protected or damaged.');
    }
    const name = decodeURIComponent(String(req.headers['x-file-name'] || 'Untitled.pdf')).slice(0, 200);
    const title = name.replace(/\.pdf$/i, '') || 'Untitled';
    const id = createDocument({ ownerId: user.id, ownerName: user.name, title, bytes, pageCount, isTemplate: req.headers['x-template'] === '1', req });
    res.status(201).json({ id });
  },
});
