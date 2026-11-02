import { api, clientInfo, fail } from '../../lib/http';
import { verifyThrottle } from '../../lib/auth';
import db from '../../lib/db';

// Public fingerprint lookup. A completed signed copy reveals title, completion date and signer names (the holder of
// that exact file already sees them); an original reveals only that it matched. Deleted documents are gone from the table.
export default api({
  GET(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    const wait = verifyThrottle(clientInfo(req).ip);
    if (wait) {
      res.setHeader('Retry-After', String(wait));
      fail(429, 'Too many checks. Try again later.');
    }
    const sha = typeof req.query.sha256 === 'string' ? req.query.sha256.trim().toLowerCase() : '';
    if (!/^[0-9a-f]{64}$/.test(sha)) fail(400, 'Enter a SHA-256 hash');
    const signed = db.prepare("SELECT id, title, completed_at FROM documents WHERE signed_sha256 = ? AND status = 'completed' ORDER BY completed_at LIMIT 1").get(sha);
    if (signed) {
      const signers = db.prepare("SELECT name, signed_at AS signedAt FROM recipients WHERE document_id = ? AND role = 'signer' AND status = 'signed' ORDER BY routing_order, position")
        .all(signed.id);
      return res.json({ match: 'signed', title: signed.title, completedAt: signed.completed_at, signers });
    }
    const original = db.prepare('SELECT 1 FROM documents WHERE original_sha256 = ? AND is_template = 0 LIMIT 1').get(sha);
    res.json(original ? { match: 'original' } : { match: null });
  },
}, { auth: false });
