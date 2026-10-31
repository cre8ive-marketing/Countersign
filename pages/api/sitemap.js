import { api, appUrl } from '../../lib/http';

// Must match the public marketing pages in pages/**; update when one is added or removed.
const PATHS = ['/', '/product', '/use-cases', '/self-host', '/security'];

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// Served at /sitemap.xml via a rewrite in next.config.mjs.
function sitemap(req, res) {
  const base = appUrl(req);
  res.setHeader('Content-Type', 'application/xml; charset=utf-8');
  res.setHeader('Cache-Control', process.env.APP_URL ? 'public, max-age=3600' : 'private, max-age=0'); // host comes from the request otherwise
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${PATHS.map((p) => `  <url><loc>${esc(base + (p === '/' ? '/' : p))}</loc></url>`).join('\n')}
</urlset>
`);
}

export default api({ GET: sitemap, HEAD: sitemap }, { auth: false });
