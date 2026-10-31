import { api, appUrl } from '../../lib/http';

// Served at /robots.txt via a rewrite in next.config.mjs.
function robots(req, res) {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', process.env.APP_URL ? 'public, max-age=3600' : 'private, max-age=0'); // host comes from the request otherwise
  res.send(['User-agent: *', 'Allow: /', 'Disallow: /api/', 'Disallow: /app', 'Disallow: /sign/',
    'Disallow: /login', 'Disallow: /signup', '', `Sitemap: ${appUrl(req)}/sitemap.xml`, ''].join('\n'));
}

export default api({ GET: robots, HEAD: robots }, { auth: false });
