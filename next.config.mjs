const prod = process.env.NODE_ENV === 'production';

// Full policy is Report-Only until the sign flow (pdf.js worker, signature pad) is verified in a browser.
// Production only: `next dev` needs 'unsafe-eval'.
const CSP_REPORT_ONLY = [
  "default-src 'self'", "script-src 'self'", "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:", "font-src 'self'", "worker-src 'self' blob:",
  "connect-src 'self'", "frame-src 'self'",
].join('; ');

/** @type {import('next').NextConfig} */
export default {
  output: 'standalone',
  poweredByHeader: false,
  async rewrites() {
    return [
      { source: '/robots.txt', destination: '/api/robots' },
      { source: '/sitemap.xml', destination: '/api/sitemap' },
    ];
  },
  async headers() {
    return [{
      source: '/:path*',
      headers: [
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'Referrer-Policy', value: 'same-origin' },
        { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
        { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
        { key: 'Content-Security-Policy', value: "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'" },
        ...(prod ? [{ key: 'Content-Security-Policy-Report-Only', value: CSP_REPORT_ONLY }] : []),
      ],
    }];
  },
};
