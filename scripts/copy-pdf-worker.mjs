// pdf.js renders in a web worker; serve it from /public so no bundler config is needed.
import fs from 'node:fs';

fs.mkdirSync('public', { recursive: true });
fs.copyFileSync('node_modules/pdfjs-dist/build/pdf.worker.min.mjs', 'public/pdf.worker.min.mjs');
