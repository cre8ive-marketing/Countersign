import fs from 'node:fs';
import { getUser } from './auth.js';
import { fileAad, readDecrypted } from './crypto.js';

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export const fail = (status, message) => { throw new HttpError(status, message); };

// Wraps an API route: method dispatch, same-origin check on writes, optional auth, JSON errors.
export function api(handlers, { auth = true } = {}) {
  return async (req, res) => {
    try {
      const handler = handlers[req.method];
      if (!handler) fail(405, 'Method not allowed');
      if (req.method !== 'GET' && req.method !== 'HEAD') checkOrigin(req);
      const user = auth ? getUser(req) : null;
      if (auth && !user) fail(401, 'Sign in required');
      await handler(req, res, user);
    } catch (e) {
      if (!(e instanceof HttpError)) console.error(e);
      if (!res.headersSent) res.status(e.status || 500).json({ error: e.status ? e.message : 'Something went wrong' });
    }
  };
}

// Forwarded headers are client-controlled unless a trusted proxy sets them (TRUST_PROXY=true).
// Takes the rightmost value: the one appended by the single trusted proxy in front of us.
const forwarded = (req, name) => (process.env.TRUST_PROXY === 'true' ? req.headers[name]?.split(',').pop().trim() || null : null);
const requestHost = (req) => forwarded(req, 'x-forwarded-host') || req.headers.host;

function checkOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return; // non-browser clients
  let originHost;
  try { originHost = new URL(origin).host; } catch { fail(403, 'Cross-origin request blocked'); } // e.g. "Origin: null"
  if (originHost !== requestHost(req)) fail(403, 'Cross-origin request blocked');
}

export function clientInfo(req) {
  return { ip: forwarded(req, 'x-forwarded-for') || req.socket?.remoteAddress || null, userAgent: req.headers['user-agent'] || null };
}

export function appUrl(req) {
  if (process.env.APP_URL) return process.env.APP_URL.replace(/\/$/, '');
  const proto = forwarded(req, 'x-forwarded-proto') === 'https' ? 'https' : 'http';
  return `${proto}://${requestHost(req)}`;
}

export const str = (v, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
export const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export async function readRaw(req, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) fail(413, `File is larger than ${Math.round(limit / 1048576)} MB`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

// `path` must be a stored "<id>.<kind>.pdf"; the AAD is derived from its name. Decryption failure throws (500), never sends garbage.
export function sendPdf(res, path, name, download) {
  if (!fs.existsSync(path)) fail(404, 'File not found');
  sendPdfBytes(res, readDecrypted(path, fileAad(path)), name, download);
}

// Sends already-verified plaintext PDF bytes (see readVerified in lib/documents.js).
export function sendPdfBytes(res, bytes, name, download) {
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Length', bytes.length);
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('Content-Disposition', `${download ? 'attachment' : 'inline'}; filename*=UTF-8''${encodeURIComponent(name)}.pdf`);
  res.end(bytes);
}
