import crypto from 'node:crypto';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import db, { newId, now } from './db.js';
import { decryptText, encryptText } from './crypto.js';
import { fail } from './http.js'; // circular with http.js; used only inside functions
import { mailEnabled, sendMail } from './mail.js';

export const EVENTS = ['document.sent', 'recipient.viewed', 'recipient.signed', 'recipient.declined', 'document.completed', 'document.declined', 'document.voided', 'document.expired'];
export const WEBHOOKS_MAX = 10;
const URL_MAX = 500;
const TIMEOUT_MS = 10_000;
const RETRY_MS = [1, 5, 30, 120, 360, 720].map((m) => m * 6e4); // wait after failed attempt n (1-based)
const MAX_ATTEMPTS = 7;
const DISABLE_AFTER = 20;
const BATCH = 50;
const LEASE_MS = 5 * 6e4; // a claimed delivery is invisible to other runs this long (well past TIMEOUT_MS)
const KEEP_DAYS = 30;

const allowPrivate = () => process.env.WEBHOOK_ALLOW_PRIVATE === 'true';
const allowHttp = () => process.env.WEBHOOK_ALLOW_HTTP === 'true';

// Not reachable from a webhook: loopback, private, link-local, CGNAT, "this network", multicast, reserved, ULA,
// IPv4-compatible and NAT64 forms. BlockList applies the IPv4 rules to IPv4-mapped IPv6 (::ffff:a.b.c.d) too.
const BLOCKED = new net.BlockList();
for (const [ip, bits] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4]]) BLOCKED.addSubnet(ip, bits, 'ipv4');
// shortcut: all of 64:ff9b::/96 (NAT64) is refused, including public targets; embed-check it if an IPv6-only DNS64 host needs webhooks.
// ::ffff:0:0:0/96 (SIIT), 2002::/16 (6to4), 2001::/32 (Teredo), 100::/64 (discard) embed or reach IPv4 we can't vet.
for (const [ip, bits] of [['::', 96], ['::ffff:0:0:0', 96], ['2002::', 16], ['2001::', 32], ['100::', 64], ['64:ff9b::', 96], ['64:ff9b:1::', 48], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]]) BLOCKED.addSubnet(ip, bits, 'ipv6');

export function blockedAddress(address) {
  const ip = String(address || '').replace(/^\[|\]$/g, '').split('%')[0];
  const family = net.isIP(ip);
  if (!family) return true;
  return BLOCKED.check(ip, family === 4 ? 'ipv4' : 'ipv6');
}

// dns.lookup that drops disallowed addresses, so the socket can only connect to an address that passed the check.
export function safeLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, all: true }, (err, list) => {
    if (err) return callback(err);
    const ok = allowPrivate() ? list : list.filter((a) => !blockedAddress(a.address));
    if (!ok.length) return callback(Object.assign(new Error('This address is not allowed'), { code: 'EADDRBLOCKED' }));
    if (options?.all) callback(null, ok);
    else callback(null, ok[0].address, ok[0].family);
  });
}

// t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>; the key is the whole whsec_... string.
export const signature = (secret, body, t = Math.floor(Date.now() / 1000)) =>
  `t=${t},v1=${crypto.createHmac('sha256', secret).update(`${t}.${body}`).digest('hex')}`;

export function checkUrl(v) {
  const raw = typeof v === 'string' ? v.trim() : '';
  if (!raw) fail(400, 'Enter a URL');
  if (raw.length > URL_MAX) fail(400, `Use a URL of at most ${URL_MAX} characters`);
  let u;
  try { u = new URL(raw); } catch { fail(400, 'Enter a valid URL'); }
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && allowHttp())) fail(400, allowHttp() ? 'Use an http:// or https:// URL' : 'Use an https:// URL');
  if (u.username || u.password) fail(400, 'Remove the user name and password from the URL');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (!host) fail(400, 'Enter a valid URL');
  if (net.isIP(host) && blockedAddress(host) && !allowPrivate()) fail(400, 'This address is not allowed');
  return u.href;
}

function checkEvents(v) {
  if (!Array.isArray(v) || !v.length) fail(400, 'Choose at least one event');
  if (v.some((e) => !EVENTS.includes(e))) fail(400, 'Unknown event');
  return [...new Set(v)];
}

const shape = (w) => ({ id: w.id, url: w.url, events: JSON.parse(w.events), active: Boolean(w.active), failureCount: w.failure_count, createdAt: w.created_at });

export const listWebhooks = (ownerId) =>
  db.prepare('SELECT * FROM webhooks WHERE owner_id = ? ORDER BY created_at').all(ownerId).map(shape);

function ownedWebhook(ownerId, id) {
  const w = db.prepare('SELECT * FROM webhooks WHERE id = ? AND owner_id = ?').get(String(id), ownerId);
  if (!w) fail(404, 'Webhook not found');
  return w;
}

const newSecret = () => `whsec_${crypto.randomBytes(32).toString('base64url')}`;

export function createWebhook(ownerId, input) {
  const url = checkUrl(input?.url);
  const events = checkEvents(input?.events);
  if (db.prepare('SELECT COUNT(*) AS n FROM webhooks WHERE owner_id = ?').get(ownerId).n >= WEBHOOKS_MAX) fail(409, `You can have up to ${WEBHOOKS_MAX} webhooks`);
  const id = newId();
  const secret = newSecret();
  const t = now();
  db.prepare('INSERT INTO webhooks (id, owner_id, url, secret_enc, events, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, ownerId, url, encryptText(secret, `webhook:${id}`), JSON.stringify(events), t, t);
  return { id, secret };
}

export function updateWebhook(ownerId, id, input = {}) {
  const w = ownedWebhook(ownerId, id);
  const url = input.url === undefined ? w.url : checkUrl(input.url);
  const events = input.events === undefined ? w.events : JSON.stringify(checkEvents(input.events));
  const active = input.active === undefined ? w.active : input.active ? 1 : 0;
  const failures = active && !w.active ? 0 : w.failure_count; // re-activating starts the count over
  db.prepare('UPDATE webhooks SET url = ?, events = ?, active = ?, failure_count = ?, updated_at = ? WHERE id = ?').run(url, events, active, failures, now(), w.id);
}

// The old secret stops working at once; deliveries still queued are signed with the new one.
export function rotateSecret(ownerId, id) {
  const w = ownedWebhook(ownerId, id);
  const secret = newSecret();
  db.prepare('UPDATE webhooks SET secret_enc = ?, updated_at = ? WHERE id = ?').run(encryptText(secret, `webhook:${w.id}`), now(), w.id);
  return { secret };
}

export function deleteWebhook(ownerId, id) {
  db.prepare('DELETE FROM webhooks WHERE id = ?').run(ownedWebhook(ownerId, id).id);
}

export function listDeliveries(ownerId, id) {
  const w = ownedWebhook(ownerId, id);
  return db.prepare('SELECT * FROM webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC, id LIMIT 50').all(w.id).map((d) => ({
    id: d.id, event: d.event, status: d.status, attempts: d.attempts, lastStatusCode: d.last_status_code,
    lastError: d.last_error, createdAt: d.created_at, deliveredAt: d.delivered_at,
  }));
}

// Only these keys ever leave the server, whatever the caller passes.
const pick = (o, keys) => Object.fromEntries(keys.map((k) => [k, o?.[k] ?? null]));
function payloadData(data) {
  const out = {};
  if (data?.document) out.document = pick(data.document, ['id', 'title', 'status']);
  if (data?.recipient) out.recipient = pick(data.recipient, ['id', 'name', 'email', 'role', 'status']);
  return out;
}

function queue(webhookId, event, data) {
  const id = newId();
  const t = now();
  const payload = JSON.stringify({ id, event, createdAt: t, data: payloadData(data) });
  db.prepare('INSERT INTO webhook_deliveries (id, webhook_id, event, payload, next_attempt_at, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, webhookId, event, payload, t, t);
}

// setImmediate: never runs delivery code inside the caller's transaction.
const kick = () => setImmediate(() => deliverDue().catch((e) => console.error('Webhook delivery failed:', e)));

// One delivery per active webhook of this owner subscribed to the event. Never throws.
export function emitEvent(ownerId, event, data) {
  try {
    const hooks = db.prepare('SELECT id, events FROM webhooks WHERE owner_id = ? AND active = 1').all(ownerId).filter((w) => JSON.parse(w.events).includes(event));
    for (const w of hooks) queue(w.id, event, data);
    if (hooks.length) kick();
  } catch (e) {
    console.error('Webhook event not queued:', e);
  }
}

// POST /api/webhooks/[id]/test
export function sendTest(ownerId, id) {
  const w = ownedWebhook(ownerId, id);
  queue(w.id, 'ping', null);
  kick();
}

// Resolves { status } or { error }; never rejects. No redirects, response body dropped.
export function post(url, headers, body) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (out) => { if (!done) { done = true; clearTimeout(timer); req.destroy(); resolve(out); } };
    const u = new URL(url);
    const host = u.hostname.replace(/^\[|\]$/g, '');
    // Literal IPs skip lookup(), so they are checked here.
    if (net.isIP(host) && blockedAddress(host) && !allowPrivate()) return resolve({ error: 'This address is not allowed' });
    const req = (u.protocol === 'https:' ? https : http).request(u, {
      method: 'POST', agent: false, lookup: safeLookup,
      headers: { ...headers, 'Content-Length': Buffer.byteLength(body) },
    }, (res) => finish({ status: res.statusCode }));
    const timer = setTimeout(() => finish({ error: 'Timed out after 10 s' }), TIMEOUT_MS);
    req.on('error', (e) => finish({ error: e.code === 'EADDRBLOCKED' ? 'This address is not allowed' : String(e.code || e.message).slice(0, 200) }));
    req.end(body);
  });
}

async function attempt(d) {
  const secret = decryptText(d.secret_enc, `webhook:${d.webhook_id}`);
  const out = await post(d.url, {
    'Content-Type': 'application/json', 'User-Agent': 'Countersign-Webhooks',
    'Countersign-Event': d.event, 'Countersign-Delivery': d.id, 'Countersign-Signature': signature(secret, d.payload),
  }, d.payload);
  const attempts = d.attempts + 1;
  const ok = out.status >= 200 && out.status < 300;
  const error = ok ? null : out.error || `HTTP ${out.status}`;
  if (ok) {
    db.prepare("UPDATE webhook_deliveries SET status = 'delivered', attempts = ?, last_status_code = ?, last_error = NULL, delivered_at = ?, next_attempt_at = NULL WHERE id = ?")
      .run(attempts, out.status, now(), d.id);
    db.prepare('UPDATE webhooks SET failure_count = 0 WHERE id = ?').run(d.webhook_id);
    return;
  }
  const failed = attempts >= MAX_ATTEMPTS;
  db.prepare('UPDATE webhook_deliveries SET status = ?, attempts = ?, last_status_code = ?, last_error = ?, next_attempt_at = ? WHERE id = ?')
    .run(failed ? 'failed' : 'pending', attempts, out.status ?? null, error, failed ? null : new Date(Date.now() + RETRY_MS[attempts - 1]).toISOString(), d.id);
  if (!failed) return;
  // failure_count counts deliveries that ran out of attempts.
  const w = db.prepare('UPDATE webhooks SET failure_count = failure_count + 1 WHERE id = ? RETURNING failure_count, active, owner_id, url').get(d.webhook_id);
  if (w?.active && w.failure_count >= DISABLE_AFTER) {
    db.prepare('UPDATE webhooks SET active = 0, updated_at = ? WHERE id = ?').run(now(), d.webhook_id);
    const owner = db.prepare('SELECT email FROM users WHERE id = ?').get(w.owner_id);
    if (owner && mailEnabled()) {
      await sendMail({
        to: owner.email, subject: 'A webhook was turned off', heading: 'A webhook was turned off',
        body: `${DISABLE_AFTER} deliveries to ${w.url} failed after every retry, so Countersign stopped sending to it. Fix the endpoint, then turn the webhook back on in Settings.`,
        actionLabel: 'Open settings', actionUrl: `${process.env.APP_URL.replace(/\/$/, '')}/app/settings`,
      });
    }
  }
}

// Every 60 s and after each emitEvent: up to 50 due deliveries of active webhooks. Each row is claimed with a
// conditional UPDATE (lease), so two runs or two processes never attempt the same delivery at once.
// In-process, runs are coalesced: one in flight; a kick during a run causes exactly one more pass afterwards.
// On globalThis: Next bundles this module separately into API routes and instrumentation, and they must share one run.
const run = (globalThis.__countersignWebhookRun ??= { running: null, again: false });
export function deliverDue() {
  if (run.running) { run.again = true; return run.running; }
  // A full batch means more may be due now, so keep going instead of waiting for the 60 s timer.
  run.running = (async () => { let full; do { run.again = false; full = (await runBatch()) === BATCH; } while (run.again || full); })().finally(() => { run.running = null; });
  return run.running;
}

async function runBatch() {
  const t = now();
  const due = db.prepare(`SELECT d.*, w.url, w.secret_enc FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id
    WHERE d.status = 'pending' AND d.next_attempt_at <= ? AND w.active = 1 ORDER BY d.next_attempt_at LIMIT ?`).all(t, BATCH);
  const lease = new Date(Date.now() + LEASE_MS).toISOString();
  const claim = db.prepare("UPDATE webhook_deliveries SET next_attempt_at = ? WHERE id = ? AND status = 'pending' AND next_attempt_at = ?");
  const mine = due.filter((d) => claim.run(lease, d.id, d.next_attempt_at).changes === 1);
  await Promise.all(mine.map((d) => attempt(d).catch((e) => console.error('Webhook delivery failed:', e))));
  return due.length;
}

// Hourly job.
export const purgeDeliveries = () =>
  db.prepare('DELETE FROM webhook_deliveries WHERE created_at < ?').run(new Date(Date.now() - KEEP_DAYS * 864e5).toISOString()).changes;
