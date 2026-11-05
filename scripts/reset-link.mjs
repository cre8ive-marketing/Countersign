// Prints a one-hour, single-use password reset link, for servers without email. Run it where the server runs:
//   node scripts/reset-link.mjs you@example.com
//   docker compose exec countersign node scripts/reset-link.mjs you@example.com
// Uses only Node built-ins: the Docker image holds this file but not the app's source.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const email = process.argv[2];
if (!email) {
  console.error('Usage: node scripts/reset-link.mjs <email>');
  process.exit(2);
}
const file = path.join(process.env.DATA_DIR || 'data', 'countersign.db');
if (!fs.existsSync(file)) { // opening it would create an empty database
  console.error(`No database at ${file}. Set DATA_DIR to the server's data folder.`);
  process.exit(1);
}
const db = new DatabaseSync(file);
db.exec('PRAGMA busy_timeout = 5000');
const user = db.prepare('SELECT id, email FROM users WHERE email = ?').get(email);
if (!user) {
  console.error('No account has that email.');
  process.exit(1);
}
const token = crypto.randomBytes(24).toString('base64url');
const t = new Date();
db.prepare('INSERT INTO password_resets (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)')
  .run(crypto.createHash('sha256').update(token).digest('hex'), user.id, new Date(t.getTime() + 36e5).toISOString(), t.toISOString());
db.prepare("INSERT INTO security_events (at, type, user_id, email, ip, user_agent, detail) VALUES (?, 'password_reset_request', ?, ?, NULL, NULL, 'link made on the server')")
  .run(t.toISOString(), user.id, user.email);
const base = (process.env.APP_URL || '').replace(/\/$/, '');
console.log(`${base}/reset#${token}`);
if (!base) console.error('APP_URL is not set: open this path on your server\'s address.');
