// Self-check for lib/crypto.js and the legacy-data migration in lib/db.js. Run: node scripts/crypto-selfcheck.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-crypto-'));
process.env.DATA_DIR = dir;
delete process.env.ENCRYPTION_KEY;

// Legacy plaintext data, created before the app opens the DB.
const files = path.join(dir, 'files');
fs.mkdirSync(files, { recursive: true });
const pdf = Buffer.from('%PDF-1.7 legacy');
fs.writeFileSync(path.join(files, 'doc1.original.pdf'), pdf);
fs.writeFileSync(path.join(files, 'doc2.signed.pdf.tmp'), 'junk');
const raw = new DatabaseSync(path.join(dir, 'countersign.db'));
raw.exec('CREATE TABLE fields (id TEXT PRIMARY KEY, document_id TEXT NOT NULL, recipient_id TEXT NOT NULL, type TEXT NOT NULL, page INTEGER NOT NULL, x REAL NOT NULL, y REAL NOT NULL, w REAL NOT NULL, h REAL NOT NULL, required INTEGER NOT NULL DEFAULT 1, label TEXT NOT NULL DEFAULT \'\', value TEXT)');
raw.prepare("INSERT INTO fields (id, document_id, recipient_id, type, page, x, y, w, h, value) VALUES (?, 'd', 'r', 'text', 1, 0, 0, 1, 1, ?)").run('f1', 'hello');
raw.prepare("INSERT INTO fields (id, document_id, recipient_id, type, page, x, y, w, h, value) VALUES (?, 'd', 'r', 'text', 1, 0, 0, 1, 1, NULL)").run('f2');
raw.close();

const c = await import('../lib/crypto.js');
const { default: db } = await import('../lib/db.js');

assert.ok(!fs.existsSync(path.join(dir, 'encryption.key')), 'key must not be created at import');

// Round trip, layout, strict decrypt (no legacy passthrough).
const data = Buffer.from('secret bytes');
const enc = c.encryptBuffer(data, 'file:x.original');
assert.equal(enc.subarray(0, 4).toString(), 'CSE1');
assert.equal(enc.length, 4 + 12 + 16 + data.length);
assert.deepEqual(c.decryptBuffer(enc, 'file:x.original'), data);
assert.ok(/^[0-9a-f]{64}\n$/.test(fs.readFileSync(path.join(dir, 'encryption.key'), 'utf8')), 'key file is 64 hex');
assert.throws(() => c.decryptBuffer(pdf, 'any'), /not encrypted/, 'plaintext buffer is rejected');
const t = c.encryptText('héllo', 'field:a');
assert.ok(t.startsWith('enc:v1:'));
assert.equal(c.decryptText(t, 'field:a'), 'héllo');
assert.throws(() => c.decryptText('plain', 'field:a'), /not encrypted/, 'plaintext value is rejected');
assert.throws(() => c.decryptText('', 'field:a'), /not encrypted/);
assert.equal(c.decryptText(null, 'field:a'), null);
assert.equal(c.decryptText(undefined, 'field:a'), undefined);

// Wrong AAD and tampering throw.
assert.throws(() => c.decryptBuffer(enc, 'file:y.original'));
assert.throws(() => c.decryptText(t, 'field:b'));
for (const i of [5, 20, enc.length - 1]) {
  const bad = Buffer.from(enc); bad[i] ^= 1;
  assert.throws(() => c.decryptBuffer(bad, 'file:x.original'), `tamper at byte ${i}`);
}
assert.throws(() => c.decryptBuffer(Buffer.from('CSE1short'), 'a'), 'truncated');

// writeEncrypted / readDecrypted / fileAad.
const out = path.join(dir, 'w.signed.pdf');
c.writeEncrypted(out, data, c.fileAad(out));
assert.ok(!fs.existsSync(out + '.tmp'));
assert.deepEqual(c.readDecrypted(out, 'file:w.signed'), data);
assert.throws(() => c.fileAad('/x/notes.txt'));

// Migration runs on first DB access and is idempotent.
const row = () => db.prepare("SELECT value FROM fields WHERE id = 'f1'").get().value;
const file = path.join(files, 'doc1.original.pdf');
assert.ok(row().startsWith('enc:v1:'));
assert.equal(c.decryptText(row(), 'field:f1'), 'hello');
assert.equal(db.prepare("SELECT value FROM fields WHERE id = 'f2'").get().value, null);
assert.deepEqual(c.readDecrypted(file, 'file:doc1.original'), pdf);
assert.equal(fs.readFileSync(path.join(files, 'doc2.signed.pdf.tmp'), 'utf8'), 'junk', '.tmp leftovers skipped');
const before = [row(), fs.readFileSync(file)];
globalThis.__countersignDb.close();
globalThis.__countersignDb = undefined;
assert.equal(row(), before[0], 'second open leaves fields alone');
assert.deepEqual(fs.readFileSync(file), before[1], 'second open leaves files alone');
const meta = (k) => db.prepare('SELECT value FROM meta WHERE key = ?').get(k)?.value;
assert.equal(meta('encryption_migrated'), '1');
assert.equal(meta('key_check'), c.keyCheck());

// After the one-time migration, planted plaintext is never laundered into ciphertext.
const planted = path.join(files, 'doc3.original.pdf');
fs.writeFileSync(planted, pdf);
db.prepare("UPDATE fields SET value = 'forged' WHERE id = 'f2'").run();
globalThis.__countersignDb.close();
globalThis.__countersignDb = undefined;
assert.deepEqual(fs.readFileSync(planted), pdf, 'planted plaintext file left as is');
assert.equal(db.prepare("SELECT value FROM fields WHERE id = 'f2'").get().value, 'forged', 'planted plaintext value left as is');
assert.throws(() => c.readDecrypted(planted, 'file:doc3.original'), /not encrypted/, 'and fails at read');
// N3: even with both meta markers deleted, existing ciphertext files block the legacy pass.
db.exec("DELETE FROM meta WHERE key IN ('encryption_migrated', 'key_check')");
globalThis.__countersignDb.close();
globalThis.__countersignDb = undefined;
assert.deepEqual(fs.readFileSync(planted), pdf, 'deleting the markers does not get a planted file re-encrypted');
assert.equal(db.prepare("SELECT value FROM fields WHERE id = 'f2'").get().value, 'forged');

// A different key fails fast at DB open.
const opener = `const { default: db } = await import(${JSON.stringify(pathToFileURL(path.resolve('lib/db.js')).href)}); db.prepare('SELECT 1').get();`;
const wrong = spawnSync(process.execPath, ['--input-type=module', '-e', opener], { env: { ...process.env, DATA_DIR: dir, ENCRYPTION_KEY: 'ef'.repeat(32) }, encoding: 'utf8' });
assert.notEqual(wrong.status, 0);
assert.match(wrong.stderr, /ENCRYPTION_KEY does not match this data/);
const right = spawnSync(process.execPath, ['--input-type=module', '-e', opener], { env: { ...process.env, DATA_DIR: dir, ENCRYPTION_KEY: fs.readFileSync(path.join(dir, 'encryption.key'), 'utf8').trim() }, encoding: 'utf8' });
assert.equal(right.status, 0, right.stderr);

// The key-file warning is printed once per process.
const warns = [];
const warn = console.warn;
console.warn = (m) => warns.push(m);
const again = await import('../lib/crypto.js?again');
again.encryptBuffer(data, 'a');
console.warn = warn;
assert.equal(warns.length, 0, 'no second key-file warning');

// Key from ENCRYPTION_KEY: bad values throw, base64 and hex accepted (fresh module instance each time).
const fresh = async (k) => { process.env.ENCRYPTION_KEY = k; return import(`../lib/crypto.js?k=${encodeURIComponent(k)}`); };
for (const k of ['nothex', 'ab'.repeat(31), Buffer.alloc(16).toString('base64'), 'zz'.repeat(32)]) {
  const m = await fresh(k);
  assert.throws(() => m.encryptBuffer(data, 'a'), /ENCRYPTION_KEY must be 32 bytes/, `rejects ${k}`);
}
const hex = 'ab'.repeat(32);
const mh = await fresh(hex);
const mb = await fresh(Buffer.from(hex, 'hex').toString('base64'));
assert.deepEqual(mb.decryptBuffer(mh.encryptBuffer(data, 'a'), 'a'), data, 'hex and base64 forms are the same key');
assert.throws(() => mh.decryptBuffer(enc, 'file:x.original'), 'wrong key throws');

globalThis.__countersignDb.close();
fs.rmSync(dir, { recursive: true, force: true });
console.log('crypto self-check: all assertions passed');
