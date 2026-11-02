// Self-check for the CSV parser and contact import (lib/contacts.js) and renderEmail (lib/mail.js).
// Run: node scripts/tier2-selfcheck.mjs   (uses a throwaway DATA_DIR and key)
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-tier2-'));
process.env.DATA_DIR = dir;
process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

const { parseCsv, importContacts, upsertContacts, listContacts, createContact } = await import('../lib/contacts.js');
const { renderEmail, EMAIL_DEFAULTS } = await import('../lib/mail.js');
const { default: db } = await import('../lib/db.js');
const { savedSignatures, saveSignature } = await import('../lib/signatures.js');

const status = (fn) => { try { fn(); } catch (e) { return e.status; } return 0; };

// CSV parsing (RFC 4180).
assert.deepEqual(parseCsv('a,b\r\nc,d\n', 10), [['a', 'b'], ['c', 'd']]);
assert.deepEqual(parseCsv('"x, ""y""",z', 10), [['x, "y"', 'z']]);
assert.deepEqual(parseCsv('"multi\nline",e\n\n\nlast,', 10), [['multi\nline', 'e'], ['last', '']]);
assert.deepEqual(parseCsv('﻿name,email', 10), [['name', 'email']]);
assert.deepEqual(parseCsv('""', 10), [['']]);
assert.deepEqual(parseCsv('', 10), []);
assert.equal(status(() => parseCsv('"open,x', 10)), 400);
assert.equal(status(() => parseCsv('a\nb\nc\n', 2)), 400);
assert.equal(parseCsv('a\n'.repeat(5000), 5000).length, 5000);

// Contacts.
const users = ['u1', 'u2'].map((id) => {
  db.prepare("INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, 'x', 'now')").run(id, `${id}@example.com`, id);
  return id;
});
assert.deepEqual(importContacts('u1', 'Ann,ann@example.com\nBad,not-an-email\n"Lee, Jr.",lee@example.com\n'), { added: 2, updated: 0, skipped: 1 });
assert.deepEqual(importContacts('u1', 'email,name\nANN@example.com,Ann B\nlee@example.com,"Lee, Jr."\nnew@example.com,New\n'), { added: 1, updated: 1, skipped: 1 });
assert.equal(status(() => importContacts('u1', 'a,a@example.com\n'.repeat(3), 2)), 400);
assert.deepEqual(upsertContacts('u2', [{ name: 'Ann', email: 'ann@example.com' }, { name: '', email: 'x@example.com' }]), { added: 1, updated: 0, skipped: 1 });
assert.equal(upsertContacts('u2', Array.from({ length: 80 }, (_, i) => ({ name: `n${i}`, email: `n${i}@example.com` }))).added, 50);
assert.equal(listContacts('u1').total, 3);
assert.equal(listContacts('u1', { q: 'ann' }).contacts[0].name, 'Ann B');
assert.equal(listContacts('u1', { q: '%' }).total, 0, 'LIKE wildcards are escaped');
assert.equal(listContacts('u2', { q: 'lee' }).total, 0, 'scoped to owner');
assert.equal(status(() => createContact('u1', { name: 'Dup', email: 'ann@EXAMPLE.com' })), 409);
assert.equal(status(() => createContact('u1', { name: '', email: 'z@example.com' })), 400);

// Row-limit message names the real limit even with a header row.
const tooMany = 'name,email\n' + 'a,a@example.com\n'.repeat(2001);
assert.throws(() => importContacts('u1', tooMany), { status: 400, message: 'The file has more than 2000 rows' });
assert.throws(() => importContacts('u1', 'a,a@example.com\n'.repeat(2001)), { message: 'The file has more than 2000 rows' });

// EMAIL rejects list/quote separators and whitespace, keeps normal addresses.
const { EMAIL } = await import('../lib/http.js');
for (const ok of ['a@example.com', 'first.last+tag@mail.sub.example.co.uk', "o'neil@example.org"]) assert.ok(EMAIL.test(ok), ok);
for (const bad of ['a,b@example.com', 'a;b@example.com', 'a<b@example.com', 'a>b@example.com', '"a"@example.com', 'a(b)@example.com',
  'a[b]@example.com', 'a\\b@example.com', 'a b@example.com', 'a@exa mple.com', 'a@example.com\n', 'a@b@example.com', 'a@example']) assert.ok(!EMAIL.test(bad), bad);
assert.equal(status(() => createContact('u1', { name: 'X', email: 'x@example.com, y@example.com' })), 400);

// 10,000 contacts per owner: create refuses, import and upsert stop at the cap.
const { CONTACTS_MAX } = await import('../lib/contacts.js');
const fill = db.prepare("INSERT INTO contacts (id, owner_id, name, email, created_at, updated_at) VALUES (?, 'u2', 'f', ?, 'now', 'now')");
const have = listContacts('u2').total;
for (let i = have; i < CONTACTS_MAX - 1; i++) fill.run(`f${i}`, `f${i}@fill.test`);
assert.deepEqual(importContacts('u2', 'A,cap1@example.com\nB,cap2@example.com\nAnn Z,ann@example.com\n'), { added: 1, updated: 1, skipped: 1 });
assert.equal(listContacts('u2').total, CONTACTS_MAX);
assert.throws(() => createContact('u2', { name: 'C', email: 'cap3@example.com' }), { status: 400, message: 'You have reached the limit of 10,000 contacts' });
assert.deepEqual(upsertContacts('u2', [{ name: 'D', email: 'cap4@example.com' }]), { added: 0, updated: 0, skipped: 1 });
assert.equal(listContacts('u2').total, CONTACTS_MAX);

// Verify throttle keys IPv6 on its /64; IPv4 and IPv4-mapped stay per address.
const { ipPrefix } = await import('../lib/auth.js');
assert.equal(ipPrefix('203.0.113.7'), '203.0.113.7');
assert.equal(ipPrefix('::ffff:203.0.113.7'), '::ffff:203.0.113.7');
assert.equal(ipPrefix(null), 'unknown');
assert.equal(ipPrefix('2001:db8:aa:bb:1:2:3:4'), '2001:db8:aa:bb::/64');
assert.equal(ipPrefix('2001:0db8:00aa:00bb:ffff::1'), '2001:db8:aa:bb::/64');
assert.equal(ipPrefix('2001:db8::1'), '2001:db8:0:0::/64');
assert.equal(ipPrefix('2001:db8::'), '2001:db8:0:0::/64');
assert.equal(ipPrefix('::1'), '0:0:0:0::/64');
assert.equal(ipPrefix('::'), '0:0:0:0::/64');
assert.equal(ipPrefix('fe80::1%eth0'), 'fe80:0:0:0::/64');
assert.equal(ipPrefix('1::2:3:4:5:6:7'), '1:0:2:3::/64');
assert.equal(ipPrefix('1::3:4:5:6:1.2.3.4'), '1:0:3:4::/64');

// renderEmail.
const vars = { sender_name: 'Sam', sender_email: 's@example.com', receiver_name: 'Rae', document_title: 'NDA', message: 'Please sign', expires_on: '' };
assert.deepEqual(renderEmail('u1', 'invite', vars), {
  subject: 'Sam sent you "NDA" to sign',
  body: 'NDA\n\n"Please sign"\n\nNo account needed. Review the document and sign in a couple of minutes.',
});
assert.equal(renderEmail('u1', 'invite', { ...vars, message: '' }).body, 'NDA\n\nNo account needed. Review the document and sign in a couple of minutes.');
assert.deepEqual(renderEmail('u1', 'completed', vars), { subject: 'Completed: NDA', body: 'NDA is complete. Download the signed copy with its certificate of completion.' });
db.prepare("INSERT INTO email_templates (user_id, kind, subject, body, updated_at) VALUES ('u1', 'invite', ?, ?, 'now')")
  .run('Hi {{receiver_name}} {{unknown}} {{document_title}}', 'From {{sender_email}} {{nope}} {{message}} until {{expires_on}}.');
const evil = renderEmail('u1', 'invite', { ...vars, document_title: 'A\r\nBcc: x@evil.test {{sender_name}}', expires_on: 'May 1, 2027' });
assert.equal(evil.subject, 'Hi Rae {{unknown}} A Bcc: x@evil.test {{sender_name}}', 'CR/LF stripped, unknown left, no re-expansion');
assert.equal(evil.body, 'From s@example.com {{nope}} Please sign until May 1, 2027.');
assert.equal(renderEmail('u1', 'invite', { ...vars, document_title: 'x'.repeat(500) }).subject.length, 200);
assert.equal(renderEmail('u2', 'invite', vars).subject, 'Sam sent you "NDA" to sign', 'other users keep defaults');
assert.ok(EMAIL_DEFAULTS.invite.body.includes('{{message_block}}'));

// Saved signatures are encrypted at rest.
const png = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
saveSignature('u1', 'initials', png);
assert.deepEqual(savedSignatures('u1'), { signature: null, initials: png });
assert.match(db.prepare('SELECT value FROM user_signatures').get().value, /^enc:v1:/);

db.close();
globalThis.__countersignDb = undefined;
fs.rmSync(dir, { recursive: true, force: true });
console.log('tier2 self-check passed');
