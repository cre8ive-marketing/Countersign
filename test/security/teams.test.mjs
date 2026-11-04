// Tier 3 wave 2 security regressions (Raymond): teams. Access modes (own/write/read) on every document route and action,
// signing-token exposure (API and SSR), role escalation, invites (hash, expiry, single use, email match), invite sign-up on a
// closed server (including a concurrent race), API keys on team routes, CSRF, and XSS in team/member/inviter names.
// Run against FRESH disposable servers (explicit ENCRYPTION_KEY, SIGNUP_MAX_PER_HOUR=1000, no TRUST_PROXY, no SMTP):
//   Server A: ALLOW_SIGNUP=true
//   Server B (optional): ALLOW_SIGNUP=false, fresh DATA_DIR. The test signs up B's first account; when B already has
//   users it resets the first account's password in B's throwaway DB (needs DATA_DIR_CLOSED) and signs in with it.
//   BASE_URL=http://localhost:<A> DATA_DIR=<A's DATA_DIR> ENCRYPTION_KEY=<key> \
//   BASE_URL_CLOSED=http://localhost:<B> DATA_DIR_CLOSED=<B's DATA_DIR> [ENCRYPTION_KEY_CLOSED=<B's key, default ENCRYPTION_KEY>] \
//   node --test test/security/teams.test.mjs
// Without DATA_DIR/ENCRYPTION_KEY the at-rest checks skip; without BASE_URL_CLOSED the closed-signup checks skip; the TW2-1
// test also needs DATA_DIR_CLOSED (it plants a team owned by another account in B's DB).
// Expects the TW2 fix round: TW2-1 (first account only on a closed server), TW2-2 (invites revoked with their creator's role),
// TW2-3 (publicUrl to the owner only), TW2-4 (scrypt outside the write lock; code review only, not tested here).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';

const BASE = new URL(process.env.BASE_URL || 'http://localhost:3000');
const CLOSED = process.env.BASE_URL_CLOSED ? new URL(process.env.BASE_URL_CLOSED) : null;
const DATA_DIR = process.env.DATA_DIR;
const KEY = process.env.ENCRYPTION_KEY;
const needDb = !(DATA_DIR && KEY) && 'needs DATA_DIR and ENCRYPTION_KEY of server A';
const needClosed = !CLOSED && 'needs BASE_URL_CLOSED (a server with ALLOW_SIGNUP=false)';
const rnd = () => crypto.randomBytes(5).toString('hex');
const NOT_FOUND = 'Document not found';

const dbs = {};
const open = (dir) => {
  if (!dbs[dir]) { dbs[dir] = new DatabaseSync(path.join(dir, 'countersign.db')); dbs[dir].exec('PRAGMA busy_timeout = 5000'); }
  return dbs[dir];
};
const db = () => open(DATA_DIR);
const keyBytes = (k) => (/^[0-9a-fA-F]{64}$/.test(k.trim()) ? Buffer.from(k.trim(), 'hex') : Buffer.from(k.trim(), 'base64'));
const keyedHash = (info, data, k = KEY) => crypto.createHmac('sha256', Buffer.from(crypto.hkdfSync('sha256', keyBytes(k), Buffer.alloc(0), 'countersign-' + info, 32))).update(data).digest('hex');
const DIR_CLOSED = process.env.DATA_DIR_CLOSED;
const KEY_CLOSED = process.env.ENCRYPTION_KEY_CLOSED || KEY;
const needClosedDb = (needClosed || (!(DIR_CLOSED && KEY_CLOSED) && 'needs DATA_DIR_CLOSED and ENCRYPTION_KEY(_CLOSED) of server B'));
const scryptHash = (password) => { const salt = crypto.randomBytes(16); return `scrypt$${salt.toString('base64')}$${crypto.scryptSync(password, salt, 64).toString('base64')}`; };

function call(p, { method = 'GET', cookie, body, headers = {}, base = BASE } = {}) {
  const h = { ...headers };
  if (cookie) h.cookie = cookie;
  let b = body;
  if (b !== undefined && !Buffer.isBuffer(b) && typeof b !== 'string') { b = JSON.stringify(b); h['content-type'] ??= 'application/json'; }
  return new Promise((resolve, reject) => {
    const req = http.request({ host: base.hostname === 'localhost' ? '127.0.0.1' : base.hostname, port: base.port, path: p, method, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        let json; try { json = JSON.parse(buf.toString()); } catch {}
        resolve({ status: res.statusCode, headers: res.headers, json, text: buf.toString('utf8'), setCookie: res.headers['set-cookie'] || [] });
      });
    });
    req.on('error', reject);
    req.end(b);
  });
}
const bearer = (key) => ({ authorization: `Bearer ${key}` });
const props = (html) => JSON.parse(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s.exec(html)[1]).props.pageProps;
const cookieOf = (r) => r.setCookie.find((c) => c.startsWith('cs_session='))?.split(';')[0];

async function signup(base = BASE, name = 'TW2 User', email = `tw2-${rnd()}@example.com`) {
  const r = await call('/api/auth/signup', { method: 'POST', base, body: { name, email, password: `pw-${rnd()}-${rnd()}` } });
  assert.equal(r.status, 200, r.text);
  return { email, name, base, cookie: cookieOf(r) };
}
async function pdfBytes() {
  const pdf = await PDFDocument.create();
  pdf.addPage([612, 792]).drawText(`tw2 ${rnd()}`, { x: 50, y: 700 });
  return Buffer.from(await pdf.save({ useObjectStreams: false }));
}
const sigF = (rid) => ({ recipientId: rid, type: 'signature', page: 0, x: 0.1, y: 0.1, w: 0.3, h: 0.06 });
async function upload(o, template = false) {
  const up = await call('/api/documents', { method: 'POST', cookie: o.cookie, base: o.base, body: await pdfBytes(), headers: { 'content-type': 'application/pdf', 'x-file-name': 'TW2.pdf', ...(template && { 'x-template': '1' }) } });
  assert.equal(up.status, 201, up.text);
  return up.json.id;
}
const save = (o, id, body) => call(`/api/documents/${id}`, { method: 'PUT', cookie: o.cookie, base: o.base, body: { title: 'TW2', ...body } });
const action = (o, id, name, body = {}, headers = {}) => call(`/api/documents/${id}/${name}`, { method: 'POST', cookie: o.cookie, base: o.base, body, headers });
async function draft(o) {
  const id = await upload(o);
  const put = await save(o, id, { recipients: [{ id: 'a', name: 'Signer One', email: `s-${rnd()}@example.com`, role: 'signer' }], fields: [sigF('a')] });
  assert.equal(put.status, 200, put.text);
  return id;
}
async function sent(o) {
  const id = await draft(o);
  const s = await action(o, id, 'send');
  assert.equal(s.status, 200, s.text);
  return id;
}
async function template(o) {
  const id = await upload(o, true);
  const put = await save(o, id, { title: 'TW2 template', recipients: [{ id: 'r0', name: 'Role 1', email: '', role: 'signer', routingOrder: 1 }], fields: [sigF('r0')] });
  assert.equal(put.status, 200, put.text);
  return id;
}
const tokenOf = (url) => url.split('/join/')[1];
async function invite(o, email, role = 'member') {
  const r = await call('/api/teams/invites', { method: 'POST', cookie: o.cookie, base: o.base, body: { email, role } });
  assert.equal(r.status, 201, r.text);
  return { id: r.json.id, token: tokenOf(r.json.url) };
}
const join = (o, token) => call('/api/teams/join', { method: 'POST', cookie: o.cookie, base: o.base, body: { token } });
async function createTeam(o, name = `Team ${rnd()}`) {
  const r = await call('/api/teams', { method: 'POST', cookie: o.cookie, base: o.base, body: { name } });
  assert.equal(r.status, 201, r.text);
  return r.json.id;
}
const team = async (o) => (await call('/api/teams', { cookie: o.cookie, base: o.base })).json;
// owner, admin, member and member2 in one team; outsider in no team; rival owns another team. Each user gets `.id`.
async function crew() {
  const owner = await signup(BASE, 'Owner'), admin = await signup(BASE, 'Admin'), member = await signup(BASE, 'Member');
  const member2 = await signup(BASE, 'Member Two'), outsider = await signup(BASE, 'Outsider'), rival = await signup(BASE, 'Rival');
  const teamId = await createTeam(owner);
  for (const [u, role] of [[admin, 'admin'], [member, 'member'], [member2, 'member']]) {
    assert.equal((await join(u, (await invite(owner, u.email, role)).token)).status, 200);
  }
  await createTeam(rival);
  const t = await team(owner);
  for (const u of [owner, admin, member, member2]) u.id = t.members.find((m) => m.email === u.email).userId;
  return { owner, admin, member, member2, outsider, rival, teamId };
}

// ---------- Access modes ----------

test('read mode: team members read team documents; outsiders, other teams and personal documents give 404', async () => {
  const c = await crew();
  const shared = await sent(c.member);
  const personal = await sent(c.member);
  assert.equal((await action(c.member, personal, 'share', { shared: false })).status, 200);
  for (const u of [c.owner, c.admin, c.member2]) {
    assert.equal((await call(`/api/documents/${shared}`, { cookie: u.cookie })).status, 200, u.name);
    const f = await call(`/api/documents/${shared}/file`, { cookie: u.cookie });
    assert.equal(f.status, 200, u.name);
    assert.match(f.headers['content-type'], /pdf/);
  }
  for (const u of [c.outsider, c.rival]) {
    for (const p of [`/api/documents/${shared}`, `/api/documents/${shared}/file`]) {
      const r = await call(p, { cookie: u.cookie });
      assert.deepEqual([r.status, r.json?.error], [404, NOT_FOUND], `${u.name} ${p}`);
    }
  }
  for (const u of [c.owner, c.admin, c.member2]) {
    const r = await call(`/api/documents/${personal}`, { cookie: u.cookie });
    assert.deepEqual([r.status, r.json?.error], [404, NOT_FOUND], `${u.name} personal`);
    assert.notEqual((await call(`/app/documents/${personal}`, { cookie: u.cookie })).status, 200, `${u.name} personal page`);
  }
  // Lists: outsiders never see team documents, scope=team without a team is empty, the folder filter is per user.
  const ids = async (u, q = '') => (await call(`/api/documents?limit=200${q}`, { cookie: u.cookie })).json.documents.map((d) => d.id);
  assert.ok((await ids(c.member2)).includes(shared));
  assert.ok(!(await ids(c.member2)).includes(personal));
  assert.ok(!(await ids(c.outsider)).includes(shared));
  assert.deepEqual(await ids(c.outsider, '&scope=team'), []);
  assert.ok(!(await ids(c.rival, '&scope=team')).includes(shared));
  const folder = (await call('/api/folders', { method: 'POST', cookie: c.member.cookie, body: { name: `f-${rnd()}` } })).json.id;
  assert.equal((await action(c.member, shared, 'move', { folderId: folder })).status, 200);
  assert.deepEqual(await ids(c.member2, `&folder=${folder}`), [], 'a teammate cannot filter by my folder');
  const row = (await call('/api/documents?limit=200', { cookie: c.member2.cookie })).json.documents.find((d) => d.id === shared);
  assert.deepEqual([row.folderId, row.ownerName, row.teamShared], [null, 'Member', true]);
});

test('write mode: members get 404 on PUT, DELETE, send, void, remind and non-template copy; admins and the owner may act', { skip: needDb }, async () => {
  const c = await crew();
  const d = await draft(c.member);
  const s = await sent(c.member);
  const probes = [
    ['PUT', `/api/documents/${d}`, { title: 'hijack' }], ['DELETE', `/api/documents/${d}`], ['POST', `/api/documents/${d}/send`, {}],
    ['POST', `/api/documents/${s}/void`, { reason: 'x' }], ['POST', `/api/documents/${s}/remind`, {}], ['POST', `/api/documents/${s}/copy`, {}],
  ];
  for (const u of [c.member2, c.outsider, c.rival]) {
    for (const [method, p, body] of probes) {
      const r = await call(p, { method, cookie: u.cookie, body });
      assert.deepEqual([r.status, r.json?.error], [404, NOT_FOUND], `${u.name} ${method} ${p}`);
    }
  }
  assert.equal(db().prepare('SELECT title FROM documents WHERE id = ?').get(d).title, 'TW2');
  assert.equal(db().prepare('SELECT status FROM documents WHERE id = ?').get(s).status, 'sent');
  // The admin acts on the member's documents; the audit names the admin.
  assert.equal((await save(c.admin, d, { title: 'by admin', recipients: [{ id: 'a', name: 'S', email: 's@example.com', role: 'signer' }], fields: [sigF('a')] })).status, 200);
  assert.equal((await action(c.admin, s, 'void', { reason: 'admin void' })).status, 200);
  assert.ok(db().prepare("SELECT 1 FROM events WHERE document_id = ? AND actor = 'Admin'").get(s), 'void event names the admin');
  const copy = await action(c.admin, s, 'copy');
  assert.equal(copy.status, 201);
  assert.equal(db().prepare('SELECT owner_id FROM documents WHERE id = ?').get(copy.json.id).owner_id, c.admin.id);
  assert.equal((await call(`/api/documents/${d}`, { method: 'DELETE', cookie: c.owner.cookie })).status, 200);
  assert.equal(db().prepare('SELECT deleted_by FROM audit_tombstones WHERE document_id = ?').get(d).deleted_by, c.owner.id);
});

test('own mode: move, public and share are owner-only, even for the team owner and admins', { skip: needDb }, async () => {
  const c = await crew();
  const tpl = await template(c.member);
  const folder = (await call('/api/folders', { method: 'POST', cookie: c.owner.cookie, body: { name: `f-${rnd()}` } })).json.id;
  for (const u of [c.owner, c.admin, c.member2, c.outsider]) {
    for (const [name, body] of [['move', { folderId: null }], ['move', { folderId: folder }], ['public', { enabled: true }], ['share', { shared: false }]]) {
      const r = await action(u, tpl, name, body);
      assert.deepEqual([r.status, r.json?.error], [404, NOT_FOUND], `${u.name} ${name}`);
    }
  }
  const row = db().prepare('SELECT team_id, public_enabled, folder_id FROM documents WHERE id = ?').get(tpl);
  assert.ok(row.team_id);
  assert.deepEqual([row.public_enabled, row.folder_id], [0, null]);
  // Share takes a boolean only; unshare and reshare work for the owner; sharing outside a team is refused.
  assert.equal((await action(c.member, tpl, 'share', { shared: 'yes' })).status, 400);
  assert.deepEqual((await action(c.member, tpl, 'share', { shared: false })).json, { teamShared: false });
  assert.equal((await call(`/api/documents/${tpl}`, { cookie: c.member2.cookie })).status, 404);
  assert.deepEqual((await action(c.member, tpl, 'share', { shared: true })).json, { teamShared: true });
  const solo = await signup();
  assert.equal((await action(solo, await upload(solo), 'share', { shared: true })).status, 409);
});

test('templates: members copy and bulk-send team templates (read); the copies are theirs; other teams get 404', { skip: needDb }, async () => {
  const c = await crew();
  const tpl = await template(c.owner);
  const copy = await action(c.member, tpl, 'copy');
  assert.equal(copy.status, 201, copy.text);
  const row = db().prepare('SELECT owner_id, team_id, folder_id FROM documents WHERE id = ?').get(copy.json.id);
  assert.deepEqual([row.owner_id, row.team_id, row.folder_id], [c.member.id, c.teamId, null]);
  const bulk = await action(c.member, tpl, 'bulk', { rows: [[{ name: 'X', email: `x-${rnd()}@example.com` }]] });
  assert.equal(bulk.status, 201, bulk.text);
  const owners = db().prepare('SELECT DISTINCT owner_id FROM documents WHERE bulk_id IS NOT NULL AND id <> ? AND created_at >= (SELECT created_at FROM documents WHERE id = ?) AND owner_id IN (?, ?)')
    .all(tpl, copy.json.id, c.member.id, c.owner.id).map((r) => r.owner_id);
  assert.deepEqual(owners, [c.member.id], 'bulk copies are owned by the member who sent them');
  for (const u of [c.outsider, c.rival]) {
    assert.equal((await action(u, tpl, 'copy')).status, 404);
    assert.equal((await action(u, tpl, 'bulk', { rows: [[{ name: 'X', email: 'x@example.com' }]] })).status, 404);
  }
  assert.equal((await save(c.member, tpl, { title: 'x' })).status, 404, 'a member cannot edit the team template');
});

// ---------- Signing links ----------

test('signing tokens: only session writers get them (API and document page SSR); readers and API keys never do', async () => {
  const c = await crew();
  const s = await sent(c.member);
  const token = (await call(`/api/documents/${s}`, { cookie: c.member.cookie })).json.recipients[0].token;
  assert.match(token, /^[A-Za-z0-9_-]{20,}$/);
  assert.equal((await call(`/api/documents/${s}`, { cookie: c.admin.cookie })).json.recipients[0].token, token, 'team admin (writer) gets the link');
  const readerView = await call(`/api/documents/${s}`, { cookie: c.member2.cookie });
  assert.equal(readerView.status, 200);
  assert.equal('token' in readerView.json.recipients[0], false);
  assert.equal(readerView.text.includes(token), false);
  for (const u of [c.member2, c.admin, c.member]) {
    const k = (await call('/api/api-keys', { method: 'POST', cookie: u.cookie, body: { name: 'k' } })).json.key;
    const r = await call(`/api/documents/${s}`, { headers: bearer(k) });
    assert.equal(r.status, 200);
    assert.equal(r.text.includes(token), false, `${u.name} API key`);
  }
  const page = async (u) => { const r = await call(`/app/documents/${s}`, { cookie: u.cookie }); assert.equal(r.status, 200); return r; };
  const readerPage = await page(c.member2);
  assert.equal(readerPage.text.includes(token), false, 'reader SSR has no signing link');
  assert.deepEqual([props(readerPage.text).canWrite, props(readerPage.text).isOwner], [false, false]);
  assert.equal(props((await page(c.admin)).text).recipients[0].token, token);
  // Removing the admin from the team ends their access at once.
  assert.equal((await call(`/api/teams/members/${c.admin.id}`, { method: 'DELETE', cookie: c.owner.cookie })).status, 200);
  assert.equal((await call(`/api/documents/${s}`, { cookie: c.admin.cookie })).status, 404);
});

test('TW2-3: GET /api/documents/[id] gives a template public link to its owner only; team writers, readers and their keys get null', async () => {
  const c = await crew();
  const tpl = await template(c.member);
  const url = (await action(c.member, tpl, 'public', { enabled: true })).json.url;
  assert.match(url, /^\/t\/[A-Za-z0-9_-]{43}$/);
  assert.equal((await call(`/api/documents/${tpl}`, { cookie: c.member.cookie })).json.publicUrl, url);
  const secret = url.slice(3);
  for (const u of [c.owner, c.admin, c.member2]) {
    const r = await call(`/api/documents/${tpl}`, { cookie: u.cookie });
    assert.equal(r.status, 200, u.name);
    assert.equal(r.json.publicUrl, null, `${u.name} session`);
    assert.equal(r.text.includes(secret), false, `${u.name} session body`);
    const k = (await call('/api/api-keys', { method: 'POST', cookie: u.cookie, body: { name: 'k' } })).json.key;
    const viaKey = await call(`/api/documents/${tpl}`, { headers: bearer(k) });
    assert.deepEqual([viaKey.status, viaKey.json.publicUrl, viaKey.text.includes(secret)], [200, null, false], `${u.name} API key`);
  }
});

// ---------- Roles ----------

test('roles: no escalation by admins or members; owner transfer keeps exactly one owner', { skip: needDb }, async () => {
  const c = await crew();
  const put = (u, id, role) => call(`/api/teams/members/${id}`, { method: 'PUT', cookie: u.cookie, body: { role } });
  const del = (u, id) => call(`/api/teams/members/${id}`, { method: 'DELETE', cookie: u.cookie });
  for (const [u, id, role] of [[c.admin, c.admin.id, 'owner'], [c.admin, c.member.id, 'admin'], [c.admin, c.owner.id, 'member'], [c.member, c.member.id, 'owner']]) {
    assert.equal((await put(u, id, role)).status, 403, `${u.name} -> ${role}`);
  }
  assert.equal((await del(c.admin, c.owner.id)).status, 403);
  assert.equal((await del(c.member, c.member2.id)).status, 403);
  const inv = (u, body) => call('/api/teams/invites', { method: 'POST', cookie: u.cookie, body: { email: `a-${rnd()}@example.com`, ...body } });
  assert.equal((await inv(c.admin, { role: 'admin' })).status, 403);
  assert.equal((await inv(c.admin, { role: 'owner' })).status, 400);
  assert.equal((await inv(c.owner, { role: 'owner' })).status, 400);
  assert.equal((await inv(c.member, {})).status, 403);
  assert.equal((await call('/api/teams/invites', { cookie: c.member.cookie })).status, 403);
  assert.equal('invites' in (await team(c.member)), false);
  for (const m of ['PUT', 'DELETE']) { const r = await call('/api/teams', { method: m, cookie: c.admin.cookie, body: m === 'PUT' ? { name: 'x' } : undefined }); assert.equal(r.status, 403, `${m} ${r.text}`); }
  assert.equal((await put(c.rival, c.member.id, 'admin')).status, 404, 'cross-team');
  assert.equal((await del(c.rival, c.member.id)).status, 404, 'cross-team');
  assert.equal((await put(c.owner, c.owner.id, 'member')).status, 400);
  assert.equal((await put(c.owner, c.member.id, 'superuser')).status, 400);
  assert.equal((await call('/api/teams/leave', { method: 'POST', cookie: c.owner.cookie })).status, 409);
  const roles = () => Object.fromEntries(db().prepare('SELECT user_id, role FROM team_members WHERE team_id = ?').all(c.teamId).map((r) => [r.user_id, r.role]));
  assert.deepEqual(roles(), { [c.owner.id]: 'owner', [c.admin.id]: 'admin', [c.member.id]: 'member', [c.member2.id]: 'member' });
  assert.equal((await put(c.owner, c.member.id, 'owner')).status, 200);
  assert.deepEqual(roles(), { [c.owner.id]: 'admin', [c.admin.id]: 'admin', [c.member.id]: 'owner', [c.member2.id]: 'member' });
  assert.equal((await put(c.owner, c.member2.id, 'admin')).status, 403, 'the former owner lost owner rights');
});

test('leave, remove and delete: the leaver\'s team documents become personal; teammates lose access', { skip: needDb }, async () => {
  const c = await crew();
  const m1 = await sent(c.member), m2 = await sent(c.member2), o1 = await sent(c.owner);
  assert.equal((await call('/api/teams/leave', { method: 'POST', cookie: c.member.cookie })).status, 200);
  assert.equal(db().prepare('SELECT team_id FROM documents WHERE id = ?').get(m1).team_id, null);
  assert.equal((await call(`/api/documents/${m1}`, { cookie: c.admin.cookie })).status, 404);
  assert.equal((await call(`/api/documents/${o1}`, { cookie: c.member.cookie })).status, 404, 'the leaver loses team access');
  assert.equal((await call(`/api/documents/${m1}`, { cookie: c.member.cookie })).status, 200, 'the leaver keeps their own');
  assert.equal((await call(`/api/teams/members/${c.member2.id}`, { method: 'DELETE', cookie: c.admin.cookie })).status, 200);
  assert.equal(db().prepare('SELECT team_id FROM documents WHERE id = ?').get(m2).team_id, null);
  const pending = await invite(c.owner, `p-${rnd()}@example.com`);
  assert.equal((await call('/api/teams', { method: 'DELETE', cookie: c.owner.cookie })).status, 200);
  assert.equal(db().prepare('SELECT team_id FROM documents WHERE id = ?').get(o1).team_id, null);
  assert.equal(db().prepare('SELECT COUNT(*) AS n FROM team_members WHERE team_id = ?').get(c.teamId).n, 0);
  assert.equal(db().prepare('SELECT COUNT(*) AS n FROM team_invites WHERE team_id = ?').get(c.teamId).n, 0);
  assert.equal((await team(c.admin)).team, null);
  assert.equal((await call(`/api/documents/${o1}`, { cookie: c.admin.cookie })).status, 404);
  assert.equal((await call(`/join/${pending.token}`)).status, 404);
});

// ---------- Invites ----------

test('invites: keyed hash only, 7-day expiry, single use, revocable, email must match (case-insensitive)', { skip: needDb }, async () => {
  const owner = await signup(BASE, 'Inv Owner');
  await createTeam(owner);
  const invitee = await signup();
  const r = await call('/api/teams/invites', { method: 'POST', cookie: owner.cookie, body: { email: invitee.email.toUpperCase() } });
  assert.equal(r.status, 201);
  assert.equal(r.headers['cache-control'], 'private, no-store');
  const token = tokenOf(r.json.url);
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  const row = db().prepare('SELECT * FROM team_invites WHERE id = ?').get(r.json.id);
  assert.equal(row.token_hash, keyedHash('team-invite', token));
  assert.equal(Object.values(row).some((v) => typeof v === 'string' && v.includes(token)), false, 'no column holds the token');
  const ttl = Date.parse(row.expires_at) - Date.parse(row.created_at);
  assert.ok(Math.abs(ttl - 7 * 864e5) < 5000, String(ttl));
  assert.equal((await call('/api/teams/invites', { cookie: owner.cookie })).text.includes(token), false);
  const stranger = await signup();
  const wrong = await join(stranger, token);
  assert.deepEqual([wrong.status, wrong.json.error], [403, 'This invite is for a different email address']);
  assert.equal((await team(stranger)).team, null);
  for (const t of [undefined, 42, { $ne: 1 }, 'x', token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A')]) assert.equal((await join(stranger, t)).status, 404, JSON.stringify(t));
  assert.equal((await join(invitee, token)).status, 200);
  assert.equal((await join(invitee, token)).status, 404, 'single use');
  assert.equal((await call(`/join/${token}`)).status, 404);
  const other = await signup();
  const rev = await invite(owner, other.email);
  assert.equal((await call(`/api/teams/invites/${rev.id}`, { method: 'DELETE', cookie: invitee.cookie })).status, 403, 'members cannot revoke');
  assert.equal((await call(`/api/teams/invites/${rev.id}`, { method: 'DELETE', cookie: owner.cookie })).status, 200);
  assert.equal((await join(other, rev.token)).status, 404);
  const exp = await invite(owner, other.email);
  db().prepare('UPDATE team_invites SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), exp.id);
  assert.equal((await join(other, exp.token)).status, 404);
  assert.equal((await call(`/join/${exp.token}`)).status, 404);
  assert.equal(props((await call(`/signup?invite=${exp.token}`)).text).invite, null);
  const busy = await signup();
  await createTeam(busy);
  assert.equal((await join(busy, (await invite(owner, busy.email)).token)).status, 409);
});

test('TW2-2: removal, leaving and demotion to member revoke the pending invites that user created; accepted and others\' invites stay', { skip: needDb }, async () => {
  const c = await crew();
  const extra = async (name) => {
    const u = await signup(BASE, name);
    assert.equal((await join(u, (await invite(c.owner, u.email, 'admin')).token)).status, 200);
    u.id = (await team(c.owner)).members.find((m) => m.email === u.email).userId;
    return u;
  };
  const leaver = await extra('Admin Leaver'), demoted = await extra('Admin Demoted'), kept = await extra('Admin Kept');
  // An invite the removed admin created and that was already accepted: that member stays.
  const early = await signup(BASE, 'Early joiner');
  assert.equal((await join(early, (await invite(c.admin, early.email)).token)).status, 200);
  const alts = {};
  for (const [k, u] of [['removed', c.admin], ['leaver', leaver], ['demoted', demoted], ['kept', kept], ['owner', c.owner]]) {
    const alt = await signup(BASE, `alt ${k}`);
    alts[k] = { alt, ...(await invite(u, alt.email)) };
  }
  assert.equal((await call(`/api/teams/members/${c.admin.id}`, { method: 'DELETE', cookie: c.owner.cookie })).status, 200);
  assert.equal((await call('/api/teams/leave', { method: 'POST', cookie: leaver.cookie })).status, 200);
  assert.equal((await call(`/api/teams/members/${demoted.id}`, { method: 'PUT', cookie: c.owner.cookie, body: { role: 'member' } })).status, 200);
  for (const k of ['removed', 'leaver', 'demoted']) {
    assert.ok(db().prepare('SELECT revoked_at FROM team_invites WHERE id = ?').get(alts[k].id).revoked_at, `${k}: revoked_at set`);
    assert.equal((await call(`/join/${alts[k].token}`)).status, 404, `${k}: join page`);
    assert.equal((await join(alts[k].alt, alts[k].token)).status, 404, `${k}: join`);
    assert.equal((await team(alts[k].alt)).team, null, `${k}: not in the team`);
  }
  assert.equal((await team(early)).team?.id, c.teamId, 'an accepted invite is not undone');
  for (const k of ['kept', 'owner']) assert.equal((await join(alts[k].alt, alts[k].token)).status, 200, `${k}: still valid`);
});

// Server B's first account (earliest created_at, then id), signed in and owning a team. A fresh B gets it by sign-up
// (the first account is always allowed); otherwise its password is reset in B's throwaway DB.
async function closedFirst() {
  const first = await call('/api/auth/signup', { method: 'POST', base: CLOSED, body: { name: 'Closed First', email: `c-${rnd()}@example.com`, password: `pw-${rnd()}-${rnd()}` } });
  let owner;
  if (first.status === 200) owner = { base: CLOSED, cookie: cookieOf(first) };
  else {
    assert.ok(DIR_CLOSED, 'server B already has users: set DATA_DIR_CLOSED');
    const row = open(DIR_CLOSED).prepare('SELECT id, email FROM users ORDER BY created_at, id LIMIT 1').get();
    const password = `pw-${rnd()}-${rnd()}`;
    open(DIR_CLOSED).prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(scryptHash(password), row.id);
    const login = await call('/api/auth/login', { method: 'POST', base: CLOSED, body: { email: row.email, password } });
    assert.equal(login.status, 200, login.text);
    owner = { base: CLOSED, cookie: cookieOf(login) };
  }
  const t = await team(owner);
  if (!t.team) await createTeam(owner);
  else assert.equal(t.team.role, 'owner', 'B\'s first account must own its team: use a fresh server B');
  owner.teamId = (await team(owner)).team.id;
  return owner;
}
// A user inserted straight into B's DB (so not the first account), signed in.
async function closedOther(name = 'Not First') {
  const email = `n-${rnd()}@example.com`, password = `pw-${rnd()}-${rnd()}`, id = crypto.randomUUID();
  open(DIR_CLOSED).prepare('INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)').run(id, email, name, scryptHash(password), new Date().toISOString());
  const login = await call('/api/auth/login', { method: 'POST', base: CLOSED, body: { email, password } });
  assert.equal(login.status, 200, login.text);
  return { id, email, base: CLOSED, cookie: cookieOf(login) };
}
const CLOSED_MSG = 'Sign-ups are closed on this server. Ask the admin for an account.';

test('closed server: invite sign-up needs a live invite for the exact email; prefill comes from the server; concurrent use joins once', { skip: needClosed }, async () => {
  const owner = await closedFirst();
  const su = (email, inviteToken) => call('/api/auth/signup', { method: 'POST', base: CLOSED, body: { name: 'N', email, password: `pw-${rnd()}-${rnd()}`, ...(inviteToken !== undefined && { inviteToken }) } });
  const email = `inv-${rnd()}@example.com`;
  const { token } = await invite(owner, email);
  assert.equal((await su(`x-${rnd()}@example.com`)).status, 403);
  assert.equal((await su(`x-${rnd()}@example.com`, token)).status, 403, 'another email');
  for (const bad of ['', 'x', { token }, [token]]) assert.equal((await su(email, bad)).status, 403, JSON.stringify(bad));
  // Signup page: prefill and "closed" come from the server-side invite lookup only.
  const pg = props((await call(`/signup?invite=${token}`, { base: CLOSED })).text);
  assert.deepEqual([pg.closed, pg.invite.email, pg.invite.token], [false, email, token]);
  assert.deepEqual([props((await call('/signup?invite=nope', { base: CLOSED })).text).closed, props((await call('/signup', { base: CLOSED })).text).invite], [true, null]);
  // Five concurrent sign-ups with the same invite and email: one account, one membership, no 5xx.
  const all = await Promise.all(Array.from({ length: 5 }, () => su(email.toUpperCase(), token)));
  const codes = all.map((r) => r.status).join(',');
  assert.equal(all.filter((r) => r.status === 200).length, 1, codes);
  assert.ok(all.every((r) => r.status < 500), `no 5xx: ${codes}`);
  assert.equal((await team({ base: CLOSED, cookie: cookieOf(all.find((r) => r.status === 200)) })).team.role, 'member');
  assert.equal((await su(`y-${rnd()}@example.com`, token)).status, 403, 'an accepted invite no longer opens sign-up');
  const e2 = `inv-${rnd()}@example.com`;
  const rev = await invite(owner, e2);
  assert.equal((await call(`/api/teams/invites/${rev.id}`, { method: 'DELETE', cookie: owner.cookie, base: CLOSED })).status, 200);
  assert.equal((await su(e2, rev.token)).status, 403, 'revoked');
});

test('TW2-1: on a closed server only the first account creates teams, and invite sign-up works only for teams it owns', { skip: needClosedDb }, async () => {
  const first = await closedFirst();
  const bdb = open(DIR_CLOSED);
  const other = await closedOther('Minter');
  const mk = await call('/api/teams', { method: 'POST', cookie: other.cookie, base: CLOSED, body: { name: 'Sock farm' } });
  assert.deepEqual([mk.status, mk.json.error], [403, "Only the server's first account can create teams while sign-ups are closed"]);
  assert.equal(bdb.prepare('SELECT COUNT(*) AS n FROM team_members WHERE user_id = ?').get(other.id).n, 0);
  // Plant invites the way createInvite stores them: one in a team owned by `other` (planted, since the API refuses it),
  // one in the first account's team (control: proves the planted rows are valid, so the refusal is about the owner).
  const plant = (teamId, createdBy, email) => {
    const token = crypto.randomBytes(32).toString('base64url'), t = new Date().toISOString();
    bdb.prepare('INSERT INTO team_invites (id, team_id, email, role, token_hash, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(crypto.randomUUID(), teamId, email, 'member', keyedHash('team-invite', token, KEY_CLOSED), createdBy, t, new Date(Date.now() + 864e5).toISOString());
    return token;
  };
  const foreignTeam = crypto.randomUUID(), t0 = new Date().toISOString();
  bdb.prepare('INSERT INTO teams (id, name, created_at) VALUES (?, ?, ?)').run(foreignTeam, 'Planted team', t0);
  bdb.prepare("INSERT INTO team_members (team_id, user_id, role, joined_at) VALUES (?, ?, 'owner', ?)").run(foreignTeam, other.id, t0);
  const su = (email, inviteToken) => call('/api/auth/signup', { method: 'POST', base: CLOSED, body: { name: 'Sock', email, password: `pw-${rnd()}-${rnd()}`, inviteToken } });
  const sock = `sock-${rnd()}@example.com`;
  const foreignToken = plant(foreignTeam, other.id, sock);
  assert.ok((await call(`/join/${foreignToken}`, { base: CLOSED })).status === 200, 'the planted invite is live');
  // The pages say so up front: no sign-up form, no "Create account" button.
  const sp = props((await call(`/signup?invite=${foreignToken}`, { base: CLOSED })).text);
  assert.deepEqual([sp.closed, sp.invite], [true, null], 'signup page shows the closed message');
  assert.equal(props((await call(`/join/${foreignToken}`, { base: CLOSED })).text).invite.canSignUp, false);
  const refused = await su(sock, foreignToken);
  assert.deepEqual([refused.status, refused.json.error], [403, CLOSED_MSG]);
  assert.equal(refused.setCookie.some((c) => c.startsWith('cs_session=')), false, 'no session');
  assert.equal(bdb.prepare('SELECT COUNT(*) AS n FROM users WHERE email = ?').get(sock).n, 0, 'no user created');
  assert.equal(bdb.prepare('SELECT accepted_at FROM team_invites WHERE token_hash = ?').get(keyedHash('team-invite', foreignToken, KEY_CLOSED)).accepted_at, null);
  // Other direction: the first account's team admits invite sign-up (planted row and API-created invite both work).
  const okEmail = `ok-${rnd()}@example.com`;
  assert.equal(props((await call(`/join/${plant(first.teamId, null, `pg-${rnd()}@example.com`)}`, { base: CLOSED })).text).invite.canSignUp, true);
  const ok = await su(okEmail, plant(first.teamId, null, okEmail));
  assert.equal(ok.status, 200, ok.text);
  assert.equal((await team({ base: CLOSED, cookie: cookieOf(ok) })).team.id, first.teamId);
  const apiEmail = `api-${rnd()}@example.com`;
  assert.equal((await su(apiEmail, (await invite(first, apiEmail)).token)).status, 200);
  // After the first account hands ownership to someone else, its team no longer opens sign-up.
  const heir = await closedOther('Heir');
  assert.equal((await join(heir, (await invite(first, heir.email)).token)).status, 200);
  const lateEmail = `late-${rnd()}@example.com`;
  const late = await invite(first, lateEmail);
  assert.equal((await call(`/api/teams/members/${heir.id}`, { method: 'PUT', cookie: first.cookie, base: CLOSED, body: { role: 'owner' } })).status, 200);
  try {
    const r = await su(lateEmail, late.token);
    assert.deepEqual([r.status, r.json.error], [403, CLOSED_MSG]);
    assert.equal(bdb.prepare('SELECT COUNT(*) AS n FROM users WHERE email = ?').get(lateEmail).n, 0);
  } finally {
    // Give ownership back in B's throwaway DB so reruns still find the first account as owner.
    bdb.prepare("UPDATE team_members SET role = 'admin' WHERE team_id = ? AND user_id = ?").run(first.teamId, heir.id);
    bdb.prepare("UPDATE team_members SET role = 'owner' WHERE team_id = ? AND user_id = (SELECT id FROM users ORDER BY created_at, id LIMIT 1)").run(first.teamId);
  }
});

// ---------- API keys, CSRF, XSS ----------

test('API keys are refused on every team route; share via a key works for the document owner only', async () => {
  const c = await crew();
  const k = (await call('/api/api-keys', { method: 'POST', cookie: c.owner.cookie, body: { name: 'k' } })).json.key;
  const routes = [['GET', '/api/teams'], ['POST', '/api/teams'], ['PUT', '/api/teams'], ['DELETE', '/api/teams'], ['PUT', '/api/teams/members/x'],
    ['DELETE', '/api/teams/members/x'], ['GET', '/api/teams/invites'], ['POST', '/api/teams/invites'], ['DELETE', '/api/teams/invites/x'],
    ['POST', '/api/teams/join'], ['POST', '/api/teams/leave']];
  for (const [method, p] of routes) {
    const r = await call(p, { method, cookie: c.owner.cookie, headers: bearer(k), body: method === 'GET' || method === 'DELETE' ? undefined : { name: 'x', email: 'a@example.com', role: 'member' } });
    assert.deepEqual([r.status, r.json?.error], [401, 'API keys cannot be used here'], `${method} ${p}`);
  }
  assert.ok((await team(c.owner)).team, 'the refused DELETE did nothing');
  const doc = await upload(c.member);
  assert.equal((await call(`/api/documents/${doc}/share`, { method: 'POST', headers: bearer(k), body: { shared: false } })).status, 404, 'team owner key');
  const mk = (await call('/api/api-keys', { method: 'POST', cookie: c.member.cookie, body: { name: 'k' } })).json.key;
  assert.equal((await call(`/api/documents/${doc}/share`, { method: 'POST', headers: bearer(mk), body: { shared: false } })).status, 200);
});

test('CSRF: a foreign Origin is refused on every team write and on share, with nothing changed', { skip: needDb }, async () => {
  const c = await crew();
  const evil = { origin: 'https://evil.example' };
  const doc = await upload(c.member);
  const tok = (await invite(c.owner, (await signup()).email)).token;
  const writes = [['POST', '/api/teams', { name: 'x' }], ['PUT', '/api/teams', { name: 'pwned' }], ['DELETE', '/api/teams'],
    ['PUT', `/api/teams/members/${c.member.id}`, { role: 'owner' }], ['DELETE', `/api/teams/members/${c.member.id}`],
    ['POST', '/api/teams/invites', { email: 'e@example.com' }], ['POST', '/api/teams/join', { token: tok }], ['POST', '/api/teams/leave']];
  for (const [method, p, body] of writes) {
    assert.equal((await call(p, { method, cookie: c.owner.cookie, body, headers: evil })).status, 403, `${method} ${p}`);
  }
  assert.equal((await action(c.member, doc, 'share', { shared: false }, evil)).status, 403);
  assert.ok(db().prepare('SELECT team_id FROM documents WHERE id = ?').get(doc).team_id);
  assert.equal(db().prepare('SELECT COUNT(*) AS n FROM team_members WHERE team_id = ?').get(c.teamId).n, 4);
  assert.equal(db().prepare('SELECT role FROM team_members WHERE user_id = ?').get(c.member.id).role, 'member');
  assert.notEqual(db().prepare('SELECT name FROM teams WHERE id = ?').get(c.teamId).name, 'pwned');
});

test('XSS: team, member and inviter names are escaped on /join, /signup, /app/team, the dashboard and the document page', async () => {
  const x = '<img src=x onerror=alert(1)>"\'</script><script>alert(2)</script>';
  const owner = await signup(BASE, `O${x}`);
  await createTeam(owner, `T${x}`.slice(0, 80));
  const m = await signup(BASE, `M${x}`);
  const { token } = await invite(owner, m.email);
  const raw = /<img src=x onerror|<script>alert\(2\)/;
  const jp = await call(`/join/${token}`);
  assert.equal(jp.status, 200);
  assert.doesNotMatch(jp.text, raw);
  assert.equal(props(jp.text).invite.inviterName, `O${x}`);
  assert.doesNotMatch((await call(`/signup?invite=${token}`)).text, raw);
  assert.equal((await join(m, token)).status, 200);
  const doc = await sent(m);
  for (const [u, p] of [[owner, '/app/team'], [m, '/app/team'], [owner, '/app'], [owner, `/app/documents/${doc}`]]) {
    const r = await call(p, { cookie: u.cookie });
    assert.equal(r.status, 200, p);
    assert.doesNotMatch(r.text, raw, p);
  }
});
