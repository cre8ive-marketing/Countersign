// Tier 3 wave 2 over HTTP: teams (create, rename, delete), invites (link, revoke, replace, expiry, cap, rate limit), join,
// invite sign-up (also on a closed-signup server), roles and ownership transfer, remove and leave, per-role document access
// on every document route and action, list and dashboard scopes, and the SSR pages.
// Needs a running FRESH server (ALLOW_SIGNUP=true, SIGNUP_MAX_PER_HOUR=1000, explicit ENCRYPTION_KEY):
//   BASE_URL=http://localhost:3492 DATA_DIR=<server's DATA_DIR> ENCRYPTION_KEY=<same as server> node --test test/teams.test.mjs
// DATA_DIR (+ ENCRYPTION_KEY or DATA_DIR/encryption.key) enables the invite expiry and stored-hash checks.
// CLOSED_BASE_URL (optional): a second FRESH server started with ALLOW_SIGNUP=false (and SIGNUP_MAX_PER_HOUR=1000). Its first
// sign-up is allowed (empty database); every later one needs a matching invite. Without it the closed-signup test skips.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { PDFDocument } from 'pdf-lib';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const CLOSED = process.env.CLOSED_BASE_URL;
const DATA = process.env.DATA_DIR;
const NEEDS_DB = !DATA && 'needs DATA_DIR pointing at the server data folder';
const PASSWORD = 'correct horse battery';
const EVIL = 'http://evil.test';
const DNF = [404, 'Document not found'];
const rnd = () => crypto.randomBytes(5).toString('hex');
const err = (r) => [r.status, r.data?.error];

let _db;
const db = () => {
  if (!_db) { _db = new DatabaseSync(path.join(DATA, 'countersign.db')); _db.exec('PRAGMA busy_timeout = 5000'); }
  return _db;
};
test.after(() => _db?.close());
const keyText = () => (process.env.ENCRYPTION_KEY || fs.readFileSync(path.join(DATA, 'encryption.key'), 'utf8')).trim();
const key = () => Buffer.from(keyText(), /^[0-9a-f]{64}$/i.test(keyText()) ? 'hex' : 'base64');
const keyedHash = (info, data) => crypto.createHmac('sha256', Buffer.from(crypto.hkdfSync('sha256', key(), Buffer.alloc(0), 'countersign-' + info, 32))).update(data).digest('hex');

// ---------- HTTP helpers ----------
function client(base = BASE) {
  const cookies = {};
  const call = async (p, { method = 'POST', body, headers = {} } = {}) => {
    const raw = body instanceof Uint8Array || typeof body === 'string';
    const cookie = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(base + p, {
      method, redirect: 'manual',
      headers: { ...(raw ? {} : { 'Content-Type': 'application/json' }), ...(cookie && { cookie }), ...headers },
      body: body == null ? undefined : raw ? body : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); cookies[kv.slice(0, i)] = kv.slice(i + 1); }
    const type = res.headers.get('content-type') || '';
    return { status: res.status, headers: res.headers, data: type.includes('json') ? await res.json() : Buffer.from(await res.arrayBuffer()) };
  };
  return call;
}
const bearer = (k) => (p, opts = {}) => client()(p, { ...opts, headers: { Authorization: `Bearer ${k}`, ...opts.headers } });
const nextData = (html) => JSON.parse(/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s.exec(html)[1]).props.pageProps;
async function page(call, p, status = 200) {
  const r = await call(p, { method: 'GET' });
  const html = r.data.toString();
  assert.equal(r.status, status, `${p}: status ${r.status}`);
  assert.ok(!/Internal Server Error|Application error/i.test(html), `${p}: error page`);
  return { html, props: nextData(html) };
}
const newEmail = () => `tm-${Date.now()}-${rnd()}@example.com`;

async function signup(name = 'Team User', email = newEmail(), extra = {}, base = BASE) {
  const call = client(base);
  const r = await call('/api/auth/signup', { body: { name, email, password: PASSWORD, ...extra } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return Object.assign(call, { email, userName: name });
}
const pdf = async () => { const d = await PDFDocument.create(); d.setTitle(rnd()); d.addPage([612, 792]); return d.save(); };
const field = (recipientId, i = 0) => ({ recipientId, type: 'signature', page: 0, x: 0.1, y: 0.1 + i * 0.1, w: 0.3, h: 0.08 });
const person = (id) => ({ id, name: `Signer ${id}`, email: `${id}-${rnd()}@example.com`, role: 'signer' });

async function upload(call, template = false) {
  const up = await call('/api/documents', { body: await pdf(), headers: { 'Content-Type': 'application/pdf', 'x-file-name': 'Teams.pdf', ...(template && { 'x-template': '1' }) } });
  assert.equal(up.status, 201, JSON.stringify(up.data));
  return up.data.id;
}
async function draft(call, recipients = [person('a')]) {
  const id = await upload(call);
  const title = `Team doc ${rnd()}`;
  const body = { title, recipients, fields: recipients.map((r, i) => field(r.id, i)) };
  const put = await call(`/api/documents/${id}`, { method: 'PUT', body });
  assert.equal(put.status, 200, JSON.stringify(put.data));
  return { id, title, body };
}
async function sent(call) {
  const d = await draft(call);
  const r = await call(`/api/documents/${d.id}/send`, { body: {} });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return d;
}
async function template(call, roles = ['Client']) {
  const id = await upload(call, true);
  const recipients = roles.map((name, i) => ({ id: `r${i}`, name, email: '', role: 'signer' }));
  const title = `Tpl ${rnd()}`;
  const body = { title, recipients, fields: recipients.map((r, i) => field(r.id, i)) };
  const put = await call(`/api/documents/${id}`, { method: 'PUT', body });
  assert.equal(put.status, 200, JSON.stringify(put.data));
  return { id, title, body };
}
const getDoc = async (call, id) => { const r = await call(`/api/documents/${id}`, { method: 'GET' }); assert.equal(r.status, 200, JSON.stringify(r.data)); return r.data; };
const list = async (call, qs = '') => { const r = await call(`/api/documents${qs}`, { method: 'GET' }); assert.equal(r.status, 200, JSON.stringify(r.data)); return r.data; };
const ids = (l) => l.documents.map((d) => d.id).sort();
const teamGet = async (call) => { const r = await call('/api/teams', { method: 'GET' }); assert.equal(r.status, 200, JSON.stringify(r.data)); return r.data; };

const tokenOf = (url) => url.slice('/join/'.length);
async function invite(by, email, role = 'member') {
  const r = await by('/api/teams/invites', { body: { email, role } });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  return r.data;
}
async function join(call, url) {
  const r = await call('/api/teams/join', { body: { token: tokenOf(url) } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return r.data;
}
// Team with an owner O, an admin A and a member M (user ids on .id). O's pre-team document is in O.personal when asked.
async function teamSetup({ personal = false, name = `Team ${rnd()}` } = {}) {
  const O = await signup('Team Owner'), A = await signup('Team Admin'), M = await signup('Team Member');
  if (personal) O.personal = await sent(O);
  const created = await O('/api/teams', { body: { name } });
  assert.equal(created.status, 201, JSON.stringify(created.data));
  await join(A, (await invite(O, A.email, 'admin')).url);
  await join(M, (await invite(O, M.email)).url);
  const t = await teamGet(O);
  for (const c of [O, A, M]) c.id = t.members.find((m) => m.email === c.email).userId;
  return { O, A, M, teamId: created.data.id, name };
}
const roleOf = async (call, user) => (await teamGet(call)).members.find((m) => m.userId === user.id)?.role;

// =====================================================================================================================
// Team lifecycle
// =====================================================================================================================

test('team: create (201 { id }), one team per user 409, name validation, GET shape per role, rename (owner only), delete (owner only)', async () => {
  const O = await signup('Team Owner');
  assert.deepEqual(await teamGet(O), { team: null }, 'no team yet');
  assert.deepEqual(err(await O('/api/teams', { body: { name: '   ' } })), [400, 'Enter a team name']);
  assert.deepEqual(err(await O('/api/teams', { body: {} })), [400, 'Enter a team name']);
  assert.deepEqual(err(await O('/api/teams', { body: { name: 'x'.repeat(81) } })), [400, 'Use at most 80 characters']);
  assert.equal((await O('/api/teams', { body: { name: 'Acme' }, headers: { Origin: EVIL } })).status, 403, 'cross-origin write');
  assert.equal((await client()('/api/teams', { body: { name: 'Acme' } })).status, 401);
  assert.equal((await client()('/api/teams', { method: 'GET' })).status, 401);
  const c = await O('/api/teams', { body: { name: '  Acme Legal  ' } });
  assert.equal(c.status, 201, JSON.stringify(c.data));
  assert.deepEqual(Object.keys(c.data), ['id']);
  assert.deepEqual(err(await O('/api/teams', { body: { name: 'Second' } })), [409, 'You are already in a team']);
  const t = await teamGet(O);
  assert.deepEqual(t.team, { id: c.data.id, name: 'Acme Legal', role: 'owner' });
  assert.equal(t.members.length, 1);
  assert.deepEqual(Object.keys(t.members[0]).sort(), ['email', 'joinedAt', 'name', 'role', 'userId']);
  assert.deepEqual([t.members[0].email, t.members[0].role, t.members[0].name], [O.email, 'owner', 'Team Owner']);
  assert.deepEqual(t.invites, []);
  const r = await O('/api/teams', { method: 'GET' });
  assert.match(r.headers.get('cache-control') || '', /no-store/);

  // Admin and member: no invites key for members, rename and delete are owner only.
  const A = await signup('Team Admin'), M = await signup('Team Member');
  await join(A, (await invite(O, A.email, 'admin')).url);
  await join(M, (await invite(O, M.email)).url);
  assert.ok(Array.isArray((await teamGet(A)).invites), 'admin sees invites');
  assert.equal((await teamGet(M)).invites, undefined, 'member gets no invites');
  assert.equal((await teamGet(M)).members.length, 3);
  for (const u of [A, M]) {
    assert.deepEqual(err(await u('/api/teams', { method: 'PUT', body: { name: 'Hijack' } })), [403, 'Only the team owner can do this']);
    assert.deepEqual(err(await u('/api/teams', { method: 'DELETE' })), [403, 'Only the team owner can do this']);
  }
  assert.deepEqual(err(await O('/api/teams', { method: 'PUT', body: { name: '' } })), [400, 'Enter a team name']);
  assert.deepEqual(await (await O('/api/teams', { method: 'PUT', body: { name: 'Acme Renamed' } })).data, { ok: true });
  assert.equal((await teamGet(M)).team.name, 'Acme Renamed');
  // Not in a team.
  const X = await signup('Outsider');
  assert.deepEqual(err(await X('/api/teams', { method: 'PUT', body: { name: 'N' } })), [409, 'Join a team first']);
  assert.deepEqual(err(await X('/api/teams', { method: 'DELETE' })), [409, 'Join a team first']);

  // Delete: everyone is out, every team document is personal again, invites die.
  const dO = await sent(O), dM = await sent(M);
  const pending = await invite(O, newEmail());
  assert.equal((await list(A, '?scope=team')).total, 2);
  assert.deepEqual((await O('/api/teams', { method: 'DELETE' })).data, { ok: true });
  for (const u of [O, A, M]) assert.deepEqual(await teamGet(u), { team: null });
  assert.equal((await getDoc(O, dO.id)).doc.team_id, null);
  assert.equal((await getDoc(M, dM.id)).doc.team_id, null);
  assert.deepEqual(err(await A(`/api/documents/${dO.id}`, { method: 'GET' })), DNF);
  assert.deepEqual(err(await O(`/api/documents/${dM.id}`, { method: 'GET' })), DNF);
  assert.deepEqual(err(await X('/api/teams/join', { body: { token: tokenOf(pending.url) } })), [404, 'This invite link is invalid or has expired']);
  // A fresh team can be made afterwards.
  assert.equal((await M('/api/teams', { body: { name: 'Next' } })).status, 201);
});

test('teams routes are session only: an API key gets 401 on every team route', async () => {
  const { O } = await teamSetup();
  const k = (await O('/api/api-keys', { body: { name: 'ci' } })).data.key;
  const b = bearer(k);
  assert.equal((await b('/api/documents', { method: 'GET' })).status, 200, 'key works on documents');
  for (const [p, method, body] of [['/api/teams', 'GET'], ['/api/teams', 'PUT', { name: 'x' }], ['/api/teams', 'DELETE'], ['/api/teams/invites', 'GET'],
    ['/api/teams/invites', 'POST', { email: newEmail() }], ['/api/teams/invites/x', 'DELETE'], ['/api/teams/members/x', 'PUT', { role: 'admin' }],
    ['/api/teams/members/x', 'DELETE'], ['/api/teams/join', 'POST', { token: 'x' }], ['/api/teams/leave', 'POST']]) {
    assert.equal((await b(p, { method, body })).status, 401, `${method} ${p}`);
  }
  assert.ok((await teamGet(O)).team, 'team untouched');
});

// =====================================================================================================================
// Invites
// =====================================================================================================================

test('invites: shape { id, url, emailed }, validation, role rules, list, replace, revoke, stored hash only, 401/403', async () => {
  const { O, A, M, name } = await teamSetup();
  const email = newEmail();
  const r = await O('/api/teams/invites', { body: { email: `  ${email.toUpperCase()} `, role: 'admin' } });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  assert.deepEqual(Object.keys(r.data).sort(), ['emailed', 'id', 'url']);
  assert.match(r.data.url, /^\/join\/[A-Za-z0-9_-]{43}$/);
  assert.equal(r.data.emailed, false, 'no SMTP on the test server');
  assert.match(r.headers.get('cache-control') || '', /no-store/);
  const listed = (await O('/api/teams/invites', { method: 'GET' })).data.invites;
  const inv = listed.find((i) => i.id === r.data.id);
  assert.deepEqual(Object.keys(inv).sort(), ['createdAt', 'email', 'expiresAt', 'id', 'role']);
  assert.deepEqual([inv.email, inv.role], [email, 'admin'], 'email trimmed and lowercased');
  const ttl = Date.parse(inv.expiresAt) - Date.parse(inv.createdAt);
  assert.ok(Math.abs(ttl - 7 * 864e5) < 60_000, `expires in 7 days, got ${ttl} ms`);
  assert.equal(JSON.stringify(listed).includes(tokenOf(r.data.url)), false, 'token not listed');
  assert.deepEqual((await A('/api/teams/invites', { method: 'GET' })).data.invites.map((i) => i.id), listed.map((i) => i.id), 'admin sees the same list');
  assert.deepEqual((await teamGet(O)).invites, listed);
  if (DATA) {
    const row = db().prepare('SELECT * FROM team_invites WHERE id = ?').get(r.data.id);
    assert.equal(row.token_hash, keyedHash('team-invite', tokenOf(r.data.url)), 'keyed hash stored');
    assert.ok(!JSON.stringify(row).includes(tokenOf(r.data.url)), 'raw token not stored');
  }

  // Validation and roles.
  for (const [body, want] of [[{ email: 'nope' }, [400, 'Enter a valid email address']], [{}, [400, 'Enter a valid email address']],
    [{ email: `${'a'.repeat(250)}@example.com` }, [400, 'Enter a valid email address']],
    [{ email: newEmail(), role: 'owner' }, [400, 'Choose admin or member']], [{ email: newEmail(), role: 'boss' }, [400, 'Choose admin or member']]]) {
    assert.deepEqual(err(await O('/api/teams/invites', { body })), want, JSON.stringify(body));
  }
  assert.equal((await O('/api/teams/invites', { body: { email: newEmail() } })).status, 201, 'role defaults to member');
  assert.deepEqual(err(await M('/api/teams/invites', { body: { email: newEmail() } })), [403, 'Only team owners and admins can do this']);
  assert.deepEqual(err(await M('/api/teams/invites', { method: 'GET' })), [403, 'Only team owners and admins can do this']);
  assert.deepEqual(err(await A('/api/teams/invites', { body: { email: newEmail(), role: 'admin' } })), [403, 'Admins can only invite members']);
  const byAdmin = await invite(A, newEmail(), 'member');
  assert.ok(byAdmin.id);
  assert.deepEqual(err(await O('/api/teams/invites', { body: { email: M.email.toUpperCase() } })), [409, 'This person is already in your team']);
  const X = await signup('Outsider');
  assert.deepEqual(err(await X('/api/teams/invites', { body: { email: newEmail() } })), [409, 'Join a team first']);
  assert.deepEqual(err(await X('/api/teams/invites', { method: 'GET' })), [409, 'Join a team first']);
  assert.equal((await O('/api/teams/invites', { body: { email: newEmail() }, headers: { Origin: EVIL } })).status, 403);
  assert.equal((await client()('/api/teams/invites', { body: { email: newEmail() } })).status, 401);

  // A new invite for the same email replaces the pending one.
  const target = await signup('Invitee');
  const first = await invite(O, target.email);
  const second = await invite(O, target.email, 'admin');
  const forTarget = (await O('/api/teams/invites', { method: 'GET' })).data.invites.filter((i) => i.email === target.email);
  assert.deepEqual(forTarget.map((i) => [i.id, i.role]), [[second.id, 'admin']], 'one pending invite per email');
  assert.deepEqual(err(await target('/api/teams/join', { body: { token: tokenOf(first.url) } })), [404, 'This invite link is invalid or has expired']);
  assert.equal((await client()(first.url, { method: 'GET' })).status, 404, 'replaced link page');

  // Revoke: owner or admin of this team only; then the link is dead.
  assert.deepEqual(err(await M(`/api/teams/invites/${second.id}`, { method: 'DELETE' })), [403, 'Only team owners and admins can do this']);
  const other = await teamSetup();
  assert.deepEqual(err(await other.O(`/api/teams/invites/${second.id}`, { method: 'DELETE' })), [404, 'Invite not found'], 'another team');
  assert.deepEqual(err(await X(`/api/teams/invites/${second.id}`, { method: 'DELETE' })), [409, 'Join a team first']);
  assert.equal((await O(`/api/teams/invites/${second.id}`, { method: 'DELETE', headers: { Origin: EVIL } })).status, 403);
  assert.deepEqual((await A(`/api/teams/invites/${second.id}`, { method: 'DELETE' })).data, { ok: true }, 'admin revokes');
  assert.deepEqual(err(await O(`/api/teams/invites/${second.id}`, { method: 'DELETE' })), [404, 'Invite not found'], 'twice');
  assert.deepEqual(err(await O(`/api/teams/invites/${crypto.randomUUID()}`, { method: 'DELETE' })), [404, 'Invite not found']);
  assert.ok(!(await O('/api/teams/invites', { method: 'GET' })).data.invites.some((i) => i.id === second.id), 'gone from the list');
  assert.deepEqual(err(await target('/api/teams/join', { body: { token: tokenOf(second.url) } })), [404, 'This invite link is invalid or has expired']);
  assert.equal((await client()(second.url, { method: 'GET' })).status, 404, 'revoked link page');
  assert.deepEqual(await teamGet(target), { team: null });
  assert.equal((await teamGet(O)).team.name, name);
});

test('invites: an expired invite cannot be used or listed and its page is 404', { skip: NEEDS_DB }, async () => {
  const { O } = await teamSetup();
  const target = await signup('Late Invitee');
  const inv = await invite(O, target.email);
  db().prepare('UPDATE team_invites SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), inv.id);
  assert.ok(!(await O('/api/teams/invites', { method: 'GET' })).data.invites.some((i) => i.id === inv.id), 'not listed');
  assert.equal((await client()(inv.url, { method: 'GET' })).status, 404);
  assert.deepEqual(err(await target('/api/teams/join', { body: { token: tokenOf(inv.url) } })), [404, 'This invite link is invalid or has expired']);
  // Sign-up with an expired invite is a normal sign-up (open server): no team.
  const late = newEmail();
  const inv2 = await invite(O, late);
  db().prepare('UPDATE team_invites SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), inv2.id);
  const u = await signup('Late Signup', late, { inviteToken: tokenOf(inv2.url) });
  assert.deepEqual(await teamGet(u), { team: null });
  assert.deepEqual(await teamGet(target), { team: null });
  // Expired invites do not count toward the cap and a new invite for the same email works.
  const fresh = await invite(O, target.email);
  assert.equal((await join(target, fresh.url)).role, 'member');
});

test('invites: 50 pending per team (409, revoking frees a slot) and 30 invite calls per hour per user (429 + Retry-After)', async () => {
  const O = await signup('Cap Owner'), A = await signup('Cap Admin');
  assert.equal((await O('/api/teams', { body: { name: 'Cap' } })).status, 201);
  await join(A, (await invite(O, A.email, 'admin')).url); // O: 1 call, 0 pending
  for (let i = 0; i < 29; i++) await invite(O, newEmail()); // O: 30 calls, 29 pending
  const over = await O('/api/teams/invites', { body: { email: newEmail() } });
  assert.deepEqual(err(over), [429, 'Too many invites. Try again later.'], '31st call');
  assert.ok(Number(over.headers.get('retry-after')) > 0, 'Retry-After');
  let last;
  for (let i = 0; i < 21; i++) last = await invite(A, newEmail()); // A: 21 calls, 50 pending
  assert.equal((await A('/api/teams/invites', { method: 'GET' })).data.invites.length, 50);
  assert.deepEqual(err(await A('/api/teams/invites', { body: { email: newEmail() } })), [409, 'You can have up to 50 pending invites']);
  assert.equal((await A(`/api/teams/invites/${last.id}`, { method: 'DELETE' })).status, 200);
  assert.equal((await A('/api/teams/invites', { body: { email: newEmail() } })).status, 201, 'slot freed');
  // Re-inviting the same pending email replaces, so it is allowed at the cap.
  const pendingEmail = (await A('/api/teams/invites', { method: 'GET' })).data.invites[0].email;
  assert.equal((await A('/api/teams/invites', { body: { email: pendingEmail } })).status, 201, 'replace at the cap');
  assert.equal((await A('/api/teams/invites', { method: 'GET' })).data.invites.length, 50);
});

// =====================================================================================================================
// Join and invite sign-up
// =====================================================================================================================

test('join: needs sign-in, matching email (case-insensitive), single use, one team per user; bad tokens 404', async () => {
  const { O, teamId } = await teamSetup();
  const target = await signup('Joiner');
  const wrong = await signup('Wrong Person');
  const inv = await invite(O, target.email.toUpperCase());
  assert.equal((await client()('/api/teams/join', { body: { token: tokenOf(inv.url) } })).status, 401);
  assert.equal((await target('/api/teams/join', { body: { token: tokenOf(inv.url) }, headers: { Origin: EVIL } })).status, 403);
  assert.deepEqual(err(await wrong('/api/teams/join', { body: { token: tokenOf(inv.url) } })), [403, 'This invite is for a different email address']);
  assert.deepEqual(await teamGet(wrong), { team: null });
  for (const token of [undefined, '', 'x', 'A'.repeat(43), 123, tokenOf(inv.url) + 'A']) {
    assert.deepEqual(err(await target('/api/teams/join', { body: { token } })), [404, 'This invite link is invalid or has expired'], String(token));
  }
  const j = await target('/api/teams/join', { body: { token: tokenOf(inv.url) } });
  assert.deepEqual(j.data, { ok: true, teamId, role: 'member' });
  assert.deepEqual((await teamGet(target)).team, { id: teamId, name: (await teamGet(O)).team.name, role: 'member' });
  assert.deepEqual(err(await target('/api/teams/join', { body: { token: tokenOf(inv.url) } })), [404, 'This invite link is invalid or has expired'], 'single use');
  assert.ok(!(await O('/api/teams/invites', { method: 'GET' })).data.invites.some((i) => i.id === inv.id), 'accepted invite not pending');
  // Someone already in another team cannot accept.
  const other = await teamSetup();
  const inv2 = await invite(O, other.M.email, 'admin');
  assert.deepEqual(err(await other.M('/api/teams/join', { body: { token: tokenOf(inv2.url) } })), [409, 'You are already in a team']);
  assert.equal((await teamGet(other.M)).team.id, other.teamId);
  // After leaving their team the same invite still works, with the invited role.
  assert.deepEqual((await other.M('/api/teams/leave', { body: {} })).data, { ok: true, deleted: false });
  assert.deepEqual((await join(other.M, inv2.url)), { ok: true, teamId, role: 'admin' });
});

test('signup with inviteToken (open server): matching email joins in the same request; another email signs up without a team', async () => {
  const { O, teamId } = await teamSetup();
  const email = newEmail();
  const inv = await invite(O, email, 'admin');
  const mismatch = await signup('Other Email', newEmail(), { inviteToken: tokenOf(inv.url) });
  assert.deepEqual(await teamGet(mismatch), { team: null }, 'not joined');
  const bogus = await signup('Bogus Token', newEmail(), { inviteToken: 'nope' });
  assert.deepEqual(await teamGet(bogus), { team: null });
  const u = await signup('Invited', email.toUpperCase(), { inviteToken: tokenOf(inv.url) });
  assert.deepEqual((await teamGet(u)).team, { id: teamId, name: (await teamGet(O)).team.name, role: 'admin' });
  assert.ok((await teamGet(O)).members.some((m) => m.email === email && m.role === 'admin'));
  // Documents made right after joining are team documents.
  const d = await sent(u);
  assert.equal((await getDoc(O, d.id)).doc.team_id, teamId);
});

test('signup with inviteToken on a closed-signup server (CLOSED_BASE_URL, ALLOW_SIGNUP=false)', { skip: !CLOSED && 'set CLOSED_BASE_URL to a fresh server started with ALLOW_SIGNUP=false' }, async (t) => {
  // The first user of an empty database may always sign up; that becomes the team owner.
  const O = client(CLOSED);
  const first = await O('/api/auth/signup', { body: { name: 'Closed Owner', email: newEmail(), password: PASSWORD } });
  if (first.status !== 200) return t.skip(`CLOSED_BASE_URL is not a fresh closed server: first sign-up returned ${first.status} ${JSON.stringify(first.data)}`);
  const closed = [403, 'Sign-ups are closed on this server. Ask the admin for an account.'];
  const signupC = (body) => client(CLOSED)('/api/auth/signup', { body: { name: 'Closed User', password: PASSWORD, ...body } });
  assert.deepEqual(err(await signupC({ email: newEmail() })), closed, 'closed after the first user');
  const c = await O('/api/teams', { body: { name: 'Closed Team' } });
  assert.equal(c.status, 201, JSON.stringify(c.data));
  const email = newEmail();
  const inv = (await O('/api/teams/invites', { body: { email, role: 'admin' } })).data;
  assert.match(inv.url, /^\/join\//);
  assert.deepEqual(err(await signupC({ email: newEmail(), inviteToken: tokenOf(inv.url) })), closed, 'another email');
  assert.deepEqual(err(await signupC({ email, inviteToken: 'A'.repeat(43) })), closed, 'unknown token');
  assert.deepEqual(err(await signupC({ email })), closed, 'no token');
  // Revoked invite: closed.
  const revokedEmail = newEmail();
  const rv = (await O('/api/teams/invites', { body: { email: revokedEmail } })).data;
  assert.equal((await O(`/api/teams/invites/${rv.id}`, { method: 'DELETE' })).status, 200);
  assert.deepEqual(err(await signupC({ email: revokedEmail, inviteToken: tokenOf(rv.url) })), closed, 'revoked');
  // Matching email (any case): account created, signed in, joined with the invited role.
  const u = client(CLOSED);
  const ok = await u('/api/auth/signup', { body: { name: 'Closed Invitee', email: email.toUpperCase(), password: PASSWORD, inviteToken: tokenOf(inv.url) } });
  assert.deepEqual([ok.status, ok.data], [200, { ok: true }]);
  assert.deepEqual((await u('/api/teams', { method: 'GET' })).data.team, { id: c.data.id, name: 'Closed Team', role: 'admin' });
  // A weak password with a valid invite is refused and does not use up the invite.
  const e2 = newEmail();
  const inv2 = (await O('/api/teams/invites', { body: { email: e2 } })).data;
  assert.equal((await signupC({ email: e2, password: 'short', inviteToken: tokenOf(inv2.url) })).status, 400);
  assert.equal((await signupC({ email: e2, inviteToken: tokenOf(inv2.url) })).status, 200, 'invite still usable');
  // A used invite: closed again.
  assert.deepEqual(err(await signupC({ email: newEmail(), inviteToken: tokenOf(inv.url) })), closed, 'used invite');
  assert.deepEqual(err(await signupC({ email, inviteToken: tokenOf(inv.url) })), closed, 'used invite, same email');
});

// =====================================================================================================================
// Roles, ownership, remove and leave
// =====================================================================================================================

test('roles: owner changes roles (validation, 404, 400 on self), admins/members 403, promote/demote changes write access', async () => {
  const { O, A, M } = await teamSetup();
  const dO = await draft(O);
  const setRole = (by, who, role, headers) => by(`/api/teams/members/${who}`, { method: 'PUT', body: { role }, headers });
  assert.deepEqual(err(await setRole(O, M.id, 'boss')), [400, 'Choose owner, admin or member']);
  assert.deepEqual(err(await setRole(O, M.id, undefined)), [400, 'Choose owner, admin or member']);
  assert.deepEqual(err(await setRole(O, O.id, 'admin')), [400, 'You cannot change your own role. Make someone else the owner first.']);
  assert.deepEqual(err(await setRole(O, crypto.randomUUID(), 'admin')), [404, 'Member not found']);
  const other = await teamSetup();
  assert.deepEqual(err(await setRole(O, other.M.id, 'admin')), [404, 'Member not found'], 'member of another team');
  assert.deepEqual(err(await setRole(A, M.id, 'admin')), [403, 'Only the team owner can do this']);
  assert.deepEqual(err(await setRole(M, A.id, 'member')), [403, 'Only the team owner can do this']);
  const X = await signup('Outsider');
  assert.deepEqual(err(await setRole(X, M.id, 'admin')), [409, 'Join a team first']);
  assert.equal((await setRole(O, M.id, 'admin', { Origin: EVIL })).status, 403);
  assert.equal((await client()(`/api/teams/members/${M.id}`, { method: 'PUT', body: { role: 'admin' } })).status, 401);
  assert.equal(await roleOf(O, M), 'member', 'nothing changed');
  assert.equal(await roleOf(other.O, other.M), 'member', 'other team untouched');

  assert.deepEqual(err(await M(`/api/documents/${dO.id}`, { method: 'PUT', body: { title: 'by member' } })), DNF);
  assert.deepEqual((await setRole(O, M.id, 'admin')).data, { ok: true });
  assert.equal(await roleOf(O, M), 'admin');
  assert.equal((await M(`/api/documents/${dO.id}`, { method: 'PUT', body: { title: 'by promoted admin' } })).status, 200, 'admin can write');
  assert.equal((await setRole(O, M.id, 'member')).status, 200);
  assert.deepEqual(err(await M(`/api/documents/${dO.id}`, { method: 'PUT', body: { title: 'demoted' } })), DNF, 'member again');
  assert.equal((await setRole(O, A.id, 'member')).status, 200);
  assert.deepEqual(err(await A('/api/teams/invites', { body: { email: newEmail() } })), [403, 'Only team owners and admins can do this'], 'demoted admin');
});

test('owner transfer: new owner gets owner powers, old owner becomes admin, exactly one owner; owner leave 409 until transferred', async () => {
  const { O, A, M } = await teamSetup();
  assert.deepEqual(err(await O('/api/teams/leave', { body: {} })), [409, 'Make someone else the owner before you leave']);
  assert.equal((await O(`/api/teams/members/${M.id}`, { method: 'PUT', body: { role: 'owner' } })).status, 200);
  const t = await teamGet(M);
  assert.equal(t.team.role, 'owner');
  assert.deepEqual(t.members.map((m) => [m.userId, m.role]).sort(), [[O.id, 'admin'], [A.id, 'admin'], [M.id, 'owner']].sort());
  assert.equal(t.members.filter((m) => m.role === 'owner').length, 1);
  assert.equal(t.members[0].userId, M.id, 'owner listed first');
  // The old owner is now an admin.
  assert.deepEqual(err(await O(`/api/teams/members/${A.id}`, { method: 'PUT', body: { role: 'member' } })), [403, 'Only the team owner can do this']);
  assert.deepEqual(err(await O('/api/teams', { method: 'PUT', body: { name: 'no' } })), [403, 'Only the team owner can do this']);
  assert.deepEqual(err(await O('/api/teams', { method: 'DELETE' })), [403, 'Only the team owner can do this']);
  assert.deepEqual(err(await O(`/api/teams/members/${M.id}`, { method: 'DELETE' })), [403, 'Admins can only remove members'], 'admin cannot remove the owner');
  assert.equal((await M('/api/teams', { method: 'PUT', body: { name: 'Renamed by new owner' } })).status, 200);
  // The old owner can leave now (as an admin).
  assert.deepEqual((await O('/api/teams/leave', { body: {} })).data, { ok: true, deleted: false });
  assert.deepEqual(await teamGet(O), { team: null });
  // Transfer to A, then M is an admin and can be demoted by A.
  assert.equal((await M(`/api/teams/members/${A.id}`, { method: 'PUT', body: { role: 'owner' } })).status, 200);
  assert.equal(await roleOf(A, M), 'admin');
  assert.equal((await A(`/api/teams/members/${M.id}`, { method: 'PUT', body: { role: 'member' } })).status, 200);
  assert.equal(await roleOf(A, M), 'member');
});

test('remove and leave: permission rules, and the leaver\'s team documents become personal again (others keep theirs)', async () => {
  const { O, A, M, teamId } = await teamSetup();
  const A2 = await signup('Second Admin'), M2 = await signup('Second Member');
  await join(A2, (await invite(O, A2.email, 'admin')).url);
  await join(M2, (await invite(O, M2.email)).url);
  const mem = (await teamGet(O)).members;
  A2.id = mem.find((m) => m.email === A2.email).userId;
  M2.id = mem.find((m) => m.email === M2.email).userId;
  const dO = await sent(O), dA = await sent(A), dM = await draft(M), dM2 = await sent(M2), tplM = await template(M);
  const rm = (by, who, headers) => by(`/api/teams/members/${who}`, { method: 'DELETE', headers });
  assert.deepEqual(err(await rm(M, M2.id)), [403, 'Only team owners and admins can do this']);
  assert.deepEqual(err(await rm(A, A2.id)), [403, 'Admins can only remove members']);
  assert.deepEqual(err(await rm(A, O.id)), [403, 'Admins can only remove members']);
  assert.deepEqual(err(await rm(O, O.id)), [400, 'Use Leave team to remove yourself']);
  assert.deepEqual(err(await rm(A, A.id)), [400, 'Use Leave team to remove yourself']);
  assert.deepEqual(err(await rm(O, crypto.randomUUID())), [404, 'Member not found']);
  assert.equal((await rm(O, M.id, { Origin: EVIL })).status, 403);
  const X = await signup('Outsider');
  assert.deepEqual(err(await rm(X, M.id)), [409, 'Join a team first']);
  assert.deepEqual(err(await X('/api/teams/leave', { body: {} })), [409, 'Join a team first']);
  assert.equal((await client()('/api/teams/leave', { body: {} })).status, 401);
  assert.equal((await M('/api/teams/leave', { body: {}, headers: { Origin: EVIL } })).status, 403);

  // An admin removes a member: M's documents leave the team; M keeps them.
  assert.equal((await getDoc(O, dM.id)).doc.team_id, teamId);
  assert.deepEqual((await rm(A, M.id)).data, { ok: true });
  assert.deepEqual(await teamGet(M), { team: null });
  for (const d of [dM, tplM]) {
    assert.equal((await getDoc(M, d.id)).doc.team_id, null, 'personal again');
    for (const u of [O, A, M2]) assert.deepEqual(err(await u(`/api/documents/${d.id}`, { method: 'GET' })), DNF);
    assert.deepEqual(err(await O(`/api/documents/${d.id}/copy`, { body: {} })), DNF);
  }
  assert.deepEqual(err(await M(`/api/documents/${dO.id}`, { method: 'GET' })), DNF, 'removed member loses team documents');
  assert.ok((await list(M)).documents.every((d) => d.teamShared === false), 'M list all personal');
  assert.equal((await getDoc(M2, dO.id)).doc.team_id, teamId, 'others untouched');
  // The owner removes an admin.
  assert.equal((await rm(O, A2.id)).status, 200);
  assert.deepEqual(await teamGet(A2), { team: null });
  // A member leaves.
  assert.deepEqual((await M2('/api/teams/leave', { body: {} })).data, { ok: true, deleted: false });
  assert.equal((await getDoc(M2, dM2.id)).doc.team_id, null);
  assert.deepEqual(err(await O(`/api/documents/${dM2.id}`, { method: 'GET' })), DNF);
  // An admin leaves.
  assert.deepEqual((await A('/api/teams/leave', { body: {} })).data, { ok: true, deleted: false });
  assert.equal((await getDoc(A, dA.id)).doc.team_id, null);
  assert.deepEqual(err(await O(`/api/documents/${dA.id}`, { method: 'GET' })), DNF);
  assert.deepEqual(err(await A(`/api/documents/${dO.id}`, { method: 'GET' })), DNF);
  // The owner, now alone, leaves: the team is deleted and its documents are personal.
  assert.equal((await teamGet(O)).members.length, 1);
  assert.deepEqual((await O('/api/teams/leave', { body: {} })).data, { ok: true, deleted: true });
  assert.deepEqual(await teamGet(O), { team: null });
  assert.equal((await getDoc(O, dO.id)).doc.team_id, null);
  if (DATA) {
    assert.equal(db().prepare('SELECT COUNT(*) AS n FROM teams WHERE id = ?').get(teamId).n, 0, 'team row gone');
    assert.equal(db().prepare('SELECT COUNT(*) AS n FROM documents WHERE team_id = ?').get(teamId).n, 0, 'no document points at it');
    assert.equal(db().prepare('SELECT COUNT(*) AS n FROM team_invites WHERE team_id = ?').get(teamId).n, 0, 'invites cascaded');
  }
});

// =====================================================================================================================
// Document access per role
// =====================================================================================================================

// Level an actor has on a team document owned by `owner`: 3 own, 2 write, 1 read, 0 none.
const levelOf = (actor, owner) => (actor === owner ? 3 : actor === 'X' ? 0 : actor === 'M' ? 1 : 2);

test('document access matrix: owner/admin/member/outsider x documents owned by owner/admin/member, every route and action', async () => {
  const s = await teamSetup();
  const X = await signup('Outsider');
  const users = { O: s.O, A: s.A, M: s.M, X };
  for (const ownerKey of ['O', 'A', 'M']) {
    for (const actorKey of ['O', 'A', 'M', 'X']) {
      const owner = users[ownerKey], actor = users[actorKey];
      const lv = levelOf(actorKey, ownerKey);
      const label = (what) => `${actorKey} on ${ownerKey}'s document: ${what}`;
      const check = (r, allowed, what, okStatus) => {
        if (!allowed) return assert.deepEqual(err(r), DNF, label(what));
        if (okStatus) assert.equal(r.status, okStatus, `${label(what)}: ${JSON.stringify(r.data)}`);
        else assert.notDeepEqual(err(r), DNF, label(what));
      };
      const d = await draft(owner);
      // write: PUT and send
      check(await actor(`/api/documents/${d.id}`, { method: 'PUT', body: { ...d.body, title: `edited ${rnd()}` } }), lv >= 2, 'PUT', 200);
      check(await actor(`/api/documents/${d.id}/send`, { body: {} }), lv >= 2, 'send', 200);
      if (lv < 2) assert.equal((await owner(`/api/documents/${d.id}/send`, { body: {} })).status, 200);
      // read: GET (signing tokens only for writers) and file
      const g = await actor(`/api/documents/${d.id}`, { method: 'GET' });
      check(g, lv >= 1, 'GET', 200);
      if (lv >= 1) {
        assert.equal(g.data.doc.status, 'sent');
        assert.equal(g.data.doc.team_id, s.teamId);
        assert.equal(g.data.recipients.every((r) => typeof r.token === 'string' && r.token.length > 20), lv >= 2, label('tokens iff write'));
        if (lv < 2) assert.ok(g.data.recipients.every((r) => !('token' in r) && !('token_hash' in r) && !('token_enc' in r)), label('no token fields'));
      }
      const f = await actor(`/api/documents/${d.id}/file`, { method: 'GET' });
      check(f, lv >= 1, 'file', 200);
      if (lv >= 1) assert.equal(f.data.subarray(0, 5).toString(), '%PDF-');
      check(await actor(`/api/documents/${d.id}/file?kind=signed`, { method: 'GET' }), lv >= 1, 'signed file (not signed yet)');
      // write: remind (unknown recipient), copy of a non-template
      check(await actor(`/api/documents/${d.id}/remind`, { body: { recipientId: 'nobody' } }), lv >= 2, 'remind');
      const cp = await actor(`/api/documents/${d.id}/copy`, { body: {} });
      check(cp, lv >= 2, 'copy (non-template)', 201);
      if (lv >= 2) {
        const c = (await getDoc(actor, cp.data.id)).doc;
        assert.deepEqual([c.owner_id, c.team_id, c.status], [actor.id, s.teamId, 'draft'], label('copy belongs to the copier, in the team'));
      }
      // bulk on a non-template: read is enough to reach the 409
      const bk = await actor(`/api/documents/${d.id}/bulk`, { body: { rows: [[{ name: 'P', email: 'p@example.com' }]] } });
      check(bk, lv >= 1, 'bulk (non-template)');
      if (lv >= 1) assert.deepEqual(err(bk), [409, 'Bulk send starts from a template'], label('bulk'));
      // own: move, public, share
      check(await actor(`/api/documents/${d.id}/move`, { body: { folderId: null } }), lv >= 3, 'move', 200);
      const pub = await actor(`/api/documents/${d.id}/public`, { body: { enabled: true } });
      check(pub, lv >= 3, 'public');
      if (lv >= 3) assert.deepEqual(err(pub), [409, 'Only templates can have a public link']);
      const sh = await actor(`/api/documents/${d.id}/share`, { body: { shared: true } });
      check(sh, lv >= 3, 'share', 200);
      if (lv >= 3) assert.deepEqual(sh.data, { teamShared: true });
      // write: void, then DELETE
      check(await actor(`/api/documents/${d.id}/void`, { body: { reason: 'matrix' } }), lv >= 2, 'void', 200);
      if (lv < 2) assert.equal((await owner(`/api/documents/${d.id}/void`, { body: { reason: 'matrix' } })).status, 200);
      if (lv === 2) {
        // The audit trail names the acting admin.
        const { props } = await page(owner, `/app/documents/${d.id}`);
        assert.ok(props.events.some((e) => e.actor === actor.userName), label(`audit actor ${actor.userName}: ${JSON.stringify(props.events.map((e) => [e.actor, e.action]))}`));
      }
      check(await actor(`/api/documents/${d.id}`, { method: 'DELETE' }), lv >= 2, 'DELETE', 200);
      if (lv >= 2 && DATA) assert.equal(db().prepare('SELECT deleted_by FROM audit_tombstones WHERE document_id = ?').get(d.id)?.deleted_by, actor.id, label('deleted_by'));
      if (lv < 2) assert.equal((await getDoc(owner, d.id)).doc.status, 'voided', label('still there'));
    }
  }
});

test('team templates: a member can view, copy and bulk send (JSON and CSV) but not edit, publish, share, move or delete; outsiders 404', async () => {
  const { O, A, M, teamId } = await teamSetup();
  const X = await signup('Outsider');
  const tpl = await template(O, ['Client']);
  const folder = (await O('/api/folders', { body: { name: `F ${rnd()}` } })).data.id;
  assert.equal((await O(`/api/documents/${tpl.id}/move`, { body: { folderId: folder } })).status, 200);
  // Member: read and use.
  assert.equal((await getDoc(M, tpl.id)).doc.is_template, 1);
  const cp = await M(`/api/documents/${tpl.id}/copy`, { body: {} });
  assert.equal(cp.status, 201, JSON.stringify(cp.data));
  const c = (await getDoc(M, cp.data.id)).doc;
  assert.deepEqual([c.owner_id, c.team_id, c.folder_id, c.is_template, c.status], [M.id, teamId, null, 0, 'draft'], 'copy: member owns it, no foreign folder');
  assert.equal((await M(`/api/documents/${cp.data.id}`, { method: 'PUT', body: { title: 'mine now' } })).status, 200, 'member can edit their copy');
  const oc = (await getDoc(O, (await O(`/api/documents/${tpl.id}/copy`, { body: {} })).data.id)).doc;
  assert.equal(oc.folder_id, folder, 'owner copy keeps the folder');
  const b = await M(`/api/documents/${tpl.id}/bulk`, { body: { rows: [[{ name: 'Ann', email: 'ann@example.com' }], [{ name: 'Bob', email: 'bob@example.com' }]] } });
  assert.equal(b.status, 201, JSON.stringify(b.data));
  assert.equal(b.data.created, 2);
  for (const id of b.data.documentIds) {
    const bd = await getDoc(M, id);
    assert.deepEqual([bd.doc.owner_id, bd.doc.team_id, bd.doc.status, bd.doc.folder_id], [M.id, teamId, 'sent', null]);
    assert.ok(bd.recipients.every((r) => r.token), 'sender gets signing links');
    assert.ok((await getDoc(A, id)).recipients.every((r) => r.token), 'admin manages it');
    assert.ok((await getDoc(O, id)).recipients.every((r) => r.token), 'owner manages it');
  }
  const csv = await M(`/api/documents/${tpl.id}/bulk`, { body: 'Cat,cat@example.com\n', headers: { 'Content-Type': 'text/csv' } });
  assert.equal(csv.status, 201, JSON.stringify(csv.data));
  assert.equal((await getDoc(M, csv.data.documentIds[0])).doc.owner_id, M.id);
  // Member: no write or own on the template.
  assert.deepEqual(err(await M(`/api/documents/${tpl.id}`, { method: 'PUT', body: { title: 'x' } })), DNF);
  assert.deepEqual(err(await M(`/api/documents/${tpl.id}`, { method: 'DELETE' })), DNF);
  for (const [a, body] of [['public', { enabled: true }], ['share', { shared: false }], ['move', { folderId: null }]]) {
    assert.deepEqual(err(await M(`/api/documents/${tpl.id}/${a}`, { body })), DNF, `member ${a}`);
  }
  // Admin: write but not own.
  assert.equal((await A(`/api/documents/${tpl.id}`, { method: 'PUT', body: tpl.body })).status, 200, 'admin edits the team template');
  assert.deepEqual(err(await A(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })), DNF);
  assert.deepEqual(err(await A(`/api/documents/${tpl.id}/share`, { body: { shared: false } })), DNF);
  assert.deepEqual(err(await A(`/api/documents/${tpl.id}/move`, { body: { folderId: null } })), DNF);
  assert.equal((await O(`/api/documents/${tpl.id}/public`, { body: { enabled: true } })).status, 200, 'owner publishes');
  // TW2-3: only the owner sees the public link; team members (readers and writers) get null.
  assert.match((await getDoc(O, tpl.id)).publicUrl, /^\/t\//, 'owner sees the public link');
  assert.equal((await getDoc(M, tpl.id)).publicUrl, null, 'member gets no public link');
  assert.equal((await getDoc(A, tpl.id)).publicUrl, null, 'admin gets no public link');
  // Outsider: nothing.
  for (const [a, body] of [['copy', {}], ['bulk', { rows: [[{ name: 'Z', email: 'z@example.com' }]] }]]) {
    assert.deepEqual(err(await X(`/api/documents/${tpl.id}/${a}`, { body })), DNF, `outsider ${a}`);
  }
  assert.deepEqual(err(await X(`/api/documents/${tpl.id}`, { method: 'GET' })), DNF);
  // A member's API key: read view without tokens; it can use the team template.
  const k = (await M('/api/api-keys', { body: { name: 'ci' } })).data.key;
  const viaKey = await bearer(k)(`/api/documents/${b.data.documentIds[0]}`, { method: 'GET' });
  assert.equal(viaKey.status, 200);
  assert.ok(viaKey.data.recipients.every((r) => !('token' in r)), 'no tokens over API keys');
  assert.equal((await bearer(k)(`/api/documents/${tpl.id}/copy`, { body: {} })).status, 201, 'member key uses a team template');
});

test('share action: owner only, boolean only, 409 outside a team; documents from before the team stay personal until shared', async () => {
  const { O, A, M, teamId } = await teamSetup({ personal: true });
  const p = O.personal;
  assert.equal((await getDoc(O, p.id)).doc.team_id, null, 'existing document stays personal');
  for (const u of [A, M]) assert.deepEqual(err(await u(`/api/documents/${p.id}`, { method: 'GET' })), DNF);
  assert.ok(!ids(await list(M)).includes(p.id));
  for (const shared of ['yes', 1, null, undefined]) {
    assert.deepEqual(err(await O(`/api/documents/${p.id}/share`, { body: { shared } })), [400, 'Send shared: true or false'], String(shared));
  }
  assert.equal((await O(`/api/documents/${p.id}/share`, { body: { shared: true }, headers: { Origin: EVIL } })).status, 403);
  assert.deepEqual((await O(`/api/documents/${p.id}/share`, { body: { shared: true } })).data, { teamShared: true });
  assert.equal((await getDoc(M, p.id)).doc.team_id, teamId);
  const item = (await list(M)).documents.find((d) => d.id === p.id);
  assert.deepEqual([item.ownerName, item.teamShared, item.folderId], ['Team Owner', true, null]);
  assert.deepEqual(err(await A(`/api/documents/${p.id}/share`, { body: { shared: false } })), DNF, 'admin cannot unshare');
  assert.deepEqual((await O(`/api/documents/${p.id}/share`, { body: { shared: false } })).data, { teamShared: false });
  for (const u of [A, M]) assert.deepEqual(err(await u(`/api/documents/${p.id}`, { method: 'GET' })), DNF);
  // TW2-8: each real change is in the audit trail; a repeat writes nothing.
  assert.deepEqual((await O(`/api/documents/${p.id}/share`, { body: { shared: false } })).data, { teamShared: false });
  const trail = (await page(O, `/app/documents/${p.id}`)).props.events.filter((e) => /^(Shared with team|Made private)$/.test(e.action));
  assert.deepEqual(trail.map((e) => [e.actor, e.action]), [['Team Owner', 'Shared with team'], ['Team Owner', 'Made private']]);
  // Outside any team.
  const X = await signup('Loner');
  const dx = await draft(X);
  assert.deepEqual(err(await X(`/api/documents/${dx.id}/share`, { body: { shared: true } })), [409, 'Join a team first']);
  assert.deepEqual((await X(`/api/documents/${dx.id}/share`, { body: { shared: false } })).data, { teamShared: false });
  assert.deepEqual(err(await O(`/api/documents/${dx.id}/share`, { body: { shared: true } })), DNF, 'someone else\'s document');
  // Uploads by team members are team documents.
  assert.equal((await getDoc(O, (await draft(M)).id)).doc.team_id, teamId);
});

// =====================================================================================================================
// Lists, dashboard and pages
// =====================================================================================================================

test('GET /api/documents and dashboard scopes: mine, team, all; ownerName/teamShared; folders stay personal; outsiders see nothing', async () => {
  const { O, A, M } = await teamSetup({ personal: true });
  const X = await signup('Outsider');
  const dO = await sent(O), dM = await draft(M), tO = await template(O), dX = await draft(X);
  const folder = (await O('/api/folders', { body: { name: `F ${rnd()}` } })).data.id;
  assert.equal((await O(`/api/documents/${dO.id}/move`, { body: { folderId: folder } })).status, 200);
  const all = await list(M);
  assert.deepEqual(ids(all), [dO.id, dM.id, tO.id].sort());
  assert.equal(all.total, 3);
  const o = all.documents.find((d) => d.id === dO.id);
  assert.deepEqual([o.ownerName, o.teamShared, o.folderId], ['Team Owner', true, null], 'someone else\'s folder hidden');
  assert.equal(all.documents.find((d) => d.id === dM.id).ownerName, 'Team Member');
  assert.deepEqual(ids(await list(M, '?scope=mine')), [dM.id]);
  assert.deepEqual(ids(await list(M, '?scope=team')), [dO.id, dM.id, tO.id].sort());
  assert.deepEqual(ids(await list(M, '?scope=team&template=1')), [tO.id]);
  assert.equal((await list(M, `?folder=${folder}`)).total, 0, 'folder filter only matches own folders');
  assert.deepEqual(ids(await list(O, `?folder=${folder}`)), [dO.id]);
  assert.deepEqual(ids(await list(O, '?scope=mine')), [O.personal.id, dO.id, tO.id].sort());
  assert.deepEqual(ids(await list(O)), [O.personal.id, dO.id, dM.id, tO.id].sort());
  assert.equal((await list(O)).documents.find((d) => d.id === O.personal.id).teamShared, false);
  assert.deepEqual(ids(await list(X)), [dX.id]);
  assert.deepEqual(await list(X, '?scope=team'), { documents: [], total: 0 }, 'no team: empty team scope');

  // Dashboard (SSR).
  const dash = async (u, qs = '') => (await page(u, `/app${qs}`)).props;
  const m = await dash(M);
  assert.deepEqual([m.inTeam, m.scope], [true, 'all']);
  assert.deepEqual(m.docs.map((d) => d.id).sort(), [dO.id, dM.id].sort(), 'documents (templates excluded)');
  const row = m.docs.find((d) => d.id === dO.id);
  assert.deepEqual([row.mine, row.ownerName, row.teamShared, row.canWrite], [false, 'Team Owner', true, false]);
  const own = m.docs.find((d) => d.id === dM.id);
  assert.deepEqual([own.mine, own.ownerName, own.canWrite], [true, null, true]);
  assert.deepEqual((await dash(M, '?scope=mine')).docs.map((d) => d.id), [dM.id]);
  const mt = await dash(M, '?scope=team');
  assert.equal(mt.scope, 'team');
  assert.deepEqual(mt.docs.map((d) => d.id).sort(), [dO.id, dM.id].sort());
  assert.deepEqual((await dash(M, '?view=templates')).docs.map((d) => d.id), [tO.id], 'team templates');
  assert.equal((await dash(A)).docs.find((d) => d.id === dO.id).canWrite, true, 'admin can write');
  assert.ok(!(await dash(O, '?scope=team')).docs.some((d) => d.id === O.personal.id), 'personal document not in team scope');
  assert.ok((await dash(O, '?scope=mine')).docs.some((d) => d.id === O.personal.id));
  const x = await dash(X, '?scope=team');
  assert.deepEqual([x.inTeam, x.scope, x.docs.map((d) => d.id)], [false, 'all', [dX.id]]);
  const h = (await page(M, '/app?scope=team')).html;
  assert.ok(h.includes(dO.title) && h.includes('Team Owner'), 'team row with owner name rendered');
  // Folders are personal: the owner's folder id must not reach a member (the API list already hides it).
  assert.equal(m.docs.find((d) => d.id === dO.id).folderId, null, 'owner folder id not exposed to member on the dashboard');
});

test('pages: /app/team per role, /join/<token> (signed out, right and wrong account, dead link), document page and editor per role', async () => {
  const { O, A, M, name } = await teamSetup();
  const X = await signup('Outsider');
  // /app/team
  const ot = await page(O, '/app/team');
  assert.deepEqual([ot.props.team.role, ot.props.team.name, ot.props.members.length], ['owner', name, 3]);
  assert.ok(ot.html.includes(name));
  const target = await signup('Join Target');
  const inv = await invite(O, target.email, 'admin');
  assert.ok((await page(O, '/app/team')).props.invites.some((i) => i.id === inv.id && i.email === target.email));
  assert.ok((await page(A, '/app/team')).props.invites.some((i) => i.id === inv.id));
  const mt = await page(M, '/app/team');
  assert.deepEqual([mt.props.team.role, mt.props.invites], ['member', []]);
  assert.equal((await page(X, '/app/team')).props.team, null);
  const out = await client()('/app/team', { method: 'GET' });
  assert.equal(out.status, 307);
  assert.match(out.headers.get('location'), /^\/login\?next=/);
  // /join/<token>
  const anon = await page(client(), inv.url);
  assert.deepEqual(anon.props.invite, { teamName: name, inviterName: 'Team Owner', email: target.email, role: 'admin', canSignUp: true });
  assert.equal(anon.props.user, null);
  assert.ok(anon.html.includes(name) && anon.html.includes('Team Owner'));
  assert.ok(!anon.html.includes(O.email), 'inviter email not shown');
  assert.deepEqual((await page(target, inv.url)).props.user, { name: 'Join Target', email: target.email });
  assert.deepEqual((await page(X, inv.url)).props.user, { name: 'Outsider', email: X.email }, 'other account: page explains');
  const dead = await page(client(), `/join/${'A'.repeat(43)}`, 404);
  assert.equal(dead.props.invite, null);
  assert.ok(dead.html.includes('This invite is not active'));
  await join(target, inv.url);
  assert.equal((await page(client(), inv.url, 404)).props.invite, null, 'accepted link');

  // Document page and editor.
  const sentDoc = await sent(O), draftDoc = await draft(O);
  const mp = await page(M, `/app/documents/${sentDoc.id}`);
  assert.deepEqual([mp.props.canWrite, mp.props.isOwner, mp.props.inTeam, mp.props.ownerName], [false, false, true, 'Team Owner']);
  assert.ok(mp.props.recipients.length && mp.props.recipients.every((r) => !('token' in r) && !('token_hash' in r) && !('token_enc' in r)), 'member page has no signing tokens');
  assert.ok(!('public_token_hash' in mp.props.doc) && !('public_token_enc' in mp.props.doc));
  assert.ok(mp.html.includes(sentDoc.title));
  const ap = await page(A, `/app/documents/${sentDoc.id}`);
  assert.deepEqual([ap.props.canWrite, ap.props.isOwner], [true, false]);
  assert.ok(ap.props.recipients.every((r) => typeof r.token === 'string'), 'admin page has tokens');
  const op = await page(O, `/app/documents/${sentDoc.id}`);
  assert.deepEqual([op.props.canWrite, op.props.isOwner, op.props.ownerName], [true, true, null]);
  // Draft: the member sees it read-only on the document page; the editor sends the member there.
  const md = await page(M, `/app/documents/${draftDoc.id}`);
  assert.deepEqual([md.props.doc.status, md.props.canWrite], ['draft', false]);
  const me = await M(`/app/documents/${draftDoc.id}/edit`, { method: 'GET' });
  assert.deepEqual([me.status, me.headers.get('location')], [307, `/app/documents/${draftDoc.id}`], 'member redirected away from the editor');
  for (const u of [O, A]) {
    const r = await u(`/app/documents/${draftDoc.id}`, { method: 'GET' });
    assert.deepEqual([r.status, r.headers.get('location')], [307, `/app/documents/${draftDoc.id}/edit`], 'writers go to the editor');
  }
  const ae = await page(A, `/app/documents/${draftDoc.id}/edit`);
  assert.deepEqual([ae.props.doc.isOwner, ae.props.doc.teamShared, ae.props.doc.publicUrl, ae.props.inTeam], [false, true, null, true]);
  const oe = await page(O, `/app/documents/${draftDoc.id}/edit`);
  assert.deepEqual([oe.props.doc.isOwner, oe.props.doc.teamShared], [true, true]);
  const mine = await draft(M);
  assert.equal((await page(M, `/app/documents/${mine.id}/edit`)).props.doc.isOwner, true, 'member edits own draft');
  // Outsider: no page and no title leak.
  for (const p of [`/app/documents/${sentDoc.id}`, `/app/documents/${draftDoc.id}/edit`]) {
    const r = await X(p, { method: 'GET' });
    const body = r.data.toString();
    assert.ok(!body.includes(sentDoc.title) && !body.includes(draftDoc.title), `${p}: no title leak`);
    assert.equal(r.status, 404, `${p}: outsider gets 404 (got ${r.status})`);
  }
});

