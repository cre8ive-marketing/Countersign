// Self-check for teams (lib/teams.js) and the team scope of listDocuments (lib/folders.js).
// Run: node scripts/teams-selfcheck.mjs   (uses a throwaway DATA_DIR and key)
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-teams-'));
process.env.DATA_DIR = dir;
process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
process.env.ALLOW_SIGNUP = 'true'; // the closed-server rules (TW2-1) are checked at the end
console.log = () => {};

const T = await import('../lib/teams.js');
const { listDocuments } = await import('../lib/folders.js');
const { keyedHash } = await import('../lib/crypto.js');
const { createUser } = await import('../lib/auth.js');
const { default: db, now, tx } = await import('../lib/db.js');

const fault = (fn) => { try { fn(); } catch (e) { return [e.status, e.message]; } return null; };
const st = (fn) => fault(fn)?.[0] ?? 0;
const mk = (name) => { const email = `${name.toLowerCase()}@x.io`; return { id: createUser({ email, name, password: 'correct horse battery' }), email, name }; };
const [own, adm, mem, mem2, out, late] = ['Olga', 'Adam', 'Mia', 'Max', 'Otto', 'Lena'].map(mk);
const t0 = now();
const addDoc = (owner, team = null) => {
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO documents (id, owner_id, team_id, title, original_sha256, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, owner.id, team, 'Doc', 'x', t0, t0);
  return { doc: db.prepare('SELECT * FROM documents WHERE id = ?').get(id) };
};
const teamIdOfDoc = (d) => db.prepare('SELECT team_id FROM documents WHERE id = ?').get(d.doc.id).team_id;
const join = (inviter, invitee, role) => T.acceptInvite(invitee, T.createInvite(inviter, { email: invitee.email, role }).url.slice(6));

// --- Create, one team per user.
assert.equal(T.teamOf(own.id), null);
assert.deepEqual(T.getTeam(own), { team: null });
assert.deepEqual(fault(() => T.createTeam(own, { name: ' ' })), [400, 'Enter a team name']);
assert.equal(st(() => T.createTeam(own, { name: 'x'.repeat(81) })), 400);
const teamId = T.createTeam(own, { name: ' Acme ' });
assert.deepEqual(T.teamOf(own.id), { teamId, role: 'owner' });
assert.deepEqual(fault(() => T.createTeam(own, { name: 'Other' })), [409, 'You are already in a team']);

// --- Invites: token format, keyed hash storage, roles.
const inv = T.createInvite(own, { email: ' ADAM@x.io ', role: 'admin' });
assert.match(inv.url, /^\/join\/[A-Za-z0-9_-]{43}$/);
const token = inv.url.slice(6);
const row = db.prepare('SELECT * FROM team_invites WHERE id = ?').get(inv.id);
assert.equal(row.token_hash, keyedHash('team-invite', token));
assert.notEqual(row.token_hash, crypto.createHash('sha256').update(token).digest('hex'));
assert.equal(JSON.stringify(row).includes(token), false, 'token never stored');
assert.equal(row.email, 'adam@x.io');
assert.ok(Math.abs(Date.parse(row.expires_at) - Date.now() - 7 * 864e5) < 60e3, 'expires in 7 days');
assert.deepEqual(T.inviteByToken(token), { teamName: 'Acme', inviterName: 'Olga', email: 'adam@x.io', role: 'admin' });
assert.equal(T.inviteByToken('nope'), null);
assert.equal(T.inviteByToken(42), null);
assert.equal(st(() => T.createInvite(own, { email: 'bad', role: 'member' })), 400);
assert.equal(st(() => T.createInvite(own, { email: 'a@x.io', role: 'owner' })), 400);
assert.equal(st(() => T.createInvite(out, { email: 'a@x.io' })), 409); // not in a team

// Email mismatch 403, then accept.
assert.deepEqual(fault(() => T.acceptInvite(mem, token)), [403, 'This invite is for a different email address']);
assert.deepEqual(T.acceptInvite({ ...adm, email: 'Adam@X.io' }, token), { teamId, role: 'admin' }); // case-insensitive
assert.equal(st(() => T.acceptInvite(adm, token)), 404); // used
assert.equal(T.inviteByToken(token), null);
assert.deepEqual(fault(() => T.createInvite(own, { email: 'adam@x.io' })), [409, 'This person is already in your team']);

// Admins invite members only; members can't invite.
assert.deepEqual(fault(() => T.createInvite(adm, { email: mem.email, role: 'admin' })), [403, 'Admins can only invite members']);
join(adm, mem, 'member');
assert.deepEqual(T.teamOf(mem.id), { teamId, role: 'member' });
assert.equal(st(() => T.createInvite(mem, { email: mem2.email })), 403);

// Replacing a pending invite revokes the old token; revoke; expiry.
const a1 = T.createInvite(own, { email: mem2.email }).url.slice(6);
const a2 = T.createInvite(own, { email: mem2.email }).url.slice(6);
assert.equal(T.inviteByToken(a1), null);
assert.equal(T.getTeam(own).invites.length, 1);
assert.equal(T.getTeam(mem).invites, undefined); // members don't see invites
const a2id = T.getTeam(own).invites[0].id;
assert.equal(st(() => T.revokeInvite(mem, a2id)), 403);
T.revokeInvite(adm, a2id);
assert.equal(T.inviteByToken(a2), null);
assert.equal(st(() => T.revokeInvite(own, a2id)), 404);
const a3 = T.createInvite(own, { email: mem2.email }).url.slice(6);
db.prepare('UPDATE team_invites SET expires_at = ? WHERE token_hash = ?').run(new Date(Date.now() - 1000).toISOString(), keyedHash('team-invite', a3));
assert.equal(T.inviteByToken(a3), null);
assert.equal(st(() => T.acceptInvite(mem2, a3)), 404);
join(own, mem2, 'member');

// TW2-2: someone's pending invites are revoked when they are demoted to member or leave; others' invites survive.
const pendingBy = (u) => db.prepare('SELECT COUNT(*) AS n FROM team_invites WHERE created_by = ? AND accepted_at IS NULL AND revoked_at IS NULL').get(u.id).n;
const ownPending = pendingBy(own);
T.setRole(own, mem2.id, 'admin');
const byMem2 = T.createInvite(mem2, { email: 'via-mem2@x.io' }).url.slice(6);
T.setRole(own, mem2.id, 'member');
assert.equal(T.inviteByToken(byMem2), null);
assert.equal(pendingBy(mem2), 0);
T.setRole(own, mem2.id, 'admin');
const byMem2b = T.createInvite(mem2, { email: 'via-mem2@x.io' }).url.slice(6);
T.leaveTeam(mem2);
assert.equal(T.inviteByToken(byMem2b), null);
assert.equal(pendingBy(own), ownPending);
join(own, mem2, 'member');

// Already in another team: 409.
T.createTeam(out, { name: 'Rival' });
const toOut = T.createInvite(own, { email: out.email }).url.slice(6);
assert.deepEqual(fault(() => T.acceptInvite(out, toOut)), [409, 'You are already in a team']);
// joinWithInvite inside signup's transaction: a failed join rolls back the new user.
const lateTok = T.createInvite(own, { email: 'late2@x.io' }).url.slice(6);
assert.equal(st(() => tx(() => { const id = createUser({ email: 'wrong@x.io', name: 'W', password: 'correct horse battery' }); T.joinWithInvite({ id, email: 'wrong@x.io' }, lateTok); })), 403);
assert.equal(db.prepare("SELECT 1 FROM users WHERE email = 'wrong@x.io'").get(), undefined);

// Pending cap.
for (let i = 0; T.getTeam(own).invites.length < T.INVITES_MAX; i++) T.createInvite(own, { email: `p${i}@x.io` });
assert.equal(st(() => T.createInvite(own, { email: 'one-more@x.io' })), 409);

// --- Roles.
assert.equal(st(() => T.setRole(adm, mem.id, 'admin')), 403); // owner only
assert.equal(st(() => T.setRole(own, mem.id, 'boss')), 400);
assert.equal(st(() => T.setRole(own, out.id, 'admin')), 404); // not in this team
assert.equal(st(() => T.setRole(own, own.id, 'member')), 400); // owner cannot demote themselves
T.setRole(own, mem2.id, 'admin');
assert.equal(T.teamOf(mem2.id).role, 'admin');
T.setRole(own, mem2.id, 'member');

// --- Documents: listing scope and removal.
const dOwn = addDoc(own, teamId);
const dMem = addDoc(mem, teamId);
const dMemPrivate = addDoc(mem);
const dOut = addDoc(out);
const ids = (u, q) => listDocuments(u, q).documents.map((d) => d.id).sort();
assert.deepEqual(ids(mem2, {}), [dOwn.doc.id, dMem.doc.id].sort());
assert.deepEqual(ids(mem, {}), [dOwn.doc.id, dMem.doc.id, dMemPrivate.doc.id].sort());
assert.deepEqual(ids(mem, { scope: 'mine' }), [dMem.doc.id, dMemPrivate.doc.id].sort());
assert.deepEqual(ids(mem, { scope: 'team' }), [dOwn.doc.id, dMem.doc.id].sort());
assert.deepEqual(ids(out, {}), [dOut.doc.id]);
assert.deepEqual(ids(late, { scope: 'team' }), []); // no team
const item = listDocuments(mem2, {}).documents.find((d) => d.id === dOwn.doc.id);
assert.equal(item.ownerName, 'Olga');
assert.equal(item.teamShared, true);

// shareDocument lives in lib/documents.js (extensionless imports); test/teams.test.mjs covers it over HTTP.

// Remove: admins can't remove owner/admins; members can't remove anyone; removed user's docs go personal.
assert.equal(st(() => T.removeMember(mem, mem2.id)), 403);
T.setRole(own, mem2.id, 'admin');
assert.deepEqual(fault(() => T.removeMember(adm, mem2.id)), [403, 'Admins can only remove members']);
assert.equal(st(() => T.removeMember(adm, own.id)), 403);
assert.equal(st(() => T.removeMember(adm, adm.id)), 400);
assert.equal(st(() => T.removeMember(adm, out.id)), 404);
T.removeMember(adm, mem.id);
assert.equal(T.teamOf(mem.id), null);
assert.equal(teamIdOfDoc(dMem), null);
assert.equal(teamIdOfDoc(dOwn), teamId);
T.removeMember(own, mem2.id); // owner may remove an admin

// --- Owner transfer and leaving.
assert.deepEqual(fault(() => T.leaveTeam(own)), [409, 'Make someone else the owner before you leave']);
assert.equal(st(() => T.renameTeam(adm, { name: 'X' })), 403);
T.renameTeam(own, { name: 'Acme Ltd' });
assert.equal(T.getTeam(adm).team.name, 'Acme Ltd');
T.setRole(own, adm.id, 'owner');
assert.equal(T.teamOf(adm.id).role, 'owner');
assert.equal(T.teamOf(own.id).role, 'admin');
assert.equal(db.prepare("SELECT COUNT(*) AS n FROM team_members WHERE team_id = ? AND role = 'owner'").get(teamId).n, 1);
assert.deepEqual(T.leaveTeam(own), { teamId, deleted: false });
assert.equal(teamIdOfDoc(dOwn), null);
assert.equal(st(() => T.leaveTeam(own)), 409); // no team any more

// Only member left: owner leaving deletes the team; every document goes personal.
const dAdm = addDoc(adm, teamId);
assert.deepEqual(T.leaveTeam(adm), { teamId, deleted: true });
assert.equal(teamIdOfDoc(dAdm), null);
assert.equal(db.prepare('SELECT COUNT(*) AS n FROM team_invites WHERE team_id = ?').get(teamId).n, 0); // cascade

// deleteTeam: owner only; documents go personal, members freed.
const rival = T.teamOf(out.id).teamId;
join(out, mem, 'member');
const dRival = addDoc(mem, rival);
assert.equal(st(() => T.deleteTeam(mem)), 403);
T.deleteTeam(out);
assert.equal(T.teamOf(mem.id), null);
assert.equal(teamIdOfDoc(dRival), null);
assert.equal(db.prepare('SELECT COUNT(*) AS n FROM teams').get().n, 0);

// User deletion cascades their membership.
const t2 = T.createTeam(late, { name: 'Solo' });
db.prepare('DELETE FROM users WHERE id = ?').run(late.id);
assert.equal(db.prepare('SELECT COUNT(*) AS n FROM team_members WHERE team_id = ?').get(t2).n, 0);

// --- TW2-1: sign-ups closed. Only the first account (earliest created_at, then id) may create a team, and invite
// sign-up only works for a team that account owns. mem's team is made while sign-ups are still open.
db.prepare("UPDATE users SET created_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(own.id);
const memTeam = T.createTeam(mem, { name: 'Made while open' });
const toMemTeam = T.createInvite(mem, { email: 'new2@x.io' }).url.slice(6);
process.env.ALLOW_SIGNUP = 'false';
assert.equal(T.canCreateTeam(own), true);
assert.equal(T.canCreateTeam(mem2), false);
assert.deepEqual(fault(() => T.createTeam(mem2, { name: 'Nope' })), [403, "Only the server's first account can create teams while sign-ups are closed"]);
assert.equal(T.teamOf(mem2.id), null);
const firstTeam = T.createTeam(own, { name: 'First' });
const signupJoin = (email, tok) => tx(() => { const id = createUser({ email, name: 'N', passwordHash: 'x' }); return T.joinWithInvite({ id, email }, tok, { signupClosed: true }); });
assert.deepEqual(signupJoin('new1@x.io', T.createInvite(own, { email: 'new1@x.io' }).url.slice(6)), { teamId: firstTeam, role: 'member' });
assert.deepEqual(fault(() => signupJoin('new2@x.io', toMemTeam)), [403, 'Sign-ups are closed on this server. Ask the admin for an account.']);
assert.equal(db.prepare("SELECT 1 FROM users WHERE email = 'new2@x.io'").get(), undefined); // rolled back
assert.ok(T.inviteByToken(toMemTeam)); // invite itself untouched
assert.equal(T.teamOf(mem.id).teamId, memTeam);
process.env.ALLOW_SIGNUP = 'true';
assert.equal(T.canCreateTeam(mem2), true);

try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* Windows: db file still open */ }
process.stdout.write('teams selfcheck: ok\n');
