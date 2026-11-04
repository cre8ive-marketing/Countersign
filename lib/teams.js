import crypto from 'node:crypto';
import db, { newId, now, tx } from './db.js';
import { fail, EMAIL } from './http.js';
import { cleanName } from './apikeys.js';
import { keyedHash } from './crypto.js';
import { signupOpen } from './auth.js';

// One team per user (team_members.user_id is UNIQUE). Roles: owner (exactly one), admin, member.
// Contacts, signatures, email templates, API keys, webhooks and folders stay per user; only documents are shared.
export const INVITES_MAX = 50;
const INVITE_TTL_MS = 7 * 864e5;
const ROLES = ['owner', 'admin', 'member'];
const hashInvite = (token) => keyedHash('team-invite', token);

export function teamOf(userId) {
  const row = db.prepare('SELECT team_id, role FROM team_members WHERE user_id = ?').get(String(userId));
  return row ? { teamId: row.team_id, role: row.role } : null;
}

function mine(user, roles = ROLES) {
  const t = teamOf(user.id);
  if (!t) fail(409, 'Join a team first');
  if (!roles.includes(t.role)) fail(403, roles.length === 1 ? 'Only the team owner can do this' : 'Only team owners and admins can do this');
  return t;
}

// Pending invites someone created stop working once they can no longer invite.
const revokeInvitesBy = (teamId, userId) => db.prepare('UPDATE team_invites SET revoked_at = ? WHERE team_id = ? AND created_by = ? AND accepted_at IS NULL AND revoked_at IS NULL')
  .run(now(), teamId, String(userId));

// Leaving or removal: that user's team documents go back to personal.
function dropMember(teamId, userId) {
  db.prepare('DELETE FROM team_members WHERE team_id = ? AND user_id = ?').run(teamId, userId);
  db.prepare('UPDATE documents SET team_id = NULL WHERE team_id = ? AND owner_id = ?').run(teamId, userId);
  revokeInvitesBy(teamId, userId);
}

// The server's first account: earliest created_at, tie-broken by id.
const firstUserId = () => db.prepare('SELECT id FROM users ORDER BY created_at, id LIMIT 1').get()?.id ?? null;

// Invites can create accounts, so while sign-ups are closed only the first account may run a team.
export const canCreateTeam = (user) => signupOpen() || String(user.id) === firstUserId();

export function createTeam(user, input) {
  const name = cleanName(input?.name, 'Enter a team name');
  return tx(() => {
    if (!canCreateTeam(user)) fail(403, "Only the server's first account can create teams while sign-ups are closed");
    if (teamOf(user.id)) fail(409, 'You are already in a team');
    const id = newId();
    const t = now();
    db.prepare('INSERT INTO teams (id, name, created_at) VALUES (?, ?, ?)').run(id, name, t);
    db.prepare("INSERT INTO team_members (team_id, user_id, role, joined_at) VALUES (?, ?, 'owner', ?)").run(id, user.id, t);
    return id;
  });
}

export function getTeam(user) {
  const t = teamOf(user.id);
  if (!t) return { team: null };
  const { name } = db.prepare('SELECT name FROM teams WHERE id = ?').get(t.teamId);
  const members = db.prepare(`SELECT u.id, u.name, u.email, m.role, m.joined_at FROM team_members m JOIN users u ON u.id = m.user_id
    WHERE m.team_id = ? ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, u.name COLLATE NOCASE`).all(t.teamId)
    .map((m) => ({ userId: m.id, name: m.name, email: m.email, role: m.role, joinedAt: m.joined_at }));
  const out = { team: { id: t.teamId, name, role: t.role }, members };
  if (t.role !== 'member') {
    out.invites = db.prepare(`SELECT id, email, role, created_at, expires_at FROM team_invites
      WHERE team_id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC`).all(t.teamId, now())
      .map((i) => ({ id: i.id, email: i.email, role: i.role, createdAt: i.created_at, expiresAt: i.expires_at }));
  }
  return out;
}

export function renameTeam(user, input) {
  const name = cleanName(input?.name, 'Enter a team name');
  db.prepare('UPDATE teams SET name = ? WHERE id = ?').run(name, mine(user, ['owner']).teamId);
}

export function deleteTeam(user) {
  tx(() => {
    const { teamId } = mine(user, ['owner']);
    db.prepare('UPDATE documents SET team_id = NULL WHERE team_id = ?').run(teamId);
    db.prepare('DELETE FROM teams WHERE id = ?').run(teamId); // members and invites cascade
  });
}

const memberRole = (teamId, userId) => db.prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?').get(teamId, String(userId))?.role;

// Owner only. Making someone owner demotes the current owner to admin.
export function setRole(user, memberId, role) {
  if (!ROLES.includes(role)) fail(400, 'Choose owner, admin or member');
  tx(() => {
    const { teamId } = mine(user, ['owner']);
    if (String(memberId) === user.id) fail(400, 'You cannot change your own role. Make someone else the owner first.');
    if (!memberRole(teamId, memberId)) fail(404, 'Member not found');
    if (role === 'owner') db.prepare("UPDATE team_members SET role = 'admin' WHERE team_id = ? AND user_id = ?").run(teamId, user.id);
    db.prepare('UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?').run(role, teamId, String(memberId));
    if (role === 'member') revokeInvitesBy(teamId, memberId);
  });
}

// Owner/admin. Admins cannot remove the owner or other admins. Use leaveTeam for yourself.
export function removeMember(user, memberId) {
  tx(() => {
    const t = mine(user, ['owner', 'admin']);
    if (String(memberId) === user.id) fail(400, 'Use Leave team to remove yourself');
    const role = memberRole(t.teamId, memberId);
    if (!role) fail(404, 'Member not found');
    if (t.role === 'admin' && role !== 'member') fail(403, 'Admins can only remove members');
    dropMember(t.teamId, String(memberId));
  });
}

// The owner must transfer ownership first, unless they are the only member (then the team is deleted).
export function leaveTeam(user) {
  return tx(() => {
    const t = mine(user);
    if (t.role === 'owner') {
      if (db.prepare('SELECT COUNT(*) AS n FROM team_members WHERE team_id = ?').get(t.teamId).n > 1) fail(409, 'Make someone else the owner before you leave');
      db.prepare('UPDATE documents SET team_id = NULL WHERE team_id = ?').run(t.teamId);
      db.prepare('DELETE FROM teams WHERE id = ?').run(t.teamId);
      return { teamId: t.teamId, deleted: true };
    }
    dropMember(t.teamId, user.id);
    return { teamId: t.teamId, deleted: false };
  });
}

// Owner/admin; admins may only invite members. Returns the token once (in url); only its keyed hash is stored.
export function createInvite(user, input) {
  const email = typeof input?.email === 'string' ? input.email.trim().toLowerCase() : '';
  const role = input?.role ?? 'member';
  if (!EMAIL.test(email) || email.length > 254) fail(400, 'Enter a valid email address');
  if (role !== 'admin' && role !== 'member') fail(400, 'Choose admin or member');
  return tx(() => {
    const t = mine(user, ['owner', 'admin']);
    if (t.role === 'admin' && role !== 'member') fail(403, 'Admins can only invite members');
    if (db.prepare('SELECT 1 FROM team_members m JOIN users u ON u.id = m.user_id WHERE m.team_id = ? AND u.email = ?').get(t.teamId, email)) {
      fail(409, 'This person is already in your team');
    }
    const t0 = now();
    db.prepare('UPDATE team_invites SET revoked_at = ? WHERE team_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL').run(t0, t.teamId, email);
    const pending = db.prepare('SELECT COUNT(*) AS n FROM team_invites WHERE team_id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?').get(t.teamId, t0).n;
    if (pending >= INVITES_MAX) fail(409, `You can have up to ${INVITES_MAX} pending invites`);
    const id = newId();
    const token = crypto.randomBytes(32).toString('base64url');
    db.prepare('INSERT INTO team_invites (id, team_id, email, role, token_hash, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, t.teamId, email, role, hashInvite(token), user.id, t0, new Date(Date.now() + INVITE_TTL_MS).toISOString());
    const teamName = db.prepare('SELECT name FROM teams WHERE id = ?').get(t.teamId).name;
    return { id, url: `/join/${token}`, email, role, teamName };
  });
}

export function revokeInvite(user, id) {
  const { teamId } = mine(user, ['owner', 'admin']);
  const { changes } = db.prepare('UPDATE team_invites SET revoked_at = ? WHERE id = ? AND team_id = ? AND accepted_at IS NULL AND revoked_at IS NULL')
    .run(now(), String(id), teamId);
  if (!changes) fail(404, 'Invite not found');
}

function liveInvite(token) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  return db.prepare(`SELECT i.id, i.team_id, i.email, i.role, t.name AS team_name, u.name AS inviter_name FROM team_invites i
    JOIN teams t ON t.id = i.team_id LEFT JOIN users u ON u.id = i.created_by
    WHERE i.token_hash = ? AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?`).get(hashInvite(token), now()) ?? null;
}

// null when unknown, expired, accepted or revoked.
// While sign-ups are closed an invite may create an account only for a team the first account owns.
// So handing that ownership to someone else stops invite sign-ups until sign-ups open.
function inviteCanSignUp(teamId) {
  if (signupOpen()) return true;
  const owner = db.prepare("SELECT user_id FROM team_members WHERE team_id = ? AND role = 'owner'").get(teamId)?.user_id;
  return Boolean(owner) && owner === firstUserId();
}

export function inviteByToken(token) {
  const i = liveInvite(token);
  return i && { teamName: i.team_name, inviterName: i.inviter_name ?? '', email: i.email, role: i.role, canSignUp: inviteCanSignUp(i.team_id) };
}

// For callers already inside tx() (signup creates the user and joins in one transaction).
// signupClosed: the invite is creating an account on a closed server, so its team must be owned by the first account.
export function joinWithInvite(user, token, { signupClosed = false } = {}) {
  const i = liveInvite(token);
  if (!i) fail(404, 'This invite link is invalid or has expired');
  if (signupClosed && !inviteCanSignUp(i.team_id)) fail(403, 'Sign-ups are closed on this server. Ask the admin for an account.');
  if (String(user.email).toLowerCase() !== i.email.toLowerCase()) fail(403, 'This invite is for a different email address');
  if (teamOf(user.id)) fail(409, 'You are already in a team');
  const t = now();
  db.prepare('INSERT INTO team_members (team_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)').run(i.team_id, user.id, i.role, t);
  db.prepare('UPDATE team_invites SET accepted_at = ? WHERE id = ?').run(t, i.id);
  return { teamId: i.team_id, role: i.role };
}

export const acceptInvite = (user, token) => tx(() => joinWithInvite(user, token));

