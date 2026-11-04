import { useRef, useState } from 'react';
import { useRouter } from 'next/router';
import { Crown, LogOut, Mail, Plus, Trash2, UserMinus, Users } from 'lucide-react';
import { signupOpen, withUser } from '../../lib/auth';
import { canCreateTeam, getTeam } from '../../lib/teams';
import { mailEnabled } from '../../lib/mail';
import { apiFetch, formatDate } from '../../lib/client';
import AppShell from '../../components/AppShell';
import { Avatar, Button, TextField } from '../../components/ui';
import { ConfirmDialog, OneTimeSecret } from '../../components/DeveloperSettings';

export const getServerSideProps = withUser(async (ctx, user) => {
  const { team, members, invites } = getTeam(user);
  return { props: { user, team: team ?? null, members: members ?? [], invites: invites ?? [], mail: mailEnabled(), canCreate: canCreateTeam(user), transferStopsInvites: !signupOpen() && canCreateTeam(user) } };
});

const ROLE_LABEL = { owner: 'Owner', admin: 'Admin', member: 'Member' };

export default function Team({ user, team, members, invites, mail, canCreate, transferStopsInvites }) {
  const router = useRouter();
  const refresh = () => router.replace(router.asPath);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [confirming, setConfirming] = useState(null); // { title, body, action, icon, run }
  const confirmDialog = useRef(null);

  async function run(key, fn) {
    setBusy(key);
    setError(null);
    try {
      await fn();
      return true;
    } catch (e) {
      setError(e.message);
      return false;
    } finally {
      setBusy(null);
    }
  }

  function ask(c) {
    setConfirming(c);
    setError(null);
    confirmDialog.current?.showModal();
  }

  async function confirmed() {
    if (await run('confirm', confirming.run)) {
      confirmDialog.current?.close();
      refresh();
    }
  }

  return (
    <AppShell user={user} title="Team">
      <div className="page page-narrow">
        <header className="page-head">
          <div>
            <h1>Team</h1>
            <p className="page-sub">Share documents and templates with the people you work with. Contacts, signatures, folders, API keys and webhooks stay personal.</p>
          </div>
        </header>

        {error && !confirming && <div className="banner banner-bad" role="alert">{error}</div>}

        {team
          ? <TeamView {...{ user, team, members, invites, mail, transferStopsInvites, busy, run, ask, refresh }} />
          : canCreate
            ? <CreateTeam run={run} busy={busy} refresh={refresh} />
            : (
              <section className="card form-card">
                <div className="form-card-head"><h2>No team yet</h2><p>Teams on this server are set up by its administrator. Ask them for an invite link.</p></div>
              </section>
            )}

        <ConfirmDialog dialogRef={confirmDialog} id="team-confirm-title" title={confirming?.title ?? ''} body={confirming?.body ?? ''}
          action={confirming?.action ?? ''} icon={confirming?.icon} busy={busy === 'confirm'} error={confirming && error}
          onConfirm={confirmed} onClose={() => { setConfirming(null); setError(null); }} />
      </div>
    </AppShell>
  );
}

function CreateTeam({ run, busy, refresh }) {
  const [name, setName] = useState('');
  async function create(e) {
    e.preventDefault();
    if (await run('create', () => apiFetch('/api/teams', { body: { name } }))) refresh();
  }
  return (
    <form className="card form-card" onSubmit={create}>
      <div className="form-card-head">
        <h2>Create a team</h2>
        <p>You become its owner. Invite people by email; they see the documents and templates shared with the team. Documents you already have stay private until you share them.</p>
      </div>
      <TextField id="team-name" label="Team name" placeholder="e.g. Acme legal" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} required autoComplete="organization" />
      <div className="form-card-foot"><Button variant="primary" type="submit" loading={busy === 'create'}><Users size={16} aria-hidden="true" />Create team</Button></div>
    </form>
  );
}

function TeamView({ user, team, members, invites, mail, transferStopsInvites, busy, run, ask, refresh }) {
  const isOwner = team.role === 'owner';
  const canManage = isOwner || team.role === 'admin';
  const [name, setName] = useState(team.name);
  const [invite, setInvite] = useState({ email: '', role: 'member' });
  const [inviteUrl, setInviteUrl] = useState(null); // shown once
  const origin = typeof window === 'undefined' ? '' : window.location.origin;

  // Admins may remove members only; the owner may remove anyone but themselves.
  const canRemove = (m) => m.userId !== user.id && (isOwner || (team.role === 'admin' && m.role === 'member'));

  async function setRole(m, role) {
    if (role === 'owner') {
      return ask({
        title: `Make ${m.name} the owner?`,
        body: `${m.name} can then delete the team and change roles. You become an admin. Only the new owner can undo this.${transferStopsInvites ? ' Sign-ups are closed on this server, so this team’s invite links will stop creating new accounts. People who already have an account can still join.' : ''}`,
        action: 'Transfer ownership', icon: Crown,
        run: () => apiFetch(`/api/teams/members/${m.userId}`, { method: 'PUT', body: { role } }),
      });
    }
    if (await run(`role:${m.userId}`, () => apiFetch(`/api/teams/members/${m.userId}`, { method: 'PUT', body: { role } }))) refresh();
  }

  async function sendInvite(e) {
    e.preventDefault();
    let url;
    if (await run('invite', async () => { ({ url } = await apiFetch('/api/teams/invites', { body: invite })); })) {
      setInviteUrl(`${origin}${url}`);
      setInvite({ email: '', role: 'member' });
      refresh();
    }
  }

  return (
    <>
      {isOwner ? (
        <form className="card form-card" onSubmit={async (e) => { e.preventDefault(); if (await run('rename', () => apiFetch('/api/teams', { method: 'PUT', body: { name } }))) refresh(); }}>
          <div className="form-card-head"><h2>Team name</h2><p>You are the owner of this team.</p></div>
          <TextField id="team-name" label="Team name" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} required autoComplete="organization" />
          <div className="form-card-foot"><Button variant="primary" type="submit" loading={busy === 'rename'} disabled={!name.trim() || name === team.name}>Save</Button></div>
        </form>
      ) : (
        <section className="card form-card">
          <div className="form-card-head"><h2>{team.name}</h2><p>You are {team.role === 'admin' ? 'an admin' : 'a member'} of this team.</p></div>
        </section>
      )}

      <section className="card form-card" aria-labelledby="members-h">
        <div className="form-card-head">
          <h2 id="members-h">Members</h2>
          <p>Members see every team document and can use team templates. Admins and the owner can also edit, send, void and delete them, and manage members.</p>
        </div>
        <ul className="dev-list">
          {members.map((m) => (
            <li key={m.userId} className="member-row">
              <Avatar name={m.name} />
              <div className="dev-main">
                <strong>{m.name}{m.userId === user.id && <span className="card-note"> (you)</span>}</strong>
                <span>{m.email} · Joined {formatDate(m.joinedAt)}</span>
              </div>
              <div className="member-actions">
                {isOwner && m.userId !== user.id ? (
                  <>
                    <label htmlFor={`role-${m.userId}`} className="sr-only">Role for {m.name}</label>
                    <select id={`role-${m.userId}`} className="input member-role" value={m.role} disabled={busy === `role:${m.userId}`} onChange={(e) => setRole(m, e.target.value)}>
                      <option value="member">Member</option>
                      <option value="admin">Admin</option>
                      <option value="owner">Owner</option>
                    </select>
                  </>
                ) : <span className="badge badge-neutral">{ROLE_LABEL[m.role]}</span>}
                {canRemove(m) && (
                  <Button variant="danger" size="sm" aria-label={`Remove ${m.name}`} onClick={() => ask({
                    title: `Remove ${m.name}?`,
                    body: `${m.name} loses access to team documents. Their own documents that were shared with the team become private to them again.`,
                    action: 'Remove member', icon: UserMinus,
                    run: () => apiFetch(`/api/teams/members/${m.userId}`, { method: 'DELETE' }),
                  })}><UserMinus size={14} aria-hidden="true" />Remove</Button>
                )}
              </div>
            </li>
          ))}
        </ul>
      </section>

      {canManage && (
        <section className="card form-card" aria-labelledby="invite-h">
          <div className="form-card-head">
            <h2 id="invite-h">Invite people</h2>
            <p>The invite link works for 7 days, only for an account with this email address. {mail ? 'We also email it.' : 'Email is not set up on this server, so send the link yourself.'}</p>
          </div>
          {inviteUrl ? <OneTimeSecret label="invite link" value={inviteUrl} onDone={() => setInviteUrl(null)} /> : (
            <form className="dev-form invite-form" onSubmit={sendInvite}>
              <TextField id="invite-email" type="email" label="Email" value={invite.email} onChange={(e) => setInvite({ ...invite, email: e.target.value })} required maxLength={254} autoComplete="off" />
              <div className="field">
                <label htmlFor="invite-role">Role</label>
                <select id="invite-role" className="input" value={invite.role} onChange={(e) => setInvite({ ...invite, role: e.target.value })}>
                  <option value="member">Member</option>
                  {isOwner && <option value="admin">Admin</option>}
                </select>
              </div>
              <div className="form-card-foot"><Button variant="primary" type="submit" loading={busy === 'invite'}><Plus size={16} aria-hidden="true" />Create invite</Button></div>
            </form>
          )}

          {invites.length > 0 && (
            <>
              <h3 className="invite-list-h">Pending invites</h3>
              <ul className="dev-list">
                {invites.map((i) => (
                  <li key={i.id}>
                    <Mail size={16} strokeWidth={1.75} aria-hidden="true" />
                    <div className="dev-main">
                      <strong>{i.email}</strong>
                      <span>{ROLE_LABEL[i.role]} · Sent {formatDate(i.createdAt)} · Expires {formatDate(i.expiresAt)}</span>
                    </div>
                    <Button variant="danger" size="sm" aria-label={`Revoke invite for ${i.email}`} onClick={() => ask({
                      title: 'Revoke this invite?',
                      body: `The link sent to ${i.email} stops working. You can invite them again later.`,
                      action: 'Revoke invite',
                      run: () => apiFetch(`/api/teams/invites/${i.id}`, { method: 'DELETE' }),
                    })}><Trash2 size={14} aria-hidden="true" />Revoke</Button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      )}

      <section className="card form-card">
        {isOwner ? (
          <>
            <div className="form-card-head">
              <h2>Delete team</h2>
              <p>Everyone leaves the team. No document is deleted: each one becomes private to the person who owns it.{members.length > 1 ? ' To leave without deleting, make someone else the owner first.' : ''}</p>
            </div>
            <div className="form-card-foot">
              <Button variant="danger" onClick={() => ask({
                title: `Delete ${team.name}?`,
                body: 'All members leave the team and lose access to each other’s documents. Every document stays with its owner as a private document. This can’t be undone.',
                action: 'Delete team',
                run: () => apiFetch('/api/teams', { method: 'DELETE' }),
              })}><Trash2 size={16} aria-hidden="true" />Delete team</Button>
            </div>
          </>
        ) : (
          <>
            <div className="form-card-head">
              <h2>Leave team</h2>
              <p>You lose access to team documents. Your own documents that were shared with the team become private to you again.</p>
            </div>
            <div className="form-card-foot">
              <Button variant="danger" onClick={() => ask({
                title: `Leave ${team.name}?`,
                body: 'You lose access to the team’s documents and templates. Your own shared documents become private again. To come back you need a new invite.',
                action: 'Leave team', icon: LogOut,
                run: () => apiFetch('/api/teams/leave'),
              })}><LogOut size={16} aria-hidden="true" />Leave team</Button>
            </div>
          </>
        )}
      </section>
    </>
  );
}
