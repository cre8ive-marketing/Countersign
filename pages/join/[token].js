import { useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import { Link2Off, LogIn, LogOut, UserPlus, Users } from 'lucide-react';
import { getUser } from '../../lib/auth';
import { inviteByToken } from '../../lib/teams';
import { apiFetch } from '../../lib/client';
import { Button, Logo } from '../../components/ui';

export async function getServerSideProps({ params, req, res }) {
  const invite = inviteByToken(String(params.token));
  if (!invite) {
    res.statusCode = 404;
    return { props: { token: null, invite: null, user: null } };
  }
  const user = getUser(req);
  return {
    props: {
      token: params.token,
      invite: { teamName: invite.teamName, inviterName: invite.inviterName, email: invite.email, role: invite.role, canSignUp: invite.canSignUp },
      user: user ? { name: user.name, email: user.email } : null,
    },
  };
}

export default function Join({ token, invite, user }) {
  return (
    <div className="signer">
      <Head><title>{`${invite ? `Join ${invite.teamName}` : 'Invite not active'} · Countersign`}</title><meta name="robots" content="noindex" /></Head>
      <div className="status-page">
        {invite ? <JoinCard token={token} invite={invite} user={user} /> : (
          <div className="status-card">
            <Logo href="/app" />
            <span className="status-icon tone-neutral"><Link2Off size={22} strokeWidth={1.75} aria-hidden="true" /></span>
            <h1>This invite is not active</h1>
            <p>It may have expired, been used already or been revoked. Ask the person who invited you for a new link.</p>
          </div>
        )}
      </div>
    </div>
  );
}

function JoinCard({ token, invite, user }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const here = `/join/${encodeURIComponent(token)}`;
  const sameEmail = user && user.email.toLowerCase() === invite.email.toLowerCase();

  async function join() {
    setBusy(true);
    setError(null);
    try {
      await apiFetch('/api/teams/join', { body: { token } });
      router.push('/app/team');
    } catch (e) {
      setError(e.message);
      setBusy(false);
    }
  }

  async function signOut() {
    setBusy(true);
    await apiFetch('/api/auth/logout').catch(() => {});
    window.location.assign(here); // full load so the page sees the signed-out session
  }

  return (
    <div className="status-card public-card">
      <Logo href={null} />
      <span className="status-icon tone-warn"><Users size={22} strokeWidth={1.75} aria-hidden="true" /></span>
      <h1>Join {invite.teamName}</h1>
      <p>{invite.inviterName} invited <strong>{invite.email}</strong> to join as {invite.role === 'admin' ? 'an admin' : 'a member'}. Team members see the documents and templates shared with the team.</p>
      {error && <p className="otp-error" role="alert">{error}</p>}
      {sameEmail ? (
        <Button variant="primary" onClick={join} loading={busy}><Users size={16} aria-hidden="true" />Join team</Button>
      ) : user ? (
        <>
          <p className="public-note">You are signed in as <strong>{user.email}</strong>. This invite only works for {invite.email}. Sign out, then sign in or create an account with that address.</p>
          <Button variant="secondary" onClick={signOut} loading={busy}><LogOut size={16} aria-hidden="true" />Sign out</Button>
        </>
      ) : (
        <div className="join-actions">
          {invite.canSignUp && <Button variant="primary" href={`/signup?invite=${encodeURIComponent(token)}`}><UserPlus size={16} aria-hidden="true" />Create account</Button>}
          <Button variant={invite.canSignUp ? 'secondary' : 'primary'} href={`/login?email=${encodeURIComponent(invite.email)}&next=${encodeURIComponent(here)}`}><LogIn size={16} aria-hidden="true" />I have an account</Button>
        </div>
      )}
    </div>
  );
}
