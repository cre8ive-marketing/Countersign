import { getUser, signupOpen } from '../lib/auth';
import { inviteByToken } from '../lib/teams';
import { oidcCanCreate, oidcName, startHref } from '../lib/oidc';
import AuthForm from '../components/AuthForm';

export function getServerSideProps({ req, query }) {
  if (getUser(req)) return { redirect: { destination: '/app', permanent: false } };
  // A valid team invite opens signup for its email even when signups are closed (see inviteByToken); the server re-checks it.
  const found = typeof query.invite === 'string' ? inviteByToken(query.invite) : null;
  const invite = found?.canSignUp ? { token: query.invite, email: found.email, teamName: found.teamName } : null;
  const closed = !invite && !signupOpen();
  const sso = closed || !oidcCanCreate() ? null : { name: oidcName(), href: startHref(invite ? `/join/${encodeURIComponent(invite.token)}` : query.next), error: null };
  return { props: { closed, invite, sso } };
}

export default function Signup({ closed, invite, sso }) {
  return <AuthForm mode="signup" closed={closed} invite={invite} sso={sso} />;
}
