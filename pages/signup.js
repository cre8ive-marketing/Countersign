import { getUser, signupOpen } from '../lib/auth';
import { inviteByToken } from '../lib/teams';
import { oidcCanCreate, oidcName, passwordSignupOff, startHref } from '../lib/oidc';
import AuthForm from '../components/AuthForm';

export function getServerSideProps({ req, query }) {
  if (getUser(req)) return { redirect: { destination: '/app', permanent: false } };
  // A valid team invite opens signup for its email even when signups are closed (see inviteByToken); the server re-checks it.
  const found = typeof query.invite === 'string' ? inviteByToken(query.invite) : null;
  const invite = found?.canSignUp ? { token: query.invite, email: found.email, teamName: found.teamName } : null;
  const shut = !invite && !signupOpen();
  const sso = shut || !oidcCanCreate() ? null : { name: oidcName(), href: startHref(invite ? `/join/${encodeURIComponent(invite.token)}` : query.next), error: null };
  const noPassword = passwordSignupOff();
  return { props: { closed: shut || (noPassword && !sso), noPassword, invite, sso } };
}

export default function Signup({ closed, noPassword, invite, sso }) {
  return <AuthForm mode="signup" closed={closed} noPassword={noPassword} invite={invite} sso={sso} />;
}
