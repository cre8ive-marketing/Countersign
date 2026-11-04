import { getUser, signupOpen } from '../lib/auth';
import { inviteByToken } from '../lib/teams';
import AuthForm from '../components/AuthForm';

export function getServerSideProps({ req, query }) {
  if (getUser(req)) return { redirect: { destination: '/app', permanent: false } };
  // A valid team invite opens signup for its email even when signups are closed (see inviteByToken); the server re-checks it.
  const found = typeof query.invite === 'string' ? inviteByToken(query.invite) : null;
  const invite = found?.canSignUp ? { token: query.invite, email: found.email, teamName: found.teamName } : null;
  return { props: { closed: !invite && !signupOpen(), invite } };
}

export default function Signup({ closed, invite }) {
  return <AuthForm mode="signup" closed={closed} invite={invite} />;
}
