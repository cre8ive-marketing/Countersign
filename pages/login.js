import { getUser } from '../lib/auth';
import { oidcName, startHref } from '../lib/oidc';
import AuthForm from '../components/AuthForm';

const SSO_ERRORS = {
  sso: 'Single sign-on did not finish. Try again.',
  sso_denied: 'This account can’t sign in here. Ask the person who runs this server.',
  sso_link: 'An account with this email already exists. Sign in with your password, then connect single sign-on in Settings.',
};

export function getServerSideProps({ req, query }) {
  if (getUser(req)) return { redirect: { destination: '/app', permanent: false } };
  return { props: { sso: { name: oidcName(), href: startHref(query.next), error: Object.hasOwn(SSO_ERRORS, String(query.error)) ? SSO_ERRORS[query.error] : null } } };
}

export default function Login({ sso }) {
  return <AuthForm mode="login" sso={sso} />;
}
