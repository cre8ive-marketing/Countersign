import { getUser } from '../lib/auth';
import AuthForm from '../components/AuthForm';

export function getServerSideProps({ req }) {
  if (getUser(req)) return { redirect: { destination: '/app', permanent: false } };
  return { props: {} };
}

export default function Login() {
  return <AuthForm mode="login" />;
}
