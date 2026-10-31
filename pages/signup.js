import { getUser, signupOpen } from '../lib/auth';
import AuthForm from '../components/AuthForm';

export function getServerSideProps({ req }) {
  if (getUser(req)) return { redirect: { destination: '/app', permanent: false } };
  return { props: { closed: !signupOpen() } };
}

export default function Signup({ closed }) {
  return <AuthForm mode="signup" closed={closed} />;
}
