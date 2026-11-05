import { useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { apiFetch } from '../lib/client';
import { mailEnabled } from '../lib/mail';
import { AuthShell } from '../components/AuthForm';
import { Button, TextField } from '../components/ui';

export function getServerSideProps() {
  return { props: { canMail: mailEnabled() } };
}

export default function Forgot({ canMail }) {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiFetch('/api/auth/forgot', { body: { email } });
      setSent(true);
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  }

  return (
    <AuthShell>
      <Head><title>Reset password · Countersign</title></Head>
      <h1>Reset your password</h1>
      {!canMail ? (
        <p className="auth-sub">This server doesn’t send email. Ask the person who runs it for a reset link.</p>
      ) : sent ? (
        <p className="auth-sub" role="status">If that address has an account, a link is on its way. It works once, for one hour.</p>
      ) : (
        <>
          <p className="auth-sub">We’ll email you a link to choose a new password.</p>
          <form onSubmit={submit}>
            {error && <div className="error-summary" role="alert">{error}</div>}
            <TextField id="email" type="email" label="Work email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            <Button variant="primary" type="submit" loading={busy} className="btn-block">Send reset link</Button>
          </form>
        </>
      )}
      <p className="auth-switch"><Link href="/login">Back to sign in</Link></p>
    </AuthShell>
  );
}
