import { useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { apiFetch } from '../lib/client';
import { AuthShell } from '../components/AuthForm';
import { Button, TextField } from '../components/ui';

export default function Reset() {
  const [token, setToken] = useState(null); // in the # part of the link, so it never reaches a server log or a Referer header
  const [password, setPassword] = useState('');
  const [done, setDone] = useState(false);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const read = () => setToken(window.location.hash.slice(1));
    read();
    window.addEventListener('hashchange', read); // a link pasted into a tab already on this page does not reload it
    return () => window.removeEventListener('hashchange', read);
  }, []);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiFetch('/api/auth/reset', { body: { token, password } });
      setDone(true);
    } catch (err) {
      setError(err.message);
    }
    setBusy(false);
  }

  return (
    <AuthShell>
      <Head><title>Choose a new password · Countersign</title></Head>
      <h1>Choose a new password</h1>
      {done ? (
        <>
          <p className="auth-sub" role="status">Your password is changed. Sign in with it now.</p>
          <p className="auth-switch"><Link href="/login">Sign in</Link></p>
        </>
      ) : token === '' ? (
        <>
          <p className="auth-sub">This link is not complete. Open it from your email again, or ask for a new one.</p>
          <p className="auth-switch"><Link href="/forgot">Ask for a new link</Link></p>
        </>
      ) : (
        <>
          <p className="auth-sub">This signs you out on every device, revokes all your API keys, pauses your webhooks and cancels pending team invites you sent.</p>
          <form onSubmit={submit}>
            {error && <div className="error-summary" role="alert">{error}</div>}
            <TextField id="password" type="password" label="New password" autoComplete="new-password" minLength={12} maxLength={256}
              value={password} onChange={(e) => setPassword(e.target.value)} required hint="At least 12 characters." />
            <Button variant="primary" type="submit" loading={busy} disabled={!token} className="btn-block">Change password</Button>
          </form>
          <p className="auth-switch"><Link href="/forgot">Ask for a new link</Link></p>
        </>
      )}
    </AuthShell>
  );
}
