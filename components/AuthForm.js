import { useEffect, useRef, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { Check } from 'lucide-react';
import { apiFetch } from '../lib/client';
import { Button, Logo, TextField } from './ui';

const POINTS = ['Unlimited documents and signers', 'Signers never need an account', 'Every action in the audit trail', 'Runs on your own server'];

// Resolve like the browser does (it strips tabs/newlines, treats \ as /) and allow same-origin targets only.
export function safeNext(next) {
  if (typeof next !== 'string' || !next) return '/app';
  try {
    const u = new URL(next, window.location.origin);
    return u.origin === window.location.origin ? u.pathname + u.search + u.hash : '/app';
  } catch {
    return '/app';
  }
}

export default function AuthForm({ mode, closed }) {
  const router = useRouter();
  // ?email= comes from the landing page start form.
  const [form, setForm] = useState(() => ({ name: '', email: typeof router.query.email === 'string' ? router.query.email.slice(0, 254) : '', password: '' }));
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const summary = useRef(null);
  const isSignup = mode === 'signup';
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  // Move focus to the error so keyboard and screen reader users hear it.
  useEffect(() => { if (error) summary.current?.focus(); }, [error]);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiFetch(`/api/auth/${mode}`, { body: form });
      router.push(safeNext(router.query.next));
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <Head><title>{isSignup ? 'Create account · Countersign' : 'Sign in · Countersign'}</title></Head>
      <aside className="auth-aside">
        <Logo />
        <div>
          <h2>Contracts signed on a server you own.</h2>
          <ul>{POINTS.map((p) => <li key={p}><Check size={18} aria-hidden="true" />{p}</li>)}</ul>
        </div>
        <small>Open source under AGPL-3.0</small>
      </aside>
      <main className="auth-main">
        <div className="auth-card">
          <div className="auth-mobile-logo"><Logo /></div>
          <h1>{isSignup ? 'Create your account' : 'Welcome back'}</h1>
          <p className="auth-sub">{isSignup ? 'Start sending documents for signature in minutes.' : 'Sign in to send and manage documents.'}</p>
          {closed ? (
            <p className="banner banner-bad">Sign-ups are closed on this server. Ask the person who runs it to create an account for you, or to set ALLOW_SIGNUP=true.</p>
          ) : (
            <form onSubmit={submit}>
              {error && <div ref={summary} className="error-summary" role="alert" tabIndex={-1}>{error}</div>}
              {isSignup && <TextField id="name" label="Full name" autoComplete="name" value={form.name} onChange={set('name')} required maxLength={120} />}
              <TextField id="email" type="email" label="Work email" autoComplete="email" value={form.email} onChange={set('email')} required />
              <TextField id="password" type="password" label="Password" autoComplete={isSignup ? 'new-password' : 'current-password'} minLength={isSignup ? 8 : undefined}
                value={form.password} onChange={set('password')} required hint={isSignup ? 'At least 8 characters.' : undefined} />
              <Button variant="primary" type="submit" loading={busy} className="btn-block">{isSignup ? 'Create account' : 'Sign in'}</Button>
            </form>
          )}
          <p className="auth-switch">
            {isSignup ? <>Already have an account? <Link href="/login">Sign in</Link></> : <>New here? <Link href="/signup">Create an account</Link></>}
          </p>
        </div>
      </main>
    </div>
  );
}
