import { useEffect, useState } from 'react';

// Marketing pages are static; the signed-in state is fetched once on the client.
export function useSession() {
  const [session, setSession] = useState({ user: null, signupOpen: true, ready: false });
  useEffect(() => {
    let live = true;
    fetch('/api/auth/session')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (live && d) setSession({ user: d.user ?? null, signupOpen: d.signupOpen !== false, ready: true }); })
      .catch(() => {}); // stay signed out
    return () => { live = false; };
  }, []);
  return session;
}

// The one primary action, worded for who is looking.
export function primaryAction({ user, signupOpen }) {
  if (user) return { href: '/app', label: 'Open app' };
  return signupOpen ? { href: '/signup', label: 'Get started' } : { href: '/login', label: 'Sign in' };
}
