import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { Files, LayoutTemplate, Settings, LogOut } from 'lucide-react';
import { Logo, Avatar } from './ui';
import { apiFetch } from '../lib/client';

const NAV = [
  { href: '/app', label: 'Documents', icon: Files, match: (p, q) => p === '/app' && q.view !== 'templates' || p.startsWith('/app/documents') },
  { href: '/app?view=templates', label: 'Templates', icon: LayoutTemplate, match: (p, q) => p === '/app' && q.view === 'templates' },
  { href: '/app/settings', label: 'Settings', icon: Settings, match: (p) => p === '/app/settings' },
];

export default function AppShell({ user, title, children }) {
  const router = useRouter();

  async function logout() {
    await apiFetch('/api/auth/logout').catch(() => {});
    router.push('/login');
  }

  return (
    <div className="shell">
      <Head><title>{`${title} · Countersign`}</title></Head>
      <aside className="sidebar">
        <div className="sidebar-top"><Logo href="/app" /></div>
        <nav aria-label="App">
          {NAV.map(({ href, label, icon: Icon, match }) => {
            const active = match(router.pathname, router.query);
            return (
              <Link key={label} href={href} className={`nav-item${active ? ' is-active' : ''}`} aria-current={active ? 'page' : undefined}>
                <Icon size={16} strokeWidth={1.75} aria-hidden="true" />{label}
              </Link>
            );
          })}
        </nav>
        <div className="sidebar-user">
          <Avatar name={user.name} />
          <div className="sidebar-user-text">
            <strong>{user.name}</strong>
            <span>{user.email}</span>
          </div>
          <button className="icon-btn" onClick={logout} aria-label="Sign out" title="Sign out">
            <LogOut size={16} strokeWidth={1.75} />
          </button>
        </div>
      </aside>
      <div className="shell-main">{children}</div>
    </div>
  );
}
