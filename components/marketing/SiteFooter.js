import Link from 'next/link';
import { Logo } from '../ui';
import { MENUS } from './SiteNav';

export default function SiteFooter({ session }) {
  const app = session.user
    ? [['/app', 'Open app']]
    : [['/login', 'Sign in'], ...(session.signupOpen ? [['/signup', 'Create account']] : [])];
  const cols = [...MENUS.map((m) => [m.label, m.items.map(([href, , title]) => [href, title])]), ['App', app]];

  return (
    <footer className="mk-footer">
      <div className="lp-wrap">
        <div className="mk-footer-grid">
          <div className="mk-footer-brand">
            <Logo />
            <p>Open-source electronic signatures that run on your own server.</p>
          </div>
          {cols.map(([title, links]) => (
            <nav key={title} aria-label={title}>
              <h2>{title}</h2>
              <ul>{links.map(([href, label]) => <li key={href}><Link href={href}>{label}</Link></li>)}</ul>
            </nav>
          ))}
        </div>
        <p className="mk-footer-legal">
          Free software under the GNU AGPL-3.0. Countersign records electronic signatures and an audit trail; a signature
          image is a mark of intent, not proof of identity. Check the signature rules that apply to your documents and jurisdiction.
        </p>
      </div>
    </footer>
  );
}
