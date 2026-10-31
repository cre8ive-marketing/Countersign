import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import {
  ChevronDown, Menu, X, MousePointerClick, ListOrdered, Smartphone, LayoutTemplate, FileCheck2, BellRing,
  Briefcase, FileSignature, UserPlus, ClipboardCheck, Server, Settings2, ShieldCheck, Scale, FolderGit2,
} from 'lucide-react';
import { Logo, Button } from '../ui';
import { primaryAction } from './useSession';

export const MENUS = [
  { label: 'Product', items: [
    ['/product#prepare', MousePointerClick, 'Prepare documents', 'Upload a PDF and place fields for each person'],
    ['/product#route', ListOrdered, 'Signing order', 'Everyone at once, or one after another'],
    ['/product#signer', Smartphone, 'Signer experience', 'No account, works on a phone'],
    ['/product#templates', LayoutTemplate, 'Templates', 'Place fields once, reuse with new names'],
    ['/product#manage', BellRing, 'Reminders, decline, void', 'Track every document to the end'],
    ['/product#audit', FileCheck2, 'Audit trail and certificate', 'Every action recorded in the signed PDF'],
  ] },
  { label: 'Use cases', items: [
    ['/use-cases#agencies', Briefcase, 'Agencies', 'Proposals and statements of work'],
    ['/use-cases#sales', FileSignature, 'Sales', 'Order forms with several client signers'],
    ['/use-cases#hr', UserPlus, 'HR and onboarding', 'Offer letters signed on a phone'],
    ['/use-cases#internal', ClipboardCheck, 'Internal approvals', 'Sign-offs in a set order, and self-sign'],
  ] },
  { label: 'Resources', items: [
    ['/self-host', Server, 'Self-host guide', 'Run it with Docker in a few minutes'],
    ['/self-host#configuration', Settings2, 'Configuration', 'URL, email, sign-ups, proxies'],
    ['/security', ShieldCheck, 'Security and audit', 'What is recorded, and the known limits'],
    ['/self-host#licence', Scale, 'Open-source licence', 'AGPL-3.0: use, modify, self-host'],
    ['https://github.com/cre8ive-marketing/Countersign', FolderGit2, 'Source code', 'The Countersign repository on GitHub'],
  ] },
];

export default function SiteNav({ session }) {
  const [open, setOpen] = useState(null); // label of the open desktop menu
  const [drawer, setDrawer] = useState(false);
  const navRef = useRef(null);
  const hoverTimer = useRef(null);
  const burger = useRef(null);
  const cta = primaryAction(session);

  useEffect(() => {
    document.documentElement.classList.toggle('mk-lock', drawer);
    return () => document.documentElement.classList.remove('mk-lock');
  }, [drawer]);

  function close(focusTrigger) {
    if (focusTrigger && open) navRef.current?.querySelector(`[data-menu="${open}"]`)?.focus();
    if (focusTrigger && drawer) burger.current?.focus();
    setOpen(null);
    setDrawer(false);
  }

  function onKeyDown(e) {
    if (e.key === 'Escape' && (open || drawer)) { e.preventDefault(); close(true); }
  }

  // Focus leaving the header closes whatever is open.
  function onBlur(e) {
    if (!e.currentTarget.contains(e.relatedTarget)) { setOpen(null); setDrawer(false); }
  }

  function onTriggerKey(e, label) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setOpen(label);
      requestAnimationFrame(() => document.getElementById(`mk-menu-${slug(label)}`)?.querySelector('a')?.focus());
    }
  }

  function hover(label) {
    clearTimeout(hoverTimer.current);
    hoverTimer.current = setTimeout(() => setOpen(label), label ? 120 : 200);
  }

  return (
    <header className="mk-nav" ref={navRef} onKeyDown={onKeyDown} onBlur={onBlur}>
      <div className="lp-wrap mk-nav-inner">
        <Logo />
        <nav aria-label="Main" className="mk-menus">
          <ul>
            {MENUS.map((m) => (
              <li key={m.label} onMouseEnter={() => hover(m.label)} onMouseLeave={() => hover(null)}>
                <button type="button" className="btn btn-ghost mk-trigger" data-menu={m.label} aria-expanded={open === m.label} aria-controls={`mk-menu-${slug(m.label)}`}
                  onClick={() => { clearTimeout(hoverTimer.current); setOpen(open === m.label ? null : m.label); }} onKeyDown={(e) => onTriggerKey(e, m.label)}>
                  {m.label}<ChevronDown size={16} aria-hidden="true" />
                </button>
                <div id={`mk-menu-${slug(m.label)}`} className="mk-panel" hidden={open !== m.label}>
                  <ul>
                    {m.items.map(([href, Icon, title, desc]) => (
                      <li key={href}>
                        <Link href={href} className="mk-panel-link" onClick={() => setOpen(null)}>
                          <Icon size={20} strokeWidth={1.75} aria-hidden="true" />
                          <span><strong>{title}</strong><span>{desc}</span></span>
                        </Link>
                      </li>
                    ))}
                  </ul>
                </div>
              </li>
            ))}
            <li><Link href="/self-host" className="btn btn-ghost mk-trigger">Self-host</Link></li>
          </ul>
        </nav>
        <div className="mk-actions">
          {!session.user && cta.href !== '/login' && <Link href="/login" className="btn btn-ghost btn-sm lp-signin">Sign in</Link>}
          <Button variant="primary" size="sm" href={cta.href} className="mk-cta">{cta.label}</Button>
          <button type="button" ref={burger} className="icon-btn mk-burger" aria-expanded={drawer} aria-controls="mk-drawer" onClick={() => { setOpen(null); setDrawer(!drawer); }}>
            {drawer ? <X size={22} aria-hidden="true" /> : <Menu size={22} aria-hidden="true" />}
            <span className="sr-only">{drawer ? 'Close menu' : 'Open menu'}</span>
          </button>
        </div>
      </div>
      <div id="mk-drawer" className="mk-drawer" hidden={!drawer}>
        {MENUS.map((m) => (
          <details key={m.label}>
            <summary>{m.label}<ChevronDown size={18} aria-hidden="true" /></summary>
            <ul>
              {m.items.map(([href, , title]) => <li key={href}><Link href={href} onClick={() => setDrawer(false)}>{title}</Link></li>)}
            </ul>
          </details>
        ))}
        <Link href="/self-host" className="mk-drawer-link" onClick={() => setDrawer(false)}>Self-host</Link>
        {!session.user && cta.href !== '/login' && <Link href="/login" className="mk-drawer-link" onClick={() => setDrawer(false)}>Sign in</Link>}
      </div>
    </header>
  );
}

const slug = (s) => s.toLowerCase().replace(/\s+/g, '-');
