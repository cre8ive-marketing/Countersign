import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';
import {
  ArrowRight, Server, Scale, Database, Lock, Upload, MousePointerClick, Send, CircleCheck, Mail, ShieldCheck,
} from 'lucide-react';
import { Button } from '../components/ui';
import MarketingLayout, { CloseBand } from '../components/marketing/MarketingLayout';
import RoleTabs from '../components/marketing/RoleTabs';
import HeroDemo from '../components/marketing/HeroDemo';
import CopyCommand, { COMPOSE } from '../components/marketing/CopyCommand';
import { useSession, primaryAction } from '../components/marketing/useSession';

const FACTS = [
  [Scale, 'Open source', 'AGPL-3.0 licensed'],
  [Server, 'Self-hosted', 'One Docker container'],
  [Database, 'Your data', 'Never leaves your server'],
  [Lock, 'Free', 'No seats, no per-document fees'],
];

const STEPS = [
  [Upload, 'Upload', 'Drop in any PDF: contracts, NDAs, proposals, onboarding forms.'],
  [MousePointerClick, 'Place fields', 'Click to place signature, initials, date, name, text and checkbox fields for each person.'],
  [Send, 'Send', 'Everyone gets a private link. Sign at once or in a set order, with automatic reminders.'],
  [CircleCheck, 'Done', 'A flattened, signed PDF with a certificate of completion for every party.'],
];

export default function Home() {
  const session = useSession();
  const cta = primaryAction(session);
  return (
    <MarketingLayout session={session} title="Countersign · Open-source e-signatures you host yourself"
      description="Send PDFs for signature and keep every document and audit trail on your own server. Free and open source.">
      <section className="lp-hero">
        <div className="lp-wrap lp-hero-grid">
          <div className="lp-hero-copy">
            <h1>Get documents signed on a server you&nbsp;own.</h1>
            <p className="lp-lead">
              Upload a PDF, place fields, send it to every party, and get back a signed copy with a full audit trail.
              No seats to buy. No documents leaving your infrastructure.
            </p>
            <HeroStart session={session} />
          </div>
          <HeroDemo />
        </div>
        <div className="lp-wrap">
          <ul className="lp-facts" aria-label="At a glance">
            {FACTS.map(([Icon, t, d]) => (
              <li key={t}><Icon size={20} strokeWidth={1.75} aria-hidden="true" /><div><strong>{t}</strong><span>{d}</span></div></li>
            ))}
          </ul>
        </div>
      </section>

      <section className="lp-section" aria-labelledby="roles-h">
        <div className="lp-wrap">
          <div className="mk-head">
            <h2 id="roles-h" className="lp-h2">Built for the paperwork small teams send every week.</h2>
            <p className="lp-sub">Pick a team to see how a document moves from upload to signed.</p>
          </div>
          <RoleTabs />
        </div>
      </section>

      <section className="lp-section mk-pt0" aria-label="Product">
        <div className="lp-wrap mk-pair">
          <article className="mk-tint mk-panel-lg">
            <h3>Send it, then see exactly where it is.</h3>
            <p>Every document shows who has it, who has opened it and who has signed. Remind, copy a link, or void it from the same page.</p>
            <Link href="/product#manage" className="mk-more">Explore tracking<ArrowRight size={16} aria-hidden="true" /></Link>
            <figure className="mk-shot" aria-label="Example recipient list">
              <ul>
                <li><span className="mk-shot-name">Priya Nair</span><span className="badge badge-ok"><span className="badge-dot" aria-hidden="true" />Signed</span></li>
                <li><span className="mk-shot-name">Alex Morgan</span><span className="badge badge-warn"><span className="badge-dot" aria-hidden="true" />Viewed</span></li>
                <li><span className="mk-shot-name">Sam Lee</span><span className="badge badge-neutral"><span className="badge-dot" aria-hidden="true" />Queued</span></li>
              </ul>
              <figcaption>Sample data</figcaption>
            </figure>
          </article>
          <article className="mk-tint mk-panel-lg">
            <h3>Signers open a link and sign. That is all.</h3>
            <p>No account, no app to install. A guided button walks them through each field on a phone or a laptop, typed or drawn.</p>
            <Link href="/product#signer" className="mk-more">Explore the signer view<ArrowRight size={16} aria-hidden="true" /></Link>
            <figure className="mk-shot" aria-label="Example signing progress">
              <div className="mk-shot-sig"><span className="demo-sig-ink">Alex Morgan</span></div>
              <div className="mk-shot-progress"><span>2 of 3 fields</span><i aria-hidden="true"><b /></i></div>
              <figcaption>Sample data</figcaption>
            </figure>
          </article>
        </div>
      </section>

      <section className="lp-section lp-muted" aria-labelledby="how-h">
        <div className="lp-wrap lp-split">
          <div>
            <h2 id="how-h" className="lp-h2">From PDF to signed in four steps.</h2>
            <p className="lp-sub">The flow your clients already know, without the bill.</p>
          </div>
          <ol className="lp-steps">
            {STEPS.map(([Icon, t, d]) => (
              <li key={t}>
                <Icon size={22} strokeWidth={1.75} aria-hidden="true" />
                <h3>{t}</h3>
                <p>{d}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="lp-section lp-dark" aria-labelledby="trust-h">
        <div className="lp-wrap mk-trust">
          <div>
            <h2 id="trust-h" className="lp-h2">Every action, on the record.</h2>
            <p className="mk-trust-copy">Uploads, sends, emails, views, signatures, declines and voids are logged with the time, plus the IP address for actions taken in a browser, then printed into the signed PDF as a certificate of completion.</p>
            <Link href="/security" className="mk-more mk-more-light">Explore security and audit<ArrowRight size={16} aria-hidden="true" /></Link>
          </div>
          <ul className="mk-proof">
            <li><span>Original file fingerprint</span><code>SHA-256 9f2c71d0…be04a41e</code><p>Printed on the certificate so anyone can check the PDF they were sent.</p></li>
            <li><span>Audit entry</span><code>10:42 Alex Morgan · Signed · 203.0.113.24</code><p>Time, person and action for every step, in order, with the IP for actions taken in a browser.</p></li>
            <li><span>Signed PDF</span><strong>Fields flattened</strong><p>Values are drawn into the page, so they cannot be edited later.</p></li>
            <li><span>Storage</span><code>/data/files/&lt;id&gt;.signed.pdf</code><p>Files and database sit in one volume on your server.</p></li>
          </ul>
        </div>
      </section>

      <section className="lp-section" aria-labelledby="host-h">
        <div className="lp-wrap lp-host">
          <div className="lp-host-copy">
            <h2 id="host-h" className="lp-h2">One container. One data volume.</h2>
            <p>Countersign runs as a single Docker container with a built-in SQLite database. Documents, signatures and audit logs live in one volume, so a backup is a single copy.</p>
            <ul className="lp-host-list">
              <li><Server size={18} strokeWidth={1.75} aria-hidden="true" />No database server, queue or object storage to run</li>
              <li><Mail size={18} strokeWidth={1.75} aria-hidden="true" />Bring any SMTP provider, or share signing links by hand</li>
              <li><ShieldCheck size={18} strokeWidth={1.75} aria-hidden="true" />Run it behind your own proxy or VPN</li>
            </ul>
            <Link href="/self-host" className="mk-more">Read the self-host guide<ArrowRight size={16} aria-hidden="true" /></Link>
          </div>
          <figure className="code-window">
            <figcaption>docker-compose.yml</figcaption>
            <pre><code>{COMPOSE}</code></pre>
          </figure>
        </div>
      </section>

      <section className="lp-section lp-muted" aria-labelledby="next-h">
        <div className="lp-wrap lp-split">
          <h2 id="next-h" className="lp-h2">Read before you install.</h2>
          <ul className="mk-links">
            <li><Link href="/self-host"><strong>Self-host guide</strong><span>Docker, configuration, email, HTTPS and backups.</span><ArrowRight size={20} aria-hidden="true" /></Link></li>
            <li><Link href="/security"><strong>Security and audit</strong><span>What is recorded, where it is stored, and the known limits.</span><ArrowRight size={20} aria-hidden="true" /></Link></li>
            <li><Link href="/self-host#licence"><strong>Open-source licence</strong><span>What AGPL-3.0 lets you do, including commercial use.</span><ArrowRight size={20} aria-hidden="true" /></Link></li>
          </ul>
        </div>
      </section>

      <CloseBand>
        <Button variant="primary" size="lg" href={cta.href}>{cta.label}<ArrowRight size={18} aria-hidden="true" /></Button>
        <CopyCommand command="docker compose up -d" />
      </CloseBand>
    </MarketingLayout>
  );
}

// Inline email start: prefills the account form on this server. Nothing is stored here.
function HeroStart({ session }) {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  if (session.user) {
    return (
      <div className="lp-hero-actions">
        <Button variant="primary" size="lg" href="/app">Open app<ArrowRight size={18} aria-hidden="true" /></Button>
        <CopyCommand command="docker compose up -d" />
      </div>
    );
  }
  const dest = session.signupOpen ? '/signup' : '/login';
  return (
    <form className="mk-start" onSubmit={(e) => { e.preventDefault(); setBusy(true); router.push(`${dest}?email=${encodeURIComponent(email.trim())}`); }}>
      <label htmlFor="start-email">Work email</label>
      <div className="mk-start-row">
        <input id="start-email" className="input" type="email" autoComplete="email" placeholder="you@company.com" required maxLength={254}
          value={email} onChange={(e) => setEmail(e.target.value)} />
        <Button variant="primary" size="lg" type="submit" loading={busy}>{session.signupOpen ? 'Create account' : 'Continue to sign in'}</Button>
      </div>
      <p className="mk-start-note">
        {session.signupOpen
          ? 'Creates an account on this server. Your email goes nowhere else.'
          : 'New accounts are created by whoever runs this server.'}
        {' '}Or run your own: <code>docker compose up -d</code>
      </p>
    </form>
  );
}
