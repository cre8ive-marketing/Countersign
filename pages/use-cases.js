import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { Button } from '../components/ui';
import MarketingLayout, { CloseBand } from '../components/marketing/MarketingLayout';
import { ROLES, RoleFlow } from '../components/marketing/RoleTabs';
import { useSession, primaryAction } from '../components/marketing/useSession';

export default function UseCases() {
  const session = useSession();
  const cta = primaryAction(session);
  return (
    <MarketingLayout session={session} title="Use cases · Countersign" description="How agencies, sales, HR and internal teams send documents for signature with Countersign.">
      <section className="mk-page-head">
        <div className="lp-wrap">
          <h1>One signing workflow, shaped to the paperwork you send.</h1>
          <p className="lp-lead">The same features in four common setups. Every step below works in Countersign today.</p>
          <nav aria-label="Use cases" className="mk-jump">
            {ROLES.map((r) => <Link key={r.id} href={`#${r.id}`}>{r.label}</Link>)}
          </nav>
        </div>
      </section>
      {ROLES.map((r) => (
        <section key={r.id} id={r.id} className="mk-row" aria-labelledby={`${r.id}-h`}>
          <div className="lp-wrap">
            <div className="mk-tint mk-role">
              <div>
                <h2 id={`${r.id}-h`}>{r.title}</h2>
                <p>{r.body}</p>
                <Link href="/product" className="mk-more">See every feature<ArrowRight size={16} aria-hidden="true" /></Link>
              </div>
              <RoleFlow flow={r.flow} />
            </div>
          </div>
        </section>
      ))}
      <CloseBand>
        <Button variant="primary" size="lg" href={cta.href}>{cta.label}<ArrowRight size={18} aria-hidden="true" /></Button>
      </CloseBand>
    </MarketingLayout>
  );
}
