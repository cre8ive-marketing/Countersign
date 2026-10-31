import Head from 'next/head';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import SiteNav from './SiteNav';
import SiteFooter from './SiteFooter';

export default function MarketingLayout({ session, title, description, children }) {
  return (
    <div className="lp">
      <Head>
        <title>{title}</title>
        <meta name="description" content={description} />
      </Head>
      <a href="#main" className="mk-skip">Skip to content</a>
      <div className="mk-utility">
        <div className="lp-wrap mk-utility-inner">
          <Link href="/self-host">Free and open source. Run it on your own server<ArrowRight size={14} aria-hidden="true" /></Link>
          <span>Signing a document? Open the link in your email. No account needed.</span>
        </div>
      </div>
      <SiteNav session={session} />
      <main id="main" tabIndex={-1}>{children}</main>
      <SiteFooter session={session} />
    </div>
  );
}

// Shared closing band before the footer.
export function CloseBand({ title = 'Own your signing workflow.', text = 'Free, open source, and running on your server in minutes.', children }) {
  return (
    <section className="lp-close">
      <div className="lp-wrap lp-close-inner">
        <div>
          <h2>{title}</h2>
          <p>{text}</p>
        </div>
        <div className="lp-hero-actions">{children}</div>
      </div>
    </section>
  );
}
