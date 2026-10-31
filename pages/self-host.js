import MarketingLayout from '../components/marketing/MarketingLayout';
import CopyCommand, { COMPOSE } from '../components/marketing/CopyCommand';
import { useSession } from '../components/marketing/useSession';

const TOC = [
  ['requirements', 'Requirements'], ['quick-start', 'Quick start'], ['configuration', 'Configuration'], ['email', 'Email'],
  ['https', 'HTTPS and proxies'], ['backups', 'Backups'], ['upgrading', 'Upgrading'], ['limits', 'Known limits'], ['licence', 'Licence'],
];

const ENV = [
  ['APP_URL', 'request host', 'Public URL used in emailed links and reminders. https:// turns on Secure cookies. Required for automatic reminders.'],
  ['DATA_DIR', './data (/data in Docker)', 'Where the database and PDFs are stored.'],
  ['ALLOW_SIGNUP', 'false', 'The first account can always sign up. Set true to let anyone create an account.'],
  ['TRUST_PROXY', 'false', 'Set true behind a reverse proxy so the audit trail records the client IP from X-Forwarded-For.'],
  ['SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASS, SMTP_FROM', 'unset', 'Email delivery. Without SMTP, senders copy each signing link from the document page.'],
  ['PORT', '3000', 'HTTP port.'],
];

export default function SelfHost() {
  const session = useSession();
  return (
    <MarketingLayout session={session} title="Self-host guide · Countersign" description="Run Countersign on your own server with Docker: configuration, email, HTTPS, backups and upgrades.">
      <section className="mk-page-head">
        <div className="lp-wrap">
          <h1>Run Countersign on your own server.</h1>
          <p className="lp-lead">One container, one data volume, and every extra service optional. This guide covers a first install through to backups.</p>
        </div>
      </section>
      <div className="lp-wrap mk-doc">
        <nav aria-label="On this page" className="mk-toc">
          <ul>{TOC.map(([id, t]) => <li key={id}><a href={`#${id}`}>{t}</a></li>)}</ul>
        </nav>
        <div className="mk-prose">
          <h2 id="requirements">Requirements</h2>
          <p>A Linux server with Docker and Docker Compose. Without Docker, Node.js 22.13 or newer is enough, since the database is the SQLite built into Node.</p>

          <h2 id="quick-start">Quick start</h2>
          <p>Get the source, copy the example settings, set <code>APP_URL</code>, then start the container.</p>
          <pre className="mk-pre"><code>{'git clone https://github.com/cre8ive-marketing/Countersign.git\ncd Countersign\ncp .env.example .env\ndocker compose up -d'}</code></pre>
          <p>Open your <code>APP_URL</code> and create the first account. Sign-ups close after the first account unless <code>ALLOW_SIGNUP=true</code>.</p>
          <figure className="code-window">
            <figcaption>docker-compose.yml with settings inline</figcaption>
            <pre><code>{COMPOSE}</code></pre>
          </figure>
          <p>Without Docker:</p>
          <pre className="mk-pre"><code>{'npm ci\nnpm run build\nnpm start'}</code></pre>

          <h2 id="configuration">Configuration</h2>
          <p>Only <code>APP_URL</code> matters for a first run.</p>
          <div className="mk-table-wrap">
            <table className="mk-table">
              <thead><tr><th scope="col">Variable</th><th scope="col">Default</th><th scope="col">What it does</th></tr></thead>
              <tbody>{ENV.map(([k, d, w]) => <tr key={k}><th scope="row"><code>{k}</code></th><td>{d}</td><td>{w}</td></tr>)}</tbody>
            </table>
          </div>

          <h2 id="email">Email</h2>
          <p>Set the <code>SMTP_*</code> variables to email signing links, reminders and completed copies through any provider. Without SMTP, signing still works: each document page shows the private signing link for every recipient, ready to copy and send by hand. Reminders and email notifications, such as telling the next signer it is their turn or sending completed copies, need SMTP.</p>

          <h2 id="https">HTTPS and proxies</h2>
          <p>Put Countersign behind Caddy, nginx or Traefik. Set <code>APP_URL=https://…</code> so cookies are marked Secure, and <code>TRUST_PROXY=true</code> so the audit trail records the real client IP.</p>

          <h2 id="backups">Backups</h2>
          <p>All state lives in the data volume: <code>countersign.db</code> and the <code>files/</code> folder with original and signed PDFs. Stop the container, or use <code>sqlite3 .backup</code>, and copy the whole volume. Back up the database and the files together.</p>

          <h2 id="upgrading">Upgrading</h2>
          <p>Back up the volume, pull the new version and rebuild. The database schema is created on start.</p>
          <CopyCommand command="git pull && docker compose up -d --build" />

          <h2 id="limits">Known limits</h2>
          <ul>
            <li>Signatures are electronic signatures with an audit trail, not certificate-based digital signatures. There is no PAdES or X.509 seal on the PDF.</li>
            <li>Text typed into fields supports Latin-1 characters only. Drawn and typed signatures are images and are not affected.</li>
            <li>Pages with a rotation flag are stamped as if unrotated.</li>
            <li>Not built yet: bulk send, teams and roles, a REST API and webhooks, custom branding, signing link expiry and SSO.</li>
          </ul>

          <h2 id="licence">Licence</h2>
          <p>Countersign is free software under the GNU Affero General Public License v3.0. You can use, modify and self-host it, including commercially. If you run a modified version as a network service, you must offer its source code to the people who use it. The full text is in the <code>LICENSE</code> file in the <a href="https://github.com/cre8ive-marketing/Countersign">source repository</a>.</p>
        </div>
      </div>
    </MarketingLayout>
  );
}
