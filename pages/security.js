import Link from 'next/link';
import { CircleCheck } from 'lucide-react';
import MarketingLayout from '../components/marketing/MarketingLayout';
import { useSession } from '../components/marketing/useSession';

const EVENTS = [
  ['Uploaded', 'The sender added the PDF'],
  ['Sent', 'The document went out to its signers'],
  ['Emailed / Ready to sign', 'A signer’s link was emailed, or made ready to copy'],
  ['Viewed', 'A signer opened their link'],
  ['Signed', 'A signer finished their fields'],
  ['Declined', 'A signer declined, with their reason'],
  ['Reminded / Reminder sent', 'A reminder went out, by hand or on schedule'],
  ['Voided', 'The sender cancelled the document, with a reason'],
  ['Template created', 'A document was saved as a template'],
  ['Created from template', 'A new document was started from a template'],
  ['Completed', 'Everyone signed and the final PDF was built'],
];

const GAPS = [
  'Titles, names, email addresses and audit entries are not encrypted in the database, so the dashboard can list and search them. Protect the data volume with disk encryption and access control.',
  'Someone with write access to the database and the encryption key can still rewrite history. Ship the server’s logs off the machine to keep an independent record.',
  'There is no two-factor sign-in, email verification, encryption-key rotation or password reset yet.',
  'The Content-Security-Policy is partial: framing, base URL, form targets and plugins are locked down, while the script and style policy runs in report-only mode for now.',
  'There is no PAdES or X.509 seal on the signed PDF.',
];

const CONTROLS = [
  'Encryption at rest for every PDF and field value',
  'Per-account access control, checked on the server',
  'Session timeouts, sign-in limits and sign out of all devices',
  'A tamper-evident audit trail for every document',
  'Security event logs you can ship to your own log system',
];

export default function Security() {
  const session = useSession();
  return (
    <MarketingLayout session={session} title="Security and audit · Countersign" description="What Countersign records for every document, where your data lives, and the known limits.">
      <section className="mk-page-head">
        <div className="lp-wrap">
          <h1>What Countersign records, and what it does not.</h1>
          <p className="lp-lead">Every document carries its own history. Here is exactly what is logged, where it is stored, and the limits you should know before you rely on it.</p>
        </div>
      </section>

      <section className="mk-row" aria-labelledby="events-h">
        <div className="lp-wrap lp-split">
          <div>
            <h2 id="events-h" className="lp-h2">Every action is an audit event.</h2>
            <p className="mk-row-body">Each event stores the time, the person, the action and, for actions taken in a browser, the IP address and browser. Behind a proxy, set <code>TRUST_PROXY=true</code> so the real client IP is recorded.</p>
            <p className="mk-row-body">Events form a keyed hash chain per document, so a changed or removed entry breaks the chain. The chain head is printed on the certificate. Signing links expire, and voiding or declining a document revokes them.</p>
          </div>
          <div className="mk-table-wrap">
            <table className="mk-table">
              <thead><tr><th scope="col">Event</th><th scope="col">When it is recorded</th></tr></thead>
              <tbody>{EVENTS.map(([e, d]) => <tr key={e}><th scope="row">{e}</th><td>{d}</td></tr>)}</tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="mk-row lp-muted" aria-labelledby="cert-h">
        <div className="lp-wrap lp-trust">
          <div>
            <h2 id="cert-h" className="lp-h2">A certificate inside every signed PDF.</h2>
            <p className="mk-row-body">When the last person signs, field values are flattened into the pages so they cannot be edited, and a certificate of completion is added at the end.</p>
            <ul className="lp-checks">
              <li><CircleCheck size={18} aria-hidden="true" />Document name, ID, page count, sent and completed times</li>
              <li><CircleCheck size={18} aria-hidden="true" />The SHA-256 fingerprint of the original PDF</li>
              <li><CircleCheck size={18} aria-hidden="true" />Each signer, their email, view and sign times and signature</li>
              <li><CircleCheck size={18} aria-hidden="true" />The audit trail with times, and IP addresses for actions taken in a browser</li>
              <li><CircleCheck size={18} aria-hidden="true" />The head of the audit hash chain and the number of events</li>
            </ul>
            <p className="mk-row-body">The SHA-256 of the finished signed PDF is stored too and shown on the sender’s document page.</p>
          </div>
          <figure className="cert" aria-label="Example certificate of completion">
            <div className="cert-head">Certificate of completion</div>
            <dl className="cert-meta">
              <dt>Document</dt><dd>Website redesign agreement</dd>
              <dt>Status</dt><dd className="cert-ok"><CircleCheck size={14} aria-hidden="true" />Completed</dd>
              <dt>SHA-256</dt><dd className="mono">9f2c71d0…be04a41e</dd>
            </dl>
            <ol className="cert-log">
              {[['Sent', 'Priya Nair', '09:10'], ['Viewed', 'Alex Morgan', '10:41'], ['Signed', 'Alex Morgan', '10:42'], ['Completed', 'Countersign', '10:42']].map(([a, who, t]) => (
                <li key={a}><strong>{a}</strong><span>{who}</span><time>{t}</time></li>
              ))}
            </ol>
            <figcaption>Sample data</figcaption>
          </figure>
        </div>
      </section>

      <section className="mk-row" aria-labelledby="data-h">
        <div className="lp-wrap lp-split">
          <h2 id="data-h" className="lp-h2">Your server, your data.</h2>
          <div className="mk-prose">
            <ul>
              <li>Documents, signatures and the database live in one data volume on the server you run. Countersign sends nothing to any outside service except the SMTP server you configure.</li>
              <li>Every PDF and every signature, initial and field value is encrypted with AES-256-GCM, bound to its own document or field so files can’t be swapped. Every download is checked against its recorded SHA-256 fingerprint and refused if it doesn’t match.</li>
              <li>You hold the key. Set <code>ENCRYPTION_KEY</code> and back it up separately from the data: losing it means losing every document.</li>
              <li>Accounts sign in with an email and a password of at least 12 characters, hashed with scrypt. Sessions use an HttpOnly, SameSite cookie, marked Secure when <code>APP_URL</code> is https, and end after inactivity or a maximum age. Repeated failed sign-ins lock temporarily.</li>
              <li>Each account sees only its own documents. Signers have no account; each gets a private link for their own fields only.</li>
              <li>Cross-site browser requests are rejected, and every check happens on the server.</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="mk-row lp-muted" aria-labelledby="gaps-h">
        <div className="lp-wrap lp-split">
          <div>
            <h2 id="gaps-h" className="lp-h2">Known limits.</h2>
            <p className="mk-row-body">These are open today. Plan around them, for example by running Countersign behind a VPN or an authenticating proxy.</p>
          </div>
          <div className="mk-prose"><ul>{GAPS.map((g) => <li key={g}>{g}</li>)}</ul></div>
        </div>
      </section>

      <section className="mk-row" aria-labelledby="audits-h">
        <div className="lp-wrap lp-split">
          <h2 id="audits-h" className="lp-h2">Standards and audits.</h2>
          <div className="mk-prose">
            <p>Countersign is software you run, so it can’t be certified itself. ISO/IEC 27001, SOC 1 and SOC 2 (SSAE 18), CSA STAR and APEC PRP assess the organisation that operates a service. Countersign supplies technical controls you can cite in those audits:</p>
            <ul>{CONTROLS.map((c) => <li key={c}>{c}</li>)}</ul>
            <p>Policies, risk assessment, monitoring, incident response and the audit itself stay with you as the operator. Countersign stores no payment card data, so PCI DSS does not apply. See the <a href="https://github.com/cre8ive-marketing/Countersign/blob/main/docs/security/control-mapping.md">control-by-control mapping</a>, including what is only partly covered.</p>
          </div>
        </div>
      </section>

      <section className="mk-row lp-muted" aria-labelledby="legal-h">
        <div className="lp-wrap lp-split">
          <h2 id="legal-h" className="lp-h2">What a signature here means.</h2>
          <div className="mk-prose">
            <p>Countersign records electronic signatures and an audit trail. A signature image is a mark of intent, not proof of identity: Countersign does not verify who a signer is beyond access to their link. Whether an electronic signature is right for a document depends on the document and the jurisdiction, so check the rules that apply to you.</p>
            <p>More on running it safely in the <Link href="/self-host#https">self-host guide</Link>.</p>
          </div>
        </div>
      </section>
    </MarketingLayout>
  );
}
