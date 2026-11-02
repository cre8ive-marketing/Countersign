import { ArrowRight, Check } from 'lucide-react';
import { Button } from '../components/ui';
import MarketingLayout, { CloseBand } from '../components/marketing/MarketingLayout';
import { useSession, primaryAction } from '../components/marketing/useSession';

// Only v1 capabilities from PRODUCT.md and README.md.
const SECTIONS = [
  ['prepare', 'Prepare any PDF in a few clicks.', 'Upload the file you already have. Click to place fields for each person, drag to move, resize from the corner, and nudge with the arrow keys.', [
    'Signature, initials, date signed, full name, email, text and checkbox fields',
    'Each recipient gets a colour, so you can see whose field is whose',
    'Required or optional fields for every person',
  ]],
  ['route', 'Everyone at once, or one after another.', 'Add as many signers as the document needs, plus people who only receive the finished copy. Choose parallel signing, or a set order where the next person is notified when the previous one finishes.', [
    'People with the same order number sign in parallel',
    'Copy recipients get the signed PDF without signing',
    'No email server? Copy each private signing link and send it yourself',
  ]],
  ['signer', 'A signer view that needs no instructions.', 'Signers open a private link. No account, no download. A guided button takes them to the next field until the document is done.', [
    'Type a signature in one of five handwriting styles, draw it, or upload your own',
    'Adopt a signature once and apply it to every signature field',
    'Works on phones and by keyboard',
  ]],
  ['templates', 'Templates for the documents you send every week.', 'Save any document as a template with role names such as Client and Agency. Reuse it and only fill in names and emails.', [
    'Fields stay where you placed them',
    'Signing order and reminder settings come with the template',
  ]],
  ['manage', 'Follow every document to the end.', 'The dashboard groups what needs your signature, what is waiting for others, what is completed and what is still a draft.', [
    'Send a reminder by hand, or every few days automatically',
    'Signers can decline with a reason',
    'Void a document while it is out for signature, with a reason',
  ]],
  ['audit', 'An audit trail and a certificate in every signed PDF.', 'When the last person signs, fields are flattened into the PDF and a certificate of completion is added at the end.', [
    'Signers, emails, view and sign times, and each signature',
    'The full audit trail with the time of each event, and the IP address for actions taken in a browser',
    'The SHA-256 fingerprint of the original document',
    'A tamper-evident hash chain of events, with its head printed on the certificate',
  ]],
];

export default function Product() {
  const session = useSession();
  const cta = primaryAction(session);
  return (
    <MarketingLayout session={session} title="Product · Countersign" description="Prepare, send, sign and track PDFs with an audit trail and certificate of completion, on your own server.">
      <section className="mk-page-head">
        <div className="lp-wrap">
          <h1>The whole signing workflow, and nothing locked.</h1>
          <p className="lp-lead">Upload, place fields, route to every signer, and get a signed PDF with a certificate back. If it is in the code, you have it.</p>
          <div className="lp-hero-actions"><Button variant="accent" size="lg" href={cta.href}>{cta.label}<ArrowRight size={18} aria-hidden="true" /></Button></div>
        </div>
      </section>
      {SECTIONS.map(([id, title, body, points]) => (
        <section key={id} id={id} className="mk-row" aria-labelledby={`${id}-h`}>
          <div className="lp-wrap lp-split">
            <h2 id={`${id}-h`} className="lp-h2">{title}</h2>
            <div>
              <p className="mk-row-body">{body}</p>
              <ul className="lp-checks">{points.map((p) => <li key={p}><Check size={18} aria-hidden="true" />{p}</li>)}</ul>
            </div>
          </div>
        </section>
      ))}
      <CloseBand>
        <Button variant="accent" size="lg" href={cta.href}>{cta.label}<ArrowRight size={18} aria-hidden="true" /></Button>
        <Button variant="secondary" size="lg" href="/self-host">Self-host guide</Button>
      </CloseBand>
    </MarketingLayout>
  );
}
