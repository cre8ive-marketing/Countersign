import { useRef, useState } from 'react';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';

// Each role is a real workflow built only from v1 capabilities (see PRODUCT.md).
export const ROLES = [
  {
    id: 'agencies', label: 'Agencies',
    title: 'Statements of work, signed by both sides.',
    body: 'Save your standard agreement as a template with Agency and Client roles. Each new project only needs names and emails.',
    flow: [
      ['Template', 'Fields already placed for Agency and Client'],
      ['Order', 'Your director signs first, then the client is emailed'],
      ['Reminders', 'The client is reminded every few days until they sign'],
      ['Done', 'Both sides download the signed PDF with its certificate'],
    ],
  },
  {
    id: 'sales', label: 'Sales',
    title: 'Order forms with several people on the client side.',
    body: 'Send one document to every signer at once, plus anyone who only needs a copy. See who has opened it and who has signed.',
    flow: [
      ['Parallel', 'Every signer gets their own private link at the same time'],
      ['Copies', 'Finance or legal receive the signed copy without signing'],
      ['Status', 'Viewed and signed states for each person on the document page'],
      ['No email server', 'Copy a signing link and send it in your own thread'],
    ],
  },
  {
    id: 'hr', label: 'HR',
    title: 'Offer letters a candidate can sign on a phone.',
    body: 'Candidates open a link, follow the guided next-field button, and type or draw a signature. They never create an account.',
    flow: [
      ['Template', 'One offer letter with name, date and signature fields'],
      ['Phone', 'A guided next-field button that works on small screens'],
      ['Decline', 'A candidate can decline with a reason, which is logged'],
      ['Record', 'Every step is logged with the time, and the IP and browser when done in a browser'],
    ],
  },
  {
    id: 'internal', label: 'Internal',
    title: 'Approvals that move in a set order.',
    body: 'Route a purchase request from manager to finance to director, or sign a document yourself without sending it to anyone.',
    flow: [
      ['Sequential', 'The next approver is notified when the previous one signs'],
      ['Self-sign', 'Sign your own paperwork and keep the audit record'],
      ['Void', 'Something changed? Void it, with a reason, while it is out for signature'],
      ['Archive', 'Signed PDFs stay in one data volume on your server'],
    ],
  },
];

export default function RoleTabs() {
  const [active, setActive] = useState(0);
  const tabs = useRef([]);
  const role = ROLES[active];

  function onKey(e) {
    const last = ROLES.length - 1;
    const next = { ArrowRight: active === last ? 0 : active + 1, ArrowLeft: active === 0 ? last : active - 1, Home: 0, End: last }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    setActive(next);
    tabs.current[next]?.focus();
  }

  return (
    <div className="mk-roles">
      <div role="tablist" aria-label="Use cases" className="mk-tablist" onKeyDown={onKey}>
        {ROLES.map((r, i) => (
          <button key={r.id} ref={(el) => { tabs.current[i] = el; }} type="button" role="tab" id={`tab-${r.id}`}
            aria-selected={i === active} aria-controls="mk-role-panel" tabIndex={i === active ? 0 : -1} onClick={() => setActive(i)}>
            {r.label}
          </button>
        ))}
      </div>
      <div id="mk-role-panel" role="tabpanel" aria-labelledby={`tab-${role.id}`} className="mk-tint mk-role" tabIndex={0}>
        <div>
          <h3>{role.title}</h3>
          <p>{role.body}</p>
          <Link href={`/use-cases#${role.id}`} className="mk-more">See the {role.label} workflow<ArrowRight size={16} aria-hidden="true" /></Link>
        </div>
        <RoleFlow flow={role.flow} />
      </div>
    </div>
  );
}

export function RoleFlow({ flow }) {
  return (
    <ol className="mk-flow">
      {flow.map(([t, d]) => <li key={t}><strong>{t}</strong><span>{d}</span></li>)}
    </ol>
  );
}
