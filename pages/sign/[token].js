import { useMemo, useRef, useState } from 'react';
import Head from 'next/head';
import { ArrowRight, Download, CircleCheck, Clock, Ban, Lock, X } from 'lucide-react';
import { markViewed, recipientByToken } from '../../lib/documents';
import db from '../../lib/db';
import { apiFetch, FIELD_META } from '../../lib/client';
import { Button, Logo } from '../../components/ui';
import PdfPages from '../../components/PdfPages';
import SignaturePad from '../../components/SignaturePad';

export async function getServerSideProps({ params, req }) {
  const found = recipientByToken(params.token);
  if (!found) return { notFound: true };
  const { recipient: r, doc, fields } = found;
  if (doc.status === 'sent') markViewed(r, req);
  const sender = db.prepare('SELECT name, email FROM users WHERE id = ?').get(doc.owner_id);

  let state = 'sign';
  if (doc.status === 'completed') state = 'completed';
  else if (doc.status === 'voided' || doc.status === 'declined') state = doc.status;
  else if (r.status === 'signed') state = 'waiting';
  else if (r.status === 'pending' && r.role === 'signer') state = 'queued';
  else if (r.role === 'cc') state = 'cc';

  return {
    props: {
      token: params.token,
      state,
      doc: { title: doc.title, message: doc.message },
      sender,
      me: { id: r.id, name: r.name, email: r.email },
      // Other signers' finished values are shown read-only so the signer sees the document as it stands.
      fields: state === 'sign' ? fields.map((f) => ({
        id: f.id, type: f.type, page: f.page, x: f.x, y: f.y, w: f.w, h: f.h,
        required: !!f.required, label: f.label, mine: f.recipient_id === r.id, value: f.recipient_id === r.id ? null : f.value,
      })) : [],
    },
  };
}

export default function SignPage({ token, state: initialState, doc, sender, me, fields }) {
  const [state, setState] = useState(initialState);
  return (
    <div className="signer">
      <Head><title>{`${doc.title} · Countersign`}</title><meta name="robots" content="noindex" /></Head>
      {state === 'sign'
        ? <Signing token={token} doc={doc} sender={sender} me={me} fields={fields} onDone={setState} />
        : <Status state={state} token={token} doc={doc} sender={sender} />}
    </div>
  );
}

function Status({ state, token, doc, sender }) {
  const content = {
    completed: { icon: CircleCheck, tone: 'ok', title: 'Everyone has signed', body: `${doc.title} is complete. Download your copy with its certificate of completion.` },
    waiting: { icon: Clock, tone: 'warn', title: 'You’re done', body: `Your signature is saved. We’ll let you know when everyone else has signed ${doc.title}.` },
    queued: { icon: Clock, tone: 'neutral', title: 'Not your turn yet', body: `${sender.name} set a signing order. You’ll get an email when it’s your turn.` },
    cc: { icon: Clock, tone: 'neutral', title: 'You’ll get a copy', body: `${sender.name} added you to receive ${doc.title} once everyone has signed.` },
    voided: { icon: Ban, tone: 'bad', title: 'This document was voided', body: `${sender.name} cancelled ${doc.title}. Nothing more is needed from you.` },
    declined: { icon: Ban, tone: 'bad', title: 'This document was declined', body: `Signing for ${doc.title} has stopped. ${sender.name} has been notified.` },
  }[state];
  const Icon = content.icon;
  return (
    <div className="status-page">
      <div className="status-card">
        <Logo href="#" />
        <span className={`status-icon tone-${content.tone}`}><Icon size={22} strokeWidth={1.75} aria-hidden="true" /></span>
        <h1>{content.title}</h1>
        <p>{content.body}</p>
        {state === 'completed' && (
          <Button variant="primary" href={`/api/sign/${token}/file?download=1`}><Download size={16} aria-hidden="true" />Download signed PDF</Button>
        )}
        <p className="status-foot"><Lock size={12} aria-hidden="true" />Sent by {sender.name} ({sender.email}) from a self-hosted Countersign server</p>
      </div>
    </div>
  );
}

function Signing({ token, doc, sender, me, fields, onDone }) {
  const mine = fields.filter((f) => f.mine);
  const today = useMemo(() => new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }), []);
  const [values, setValues] = useState({});
  const [adopted, setAdopted] = useState({});
  const [pad, setPad] = useState(null); // { fieldId, kind }
  const [declining, setDeclining] = useState(false);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [started, setStarted] = useState(false);
  const padDialog = useRef(null);
  const declineDialog = useRef(null);

  const autoValue = (f) => ({ date: today, name: me.name, email: me.email }[f.type]);
  const isFilled = (f) => FIELD_META[f.type].auto || (f.type === 'checkbox' ? values[f.id] === true : Boolean(values[f.id]));
  const required = mine.filter((f) => f.required && !FIELD_META[f.type].auto);
  const remaining = required.filter((f) => !isFilled(f));
  const done = required.length - remaining.length;

  function openPad(f) {
    if (adopted[f.type]) return setValues((v) => ({ ...v, [f.id]: adopted[f.type] }));
    setPad({ fieldId: f.id, kind: f.type });
    padDialog.current?.showModal();
  }
  function adopt(png) {
    if (!png) return;
    setAdopted((a) => ({ ...a, [pad.kind]: png }));
    setValues((v) => ({ ...v, [pad.fieldId]: png }));
    padDialog.current?.close();
    setPad(null);
  }

  function next() {
    setStarted(true);
    const target = remaining[0] ?? mine[0];
    if (!target) return;
    const el = document.querySelector(`[data-field="${target.id}"]`);
    el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setTimeout(() => (el?.querySelector('input') ?? el)?.focus({ preventScroll: true }), 350);
  }

  async function finish() {
    if (remaining.length) return next();
    setBusy(true);
    setError(null);
    try {
      const { status } = await apiFetch(`/api/sign/${token}`, { body: { values } });
      onDone(status === 'completed' ? 'completed' : 'waiting');
    } catch (e) {
      setError(e.message);
      setBusy(false);
    }
  }

  async function decline(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await apiFetch(`/api/sign/${token}/decline`, { body: { reason } });
      declineDialog.current?.close();
      onDone('declined');
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <>
      <header className="signer-bar">
        <Logo href="#" compact />
        <div className="signer-bar-title">
          <strong>{doc.title}</strong>
          <span>From {sender.name}</span>
        </div>
        <div className="signer-bar-actions">
          <Button variant="ghost" type="button" onClick={() => declineDialog.current?.showModal()}>Decline</Button>
          <Button variant={remaining.length ? 'primary' : 'accent'} onClick={finish} loading={busy}>
            {remaining.length ? <>{started ? 'Next field' : 'Start'}<ArrowRight size={15} aria-hidden="true" /></> : 'Finish'}
          </Button>
        </div>
      </header>

      <div className="signer-progress" aria-live="polite">
        <div className="signer-progress-bar"><span style={{ transform: `scaleX(${required.length ? done / required.length : 1})` }} /></div>
        <span>{required.length ? `${done} of ${required.length} required fields` : 'Nothing to fill in. Review and finish.'}</span>
      </div>

      {error && <div className="signer-error" role="alert">{error}</div>}

      <main className="signer-main">
        <section className="signer-intro">
          <h1>{sender.name} asked you to sign</h1>
          <p>Review {doc.title}, then fill in the highlighted fields. It takes about a minute. No account needed.</p>
          {doc.message && <blockquote>{doc.message}</blockquote>}
        </section>

        <PdfPages
          url={`/api/sign/${token}/file`}
          renderOverlay={(page, size) => (
            <div className="page-overlay">
              {fields.filter((f) => f.page === page).map((f) => {
                const style = { left: f.x * size.width, top: f.y * size.height, width: f.w * size.width, height: f.h * size.height };
                if (!f.mine) return <ReadOnlyField key={f.id} field={f} style={style} />;
                return (
                  <SignerField key={f.id} field={f} style={style} value={values[f.id]} auto={autoValue(f)}
                    onChange={(v) => setValues((s) => ({ ...s, [f.id]: v }))} onSign={() => openPad(f)} />
                );
              })}
            </div>
          )}
        />
      </main>

      <dialog ref={padDialog} className="dialog" onClose={() => setPad(null)} aria-labelledby="pad-title">
        {pad && (
          <>
            <h2 id="pad-title">{pad.kind === 'initials' ? 'Adopt your initials' : 'Adopt your signature'}</h2>
            <SignaturePad kind={pad.kind} defaultName={me.name} onAdopt={adopt} onCancel={() => padDialog.current?.close()} />
          </>
        )}
      </dialog>

      <dialog ref={declineDialog} className="dialog" aria-labelledby="decline-title">
        <form onSubmit={decline}>
          <h2 id="decline-title">Decline to sign?</h2>
          <p className="dialog-text">{sender.name} will be notified and the document will stop here for everyone.</p>
          <div className="field">
            <label htmlFor="reason">Reason</label>
            <textarea id="reason" className="input" rows={3} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Let them know why" />
          </div>
          <div className="dialog-actions">
            <Button variant="ghost" type="button" onClick={() => declineDialog.current?.close()}>Keep reviewing</Button>
            <Button variant="danger" type="submit" loading={busy}><Ban size={16} aria-hidden="true" />Decline</Button>
          </div>
        </form>
      </dialog>
    </>
  );
}

function SignerField({ field: f, style, value, auto, onChange, onSign }) {
  const meta = FIELD_META[f.type];
  const filled = meta.auto || (f.type === 'checkbox' ? value === true : Boolean(value));
  const cls = `sfield is-${f.type}${filled ? ' is-filled' : ''}${f.required ? ' is-required' : ''}`;

  if (meta.auto) {
    return <div className={cls} style={style} data-field={f.id}><span className="sfield-text">{auto}</span></div>;
  }
  if (f.type === 'signature' || f.type === 'initials') {
    return (
      <button type="button" className={cls} style={style} data-field={f.id} onClick={onSign} aria-label={value ? `${meta.label}, signed. Click to sign again` : `${meta.label}, click to sign`}>
        {value ? <img src={value} alt="" /> : <span className="sfield-cta">{f.type === 'initials' ? 'Initial' : 'Sign'}</span>}
      </button>
    );
  }
  if (f.type === 'checkbox') {
    return (
      <label className={cls} style={style} data-field={f.id}>
        <input type="checkbox" checked={value === true} onChange={(e) => onChange(e.target.checked)} aria-label={f.label || 'Checkbox'} />
      </label>
    );
  }
  return (
    <div className={cls} style={style} data-field={f.id}>
      <input value={value ?? ''} onChange={(e) => onChange(e.target.value)} placeholder={f.label || (f.required ? 'Required' : 'Optional')} aria-label={f.label || 'Text'} maxLength={500} />
    </div>
  );
}

function ReadOnlyField({ field: f, style }) {
  if (!f.value) return null;
  if (f.type === 'signature' || f.type === 'initials') return <img className="rofield" style={style} src={f.value} alt="Signed" />;
  if (f.type === 'checkbox') return f.value === 'true' ? <span className="rofield rofield-check" style={style} aria-label="Checked"><X size="80%" strokeWidth={2.5} /></span> : null;
  return <span className="rofield rofield-text" style={style}><span>{f.value}</span></span>;
}
