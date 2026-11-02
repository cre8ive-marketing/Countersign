import { useEffect, useMemo, useRef, useState } from 'react';
import Head from 'next/head';
import { ArrowRight, Download, CircleCheck, Clock, Ban, Lock, Link2Off, X, MailCheck, CalendarClock } from 'lucide-react';
import { signerByToken, markViewed, signerVerified, maskEmail } from '../../lib/documents';
import db from '../../lib/db';
import { apiFetch, FIELD_META, NUMBER_RE } from '../../lib/client';
import { Button, Logo } from '../../components/ui';
import PdfPages from '../../components/PdfPages';
import SignaturePad from '../../components/SignaturePad';

export async function getServerSideProps({ params, req, res }) {
  let found;
  try {
    found = signerByToken(params.token, req);
    if (!found) throw Object.assign(new Error('Not found'), { status: 404 });
  } catch (e) {
    if (e.status !== 410 && e.status !== 404) throw e;
    // A dead link gets a calm page with the right status code; the token is never sent back.
    res.statusCode = e.status;
    const docExpired = /^This document expired/i.test(e.message);
    const state = e.status === 404 ? 'link-unknown' : docExpired ? 'expired' : /expired/i.test(e.message) ? 'link-expired' : 'link-invalid';
    return { props: { token: null, state, doc: null, sender: null, me: null, fields: [], notice: docExpired ? e.message : null } };
  }
  const { recipient: r, doc, fields } = found;
  const sender = db.prepare('SELECT name, email FROM users WHERE id = ?').get(doc.owner_id);

  let state = 'sign';
  if (doc.status === 'completed') state = 'completed';
  else if (doc.status === 'voided' || doc.status === 'declined' || doc.status === 'expired') state = doc.status;
  else if (r.status === 'signed') state = 'waiting';
  else if (r.status === 'pending' && r.role === 'signer') state = 'queued';
  else if (r.role === 'cc') state = 'cc';

  // Until verified, the page gets no fields, message or address; the API routes enforce the same on the server.
  const notice = state === 'expired' && doc.expires_at ? `This document expired on ${new Date(doc.expires_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}.` : null;
  // Status pages (queued, cc, waiting, voided...) only need the title, so they show without a code but still leak nothing else.
  if (!signerVerified(found, req)) {
    const gated = state === 'sign' || state === 'completed';
    return { props: { token: params.token, state: gated ? 'verify' : state, doc: { title: doc.title }, sender, me: null, fields: [], notice, maskedEmail: maskEmail(r.email) } };
  }
  if (doc.status === 'sent') markViewed(r, req);

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
        options: f.options,
      })) : [],
      notice,
    },
  };
}

export default function SignPage({ token, state: initialState, doc, sender, me, fields, notice, maskedEmail }) {
  const [state, setState] = useState(initialState);
  return (
    <div className="signer">
      <Head><title>{`${doc?.title ?? 'Signing link'} · Countersign`}</title><meta name="robots" content="noindex" /></Head>
      {state === 'sign'
        ? <Signing token={token} doc={doc} sender={sender} me={me} fields={fields} onDone={setState} />
        : state === 'verify'
          ? <Verify token={token} doc={doc} sender={sender} maskedEmail={maskedEmail} />
          : <Status state={state} token={token} doc={doc} sender={sender} notice={notice} />}
    </div>
  );
}

const CODE_COOLDOWN = 60; // seconds; matches the server's resend cooldown

function Verify({ token, doc, sender, maskedEmail }) {
  const [sentTo, setSentTo] = useState(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(null); // 'send' | 'verify'
  const [error, setError] = useState(null);
  const [wait, setWait] = useState(0);
  const input = useRef(null);
  const errorRef = useRef(null);

  useEffect(() => {
    if (wait <= 0) return;
    const t = setTimeout(() => setWait((w) => w - 1), 1000);
    return () => clearTimeout(t);
  }, [wait]);
  useEffect(() => { if (error) errorRef.current?.focus(); }, [error]);

  async function send() {
    setBusy('send');
    setError(null);
    try {
      const { sentTo: to } = await apiFetch(`/api/sign/${token}/otp`, { body: { action: 'send' } });
      setSentTo(to || maskedEmail || 'your email');
      setCode('');
      setWait(CODE_COOLDOWN);
      setTimeout(() => input.current?.focus(), 0);
    } catch (e) {
      setError(e.message);
      if (e.status === 429 && e.retryAfter) setWait(e.retryAfter);
    } finally {
      setBusy(null);
    }
  }

  async function verify(e) {
    e.preventDefault();
    if (!/^\d{6}$/.test(code)) return setError('Enter the 6-digit code from the email.');
    setBusy('verify');
    setError(null);
    try {
      await apiFetch(`/api/sign/${token}/otp`, { body: { action: 'verify', code } });
      window.location.reload(); // the server now sees the verification cookie and returns the document
    } catch (err) {
      setError(err.message);
      setBusy(null);
    }
  }

  return (
    <div className="status-page">
      <div className="status-card">
        <Logo href={null} />
        <span className="status-icon tone-warn"><MailCheck size={22} strokeWidth={1.75} aria-hidden="true" /></span>
        <h1>Confirm it’s you</h1>
        <p>{sender.name} asked for an email code before you can open {doc.title}.{' '}
          {sentTo ? `We sent a 6-digit code to ${sentTo}. It works for 10 minutes.` : `We’ll send it to ${maskedEmail || 'the address this link was sent to'}.`}</p>
        {error && <p className="otp-error" role="alert" tabIndex={-1} ref={errorRef}>{error}</p>}
        {sentTo ? (
          <form className="otp-form" onSubmit={verify} noValidate>
            <label htmlFor="otp-code">Code</label>
            <input id="otp-code" ref={input} className="input otp-input" inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6}
              value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} aria-invalid={error ? true : undefined} />
            <Button variant="accent" type="submit" loading={busy === 'verify'} disabled={!!busy}>Verify and continue</Button>
            <Button variant="ghost" type="button" onClick={send} loading={busy === 'send'} disabled={!!busy || wait > 0}>
              {wait > 0 ? `Send a new code in ${wait}s` : 'Send a new code'}
            </Button>
          </form>
        ) : (
          <Button variant="primary" onClick={send} loading={busy === 'send'} disabled={!!busy || wait > 0}>
            {wait > 0 ? `Email me a code in ${wait}s` : 'Email me a code'}
          </Button>
        )}
        <p className="status-foot"><Lock size={12} aria-hidden="true" />Sent by {sender.name} ({sender.email}) from a self-hosted Countersign server</p>
      </div>
    </div>
  );
}

function Status({ state, token, doc, sender, notice }) {
  // Link-error states have no document or sender, and every body below is built eagerly.
  const title = doc?.title, from = sender?.name;
  const content = {
    completed: { icon: CircleCheck, tone: 'ok', title: 'Everyone has signed', body: `${title} is complete. Download your copy with its certificate of completion.` },
    waiting: { icon: Clock, tone: 'warn', title: 'You’re done', body: `Your signature is saved. We’ll let you know when everyone else has signed ${title}.` },
    queued: { icon: Clock, tone: 'neutral', title: 'Not your turn yet', body: `${from} set a signing order. You’ll get an email when it’s your turn.` },
    cc: { icon: Clock, tone: 'neutral', title: 'You’ll get a copy', body: `${from} added you to receive ${title} once everyone has signed.` },
    voided: { icon: Ban, tone: 'bad', title: 'This document was voided', body: `${from} cancelled ${title}. Nothing more is needed from you.` },
    declined: { icon: Ban, tone: 'bad', title: 'This document was declined', body: `Signing for ${title} has stopped. ${from} has been notified.` },
    expired: { icon: CalendarClock, tone: 'neutral', title: 'This document expired', body: `${notice ? `${notice} ` : ''}Signing is closed and nothing more is needed from you. Ask the sender if you still need to sign.` },
    'link-expired': { icon: Clock, tone: 'neutral', title: 'This signing link has expired', body: 'Links stop working after a while to keep your documents safe. Ask the sender to send you a new link.' },
    'link-invalid': { icon: Link2Off, tone: 'neutral', title: 'This signing link no longer works', body: 'The document may have been completed, cancelled or sent again. Ask the sender for a new link if you still need to sign.' },
    'link-unknown': { icon: Link2Off, tone: 'neutral', title: 'We couldn’t find this signing link', body: 'Check that you opened the full link from your email, or ask the sender to send it again.' },
  }[state];
  const Icon = content.icon;
  return (
    <div className="status-page">
      <div className="status-card">
        <Logo href={null} />
        <span className={`status-icon tone-${content.tone}`}><Icon size={22} strokeWidth={1.75} aria-hidden="true" /></span>
        <h1>{content.title}</h1>
        <p>{content.body}</p>
        {state === 'completed' && (
          <Button variant="primary" href={`/api/sign/${token}/file?download=1`}><Download size={16} aria-hidden="true" />Download signed PDF</Button>
        )}
        <p className="status-foot"><Lock size={12} aria-hidden="true" />{sender ? `Sent by ${sender.name} (${sender.email}) from a self-hosted Countersign server` : 'A self-hosted Countersign server'}</p>
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
    setTimeout(() => (el?.querySelector('input, select') ?? el)?.focus({ preventScroll: true }), 350);
  }

  async function finish() {
    if (remaining.length) return next();
    const badNumber = mine.find((f) => f.type === 'number' && values[f.id] && !NUMBER_RE.test(values[f.id].trim()));
    if (badNumber) {
      setError('Enter a number');
      return document.querySelector(`[data-field="${badNumber.id}"] input`)?.focus();
    }
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
        <Logo href={null} compact />
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
            <h2 id="pad-title">{{ initials: 'Adopt your initials', stamp: 'Upload your stamp' }[pad.kind] ?? 'Adopt your signature'}</h2>
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
  if (f.type === 'signature' || f.type === 'initials' || f.type === 'stamp') {
    const verb = f.type === 'stamp' ? 'stamp' : 'sign';
    return (
      <button type="button" className={cls} style={style} data-field={f.id} onClick={onSign} aria-label={value ? `${meta.label}, done. Click to ${verb} again` : `${meta.label}, click to ${verb}`}>
        {value ? <img src={value} alt="" /> : <span className="sfield-cta">{{ initials: 'Initial', stamp: 'Stamp' }[f.type] ?? 'Sign'}</span>}
      </button>
    );
  }
  if (f.type === 'dropdown') {
    return (
      <div className={cls} style={style} data-field={f.id}>
        <select value={value ?? ''} onChange={(e) => onChange(e.target.value)} aria-label={f.label || 'Choose an option'}>
          <option value="" disabled={f.required}>{f.required ? 'Choose…' : 'None'}</option>
          {(f.options ?? []).map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
      </div>
    );
  }
  if (f.type === 'radio') {
    return (
      <fieldset className={cls} style={style} data-field={f.id} aria-label={f.label || 'Choose one'}>
        {(f.options ?? []).map((o) => (
          <label key={o} className="sfield-radio">
            <input type="radio" name={`radio-${f.id}`} value={o} checked={value === o} onChange={() => onChange(o)} />
            <span>{o}</span>
          </label>
        ))}
      </fieldset>
    );
  }
  if (f.type === 'number') {
    const bad = Boolean(value) && !NUMBER_RE.test(value.trim());
    return (
      <div className={`${cls}${bad ? ' is-invalid' : ''}`} style={style} data-field={f.id}>
        <input inputMode="decimal" value={value ?? ''} onChange={(e) => onChange(e.target.value)} placeholder={f.label || (f.required ? 'Required' : 'Optional')}
          aria-label={f.label || 'Number'} aria-invalid={bad || undefined} maxLength={23} />
      </div>
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
      <input value={value ?? ''} onChange={(e) => onChange(e.target.value)} placeholder={f.label || (f.required ? 'Required' : 'Optional')} aria-label={f.label || meta.label} maxLength={f.type === 'text' ? 500 : 200} />
    </div>
  );
}

function ReadOnlyField({ field: f, style }) {
  if (!f.value) return null;
  if (f.type === 'signature' || f.type === 'initials' || f.type === 'stamp') return <img className="rofield" style={style} src={f.value} alt={f.type === 'stamp' ? 'Stamped' : 'Signed'} />;
  if (f.type === 'checkbox') return f.value === 'true' ? <span className="rofield rofield-check" style={style} aria-label="Checked"><X size="80%" strokeWidth={2.5} /></span> : null;
  return <span className="rofield rofield-text" style={style}><span>{f.value}</span></span>;
}
