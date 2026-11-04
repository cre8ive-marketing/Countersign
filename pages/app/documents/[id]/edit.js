import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft, Plus, Trash2, ChevronUp, ChevronDown, Send, Check, UserRound, PenLine, X } from 'lucide-react';
import { withUser } from '../../../../lib/auth';
import { ownedDocument, publicUrlFor } from '../../../../lib/documents';
import { teamOf } from '../../../../lib/teams';
import { mailEnabled } from '../../../../lib/mail';
import { apiFetch, cleanOptions, FIELD_META, recipientColor, redirectUrlError } from '../../../../lib/client';
import { Button } from '../../../../components/ui';
import ContactInput from '../../../../components/ContactInput';
import { BulkSend, PublicLink } from '../../../../components/TemplateTools';
import PdfPages from '../../../../components/PdfPages';
import ShareToggle from '../../../../components/ShareToggle';

export const getServerSideProps = withUser(async (ctx, user) => {
  let doc, recipients, fields;
  try { ({ doc, recipients, fields } = ownedDocument(ctx.params.id, user.id, 'read')); }
  catch (e) { if (e.status === 404) return { notFound: true }; throw e; }
  const team = teamOf(user.id);
  const isOwner = doc.owner_id === user.id;
  const canWrite = isOwner || (!!doc.team_id && team?.teamId === doc.team_id && (team.role === 'owner' || team.role === 'admin'));
  if (doc.status !== 'draft' || !canWrite) return { redirect: { destination: `/app/documents/${doc.id}`, permanent: false } };
  return {
    props: {
      user,
      mail: mailEnabled(),
      doc: {
        id: doc.id, title: doc.title, message: doc.message, sequential: !!doc.sequential, reminderDays: doc.reminder_days, isTemplate: !!doc.is_template,
        requireOtp: !!doc.require_otp, expireDays: doc.expire_days ?? 0, redirectUrl: doc.redirect_url ?? '',
        publicUrl: isOwner && doc.is_template ? publicUrlFor(doc) ?? null : null,
        isOwner, teamShared: !!doc.team_id,
      },
      inTeam: !!team,
      initialRecipients: recipients.map((r) => ({ id: r.id, name: r.name, email: r.email, role: r.role })),
      initialFields: fields.map((f) => ({ id: f.id, recipientId: f.recipient_id, type: f.type, page: f.page, x: f.x, y: f.y, w: f.w, h: f.h, required: !!f.required, label: f.label, options: f.options })),
    },
  };
});

const tempId = () => `t${Math.random().toString(36).slice(2, 10)}`;
const clamp01 = (n) => Math.max(0, Math.min(1, n));
const EXPIRY_CHOICES = [0, 7, 14, 30, 60, 90];

export default function Editor({ user, mail, doc, inTeam, initialRecipients, initialFields }) {
  const router = useRouter();
  const [title, setTitle] = useState(doc.title);
  const [message, setMessage] = useState(doc.message);
  const [sequential, setSequential] = useState(doc.sequential);
  const [reminderDays, setReminderDays] = useState(doc.reminderDays);
  const [requireOtp, setRequireOtp] = useState(doc.requireOtp && mail);
  const [expireDays, setExpireDays] = useState(doc.expireDays);
  const [redirectUrl, setRedirectUrl] = useState(doc.redirectUrl);
  const [redirectTouched, setRedirectTouched] = useState(false);
  const [recipients, setRecipients] = useState(initialRecipients.length ? initialRecipients
    : [{ id: tempId(), name: '', email: '', role: 'signer' }]);
  const [fields, setFields] = useState(initialFields);
  const [activeId, setActiveId] = useState(recipients.find((r) => r.role === 'signer')?.id);
  const [placing, setPlacing] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [saveState, setSaveState] = useState('saved');
  const [sending, setSending] = useState(null); // 'send' | 'self'
  const [error, setError] = useState(null);
  const pageSizes = useRef([]);

  const signers = recipients.filter((r) => r.role === 'signer');
  const colorOf = useCallback((rid) => recipientColor(recipients.findIndex((r) => r.id === rid)), [recipients]);
  const selected = fields.find((f) => f.id === selectedId);
  const active = recipients.find((r) => r.id === activeId);

  const redirectError = redirectUrlError(redirectUrl.trim());

  // Autosave the whole draft shortly after any change. An address still being typed is left out so autosave does not fail on it.
  const payload = useMemo(() => ({
    title, message, sequential, reminderDays, requireOtp, expireDays, recipients,
    ...(redirectError ? {} : { redirectUrl: redirectUrl.trim() }),
    fields: fields.map((f) => (FIELD_META[f.type].choices ? { ...f, options: cleanOptions(f.options) } : f)),
  }), [title, message, sequential, reminderDays, requireOtp, expireDays, redirectUrl, redirectError, recipients, fields]);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    setSaveState('dirty');
    const t = setTimeout(() => save(payload), 700);
    return () => clearTimeout(t);
  }, [payload]); // eslint-disable-line react-hooks/exhaustive-deps

  async function save(body) {
    setSaveState('saving');
    try {
      await apiFetch(`/api/documents/${doc.id}`, { method: 'PUT', body });
      setSaveState('saved');
    } catch (e) {
      setSaveState('error');
      setError(e.message);
    }
  }

  // Bulk send and the public link act on the saved template, so save what is on screen first.
  async function saveFirst() {
    if (redirectError) { setRedirectTouched(true); throw new Error(redirectError); }
    await apiFetch(`/api/documents/${doc.id}`, { method: 'PUT', body: payload });
    setSaveState('saved');
  }

  async function send() {
    if (redirectError) { setRedirectTouched(true); return setError(redirectError); }
    setError(null);
    setSending('send');
    try {
      await apiFetch(`/api/documents/${doc.id}`, { method: 'PUT', body: payload });
      if (doc.isTemplate) return router.push('/app?view=templates');
      await apiFetch(`/api/documents/${doc.id}/send`);
      router.push(`/app/documents/${doc.id}?sent=1`);
    } catch (e) {
      setError(e.message);
      setSending(null);
    }
  }

  // Makes the owner the only signer, gives them every field, and opens the signing page. No invitation is emailed.
  async function signMyself() {
    const isMe = (r) => r.email.toLowerCase() === user.email.toLowerCase();
    if (recipients.some((r) => !isMe(r)) && !confirm('Sign it myself removes the other recipients and gives all fields to you. Continue?')) return;
    const me = recipients.find(isMe);
    const self = { id: me?.id ?? tempId(), name: me?.name || user.name, email: user.email, role: 'signer' };
    const movedFields = payload.fields.map((f) => ({ ...f, recipientId: self.id }));
    setRecipients([self]);
    setFields(movedFields);
    setActiveId(self.id);
    setRequireOtp(false);
    setError(null);
    setSending('self');
    try {
      await apiFetch(`/api/documents/${doc.id}`, { method: 'PUT', body: { ...payload, requireOtp: false, recipients: [self], fields: movedFields } });
      const { signUrl } = await apiFetch(`/api/documents/${doc.id}/send`, { body: { selfSign: true } });
      router.push(signUrl);
    } catch (e) {
      setError(e.message);
      setSending(null);
    }
  }

  async function discard() {
    if (!confirm(doc.isTemplate ? 'Delete this template?' : 'Delete this draft?')) return;
    try {
      await apiFetch(`/api/documents/${doc.id}`, { method: 'DELETE' });
      router.push(doc.isTemplate ? '/app?view=templates' : '/app');
    } catch (e) { setError(e.message); }
  }

  // Recipients
  const updateRecipient = (id, patch) => setRecipients((rs) => rs.map((r) => (r.id === id ? { ...r, ...patch } : r)));
  const addRecipient = (r = {}) => {
    const n = { id: tempId(), name: '', email: '', role: 'signer', ...r };
    setRecipients((rs) => [...rs, n]);
    if (n.role === 'signer') setActiveId(n.id);
  };
  const removeRecipient = (id) => {
    setRecipients((rs) => rs.filter((r) => r.id !== id));
    setFields((fs) => fs.filter((f) => f.recipientId !== id));
    if (activeId === id) setActiveId(signers.find((s) => s.id !== id)?.id);
  };
  const moveRecipient = (i, dir) => setRecipients((rs) => {
    const next = [...rs];
    const j = i + dir;
    if (j < 0 || j >= next.length) return rs;
    [next[i], next[j]] = [next[j], next[i]];
    return next;
  });
  const hasMe = recipients.some((r) => r.email.toLowerCase() === user.email.toLowerCase());

  // Fields
  const updateField = (id, patch) => setFields((fs) => fs.map((f) => (f.id === id ? { ...f, ...patch } : f)));
  const removeField = (id) => { setFields((fs) => fs.filter((f) => f.id !== id)); setSelectedId(null); };

  function placeAt(page, e, size) {
    if (!placing || !active) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const meta = FIELD_META[placing];
    const w = meta.w / size.ptWidth;
    const h = meta.h / size.ptHeight;
    const x = clamp01((e.clientX - rect.left) / rect.width - w / 2);
    const y = clamp01((e.clientY - rect.top) / rect.height - h / 2);
    const f = { id: tempId(), recipientId: active.id, type: placing, page, x: Math.min(x, 1 - w), y: Math.min(y, 1 - h), w, h, required: placing !== 'checkbox', label: '',
      options: meta.choices ? ['Option 1', 'Option 2'] : null };
    setFields((fs) => [...fs, f]);
    setSelectedId(f.id);
    setPlacing(null);
  }

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') { setPlacing(null); setSelectedId(null); return; }
      if (!selectedId || /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName)) return;
      if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); removeField(selectedId); }
      const step = e.shiftKey ? 0.01 : 0.002;
      const d = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[e.key];
      if (d) {
        e.preventDefault();
        setFields((fs) => fs.map((f) => (f.id === selectedId ? { ...f, x: clamp01(Math.min(f.x + d[0], 1 - f.w)), y: clamp01(Math.min(f.y + d[1], 1 - f.h)) } : f)));
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selectedId]); // eslint-disable-line react-hooks/exhaustive-deps

  const fieldCount = (rid) => fields.filter((f) => f.recipientId === rid).length;
  const saveLabel = { saved: 'Saved', saving: 'Saving…', dirty: 'Unsaved changes', error: 'Not saved' }[saveState];

  return (
    <div className="editor">
      <Head><title>{`Prepare ${title} · Countersign`}</title></Head>
      <header className={`editor-bar${doc.isTemplate ? ' is-template' : ''}${doc.isOwner && inTeam ? ' has-share' : ''}`}>
        <Link href={doc.isTemplate ? '/app?view=templates' : '/app'} className="icon-btn" aria-label="Back to documents"><ArrowLeft size={18} strokeWidth={1.75} /></Link>
        <div className="editor-title">
          <label htmlFor="doc-title" className="sr-only">Document title</label>
          <input id="doc-title" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} />
          <span className={`save-state is-${saveState}`}>{saveState === 'saved' && <Check size={13} strokeWidth={2} aria-hidden="true" />}{saveLabel}</span>
        </div>
        {doc.isTemplate && <span className="badge badge-neutral">Template</span>}
        <div className="editor-bar-actions">
          {doc.isOwner && inTeam && <ShareToggle docId={doc.id} initialShared={doc.teamShared} />}
          <Button variant="ghost" onClick={discard} aria-label={doc.isTemplate ? 'Delete template' : 'Delete draft'} title={doc.isTemplate ? 'Delete template' : 'Delete draft'}><Trash2 size={16} strokeWidth={1.75} /></Button>
          {doc.isTemplate && (
            <>
              {doc.isOwner && <PublicLink docId={doc.id} initialUrl={doc.publicUrl} eligible={recipients.length === 1 && recipients[0].role === 'signer'} saveFirst={saveFirst} disabled={!!sending} />}
              <BulkSend docId={doc.id} roles={recipients} mail={mail} saveFirst={saveFirst} disabled={!!sending} />
            </>
          )}
          {!doc.isTemplate && (
            <Button variant="secondary" onClick={signMyself} loading={sending === 'self'} disabled={!!sending}>
              <PenLine size={15} strokeWidth={1.75} aria-hidden="true" />Sign it myself
            </Button>
          )}
          <Button variant="primary" onClick={send} loading={sending === 'send'} disabled={!!sending}>
            {doc.isTemplate ? <>Save template</> : <><Send size={15} strokeWidth={1.75} aria-hidden="true" />Send for signature</>}
          </Button>
        </div>
      </header>

      {error && <div className="editor-error" role="alert"><span>{error}</span><button type="button" className="btn btn-ghost btn-sm" onClick={() => setError(null)}>Dismiss</button></div>}

      <div className="editor-body">
        <aside className="editor-rail">
          <section className="rail-section">
            <div className="rail-head">
              <h2>Recipients</h2>
              <label className="switch">
                <input type="checkbox" checked={sequential} onChange={(e) => setSequential(e.target.checked)} />
                <span className="switch-track" aria-hidden="true" />
                Signing order
              </label>
            </div>
            <ol className="recipients">
              {recipients.map((r, i) => {
                const order = recipients.slice(0, i + 1).filter((x) => x.role === 'signer').length;
                return (
                  <li key={r.id} className={`recipient${activeId === r.id ? ' is-active' : ''}`} style={{ '--rc': recipientColor(i) }}>
                    <div className="recipient-top">
                      {sequential && r.role === 'signer' ? <span className="order-pill">{order}</span> : <span className="color-dot" aria-hidden="true" />}
                      <select aria-label="Recipient role" value={r.role} onChange={(e) => updateRecipient(r.id, { role: e.target.value })}>
                        <option value="signer">Needs to sign</option>
                        <option value="cc">Receives a copy</option>
                      </select>
                      <div className="recipient-tools">
                        <button className="icon-btn icon-btn-sm" onClick={() => moveRecipient(i, -1)} disabled={i === 0} aria-label="Move up"><ChevronUp size={14} /></button>
                        <button className="icon-btn icon-btn-sm" onClick={() => moveRecipient(i, 1)} disabled={i === recipients.length - 1} aria-label="Move down"><ChevronDown size={14} /></button>
                        <button className="icon-btn icon-btn-sm" onClick={() => removeRecipient(r.id)} aria-label={`Remove ${r.name || 'recipient'}`}><Trash2 size={14} /></button>
                      </div>
                    </div>
                    {doc.isTemplate ? (
                      <input className="input input-sm" placeholder="Role, e.g. Client" aria-label="Name" value={r.name}
                        onChange={(e) => updateRecipient(r.id, { name: e.target.value })} onFocus={() => r.role === 'signer' && setActiveId(r.id)} />
                    ) : (
                      <>
                        <ContactInput className="input input-sm" placeholder="Full name" aria-label="Name" value={r.name}
                          onChange={(e) => updateRecipient(r.id, { name: e.target.value })} onPick={(c) => updateRecipient(r.id, { name: c.name, email: c.email })}
                          onFocus={() => r.role === 'signer' && setActiveId(r.id)} />
                        <ContactInput className="input input-sm" type="email" placeholder="Email" aria-label="Email" value={r.email}
                          onChange={(e) => updateRecipient(r.id, { email: e.target.value })} onPick={(c) => updateRecipient(r.id, { name: c.name, email: c.email })}
                          onFocus={() => r.role === 'signer' && setActiveId(r.id)} />
                      </>
                    )}
                  </li>
                );
              })}
            </ol>
            <div className="rail-row">
              <Button size="sm" onClick={() => addRecipient()}><Plus size={14} aria-hidden="true" />Add recipient</Button>
              {!doc.isTemplate && !hasMe && (
                <Button size="sm" variant="ghost" onClick={() => addRecipient({ name: user.name, email: user.email })}><UserRound size={14} aria-hidden="true" />Add me</Button>
              )}
            </div>
          </section>

          <section className="rail-section">
            <div className="rail-head"><h2>Fields</h2></div>
            {signers.length > 1 && (
              <div className="for-picker">
                <span>Placing for</span>
                <select aria-label="Placing fields for" value={activeId ?? ''} onChange={(e) => setActiveId(e.target.value)}>
                  {signers.map((s) => <option key={s.id} value={s.id}>{s.name || 'Unnamed signer'}</option>)}
                </select>
              </div>
            )}
            {!signers.length ? (
              <p className="rail-note">Add someone who needs to sign before placing fields.</p>
            ) : (
              <div className="palette" style={{ '--rc': colorOf(activeId) }}>
                {Object.entries(FIELD_META).map(([type, meta]) => {
                  const Icon = meta.icon;
                  return (
                    <button key={type} className={`palette-item${placing === type ? ' is-active' : ''}`} aria-pressed={placing === type}
                      onClick={() => setPlacing(placing === type ? null : type)}>
                      <Icon size={15} strokeWidth={1.75} aria-hidden="true" />{meta.label}
                    </button>
                  );
                })}
              </div>
            )}
            <p className="rail-note">{placing ? `Click on the page to place ${FIELD_META[placing].label.toLowerCase()}. Esc cancels.` : 'Pick a field, then click where it goes. Drag to move, arrow keys to nudge.'}</p>
          </section>
        </aside>

        <main className={`editor-canvas${placing ? ' is-placing' : ''}`} onPointerDown={(e) => { if (e.target === e.currentTarget) setSelectedId(null); }}>
          <div className="editor-pages">
            <PdfPages
              url={`/api/documents/${doc.id}/file`}
              onLoad={(sizes) => { pageSizes.current = sizes; }}
              renderOverlay={(page, size) => (
                <div className="page-overlay" onClick={(e) => { if (e.target === e.currentTarget) { placing ? placeAt(page, e, size) : setSelectedId(null); } }}>
                  {fields.filter((f) => f.page === page).map((f) => (
                    <EditorField key={f.id} field={f} size={size} color={colorOf(f.recipientId)} selected={f.id === selectedId}
                      recipientName={recipients.find((r) => r.id === f.recipientId)?.name}
                      onSelect={() => setSelectedId(f.id)} onChange={(patch) => updateField(f.id, patch)} />
                  ))}
                </div>
              )}
            />
          </div>
        </main>

        <aside className="editor-panel">
          {selected ? (
            <section className="rail-section">
              <div className="rail-head"><h2>{FIELD_META[selected.type].label}</h2></div>
              <div className="field">
                <label htmlFor="f-owner">Assigned to</label>
                <select id="f-owner" className="input" value={selected.recipientId} onChange={(e) => updateField(selected.id, { recipientId: e.target.value })}>
                  {signers.map((s) => <option key={s.id} value={s.id}>{s.name || 'Unnamed signer'}</option>)}
                </select>
              </div>
              {['text', 'company', 'jobtitle', 'number'].includes(selected.type) && (
                <div className="field">
                  <label htmlFor="f-label">Placeholder</label>
                  <input id="f-label" className="input" value={selected.label} maxLength={80} placeholder={selected.type === 'number' ? 'e.g. Amount' : 'e.g. Department'} onChange={(e) => updateField(selected.id, { label: e.target.value })} />
                </div>
              )}
              {FIELD_META[selected.type].choices && (
                <OptionsEditor options={selected.options ?? []} onChange={(options) => updateField(selected.id, { options })} />
              )}
              {!FIELD_META[selected.type].auto && (
                <label className="check">
                  <input type="checkbox" checked={selected.required} onChange={(e) => updateField(selected.id, { required: e.target.checked })} />
                  Required
                </label>
              )}
              {FIELD_META[selected.type].auto && <p className="rail-note">Filled in automatically when they sign.</p>}
              <Button variant="danger" size="sm" onClick={() => removeField(selected.id)}><Trash2 size={14} aria-hidden="true" />Remove field</Button>
            </section>
          ) : (
            <section className="rail-section">
              <div className="rail-head"><h2>Message</h2></div>
              <div className="field">
                <label htmlFor="msg">Note to recipients</label>
                <textarea id="msg" className="input" rows={5} maxLength={2000} placeholder="Optional. Shown in the email and on the signing page." value={message} onChange={(e) => setMessage(e.target.value)} />
              </div>
              <div className="field">
                <label htmlFor="remind">Reminders</label>
                <select id="remind" className="input" value={reminderDays} onChange={(e) => setReminderDays(Number(e.target.value))}>
                  <option value={0}>Off</option>
                  <option value={1}>Every day</option>
                  <option value={2}>Every 2 days</option>
                  <option value={3}>Every 3 days</option>
                  <option value={7}>Every week</option>
                </select>
                <p className="field-hint">Sent by email while someone still needs to sign.</p>
              </div>
              {!doc.isTemplate && (
                <div className="field">
                  <label htmlFor="expire">Expires</label>
                  <select id="expire" className="input" value={expireDays} onChange={(e) => setExpireDays(Number(e.target.value))}>
                    {EXPIRY_CHOICES.map((d) => <option key={d} value={d}>{d ? `${d} days after sending` : 'Never'}</option>)}
                  </select>
                  <p className="field-hint">After this, signing links stop working and the document is marked expired.</p>
                </div>
              )}
              <div className="field">
                <label htmlFor="redirect">After signing, send signers to</label>
                <input id="redirect" className="input" type="url" inputMode="url" maxLength={500} placeholder="https://example.com/thanks" value={redirectUrl}
                  aria-invalid={redirectTouched && redirectError ? true : undefined} aria-describedby="redirect-hint"
                  onChange={(e) => setRedirectUrl(e.target.value)} onBlur={() => setRedirectTouched(true)} />
                {redirectTouched && redirectError
                  ? <p id="redirect-hint" className="field-error" role="alert">{redirectError}</p>
                  : <p id="redirect-hint" className="field-hint">Optional. An https:// address. When they finish, signers see a button to continue there.</p>}
              </div>
              <div className="field">
                <label className="check">
                  <input type="checkbox" checked={requireOtp && mail} disabled={!mail} aria-describedby="otp-hint" onChange={(e) => setRequireOtp(e.target.checked)} />
                  Require an email code before signing
                </label>
                <p id="otp-hint" className="field-hint">{mail
                  ? 'Each signer gets a 6-digit code by email and enters it before they can see the document.'
                  : 'Needs email (SMTP) to be set up on this server.'}</p>
              </div>
              <div className="summary">
                <h3>Summary</h3>
                <ul>
                  {signers.map((s) => (
                    <li key={s.id} style={{ '--rc': colorOf(s.id) }}>
                      <span className="color-dot" aria-hidden="true" />
                      <span className="summary-name">{s.name || 'Unnamed signer'}</span>
                      <span className={fields.some((f) => f.recipientId === s.id && f.type === 'signature') ? 'summary-count' : 'summary-count is-missing'}>
                        {fieldCount(s.id) ? `${fieldCount(s.id)} field${fieldCount(s.id) > 1 ? 's' : ''}` : 'No fields'}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </section>
          )}
        </aside>
      </div>
    </div>
  );
}

function EditorField({ field, size, color, selected, recipientName, onSelect, onChange }) {
  const meta = FIELD_META[field.type];
  const Icon = meta.icon;
  const drag = useRef(null);

  const start = (mode) => (e) => {
    e.stopPropagation();
    e.preventDefault();
    onSelect();
    e.currentTarget.setPointerCapture(e.pointerId);
    drag.current = { mode, x: e.clientX, y: e.clientY, f: { ...field } };
  };
  const move = (e) => {
    const d = drag.current;
    if (!d) return;
    const dx = (e.clientX - d.x) / size.width;
    const dy = (e.clientY - d.y) / size.height;
    if (d.mode === 'move') {
      onChange({ x: clamp01(Math.min(d.f.x + dx, 1 - d.f.w)), y: clamp01(Math.min(d.f.y + dy, 1 - d.f.h)) });
    } else {
      const minW = 12 / size.ptWidth, minH = 12 / size.ptHeight;
      onChange({ w: Math.max(minW, Math.min(d.f.w + dx, 1 - d.f.x)), h: Math.max(minH, Math.min(d.f.h + dy, 1 - d.f.y)) });
    }
  };
  const end = () => { drag.current = null; };

  const px = { left: field.x * size.width, top: field.y * size.height, width: field.w * size.width, height: field.h * size.height };
  const small = px.height < 26 || px.width < 70;

  return (
    <div
      className={`efield${selected ? ' is-selected' : ''}${field.type === 'checkbox' ? ' is-check' : ''}`}
      style={{ ...px, '--rc': color }}
      role="button"
      tabIndex={0}
      aria-label={`${meta.label} for ${recipientName || 'signer'}`}
      onPointerDown={start('move')} onPointerMove={move} onPointerUp={end} onPointerCancel={end}
      onFocus={onSelect}
    >
      {field.type !== 'checkbox' && (
        <span className="efield-label">
          {!small && <Icon size={13} strokeWidth={1.75} aria-hidden="true" />}
          {field.label || meta.label}{field.required && !meta.auto && <span className="efield-req" aria-hidden="true">*</span>}
        </span>
      )}
      {selected && <span className="efield-handle" onPointerDown={start('resize')} onPointerMove={move} onPointerUp={end} aria-hidden="true" />}
    </div>
  );
}
