import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/router';
import { withUser, signupOpen } from '../../lib/auth';
import { mailEnabled } from '../../lib/mail';
import { apiFetch } from '../../lib/client';
import AppShell from '../../components/AppShell';
import { LogOut, PenLine, RotateCcw, Trash2 } from 'lucide-react';
import { Button, TextField } from '../../components/ui';
import SignaturePad from '../../components/SignaturePad';
import { ApiKeys, Webhooks } from '../../components/DeveloperSettings';

export const getServerSideProps = withUser(async (ctx, user) => ({
  props: { user, server: { mail: mailEnabled(), signup: signupOpen(), appUrl: process.env.APP_URL || null } },
}));

export default function Settings({ user, server }) {
  const router = useRouter();
  const [name, setName] = useState(user.name);
  const [currentPassword, setCurrent] = useState('');
  const [newPassword, setNew] = useState('');
  const [state, setState] = useState({});
  const [outError, setOutError] = useState(null);
  const [outBusy, setOutBusy] = useState(false);
  const [outKeys, setOutKeys] = useState(false);
  const outDialog = useRef(null);

  async function signOutEverywhere() {
    setOutBusy(true);
    setOutError(null);
    try {
      await apiFetch('/api/auth/logout-all', { body: { apiKeys: outKeys } });
      window.location.assign('/login'); // full load so no signed-in state lingers in memory
    } catch (e) {
      setOutError(e.message);
      setOutBusy(false);
    }
  }

  async function save(key, body) {
    setState({ [key]: 'busy' });
    try {
      await apiFetch('/api/account', { method: 'PATCH', body });
      setState({ [key]: 'done' });
      if (key === 'password') { setCurrent(''); setNew(''); }
      router.replace(router.asPath);
    } catch (e) {
      setState({ [key]: e.message });
    }
  }

  const msg = (key) => state[key] && state[key] !== 'busy' && (
    <p className={state[key] === 'done' ? 'form-ok' : 'field-error'} role="status">{state[key] === 'done' ? 'Saved.' : state[key]}</p>
  );

  return (
    <AppShell user={user} title="Settings">
      <div className="page page-narrow">
        <header className="page-head"><div><h1>Settings</h1></div></header>

        <form className="card form-card" onSubmit={(e) => { e.preventDefault(); save('profile', { name }); }}>
          <div className="form-card-head"><h2>Profile</h2><p>Your name appears on emails and in the audit trail.</p></div>
          <TextField id="name" label="Name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={120} />
          <TextField id="email" label="Email" value={user.email} disabled hint="Used to sign in." />
          <div className="form-card-foot">{msg('profile')}<Button variant="primary" type="submit" loading={state.profile === 'busy'}>Save</Button></div>
        </form>

        <form className="card form-card" onSubmit={(e) => { e.preventDefault(); save('password', { currentPassword, newPassword }); }}>
          <div className="form-card-head"><h2>Password</h2><p>Changing it signs you out on your other devices and revokes all your API keys.</p></div>
          <TextField id="cur" type="password" label="Current password" autoComplete="current-password" value={currentPassword} onChange={(e) => setCurrent(e.target.value)} required />
          <TextField id="new" type="password" label="New password" autoComplete="new-password" minLength={12} maxLength={256} value={newPassword} onChange={(e) => setNew(e.target.value)} required hint="At least 12 characters." />
          <div className="form-card-foot">{msg('password')}<Button variant="primary" type="submit" loading={state.password === 'busy'}>Change password</Button></div>
        </form>

        <SavedSignatures user={user} />
        <EmailTemplates user={user} />
        <ApiKeys />
        <Webhooks />

        <section className="card form-card">
          <div className="form-card-head"><h2>Sessions</h2><p>Lost a device or signed in on a shared computer? Sign out everywhere, including this browser.</p></div>
          <div className="form-card-foot">
            <Button variant="secondary" type="button" onClick={() => { setOutError(null); outDialog.current?.showModal(); }}><LogOut size={16} aria-hidden="true" />Sign out of all devices</Button>
          </div>
        </section>

        <dialog ref={outDialog} className="dialog" aria-labelledby="out-title">
          <h2 id="out-title">Sign out of all devices?</h2>
          <p className="dialog-text">Every browser signed in to this account, including this one, will need to sign in again.</p>
          <label className="check">
            <input type="checkbox" checked={outKeys} onChange={(e) => setOutKeys(e.target.checked)} />
            Also revoke all my API keys
          </label>
          {outError && <p className="field-error" role="alert">{outError}</p>}
          <div className="dialog-actions">
            <Button variant="ghost" type="button" onClick={() => outDialog.current?.close()}>Cancel</Button>
            <Button variant="danger" type="button" onClick={signOutEverywhere} loading={outBusy}><LogOut size={16} aria-hidden="true" />Sign out everywhere</Button>
          </div>
        </dialog>

        <section className="card form-card">
          <div className="form-card-head"><h2>Server</h2><p>Set with environment variables. See the self-hosting guide.</p></div>
          <dl className="meta-list meta-list-row">
            <dt>Email delivery</dt>
            <dd>{server.mail ? 'SMTP configured' : 'Off. Signing links are shown for you to copy.'}</dd>
            <dt>Public URL</dt>
            <dd className="mono">{server.appUrl || 'Not set (APP_URL). Needed for reminder emails.'}</dd>
            <dt>New sign-ups</dt>
            <dd>{server.signup ? 'Open' : 'Closed. Set ALLOW_SIGNUP=true to open.'}</dd>
          </dl>
        </section>
      </div>
    </AppShell>
  );
}

const SIG_KINDS = [['signature', 'Signature'], ['initials', 'Initials']];

function SavedSignatures({ user }) {
  const [sigs, setSigs] = useState(null); // { signature, initials } once loaded
  const [loadError, setLoadError] = useState(null);
  const [editing, setEditing] = useState(null); // kind being adopted
  const [removing, setRemoving] = useState(null); // kind being removed
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const padDialog = useRef(null);
  const removeDialog = useRef(null);

  useEffect(() => {
    apiFetch('/api/signatures', { method: 'GET' }).then(setSigs).catch((e) => setLoadError(e.message));
  }, []);

  async function save(png) {
    if (!png) return;
    setBusy(true);
    setError(null);
    try {
      await apiFetch('/api/signatures', { method: 'PUT', body: { kind: editing, value: png } });
      setSigs((s) => ({ ...s, [editing]: png }));
      padDialog.current?.close();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    setError(null);
    try {
      await apiFetch(`/api/signatures?kind=${removing}`, { method: 'DELETE' });
      setSigs((s) => ({ ...s, [removing]: null }));
      removeDialog.current?.close();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card form-card" aria-labelledby="sig-h">
      <div className="form-card-head">
        <h2 id="sig-h">Your signature</h2>
        <p>Save it once. When you are signed in and open a signing link sent to {user.email}, you can use it instead of creating it again.</p>
      </div>
      {loadError && <p className="field-error" role="alert">{loadError}</p>}
      {!sigs && !loadError && <p className="field-hint" role="status">Loading…</p>}
      {sigs && SIG_KINDS.map(([kind, label]) => (
        <div key={kind} className="saved-sig">
          <div className="saved-sig-main">
            <h3>{label}</h3>
            <div className="sigpad-preview sigpad-image saved-sig-preview">
              {sigs[kind] ? <img src={sigs[kind]} alt={`Your saved ${kind}`} /> : <span className="sigpad-empty">None saved</span>}
            </div>
          </div>
          <div className="saved-sig-actions">
            <Button variant="secondary" size="sm" onClick={() => { setEditing(kind); setError(null); padDialog.current?.showModal(); }}>
              <PenLine size={14} aria-hidden="true" />{sigs[kind] ? `Replace ${kind}` : `Add ${kind}`}
            </Button>
            {sigs[kind] && (
              <Button variant="danger" size="sm" onClick={() => { setRemoving(kind); setError(null); removeDialog.current?.showModal(); }}>
                <Trash2 size={14} aria-hidden="true" />Remove
              </Button>
            )}
          </div>
        </div>
      ))}

      <dialog ref={padDialog} className="dialog" aria-labelledby="sigpad-title" onClose={() => setEditing(null)}>
        {editing && (
          <>
            <h2 id="sigpad-title">{editing === 'initials' ? 'Save your initials' : 'Save your signature'}</h2>
            {error && <p className="field-error" role="alert">{error}</p>}
            <SignaturePad kind={editing} defaultName={user.name} forAccount saving={busy} onAdopt={save} onCancel={() => padDialog.current?.close()} />
          </>
        )}
      </dialog>

      <dialog ref={removeDialog} className="dialog" aria-labelledby="sigrm-title">
        <h2 id="sigrm-title">{removing === 'initials' ? 'Remove your saved initials?' : 'Remove your saved signature?'}</h2>
        <p className="dialog-text">Documents you already signed keep their signatures. You can save a new one at any time.</p>
        {error && <p className="field-error" role="alert">{error}</p>}
        <div className="dialog-actions">
          <Button variant="ghost" type="button" onClick={() => removeDialog.current?.close()}>Cancel</Button>
          <Button variant="danger" type="button" onClick={remove} loading={busy}><Trash2 size={16} aria-hidden="true" />Remove</Button>
        </div>
      </dialog>
    </section>
  );
}

// [kind, switch label, the action button the server adds]
const EMAIL_KINDS = [
  ['invite', 'Invitation to sign', 'Review and sign'],
  ['completed', 'Completed copy', 'Download signed PDF'],
];

function EmailTemplates({ user }) {
  const [data, setData] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const [kind, setKind] = useState('invite');

  useEffect(() => {
    apiFetch('/api/email-templates', { method: 'GET' }).then(setData).catch((e) => setLoadError(e.message));
  }, []);

  return (
    <section className="card form-card" aria-labelledby="tpl-h">
      <div className="form-card-head">
        <h2 id="tpl-h">Email templates</h2>
        <p>The subject and text of the emails your recipients get. The button with their link is always added below your text and can’t be removed or changed.</p>
      </div>
      {loadError && <p className="field-error" role="alert">{loadError}</p>}
      {!data && !loadError && <p className="field-hint" role="status">Loading…</p>}
      {data && (
        <>
          <div className="segmented tpl-switch" role="group" aria-label="Which email">
            {EMAIL_KINDS.map(([k, label]) => (
              <button key={k} type="button" aria-pressed={kind === k} className={kind === k ? 'is-active' : ''} onClick={() => setKind(k)}>{label}</button>
            ))}
          </div>
          {/* Both stay mounted so switching keeps unsaved edits. */}
          {EMAIL_KINDS.map(([k, label, action]) => (
            <div key={k} hidden={kind !== k}>
              <TemplateEditor kind={k} label={label} action={action} initial={data[k]} variables={data.variables} user={user} />
            </div>
          ))}
        </>
      )}
    </section>
  );
}

function TemplateEditor({ kind, label, action, initial, variables, user }) {
  const [subject, setSubject] = useState(initial.subject);
  const [body, setBody] = useState(initial.body);
  const [custom, setCustom] = useState(initial.custom);
  const [state, setState] = useState(null); // 'save' | 'reset' while busy, 'done', or an error message
  const subjectRef = useRef(null);
  const bodyRef = useRef(null);
  const lastField = useRef('body');
  const id = `tpl-${kind}`;

  function insert(name) {
    const token = `{{${name}}}`;
    const isSubject = lastField.current === 'subject';
    const el = isSubject ? subjectRef.current : bodyRef.current;
    const value = isSubject ? subject : body;
    const start = el.selectionStart ?? value.length, end = el.selectionEnd ?? value.length;
    const max = isSubject ? 200 : 4000;
    if (value.length - (end - start) + token.length > max) return setState(`That would make the ${isSubject ? 'subject' : 'message'} longer than ${max} characters.`);
    (isSubject ? setSubject : setBody)(value.slice(0, start) + token + value.slice(end));
    requestAnimationFrame(() => { el.focus(); el.setSelectionRange(start + token.length, start + token.length); });
  }

  async function save(e) {
    e.preventDefault();
    setState('save');
    try {
      await apiFetch('/api/email-templates', { method: 'PUT', body: { kind, subject, body } });
      setCustom(true);
      setState('done');
    } catch (err) {
      setState(err.message);
    }
  }

  async function reset() {
    setState('reset');
    try {
      await apiFetch(`/api/email-templates?kind=${kind}`, { method: 'DELETE' });
      const fresh = await apiFetch('/api/email-templates', { method: 'GET' });
      setSubject(fresh[kind].subject);
      setBody(fresh[kind].body);
      setCustom(false);
      setState('done');
    } catch (err) {
      setState(err.message);
    }
  }

  // Same substitution as the server (known variables only, one pass), with sample values.
  const sample = {
    sender_name: user.name, sender_email: user.email, receiver_name: 'Alex Morgan', document_title: 'Website redesign agreement',
    message: 'Please sign by Friday.', message_block: '\n\n"Please sign by Friday."', expires_on: 'March 31, 2027',
  };
  const fill = (s) => s.replace(/\{\{(\w+)\}\}/g, (m, k) => (variables.includes(k) ? sample[k] ?? '' : m));
  const busy = state === 'save' || state === 'reset';

  return (
    <form className="tpl" onSubmit={save} aria-label={label}>
      <div className="tpl-edit">
        <div className="field">
          <label htmlFor={`${id}-subject`}>Subject</label>
          <input id={`${id}-subject`} ref={subjectRef} className="input" value={subject} maxLength={200} required
            onChange={(e) => setSubject(e.target.value)} onFocus={() => { lastField.current = 'subject'; }} />
        </div>
        <div className="field">
          <label htmlFor={`${id}-body`}>Message</label>
          <textarea id={`${id}-body`} ref={bodyRef} className="input tpl-body" rows={7} maxLength={4000} required value={body}
            onChange={(e) => setBody(e.target.value)} onFocus={() => { lastField.current = 'body'; }} />
        </div>
        <div className="field" role="group" aria-labelledby={`${id}-vars`}>
          <span className="tpl-vars-label" id={`${id}-vars`}>Insert a variable at the cursor</span>
          <div className="chips">
            {variables.map((v) => (
              <Button key={v} variant="secondary" size="sm" type="button" onClick={() => insert(v)}><code>{`{{${v}}}`}</code></Button>
            ))}
          </div>
          <p className="field-hint"><code>{'{{message_block}}'}</code> is your note to recipients as its own paragraph, or nothing when there is no note. <code>{'{{expires_on}}'}</code> is empty when the document never expires.</p>
        </div>
      </div>

      <figure className="tpl-preview">
        <figcaption>Preview with sample values</figcaption>
        <p className="tpl-preview-subject"><span>Subject</span>{fill(subject).replace(/[\r\n]+/g, ' ').trim() || '(empty)'}</p>
        <div className="tpl-preview-mail">
          <p className="tpl-preview-body">{fill(body) || '(empty)'}</p>
          <span className="tpl-action">{action}</span>
          <p className="tpl-preview-note">Added by Countersign to every email, with the recipient’s own link.</p>
        </div>
      </figure>

      <div className="form-card-foot">
        {state && !busy && <p className={state === 'done' ? 'form-ok' : 'field-error'} role="status">{state === 'done' ? 'Saved.' : state}</p>}
        {custom && <Button variant="ghost" type="button" onClick={reset} loading={state === 'reset'} disabled={busy}><RotateCcw size={15} aria-hidden="true" />Reset to default</Button>}
        <Button variant="primary" type="submit" loading={state === 'save'} disabled={busy}>Save template</Button>
      </div>
    </form>
  );
}
