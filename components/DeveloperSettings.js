import { useEffect, useRef, useState } from 'react';
import { Check, Copy, KeyRound, Plus, Send, Trash2, Webhook } from 'lucide-react';
import { apiFetch, formatDate } from '../lib/client';
import { Button, TextField } from './ui';

// A secret shown once with a copy button. It lives only in this component's state and is gone after Done.
export function OneTimeSecret({ label, value, onDone }) {
  const [copied, setCopied] = useState(false);
  const ref = useRef(null);
  useEffect(() => { ref.current?.focus(); }, []);
  return (
    <div className="secret-box" role="status">
      <p><strong>Copy your {label} now.</strong> It is not shown again. If you lose it, create a new one.</p>
      <div className="copy-row">
        <label htmlFor="secret-value" className="sr-only">{label}</label>
        <input id="secret-value" ref={ref} className="input mono" readOnly value={value} onFocus={(e) => e.target.select()} />
        <Button type="button" onClick={async () => { await navigator.clipboard.writeText(value); setCopied(true); }}>
          {copied ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}{copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      <div className="form-card-foot"><Button variant="primary" type="button" onClick={onDone}>Done</Button></div>
    </div>
  );
}

export function ConfirmDialog({ dialogRef, id, title, body, action, icon: Icon = Trash2, busy, error, onConfirm, onClose }) {
  return (
    <dialog ref={dialogRef} className="dialog" aria-labelledby={id} onClose={onClose}>
      <h2 id={id}>{title}</h2>
      <p className="dialog-text">{body}</p>
      {error && <p className="field-error" role="alert">{error}</p>}
      <div className="dialog-actions">
        <Button variant="ghost" type="button" onClick={() => dialogRef.current?.close()}>Cancel</Button>
        <Button variant="danger" type="button" onClick={onConfirm} loading={busy}><Icon size={16} aria-hidden="true" />{action}</Button>
      </div>
    </dialog>
  );
}

export function ApiKeys() {
  const [keys, setKeys] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const [name, setName] = useState('');
  const [created, setCreated] = useState(null); // the full key, shown once
  const [revoking, setRevoking] = useState(null);
  const [busy, setBusy] = useState(null); // 'create' | 'revoke'
  const [error, setError] = useState(null);
  const revokeDialog = useRef(null);

  const load = () => apiFetch('/api/api-keys', { method: 'GET' }).then((r) => setKeys(r.keys)).catch((e) => setLoadError(e.message));
  useEffect(() => { load(); }, []);

  async function create(e) {
    e.preventDefault();
    setBusy('create');
    setError(null);
    try {
      const { key } = await apiFetch('/api/api-keys', { body: { name } });
      setCreated(key);
      setName('');
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  async function revoke() {
    setBusy('revoke');
    setError(null);
    try {
      await apiFetch(`/api/api-keys/${revoking.id}`, { method: 'DELETE' });
      revokeDialog.current?.close();
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="card form-card" aria-labelledby="keys-h">
      <div className="form-card-head">
        <h2 id="keys-h">API keys</h2>
        <p>Let your own scripts list, upload, send and download your documents. Send the key as <code>Authorization: Bearer cs_…</code>. A key cannot change your account, manage keys or webhooks.</p>
      </div>
      {loadError && <p className="field-error" role="alert">{loadError}</p>}
      {!keys && !loadError && <p className="field-hint" role="status">Loading…</p>}
      {keys && (keys.length ? (
        <ul className="dev-list">
          {keys.map((k) => (
            <li key={k.id}>
              <KeyRound size={16} strokeWidth={1.75} aria-hidden="true" />
              <div className="dev-main">
                <strong>{k.name}</strong>
                <span><code>{k.prefix}…</code> · Created {formatDate(k.createdAt)} · {k.lastUsedAt ? `Last used ${formatDate(k.lastUsedAt, true)}` : 'Never used'}</span>
              </div>
              <Button variant="danger" size="sm" onClick={() => { setRevoking(k); setError(null); revokeDialog.current?.showModal(); }} aria-label={`Revoke ${k.name}`}>
                <Trash2 size={14} aria-hidden="true" />Revoke
              </Button>
            </li>
          ))}
        </ul>
      ) : <p className="field-hint">No API keys yet.</p>)}

      {created ? <OneTimeSecret label="API key" value={created} onDone={() => setCreated(null)} /> : (
        <form className="dev-form" onSubmit={create}>
          <TextField id="key-name" label="New key name" placeholder="e.g. CRM sync" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} required autoComplete="off" />
          {error && !revoking && <p className="field-error" role="alert">{error}</p>}
          <div className="form-card-foot"><Button variant="primary" type="submit" loading={busy === 'create'}><Plus size={16} aria-hidden="true" />Create key</Button></div>
        </form>
      )}

      <ConfirmDialog dialogRef={revokeDialog} id="key-revoke-title" title="Revoke this API key?"
        body={revoking ? `Anything using “${revoking.name}” (${revoking.prefix}…) stops working right away. This can’t be undone.` : ''}
        action="Revoke key" busy={busy === 'revoke'} error={revoking && error} onConfirm={revoke} onClose={() => setRevoking(null)} />
    </section>
  );
}

const DELIVERY_TONE = { delivered: ['ok', 'Delivered'], pending: ['warn', 'Retrying'], failed: ['bad', 'Failed'] };

export function Webhooks() {
  const [data, setData] = useState(null); // { webhooks, events }
  const [loadError, setLoadError] = useState(null);
  const [url, setUrl] = useState('');
  const [events, setEvents] = useState([]);
  const [created, setCreated] = useState(null); // signing secret, shown once
  const [removing, setRemoving] = useState(null);
  const [busy, setBusy] = useState(null); // 'create' | 'delete' | `${id}:test` | `${id}:active`
  const [error, setError] = useState(null);
  const [rowMsg, setRowMsg] = useState({}); // id -> message after an action
  const [log, setLog] = useState({}); // id -> deliveries | 'loading' | error string
  const removeDialog = useRef(null);

  const load = () => apiFetch('/api/webhooks', { method: 'GET' }).then(setData).catch((e) => setLoadError(e.message));
  useEffect(() => { load(); }, []);
  const choices = (data?.events ?? []).filter((e) => e !== 'ping');

  async function create(e) {
    e.preventDefault();
    setBusy('create');
    setError(null);
    try {
      const { secret } = await apiFetch('/api/webhooks', { body: { url: url.trim(), events } });
      setCreated(secret);
      setUrl('');
      setEvents([]);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  async function act(w, kind, fn, okMsg) {
    setBusy(`${w.id}:${kind}`);
    setRowMsg((m) => ({ ...m, [w.id]: null }));
    try {
      await fn();
      setRowMsg((m) => ({ ...m, [w.id]: okMsg }));
      await load();
      if (Array.isArray(log[w.id])) await loadLog(w.id);
    } catch (err) {
      setRowMsg((m) => ({ ...m, [w.id]: err.message }));
    } finally {
      setBusy(null);
    }
  }

  async function loadLog(id) {
    setLog((l) => ({ ...l, [id]: 'loading' }));
    try {
      const res = await apiFetch(`/api/webhooks/${id}/deliveries`, { method: 'GET' });
      setLog((l) => ({ ...l, [id]: Array.isArray(res) ? res : res.deliveries ?? [] }));
    } catch (err) {
      setLog((l) => ({ ...l, [id]: err.message }));
    }
  }

  async function remove() {
    setBusy('delete');
    setError(null);
    try {
      await apiFetch(`/api/webhooks/${removing.id}`, { method: 'DELETE' });
      removeDialog.current?.close();
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="card form-card" aria-labelledby="hooks-h">
      <div className="form-card-head">
        <h2 id="hooks-h">Webhooks</h2>
        <p>This server sends a signed JSON POST to your address when something happens to your documents. Payloads carry the document and recipient, never files, field values or signatures. Failed deliveries are retried for about a day.</p>
      </div>
      {loadError && <p className="field-error" role="alert">{loadError}</p>}
      {!data && !loadError && <p className="field-hint" role="status">Loading…</p>}
      {data && (data.webhooks.length ? (
        <ul className="dev-list">
          {data.webhooks.map((w) => {
            const entries = log[w.id];
            return (
              <li key={w.id} className="hook">
                <Webhook size={16} strokeWidth={1.75} aria-hidden="true" />
                <div className="dev-main">
                  <strong className="mono">{w.url}</strong>
                  <span>{w.events.join(', ')}</span>
                  <span>{w.active ? 'Active' : 'Off'}{w.failureCount ? ` · ${w.failureCount} failed deliver${w.failureCount === 1 ? 'y' : 'ies'} in a row` : ''}{!w.active && w.failureCount >= 20 ? '. Turned off after repeated failures.' : ''}</span>
                  <div className="hook-actions">
                    <label className="switch">
                      <input type="checkbox" checked={!!w.active} disabled={busy === `${w.id}:active`}
                        onChange={(e) => act(w, 'active', () => apiFetch(`/api/webhooks/${w.id}`, { method: 'PUT', body: { active: e.target.checked } }), e.target.checked ? 'Turned on.' : 'Turned off.')} />
                      <span className="switch-track" aria-hidden="true" />
                      Enabled<span className="sr-only"> for {w.url}</span>
                    </label>
                    <Button size="sm" onClick={() => act(w, 'test', () => apiFetch(`/api/webhooks/${w.id}/test`), 'Test event queued.')} loading={busy === `${w.id}:test`} disabled={!w.active}>
                      <Send size={14} aria-hidden="true" />Send test
                    </Button>
                    <Button size="sm" variant="ghost" aria-expanded={entries !== undefined} aria-controls={`log-${w.id}`}
                      onClick={() => (entries === undefined ? loadLog(w.id) : setLog((l) => { const { [w.id]: _, ...rest } = l; return rest; }))}>
                      {entries === undefined ? 'Show deliveries' : 'Hide deliveries'}
                    </Button>
                    <Button size="sm" variant="danger" onClick={() => { setRemoving(w); setError(null); removeDialog.current?.showModal(); }} aria-label={`Delete webhook ${w.url}`}>
                      <Trash2 size={14} aria-hidden="true" />Delete
                    </Button>
                  </div>
                  <p className="field-hint" role="status">{rowMsg[w.id]}</p>
                  {entries !== undefined && (
                    <div id={`log-${w.id}`} className="hook-log">
                      {entries === 'loading' ? <p className="field-hint">Loading…</p>
                        : typeof entries === 'string' ? <p className="field-error" role="alert">{entries}</p>
                          : entries.length ? (
                            <table>
                              <caption className="sr-only">Last deliveries to {w.url}</caption>
                              <thead><tr><th scope="col">Event</th><th scope="col">Status</th><th scope="col">Attempts</th><th scope="col">Response</th><th scope="col">Created</th></tr></thead>
                              <tbody>
                                {entries.map((d) => {
                                  const [tone, label] = DELIVERY_TONE[d.status] ?? ['neutral', d.status];
                                  return (
                                    <tr key={d.id}>
                                      <td><code>{d.event}</code></td>
                                      <td><span className={`badge badge-${tone}`}><span className="badge-dot" aria-hidden="true" />{label}</span></td>
                                      <td>{d.attempts}</td>
                                      <td>{d.lastStatusCode ? `HTTP ${d.lastStatusCode}` : d.lastError || 'None'}</td>
                                      <td>{formatDate(d.createdAt, true)}</td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          ) : <p className="field-hint">No deliveries yet. Send a test to try it.</p>}
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      ) : <p className="field-hint">No webhooks yet.</p>)}

      {created ? <OneTimeSecret label="signing secret" value={created} onDone={() => setCreated(null)} /> : data && (
        <form className="dev-form" onSubmit={create}>
          <TextField id="hook-url" label="Endpoint URL" type="url" inputMode="url" placeholder="https://example.com/countersign" value={url} onChange={(e) => setUrl(e.target.value)} maxLength={500} required autoComplete="off" />
          <fieldset className="hook-events">
            <legend>Events</legend>
            {choices.map((ev) => (
              <label key={ev} className="check">
                <input type="checkbox" checked={events.includes(ev)} onChange={(e) => setEvents((s) => (e.target.checked ? [...s, ev] : s.filter((x) => x !== ev)))} />
                <code>{ev}</code>
              </label>
            ))}
          </fieldset>
          {error && !removing && <p className="field-error" role="alert">{error}</p>}
          <div className="form-card-foot"><Button variant="primary" type="submit" loading={busy === 'create'}><Plus size={16} aria-hidden="true" />Add webhook</Button></div>
        </form>
      )}

      <figure className="code-window hook-sample">
        <figcaption>Check the Countersign-Signature header (Node.js)</figcaption>
        <pre><code>{VERIFY_SAMPLE}</code></pre>
      </figure>

      <ConfirmDialog dialogRef={removeDialog} id="hook-del-title" title="Delete this webhook?"
        body={removing ? `${removing.url} stops getting events, and its delivery log is deleted.` : ''}
        action="Delete webhook" busy={busy === 'delete'} error={removing && error} onConfirm={remove} onClose={() => setRemoving(null)} />
    </section>
  );
}

const VERIFY_SAMPLE = `import crypto from 'node:crypto';

// rawBody: the request body exactly as received, before JSON.parse.
function isFromCountersign(rawBody, header, secret) {
  const parts = Object.fromEntries(header.split(',').map((p) => p.split('=')));
  const expected = crypto.createHmac('sha256', secret)
    .update(\`\${parts.t}.\${rawBody}\`).digest('hex');
  const recent = Math.abs(Date.now() / 1000 - Number(parts.t)) < 300;
  return recent && parts.v1?.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(parts.v1), Buffer.from(expected));
}`;
