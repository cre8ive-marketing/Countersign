import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { Check, Copy, FileUp, Globe, Plus, Send, Trash2, Users } from 'lucide-react';
import { apiFetch, bulkRowsFromCsv } from '../lib/client';
import { Button } from './ui';

const MAX_ROWS = 500;
const MAX_CSV = 1048576;
const roleLabel = (r, i) => r.name.trim() || `Role ${i + 1}`;
const emptyRow = (n) => Array.from({ length: n }, () => ({ name: '', email: '' }));
// getRandomValues, not randomUUID: randomUUID is missing on plain-http self-hosted installs (insecure context).
const newRequestId = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');

// Template editor actions: bulk send and the public link. Both save the template first so the server works on what is on screen.
export function BulkSend({ docId, roles, mail, saveFirst, disabled }) {
  const dialog = useRef(null);
  const file = useRef(null);
  const [rows, setRows] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const requestId = useRef(null); // one per dialog session, so a retry after a timeout cannot send twice

  function open() {
    requestId.current = newRequestId();
    setRows([emptyRow(roles.length)]);
    setError(null);
    setResult(null);
    dialog.current?.showModal();
  }

  const setCell = (ri, ci, key, value) => setRows((rs) => rs.map((r, i) => (i === ri ? r.map((c, j) => (j === ci ? { ...c, [key]: value } : c)) : r)));
  const isBlank = (r) => r.every((c) => !c.name.trim() && !c.email.trim());

  async function importCsv(f) {
    if (!f) return;
    setError(null);
    if (f.size > MAX_CSV) return setError('This file is larger than 1 MB. Split it into smaller files.');
    try {
      const imported = bulkRowsFromCsv(await f.text(), roles.length);
      if (!imported.length) return setError('The file has no rows.');
      const kept = rows.filter((r) => !isBlank(r));
      if (kept.length + imported.length > MAX_ROWS) return setError(`Bulk send takes up to ${MAX_ROWS} rows. This would make ${kept.length + imported.length}.`);
      setRows([...kept, ...imported]);
    } catch (e) {
      setError(e.message);
    }
  }

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await saveFirst();
      const body = { rows: rows.map((r) => r.map((c) => ({ name: c.name.trim(), email: c.email.trim() }))) };
      setResult(await apiFetch(`/api/documents/${docId}/bulk`, { body, headers: { 'Idempotency-Key': requestId.current } }));
      requestId.current = newRequestId();
    } catch (err) {
      setError(err.status === 409 && /already started/i.test(err.message)
        ? 'These documents are already being sent. Check your documents list before sending again.'
        : err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Button variant="secondary" onClick={open} disabled={disabled || !roles.length} title={roles.length ? undefined : 'Add at least one role first'}>
        <Users size={15} strokeWidth={1.75} aria-hidden="true" />Bulk send
      </Button>
      <dialog ref={dialog} className="dialog dialog-wide" aria-labelledby="bulk-title">
        <h2 id="bulk-title">Bulk send</h2>
        {result ? (
          <div role="status">
            <p className="dialog-text">
              {result.created} document{result.created === 1 ? '' : 's'} sent{result.failed.length ? `, ${result.failed.length} row${result.failed.length === 1 ? '' : 's'} failed` : ''}.
              {!mail && ' Signers get no email; copy links from each document.'}
            </p>
            {result.failed.length > 0 && (
              <ul className="bulk-failed">
                {result.failed.map((f) => <li key={f.row}><strong>Row {f.row}:</strong> {f.error}</li>)}
              </ul>
            )}
            <div className="dialog-actions">
              <Button variant="ghost" type="button" onClick={() => dialog.current?.close()}>Close</Button>
              <Button variant="primary" href="/app?view=waiting">See sent documents</Button>
            </div>
          </div>
        ) : (
          <form onSubmit={submit}>
            <p className="dialog-text">Each row becomes its own copy of this template, sent to the people in that row. Fill in a name and email for every role.{!mail && ' Signers get no email; copy links from each document.'}</p>
            {error && <p className="otp-error contact-error" role="alert">{error}</p>}
            <div className="bulk-import">
              <input ref={file} type="file" accept=".csv,text/csv" hidden onChange={(e) => { importCsv(e.target.files[0]); e.target.value = ''; }} />
              <Button size="sm" type="button" onClick={() => file.current?.click()} aria-describedby="bulk-csv-hint"><FileUp size={14} aria-hidden="true" />Import CSV</Button>
              <p id="bulk-csv-hint" className="field-hint">Columns: {roles.map((r, i) => `${roleLabel(r, i)} name, ${roleLabel(r, i)} email`).join(', ')}. A header row is optional. Up to {MAX_ROWS} rows.</p>
            </div>
            <ol className="bulk-rows">
              {rows.map((row, ri) => (
                <li key={ri}>
                  <fieldset className="bulk-row">
                    <legend>Row {ri + 1}</legend>
                    <div className="bulk-cells">
                      {roles.map((r, ci) => (
                        <div key={ci} className="bulk-pair">
                          <div className="field">
                            <label htmlFor={`b-${ri}-${ci}-n`}>{roleLabel(r, ci)} name</label>
                            <input id={`b-${ri}-${ci}-n`} className="input" required maxLength={200} autoComplete="off" value={row[ci].name} onChange={(e) => setCell(ri, ci, 'name', e.target.value)} />
                          </div>
                          <div className="field">
                            <label htmlFor={`b-${ri}-${ci}-e`}>{roleLabel(r, ci)} email</label>
                            <input id={`b-${ri}-${ci}-e`} className="input" type="email" required maxLength={254} autoComplete="off" value={row[ci].email} onChange={(e) => setCell(ri, ci, 'email', e.target.value)} />
                          </div>
                        </div>
                      ))}
                    </div>
                    <button type="button" className="icon-btn" onClick={() => setRows((rs) => rs.filter((_, i) => i !== ri))} disabled={rows.length === 1} aria-label={`Remove row ${ri + 1}`} title="Remove row">
                      <Trash2 size={16} strokeWidth={1.75} />
                    </button>
                  </fieldset>
                </li>
              ))}
            </ol>
            <Button size="sm" type="button" onClick={() => setRows((rs) => [...rs, emptyRow(roles.length)])} disabled={rows.length >= MAX_ROWS}><Plus size={14} aria-hidden="true" />Add row</Button>
            <div className="dialog-actions">
              <Button variant="ghost" type="button" onClick={() => dialog.current?.close()}>Cancel</Button>
              <Button variant="primary" type="submit" loading={busy}><Send size={15} strokeWidth={1.75} aria-hidden="true" />Send {rows.length} document{rows.length === 1 ? '' : 's'}</Button>
            </div>
          </form>
        )}
      </dialog>
    </>
  );
}

export function PublicLink({ docId, initialUrl, eligible, saveFirst, disabled }) {
  const dialog = useRef(null);
  const [path, setPath] = useState(initialUrl);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const [origin, setOrigin] = useState('');
  useEffect(() => { setOrigin(window.location.origin); }, []);
  // The server turns the link off when a save breaks the one-signer rule.
  const url = eligible && path ? `${origin}${path}` : null;

  async function toggle(enabled) {
    setBusy(true);
    setError(null);
    setCopied(false);
    try {
      await saveFirst();
      const res = await apiFetch(`/api/documents/${docId}/public`, { body: { enabled } });
      setPath(enabled ? res.url : null);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function copy() {
    await navigator.clipboard.writeText(url);
    setCopied(true);
  }

  return (
    <>
      <Button variant="secondary" onClick={() => { setError(null); setCopied(false); dialog.current?.showModal(); }} disabled={disabled}>
        <Globe size={15} strokeWidth={1.75} aria-hidden="true" />Public link{url ? <span className="sr-only"> (on)</span> : null}
      </Button>
      <dialog ref={dialog} className="dialog" aria-labelledby="public-title">
        <h2 id="public-title">Public link</h2>
        <p className="dialog-text">Anyone with this link can create and sign a copy. The signer’s name and email are what they type in.</p>
        {error && <p className="otp-error contact-error" role="alert">{error}</p>}
        {!eligible && <p className="field-hint public-note">A public link needs a template with exactly one signer.</p>}
        <label className="switch public-switch">
          <input type="checkbox" checked={!!url} disabled={!eligible || busy} aria-busy={busy || undefined} onChange={(e) => toggle(e.target.checked)} />
          <span className="switch-track" aria-hidden="true" />
          {url ? 'Link is on' : 'Link is off'}
        </label>
        {url && (
          <div className="field">
            <label htmlFor="public-url">Link</label>
            <div className="copy-row">
              <input id="public-url" className="input mono" readOnly value={url} onFocus={(e) => e.target.select()} />
              <Button type="button" onClick={copy}>{copied ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}{copied ? 'Copied' : 'Copy'}</Button>
            </div>
            <p className="field-hint">Turning the link off and on again makes a new link; the old one stops working. Documents created from it appear in <Link href="/app">Documents</Link>.</p>
          </div>
        )}
        <div className="dialog-actions">
          <Button variant="ghost" type="button" onClick={() => dialog.current?.close()}>Close</Button>
        </div>
      </dialog>
    </>
  );
}
