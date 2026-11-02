import { useRef, useState } from 'react';
import Link from 'next/link';
import { CircleCheck, FileUp, CircleHelp, History } from 'lucide-react';
import MarketingLayout from '../components/marketing/MarketingLayout';
import { useSession } from '../components/marketing/useSession';
import { Button } from '../components/ui';
import { apiFetch, formatDate } from '../lib/client';

async function sha256Hex(file) {
  const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export default function Verify() {
  const session = useSession();
  const [file, setFile] = useState(null); // { name, hash }
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const input = useRef(null);

  async function check(f) {
    if (!f) return;
    setError(null);
    setResult(null);
    setFile(null);
    if (!globalThis.crypto?.subtle) return setError('This browser can only compute the fingerprint on a secure (https://) address.');
    setBusy(true);
    try {
      const hash = await sha256Hex(f);
      setFile({ name: f.name, hash });
      setResult(await apiFetch(`/api/verify?sha256=${hash}`, { method: 'GET' }));
    } catch (e) {
      setError(e.status === 429 && e.retryAfter
        ? `Too many checks from your network. Try again in ${Math.ceil(e.retryAfter / 60)} minute${e.retryAfter > 60 ? 's' : ''}.`
        : e.message || 'This file could not be read.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <MarketingLayout session={session} title="Verify a document · Countersign" description="Check whether a PDF is the exact copy this Countersign server recorded. The file never leaves your browser.">
      <section className="mk-page-head">
        <div className="lp-wrap">
          <h1>Check a PDF against this server.</h1>
          <p className="lp-lead">Pick a PDF to see whether this server recorded it, byte for byte. Your file never leaves your browser: it computes the file’s SHA-256 fingerprint, and only that fingerprint is sent.</p>
        </div>
      </section>

      <section className="mk-row" aria-labelledby="check-h">
        <div className="lp-wrap verify">
          <h2 id="check-h" className="sr-only">Check a file</h2>
          <div className="card verify-card">
            <input ref={input} type="file" accept="application/pdf,.pdf" hidden onChange={(e) => { check(e.target.files[0]); e.target.value = ''; }} />
            <Button variant="primary" size="lg" onClick={() => input.current?.click()} loading={busy}>
              {!busy && <FileUp size={18} aria-hidden="true" />}{file ? 'Check another PDF' : 'Choose a PDF'}
            </Button>
            <p className="field-hint">Nothing is uploaded. Checks are limited to 60 an hour per network.</p>

            <div aria-live="polite">
              {error && <p className="otp-error" role="alert">{error}</p>}
              {file && result && (
                <div className="verify-result">
                  <Outcome result={result} />
                  <dl className="meta-list">
                    <dt>File</dt><dd className="verify-file">{file.name}</dd>
                    <dt>SHA-256</dt><dd className="mono">{file.hash}</dd>
                  </dl>
                </div>
              )}
            </div>
          </div>

          <div className="mk-prose verify-notes">
            <h2>What a match means</h2>
            <ul>
              <li>A match shows the file is exactly the copy this server recorded. It does not prove who signed, and it says nothing about copies held on other servers.</li>
              <li>Any change to the file, even opening and saving it again, gives it a different fingerprint, so an edited copy shows no match.</li>
              <li>If this server seals completed documents, the certificate of completion inside the signed copy describes the seal. See <Link href="/security">security and audit</Link> for what the seal does and does not show.</li>
            </ul>
          </div>
        </div>
      </section>
    </MarketingLayout>
  );
}

function Outcome({ result }) {
  if (result.match === 'signed') {
    return (
      <div className="verify-outcome">
        <span className="status-icon tone-ok"><CircleCheck size={22} strokeWidth={1.75} aria-hidden="true" /></span>
        <div>
          <h3>This is the completed copy recorded on this server.</h3>
          <p><strong>{result.title}</strong>{result.completedAt ? `, completed ${formatDate(result.completedAt, true)}` : ''}.</p>
          {result.signers?.length > 0 && (
            <ul className="verify-signers">
              {result.signers.map((s, i) => <li key={i}>{s.name}{s.signedAt ? <span>Signed {formatDate(s.signedAt, true)}</span> : null}</li>)}
            </ul>
          )}
        </div>
      </div>
    );
  }
  if (result.match === 'original') {
    return (
      <div className="verify-outcome">
        <span className="status-icon tone-warn"><History size={22} strokeWidth={1.75} aria-hidden="true" /></span>
        <div>
          <h3>This matches the original file before signing.</h3>
          <p>It is the PDF as it was uploaded, without signatures, not the completed copy.</p>
        </div>
      </div>
    );
  }
  return (
    <div className="verify-outcome">
      <span className="status-icon tone-neutral"><CircleHelp size={22} strokeWidth={1.75} aria-hidden="true" /></span>
      <div>
        <h3>No document with this exact content is recorded here.</h3>
        <p>Any change, even re-saving, alters the fingerprint. It may also come from a different server, or have been deleted.</p>
      </div>
    </div>
  );
}
