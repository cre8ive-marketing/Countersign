import { useState } from 'react';
import { apiFetch } from '../lib/client';

// Owner-only switch: shares a document with the owner's team (team_id set) or makes it private again.
export default function ShareToggle({ docId, initialShared }) {
  const [shared, setShared] = useState(!!initialShared);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function toggle(next) {
    setBusy(true);
    setError(null);
    try {
      await apiFetch(`/api/documents/${docId}/share`, { body: { shared: next } });
      setShared(next);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="share-toggle">
      <label className="switch share-switch" title={shared ? 'Your team can see this. Admins can also manage it.' : 'Only you can see this.'}>
        <input type="checkbox" checked={shared} disabled={busy} aria-busy={busy || undefined} onChange={(e) => toggle(e.target.checked)} />
        <span className="switch-track" aria-hidden="true" />
        Share with team
      </label>
      {error && <p className="field-error" role="alert">{error}</p>}
    </div>
  );
}
