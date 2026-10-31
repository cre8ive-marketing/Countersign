import { useEffect, useState } from 'react';
import { CircleCheck, Signature } from 'lucide-react';
import { Button } from '../ui';

// Interactive sample: typing a name signs the sample agreement and appends an audit entry.
export default function HeroDemo() {
  const [name, setName] = useState('');
  const [signed, setSigned] = useState(false);
  const [time, setTime] = useState('');
  useEffect(() => setTime(new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })), [signed]);

  return (
    <div className="demo" aria-label="Interactive example of signing a document">
      <div className="demo-bar">
        <span className="demo-title">Website redesign agreement.pdf</span>
        <span className={`badge ${signed ? 'badge-ok' : 'badge-warn'}`}><span className="badge-dot" aria-hidden="true" />{signed ? 'Completed' : '1 of 2 signed'}</span>
      </div>
      <div className="demo-page">
        <p className="demo-doc-h">Services Agreement</p>
        <p className="demo-doc-p">Between Northwind Studio (“Agency”) and the client named below, for the design and build of a marketing website in four milestones.</p>
        <div className="demo-lines" aria-hidden="true"><i /><i /><i style={{ width: '64%' }} /></div>
        <div className="demo-sign-grid">
          <div className="demo-sig is-done">
            <span className="demo-sig-ink">Priya Nair</span>
            <span className="demo-sig-cap">Agency</span>
          </div>
          <div className={`demo-sig${signed ? ' is-done' : ' is-pending'}`}>
            {signed ? <span className="demo-sig-ink">{name}</span> : <span className="demo-sig-cta">Sign here</span>}
            <span className="demo-sig-cap">Client</span>
          </div>
        </div>
      </div>
      <div className="demo-foot">
        {!signed ? (
          <form onSubmit={(e) => { e.preventDefault(); if (name.trim()) setSigned(true); }}>
            <label htmlFor="demo-name">Try it: type your name to sign</label>
            <div className="demo-row">
              <input id="demo-name" className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Alex Morgan" maxLength={24} autoComplete="off" />
              <Button variant="accent" type="submit" disabled={!name.trim()}>Sign</Button>
            </div>
            <p className="demo-note">Sample document. Nothing is saved.</p>
          </form>
        ) : (
          <div className="demo-done">
            <ol className="demo-audit">
              <li><CircleCheck size={16} aria-hidden="true" /><strong>Completed</strong><span>Signed PDF and certificate generated · {time}</span></li>
              <li><Signature size={16} aria-hidden="true" /><strong>Signed</strong><span>{name} · {time}</span></li>
            </ol>
            <button type="button" className="link-btn" onClick={() => { setSigned(false); setName(''); }}>Reset example</button>
          </div>
        )}
      </div>
    </div>
  );
}
