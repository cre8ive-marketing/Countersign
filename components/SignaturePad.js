import { useEffect, useRef, useState } from 'react';
import { Button } from './ui';
import { script } from '../lib/fonts';

const INK = '#14213d';

// Lets a signer type or draw a signature; resolves to a trimmed transparent PNG data URL.
export default function SignaturePad({ kind = 'signature', defaultName = '', onAdopt, onCancel }) {
  const initialsOf = (n) => n.split(/\s+/).filter(Boolean).map((p) => p[0]).join('').toUpperCase().slice(0, 3);
  const [mode, setMode] = useState('type');
  const [text, setText] = useState(kind === 'initials' ? initialsOf(defaultName) : defaultName);
  const [drawn, setDrawn] = useState(false);
  const canvas = useRef(null);
  const drawing = useRef(null);

  useEffect(() => {
    if (mode !== 'draw') return;
    const c = canvas.current;
    const dpr = window.devicePixelRatio || 1;
    c.width = c.clientWidth * dpr;
    c.height = c.clientHeight * dpr;
    const ctx = c.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.strokeStyle = INK;
    ctx.lineWidth = 2.4;
    setDrawn(false);
  }, [mode]);

  const point = (e) => {
    const r = canvas.current.getBoundingClientRect();
    return [e.clientX - r.left, e.clientY - r.top];
  };
  const down = (e) => {
    canvas.current.setPointerCapture(e.pointerId);
    drawing.current = point(e);
  };
  const move = (e) => {
    if (!drawing.current) return;
    const ctx = canvas.current.getContext('2d');
    const [x, y] = point(e);
    const [px, py] = drawing.current;
    ctx.beginPath();
    ctx.moveTo(px, py);
    ctx.quadraticCurveTo(px, py, (px + x) / 2, (py + y) / 2);
    ctx.lineTo(x, y);
    ctx.stroke();
    drawing.current = [x, y];
    setDrawn(true);
  };
  const up = () => { drawing.current = null; };
  const clear = () => {
    const c = canvas.current;
    c.getContext('2d').clearRect(0, 0, c.width, c.height);
    setDrawn(false);
  };

  async function adopt() {
    if (mode === 'draw') return onAdopt(trim(canvas.current));
    const family = script.style.fontFamily;
    await document.fonts.load(`64px ${family}`);
    const c = document.createElement('canvas');
    const ctx = c.getContext('2d');
    const font = `${kind === 'initials' ? 150 : 130}px ${family}`;
    ctx.font = font;
    c.width = Math.ceil(ctx.measureText(text.trim()).width) + 80;
    c.height = 300;
    ctx.font = font; // resizing the canvas resets context state
    ctx.fillStyle = INK;
    ctx.textBaseline = 'middle';
    ctx.fillText(text.trim(), 20, 160);
    onAdopt(trim(c));
  }

  const ready = mode === 'draw' ? drawn : text.trim().length > 0;
  const noun = kind === 'initials' ? 'initials' : 'signature';

  return (
    <div className="sigpad">
      <div className="segmented" role="tablist" aria-label={`How to create your ${noun}`}>
        {['type', 'draw'].map((m) => (
          <button key={m} role="tab" aria-selected={mode === m} className={mode === m ? 'is-active' : ''} onClick={() => setMode(m)}>
            {m === 'type' ? 'Type' : 'Draw'}
          </button>
        ))}
      </div>

      {mode === 'type' ? (
        <div className="sigpad-type">
          <label htmlFor="sig-text" className="sr-only">Your {noun}</label>
          <input id="sig-text" className="input" value={text} onChange={(e) => setText(e.target.value)} maxLength={kind === 'initials' ? 4 : 60} autoFocus />
          <div className="sigpad-preview" aria-hidden="true"><span>{text || ' '}</span></div>
        </div>
      ) : (
        <div className="sigpad-draw">
          <canvas ref={canvas} onPointerDown={down} onPointerMove={move} onPointerUp={up} onPointerCancel={up} aria-label={`Draw your ${noun} here`} />
          <div className="sigpad-baseline" aria-hidden="true" />
          {drawn && <button className="link-btn sigpad-clear" onClick={clear}>Clear</button>}
        </div>
      )}

      <p className="sigpad-legal">By adopting, you agree this {noun} is the legal equivalent of your handwritten {noun} on this document.</p>
      <div className="sigpad-actions">
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button variant="accent" onClick={adopt} disabled={!ready}>Adopt and sign</Button>
      </div>
    </div>
  );
}

function trim(src) {
  const ctx = src.getContext('2d');
  const { width, height } = src;
  const data = ctx.getImageData(0, 0, width, height).data;
  let x0 = width, y0 = height, x1 = 0, y1 = 0;
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      if (data[(y * width + x) * 4 + 3] > 8) {
        if (x < x0) x0 = x; if (x > x1) x1 = x;
        if (y < y0) y0 = y; if (y > y1) y1 = y;
      }
    }
  }
  if (x1 < x0) return null;
  const pad = 8;
  const out = document.createElement('canvas');
  out.width = x1 - x0 + pad * 2;
  out.height = y1 - y0 + pad * 2;
  out.getContext('2d').drawImage(src, x0 - pad, y0 - pad, out.width, out.height, 0, 0, out.width, out.height);
  return out.toDataURL('image/png');
}
