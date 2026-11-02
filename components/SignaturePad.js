import { useEffect, useRef, useState } from 'react';
import { Dancing_Script, Great_Vibes, Allura, Caveat } from 'next/font/google';
import { ImageUp, Lock } from 'lucide-react';
import { Button } from './ui';
import { script } from '../lib/fonts';

// Declared here, not in lib/fonts.js, so only pages that render the pad ship these faces. Not preloaded: they load when the dialog opens.
const dancing = Dancing_Script({ subsets: ['latin'], weight: '500', display: 'swap', preload: false });
const vibes = Great_Vibes({ subsets: ['latin'], weight: '400', display: 'swap', preload: false });
const allura = Allura({ subsets: ['latin'], weight: '400', display: 'swap', preload: false });
const caveat = Caveat({ subsets: ['latin'], weight: '500', display: 'swap', preload: false });

// size evens out the faces' different x-heights in the preview.
const STYLES = [
  { id: 'delafield', label: 'Mrs Saint Delafield', font: script, size: 36 },
  { id: 'vibes', label: 'Great Vibes', font: vibes, size: 34 },
  { id: 'allura', label: 'Allura', font: allura, size: 36 },
  { id: 'dancing', label: 'Dancing Script', font: dancing, size: 30 },
  { id: 'caveat', label: 'Caveat', font: caveat, size: 32 },
];

const INK = '#1C2541'; // deep navy from the brand palette
const MAX_BYTES = 5 * 1024 * 1024;
const MAX_URL = 400000; // the server rejects longer data URLs
const MAX_W = 900, MAX_H = 300;

// Lets a signer type, draw or upload a signature (a stamp is upload only); resolves to a trimmed transparent PNG data URL.
export default function SignaturePad({ kind = 'signature', defaultName = '', onAdopt, onCancel }) {
  const noun = { initials: 'initials', stamp: 'stamp' }[kind] ?? 'signature';
  const initialsOf = (n) => n.split(/\s+/).filter(Boolean).map((p) => p[0]).join('').toUpperCase().slice(0, 3);
  const modes = kind === 'stamp' ? ['upload'] : ['type', 'draw', 'upload'];
  const [mode, setMode] = useState(modes[0]);
  const [text, setText] = useState(kind === 'initials' ? initialsOf(defaultName) : defaultName);
  const [style, setStyle] = useState(STYLES[0].id);
  const [drawn, setDrawn] = useState(false);
  const [upload, setUpload] = useState(null); // processed PNG data URL
  const [uploadError, setUploadError] = useState('');
  const [busy, setBusy] = useState(false);
  const canvas = useRef(null);
  const drawing = useRef(null);
  const fileInput = useRef(null);

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

  async function pickFile(e) {
    const file = e.target.files?.[0];
    e.target.value = ''; // lets the same file be chosen again after an error
    if (!file) return;
    setUploadError('');
    if (file.type !== 'image/png' && file.type !== 'image/jpeg') return setUploadError('Choose a PNG or JPEG image.');
    if (file.size > MAX_BYTES) return setUploadError('This image is larger than 5 MB. Choose a smaller one.');
    setBusy(true);
    try {
      const png = await processUpload(file);
      if (!png) setUploadError(`No ${noun} found in this image. Use dark ink on a light background.`);
      setUpload(png);
    } catch {
      setUploadError('This image could not be read. Try saving it again as PNG or JPEG.');
      setUpload(null);
    } finally {
      setBusy(false);
    }
  }

  async function adopt() {
    if (mode === 'upload') return onAdopt(upload);
    if (mode === 'draw') return onAdopt(fit(trim(canvas.current)));
    setBusy(true);
    try {
      const family = STYLES.find((s) => s.id === style).font.style.fontFamily;
      const font = `${kind === 'initials' ? 150 : 130}px ${family}`;
      await document.fonts.load(font, text.trim());
      onAdopt(fit(trim(renderText(text.trim(), font))));
    } finally {
      setBusy(false);
    }
  }

  const ready = { type: text.trim().length > 0, draw: drawn, upload: Boolean(upload) }[mode];
  const sample = text.trim() || (kind === 'initials' ? 'AB' : 'Your name');

  return (
    <div className="sigpad">
      {modes.length > 1 && <div className="segmented" role="tablist" aria-label={`How to create your ${noun}`}>
        {modes.map((m) => (
          <button key={m} type="button" role="tab" aria-selected={mode === m} className={mode === m ? 'is-active' : ''} onClick={() => setMode(m)}>
            {{ type: 'Type', draw: 'Draw', upload: 'Upload' }[m]}
          </button>
        ))}
      </div>}

      {mode === 'type' && (
        <div className="sigpad-type">
          <label htmlFor="sig-text" className="sr-only">Your {noun}</label>
          <input id="sig-text" className="input" value={text} onChange={(e) => setText(e.target.value)} maxLength={kind === 'initials' ? 4 : 60} autoFocus />
          <fieldset className="sigfonts">
            <legend>Style</legend>
            {STYLES.map((s) => (
              <label key={s.id} className="sigfont">
                <input type="radio" name="sig-style" className="sr-only" value={s.id} checked={style === s.id} onChange={() => setStyle(s.id)} aria-label={s.label} />
                <span className={s.font.className} style={{ fontSize: s.size }} aria-hidden="true">{sample}</span>
              </label>
            ))}
          </fieldset>
        </div>
      )}

      {mode === 'draw' && (
        <div className="sigpad-draw">
          <canvas ref={canvas} onPointerDown={down} onPointerMove={move} onPointerUp={up} onPointerCancel={up} aria-label={`Draw your ${noun} here`} />
          <div className="sigpad-baseline" aria-hidden="true" />
          {drawn && <button type="button" className="btn btn-ghost btn-sm sigpad-clear" onClick={clear}>Clear</button>}
        </div>
      )}

      {mode === 'upload' && (
        <div className="sigpad-upload">
          <div className="sigpad-preview sigpad-image">
            {upload
              ? <img src={upload} alt={`Your uploaded ${noun}`} />
              : <span className="sigpad-empty">PNG or JPEG, up to 5 MB. A white background is removed.</span>}
          </div>
          <input ref={fileInput} id="sig-file" type="file" accept="image/png,image/jpeg" hidden onChange={pickFile} />
          <div className="sigpad-upload-row">
            <Button variant="secondary" onClick={() => fileInput.current?.click()} loading={busy} aria-describedby={uploadError ? 'sig-file-error' : undefined}>
              {!busy && <ImageUp size={16} aria-hidden="true" />}{upload ? 'Choose another image' : 'Choose image'}
            </Button>
          </div>
          {uploadError && <p id="sig-file-error" className="field-error" role="alert">{uploadError}</p>}
        </div>
      )}

      <p className="sigpad-legal">{kind === 'stamp'
        ? 'By adopting, you agree to place this stamp on the document as your mark.'
        : `By adopting, you agree ${kind === 'initials' ? 'these initials are' : 'this signature is'} the legal equivalent of your handwritten ${noun} on this document.`}</p>
      <p className="sigpad-note"><Lock size={14} aria-hidden="true" />Your {noun} {kind === 'initials' ? 'are' : 'is'} stored encrypted on this server.</p>
      <div className="sigpad-actions">
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button variant="accent" onClick={adopt} disabled={!ready || busy} loading={busy && mode === 'type'}>{kind === 'stamp' ? 'Adopt and stamp' : 'Adopt and sign'}</Button>
      </div>
    </div>
  );
}

function renderText(t, font) {
  const c = document.createElement('canvas');
  const ctx = c.getContext('2d');
  ctx.font = font;
  const m = ctx.measureText(t);
  // Script faces swash past their advance width, so size from the ink box, not the advance.
  const left = Math.ceil(m.actualBoundingBoxLeft), asc = Math.ceil(m.actualBoundingBoxAscent);
  c.width = left + Math.ceil(m.actualBoundingBoxRight) + 40;
  c.height = asc + Math.ceil(m.actualBoundingBoxDescent) + 40;
  ctx.font = font; // resizing the canvas resets context state
  ctx.fillStyle = INK;
  ctx.fillText(t, 20 + left, 20 + asc);
  return c;
}

async function processUpload(file) {
  const bmp = await createImageBitmap(file);
  // Cap the working size so a huge photo can't exhaust memory in getImageData.
  const s = Math.min(1, 2000 / Math.max(bmp.width, bmp.height));
  const c = document.createElement('canvas');
  c.width = Math.max(1, Math.round(bmp.width * s));
  c.height = Math.max(1, Math.round(bmp.height * s));
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(bmp, 0, 0, c.width, c.height);
  bmp.close();
  const img = ctx.getImageData(0, 0, c.width, c.height);
  const d = img.data;
  for (let i = 0; i < d.length; i += 4) {
    const lo = Math.min(d[i], d[i + 1], d[i + 2]);
    // Near-white becomes transparent; light greys fade so anti-aliased edges stay smooth.
    if (lo >= 235) d[i + 3] = 0;
    else if (lo > 190) d[i + 3] = Math.round(d[i + 3] * (235 - lo) / 45);
  }
  ctx.putImageData(img, 0, 0);
  return fit(trim(c));
}

// Returns a canvas cropped to the visible ink, or null when it is blank.
function trim(src) {
  if (!src) return null;
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
  return out;
}

// Scales into MAX_W x MAX_H, then keeps shrinking until the data URL fits the server limit.
function fit(src) {
  if (!src) return null;
  let scale = Math.min(1, MAX_W / src.width, MAX_H / src.height);
  for (;;) {
    const c = document.createElement('canvas');
    c.width = Math.max(1, Math.round(src.width * scale));
    c.height = Math.max(1, Math.round(src.height * scale));
    c.getContext('2d').drawImage(src, 0, 0, c.width, c.height);
    const url = c.toDataURL('image/png');
    if (url.length <= MAX_URL || c.width <= 40) return url;
    scale *= 0.8;
  }
}
