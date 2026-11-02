import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';

// shortcut: standard PDF fonts only cover Latin-1, so other characters print as "?"; embed a Unicode TTF via @pdf-lib/fontkit to lift this.
const latin1 = (s) => String(s ?? '').replace(/[^\x20-\x7E\xA0-\xFF]/g, '?');

export async function countPages(bytes) {
  const pdf = await PDFDocument.load(bytes);
  return pdf.getPageCount();
}

// Brand palette: #0B132B ink, #3A506B muted, rule is 20% #3A506B on white.
const INK = rgb(11 / 255, 19 / 255, 43 / 255);
const MUTED = rgb(58 / 255, 80 / 255, 107 / 255);
const RULE = rgb(216 / 255, 220 / 255, 225 / 255);

function fitText(font, text, maxWidth, size) {
  while (size > 5 && font.widthOfTextAtSize(text, size) > maxWidth) size -= 0.5;
  return size;
}

function stampField(pdf, page, field, font, images) {
  const { width: W, height: H } = page.getSize();
  const box = { x: field.x * W, y: H - (field.y + field.h) * H, w: field.w * W, h: field.h * H };
  const v = field.value;
  if (!v) return;
  if (field.type === 'signature' || field.type === 'initials') {
    const img = images.get(field.id);
    const scale = Math.min(box.w / img.width, box.h / img.height);
    const w = img.width * scale, h = img.height * scale;
    page.drawImage(img, { x: box.x + (box.w - w) / 2, y: box.y + (box.h - h) / 2, width: w, height: h });
  } else if (field.type === 'checkbox') {
    if (v !== 'true') return;
    const p = Math.min(box.w, box.h) * 0.22;
    const t = Math.max(1, Math.min(box.w, box.h) * 0.1);
    page.drawLine({ start: { x: box.x + p, y: box.y + p }, end: { x: box.x + box.w - p, y: box.y + box.h - p }, thickness: t, color: INK });
    page.drawLine({ start: { x: box.x + p, y: box.y + box.h - p }, end: { x: box.x + box.w - p, y: box.y + p }, thickness: t, color: INK });
  } else {
    const text = latin1(v);
    const size = fitText(font, text, box.w - 4, Math.min(box.h * 0.62, 12));
    page.drawText(text, { x: box.x + 2, y: box.y + (box.h - size * 0.72) / 2, size, font, color: INK });
  }
}

// Flattens every field value into the original PDF and appends a certificate of completion.
export async function buildSignedPdf({ original, doc, recipients, fields, events, chain }) {
  const pdf = await PDFDocument.load(original);
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const pages = pdf.getPages();

  const images = new Map();
  for (const f of fields) {
    if ((f.type === 'signature' || f.type === 'initials') && f.value) {
      images.set(f.id, await pdf.embedPng(Buffer.from(f.value.split(',')[1], 'base64')));
    }
  }
  for (const f of fields) if (pages[f.page]) stampField(pdf, pages[f.page], f, font, images);

  // Certificate pages
  const [W, H] = [612, 792];
  const M = 54;
  let page, y;
  const newPage = () => { page = pdf.addPage([W, H]); y = H - M; };
  const ensure = (need) => { if (y - need < M) newPage(); };
  const text = (s, x, size = 9, f = font, color = INK) => page.drawText(latin1(s), { x, y, size, font: f, color });
  const rule = () => { page.drawLine({ start: { x: M, y }, end: { x: W - M, y }, thickness: 0.5, color: RULE }); };

  newPage();
  text('Countersign', M, 10, bold);
  y -= 34;
  text('Certificate of completion', M, 20, bold);
  y -= 26;
  const meta = [
    ['Document', doc.title],
    ['Document ID', doc.id],
    ['Pages', String(doc.page_count)],
    ['Sent', fmt(doc.sent_at)],
    ['Completed', fmt(doc.completed_at)],
    ['Original SHA-256', doc.original_sha256],
  ];
  // Head of the per-document hash chain at stamping time; later events extend the chain beyond it.
  if (chain) {
    meta.push(['Audit events', chain.ok ? String(chain.count) : `${chain.count} (chain broken at event ${chain.brokenAt})`]);
    meta.push(['Audit chain head', chain.head || '-']);
  }
  const small = new Set(['Original SHA-256', 'Audit chain head']);
  for (const [k, v] of meta) {
    text(k, M, 9, font, MUTED);
    text(v, M + 110, small.has(k) ? 7.5 : 9);
    y -= 16;
  }

  y -= 14;
  text('Recipients', M, 12, bold);
  y -= 10;
  for (const r of recipients) {
    ensure(70);
    y -= 8; rule(); y -= 18;
    text(r.name, M, 10, bold);
    text(r.role === 'cc' ? 'Receives a copy' : doc.sequential ? `Signer, order ${r.routing_order}` : 'Signer', W - M - 140, 9, font, MUTED);
    y -= 14;
    text(r.email, M, 9, font, MUTED);
    y -= 14;
    if (r.role !== 'cc') {
      text(`Viewed ${fmt(r.viewed_at)}    Signed ${fmt(r.signed_at)}`, M, 8.5);
      const sig = fields.find((f) => f.recipient_id === r.id && f.type === 'signature' && f.value);
      if (sig) {
        const img = images.get(sig.id);
        const s = Math.min(120 / img.width, 34 / img.height);
        page.drawImage(img, { x: W - M - img.width * s, y: y - 6, width: img.width * s, height: img.height * s });
      }
      y -= 14;
    }
  }

  y -= 18;
  ensure(60);
  text('Audit trail', M, 12, bold);
  y -= 10;
  for (const e of events) {
    ensure(24);
    y -= 6; rule(); y -= 14;
    text(fmt(e.created_at), M, 8, font, MUTED);
    text(`${e.actor} - ${e.action}${e.detail ? `: ${e.detail}` : ''}`.slice(0, 70), M + 112, 8.5);
    if (e.ip) text(e.ip.slice(0, 40), W - M - 110, 7.5, font, MUTED);
    y -= 2;
  }

  pdf.setTitle(doc.title);
  pdf.setProducer('Countersign');
  return Buffer.from(await pdf.save());
}

function fmt(iso) {
  if (!iso) return '-';
  return new Date(iso).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}
