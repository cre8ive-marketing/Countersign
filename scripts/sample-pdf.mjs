// Writes a two-page sample NDA for trying the editor: node scripts/sample-pdf.mjs <out.pdf>
import fs from 'node:fs';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';

const out = process.argv[2] || 'sample-nda.pdf';
const pdf = await PDFDocument.create();
const font = await pdf.embedFont(StandardFonts.Helvetica);
const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
const line = 'Each party agrees to keep the other party\'s confidential information private and to use it only to evaluate';

for (let p = 0; p < 2; p++) {
  const page = pdf.addPage([612, 792]);
  page.drawText(p ? 'Signatures' : 'Mutual Non-Disclosure Agreement', { x: 72, y: 700, size: 20, font: bold });
  let y = 660;
  for (let i = 0; i < (p ? 4 : 18); i++, y -= 18) page.drawText(line, { x: 72, y, size: 9.5, font, color: rgb(0.25, 0.25, 0.3) });
  if (p) {
    for (const [x, label] of [[72, 'Disclosing party'], [330, 'Receiving party']]) {
      page.drawLine({ start: { x, y: 480 }, end: { x: x + 210, y: 480 }, thickness: 0.8 });
      page.drawText(label, { x, y: 466, size: 9, font });
    }
  }
}
fs.writeFileSync(out, await pdf.save());
console.log(`wrote ${out}`);
