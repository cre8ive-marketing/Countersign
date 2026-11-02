import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import forge from 'node-forge';
import { SignPdf } from '@signpdf/signpdf';
import { pdflibAddPlaceholder } from '@signpdf/placeholder-pdf-lib';
import { P12Signer } from '@signpdf/signer-p12';
import { DATA_DIR } from './db.js';
import { readDecrypted, writeEncrypted } from './crypto.js';
import { fail } from './http.js';

// PDF seal: a PKCS#7 detached signature over the completed PDF, so later edits are detectable.
// It identifies this server's certificate, not a person or company.

const REASON = 'Sealed by Countersign at completion';
const P12_AAD = 'signing-p12';
let cached = null;

function sealName() {
  try {
    return `Countersign seal (${new URL(process.env.APP_URL).host})`;
  } catch {
    return 'Countersign seal (self-hosted)';
  }
}

function selfSignedP12() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const key = forge.pki.privateKeyFromPem(privateKey);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(publicKey);
  cert.serialNumber = '01' + crypto.randomBytes(15).toString('hex'); // leading 01 keeps it positive
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 10 * 365.25 * 864e5);
  const attrs = [{ name: 'commonName', value: sealName() }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{ name: 'basicConstraints', cA: false }, { name: 'keyUsage', digitalSignature: true }]);
  cert.sign(key, forge.md.sha256.create());
  const asn1 = forge.pkcs12.toPkcs12Asn1(key, [cert], '', { algorithm: '3des' });
  return Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary');
}

function checkValidity(label, { notBefore, notAfter }) {
  const t = new Date();
  if (notAfter < t || notBefore > t) throw new Error(`${label}: the seal certificate is not valid now (${notBefore.toISOString()} to ${notAfter.toISOString()}). Replace it to keep sealing documents.`);
}

function parseP12(p12, passphrase, label) {
  let bundle;
  try {
    bundle = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(p12.toString('binary')), passphrase);
  } catch (e) {
    throw new Error(`${label} could not be read (wrong format or passphrase): ${e.message}`);
  }
  const certs = bundle.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] ?? [];
  const keys = [
    ...(bundle.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] ?? []),
    ...(bundle.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] ?? []),
  ];
  const cert = certs[0]?.cert;
  if (!cert || !keys.some((k) => k.key)) throw new Error(`${label} must contain a certificate and its private key`);
  checkValidity(label, cert.validity);
  const der = Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary');
  return {
    label, validity: { notBefore: cert.validity.notBefore, notAfter: cert.validity.notAfter },
    cn: cert.subject.getField('CN')?.value || 'Countersign seal',
    subject: cert.subject.attributes.map((a) => `${a.shortName || a.name}=${a.value}`).join(', '),
    fingerprint256: crypto.createHash('sha256').update(der).digest('hex'),
  };
}

// Loaded on first use, never at import, so `next build` creates no key.
function load() {
  // Re-checked on every use: a long-running server must not keep sealing with a certificate that has since expired.
  if (cached) {
    checkValidity(cached.label, cached.validity);
    return cached;
  }
  let p12, passphrase, source, label;
  if (process.env.SIGNING_P12_BASE64) {
    p12 = Buffer.from(process.env.SIGNING_P12_BASE64, 'base64');
    passphrase = process.env.SIGNING_P12_PASSPHRASE || '';
    source = 'operator';
    label = 'SIGNING_P12_BASE64';
  } else {
    const file = path.join(DATA_DIR, 'signing.p12');
    // shortcut: no cross-process lock; two server processes starting at once could each generate one (both seals stay valid). Add a lock file if multi-process deploys appear.
    if (!fs.existsSync(file)) writeEncrypted(file, selfSignedP12(), P12_AAD);
    p12 = readDecrypted(file, P12_AAD);
    passphrase = '';
    source = 'self-signed';
    label = file;
  }
  return (cached = { p12, passphrase, source, ...parseP12(p12, passphrase, label) });
}

export function sealCertificate() {
  const { subject, fingerprint256, source } = load();
  return { subject, fingerprint256, source };
}

// Adds the signature placeholder, saves, and signs. The returned bytes are final: hash these, change nothing after.
export async function sealPdf(pdfDoc) {
  const c = load();
  pdflibAddPlaceholder({ pdfDoc, reason: REASON, contactInfo: '', name: c.cn, location: '', signatureLength: 16384 });
  const bytes = await pdfDoc.save({ useObjectStreams: false });
  let signed;
  try {
    signed = await new SignPdf().sign(Buffer.from(bytes), new P12Signer(c.p12, { passphrase: c.passphrase }));
  } catch (e) {
    // The original already holds text matching @signpdf's fixed placeholder, so the library cannot tell which one is ours.
    if (/multiple ByteRange placeholders/i.test(e?.message)) fail(422, 'This PDF contains an unsigned signature placeholder, so it cannot be sealed. Ask the sender to upload a clean copy of the document.');
    throw e;
  }
  return new Uint8Array(signed);
}
