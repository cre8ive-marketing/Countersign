import { PenLine, Signature, CalendarDays, UserRound, AtSign, TextCursorInput, SquareCheck, Building2, BriefcaseBusiness, Hash, SquareChevronDown, CircleDot, Stamp } from 'lucide-react';

export async function apiFetch(url, { method = 'POST', body, headers } = {}) {
  const isRaw = body instanceof Blob || body instanceof ArrayBuffer;
  const res = await fetch(url, {
    method,
    headers: isRaw ? headers : { 'Content-Type': 'application/json', ...headers },
    body: body == null ? undefined : isRaw ? body : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.status = res.status;
    err.retryAfter = Number(res.headers.get('Retry-After')) || null; // seconds, when the server rate-limits
    throw err;
  }
  return data;
}

// Width/height in PDF points at 100% page size.
export const FIELD_META = {
  signature: { label: 'Signature', icon: Signature, w: 170, h: 46 },
  initials: { label: 'Initials', icon: PenLine, w: 64, h: 40 },
  date: { label: 'Date signed', icon: CalendarDays, w: 110, h: 22, auto: true },
  name: { label: 'Full name', icon: UserRound, w: 160, h: 22, auto: true },
  email: { label: 'Email', icon: AtSign, w: 180, h: 22, auto: true },
  text: { label: 'Text', icon: TextCursorInput, w: 160, h: 22 },
  checkbox: { label: 'Checkbox', icon: SquareCheck, w: 16, h: 16 },
  company: { label: 'Company', icon: Building2, w: 160, h: 22 },
  jobtitle: { label: 'Job title', icon: BriefcaseBusiness, w: 160, h: 22 },
  number: { label: 'Number', icon: Hash, w: 100, h: 22 },
  dropdown: { label: 'Dropdown', icon: SquareChevronDown, w: 160, h: 22, choices: true },
  radio: { label: 'Radio', icon: CircleDot, w: 140, h: 52, choices: true },
  stamp: { label: 'Stamp', icon: Stamp, w: 110, h: 80, image: true },
};
// Same pattern the server checks; lets the signing page flag a bad number before submitting.
export const NUMBER_RE = /^-?\d{1,15}([.,]\d{1,6})?$/;
// Server rules for dropdown/radio options: trimmed, 1-60 chars, unique, at most 20. Invalid sets drop the field, so clean before saving.
export const cleanOptions = (opts) => [...new Set((opts ?? []).map((o) => String(o).trim()).filter(Boolean).map((o) => o.slice(0, 60)))].slice(0, 20);

// Brand palette only. Each one holds 4.5:1+ as text on white and under white text, so field labels and order pills stay readable.
export const RECIPIENT_COLORS = [
  'color-mix(in srgb, #5BC0DE 58%, #0B132B)', // deep cyan, about 5.0:1
  'color-mix(in srgb, #D97706 70%, #0B132B)', // burnt amber, about 5.5:1
  '#0B132B', // ink, 18.4:1
  '#3A506B', // slate, 8.3:1
  'color-mix(in srgb, #F4D6B0 45%, #0B132B)', // warm stone, about 4.9:1
  'color-mix(in srgb, #D97706 45%, #0B132B)', // dark umber, about 9.0:1
];
export const recipientColor = (i) => RECIPIENT_COLORS[((i % RECIPIENT_COLORS.length) + RECIPIENT_COLORS.length) % RECIPIENT_COLORS.length];

export const DOC_STATUS = {
  draft: { label: 'Draft', tone: 'neutral' },
  sent: { label: 'Waiting for others', tone: 'warn' },
  completed: { label: 'Completed', tone: 'ok' },
  declined: { label: 'Declined', tone: 'bad' },
  voided: { label: 'Voided', tone: 'bad' },
  expired: { label: 'Expired', tone: 'bad' },
};

export const RECIPIENT_STATUS = {
  pending: 'Queued',
  sent: 'Needs to sign',
  viewed: 'Viewed',
  signed: 'Signed',
  declined: 'Declined',
};

export function formatDate(iso, withTime = false) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleString('en-US', withTime
    ? { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }
    : { month: 'short', day: 'numeric', year: 'numeric' });
}

export function relativeTime(iso) {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 604800) return `${Math.floor(s / 86400)}d ago`;
  return formatDate(iso);
}
