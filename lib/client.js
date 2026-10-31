import { PenLine, Signature, CalendarDays, UserRound, AtSign, TextCursorInput, SquareCheck } from 'lucide-react';

export async function apiFetch(url, { method = 'POST', body, headers } = {}) {
  const isRaw = body instanceof Blob || body instanceof ArrayBuffer;
  const res = await fetch(url, {
    method,
    headers: isRaw ? headers : { 'Content-Type': 'application/json', ...headers },
    body: body == null ? undefined : isRaw ? body : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
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
};

export const RECIPIENT_COLORS = ['#2563eb', '#b45309', '#0f766e', '#be185d', '#6d28d9', '#4d7c0f'];
export const recipientColor = (i) => RECIPIENT_COLORS[((i % RECIPIENT_COLORS.length) + RECIPIENT_COLORS.length) % RECIPIENT_COLORS.length];

export const DOC_STATUS = {
  draft: { label: 'Draft', tone: 'neutral' },
  sent: { label: 'Waiting for others', tone: 'warn' },
  completed: { label: 'Completed', tone: 'ok' },
  declined: { label: 'Declined', tone: 'bad' },
  voided: { label: 'Voided', tone: 'bad' },
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
