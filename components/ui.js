import Link from 'next/link';
import { DOC_STATUS } from '../lib/client';

// Pass href={null} for a plain brand mark (no link), e.g. on signer pages where "home" is not the signer's.
export function Logo({ href = '/', compact = false }) {
  const Tag = href ? Link : 'span';
  const a11y = href ? { href, 'aria-label': 'Countersign home' } : compact ? { role: 'img', 'aria-label': 'Countersign' } : {};
  return (
    <Tag className="logo" {...a11y}>
      <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
        <rect x="1" y="1" width="20" height="20" rx="6" fill="var(--ink)" />
        <path d="M6 13.6c1.6-3.8 3-5.6 4.1-5.6 1.4 0 .1 5.2 1.4 5.2 1 0 1.6-2.7 2.6-2.7.8 0 .9 1.6 1.9 1.6" fill="none" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M6 16h10" stroke="var(--accent-on-ink)" strokeWidth="1.6" strokeLinecap="round" />
      </svg>
      {!compact && <span>Countersign</span>}
    </Tag>
  );
}

export function Button({ variant = 'secondary', size, loading, children, className = '', ...props }) {
  const cls = `btn btn-${variant}${size ? ` btn-${size}` : ''} ${className}`;
  if (props.href) {
    const { href, ...rest } = props;
    return <Link href={href} className={cls} {...rest}>{children}</Link>;
  }
  return (
    <button className={cls} disabled={loading || props.disabled} aria-busy={loading || undefined} {...props}>
      {loading && <span className="spinner" aria-hidden="true" />}
      {children}
    </button>
  );
}

export function StatusBadge({ status }) {
  const s = DOC_STATUS[status] ?? DOC_STATUS.draft;
  return <span className={`badge badge-${s.tone}`}><span className="badge-dot" aria-hidden="true" />{s.label}</span>;
}

export function TextField({ label, hint, error, id, ...props }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} className="input" aria-invalid={error ? true : undefined} {...props} />
      {hint && !error && <p className="field-hint">{hint}</p>}
      {error && <p className="field-error" role="alert">{error}</p>}
    </div>
  );
}

export function Avatar({ name, color }) {
  const initials = (name || '?').split(/\s+/).map((p) => p[0]).slice(0, 2).join('').toUpperCase();
  return <span className="avatar" style={color ? { '--avatar': color } : undefined} aria-hidden="true">{initials}</span>;
}
