import { useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { Upload, Search, ChevronRight, FileText, LayoutTemplate, PenLine } from 'lucide-react';
import { withUser } from '../../lib/auth';
import db from '../../lib/db';
import { signingToken } from '../../lib/documents';
import { apiFetch, formatDate, relativeTime, recipientColor } from '../../lib/client';
import AppShell from '../../components/AppShell';
import { Avatar, Button, StatusBadge } from '../../components/ui';

const VIEWS = [
  { id: 'all', label: 'All' },
  { id: 'action', label: 'Needs your signature' },
  { id: 'waiting', label: 'Waiting for others' },
  { id: 'completed', label: 'Completed' },
  { id: 'draft', label: 'Drafts' },
  { id: 'expired', label: 'Expired' },
];

export const getServerSideProps = withUser(async (ctx, user) => {
  const isTemplates = ctx.query.view === 'templates';
  const docs = db.prepare(`SELECT id, title, status, updated_at, page_count, expires_at FROM documents
    WHERE owner_id = ? AND is_template = ? ORDER BY updated_at DESC`).all(user.id, isTemplates ? 1 : 0);
  const recips = db.prepare(`SELECT r.document_id, r.name, r.role, r.status, r.position FROM recipients r
    JOIN documents d ON d.id = r.document_id WHERE d.owner_id = ? ORDER BY r.position`).all(user.id);
  // Only the user's own documents where they are also a signer. Emails are unverified, so matching
  // recipients by email across other owners would hand their signing links to anyone who signs up with that address.
  const action = db.prepare(`SELECT r.*, d.title, d.updated_at AS doc_updated_at FROM recipients r
    JOIN documents d ON d.id = r.document_id
    WHERE d.owner_id = ? AND r.email = ? AND d.status = 'sent' AND r.status IN ('sent', 'viewed') ORDER BY d.updated_at DESC`).all(user.id, user.email.toLowerCase());

  const byDoc = {};
  for (const r of recips) (byDoc[r.document_id] ??= []).push({ name: r.name, role: r.role, status: r.status, position: r.position });
  return {
    props: {
      user,
      isTemplates,
      docs: docs.map((d) => ({ id: d.id, title: d.title, status: d.status, updated_at: d.updated_at, page_count: d.page_count, expires_at: d.expires_at, recipients: byDoc[d.id] ?? [] })),
      // Rows whose link is expired or revoked have no token and are left out.
      action: action.map((a) => ({ id: a.document_id, title: a.title, updated_at: a.doc_updated_at, token: signingToken(a) }))
        .filter((a) => a.token),
    },
  };
});

export default function Documents({ user, isTemplates, docs, action }) {
  const router = useRouter();
  const view = isTemplates ? 'templates' : (router.query.view || 'all');
  const [query, setQuery] = useState('');
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState(null);
  const input = useRef(null);

  async function upload(file) {
    if (!file) return;
    if (file.type !== 'application/pdf' && !file.name.toLowerCase().endsWith('.pdf')) return setError('Only PDF files can be uploaded.');
    setError(null);
    setUploading(true);
    try {
      const { id } = await apiFetch('/api/documents', {
        body: file,
        headers: { 'Content-Type': 'application/pdf', 'x-file-name': encodeURIComponent(file.name), ...(isTemplates ? { 'x-template': '1' } : {}) },
      });
      router.push(`/app/documents/${id}/edit`);
    } catch (e) {
      setError(e.message);
      setUploading(false);
    }
  }

  async function useTemplate(id) {
    try {
      const { id: newId } = await apiFetch(`/api/documents/${id}/copy`, { body: { asTemplate: false } });
      router.push(`/app/documents/${newId}/edit`);
    } catch (e) { setError(e.message); }
  }

  const filtered = docs.filter((d) => {
    if (query && !d.title.toLowerCase().includes(query.toLowerCase())) return false;
    if (view === 'waiting') return d.status === 'sent';
    if (view === 'completed') return d.status === 'completed';
    if (view === 'draft') return d.status === 'draft';
    if (view === 'expired') return d.status === 'expired';
    return true;
  });
  const counts = {
    action: action.length,
    waiting: docs.filter((d) => d.status === 'sent').length,
    draft: docs.filter((d) => d.status === 'draft').length,
  };

  return (
    <AppShell user={user} title={isTemplates ? 'Templates' : 'Documents'}>
      <div
        className={`page${dragging ? ' is-dragging' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={(e) => { if (e.currentTarget === e.target) setDragging(false); }}
        onDrop={(e) => { e.preventDefault(); setDragging(false); upload(e.dataTransfer.files[0]); }}
      >
        <header className="page-head">
          <div>
            <h1>{isTemplates ? 'Templates' : 'Documents'}</h1>
            <p className="page-sub">{isTemplates ? 'Reusable documents with fields already placed. Fill in names and emails, then send.' : 'Everything you have sent, signed or started.'}</p>
          </div>
          <input ref={input} type="file" accept="application/pdf,.pdf" hidden onChange={(e) => upload(e.target.files[0])} />
          <Button variant="primary" onClick={() => input.current.click()} loading={uploading}>
            <Upload size={16} strokeWidth={1.75} aria-hidden="true" />{isTemplates ? 'New template' : 'Upload PDF'}
          </Button>
        </header>

        {error && <div className="banner banner-bad" role="alert">{error}</div>}

        {!isTemplates && (
          <div className="toolbar">
            <nav className="tabs" aria-label="Filter documents">
              {VIEWS.map((v) => (
                <Link key={v.id} href={v.id === 'all' ? '/app' : `/app?view=${v.id}`} className={`tab${view === v.id ? ' is-active' : ''}`} aria-current={view === v.id ? 'page' : undefined}>
                  {v.label}{counts[v.id] ? <span className="tab-count">{counts[v.id]}</span> : null}
                </Link>
              ))}
            </nav>
            <div className="search">
              <Search size={15} strokeWidth={1.75} aria-hidden="true" />
              <label htmlFor="q" className="sr-only">Search documents</label>
              <input id="q" placeholder="Search" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
          </div>
        )}

        {view === 'action' ? (
          action.length ? (
            <ul className="doc-list">
              {action.map((a) => (
                <li key={a.id}>
                  <Link href={`/sign/${a.token}`} className="doc-row">
                    <span className="doc-icon is-action"><PenLine size={16} strokeWidth={1.75} aria-hidden="true" /></span>
                    <span className="doc-main"><strong>{a.title}</strong><span>Sent by you</span></span>
                    <span className="doc-meta">{relativeTime(a.updated_at)}</span>
                    <span className="btn btn-accent btn-sm">Sign</span>
                  </Link>
                </li>
              ))}
            </ul>
          ) : <Empty title="Nothing to sign" body="Documents you send with yourself as a signer show up here. Documents from other people arrive by email." />
        ) : filtered.length ? (
          <ul className="doc-list">
            {filtered.map((d) => <DocRow key={d.id} doc={d} isTemplate={isTemplates} onUse={() => useTemplate(d.id)} />)}
          </ul>
        ) : query ? (
          <Empty title="No matches" body={`No documents match “${query}”.`} />
        ) : (
          <Empty
            icon={isTemplates ? LayoutTemplate : FileText}
            title={isTemplates ? 'No templates yet' : view === 'all' ? 'Send your first document' : 'Nothing here yet'}
            body={isTemplates
              ? 'Upload a PDF you send often, place fields for each role once, and reuse it in two clicks.'
              : 'Drop a PDF anywhere on this page, or upload one. Add who needs to sign, place fields, and send.'}
            action={view === 'all' || isTemplates ? <Button variant="primary" onClick={() => input.current.click()}><Upload size={16} aria-hidden="true" />{isTemplates ? 'New template' : 'Upload PDF'}</Button> : null}
          />
        )}
        {dragging && <div className="drop-hint" aria-hidden="true"><Upload size={22} strokeWidth={1.5} />Drop PDF to upload</div>}
      </div>
    </AppShell>
  );
}

function DocRow({ doc, isTemplate, onUse }) {
  const signers = doc.recipients.filter((r) => r.role === 'signer');
  const signed = signers.filter((r) => r.status === 'signed').length;
  const href = isTemplate || doc.status === 'draft' ? `/app/documents/${doc.id}/edit` : `/app/documents/${doc.id}`;
  return (
    <li>
      <Link href={href} className="doc-row">
        <span className="doc-icon"><FileText size={16} strokeWidth={1.75} aria-hidden="true" /></span>
        <span className="doc-main">
          <strong>{doc.title}</strong>
          <span>{isTemplate ? `${doc.page_count} page${doc.page_count === 1 ? '' : 's'} · ${signers.length} role${signers.length === 1 ? '' : 's'}` : signers.length ? `${signed} of ${signers.length} signed${doc.status === 'sent' && doc.expires_at ? ` · Expires ${formatDate(doc.expires_at)}` : ''}` : 'No recipients yet'}</span>
        </span>
        <span className="avatars" aria-label={signers.map((s) => s.name).join(', ')}>
          {signers.slice(0, 4).map((s) => <Avatar key={s.position} name={s.name} color={recipientColor(s.position)} />)}
        </span>
        {!isTemplate && <StatusBadge status={doc.status} />}
        <span className="doc-meta">{relativeTime(doc.updated_at)}</span>
        {isTemplate
          ? <button type="button" className="btn btn-secondary btn-sm" onClick={(e) => { e.preventDefault(); onUse(); }}>Use</button>
          : <ChevronRight size={16} className="doc-chevron" aria-hidden="true" />}
      </Link>
    </li>
  );
}

function Empty({ icon: Icon = FileText, title, body, action }) {
  return (
    <div className="empty">
      <span className="empty-icon"><Icon size={20} strokeWidth={1.5} aria-hidden="true" /></span>
      <h2>{title}</h2>
      <p>{body}</p>
      {action}
    </div>
  );
}
