import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { Upload, Search, ChevronRight, FileText, LayoutTemplate, PenLine, Folder, FolderPlus, FolderInput, Pencil, Trash2 } from 'lucide-react';
import { withUser } from '../../lib/auth';
import db from '../../lib/db';
import { signingToken } from '../../lib/documents';
import { teamOf } from '../../lib/teams';
import { apiFetch, formatDate, relativeTime, recipientColor } from '../../lib/client';
import AppShell from '../../components/AppShell';
import { Avatar, Button, StatusBadge, TextField } from '../../components/ui';

const SCOPES = [{ id: 'all', label: 'All' }, { id: 'mine', label: 'Mine' }, { id: 'team', label: 'Team' }];

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
  const folders = db.prepare(`SELECT f.id, f.name, (SELECT COUNT(*) FROM documents d WHERE d.folder_id = f.id AND d.owner_id = f.owner_id) AS count
    FROM folders f WHERE f.owner_id = ? ORDER BY f.name COLLATE NOCASE`).all(user.id);
  const folder = typeof ctx.query.folder === 'string' ? folders.find((f) => f.id === ctx.query.folder) : null;
  if (ctx.query.folder && !folder) return { redirect: { destination: isTemplates ? '/app?view=templates' : '/app', permanent: false } };
  const folderId = folder?.id ?? null;
  const team = teamOf(user.id);
  const teamId = team?.teamId ?? null;
  const manager = team?.role === 'owner' || team?.role === 'admin';
  const scope = teamId && ['mine', 'team'].includes(ctx.query.scope) ? ctx.query.scope : 'all';
  // Mine: documents I own. Team: documents shared with my team (mine included). All: both. Folders are personal, so a folder shows only my documents.
  const visible = `(d.owner_id = ? OR (? IS NOT NULL AND d.team_id = ?))
    AND (? <> 'mine' OR d.owner_id = ?) AND (? <> 'team' OR d.team_id = ?)`;
  const visibleArgs = [user.id, teamId, teamId, scope, user.id, scope, teamId];
  const docs = db.prepare(`SELECT d.id, d.title, d.status, d.updated_at, d.page_count, d.expires_at, d.folder_id, d.owner_id, d.team_id, u.name AS owner_name
    FROM documents d JOIN users u ON u.id = d.owner_id
    WHERE ${visible} AND d.is_template = ? AND (? IS NULL OR (d.folder_id = ? AND d.owner_id = ?)) ORDER BY d.updated_at DESC`)
    .all(...visibleArgs, isTemplates ? 1 : 0, folderId, folderId, user.id);
  const recips = db.prepare(`SELECT r.document_id, r.name, r.role, r.status, r.position FROM recipients r
    JOIN documents d ON d.id = r.document_id WHERE ${visible} ORDER BY r.position`).all(...visibleArgs);
  // Only the user's own documents where they are also a signer. Emails are unverified, so matching
  // recipients by email across other owners would hand their signing links to anyone who signs up with that address.
  const action = db.prepare(`SELECT r.*, d.title, d.updated_at AS doc_updated_at FROM recipients r
    JOIN documents d ON d.id = r.document_id
    WHERE d.owner_id = ? AND r.email = ? AND d.status = 'sent' AND r.status IN ('sent', 'viewed') AND (? IS NULL OR d.folder_id = ?)
    ORDER BY d.updated_at DESC`).all(user.id, user.email.toLowerCase(), folderId, folderId);

  const byDoc = {};
  for (const r of recips) (byDoc[r.document_id] ??= []).push({ name: r.name, role: r.role, status: r.status, position: r.position });
  return {
    props: {
      user,
      isTemplates,
      folders: folders.map((f) => ({ id: f.id, name: f.name, count: Number(f.count) })),
      folderId,
      inTeam: !!teamId,
      scope,
      docs: docs.map((d) => {
        const mine = d.owner_id === user.id;
        return {
          id: d.id, title: d.title, status: d.status, updated_at: d.updated_at, page_count: d.page_count, expires_at: d.expires_at, folderId: mine ? d.folder_id ?? null : null, recipients: byDoc[d.id] ?? [],
          mine, ownerName: mine ? null : d.owner_name, teamShared: !!d.team_id, canWrite: mine || manager,
        };
      }),
      // Rows whose link is expired or revoked have no token and are left out.
      action: action.map((a) => ({ id: a.document_id, title: a.title, updated_at: a.doc_updated_at, token: signingToken(a) }))
        .filter((a) => a.token),
    },
  };
});

// Keeps the current view and folder together in every link.
const listHref = (view, folder, scope) => {
  const q = new URLSearchParams();
  if (view && view !== 'all') q.set('view', view);
  if (folder) q.set('folder', folder);
  if (scope && scope !== 'all') q.set('scope', scope);
  const s = q.toString();
  return s ? `/app?${s}` : '/app';
};

export default function Documents({ user, isTemplates, folders, folderId, inTeam, scope, docs, action }) {
  const router = useRouter();
  const view = isTemplates ? 'templates' : (router.query.view || 'all');
  const folder = folders.find((f) => f.id === folderId);
  const [query, setQuery] = useState('');
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState(null);
  const [moving, setMoving] = useState(null); // document being moved to a folder
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
            <h1>{isTemplates ? 'Templates' : 'Documents'}{folder && <span className="page-crumb"> / {folder.name}</span>}</h1>
            <p className="page-sub">{isTemplates ? 'Reusable documents with fields already placed. Fill in names and emails, then send.' : 'Everything you have sent, signed or started.'}</p>
          </div>
          <input ref={input} type="file" accept="application/pdf,.pdf" hidden onChange={(e) => upload(e.target.files[0])} />
          <Button variant="primary" onClick={() => input.current.click()} loading={uploading}>
            <Upload size={16} strokeWidth={1.75} aria-hidden="true" />{isTemplates ? 'New template' : 'Upload PDF'}
          </Button>
        </header>

        {error && <div className="banner banner-bad" role="alert">{error}</div>}

        <div className="dash">
          <Folders folders={folders} folderId={folderId} view={view} scope={scope} />
          <div className="dash-main">
            {inTeam && (
              <nav className="segmented scope-filter" aria-label="Whose documents">
                {SCOPES.map((sc) => (
                  <Link key={sc.id} href={listHref(view, folderId, sc.id)} className={scope === sc.id ? 'is-active' : undefined} aria-current={scope === sc.id ? 'page' : undefined}>{sc.label}</Link>
                ))}
              </nav>
            )}
            {!isTemplates && (
              <div className="toolbar">
                <nav className="tabs" aria-label="Filter documents">
                  {VIEWS.map((v) => (
                    <Link key={v.id} href={listHref(v.id, folderId, scope)} className={`tab${view === v.id ? ' is-active' : ''}`} aria-current={view === v.id ? 'page' : undefined}>
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
                {filtered.map((d) => <DocRow key={d.id} doc={d} isTemplate={isTemplates} onUse={() => useTemplate(d.id)} onMove={() => setMoving(d)} />)}
              </ul>
            ) : query ? (
              <Empty title="No matches" body={`No documents match “${query}”.`} />
            ) : (
              <Empty
                icon={isTemplates ? LayoutTemplate : FileText}
                title={scope === 'team' && !folder ? 'Nothing shared with the team yet' : folder ? 'This folder is empty' : isTemplates ? 'No templates yet' : view === 'all' ? 'Send your first document' : 'Nothing here yet'}
                body={scope === 'team' && !folder
                  ? 'New documents and templates you create are shared with your team. Open an older one and turn on Share with team to add it.'
                  : folder
                  ? 'Use Move to folder on any document or template to put it here. New uploads are not filed automatically.'
                  : isTemplates
                    ? 'Upload a PDF you send often, place fields for each role once, and reuse it in two clicks.'
                    : 'Drop a PDF anywhere on this page, or upload one. Add who needs to sign, place fields, and send.'}
                action={!folder && scope !== 'team' && (view === 'all' || isTemplates) ? <Button variant="primary" onClick={() => input.current.click()}><Upload size={16} aria-hidden="true" />{isTemplates ? 'New template' : 'Upload PDF'}</Button> : null}
              />
            )}
          </div>
        </div>
        <MoveDialog doc={moving} folders={folders} onClose={() => setMoving(null)} />
        {dragging && <div className="drop-hint" aria-hidden="true"><Upload size={22} strokeWidth={1.5} />Drop PDF to upload</div>}
      </div>
    </AppShell>
  );
}

function DocRow({ doc, isTemplate, onUse, onMove }) {
  const signers = doc.recipients.filter((r) => r.role === 'signer');
  const signed = signers.filter((r) => r.status === 'signed').length;
  // Someone who cannot edit a team draft or template opens its read-only page instead of the editor.
  const href = (isTemplate || doc.status === 'draft') && doc.canWrite ? `/app/documents/${doc.id}/edit` : `/app/documents/${doc.id}`;
  const owner = doc.ownerName ? `${doc.ownerName} · ` : doc.teamShared ? 'Shared with team · ' : '';
  return (
    <li className="doc-item">
      <Link href={href} className="doc-row">
        <span className="doc-icon"><FileText size={16} strokeWidth={1.75} aria-hidden="true" /></span>
        <span className="doc-main">
          <strong>{doc.title}</strong>
          <span>{owner}{isTemplate ? `${doc.page_count} page${doc.page_count === 1 ? '' : 's'} · ${signers.length} role${signers.length === 1 ? '' : 's'}` : signers.length ? `${signed} of ${signers.length} signed${doc.status === 'sent' && doc.expires_at ? ` · Expires ${formatDate(doc.expires_at)}` : ''}` : 'No recipients yet'}</span>
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
      {doc.mine ? (
        <button type="button" className="icon-btn doc-move" onClick={onMove} aria-label={`Move ${doc.title} to a folder`} title="Move to folder">
          <FolderInput size={16} strokeWidth={1.75} />
        </button>
      ) : <span className="doc-move doc-move-spacer" aria-hidden="true" />}
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

function Folders({ folders, folderId, view, scope }) {
  const router = useRouter();
  const [editing, setEditing] = useState(null); // { id?, name }
  const [removing, setRemoving] = useState(null);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState(null);
  const editDialog = useRef(null);
  const deleteDialog = useRef(null);
  const current = folders.find((f) => f.id === folderId);

  function openEdit(f) {
    setEditing(f ? { id: f.id, name: f.name } : { name: '' });
    setFormError(null);
    editDialog.current?.showModal();
  }

  async function save(e) {
    e.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      const body = { name: editing.name };
      if (editing.id) {
        await apiFetch(`/api/folders/${editing.id}`, { method: 'PUT', body });
        editDialog.current?.close();
        router.replace(router.asPath);
      } else {
        const { id } = await apiFetch('/api/folders', { body });
        editDialog.current?.close();
        router.push(listHref(view, id, scope));
      }
    } catch (err) {
      setFormError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    setFormError(null);
    try {
      await apiFetch(`/api/folders/${removing.id}`, { method: 'DELETE' });
      deleteDialog.current?.close();
      router.push(listHref(view, removing.id === folderId ? null : folderId, scope));
    } catch (err) {
      setFormError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <aside className="folders" aria-labelledby="folders-h">
      <div className="folders-head">
        <h2 id="folders-h">Folders</h2>
        <button type="button" className="icon-btn" onClick={() => openEdit(null)} aria-label="New folder" title="New folder"><FolderPlus size={16} strokeWidth={1.75} /></button>
      </div>
      <ul className="folder-list">
        <li>
          <Link href={listHref(view, null, scope)} className={`folder-item${!folderId ? ' is-active' : ''}`} aria-current={!folderId ? 'page' : undefined}>
            <Folder size={15} strokeWidth={1.75} aria-hidden="true" /><span className="folder-name">All</span>
          </Link>
        </li>
        {folders.map((f) => (
          <li key={f.id}>
            <Link href={listHref(view, f.id, scope)} className={`folder-item${f.id === folderId ? ' is-active' : ''}`} aria-current={f.id === folderId ? 'page' : undefined}>
              <Folder size={15} strokeWidth={1.75} aria-hidden="true" /><span className="folder-name">{f.name}</span>
              <span className="folder-count"><span className="sr-only">, </span>{f.count}<span className="sr-only"> item{f.count === 1 ? '' : 's'}</span></span>
            </Link>
          </li>
        ))}
      </ul>
      {!folders.length && <p className="field-hint">Group documents and templates, for example by client.</p>}
      {current && (
        <div className="folder-tools">
          <Button size="sm" onClick={() => openEdit(current)}><Pencil size={14} aria-hidden="true" />Rename</Button>
          <Button size="sm" variant="danger" onClick={() => { setRemoving(current); setFormError(null); deleteDialog.current?.showModal(); }}><Trash2 size={14} aria-hidden="true" />Delete</Button>
        </div>
      )}

      <dialog ref={editDialog} className="dialog" aria-labelledby="folder-edit-title" onClose={() => setEditing(null)}>
        {editing && (
          <form onSubmit={save} noValidate>
            <h2 id="folder-edit-title">{editing.id ? 'Rename folder' : 'New folder'}</h2>
            {formError && <p className="otp-error contact-error" role="alert">{formError}</p>}
            <TextField id="folder-name" label="Folder name" value={editing.name} maxLength={80} autoComplete="off" required autoFocus
              onChange={(e) => setEditing((f) => ({ ...f, name: e.target.value }))} />
            <div className="dialog-actions">
              <Button variant="ghost" type="button" onClick={() => editDialog.current?.close()}>Cancel</Button>
              <Button variant="primary" type="submit" loading={busy}>{editing.id ? 'Save' : 'Create folder'}</Button>
            </div>
          </form>
        )}
      </dialog>

      <dialog ref={deleteDialog} className="dialog" aria-labelledby="folder-del-title">
        <h2 id="folder-del-title">Delete this folder?</h2>
        <p className="dialog-text">{removing ? `“${removing.name}” is removed. The ${removing.count} item${removing.count === 1 ? '' : 's'} in it are kept and become unfiled.` : ''}</p>
        {formError && <p className="field-error" role="alert">{formError}</p>}
        <div className="dialog-actions">
          <Button variant="ghost" type="button" onClick={() => deleteDialog.current?.close()}>Cancel</Button>
          <Button variant="danger" type="button" onClick={remove} loading={busy}><Trash2 size={16} aria-hidden="true" />Delete folder</Button>
        </div>
      </dialog>
    </aside>
  );
}

function MoveDialog({ doc, folders, onClose }) {
  const router = useRouter();
  const dialog = useRef(null);
  const [target, setTarget] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!doc) return;
    setTarget(doc.folderId ?? '');
    setError(null);
    dialog.current?.showModal();
  }, [doc]);

  async function move(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiFetch(`/api/documents/${doc.id}/move`, { body: { folderId: target || null } });
      dialog.current?.close();
      router.replace(router.asPath);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <dialog ref={dialog} className="dialog" aria-labelledby="move-title" onClose={onClose}>
      {doc && (
        <form onSubmit={move}>
          <h2 id="move-title">Move to folder</h2>
          <p className="dialog-text move-doc">{doc.title}</p>
          {error && <p className="otp-error contact-error" role="alert">{error}</p>}
          {folders.length ? (
            <fieldset className="move-options">
              <legend className="sr-only">Folder</legend>
              <label className="check"><input type="radio" name="move-folder" checked={target === ''} onChange={() => setTarget('')} />No folder</label>
              {folders.map((f) => (
                <label key={f.id} className="check"><input type="radio" name="move-folder" checked={target === f.id} onChange={() => setTarget(f.id)} />{f.name}</label>
              ))}
            </fieldset>
          ) : <p className="field-hint">You have no folders yet. Create one with New folder beside the list.</p>}
          <div className="dialog-actions">
            <Button variant="ghost" type="button" onClick={() => dialog.current?.close()}>Cancel</Button>
            <Button variant="primary" type="submit" loading={busy} disabled={!folders.length || target === (doc.folderId ?? '')}>Move</Button>
          </div>
        </form>
      )}
    </dialog>
  );
}
