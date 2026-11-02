import { useEffect, useRef, useState } from 'react';
import { BookUser, FileUp, Pencil, Plus, Search, Trash2 } from 'lucide-react';
import { withUser } from '../../lib/auth';
import { listContacts } from '../../lib/contacts';
import { apiFetch } from '../../lib/client';
import AppShell from '../../components/AppShell';
import { Avatar, Button, TextField } from '../../components/ui';

const PAGE = 50;
const MAX_CSV = 1048576; // the server reads at most 1 MB

export const getServerSideProps = withUser(async (ctx, user) => ({
  props: { user, initial: listContacts(user.id, { limit: PAGE }) },
}));

export default function Contacts({ user, initial }) {
  const [query, setQuery] = useState('');
  const [list, setList] = useState(initial);
  const [loading, setLoading] = useState(false); // 'more' while appending a page
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);
  const [editing, setEditing] = useState(null); // { id?, name, email }
  const [formError, setFormError] = useState(null);
  const [removing, setRemoving] = useState(null);
  const [busy, setBusy] = useState(null); // 'save' | 'delete' | 'import'
  const editDialog = useRef(null);
  const deleteDialog = useRef(null);
  const fileInput = useRef(null);
  const first = useRef(true);

  async function load(q, offset = 0) {
    setLoading(offset ? 'more' : true);
    try {
      const res = await apiFetch(`/api/contacts?q=${encodeURIComponent(q)}&limit=${PAGE}&offset=${offset}`, { method: 'GET' });
      setList((l) => (offset ? { contacts: [...l.contacts, ...res.contacts], total: res.total } : res));
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (first.current) { first.current = false; return; }
    const t = setTimeout(() => load(query.trim()), 250);
    return () => clearTimeout(t);
  }, [query]); // eslint-disable-line react-hooks/exhaustive-deps

  function openEdit(c) {
    setEditing(c ? { ...c } : { name: '', email: '' });
    setFormError(null);
    editDialog.current?.showModal();
  }

  async function save(e) {
    e.preventDefault();
    setBusy('save');
    setFormError(null);
    try {
      const body = { name: editing.name, email: editing.email };
      if (editing.id) await apiFetch(`/api/contacts/${editing.id}`, { method: 'PUT', body });
      else await apiFetch('/api/contacts', { body });
      editDialog.current?.close();
      setNotice(editing.id ? 'Contact saved.' : `${editing.name.trim()} added.`);
      await load(query.trim());
    } catch (err) {
      setFormError(err.message);
    } finally {
      setBusy(null);
    }
  }

  async function remove() {
    setBusy('delete');
    try {
      await apiFetch(`/api/contacts/${removing.id}`, { method: 'DELETE' });
      deleteDialog.current?.close();
      setNotice(`${removing.name} deleted.`);
      await load(query.trim());
    } catch (err) {
      setFormError(err.message);
    } finally {
      setBusy(null);
    }
  }

  async function importCsv(file) {
    if (!file) return;
    setError(null);
    setNotice(null);
    if (file.size > MAX_CSV) return setError('This file is larger than 1 MB. Split it into smaller files.');
    setBusy('import');
    try {
      const { added, updated, skipped } = await apiFetch('/api/contacts/import', { body: file, headers: { 'Content-Type': 'text/csv' } });
      setNotice(`Import finished: ${added} added, ${updated} updated, ${skipped} skipped.`);
      await load(query.trim());
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  const { contacts, total } = list;

  return (
    <AppShell user={user} title="Contacts">
      <div className="page">
        <header className="page-head">
          <div>
            <h1>Contacts</h1>
            <p className="page-sub">People you send documents to. Everyone you send to is added here, and the editor suggests them as you type.</p>
          </div>
          <div className="head-actions">
            <input ref={fileInput} type="file" accept=".csv,text/csv" hidden onChange={(e) => { importCsv(e.target.files[0]); e.target.value = ''; }} />
            <Button variant="secondary" onClick={() => fileInput.current?.click()} loading={busy === 'import'} aria-describedby="csv-hint">
              {busy !== 'import' && <FileUp size={16} aria-hidden="true" />}Import CSV
            </Button>
            <Button variant="primary" onClick={() => openEdit(null)}><Plus size={16} aria-hidden="true" />Add contact</Button>
          </div>
        </header>
        <p id="csv-hint" className="field-hint contacts-hint">CSV import: one contact per row, name then email. A header row is optional, up to 2,000 rows and 1 MB.</p>

        {error && <div className="banner banner-bad" role="alert">{error}</div>}
        <div role="status">{notice && <div className="banner banner-ok"><span>{notice}</span><Button variant="ghost" size="sm" onClick={() => setNotice(null)}>Dismiss</Button></div>}</div>

        <div className="search contacts-search">
          <Search size={15} strokeWidth={1.75} aria-hidden="true" />
          <label htmlFor="q" className="sr-only">Search contacts</label>
          <input id="q" type="search" placeholder="Search by name or email" value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>

        {contacts.length ? (
          <>
            <ul className="doc-list" aria-busy={loading === true || undefined}>
              {contacts.map((c) => (
                <li key={c.id}>
                  <div className="doc-row">
                    <Avatar name={c.name} />
                    <span className="doc-main"><strong>{c.name}</strong><span>{c.email}</span></span>
                    <span className="contact-actions">
                      <button type="button" className="icon-btn" onClick={() => openEdit(c)} aria-label={`Edit ${c.name}`} title="Edit"><Pencil size={16} strokeWidth={1.75} /></button>
                      <button type="button" className="icon-btn" onClick={() => { setRemoving(c); setFormError(null); deleteDialog.current?.showModal(); }} aria-label={`Delete ${c.name}`} title="Delete"><Trash2 size={16} strokeWidth={1.75} /></button>
                    </span>
                  </div>
                </li>
              ))}
            </ul>
            <div className="list-foot">
              <span>{contacts.length < total ? `Showing ${contacts.length} of ${total}` : `${total} contact${total === 1 ? '' : 's'}`}</span>
              {contacts.length < total && <Button variant="secondary" onClick={() => load(query.trim(), contacts.length)} loading={loading === 'more'}>Show more</Button>}
            </div>
          </>
        ) : query.trim() ? (
          <div className="empty"><h2>No matches</h2><p>{`No contacts match “${query.trim()}”.`}</p></div>
        ) : (
          <div className="empty">
            <span className="empty-icon"><BookUser size={20} strokeWidth={1.5} aria-hidden="true" /></span>
            <h2>No contacts yet</h2>
            <p>Contacts are added when you send a document. You can also add them one by one or import a CSV file.</p>
            <Button variant="primary" onClick={() => openEdit(null)}><Plus size={16} aria-hidden="true" />Add contact</Button>
          </div>
        )}

        <dialog ref={editDialog} className="dialog" aria-labelledby="edit-title" onClose={() => setEditing(null)}>
          {editing && (
            <form onSubmit={save} noValidate>
              <h2 id="edit-title">{editing.id ? 'Edit contact' : 'Add contact'}</h2>
              {formError && <p className="otp-error contact-error" role="alert">{formError}</p>}
              <TextField id="c-name" label="Name" value={editing.name} maxLength={120} autoComplete="off" required autoFocus
                onChange={(e) => setEditing((c) => ({ ...c, name: e.target.value }))} />
              <TextField id="c-email" label="Email" type="email" value={editing.email} maxLength={254} autoComplete="off" required
                onChange={(e) => setEditing((c) => ({ ...c, email: e.target.value }))} />
              <div className="dialog-actions">
                <Button variant="ghost" type="button" onClick={() => editDialog.current?.close()}>Cancel</Button>
                <Button variant="primary" type="submit" loading={busy === 'save'}>{editing.id ? 'Save' : 'Add contact'}</Button>
              </div>
            </form>
          )}
        </dialog>

        <dialog ref={deleteDialog} className="dialog" aria-labelledby="del-title">
          <h2 id="del-title">Delete this contact?</h2>
          <p className="dialog-text">{removing ? `${removing.name} (${removing.email}) is removed from your contacts. Documents already sent to them are not affected.` : ''}</p>
          {formError && <p className="field-error" role="alert">{formError}</p>}
          <div className="dialog-actions">
            <Button variant="ghost" type="button" onClick={() => deleteDialog.current?.close()}>Cancel</Button>
            <Button variant="danger" type="button" onClick={remove} loading={busy === 'delete'}><Trash2 size={16} aria-hidden="true" />Delete</Button>
          </div>
        </dialog>
      </div>
    </AppShell>
  );
}
