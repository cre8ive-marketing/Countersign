import { useRef, useState } from 'react';
import { useRouter } from 'next/router';
import Link from 'next/link';
import { ArrowLeft, Download, Copy, Check, Bell, Ban, LayoutTemplate, Trash2, CircleCheck, Clock, CircleX, Eye, Mail } from 'lucide-react';
import { withUser } from '../../../../lib/auth';
import { events, ownedDocument } from '../../../../lib/documents';
import { teamOf } from '../../../../lib/teams';
import db from '../../../../lib/db';
import { mailEnabled } from '../../../../lib/mail';
import { apiFetch, formatDate, recipientColor, RECIPIENT_STATUS } from '../../../../lib/client';
import AppShell from '../../../../components/AppShell';
import { Avatar, Button, StatusBadge } from '../../../../components/ui';
import PdfPages from '../../../../components/PdfPages';
import ShareToggle from '../../../../components/ShareToggle';
import { BulkSend } from '../../../../components/TemplateTools';

export const getServerSideProps = withUser(async (ctx, user) => {
  let doc, recipients;
  try { ({ doc, recipients } = ownedDocument(ctx.params.id, user.id, 'read')); }
  catch (e) { if (e.status === 404) return { notFound: true }; throw e; }
  const team = teamOf(user.id);
  const isOwner = doc.owner_id === user.id;
  const canWrite = isOwner || (!!doc.team_id && team?.teamId === doc.team_id && (team.role === 'owner' || team.role === 'admin'));
  // Team members who cannot edit see drafts and templates read-only here instead of in the editor.
  if (doc.status === 'draft' && canWrite) return { redirect: { destination: `/app/documents/${doc.id}/edit`, permanent: false } };
  const { public_token_hash, public_token_enc, ...docProps } = doc;
  return {
    props: {
      user,
      doc: docProps,
      canWrite,
      isOwner,
      inTeam: !!team,
      ownerName: isOwner ? null : db.prepare('SELECT name FROM users WHERE id = ?').get(doc.owner_id)?.name ?? null,
      // Signing links let anyone sign as that recipient, so only people who manage the document get them.
      recipients: recipients.map(({ token, ...r }) => (canWrite ? { ...r, token } : r)),
      events: events(doc.id).map((e) => ({ ...e })),
      mail: mailEnabled(),
      justSent: ctx.query.sent === '1',
    },
  };
});

const STATUS_ICON = { signed: CircleCheck, declined: CircleX, viewed: Eye, sent: Mail, pending: Clock };

export default function DocumentPage({ user, doc, canWrite, isOwner, inTeam, ownerName, recipients, events, mail, justSent }) {
  const router = useRouter();
  const [copied, setCopied] = useState(null);
  const [busy, setBusy] = useState(null);
  const [notice, setNotice] = useState(justSent ? (mail ? 'Sent. Recipients have been emailed.' : 'Sent. Email is not set up on this server, so copy each signing link below and share it.') : null);
  const [error, setError] = useState(null);
  const voidDialog = useRef(null);
  const [reason, setReason] = useState('');

  const origin = typeof window === 'undefined' ? '' : window.location.origin;
  const refresh = () => router.replace(router.asPath.split('?')[0]);

  async function run(key, fn, success) {
    setBusy(key);
    setError(null);
    try {
      await fn();
      if (success) setNotice(success);
      refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  }

  async function copyLink(r) {
    await navigator.clipboard.writeText(`${origin}/sign/${r.token}`);
    setCopied(r.id);
    setTimeout(() => setCopied(null), 1600);
  }

  const signers = recipients.filter((r) => r.role === 'signer');
  const cc = recipients.filter((r) => r.role === 'cc');
  const completed = doc.status === 'completed';
  const isTemplate = !!doc.is_template;
  const isDraft = doc.status === 'draft';

  return (
    <AppShell user={user} title={doc.title}>
      <div className="page page-wide">
        <Link href={isTemplate ? '/app?view=templates' : '/app'} className="back-link"><ArrowLeft size={15} aria-hidden="true" />{isTemplate ? 'Templates' : 'Documents'}</Link>
        <header className="page-head">
          <div>
            <div className="title-row"><h1>{doc.title}</h1>{isTemplate ? <span className="badge badge-neutral">Template</span> : <StatusBadge status={doc.status} />}</div>
            <p className="page-sub">
              {ownerName && `Owned by ${ownerName} · `}
              {isDraft ? 'Read only. The owner or a team admin can edit it.' : <>Sent {formatDate(doc.sent_at, true)}</>}{completed && ` · Completed ${formatDate(doc.completed_at, true)}`}
              {doc.expires_at && !completed && ` · ${doc.status === 'expired' ? 'Expired' : 'Expires'} ${formatDate(doc.expires_at, true)}`}
              {!!doc.require_otp && ' · Signers confirm an email code before signing'}
            </p>
          </div>
          <div className="head-actions">
            {completed && <Button variant="primary" href={`/api/documents/${doc.id}/file?kind=signed&download=1`}><Download size={16} aria-hidden="true" />Download signed</Button>}
            <Button href={`/api/documents/${doc.id}/file?download=1`}><Download size={16} aria-hidden="true" />Original</Button>
            {isTemplate ? (
              <>
                <BulkSend docId={doc.id} roles={recipients} mail={mail} saveFirst={async () => {}} disabled={!!busy} />
                <Button variant="primary" onClick={() => run('use', async () => {
                  const { id } = await apiFetch(`/api/documents/${doc.id}/copy`, { body: { asTemplate: false } });
                  router.push(`/app/documents/${id}/edit`);
                })} loading={busy === 'use'}><Copy size={16} aria-hidden="true" />Use template</Button>
              </>
            ) : canWrite && (
              <Button onClick={() => run('tpl', async () => {
                const { id } = await apiFetch(`/api/documents/${doc.id}/copy`, { body: { asTemplate: true } });
                router.push(`/app/documents/${id}/edit`);
              })} loading={busy === 'tpl'}><LayoutTemplate size={16} aria-hidden="true" />Save as template</Button>
            )}
            {canWrite && doc.status === 'sent' && <Button variant="danger" onClick={() => voidDialog.current.showModal()}><Ban size={16} aria-hidden="true" />Void</Button>}
            {canWrite && ['voided', 'declined', 'expired'].includes(doc.status) && (
              <Button variant="danger" loading={busy === 'del'} onClick={() => confirm('Delete this document and its audit trail?') && run('del', async () => {
                await apiFetch(`/api/documents/${doc.id}`, { method: 'DELETE' });
                router.push('/app');
              })}><Trash2 size={16} aria-hidden="true" />Delete</Button>
            )}
          </div>
        </header>

        {notice && <div className="banner banner-ok" role="status"><span>{notice}</span><button type="button" className="btn btn-ghost btn-sm" onClick={() => setNotice(null)}>Dismiss</button></div>}
        {error && <div className="banner banner-bad" role="alert">{error}</div>}

        <div className="detail">
          <div className="detail-doc">
            <PdfPages url={`/api/documents/${doc.id}/file${completed ? '?kind=signed' : ''}`} gap={16} />
          </div>

          <aside className="detail-side">
            {isOwner && inTeam && (
              <section className="card">
                <h2 className="card-title">Team</h2>
                <ShareToggle docId={doc.id} initialShared={!!doc.team_id} />
              </section>
            )}
            <section className="card">
              <h2 className="card-title">{isTemplate ? 'Roles' : 'Signers'}{doc.sequential ? <span className="card-note">In order</span> : null}</h2>
              <ol className={`route${doc.sequential ? ' is-sequential' : ''}`}>
                {signers.map((r) => {
                  const Icon = STATUS_ICON[r.status] ?? Clock;
                  const waiting = doc.status === 'sent' && (r.status === 'sent' || r.status === 'viewed');
                  return (
                    <li key={r.id} className={`route-step is-${r.status}`}>
                      <Avatar name={r.name} color={recipientColor(r.position)} />
                      <div className="route-body">
                        <div className="route-name"><strong>{r.name}</strong>{!!doc.sequential && <span className="route-order">#{r.routing_order}</span>}</div>
                        <span className="route-email">{r.email}</span>
                        {!isDraft && <span className={`route-status is-${r.status}`}>
                          <Icon size={13} strokeWidth={2} aria-hidden="true" />
                          {RECIPIENT_STATUS[r.status]}
                          {r.signed_at && ` · ${formatDate(r.signed_at, true)}`}
                        </span>}
                        {r.declined_reason && <p className="route-reason">“{r.declined_reason}”</p>}
                        {waiting && (
                          <div className="route-actions">
                            {r.token && (
                              <button type="button" className="btn btn-secondary btn-sm" onClick={() => copyLink(r)}>
                                {copied === r.id ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
                                {copied === r.id ? 'Copied' : 'Copy signing link'}
                              </button>
                            )}
                            {mail && canWrite && (
                              <button type="button" className="btn btn-secondary btn-sm" disabled={busy === r.id} onClick={() => run(r.id, () => apiFetch(`/api/documents/${doc.id}/remind`, { body: { recipientId: r.id } }), `Reminder sent to ${r.name}.`)}>
                                <Bell size={13} aria-hidden="true" />Remind
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ol>
              {cc.length > 0 && (
                <div className="cc-list">
                  <h3>Receives a copy</h3>
                  {cc.map((r) => <p key={r.id}><strong>{r.name}</strong> <span>{r.email}</span></p>)}
                </div>
              )}
            </section>

            <section className="card">
              <h2 className="card-title">Audit trail</h2>
              <ol className="timeline">
                {[...events].reverse().map((e) => (
                  <li key={e.id}>
                    <span className="timeline-dot" aria-hidden="true" />
                    <div>
                      <p><strong>{e.action}</strong>{e.detail && <span className="timeline-detail"> · {e.detail}</span>}</p>
                      <p className="timeline-meta">{e.actor} · {formatDate(e.created_at, true)}{e.ip ? ` · ${e.ip}` : ''}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </section>

            <section className="card">
              <h2 className="card-title">Details</h2>
              <dl className="meta-list">
                <dt>Document ID</dt><dd className="mono">{doc.id}</dd>
                <dt>Pages</dt><dd>{doc.page_count}</dd>
                <dt>Original SHA-256</dt><dd className="mono">{doc.original_sha256}</dd>
                {doc.signed_sha256 && <><dt>Signed SHA-256</dt><dd className="mono">{doc.signed_sha256}</dd></>}
              </dl>
            </section>
          </aside>
        </div>
      </div>

      <dialog ref={voidDialog} className="dialog" aria-labelledby="void-title">
        <form onSubmit={(e) => { e.preventDefault(); voidDialog.current.close(); run('void', () => apiFetch(`/api/documents/${doc.id}/void`, { body: { reason } }), 'Document voided. Signing links no longer work.'); }}>
          <h2 id="void-title">Void this document?</h2>
          <p className="dialog-text">Signing links stop working and nobody else can sign. This can’t be undone.</p>
          <div className="field">
            <label htmlFor="void-reason">Reason</label>
            <textarea id="void-reason" className="input" rows={3} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Recorded in the audit trail" />
          </div>
          <div className="dialog-actions">
            <Button variant="ghost" type="button" onClick={() => voidDialog.current.close()}>Cancel</Button>
            <Button variant="danger" type="submit"><Ban size={16} aria-hidden="true" />Void document</Button>
          </div>
        </form>
      </dialog>
    </AppShell>
  );
}
