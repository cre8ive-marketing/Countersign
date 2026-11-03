import { useEffect, useRef, useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import { FileSignature, Link2Off, Lock, MailCheck } from 'lucide-react';
import { publicTemplateByToken } from '../../lib/documents';
import { apiFetch } from '../../lib/client';
import { Button, Logo, TextField } from '../../components/ui';

export async function getServerSideProps({ params, res }) {
  const tpl = publicTemplateByToken(String(params.token));
  if (!tpl) {
    res.statusCode = 404;
    return { props: { token: null, tpl: null } };
  }
  return { props: { token: params.token, tpl: { title: tpl.title, ownerName: tpl.ownerName, requireOtp: !!tpl.requireOtp, pageCount: tpl.pageCount } } };
}

export default function PublicTemplate({ token, tpl }) {
  return (
    <div className="signer">
      <Head><title>{`${tpl?.title ?? 'Link not active'} · Countersign`}</title><meta name="robots" content="noindex" /></Head>
      <div className="status-page">
        {tpl ? <StartForm token={token} tpl={tpl} /> : (
          <div className="status-card">
            <Logo href={null} />
            <span className="status-icon tone-neutral"><Link2Off size={22} strokeWidth={1.75} aria-hidden="true" /></span>
            <h1>This link is not active</h1>
            <p>The sender may have turned it off or replaced it with a new link. Ask them for the current one.</p>
            <p className="status-foot"><Lock size={12} aria-hidden="true" />A self-hosted Countersign server</p>
          </div>
        )}
      </div>
    </div>
  );
}

function StartForm({ token, tpl }) {
  const router = useRouter();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [website, setWebsite] = useState(''); // honeypot: people never see or fill it
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const errorRef = useRef(null);
  useEffect(() => { if (error) errorRef.current?.focus(); }, [error]);

  async function submit(e) {
    e.preventDefault();
    if (!name.trim() || !email.trim()) return setError('Enter your name and email.');
    setBusy(true);
    setError(null);
    try {
      const { signUrl } = await apiFetch(`/api/public-templates/${encodeURIComponent(token)}`, { body: { name: name.trim(), email: email.trim(), website } });
      if (signUrl) return router.push(signUrl);
      setBusy(false);
    } catch (err) {
      setError(err.status === 429 && err.retryAfter
        ? `Too many requests. Try again in ${Math.ceil(err.retryAfter / 60)} minute${err.retryAfter > 60 ? 's' : ''}.`
        : err.message);
      setBusy(false);
    }
  }

  return (
    <div className="status-card public-card">
      <Logo href={null} />
      <span className="status-icon tone-warn"><FileSignature size={22} strokeWidth={1.75} aria-hidden="true" /></span>
      <h1>{tpl.title}</h1>
      <p>{tpl.ownerName} shared this document for signing. Enter your details to open your own copy{tpl.pageCount ? ` (${tpl.pageCount} page${tpl.pageCount === 1 ? '' : 's'})` : ''}.</p>
      {error && <p className="otp-error" role="alert" tabIndex={-1} ref={errorRef}>{error}</p>}
      <form className="public-form" onSubmit={submit} noValidate>
        <TextField id="pt-name" label="Full name" value={name} onChange={(e) => setName(e.target.value)} maxLength={200} autoComplete="name" required />
        <TextField id="pt-email" label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} maxLength={254} autoComplete="email" required
          hint={tpl.requireOtp ? 'We email a 6-digit code to this address before you can open the document.' : undefined} />
        <div className="hp" aria-hidden="true">
          <label htmlFor="pt-website">Website</label>
          <input id="pt-website" name="website" tabIndex={-1} autoComplete="off" value={website} onChange={(e) => setWebsite(e.target.value)} />
        </div>
        <Button variant="accent" type="submit" loading={busy}>Continue to sign</Button>
      </form>
      <p className="public-note">Your name and email are recorded with the document as you enter them.</p>
      <p className="status-foot"><Lock size={12} aria-hidden="true" />Shared by {tpl.ownerName} from a self-hosted Countersign server</p>
    </div>
  );
}
