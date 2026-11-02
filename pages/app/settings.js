import { useRef, useState } from 'react';
import { useRouter } from 'next/router';
import { withUser, signupOpen } from '../../lib/auth';
import { mailEnabled } from '../../lib/mail';
import { apiFetch } from '../../lib/client';
import AppShell from '../../components/AppShell';
import { LogOut } from 'lucide-react';
import { Button, TextField } from '../../components/ui';

export const getServerSideProps = withUser(async (ctx, user) => ({
  props: { user, server: { mail: mailEnabled(), signup: signupOpen(), appUrl: process.env.APP_URL || null } },
}));

export default function Settings({ user, server }) {
  const router = useRouter();
  const [name, setName] = useState(user.name);
  const [currentPassword, setCurrent] = useState('');
  const [newPassword, setNew] = useState('');
  const [state, setState] = useState({});
  const [outError, setOutError] = useState(null);
  const [outBusy, setOutBusy] = useState(false);
  const outDialog = useRef(null);

  async function signOutEverywhere() {
    setOutBusy(true);
    setOutError(null);
    try {
      await apiFetch('/api/auth/logout-all');
      window.location.assign('/login'); // full load so no signed-in state lingers in memory
    } catch (e) {
      setOutError(e.message);
      setOutBusy(false);
    }
  }

  async function save(key, body) {
    setState({ [key]: 'busy' });
    try {
      await apiFetch('/api/account', { method: 'PATCH', body });
      setState({ [key]: 'done' });
      if (key === 'password') { setCurrent(''); setNew(''); }
      router.replace(router.asPath);
    } catch (e) {
      setState({ [key]: e.message });
    }
  }

  const msg = (key) => state[key] && state[key] !== 'busy' && (
    <p className={state[key] === 'done' ? 'form-ok' : 'field-error'} role="status">{state[key] === 'done' ? 'Saved.' : state[key]}</p>
  );

  return (
    <AppShell user={user} title="Settings">
      <div className="page page-narrow">
        <header className="page-head"><div><h1>Settings</h1></div></header>

        <form className="card form-card" onSubmit={(e) => { e.preventDefault(); save('profile', { name }); }}>
          <div className="form-card-head"><h2>Profile</h2><p>Your name appears on emails and in the audit trail.</p></div>
          <TextField id="name" label="Name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={120} />
          <TextField id="email" label="Email" value={user.email} disabled hint="Used to sign in." />
          <div className="form-card-foot">{msg('profile')}<Button variant="primary" type="submit" loading={state.profile === 'busy'}>Save</Button></div>
        </form>

        <form className="card form-card" onSubmit={(e) => { e.preventDefault(); save('password', { currentPassword, newPassword }); }}>
          <div className="form-card-head"><h2>Password</h2><p>Changing it signs you out on your other devices.</p></div>
          <TextField id="cur" type="password" label="Current password" autoComplete="current-password" value={currentPassword} onChange={(e) => setCurrent(e.target.value)} required />
          <TextField id="new" type="password" label="New password" autoComplete="new-password" minLength={12} maxLength={256} value={newPassword} onChange={(e) => setNew(e.target.value)} required hint="At least 12 characters." />
          <div className="form-card-foot">{msg('password')}<Button variant="primary" type="submit" loading={state.password === 'busy'}>Change password</Button></div>
        </form>

        <section className="card form-card">
          <div className="form-card-head"><h2>Sessions</h2><p>Lost a device or signed in on a shared computer? Sign out everywhere, including this browser.</p></div>
          <div className="form-card-foot">
            <Button variant="secondary" type="button" onClick={() => { setOutError(null); outDialog.current?.showModal(); }}><LogOut size={16} aria-hidden="true" />Sign out of all devices</Button>
          </div>
        </section>

        <dialog ref={outDialog} className="dialog" aria-labelledby="out-title">
          <h2 id="out-title">Sign out of all devices?</h2>
          <p className="dialog-text">Every browser signed in to this account, including this one, will need to sign in again.</p>
          {outError && <p className="field-error" role="alert">{outError}</p>}
          <div className="dialog-actions">
            <Button variant="ghost" type="button" onClick={() => outDialog.current?.close()}>Cancel</Button>
            <Button variant="danger" type="button" onClick={signOutEverywhere} loading={outBusy}><LogOut size={16} aria-hidden="true" />Sign out everywhere</Button>
          </div>
        </dialog>

        <section className="card form-card">
          <div className="form-card-head"><h2>Server</h2><p>Set with environment variables. See the self-hosting guide.</p></div>
          <dl className="meta-list meta-list-row">
            <dt>Email delivery</dt>
            <dd>{server.mail ? 'SMTP configured' : 'Off. Signing links are shown for you to copy.'}</dd>
            <dt>Public URL</dt>
            <dd className="mono">{server.appUrl || 'Not set (APP_URL). Needed for reminder emails.'}</dd>
            <dt>New sign-ups</dt>
            <dd>{server.signup ? 'Open' : 'Closed. Set ALLOW_SIGNUP=true to open.'}</dd>
          </dl>
        </section>
      </div>
    </AppShell>
  );
}
