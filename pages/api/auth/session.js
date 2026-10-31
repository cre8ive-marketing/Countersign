import { api } from '../../../lib/http';
import { getUser, signupOpen } from '../../../lib/auth';

// Public nav state for marketing pages. Never expose id or password hash.
function session(req, res) {
  const u = getUser(req);
  res.setHeader('Cache-Control', 'private, no-store');
  res.json({ user: u ? { name: u.name, email: u.email } : null, signupOpen: signupOpen() });
}

export default api({ GET: session, HEAD: session }, { auth: false });
