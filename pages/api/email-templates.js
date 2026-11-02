import { api, fail } from '../../lib/http';
import db, { now } from '../../lib/db';
import { EMAIL_BODY_MAX, EMAIL_KINDS, EMAIL_SUBJECT_MAX, EMAIL_VARIABLES, emailTemplate } from '../../lib/mail';

const kindOf = (v) => (EMAIL_KINDS.includes(v) ? v : fail(400, 'Choose invite or completed'));

export default api({
  GET(req, res, user) {
    res.json({ invite: emailTemplate(user.id, 'invite'), completed: emailTemplate(user.id, 'completed'), variables: EMAIL_VARIABLES });
  },
  PUT(req, res, user) {
    const kind = kindOf(req.body?.kind);
    const subject = typeof req.body?.subject === 'string' ? req.body.subject.replace(/[\r\n]+/g, ' ').trim() : '';
    const body = typeof req.body?.body === 'string' ? req.body.body.replace(/\r\n?/g, '\n').trim() : '';
    if (!subject) fail(400, 'Enter a subject');
    if (subject.length > EMAIL_SUBJECT_MAX) fail(400, `Subject must be at most ${EMAIL_SUBJECT_MAX} characters`);
    if (!body) fail(400, 'Enter a message');
    if (body.length > EMAIL_BODY_MAX) fail(400, `Message must be at most ${EMAIL_BODY_MAX} characters`);
    db.prepare(`INSERT INTO email_templates (user_id, kind, subject, body, updated_at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(user_id, kind) DO UPDATE SET subject = excluded.subject, body = excluded.body, updated_at = excluded.updated_at`)
      .run(user.id, kind, subject, body, now());
    res.json({ ok: true });
  },
  DELETE(req, res, user) {
    db.prepare('DELETE FROM email_templates WHERE user_id = ? AND kind = ?').run(user.id, kindOf(req.query.kind));
    res.json({ ok: true });
  },
});
