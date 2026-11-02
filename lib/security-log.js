import db, { now } from './db.js';

// Security events: one DB row plus one JSON line on stdout for SIEM shipping. Never pass passwords or tokens.
export function logSecurity(type, { userId = null, email = null, ip = null, userAgent = null, detail = '' } = {}) {
  const event = { at: now(), type, user_id: userId, email, ip, user_agent: userAgent, detail: String(detail) };
  db.prepare('INSERT INTO security_events (at, type, user_id, email, ip, user_agent, detail) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(event.at, type, userId, email, ip, userAgent, event.detail);
  console.log(JSON.stringify({ security_event: event }));
}
