export async function register() {
  // Written as a literal check so the edge bundle drops the Node-only import.
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    if (process.env.SMTP_HOST && !process.env.APP_URL) console.warn('SMTP is configured but APP_URL is not set: no emails will be sent.');
    const { sendDueReminders } = await import('./lib/documents');
    setInterval(() => sendDueReminders().catch((e) => console.error('Reminders failed:', e)), 60 * 60 * 1000).unref();
  }
}
