export async function register() {
  // Written as a literal check so the edge bundle drops the Node-only import.
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    if (process.env.SMTP_HOST && !process.env.APP_URL) console.warn('SMTP is configured but APP_URL is not set: no emails will be sent.');
    // Open the DB now so migrations and the key check run at boot: a wrong ENCRYPTION_KEY stops the server
    // instead of leaving it up (and healthy) while every request fails.
    try {
      (await import('./lib/db')).default.prepare('SELECT 1').get();
      // Only the operator certificate: the self-signed one is generated lazily at first completion.
      if (process.env.SIGNING_P12_BASE64) (await import('./lib/pdfsign')).sealCertificate();
    } catch (e) {
      console.error(`Startup check failed: ${e.message}`);
      process.exit(1);
    }
    const documents = await import('./lib/documents');
    const { sendDueReminders } = documents;
    const { purgeExpired } = await import('./lib/auth');
    const webhooks = await import('./lib/webhooks');
    setInterval(() => webhooks.deliverDue().catch((e) => console.error('Webhook delivery failed:', e)), 60 * 1000).unref();
    setInterval(async () => {
      // Expire first so reminders never go out for a document past its expiry.
      try { await documents.expireDueDocuments?.(); } catch (e) { console.error('Expiry failed:', e); }
      sendDueReminders().catch((e) => console.error('Reminders failed:', e));
      try { purgeExpired(); } catch (e) { console.error('Session purge failed:', e); }
      try { webhooks.purgeDeliveries(); } catch (e) { console.error('Webhook delivery purge failed:', e); }
    }, 60 * 60 * 1000).unref();
  }
}
