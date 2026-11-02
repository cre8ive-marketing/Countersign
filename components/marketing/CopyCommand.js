import { useState } from 'react';
import { Check, Copy } from 'lucide-react';

export default function CopyCommand({ command }) {
  const [copied, setCopied] = useState(false);
  return (
    <button type="button" className="btn btn-secondary btn-lg cmd" onClick={() => { navigator.clipboard?.writeText(command); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>
      <span className="cmd-prompt" aria-hidden="true">$</span>
      <code>{command}</code>
      <span className="cmd-icon" aria-hidden="true">{copied ? <Check size={16} /> : <Copy size={16} />}</span>
      <span className="sr-only" aria-live="polite">{copied ? 'Copied' : 'Copy command'}</span>
    </button>
  );
}

// Shown on the home page and in the self-host guide.
export const COMPOSE = `services:
  countersign:
    build: .
    ports: ["3000:3000"]
    volumes: ["countersign-data:/data"]
    environment:
      APP_URL: https://sign.example.com
      # Your AES-256 key (openssl rand -hex 32). Back it up separately.
      ENCRYPTION_KEY: \${ENCRYPTION_KEY}
      # Optional: email links and reminders
      SMTP_HOST: smtp.example.com
      SMTP_USER: sign@example.com
      SMTP_PASS: \${SMTP_PASS}
    restart: unless-stopped

volumes:
  countersign-data:`;
