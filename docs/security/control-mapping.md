# Countersign: security control mapping

Reviewer: Raymond (security). Code state reviewed: 2026-11-02, after two fix rounds (H1, M1-M4, L1-L6, then N1-N3, L7, L8). Line numbers refer to that state.

**What this is.** ISO/IEC 27001, SOC 1/SOC 2 (SSAE 18), CSA STAR, PCI DSS and APEC PRP certify or attest an *organisation's* controls. A program can't be certified against them. This document maps the controls that self-hosted **software** can provide to the clauses an operator's auditor will test, and lists what is missing. It is not a compliance claim. Countersign is not certified, attested or registered under any of these schemes.

Status key: **Met** = control implemented in code and exercised by a regression test against a disposable server (not independently audited). **Partial** = some of it exists, or it exists with a known weakness listed in the same row. **Gap** = missing. **Operator** = outside the software.

Evidence: `test/security/p0.test.mjs` and `test/security/web.test.mjs`. On 2026-11-02 they ran against a fresh server with an explicit `ENCRYPTION_KEY` and `DATA_DIR`/`SERVER_LOG` checks enabled: 35 pass, 0 fail, 1 skipped (no SMTP sink), 0 `todo`. Restart-time behaviour (migration marker, key check at boot) was checked by hand. It is described in section 0 and is not covered by an automated test.

## 0. What the controls do and don't prove

- **Encryption at rest** covers PDF files, `fields.value`, the owner's copy of signing tokens, and tombstone event lists (`lib/crypto.js:51-79`, `lib/documents.js:22-23,40-41,47`). The rest of the SQLite database is plaintext: titles, messages, names, emails, IPs, audit events and security events. Confidentiality depends on where the key lives. With no `ENCRYPTION_KEY`, the key sits in `DATA_DIR/encryption.key` (`lib/crypto.js:29-45`), so anyone with a copy of the data volume can decrypt everything.
- **File integrity.**
  - Decryption is strict: anything that isn't `CSE1` ciphertext throws (`lib/crypto.js:61-62,75-77`).
  - Every PDF read is checked against the SHA-256 recorded in the DB: owner download, signer download, stamping and template copy (`lib/documents.js:26-35`). A mismatch is a 500 plus a `file_integrity_failure` security event.
  - Legacy plaintext is encrypted only on the first open of pre-encryption data: when there is no `encryption_migrated` marker, no `key_check` and no CSE1 file (`lib/db.js:132-141`). Verified by hand: after deleting the marker and rewriting `original_sha256`, a planted plaintext file is not re-encrypted on restart (N3 closed).
  - Limit: if that very first migration is interrupted part-way, the next start sees CSE1 files and skips the legacy pass. The PDFs still in plaintext then fail closed (500) until an operator re-runs the migration by hand. Nothing is lost or laundered, but the documents are unavailable.
- **Audit chain.**
  - Each link is HMAC-SHA256 under a subkey derived with HKDF from the encryption key (`lib/crypto.js:105-118`).
  - A DB writer *without the key* can no longer forge or rewrite the chain. Verified: a full chain recomputed with plain SHA-256 is reported on the certificate as "chain broken at event N".
  - Tail truncation leaves a chain that is still internally valid. It shows up only against the `audit_head` line printed to stdout after every commit (`lib/documents.js:91-104`), and only if those lines were shipped off the host. Nothing in the product compares the DB against them.
  - The certificate prints the head as of the Signed event. The Completed event that follows records both file hashes in the chain (`lib/documents.js:352`). The Uploaded and template events now carry the original SHA-256 (verified in the DB), so the chain binds it from the start.
  - Anyone who holds the key can still rewrite the chain. When the key lives in `DATA_DIR` (no `ENCRYPTION_KEY`), a disk-level attacker has it.

## 1. ISO/IEC 27001:2022 Annex A (software-relevant controls)

| Control | Requirement (summary) | How Countersign meets it today | Status | To build |
|---|---|---|---|---|
| 5.15 Access control | Access rules enforced on every resource | Every API route is wrapped in `api()`, and a session is required unless `{auth:false}` (`lib/http.js:15-29`). Documents are checked by owner (`lib/documents.js:57-61`). Signers are limited to their own token (`pages/api/sign/[token]/file.js:6-9`). "Needs your signature" lists only the user's own documents (`pages/app/index.js:25-30`), which closes H1 (tested) | Met (per user) | Per-user only, no roles or organisations. Email addresses are still unverified, so any future cross-owner feature must not trust them |
| 5.17 Authentication information | Secure handling of secrets | scrypt with random salt and a timing-safe compare (`lib/auth.js:11-22`). Session cookies are stored only as SHA-256 (`lib/auth.js:126-132`). Signing tokens are stored as SHA-256 plus AES-GCM ciphertext, with the plaintext column nulled, and every migrated token gets an expiry (`lib/db.js:206-212`). Password policy: 12 to 256 characters, not the email (`lib/auth.js:32-37`) | Met | No common-password blocklist |
| 5.18 Access rights | Provision, review, revoke | First user plus `ALLOW_SIGNUP` (`lib/auth.js:183-186`). Sign out everywhere (`pages/api/auth/logout-all.js`) | Partial | Admin user list: disable or delete a user, revoke their sessions. Email verification |
| 5.28 / 5.33 Evidence, records | Protect records from loss and tampering | SHA-256 of the original and signed PDF, re-checked on every read (`lib/documents.js:26-35`). HMAC-keyed per-document chain with the head on the certificate. The Completed event binds both file hashes. Every new head is logged to stdout. The signed PDF is built before `completed` is committed (`lib/documents.js:313-354`). Strict PNG validation (`:271-287`). An audit tombstone is written on delete (`:453-468`) | Partial | Truncation is detectable only against off-host logs. A partly failed first migration leaves plaintext PDFs unavailable until fixed by hand. Tombstones don't record the document hashes |
| 5.34 PII protection | Minimise and protect PII; support access and erasure | Signer PII is limited to name, email, IP and UA. Field values are encrypted at rest | Partial | PII in the DB is plaintext. No export or erasure of a data subject's data. No retention setting |
| 8.2 Privileged access | Restricted admin rights | No in-app admin exists. The container runs as non-root (`Dockerfile:21`) | Partial | Admin role (see 5.18), with admin actions logged |
| 8.3 Information access restriction | Need-to-know at object level | Ownership check plus 404 on mismatch. The signer file is gated by status (`pages/api/sign/[token]/file.js:7-9`) | Met (per user) | Org scoping when organisations exist |
| 8.5 Secure authentication | Strong auth, brute-force protection, session control | Login always runs scrypt and returns one generic error (`lib/auth.js:26-29`). Locks: 5 failures per account+IP, or 50 per IP (accounts with a recent success from that IP are exempt), each for 15 minutes with a 429 and `Retry-After`. Account-wide failures add a delay instead of a lock (`lib/auth.js:39-99`). Tested: failures from an attacker IP don't stop the victim signing in from their own IP. Signup is throttled per IP (`:110-114`), and so is the current-password check (`:117-119`). Forwarded IPs are trusted only with `TRUST_PROXY=true`. 60-minute idle and 7-day absolute session timeouts (`:153-170`). Password change revokes other sessions. Signing links expire and are revoked on void or decline | Partial | No MFA. `scryptSync` still blocks the event loop (L9). N2 closed: the attempt is reserved before the delay, and a parallel burst is now held to the limit (tested) |
| 8.9 Configuration | Secure defaults, hardened config | Signups closed by default. `poweredByHeader:false` and security headers. Forwarded headers are ignored unless `TRUST_PROXY` is set. Mail refuses to send without `APP_URL`. Key check at boot (`instrumentation.js`): verified, a wrong `ENCRYPTION_KEY` makes the process exit 1 with a clear message | Partial | No HSTS header. SMTP STARTTLS is opportunistic. `TRUST_PROXY` trusts exactly one proxy hop |
| 8.10 Information deletion | Delete when no longer needed | Both PDFs and any `.tmp` are unlinked; an audit tombstone is kept (`lib/documents.js:453-468`) | Partial | No retention policy. Completed documents can never be deleted. Single global key, so crypto-erasure of one document isn't possible |
| 8.12 Data leakage prevention | Prevent unintended disclosure | `Cache-Control: private, no-store` on PDFs. Generic 500 bodies. `Referrer-Policy: same-origin`. Dead-link pages return 404/410 and drop the token from the page props | Met | — |
| 8.15 Logging | Record and protect events | Hash-chained (HMAC) document events with an `audit_head` line on stdout after each commit. Security events go to a table and to JSON on stdout (`lib/security-log.js:4-9`), including `file_integrity_failure` and `audit_chain_broken`. An unknown login identifier is logged only as a hash prefix. Verified: no passwords, cookies, tokens or the key in stdout or in the DB logs | Partial | `security_events` is neither chained nor append-only. An unknown login identifier is logged only as a keyed HMAC id (`lib/crypto.js:122`) |
| 8.16 Monitoring | Detect anomalous activity | JSON security events and audit heads on stdout, ready for a SIEM | Partial | Alerting and head comparison are the operator's job. No event for a revoked-token hit (only expired ones) |
| 8.17 Clock sync | Reliable timestamps | UTC ISO timestamps. The chain keeps event order if the clock steps back | Operator | NTP on the host. Optional RFC 3161 timestamp on signed PDFs |
| 8.24 Cryptography | Policy-based crypto and key management | AES-256-GCM with a random 96-bit IV per write and AAD binding (`file:<id>.<kind>`, `field:<id>`, `token:<recipient>`, `tombstone:<doc>`). Strict, fail-closed decryption, verified by swap, bit-flip, plaintext-file and plaintext-field tests. Atomic writes. Stored key-check value. HKDF-derived audit subkey with a public key id (`lib/crypto.js:105-121`) | Partial | No key id in the ciphertext header and no rotation. `0o600` is ignored on Windows (documented in code, operator must restrict the ACL). The key may sit beside the data |
| 8.25 / 8.28 Secure development, coding | SDLC, input validation, output encoding | Input clamps. Signature PNGs are checked for strict base64, magic number and IHDR, at most 4000 px per side and 4 MP, and must decode with pdf-lib (`lib/documents.js:271-287`). Tested with malformed, header-only and oversized images. PDF magic, parse and 25 MB limit. HTML escaping in mail. Security regression tests | Partial | CSP is Report-Only for script-src. No CI, no `npm audit`, no SBOM |
| 8.13 Backup | Recoverable copies | README covers volume backup and backing up the key separately (`README.md:99,132`) | Operator | Restore check |

## 2. SOC 2 Trust Services Criteria (2017, rev. 2022)

| Criterion | How Countersign supports it | Status | To build |
|---|---|---|---|
| CC6.1 Logical access, encryption | Hashed tokens and sessions. AES-256-GCM with strict decrypt and hash checks | Partial | Key management (rotation, off-host key) |
| CC6.2 / CC6.3 Provision, remove, least privilege | Per-user isolation. Sign out everywhere | Gap | Admin user management, deprovisioning, roles |
| CC6.6 External threats | Origin check, security headers, upload limits, account+IP and per-IP login locks, signup and password-check throttles | Partial | Enforced CSP, HSTS |
| CC6.7 Data in transit | `Secure` cookie on https | Operator / Partial | HSTS header. Option to require SMTP TLS |
| CC6.8 Malicious software | PDF parse check only | Operator | Malware scanning of uploads belongs to the operator |
| CC7.2 / CC7.3 Monitoring and anomaly evaluation | Security events and audit heads on stdout | Partial | SIEM rules and head comparison are the operator's |
| CC7.4 / CC7.5 Incident response, recovery | Sign out everywhere. Void revokes every link of a document | Partial | Admin "revoke all sessions/links" for a user. Audit export |
| CC8.1 Change management | Maintainer collaboration rules (one owner per file, review before merge). Lockfile | Partial | CI with build, tests, `npm audit` and SBOM. Release tags |
| A1.2 Availability, backup | Healthcheck (`Dockerfile:24`). WAL SQLite | Operator | Backup and restore guide including the key |
| C1.1 / C1.2 Confidentiality, disposal | Encryption of files and field values. Delete for drafts, voided and declined documents | Partial | Metadata is plaintext. Retention and disposal settings |
| PI1.x Processing integrity | State machine guards with re-checks under the write lock. Hashes re-verified on read. Signed PDF built before commit. HMAC chain | Partial | A verify endpoint for owners and a public hash check for a signed PDF |
| P-series (notice, consent, access, disclosure, quality) | Emails state who sent the document | Gap / Operator | Signer data export and erasure, retention. Privacy notice is the operator's |

## 3. CSA Cloud Controls Matrix v4 (STAR)

| Domain | Relevant controls | Status | Notes |
|---|---|---|---|
| IAM | IAM-02 policy, IAM-05 least privilege, IAM-08 access review, IAM-14 strong auth, IAM-16 privileged access | Partial | Rate limits, timeouts, hashed secrets in place. No MFA, no admin, no email verification |
| CEK | CEK-03 data encryption, CEK-10/11 key generation and management, CEK-12 key rotation, CEK-13 revocation | Partial | AES-256-GCM with a CSPRNG key and a key-check value. No rotation or key versioning |
| LOG | LOG-02 audit logging, LOG-03 security monitoring, LOG-04 log access protection, LOG-08 log records, LOG-09 log protection | Partial | Keyed chain plus stdout anchors. Protection against a key holder depends on shipping logs off-host. Security events aren't chained |
| DSP | DSP-07 data protection by design, DSP-10 sensitive data transfer, DSP-16 retention and deletion, DSP-17 sensitive data protection | Partial | No retention settings. No data-subject export or erasure |
| AIS | AIS-04 secure development, AIS-05 testing, AIS-07 vulnerability remediation | Partial | Regression tests exist. No CI, SAST or dependency audit |
| TVM | TVM-03 vulnerability remediation, TVM-07 detection | Gap | `npm audit` in CI. Pin `next` (currently `^16.4.3` in `package.json`, the lockfile pins it) |

## 4. PCI DSS v4.0 (by analogy only)

**Out of scope for cardholder data.** Countersign doesn't collect, process, store or transmit PAN or sensitive authentication data. There's no payment feature (`Permissions-Policy: payment=()`). The operator must not upload documents containing cardholder data into Countersign and treat it as part of a CDE. The analogies below are used only as a hardening yardstick.

| Req | Analogy | Status | Gap |
|---|---|---|---|
| 3 Protect stored data | Encrypt documents at rest, manage keys | Partial | Key rotation, key off-host (env or KMS) |
| 4 Encrypt in transit | TLS everywhere | Operator / Partial | HSTS. Required SMTP TLS |
| 6 Secure software | 6.2 secure coding, 6.3 vulnerability management, 6.4.1 public web app protection | Partial | CI dependency audit. Enforced CSP |
| 7 Restrict access | Need-to-know | Met (per user) | Roles |
| 8 Identify and authenticate | 8.3.4 lockout after ≤10 tries, 8.3.6 12-char passwords, 8.4 MFA, 8.2.8 15-min idle timeout | Partial | The 12-character minimum is in place. Lockout holds under parallel requests (tested). MFA is missing. The default idle timeout is 60 minutes; set `SESSION_IDLE_MINUTES=15` to match 8.2.8 |
| 10 Log and monitor | 10.2 audit events incl. invalid logins, 10.3 protect logs, 10.5 retention | Partial | Invalid logins are logged. Log protection relies on off-host shipping. Retention is the operator's |

## 5. APEC Privacy Recognition for Processors (PRP)

| Processor obligation | Software support | Status | To build |
|---|---|---|---|
| Security safeguards | See sections 1 and 2 | Partial | Open findings below |
| Accountability (act on the controller's instructions, keep records) | HMAC-chained per-document audit trail, stdout anchors, tombstones on delete, security-event log | Partial | Admin-action log. In-product verification against anchors |
| Breach notification support | Security-event log. Sign out everywhere. Void revokes links | Partial | Audit export. Admin bulk revoke |
| Sub-processors | Only optional SMTP (`lib/mail.js`). No telemetry (`NEXT_TELEMETRY_DISABLED=1`, `Dockerfile:16`). Fonts are self-hosted | Met (software) | Operator lists their SMTP provider and hosting provider |
| Return or deletion at end of service | Volume copy. Per-document delete only for non-completed documents | Gap | Export of all of an account's documents and audit (zip). Account deletion with an audit tombstone |

## 6. Findings

### Closed (re-tested 2026-11-02)

| ID | Was | Verification |
|---|---|---|
| H1 | Cross-owner signing links shown to unverified email | Regression test passes. The attacker's `/app` and `/app?view=action` contain no victim token; the owner's own pending signature is still listed |
| M1 | Plaintext passthrough and restart laundering | Tests pass: a planted plaintext file is refused for owner and signer, completion refuses to stamp it, and the document stays `sent`. Correct-key ciphertext with different content fails the hash check and logs `file_integrity_failure`. A plaintext field value fails closed. By hand: with the marker present, a restart does not launder (residual risk in N3) |
| M2 | Malformed PNG left `completed` without a signed PDF | Tests pass for malformed, non-base64, header-only, 5000 px and 9 MP images. The document stays `sent`  |
| M3 | Lockout DoS | Tests pass: the pair lock applies from the attacker's IP only, and the victim signs in from another IP  |
| M4 | Unkeyed, unanchored chain | Tests pass: links are HMAC, not plain SHA-256. A chain rewritten without the key is reported broken. The certificate shows the Signed head, and Completed binds both hashes. `audit_head` lines match the DB and expose truncation |
| L1 | Key file handling | Windows limitation documented in code. POSIX mode warning, retry on an empty key file, key-check value  |
| L2 | Migrated tokens without expiry | Migration sets an expiry on every token (`lib/db.js:212`). Checked by reading the code only |
| L3 | Completion keeps links | Accepted design, commented at `lib/documents.js:347-349` |
| L4 | Signup oracle | Per-IP signup throttle. `scryptSync` is still synchronous |
| L5 | Unthrottled current-password check | Test passes: 5 wrong attempts, then 429 even for the right password |
| L6 | Typed email logged verbatim | Test passes: a password-like identifier never appears in logs  |
| N1 | Concurrent final submissions deleted the signed PDF | Test passes: of 6 parallel final submissions exactly one wins, the document is `completed`, the signed PDF downloads, and no candidate `.tmp` files are left |
| N2 | Parallel login guesses bypassed the lock while the delay was active | Test passes: a burst of 20 from one IP is held to the per account+IP limit |
| N3 | Deleting the marker re-enabled laundering | By hand: with the marker deleted and `original_sha256` rewritten, a restart leaves the planted file in plaintext. Uploaded events carry the original SHA-256 |
| L7 | Key check ran lazily | By hand: a wrong key makes the process exit 1 at boot with the key-check message |
| L8 | Unsalted identifier hash in logs | The identifier is now a keyed HMAC (`lib/crypto.js:122`). Checked by reading the code; a test confirms the raw value never appears in the logs |

### Open

| ID | Severity | Finding | Where | Owner |
|---|---|---|---|---|
| L9 | Low | `scryptSync` blocks the event loop on every login and signup. The throttles limit the volume but not the per-request stall. Fix: async `crypto.scrypt` | `lib/auth.js:13,20` | Elon |
| L10 | Low | If the first legacy migration is interrupted part-way, the next start sees CSE1 files and skips the legacy pass. Plaintext PDFs left behind then fail closed (500) and need a manual re-run. Availability only, no laundering | `lib/db.js:132-141` | Elon (document an operator re-run, or record per-file progress) |

## 7. Prioritised build list

Sizes: S ≤ 1 day, M ≤ 1 week, L > 1 week. Owners follow the maintainer file-ownership rules. Schema changes go through Elon and need orchestrator approval first.

| P | Item | Evidence (current code) | Size | Owner |
|---|---|---|---|---|
| P1 | Owner-facing verify endpoint: recompute the chain and compare it with a supplied or logged head | `lib/documents.js:111-119` | S | Linus, Elon |
| P1 | Password blocklist (NIST 800-63B). Async scrypt (L9). Operator re-run path for an interrupted first migration (L10) | `lib/auth.js:11-37`, `lib/db.js:132-141` | S | Elon |
| P1 | Optional TOTP MFA for senders, plus recovery codes | — | M | Elon (+ Steve) |
| P1 | Enforced CSP with per-request nonces | `next.config.mjs` | M | Elon (+ Steve for `_document`) |
| P1 | HSTS header when `APP_URL` is https. `SMTP_REQUIRE_TLS` option | `next.config.mjs`, `lib/mail.js:8-13` | S | Elon |
| P1 | Audit export (CSV/JSON) per document and per account, including the security log | — | S | Elon (route), Steve (button) |
| P1 | Key rotation: key id in the header (`CSE2`), keyring env, re-encrypt job | `lib/crypto.js:6,56` | M | Elon (+ Linus for callers) |
| P1 | Admin role: list, disable and delete users, revoke sessions and links, with admin actions logged | `lib/auth.js:183-186` | M | Elon (+ Steve) |
| P1 | Email verification (prerequisite for any cross-owner feature) | `pages/api/auth/signup.js` | M | Elon (+ Steve) |
| P1 | Retention and deletion: operator retention period, purge job that keeps the tombstone, account export and deletion, signer PII erasure | `lib/documents.js:453-468` | M | Linus (lifecycle), Elon (job, schema) |
| P1 | Signer access code or email OTP option before a document opens | `pages/api/sign/[token]/*` | M | Linus (+ Steve) |
| P1 | CI: build, `npm test` against a throwaway server, `npm audit --omit=dev`, `npm sbom` | no `.github/` | S | Orchestrator, Elon for scripts |
| P2 | Organisations and RBAC | `documents.owner_id` | L | Elon, Linus, Steve |
| P2 | SSO (OIDC/SAML) | — | L | Elon |
| P2 | PAdES/X.509 seal and RFC 3161 timestamp on signed PDFs | `lib/stamp.js` | L | Linus |
| P2 | External KMS or HSM key provider | `lib/crypto.js:24-47` | M | Elon |

## 8. Operator responsibilities (software cannot cover)

Running Countersign doesn't make an organisation compliant. The operator owns the ISMS scope, policies, risk assessment and treatment, and Statement of Applicability. They also own engaging the auditor or CPA firm (SOC), the CSA STAR registry submission and the APEC PRP Accountability Agent. Beyond that: HR security (screening, training, offboarding), vendor and sub-processor management (hosting, SMTP), physical and environmental security, and BCP/DR with tested restores (database, `files/` and the encryption key, backed up separately). Also: setting `ENCRYPTION_KEY` from a secret store rather than relying on the key file (otherwise the audit HMAC key also sits beside the data), restricting the data directory's ACL on Windows hosts, setting `TRUST_PROXY` correctly behind a reverse proxy, TLS termination with HSTS, host hardening and patching, NTP, network controls and WAF, malware scanning of uploads, log retention and SIEM (including shipping the JSON security events and `audit_head` lines off-host and comparing heads, which is the only defence against truncation by a key holder), incident response and breach notification to controllers or regulators, privacy notices and lawful basis, data-subject request handling, and legal review of whether these electronic signatures are suitable for each document type and jurisdiction.
