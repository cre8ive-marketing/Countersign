# Security policy

## Supported versions

Countersign has no versioned releases yet. Security fixes land on `main`. Run the latest `main` (or rebuild your Docker image from it) to get them.

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a security problem.

Report it privately through GitHub: open the [Security tab](https://github.com/cre8ive-marketing/Countersign/security) and choose **Report a vulnerability** ([direct link](https://github.com/cre8ive-marketing/Countersign/security/advisories/new)). Only the maintainers can see the report.

Helpful details:

- what an attacker can do, and what they need first (an account, a signing link, network access)
- steps to reproduce, or a proof of concept
- the commit or image you tested, and relevant settings (`APP_URL`, `TRUST_PROXY`, SMTP, `WEBHOOK_*`)
- any logs, with secrets, keys and personal data removed

## What happens next

- We aim to acknowledge a report within 5 working days and to share a first assessment within 14 days.
- We keep you updated while we work on a fix and agree a disclosure date with you. If you want, we credit you in the advisory.
- Fixes are published as a GitHub security advisory together with the commit that fixes the issue.

This is a volunteer-run open-source project, so these are goals, not guarantees.

## Scope

In scope: the code in this repository, including the web app, API, signing flow, PDF stamping and seal, encryption at rest, the audit trail, webhooks, API keys, and the `Dockerfile` and `docker-compose.yml`.

Out of scope:

- vulnerabilities in a specific deployment that come from its own configuration (for example, no HTTPS, a leaked `ENCRYPTION_KEY`, or `WEBHOOK_ALLOW_PRIVATE=true` in production)
- findings that need an already compromised server or operator account
- missing hardening with no demonstrated impact, and reports from automated scanners alone
- denial of service through sheer request volume

Please test only against your own installation. Do not test against other people's servers or data.

## Known limits

Known gaps and accepted risks are listed in [`docs/security/control-mapping.md`](docs/security/control-mapping.md) and in the README's [Security model](README.md#security-model) section. A report about one of them is still welcome if you found a way to make the impact worse.
