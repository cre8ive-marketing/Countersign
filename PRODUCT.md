# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Next.js (Pages Router) in one Docker container. SQLite file database (`node:sqlite`) and local disk file storage under one data volume. SMTP email optional; without it, signing links are shown to the sender to copy.

## Users

Small teams and agencies who send contracts, NDAs and proposals to clients and sign internal paperwork. They run Countersign on their own server for privacy and to avoid per-seat pricing. Signers are external people who receive a link and have no account.

## Product Purpose

Open-source, self-hosted electronic signature. A sender uploads a PDF, places fields, sends it to one or more signers, and gets back a signed PDF with a completion certificate and an audit trail. Success: a document goes from upload to fully signed without the sender or signer needing help.

## Positioning

The core signing workflow of DocuSign, owned by the team that runs it: no pricing, no seats, documents never leave the team's server.

## Operating Context

- Sender: desktop browser, preparing documents between client calls.
- Signer: often on a phone, opening a link from email, signing once and leaving.
- Operator: one person with a Linux server who runs `docker run` and maybe sets SMTP.

## Capabilities and Constraints

v1 (core signing): accounts, PDF upload, drag-and-drop fields (signature, initials, date signed, name, text, checkbox), multiple signers, signing order (sequential or parallel), email links, reminders, decline with reason, void, audit trail, signed PDF flattened with a completion certificate, templates, self-sign.

Out of v1: bulk send, teams/roles, webhooks/REST API, custom branding, payments, ID verification, AI/CLM. No pricing anywhere: the product is free and open source.

Terminology: "envelope" is DocuSign's word; Countersign uses "document" for the thing sent and "recipient" for signers.

## Brand Commitments

Name: Countersign. Must look like a premium SaaS product, not AI-generated. Must not copy DocuSign's name, logo, font or brand colors.

## Evidence on Hand

None. No customers, testimonials, logos or usage numbers exist. Do not invent any.

## Product Principles

1. The signer never needs an account or instructions.
2. Self-hosting is one command; every extra service is optional.
3. Every action on a document is in the audit trail.
4. Free means free: no upsell, no locked features.

## Accessibility & Inclusion

Signing must work by keyboard and on small screens. Typed signature is always available as an alternative to drawing.
