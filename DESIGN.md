# Design

Countersign uses **Minimalism & Swiss Style**, generated with the ui-ux-pro-max skill. The full generated system lives in [design-system/countersign/MASTER.md](design-system/countersign/MASTER.md). This file records how the code applies it. Tokens live in `styles/globals.css` under `:root`.

## Colour roles

| Token | Value | Use |
|---|---|---|
| `--color-primary` | `#1E3A5F` trust navy | Brand, headings on marketing pages, primary buttons, active nav |
| `--color-secondary` | `#2563EB` | Links, focus rings, selection, feature icons |
| `--color-accent` | `#15803D` (from `#16A34A`, darkened so white text passes 4.5:1) | Signing and completion only: "Adopt and sign", "Finish", signed states, progress |
| `--color-background` / `--color-card` / `--color-muted` | `#F8FAFC` / `#FFF` / `#E9EEF5` | Page, surfaces, document canvas |
| `--color-foreground` / `--color-muted-foreground` | `#0F172A` / `#475569` | Text (both pass AA on white and background) |
| `--color-border` / `--color-border-soft` | `#CBD5E1` / `#E2E8F0` | Control borders, dividers and ruled grids |
| `--color-destructive`, `--color-warn` | `#DC2626`, `#B45309` | Void, decline, errors; waiting states |
| Recipient palette | `#2563EB #B45309 #0F766E #BE185D #6D28D9 #4D7C0F` | One hue per recipient (`lib/client.js`) |

## Type

- Headings: **Lexend** 600, tight tracking. Body: **Source Sans 3**, 16px base, line-height 1.5. Both are self-hosted through `next/font`.
- Mono (Geist Mono) only for commands, hashes and IDs. Mrs Saint Delafield is used only for signatures.

## Space, shape, depth

- Spacing scale: 4 / 8 / 16 / 24 / 32 / 48 / 64 / 96px (`--space-*`).
- Radius: 6px small controls, 8px controls, 12px cards and dialogs.
- Mostly borders; shadows only where something floats (demo, certificate, dialogs, status cards).

## Interaction

- Controls are at least 40px tall on desktop and 44px on screens under 860px, with 8px+ gaps.
- Visible focus ring on every control. Form errors show in a summary that takes focus, and fields stay labelled.
- Transitions take 200ms with an ease-out curve. The progress bar animates transform, not width. `prefers-reduced-motion` turns motion off.

## Layout

- Marketing site (`/`, `/product`, `/use-cases`, `/self-host`, `/security`): 1200px grid, statically rendered, shared chrome in `components/marketing/` (navy utility bar, sticky nav with Product / Use cases / Resources mega-menus, a drawer under 860px, rich footer). Section rules and the honest replacements for borrowed patterns are in [design-system/countersign/pages/marketing.md](design-system/countersign/pages/marketing.md). The home hero is split: copy with an inline email start on one side, a live signing demo on the other.
- App: 248px sidebar, which becomes a top bar under 860px. The content area is 1080px wide (1320px on document detail).
- Editor: 312px rail, PDF canvas, and a 288px panel that hides under 1100px. The signer view uses a single column up to 880px and works at 375px.
- Auth: a navy panel with the product's promise beside the form. The panel collapses to the form alone on smaller screens.
