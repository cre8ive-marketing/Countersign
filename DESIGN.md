# Design

Countersign uses **Minimalism & Swiss Style**, generated with the ui-ux-pro-max skill. The full generated system lives in [design-system/countersign/MASTER.md](design-system/countersign/MASTER.md). This file records how the code applies it. Tokens live in `styles/globals.css` under `:root`.

## Colour roles

Six brand colours only: `#0B132B` ink, `#1C2541` deep navy, `#3A506B` slate, `#5BC0DE` cyan, `#F4D6B0` sand, `#D97706` amber. White is allowed for cards and inputs; every other neutral is a `color-mix()` of a brand colour with white, or an `rgba()` of one. No red, green, blue or gray hexes. Full token table in MASTER.md.

| Role | Colour | Contrast |
|---|---|---|
| Text, headings, primary button, dark bands, logo tile | ink | 18.4:1 on white |
| Primary hover, code blocks, signature ink | navy | white on navy 15.1:1 |
| Muted text, links, icons, focus ring, control edges (62% mix) | slate | 8.3:1 on white; 62% edge 3.1:1 |
| Signing accent: Sign, Adopt and sign, Finish, main marketing CTA, progress | amber, ink text | 5.8:1; never white on amber, never amber text on white |
| On dark: logo stroke, icons, focus ring; tints: selection, sent badge, info banner | cyan | 8.8:1 on ink; never text on light |
| On dark: body text; warm tints, required fields, danger button | sand | 13.2:1 on ink; ink on sand 13.2:1 |
| Recipients (`lib/client.js`) | deep cyan, burnt amber, ink, slate, warm stone, umber (palette mixes) | each 4.5:1+ on white and under white text |

Destructive actions and errors add no new hue. Danger buttons are sand with ink text and always carry an icon and a confirm step. Errors are bold ink text on a sand tint with an amber edge. Status badges: draft slate tint, sent cyan tint, completed amber tint, declined/voided outlined; each keeps its label.

## Buttons

One `.btn` base (8px radius, 600 weight, 15px, pressed `translateY(1px)`, 0.55 opacity when disabled or busy, 2px slate focus ring; cyan on dark) with five variants and three sizes. See MASTER.md for the table.

| Variant | Look | Use |
|---|---|---|
| `primary` | ink fill, white text | Main action per screen, nav CTA |
| `accent` | amber fill, ink text | Signing and the main marketing CTA |
| `secondary` | white, slate edge, ink text | Alternatives, copy link, jump links, copy command |
| `ghost` | transparent, slate text | Cancel, Dismiss, Decline trigger, nav triggers, `.icon-btn` |
| `danger` | sand fill, ink text, icon | Void, Delete, Remove field, confirm Decline |

Sizes: `sm` 36px (40px hit area), default 40px, `lg` 48px; under 860px default is 44px and `sm` 40px. Tabs, the Type/Draw segmented control and the field palette reuse the same radius, weight, hover, pressed and focus tokens.

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

- Marketing site (`/`, `/product`, `/use-cases`, `/self-host`, `/security`): 1200px grid, statically rendered, shared chrome in `components/marketing/` (ink utility bar, sticky nav with Product / Use cases / Resources mega-menus, a drawer under 860px, rich footer). Section rules and the honest replacements for borrowed patterns are in [design-system/countersign/pages/marketing.md](design-system/countersign/pages/marketing.md). The home hero is split: copy with an inline email start on one side, a live signing demo on the other.
- App: 248px sidebar, which becomes a top bar under 860px. The content area is 1080px wide (1320px on document detail).
- Editor: 312px rail, PDF canvas, and a 288px panel that hides under 1100px. The signer view uses a single column up to 880px and works at 375px.
- Auth: an ink panel with the product's promise beside the form. The panel collapses to the form alone on smaller screens.
