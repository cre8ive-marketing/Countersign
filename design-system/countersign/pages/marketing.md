# Marketing pages

Overrides MASTER.md for `/`, `/product`, `/use-cases`, `/self-host` and `/security`.

The page architecture borrows the patterns of a large e-signature vendor's site (utility bar, mega-menu nav, inline email start, role tabs, tinted feature panels, dark trust band, pre-footer call to action, rich footer). Copy, brand, colours, fonts, imagery, stats and customer logos are our own or absent.

## Honest replacements

| Borrowed pattern | Countersign content |
|---|---|
| Plans & Pricing nav slot | "Self-host" link to the guide |
| Logo strip | Facts row: open source, self-hosted, your data, free |
| Stat cards in the trust band | Verifiable artefacts: SHA-256 line, an audit entry, flattened PDF, storage path |
| Customer stories carousel | Removed. No evidence exists (PRODUCT.md) |
| Resource carousel | Static "Read before you install" link list |
| Trust center | `/security`, including the known gaps, stated plainly |

## Rules

- No eyebrows above headings, no stats, no testimonials, no pricing, no compliance or legal-validity claims.
- Copy describes only v1 capabilities. When a capability changes, update `/product`, `/security` and the role flows in `components/marketing/RoleTabs.js`.
- Tinted panels use `#eef3f9` (navy tint). Dark band uses `--color-primary`; focus rings on dark use `--accent-on-ink`.
- One motion moment per page: the hero demo signature. Menus fade in at 160ms; reduced motion turns it off.
- Mega-menus are disclosure buttons (`aria-expanded`), opened by click, Enter, Space or ArrowDown, and by hover after 120ms. Escape closes and returns focus. Focus leaving the header closes them.
- Under 860px the nav becomes a drawer with `<details>` groups, 44px rows and scroll lock.
- Signed-in state comes from `GET /api/auth/session` on the client (`components/marketing/useSession.js`). The primary action reads Get started, Sign in (sign-ups closed) or Open app, in a fixed-width slot.
