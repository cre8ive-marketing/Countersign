# Design System Master File

> **LOGIC:** When building a specific page, first check `design-system/pages/[page-name].md`.
> If that file exists, its rules **override** this Master file.
> If not, strictly follow the rules below.

---

**Project:** Countersign
**Generated:** 2026-10-31 12:20:36
**Category:** E-signature / Document Workflow
**Design Dials:** Variance 5/10 (Balanced / Modern) | Motion 4/10 (Standard) | Density 6/10 (Standard)

---

## Global Rules

### Color Palette

Six brand colours are the only chromatic colours allowed anywhere in the UI. White (`#fff`) is allowed for cards and inputs. Every other neutral is mixed from the six with white or transparency (`color-mix()` or `rgba()` of a brand colour). Do not add a red, green, blue or gray hex.

| Brand colour | Hex | CSS variable | Role |
|---|---|---|---|
| Ink | `#0B132B` | `--brand-ink` | Body text, headings, primary button fill, dark bands, logo tile |
| Deep navy | `#1C2541` | `--brand-navy` | Primary hover and pressed, code blocks, signature ink, secondary dark surfaces |
| Slate | `#3A506B` | `--brand-slate` | Muted text, links, icons, strong borders, focus ring on light surfaces |
| Cyan | `#5BC0DE` | `--brand-cyan` | Only on dark surfaces (logo stroke, icons, focus ring) or as a tint (selection, "sent" badge, info banner). Never as text on light backgrounds (about 2:1) |
| Sand | `#F4D6B0` | `--brand-sand` | Text on dark surfaces, warm tints, required-field fill, the danger button |
| Amber | `#D97706` | `--brand-amber` | The signing accent: Sign, Adopt and sign, Finish, main marketing CTA, signed states, progress. Always ink text on amber, never white. Never amber text on white |

| Semantic token | Value | Use |
|---|---|---|
| `--color-primary` / `-hover` | ink / navy | Primary buttons, active nav, switches |
| `--color-secondary` | slate | Links and icons |
| `--color-accent` / `-hover` | amber / amber 80% + sand | Accent buttons, progress, signed connectors |
| `--color-accent-ink` | amber 70% + ink | Amber icons on tinted fills |
| `--color-accent-soft` | amber 16% + white | Completed badge, "needs your signature" icon tile |
| `--color-info-soft` | cyan 20% + white | Sent badge, info banners |
| `--color-sand-soft` / `--color-destructive-soft` | sand 45% + white | Error boxes, declined/voided status icon |
| `--color-background` | slate 4% + white | Page |
| `--color-muted` | slate 10% + white | Hover fills, canvas, draft badge |
| `--color-subtle` | slate 85% + white | Placeholders, captions |
| `--color-border-strong` | slate 62% + white | Control edges (inputs, secondary buttons) |
| `--color-border` / `-soft` | slate 28% / 15% + white | Rules and dividers |
| `--color-destructive` / `-edge` | ink / amber | Error text (bold ink) and the edge of invalid inputs and error boxes |
| `--color-ring` | slate | Focus outline (2px, 2px offset) on light; cyan on dark |
| Shadows | `rgba(11, 19, 43, α)` | Ink-tinted depth only |
| Recipients (`lib/client.js`) | deep cyan, burnt amber, ink, slate, warm stone, umber | Mixed from the palette, each 4.5:1+ on white and under white text |

**Status without red or green:** draft is a slate tint, sent is a cyan tint, completed is an amber tint with an amber dot, and declined or voided is an outlined white pill. Every badge keeps its text label. Errors use bold ink text, a sand fill and an amber edge.

**Color Notes:** Ink and slate for trust, amber for the act of signing, cyan and sand only as light on dark or as tints.

### Typography

- **Heading Font:** Lexend
- **Body Font:** Source Sans 3
- **Mood:** corporate, trustworthy, accessible, readable, professional, clean
- **Google Fonts:** [Lexend + Source Sans 3](https://fonts.googleapis.com/css2?family=Lexend:wght@300;400;500;600;700&family=Source+Sans+3:wght@300;400;500;600;700&display=swap)

**CSS Import:**
```css
@import url('https://fonts.googleapis.com/css2?family=Lexend:wght@300;400;500;600;700&family=Source+Sans+3:wght@300;400;500;600;700&display=swap');
```

### Spacing Variables

*Density: 6/10 — Standard*

| Token | Value | Usage |
|-------|-------|-------|
| `--space-xs` | `4px` / `0.25rem` | Tight gaps |
| `--space-sm` | `8px` / `0.5rem` | Icon gaps, inline spacing |
| `--space-md` | `16px` / `1rem` | Standard padding |
| `--space-lg` | `24px` / `1.5rem` | Section padding |
| `--space-xl` | `32px` / `2rem` | Large gaps |
| `--space-2xl` | `48px` / `3rem` | Section margins |
| `--space-3xl` | `64px` / `4rem` | Hero padding |

### Shadow Depths

| Level | Value | Usage |
|-------|-------|-------|
| `--shadow-sm` | `0 1px 2px rgba(11,19,43,0.06)` | Subtle lift (primary and accent buttons) |
| `--shadow-md` | `0 4px 6px -1px rgba(11,19,43,0.08)` | PDF pages, menus |
| `--shadow-lg` | `0 10px 15px -3px rgba(11,19,43,0.1)` | Certificate, status cards |
| `--shadow-xl` | `0 20px 25px -5px rgba(11,19,43,0.12)` | Demo, dialogs, mega-menus |

---

## Component Specs

### Buttons

One system for every button-like control. Base `.btn`: 8px radius, Source Sans 3 600, 15px, 1px border, 200ms colour transitions, `translateY(1px)` when pressed, 0.55 opacity and `not-allowed` when disabled or busy, and the global focus ring (2px slate outline, 2px offset; cyan on dark surfaces).

| Variant | Class | Fill / text / border | Hover | Use |
|---|---|---|---|---|
| Primary | `.btn-primary` | ink / white (18.4:1) | navy (15.1:1) | Main action on a screen: Send, Save, Download, nav CTA |
| Accent | `.btn-accent` | amber / ink (5.8:1) | amber 80% + sand (6.8:1) | Signing only: Sign, Adopt and sign, Finish, main marketing CTA |
| Secondary | `.btn-secondary` | white / ink / slate 62% edge (3.1:1) | page tint, slate edge | Alternatives: Original, Save as template, Copy signing link, Use, jump links, copy command |
| Ghost | `.btn-ghost` | transparent / slate (8.3:1) | slate 10% tint, ink text | Low emphasis: Cancel, Dismiss, Decline trigger, Clear, Sign in, nav menu triggers |
| Danger | `.btn-danger` | sand / ink (13.2:1) / amber-sand edge | sand 75% + amber (10.8:1) | Destructive: Void, Delete, Remove field, confirm Decline. Always with an icon (Ban, Trash) and a confirm step |

| Size | Class | Height desktop / under 860px | Padding, font |
|---|---|---|---|
| Small | `.btn-sm` | 36px (40px hit area via `::after`) / 40px | 12px, 14px |
| Default | none | 40px / 44px | 16px, 15px |
| Large | `.btn-lg` | 48px / 48px | 22px, 16px |

- Icon-only: `.icon-btn` is a ghost button at 40px (44px under 860px); `.icon-btn-sm` is 36px with a 40px hit area. Both need an `aria-label`.
- `Button` in `components/ui.js` renders all of these (`variant`, `size`, `loading`, `href`).
- Controls that cannot be a `.btn` reuse the same tokens: app tabs and `.mk-tablist` (ghost hover, ink underline), `.segmented` (40px segments, 8px radius, white active segment), `.palette-item` (secondary edge, 40px, pressed state, recipient-colour active ring).
- Signing fields on the PDF (`.sfield`, `.efield`) are sized by the document, not by the button scale: required is a sand fill with an amber edge and ink "SIGN" text, filled is a slate tint.

### Cards

```css
.card {
  background: #fff;
  border: 1px solid var(--color-border-soft);
  border-radius: 12px;
  padding: 24px;
}
```

### Inputs

```css
.input {
  min-height: 42px;
  padding: 0 12px;
  border: 1px solid var(--color-border-strong); /* slate 62%, 3.1:1 on white */
  border-radius: 8px;
  font-size: 16px;
}
.input:focus {
  border-color: var(--color-ring);              /* slate */
  box-shadow: 0 0 0 3px rgba(91, 192, 222, 0.35);
}
.input[aria-invalid] { border-color: var(--brand-amber); }
```

### Modals

Native `<dialog>` with `.dialog`: white, 12px radius, 32px padding, `--shadow-xl`, backdrop `rgba(11, 19, 43, 0.5)`. Actions sit right-aligned: ghost Cancel, then the primary or danger action.

---

## Style Guidelines

**Style:** Minimalism & Swiss Style

**Keywords:** Clean, simple, spacious, functional, white space, high contrast, geometric, sans-serif, grid-based, essential

**Best For:** Enterprise apps, dashboards, documentation sites, SaaS platforms, professional tools

**Key Effects:** Subtle hover (200-250ms), smooth transitions, sharp shadows if any, clear type hierarchy, fast loading

### Page Pattern

**Pattern Name:** Enterprise Gateway

- **Conversion Strategy:** Path selection (I am a...). Mega menu navigation. Trust signals prominent. Provide pause/stop for video and rotating logos; stop on focus and reduced motion. Logo carousel controls must be keyboard operable; pause moving media offscreen/hidden and render a static final state under reduced motion.
- **CTA Placement:** Contact Sales (Primary) + Login (Secondary)
- **Section Order:** Hero (Video/Mission) > Solutions by Industry > Solutions by Role > Client Logos > Contact Sales

---

## Motion

**Stagger List** (Standard) — Trigger: load or scroll | Duration: 300-450ms | Easing: `back.out(1.4)`

```js
gsap.from('.grid-item', { opacity: 0, scale: 0.92, y: 16, duration: 0.4, stagger: { each: 0.06, from: 'start', grid: 'auto' }, ease: 'back.out(1.4)' });
```

**Framework notes:** grid: 'auto' lets GSAP infer rows/columns from a CSS grid layout for a natural wave stagger; Use matchMedia('(prefers-reduced-motion: reduce)') to skip non-essential motion and render the final state immediately

- ✅ Combine with from: 'center' for a bento-grid layout to draw the eye inward first
- ❌ Don't use back.out on dense data tables; the overshoot reads as sloppy on informational UI
- ⚡ Group DOM writes; avoid interleaving layout reads (getBoundingClientRect) between staggered tweens

---

## Anti-Patterns (Do NOT Use)

- ❌ Confusing signing flow
- ❌ weak audit trail
- ❌ hidden consent

### Additional Forbidden Patterns

- ❌ **Emojis as icons** — Use SVG icons (Heroicons, Lucide, Simple Icons)
- ❌ **Missing cursor:pointer** — All clickable elements must have cursor:pointer
- ❌ **Layout-shifting hovers** — Avoid scale transforms that shift layout
- ❌ **Low contrast text** — Maintain 4.5:1 minimum contrast ratio
- ❌ **Instant state changes** — Always use transitions (150-300ms)
- ❌ **Invisible focus states** — Focus states must be visible for a11y

---

## Pre-Delivery Checklist

Before delivering any UI code, verify:

- [ ] No emojis used as icons (use SVG instead)
- [ ] All icons from consistent icon set (Heroicons/Lucide)
- [ ] `cursor-pointer` on all clickable elements
- [ ] Hover states with smooth transitions (150-300ms)
- [ ] Light mode: text contrast 4.5:1 minimum
- [ ] Focus states visible for keyboard navigation
- [ ] `prefers-reduced-motion` respected
- [ ] Responsive: 375px, 768px, 1024px, 1440px
- [ ] No content hidden behind fixed navbars
- [ ] No horizontal scroll on mobile
