---
name: ui-principles
description: The craft principles behind Deptex UI — hierarchy, restraint, Sentry/Linear benchmarking, state completeness, motion, and the tab-by-tab "filter, don't redesign" working method. Read alongside frontend-design (the concrete system) before planning or reviewing any screen.
---

# Deptex UI Principles

`frontend-design/SKILL.md` is the *what* (tokens, recipes, file:line references). This is the *how to think*. The bar is explicit: Deptex screens are benchmarked side-by-side against **Sentry and Linear**, and "functional but generic" is a rejection, not a milestone.

---

## 1. Hierarchy through weight and space, never through color

- Build visual hierarchy with **size, weight, spacing, and contrast** — color is reserved for meaning (severity band, status, the one CTA, destructive). If removing every colored element from your screen would erase the hierarchy, the hierarchy was fake.
- The three text tiers (white / `#c8c8c8` secondary / `#71717a` muted) ARE the hierarchy system. Labels are small-gray-uppercase; data is white and slightly larger. Gray labels over bright data — never the reverse.
- **When unsure whether something is "secondary," it isn't.** Identity data (names, repos, counts, paths, descriptions users actually read) is white. Gray got walked back to white repeatedly, with frustration, on every table iteration.
- Numbers align (`tabular-nums`), columns lock (`table-fixed` + colgroup), rows never shift when data lands. Alignment is hierarchy too — a wobbling layout reads amateur regardless of styling.
- Lift = lighter. On the near-black palette, elevation is a *lighter background* (`#171717` on `#0a0a0a`), plus at most `shadow-sm ring-1 ring-white/[0.06]`. Heavy shadows and glows are off-palette.

## 2. Restraint

- **Spend color like it's expensive.** The house critique is that color gets "spent like it's free." One green button per screen. Pills tinted only where the tint encodes a band or status. Everything else: black, white, borders.
- **Density over decoration.** Sentry and Linear win by showing a lot of information calmly — tight paddings (`px-4 py-3` cells, h-8 controls), small type (`text-sm` body, `text-xs` labels), no ornament. Do not add illustration, emoji, gradients, or oversized empty whitespace to "warm up" a screen.
- **Icon-less by default.** Pills and badges carry meaning by color + text; tooltips do the explaining. Icons appear where they carry information (finding-type glyph, framework logo, status glyph) — not as garnish next to every label.
- Copy is concise. One sentence beats two everywhere: dialog descriptions, empty states, section blurbs. Sentence case, always.
- Monotony is also a failure: a KPI strip, a chart, and a table on one page must each look like themselves. Identical stacked `bg-background-card` boxes = "lazy design." Cohesion comes from shared border/radius/spacing, not a single card template.

## 3. Benchmarking discipline (Sentry / Linear)

- Before styling a new surface type, ask: *how does Linear (workflow/status/list surfaces) or Sentry (filter bars, dense data tables, dropdowns) render this exact thing?* Then find the closest already-shipped Deptex equivalent and copy its structure. Both references exist because our early tables looked "amateur / lame / flat" next to them.
- Concrete idioms already adopted from them: Linear's half-filled ring "Open" glyph and status-pill dropdown; the GitHub/Linear count-chips-inside-segments toggle; Sentry's two-line dropdown items (label + description); Aikido's dim-in-place ignored rows; Vercel's fade-out loading tables.
- **Reuse real app components fed real (or mock) data — never build facsimiles.** Landing pages and demos render the actual `VulnerabilityExpandableTable`, actual pills, actual cards with mock props. A hand-drawn imitation of the app is always visibly wrong.
- When comparing screenshots with Henry ("thoughts?"), give a genuine opinionated read of what falls short of the benchmark — he wants a design critique, not validation.

## 4. State completeness

A surface is not done when the happy path renders. Every data surface ships all four states, in the house patterns (recipes in frontend-design):

1. **Loading** — fade-mask skeleton that mirrors the loaded layout exactly (same frame, same colgroup). Never a centered spinner for content; never a layout that reflows when data lands. In-flight buttons: spinner-only at preserved size.
2. **Empty** — icon box + heading + one line. Distinguish "truly empty" from "filtered to empty" ("No projects yet" vs "No matches").
3. **Error** — title + context + plain outline "Try again". No icon, no raw error string. And the wiring matters as much as the markup: a catch that swallows into an empty array renders a lying empty state. Error state must be reachable and retry must actually refetch.
4. **Loaded** — including the degraded rows: dimmed/ignored items stay visible in place; partial data renders what it has.

Perceived performance is a design feature: optimistic updates (status changes, dialog submits) apply instantly and reconcile in the background; dialogs close before the refetch. Blocking a close on a slow endpoint reads as broken UI even when the code is "correct."

## 5. Motion

- Motion comes from the primitives, not from custom keyframes: Radix/shadcn enter-exit animations on dialogs, dropdowns, tooltips (`animate-in fade-in-0 zoom-in-95`), `transition-colors` on hovers, `transition-all` on row dim/undim, `animate-pulse` on skeleton bars.
- Keep it under ~200ms and purposeful — motion confirms an interaction (opened, hovered, dimmed); it never decorates. No scroll-triggered effects, no bouncing, no attention-seeking loops in the app (marquee/glow animations are landing-page-only).
- Mount dialogs on stable conditions so enter AND exit animations actually run — a popup that snaps open with no animation is a recurring regression.
- Respect `prefers-reduced-motion` for anything that loops.

## 6. Working method: polish tab-by-tab; filter, don't redesign

- **One surface at a time, fast loops.** Pick a single tab/table/panel, make one focused change, typecheck, tell Henry what to refresh — he drives the browser and reacts. Expect many small reversible tweaks and revert requests; keep every change surgical and easy to flip. Don't batch a whole-page restyle and don't over-explain the diff.
- **"Clean up / remove the garbage" = FILTER, not redesign.** When asked to clean up a UI he likes, preserve the exact visual treatment and only remove/trim content. If a redesign so much as crosses your mind, stop and either do the minimal filter or ask first. An unrequested redesign of a liked screen throws away approved work and costs a full round-trip.
- **Ground every new screen before writing code:** read both skill docs, then open a genuinely polished shipped screen (findings table, settings sections, billing) and copy its structure. Never use a same-arc sibling as the reference — it's unreviewed.
- **Scope of "done" includes the sweep:** while polishing a section, delete dead code, stale states, and debt you touch (the account-settings standard: styling + tests covering gating/dirty-state + dead-code removal, all before "done").
- Consistency beats novelty: if a pattern exists (status pill, segmented toggle, error card), a new surface uses it byte-equivalently. Divergence needs a reason; three synced copies of the depscore ramp stay synced.
- Verify against the user's actual bar before declaring done: minimal diff, typecheck green, and the screen visually matches its canonical siblings in the browser.
