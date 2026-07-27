---
name: frontend-design
description: The Deptex design SYSTEM — real tokens, color rules, and copy-this-file component recipes (buttons, pills, tables, dialogs, states). Read before writing ANY frontend markup; every recipe cites the canonical implementation to copy.
---

# Deptex Frontend Design System

Dark-only, Vercel-style black UI. React 18 + Tailwind 3 + Radix (shadcn pattern). The single most important rule: **never author Tailwind from instinct — open the cited canonical file and copy its class structure.** Every time a screen was built "from taste" it got rejected ("the single ugliest screen I've ever seen"). Every time it copied a shipped, refined screen it passed.

Canonical polished surfaces to crib from (in order of trust):
- Findings table: `frontend/src/components/security/VulnerabilityExpandableTable.tsx`
- Org projects table: `frontend/src/components/ProjectsAssetTable.tsx`
- Settings cards: `frontend/src/components/settings/ReachabilitySection.tsx`, `AISection.tsx`, `MaliciousAllowlistSection.tsx`
- Dialogs: `frontend/src/components/InviteMemberDialog.tsx`
- Billing: `frontend/src/components/billing/` (TopUpForm, ConsumptionBreakdownChart)

Do NOT copy from a sibling component built in the same feature arc — it is unreviewed. Copy only from shipped screens.

---

## 1. Design tokens (source: `frontend/tailwind.config.js`, `frontend/src/app/Main.css`)

### Surfaces (darkest → lightest)
| Token | Value | Use |
|---|---|---|
| `bg-background` | `#000000` | Page background |
| `bg-background-card-header` / `bg-background-table-header` | `#050505` | Table `<thead>`, card header strips, dialog footers |
| `bg-background-card` | `#0a0a0a` | Cards, tables, inputs, popovers, dropdowns |
| `bg-table-hover` | `#111111` | Row hover |
| `bg-background-subtle` | `#171717` | Raised/active elements (active segment, ghost-hover, icon boxes). Also `bg-muted` (skeleton bars) |

**Lift = lighter.** On this palette an element reads as raised because its bg is *lighter* than its track (`bg-background-subtle` on `bg-background-card`), not because of shadows. `border` = `#262626` (`input` same; `vercel.border-hover` `#404040` for hover borders; `ring` `#525252`).

### Text (three tiers — no hand-rolled opacities)
| Token | Value | Use |
|---|---|---|
| `text-foreground` | `#fafafa` | Default. ALL identity/primary data (names, repos, counts, descriptions). When unsure → white |
| `text-foreground-secondary` | `#c8c8c8` | Genuinely secondary metadata only: table headers, timestamps, captions, labels. (`text-muted-foreground` renders the same value) |
| `text-foreground-muted` | `#71717a` | Truly de-emphasized only (placeholder-ish). Never body text |

Never write `text-foreground/80`, `/65`, `/55` etc. — use the named tokens. Custom opacities are the #1 "amateur" tell.

### Accent & status colors
- **Brand accent = emerald**, spent almost exclusively on the one primary button per screen: `bg-emerald-700` + `border-emerald-500/50` (see button recipe). Visible accents (active tab underline, positive money) use `emerald-500`.
- The `primary` token (`#025230`) is a STALE near-black green — never use it for accents/underlines/text; it's invisible. Green *text* on dark surfaces uses `text-accent-text` (`#34d08a`, contrast-safe — currently landing/docs only).
- Depscore band ramp (the only coloring for finding severity): **red / orange / yellow / zinc** — see pill recipe. Not blue, not green.
- `destructive` `#EF5350`; badge-tint colors are always `color-500/10` bg + `color-500/20` border + `color-400` text.

### Type & shape
- Font: **Inter** (`font-sans`), **JetBrains Mono** (`font-mono`) for code/paths. `html { font-size: 15px }` (`Main.css:342`) — 1rem = 15px, so everything renders slightly denser than stock Tailwind.
- Radius: `--radius: 0.5rem` → `rounded-lg` (8px) for cards/tables/dialogs/buttons, `rounded-md` (6px) for inputs/selects/menu items, `rounded-full` for pills. Never `rounded-xl`/`rounded-2xl` in the app (a known rejected tell).
- Numbers in tables/pills/counters: always `tabular-nums`.
- Focus: the browser outline is globally removed (`Main.css:113-116`); intentional focus = Tailwind `ring-*` only. Scrollbars are hidden globally; opt back in with `.custom-scrollbar`.
- Global `color-scheme: dark` is set; the app has no light mode.

---

## 2. Color usage rules

1. **Color is meaning, never decoration.** A screen should be black/white/gray with color appearing only where it encodes something: depscore band, status, the one primary CTA, destructive.
2. **One green button per screen.** `variant="green"` = the screen's single primary create/commit/confirm action. Second-most-prominent → `variant="white"`. Cancel/dismiss → `variant="outline"`. Two green buttons on one screen is a bug.
3. **Gray is earned, not default.** Identity data is white. He has flipped gray→white with visible frustration multiple times. Descriptions under section titles: concise + as bright as the canon allows (settings cards use `text-xs text-foreground-secondary` for card sub-descriptions; landing/hero descriptions are full white `text-foreground`).
4. **Brand/framework icons render white at real size** (`size 20 className="text-white"`), never shrunk to gray. Don't brand-color dark-logo techs (Express/Flask = black = invisible).
5. **No raw hex in JSX.** Use tokens. Chart internals are the one exception (see Charts).
6. **No gradients on UI surfaces.** Chart area fills may use a subtle `linearGradient` — data-viz is exempt.

---

## 3. Component recipes

### Buttons — `frontend/src/components/ui/button.tsx`
Variants (lines 12-27). The modern trio is all `!h-8 !px-3 !rounded-lg`:
- `green` (line 24): `bg-emerald-700 text-white border border-emerald-500/50 hover:bg-emerald-800` — THE primary CTA.
- `white` (line 22): `bg-foreground text-background hover:bg-foreground/85` — secondary/neutral/nav (e.g. "Connect GitHub", post-success "Go to organizations").
- `outline` (line 18): cancel + retry + tertiary. When paired with the h-8 pills, size it: `className="h-8 rounded-lg px-3"`.
- `destructive` (line 16) for dangerous confirms; `ghost` for icon-ish inline actions.
- The legacy `default` variant (`bg-primary`, h-9 rounded-md) is **debt — never use it**, and never hand-roll `bg-primary` classes.

**Submitting state = spinner-only at full size** — copy `frontend/src/components/billing/TopUpForm.tsx:133-140` exactly:
```tsx
<Button variant="green" disabled={busy} className="relative">
  <span className={busy ? 'invisible' : undefined}>Add credit</span>
  {busy && (
    <span className="absolute inset-0 flex items-center justify-center">
      <Loader2 className="h-4 w-4 animate-spin" />
    </span>
  )}
</Button>
```
Never `{busy ? <Loader2/> : 'label'}` (button collapses) and never spinner+text.

### Pills & badges
Icon-less. Color carries the meaning; a Radix tooltip names it.

- **Depscore value pill** — `security/VulnerabilityExpandableTable.tsx:988-1013` (`DepscoreValue`): `inline-flex items-center justify-center px-2.5 py-1 rounded-full text-[13px] font-semibold tabular-nums border` + band class. Band ramp (shared law, three synced copies — `DepscoreValue`, `SeverityPills.tsx`, `aegis/FixIssueCard.tsx`):
  - ≥90 `bg-red-500/10 text-red-400 border-red-500/20`
  - ≥70 `bg-orange-500/10 text-orange-400 border-orange-500/20`
  - ≥40 `bg-yellow-500/10 text-yellow-400 border-yellow-500/20`
  - <40 `bg-zinc-500/10 text-zinc-400 border-zinc-500/20`
- **Severity count pills** — `components/SeverityPills.tsx` (counts only, all four bands render with zeros muted so columns align; Radix tooltip spells the band out).
- **Status pill** — `VulnerabilityExpandableTable.tsx:81-101`: `rounded-full border border-zinc-700/80 bg-background px-2.5 py-1 text-[12px] font-medium text-foreground` + a tiny status glyph (`CircleDashed` New, Linear-style half-filled `OpenGlyph` Open, `CircleSlash` Ignored). Clickable pill opens a `DropdownMenu` to change status — copy lines 409-439.
- **Small label chip** (settings style): `rounded-full border border-border bg-background-subtle px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider`.
- **shadcn `ui/badge.tsx`** for generic labeled badges — `success`/`warning`/`destructive` variants already use the tint formula.

### Tables — copy `ProjectsAssetTable.tsx:280-284` / `VulnerabilityExpandableTable.tsx:2060-2101`
- Frame: `rounded-lg border border-border bg-background-card overflow-hidden`. Tables sit on the page in this frame — never buried inside a titled generic card.
- `<table className="w-full text-sm table-fixed">` + an explicit `<colgroup>` (fixed widths for every column except the one flexible content column). **The same colgroup component must be shared by the skeleton and the loaded table** — zero layout shift.
- `<thead className="bg-background-card-header border-b border-border">`; header cells `px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider` (`text-left`/`text-center` per column).
- Body: `divide-y divide-border`; rows `hover:bg-table-hover transition-colors cursor-pointer`; cells `px-4 py-3`; long cells `truncate`.
- Set-aside/ignored rows dim in place (Aikido pattern): `opacity-55 hover:opacity-100 transition-all` on the `<tr>` — and the dim condition must be IDENTICAL to whatever renders the "Ignored" badge.
- Filter bar above the table is minimal: h-8 selects (`SelectTrigger className="h-8 w-auto min-w-[120px] text-xs gap-1.5"`, `VulnerabilityExpandableTable.tsx:2029-2056`). Only show a filter when >1 option is present in the data. Filter-icon buttons with count chips: `ProjectsAssetTable.tsx:150-207`.

### Segmented toggle (2-3 way) — copy `app/pages/IntegrationsPage.tsx:100-120`
Track `inline-flex items-center gap-1 rounded-lg border border-border bg-background-card p-1` (h-8 segments align with h-8 selects); active segment `bg-background-subtle text-foreground font-medium shadow-sm ring-1 ring-white/[0.06]`; inactive `text-foreground-secondary hover:text-foreground`. Per-segment count chips (`tabular-nums`) bake into the segment, GitHub/Linear "Open 8 / Closed 23" style.

### Dialogs — shadcn `ui/dialog.tsx`; canonical usage `InviteMemberDialog.tsx:192-196, 282`
Never hand-roll `fixed inset-0` modals. The 3-section flex shell:
```tsx
<Dialog open={open} onOpenChange={(next) => { if (!next) close(); }}>
  <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col">
    <div className="px-6 pt-6 pb-4 flex-shrink-0">          {/* header — NO border-b */}
      <DialogTitle>Invite new member</DialogTitle>
      <DialogDescription className="mt-1">…</DialogDescription>
    </div>
    <div className="px-6 py-4 grid gap-4 overflow-y-auto flex-1 min-h-0">…</div>  {/* body scrolls */}
    <DialogFooter className="px-6 py-4 flex-shrink-0 border-t border-border bg-background-card-header sm:rounded-b-lg sm:justify-between">
      <Button variant="outline" className="h-8 rounded-lg px-3">Cancel</Button>   {/* left */}
      <Button variant="green">Send invite</Button>                                 {/* right */}
    </DialogFooter>
  </DialogContent>
</Dialog>
```
- Form dialogs `sm:max-w-[520px]`; one-sentence confirms `sm:max-w-md` (reference: remove-member confirm in `MembersSection.tsx`).
- Body uses `flex-1 min-h-0` (NOT a fixed `max-h`) so the footer never clips; `sm:rounded-b-lg` on the footer is required or the bottom corners paint square.
- Mount the Dialog on a stable condition (not the per-item data object) so enter/exit animations run; don't null the item on close.
- **Optimistic close:** never `await` a slow refetch before closing — update local state, close immediately, reconcile with a background refetch.
- Titles/labels in sentence case ("Add team member", not "Add Team Member"). Field labels `text-sm font-medium text-foreground`.

### Inputs & selects — `ui/input.tsx:14`, `ui/select.tsx:20`
`h-9 rounded-md border border-border bg-background-card px-3 text-sm text-foreground shadow-sm placeholder:text-foreground-secondary` (+ ring focus). In compact filter bars, force `h-8 text-xs`. Skeleton loading goes *inside* the control (e.g. inside `SelectTrigger`), not replacing the card.

### Tooltips — `ui/tooltip.tsx`; provider already global in `main.tsx:14`
**NEVER the native `title=` attribute** ("that ugly white hover thing"). Always:
```tsx
<Tooltip><TooltipTrigger asChild><span>…</span></TooltipTrigger><TooltipContent>label</TooltipContent></Tooltip>
```
Rich tooltip content (multi-line explainer with heading): see `DepscoreColumnHeader`, `VulnerabilityExpandableTable.tsx:1015-1040`. Hoverable-term affordance: `cursor-help underline decoration-dotted underline-offset-2 decoration-foreground-secondary/40` (`AISection.tsx:206`).

### Settings / section cards — copy `settings/ReachabilitySection.tsx:224-232`
- Card: `rounded-lg border border-border bg-background-card overflow-hidden`.
- Card header inside: `px-5 py-4 border-b border-border` (or `px-4 py-3`), title `text-sm font-semibold text-foreground`, description `text-xs text-foreground-secondary mt-1`.
- Bare section heading above a card: `text-base font-semibold text-foreground` + `mt-0.5 text-xs text-foreground-secondary` (`AISection.tsx:154-157`).
- Save-bar footer, dirty-check discipline, Danger Zone recipe: match the account-settings standard (`bg-black/20 border-t` footer, save disabled until an actual change vs the loaded value; Danger Zone `border-destructive/30 bg-destructive/5` card with `bg-destructive/10` header strip, both reveal and confirm buttons `variant="destructive"`, confirm-box cancel `variant="ghost"`).

### Page header — `components/PageHeader.tsx:20-38`
`border-b border-border bg-background` band, `min-h-12`, title `text-base font-semibold`, optional `text-sm text-foreground-secondary` description, actions right-aligned. Use it; don't invent per-page title bars.

### Loading state = Vercel fade skeleton (NOT a spinner, NOT a hard block)
Canonical: `security/OrganizationVulnerabilitiesTableSkeleton.tsx` (whole file) and `ProjectsAssetTable.tsx:211-238`.
- Same card frame + same `table-fixed`/colgroup as the loaded table, 5-8 rows of `bg-muted animate-pulse` bars with varied widths.
- Wrapper gets the downward fade: `maskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)'` (+ `WebkitMaskImage`) + `pointer-events-none select-none` — the table dissolves so it reads "loading", not "stalled".
- `animate-pulse` lives on the placeholder blocks, NOT the `<tr>` — pulsing the row makes the `divide-y` borders flash.

### Empty state — `ProjectsAssetTable.tsx:266-277`
Centered, `py-12`/`py-16`: icon box `h-12 w-12 rounded-lg border border-border bg-background-subtle/50` with a lucide icon `h-6 w-6 text-foreground-secondary`, then `text-base font-medium text-foreground` heading + `text-sm text-foreground-secondary max-w-[260px]` line. Empty states KEEP their icon.

### Error state — `ProjectsAssetTable.tsx:239-248` / `SidebarErrorState` in `OrganizationOverviewPage.tsx:230-240`
```tsx
<div className="flex flex-col items-center justify-center py-12 text-center">
  <h3 className="text-base font-medium text-foreground mb-1">Couldn't load X</h3>
  <p className="text-sm text-foreground-secondary max-w-[260px] mb-4">Something went wrong fetching {context}.</p>
  <Button variant="outline" onClick={onRetry} className="h-8 rounded-lg px-3">Try again</Button>
</div>
```
NO icon, NO raw error message (errors go to console/Sentry, not the UI). Wiring: an `xError` bool + `xRefetch` counter per fetch group; the catch must set the error AND zero the data — a swallowed catch that leaves an empty list renders a lying "no data" empty state.

### Dropdown menus
`DropdownMenuContent` gets `rounded-lg border-border bg-background-card shadow-lg` (`ProjectsAssetTable.tsx:160`). Sentry-style two-line items (label + small description) where the choice needs explaining. List only options present in the data.

### Charts = Recharts (already a dep) — `billing/ConsumptionBreakdownChart.tsx`
`CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false}`; axis ticks `fill: 'rgba(255,255,255,0.55)'`, `tickLine={false} axisLine={false}`; custom tooltip in a `bg-background-card` bordered box; area fills may use a subtle linearGradient. KPI numbers go bare — `text-3xl font-bold tabular-nums text-foreground` in a grid with `divide-x divide-border` — never one-bordered-card-each.

---

## 4. Do / Don't

**Do**
- Copy class structure from a cited shipped file; verify with the browser (Henry drives it — typecheck, then tell him what to refresh).
- One `variant="green"` per screen; `white` secondary; `outline` cancel/retry.
- `table-fixed` + shared colgroup + fade-mask skeleton for every table.
- `text-foreground` for anything a user actually reads; named gray tokens for the rest.
- Radix Tooltip for every hover hint; sentence case everywhere; `tabular-nums` on numbers.
- Vary surfaces: KPI strip ≠ chart panel ≠ table. Cohesion comes from shared border/radius/padding, not identical cards.

**Don't**
- `rounded-2xl`, custom `text-foreground/NN` opacities, hand-rolled `bg-primary` buttons, `fixed inset-0` modals, native `title=` tooltips — the five classic rejected tells.
- Spinner for table loading; icon or raw error text in error states; `{busy ? <Loader2/> : 'label'}`.
- Gratuitous accent color (a green active-state was explicitly rejected); the `primary` token as an accent.
- A filter dropdown with ≤1 real option; a facet bar when a toggle + one filter is the ask.
- Bury a table in a titled card; stack identical generic cards.
- Copy a same-arc sibling component as your reference.
