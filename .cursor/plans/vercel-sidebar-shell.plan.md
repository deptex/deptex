# Vercel-Style Sidebar Shell — Implementation Plan

## Overview

Replace the current `OrganizationHeader` (h-12 fixed top bar) + hover-expand `OrganizationSidebar` on `/organizations/:id/*` with a Vercel-style persistent left sidebar built on the shadcn `sidebar` block. The new sidebar:

- Always renders at full width (no hover-expand collapse)
- Hosts the org switcher in its header (replacing the killed top bar)
- Drills down into the Settings sub-nav in place when the user enters `/settings*`, with a `←` back arrow and `Settings` title (Vercel image 3)
- Absorbs Feedback + Help into the existing avatar dropdown in the sidebar footer

Each org page renders a thin `<PageHeader>` slot at the top of its main content area to recover title / breadcrumb / right-side actions previously hosted by the killed top bar.

Scope is `/organizations/:id/*` only this round. `AppHeader` itself is **not** removed — the personal `/settings` page still uses it and is out of scope.

---

## Competitive Research & Design Rationale

### Vercel (target reference — provided screenshots)

- Persistent ~240px sidebar, no hover collapse
- Sidebar header: org name + plan badge + chevron switcher, then a Find search
- Main nav grouped by capability (Projects / Deployments / Logs / etc) with no group labels — visual groups via spacing
- User avatar pinned bottom-left with a `...` overflow menu (themes, log out, etc)
- **Drilldown**: clicking Settings replaces the main nav with `← back`, "Settings" title, and the Settings sub-nav. Page area stays full width. Vercel additionally renders a second column ("All Projects") for scope selection — **we are skipping this** since we have no scope split.

### Linear

- Same sidebar drilldown idea: clicking into a project swaps the sidebar to that project's sub-nav (Issues / Cycles / Projects / etc). Confirms the drilldown UX is industry-standard, not a Vercel quirk.

### Supabase

- Persistent sidebar, but uses an icon-only collapsed rail by default. Less relevant — we already had this pattern and Henry explicitly wants away from it.

### What we're adopting

| Pattern | Source | Why |
|---|---|---|
| Persistent full-width sidebar (no hover) | Vercel | User direct ask — collapse pattern feels noisy |
| In-place drilldown for Settings | Vercel + Linear | Industry-standard; keeps content full width; reuses sidebar real estate that's otherwise idle |
| Org switcher in sidebar header | Vercel | Removes the entire top bar without losing the switcher |
| `...` overflow menu in footer for Help/Feedback | Vercel | Low-traffic actions don't deserve top-of-page real estate |
| shadcn `sidebar` block | shadcn/ui | Gives `SidebarProvider`, `SidebarInset`, mobile sheet, keyboard shortcut, cookie persistence for collapsed state — all things we'd otherwise reinvent. Henry explicitly asked to use shadcn |

### Where we're differentiating

- **No second column** for Settings — Vercel uses it for project scope; we don't have that split today
- **Only Settings drills down** — Aegis/Vulns/Compliance/Flows are flat top-level pages, no meaningful sub-nav exists today
- **Adapt shadcn color tokens** — the shadcn sidebar block ships with `--sidebar`, `--sidebar-foreground`, etc. CSS vars and HSL-space tokens. Our project (`tailwind.config.js`) uses **direct hex tokens** (`background: "#000000"`, `border: "#262626"`, etc), not HSL var indirection. The sidebar component will be hand-edited to reference our existing tokens (`bg-background`, `text-foreground`, `border-border`) instead of pulling in a parallel `--sidebar-*` color system

---

## Codebase Analysis

### Existing files (read in full)

| File | Role today | Action |
|---|---|---|
| `frontend/src/app/pages/OrganizationLayout.tsx` | Sole consumer of `OrganizationSidebar` + `OrganizationHeader`. Three loading branches each render the header + sidebar separately. Main content offset with `pl-12`. | **Major rewrite** — replace header+sidebar with new `<OrgSidebar>`. Update content padding to match new sidebar width. Collapse the three loading branches now that header skeleton is gone (sidebar handles its own loading state). |
| `frontend/src/components/OrganizationSidebar.tsx` (411 lines) | Hover-expand sidebar w-12→w-48. Contains main nav (Workspace / Organization sections), avatar dropdown footer, "Create Team" modal. | **Rebuild as `OrgSidebar.tsx`** using shadcn primitives. Preserve: nav item list, permission gating logic (`view_settings`, `interact_with_aegis`, `manage_teams_and_projects`, etc.), avatar dropdown content, Create Team modal, the `organization:openCreateTeam` window event listener, the `memo` shallow-compare optimization. |
| `frontend/src/components/OrganizationHeader.tsx` (56 lines) | Thin wrapper around `AppHeader` — passes `hideRightActions` and `customLeftContent={logo + OrganizationSwitcher}`. Used only by `OrganizationLayout`. | **Delete after M2.** |
| `frontend/src/components/AppHeader.tsx` (227 lines) | General header used by `OrganizationHeader` (org pages, going away) and `SettingsPage` (personal settings, out of scope). | **Leave untouched.** Still needed by personal `/settings`. |
| `frontend/src/app/pages/OrganizationSettingsPage.tsx` (~9000 lines, 333KB) | Hosts the inline `<aside className="w-64 flex-shrink-0">` settings sub-nav at L2799. `orgSettingsSections` array defined inline at L2653-2761 with 17 sections + 3 category headers. URL is source of truth (`/settings/:section`, `VALID_SETTINGS_SECTIONS` set at L153). | **Two changes:** (1) Extract `orgSettingsSections` builder into a shared module so both the page and the new sidebar drilldown render the same list. (2) Delete the inline `<aside>` (L2798-2832) and the `flex gap-8 items-start` wrapper — content becomes single column. The loading skeleton's sidebar block (L2770-2782) also goes. |
| `frontend/src/components/AppHeader.tsx` `customRightContent` / `customLeftContent` / `hideRightActions` | Three escape-hatch props. `customRightContent` is grep-confirmed **unused on org pages** (Aegis page does not use it, no other org page uses it). `customLeftContent` + `hideRightActions` only used by `OrganizationHeader`. | After deleting `OrganizationHeader`, those props would be only-used by `SettingsPage` for the personal-settings layout. Leave the props alone — pruning them is out of scope. |

### Key observations from grep

- `grep AppHeader` → 4 hits: `OrganizationHeader.tsx`, `AppHeader.tsx` (self), `SettingsPage.tsx` (personal, out of scope), `OrganizationHeader.test.tsx`. So removing the org header is a 1-file delete.
- `grep OrganizationSidebar` → 2 hits: the component itself + `OrganizationLayout.tsx`. Single consumer.
- `grep customRightContent` on `frontend/src/app/pages/` → no Aegis usage. The "Aegis model picker" referenced in the brief is rendered **inside** `ChatPane` / chat input, not in any header.
- `OrganizationSettingsPage` already uses `useParams<{ section }>` and `VALID_SETTINGS_SECTIONS` to drive content; URL-driven from day one. The drilldown sidebar can match the URL the same way without lifting state.
- No existing tests for `OrganizationSidebar` or `OrganizationLayout`. One test for `OrganizationHeader` that mocks `AppHeader` (will be deleted with the component).

### Reusable code identified

- `OrganizationSwitcher` (full trigger variant, currently passed `triggerVariant="full"`) — drop into the new sidebar header as-is
- `FeedbackPopover` — drop into the avatar dropdown in the new sidebar footer (it already self-contains a Popover, just trigger differently)
- shadcn primitives already in `frontend/src/components/ui/`: `dropdown-menu`, `tooltip`, `dialog`, `button`, `popover`, `input` — all used by current sidebar, all reusable
- `Plan` badge logic from `PlanContext` (already provided by `OrganizationLayout`'s `<PlanProvider>`) — sidebar header can read tier display from `usePlan()`

### Integration points

| Where | What changes |
|---|---|
| `OrganizationLayout.tsx` | Wrap children in `<SidebarProvider>` from shadcn. Replace 3 nearly-identical render branches with one branch using `<OrgSidebar>` + `<SidebarInset>` (shadcn's main-content slot). Adjust loading-state markup. |
| `OrganizationSettingsPage.tsx` | Remove `<aside>` + outer `flex` wrapper. Lift `orgSettingsSections` builder into `frontend/src/lib/orgSettingsSections.ts`. |
| `frontend/src/app/pages/AegisPage.tsx`, `OrganizationOverviewPage.tsx`, `OrganizationVulnerabilitiesPage.tsx`, `CompliancePage.tsx`, `OrganizationFlowsPage.tsx`, `FlowEditorPage.tsx` | Optionally add `<PageHeader>` slot. Most don't need a title bar today — Aegis is full-bleed, Overview has its own canvas, Vulns has its own filters row. **Verify per-page** in M4 rather than assume each needs one. |

---

## Data Model

**No database changes.** Frontend-only refactor.

---

## API Design

**No API changes.** Frontend-only refactor.

---

## Frontend Design

### Pages & Routes

No route changes. URL structure stays identical:
- `/organizations/:id` (Overview)
- `/organizations/:id/aegis[/:threadId]`
- `/organizations/:id/vulnerabilities`
- `/organizations/:id/compliance[/:section]`
- `/organizations/:id/flows[/:flowId]`
- `/organizations/:id/settings[/:section]`

The drilldown is purely a **sidebar render decision** based on `useLocation().pathname`. No new routes; no router changes.

### Component tree (after)

```
OrganizationLayout
├── SidebarProvider                          (shadcn — owns expanded/mobile state via cookie)
│   ├── OrgSidebar                           (NEW — replaces OrganizationHeader + OrganizationSidebar)
│   │   ├── SidebarHeader
│   │   │   └── OrganizationSwitcher (full)  (REUSED)
│   │   ├── SidebarContent
│   │   │   ├── if pathname.includes('/settings'):
│   │   │   │   ├── back button → navigate to last non-settings org URL (default: overview)
│   │   │   │   ├── "Settings" title
│   │   │   │   └── SettingsSubNav            (NEW — reads buildOrgSettingsSections())
│   │   │   └── else:
│   │   │       └── MainNav                   (Overview, Aegis, Vulns, Compliance, Flows, Settings)
│   │   └── SidebarFooter
│   │       └── UserAvatarDropdown            (REUSED from current sidebar footer)
│   │           └── adds Feedback, Help submenu items
│   ├── SidebarInset                          (shadcn — main content slot, auto-pads for sidebar width)
│   │   └── <Outlet />                        (page-specific PageHeader + content)
│   └── modals: CreateProjectSidebar, InviteMemberDialog, Toaster   (unchanged)
```

### Design specifications

Following `.cursor/skills/frontend-design/SKILL.md`:

| Element | Token / class |
|---|---|
| Sidebar background | `bg-background` (#000000) — matches Vercel |
| Sidebar border | `border-r border-border` (#262626) |
| Sidebar width | `w-56` (224px) — close to Vercel's ~240px without overshooting |
| Active nav item | `text-foreground bg-background-card` (existing pattern from current sidebar L213) |
| Inactive nav item | `text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50` (existing) |
| Section group label (drilldown) | `text-xs font-semibold text-foreground-secondary uppercase tracking-wider px-3 pt-4 pb-2` (existing settings page L2808) |
| Back button | Ghost variant, `ChevronLeft` icon, `text-foreground-secondary hover:text-foreground` |
| Sidebar footer divider | Same `border-t border-border` pattern as current sidebar L240 |

shadcn `sidebar` block will be installed via `npx shadcn@latest add sidebar` and then **edited in-place** to:
- Strip `--sidebar-*` CSS variable references; use `bg-background`, `text-foreground`, `border-border` directly (matches our hex-token convention, no parallel color system)
- Drop the `data-variant="floating"` and `data-variant="inset"` modes — we use `sidebar` variant only
- Keep: `SidebarProvider`, `Sidebar`, `SidebarHeader`, `SidebarContent`, `SidebarFooter`, `SidebarMenu`, `SidebarMenuItem`, `SidebarMenuButton`, `SidebarGroup`, `SidebarGroupLabel`, `SidebarInset`, `useSidebar` hook, `SidebarTrigger`, mobile `Sheet` collapse

### Per-page title bars (M4)

A new `<PageHeader>` component:
```
frontend/src/components/PageHeader.tsx
- title: string
- description?: string
- actions?: React.ReactNode    // right-side toolbar
- breadcrumb?: BreadcrumbItem[]
```
Renders `h-12 border-b border-border px-6 flex items-center justify-between` to keep the visual weight that the killed top bar provided. Pages that already have their own dense header (Aegis, Overview canvas) can skip it.

Audit per-page in M4 — do not assume:
- Overview: skip (canvas is full-bleed, has its own header inside)
- Aegis: skip (chat panel has its own header)
- Vulnerabilities: add (currently has filters row that can compose with PageHeader)
- Compliance: add
- Flows / FlowEditor: add
- Settings: add — replaces the current page's H1 ("Organization Settings") with `<PageHeader title="Settings — General" />` driven by activeSection

---

## Implementation Tasks

### M1 — Install shadcn sidebar primitive (S)

- [ ] **M1.1** Run `npx shadcn@latest add sidebar` in `frontend/` (writes `components/ui/sidebar.tsx`)
- [ ] **M1.2** Edit `frontend/src/components/ui/sidebar.tsx` to remove `--sidebar-*` CSS var references and use existing tokens (`bg-background`, `text-foreground`, `border-border`). Keep the API surface identical.
- [ ] **M1.3** Confirm `useSidebar`, `SidebarProvider`, `SidebarInset`, `SidebarMenuButton` all import cleanly. No tailwind config additions needed (we hand-mapped colors).
- [ ] Files: `frontend/src/components/ui/sidebar.tsx` (new + hand-edited)

### M2 — New OrgSidebar replaces header + old sidebar (M)

- [ ] **M2.1** Create `frontend/src/components/OrgSidebar.tsx`
  - Build the main-nav rendering using shadcn `Sidebar` primitives
  - Port the existing nav-item list (`allNavItems`, `SIDEBAR_SECTIONS`) and permission gating from `OrganizationSidebar.tsx`
  - Port the avatar dropdown footer (`DropdownMenu` + user info + Account/Support/Logout) from the existing sidebar
  - Add Feedback + Help dropdown items to the avatar dropdown (between Support and Logout, before Sign out)
  - Add `OrganizationSwitcher` (variant="full") to `SidebarHeader`
  - Drilldown is **not yet implemented** — every nav click goes to the section's top-level URL
- [ ] **M2.2** Rewrite `OrganizationLayout.tsx`:
  - Wrap return in `<SidebarProvider>`
  - Replace `<OrganizationHeader>` + `<OrganizationSidebar>` with `<OrgSidebar>` + `<SidebarInset>`
  - Move `<Outlet>` into `<SidebarInset>`
  - Drop `pl-12` on `<main>` (shadcn `SidebarInset` handles offset)
  - Drop the `<div className="h-12">` spacer (no fixed top bar to clear)
  - Collapse 3 loading branches into 1 (sidebar self-renders skeleton when `organization == null`)
- [ ] **M2.3** Browser smoke: each org tab loads, switcher works, Feedback/Help dropdown items work, Plus/Create Team modal still triggers via `organization:openCreateTeam` event
- [ ] **🛑 Henry browser sign-off checkpoint** — per the visual-redesign-iteration rule, ship M1+M2 and pause for sign-off before M3-M5
- [ ] Files: `frontend/src/components/OrgSidebar.tsx` (new), `frontend/src/app/pages/OrganizationLayout.tsx` (rewrite), `frontend/src/components/FeedbackPopover.tsx` (may need a `triggerless` mode so it can render inside a `DropdownMenuItem`)

### M3 — Settings drilldown (M)

- [ ] **M3.1** Extract `orgSettingsSections` builder out of `OrganizationSettingsPage.tsx` (L2653-2761) into `frontend/src/lib/orgSettingsSections.ts`. Export:
  - `buildOrgSettingsSections(permissions: RolePermissions): SectionEntry[]` — same shape as today (mix of sections and category headers)
  - `VALID_SETTINGS_SECTIONS` — moved from L153
- [ ] **M3.2** Update `OrganizationSettingsPage.tsx` to import the extracted module (no behavior change yet)
- [ ] **M3.3** Add drilldown to `OrgSidebar.tsx`:
  - Detect `pathname.includes('/settings')` → render `<SettingsSubNav>` instead of main nav
  - `SettingsSubNav` reads `buildOrgSettingsSections(userPermissions)` and renders the same structure (categories as `SidebarGroupLabel`, items as `SidebarMenuButton`)
  - Back button: `ChevronLeft` + "Back" → navigates to `/organizations/:id/overview` (or last non-settings URL if we want to track it via `useRef` — keep simple for now, default to overview)
  - Active state matches `useParams<{section}>` against item id
- [ ] **M3.4** Delete the inline `<aside className="w-64">` block from `OrganizationSettingsPage.tsx` (L2798-2832) and the matching loading-state aside (L2770-2782). Unwrap the `flex gap-8 items-start` container. Content becomes single column with the same `max-w-7xl px-4 sm:px-6 lg:px-8 py-8` wrapper.
- [ ] Files: `frontend/src/lib/orgSettingsSections.ts` (new), `frontend/src/components/OrgSidebar.tsx` (drilldown logic), `frontend/src/app/pages/OrganizationSettingsPage.tsx` (remove inline aside, import shared sections)

### M4 — Per-page PageHeader slots (S/M)

- [ ] **M4.1** Create `frontend/src/components/PageHeader.tsx` per spec above
- [ ] **M4.2** Add `<PageHeader>` to: `OrganizationVulnerabilitiesPage`, `CompliancePage`, `OrganizationFlowsPage`, `FlowEditorPage` (skip Overview, Aegis — they're full-bleed)
- [ ] **M4.3** Settings page: add a `<PageHeader title="Settings — {sectionLabel}" />` driven by `activeSection`. Remove the existing inline H1 / heading per section if it duplicates.
- [ ] Files: `frontend/src/components/PageHeader.tsx` (new), 4-5 page files (incremental adds)

### M5 — Cleanup (S)

- [ ] **M5.1** Delete `frontend/src/components/OrganizationHeader.tsx` and its test `__tests__/OrganizationHeader.test.tsx`
- [ ] **M5.2** Delete `frontend/src/components/OrganizationSidebar.tsx` (ensure no residual imports — grep before deleting)
- [ ] **M5.3** Update `.cursor/skills/frontend-design/SKILL.md` "Project Layout" section: replace the h-12 header / w-12 hover-expand sidebar description with the new persistent w-56 sidebar pattern
- [ ] **M5.4** Save a feedback memory: "Org pages use shadcn sidebar block via `OrgSidebar.tsx`; Settings drilldown lives in the sidebar, not on the page."
- [ ] Files: 2 deletes, 1 doc update

---

## Testing & Validation Strategy

### Manual browser walk-through (M2 sign-off)

1. Navigate to `/organizations/:id` — sidebar renders, no top bar, no double scroll
2. Hover/click each main-nav item — correct route, correct active state
3. Click org switcher — opens dropdown, switching to another org navigates correctly
4. Click avatar → Feedback opens FeedbackPopover; Help opens Help submenu; Sign out works
5. Trigger Create Team modal from Plus button (existing `organization:openCreateTeam` event)
6. Resize browser to mobile width — shadcn sidebar collapses to a Sheet trigger button (no broken layout)

### Manual browser walk-through (M3 sign-off)

7. Click Settings from main nav — sidebar swaps to Settings sub-nav with back arrow + "Settings" title
8. Click each settings section in sub-nav — URL updates to `/settings/:section`, content changes, active state correct
9. Click back arrow — returns to overview, sidebar swaps back to main nav
10. Direct-load `/organizations/:id/settings/members` — sidebar opens already in drilldown state
11. Verify settings sections appear/disappear based on user role (revoke `manage_billing` → Plan section disappears from sidebar drilldown AND from any deep links)

### Regression checks

- Run `cd frontend && npm run build` — typecheck passes
- Run any existing frontend tests: `cd frontend && npm test` — `OrganizationHeader.test.tsx` will fail because the component is deleted; either delete the test (M5.1) or update it. `OrganizationTabs.test.tsx` is unrelated, should still pass.
- Open `/settings` (personal) — `AppHeader` still renders, untouched
- Open `/docs` — `DocsHeader` untouched

### What can't be auto-tested

- The drilldown animation (or absence of it) — eyeball it
- That the sidebar feels right on the org pages — Henry sign-off after M2

### Performance

- The new sidebar is plain DOM (no Reactflow / canvas). No measurable perf concern.
- shadcn sidebar uses `cookie` to persist collapsed state — one cookie write per toggle. Negligible.

---

## Risks & Open Questions

### Risks

1. **`OrganizationSettingsPage.tsx` is 333KB / 9000 lines.** Even small surgical edits (M3.4) risk merge conflicts since this file is touched often. Mitigation: do M3.4 in a tight 2-edit batch (extract sections, then remove aside) and merge fast.
2. **The shadcn sidebar block has its own opinionated styling.** When I edit it down to use our existing tokens (M1.2), I need to be careful not to break its keyboard-shortcut / mobile-Sheet logic. Mitigation: edit only color classes, leave structure / state / hooks alone.
3. **OrganizationSettingsPage internal H1s/section titles** may visually duplicate the new `<PageHeader>` (M4.3). Mitigation: do a per-section eyeball pass and remove any duplicates.
4. **`pl-12` padding on `<main>` is removed in M2.2** — if I miss a page that hardcodes `pl-12` itself or uses a `fixed` overlay positioned against the old sidebar width, layout will shift. Mitigation: grep `pl-12` and `left-0 top-12` after M2 and inspect each hit.
5. **shadcn's `--sidebar-*` HSL color tokens.** If a future shadcn block adds a sidebar-related component that depends on those vars, it'll silently render with no color. Document the deviation in M5.3 doc update.

### Open questions

- **Back button target** — should it remember the last non-settings URL (Overview vs Aegis vs Vulns), or always go back to Overview? Plan defaults to **always Overview** for simplicity. Henry can flip this in browser review if it feels wrong.
- **Settings drilldown for personal `/settings`?** — Out of scope per the brief (Henry chose "just org pages first"). Can be a follow-up if the new shell feels good.
- **Sidebar default state on mobile** — collapsed (the shadcn default). Acceptable.

---

## Dependencies

- shadcn CLI must be available (`npx shadcn@latest add sidebar`) — already used elsewhere per CLAUDE.md
- Existing components reused: `OrganizationSwitcher`, `FeedbackPopover`, `dropdown-menu`, `tooltip`, `dialog`, `button`, `popover`
- No new npm dependencies (shadcn sidebar uses primitives already in the tree)
- No backend / infra changes

---

## Success Criteria

- `/organizations/:id/*` pages render with no top bar, only the new persistent left sidebar
- Sidebar drills into Settings sub-nav when entering `/settings*` and out via the back button
- Org switcher, Feedback, Help, Sign out, Create Team all still reachable from the new sidebar
- `OrganizationSettingsPage`'s inline `<aside>` is gone — settings is single-column with the sub-nav owned by the sidebar
- `OrganizationHeader.tsx` and `OrganizationSidebar.tsx` are deleted; `AppHeader.tsx` untouched
- No regression on personal `/settings`, `/docs`, public marketing pages
- Henry browser-signs off after M2 before M3 ships
