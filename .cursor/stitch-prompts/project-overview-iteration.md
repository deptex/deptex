# Stitch prompt: Project Overview page – current state (for further iteration)

Use this with Stitch to keep iterating on the single-project Overview screen.

---

## What we have now

**Route:** `/organizations/:orgId/projects/:projectId` (Overview tab).

**Header**
- Left: Framework icon + project name; below: branch (e.g. `main`) · Last synced {relativeTime}.
- Right: **Status badge only** (no card). Shows evaluated status name with its color, or org default compliant status (first `is_passing` by rank) with badge, or "Not evaluated".

**Extraction card** (when syncing)
- Full-width card: **left accent bar** (green/primary), then spinner in a circular primary-tinted container, title "Extraction in progress", step label (e.g. "Scanning for vulnerabilities...").
- No heavy borders; one clear accent strip.

**Required actions** (left column, half width)
- **Table** (same style as other app tables): `bg-background-card`, `rounded-lg`, `thead` with `bg-background-card-header`, `tbody` with `divide-y divide-border`, rows `hover:bg-table-hover`.
- Columns: Type (icon), Title, Description, chevron. Row click navigates to action link.
- Empty: single table row, "No required actions." (no big card).

**Recent activity** (right column, half width)
- **Table** (same style): header "Recent activity", then table with columns Event (icon in circle), Details (title + description), Time (relative).
- Row click opens slide-out detail sidebar. Loading state is table skeleton.

**Removed**
- Dependencies card (was packages count + healthy/vulnerable bar).
- Overview graph.
- Big "Everything looks good" card; status is badge-only; extraction has accent bar.

---

## Design tokens (Deptex)

- Tables: `bg-background-card`, `border-border`, `bg-background-card-header` for thead, `divide-border`, `hover:bg-table-hover`, `text-foreground-secondary` for labels, `text-xs font-semibold uppercase tracking-wider` for th.
- Primary accent: `bg-primary`, `text-primary`, `bg-primary/10`, `border-primary/20`.
- Cards: `rounded-lg border border-border bg-background-card`.

---

## Ideas for next iteration

- **Extraction card:** Add a subtle progress indicator (step N of M) or pulse animation; or keep minimal.
- **Required actions table:** Add a "Priority" or "Severity" column; or make the table responsive (stack on small screens).
- **Recent activity table:** Add "View all" link; or cap at N rows with expand.
- **Overall:** Align spacing (e.g. section titles, margins) with Project Settings or Compliance for consistency.

Use this as the baseline when asking Stitch for visual or layout tweaks.
