# Stitch prompt: Project Watchtower tab – add commits and commit analysis

Use this prompt in Stitch to understand what we have today and get concrete suggestions for surfacing **commits** and **commit analysis** on the project-level Watchtower tab. We are not asking for implementation yet—only suggestions and options.

---

## What this screen is

**Route:** `/organizations/:orgId/projects/:projectId/watchtower` (project Watchtower tab; reachable from project sidebar).  
**Context:** User is inside a project. The Watchtower tab is one of several project tabs (Overview, Security, Dependencies, Compliance, Settings, **Watchtower**).  
**Purpose:** Supply-chain monitoring for the project’s direct dependencies: registry integrity, install scripts, entropy analysis, and **commit anomaly detection**. The tab should help users see which packages are on Watchtower, their analysis status, and—importantly—**recent or anomalous commits** across those packages.

---

## What we have today

### UI (project Watchtower tab only)

- **When extraction not ready / no repo:** Message to connect a repo or wait for extraction; no Watchtower data.
- **When Watchtower disabled:** “Enable Watchtower” CTA, short description, and four feature bullets (Registry Integrity, Install Scripts, Entropy Analysis, **Commit Anomaly Detection**). No commits shown.
- **When Watchtower enabled:**  
  - Header: “Watchtower” + “Active” badge, Docs link, Disable button.  
  - **Toolbar:** Search (filter by package name), filter pills: **All** | **Alerts** | **Blocked** | **Safe**.  
  - **Single content block:** A **packages table** only. Columns: Package (name), Version, Registry (pass/fail/warning), Scripts, Entropy, Anomaly (max score), Next version (Ready/Blocked/Quarantined/Latest). Rows can expand to show “Reanalyze” and optional extra info.  
- **No commits section, no commit list, no commit detail, no “touches imported” filter, no clear-commits action** on this tab. Commit analysis is mentioned in the disabled-state copy but not surfaced once Watchtower is on.

### Backend (already implemented)

- **Stats:** `GET /api/organizations/:orgId/projects/:projectId/watchtower/stats` → `enabled`, `total_direct`, `analyzed`, `alerts`, `blocked`, `errored`.  
- **Packages:** `GET .../watchtower/packages` → list of watched packages with status, anomaly, next version, etc.  
- **Commits (project-level, not used by frontend yet):**  
  - `GET .../watchtower/commits?limit=&offset=&sort=recent|anomaly&filter=all|high_anomaly&package=`  
  - Returns commits from **all** watched packages for this project (from `package_commits` + `package_anomalies`). Each commit can include `package_name` (which dependency it belongs to). Supports sort by recent vs anomaly, filter all vs high anomaly, optional package filter.  
- **Clear commits:** `POST .../watchtower/clear-commits` clears “reviewed” state for all watched packages of this project (org-level cleared_at).

### Reference: per-dependency Watchtower (what “commits” look like elsewhere)

We already have a **per-dependency** Watchtower view: when you open a dependency and go to its **Watchtower** sub-tab (`DependencyWatchtowerPage`), we show:

- Summary card (status, bump/decrease PRs, registry/scripts/entropy badges).  
- **Commits section:** table of commits with columns: Author, Message, +/- lines, Files, Anomaly score, Touches imported (functions).  
- Sort: **Recent** | **Anomaly**. Filter: **All** | **Touches imported**.  
- “Load more” / infinite scroll.  
- Row click opens a **CommitSidebar** with full message, anomaly breakdown, “Explain with Aegis”, “Acknowledge” (clear) single commit.  
- “Clear all commits” to mark all as reviewed.  
- API used there: package-scoped `GET /api/watchtower/:packageName/commits` (and clear single/clear all at org+project+dependency level).

So: **commit analysis and commit list UI already exist**, but only when you drill into **one dependency**. On the **project** Watchtower tab we only show the **packages table** and never show commits.

---

## What we want from Stitch

1. **Describe the gap:** The project Watchtower tab currently has no way to see commits or commit analysis; the backend already exposes project-level commits. We want to “add that back” / surface it on this tab.  
2. **Suggest concrete options** for how to add commits (and optionally commit analysis) to the **project** Watchtower tab. For example (only as inspiration):  
   - A second section or sub-tab below (or beside) the packages table: “Recent commits” or “Commit activity” that lists commits across all watched packages, with package name, author, message, anomaly, “touches imported”, and link or drill-down to the dependency’s Watchtower view or a commit sidebar.  
   - Integrating a compact “recent / high-anomaly commits” strip or widget into the current layout.  
   - Tabs on the same page: “Packages” (current table) vs “Commits” (project-level commit list with filters/sort and optional detail sidebar).  
   - Any other pattern that reuses our existing commit data and, where possible, the existing CommitSidebar or similar UX.  
3. **Call out** what would stay the same (e.g. packages table, enable/disable, stats) and what would be new (e.g. project-level commit list, filters, link to per-dependency view or commit detail).  
4. **Keep in mind:** Our design system (Tailwind, Radix/shadcn, existing tables and sidebars) and that we already have a project-level commits API and a per-dependency commit UI to reuse or mirror.

We are **not** asking for implementation in this step—only a short set of clear, actionable suggestions (with optional wireframe-style descriptions or layout notes) so we can pick a direction before building.
