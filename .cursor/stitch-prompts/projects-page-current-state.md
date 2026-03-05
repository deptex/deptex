# Stitch prompt: Deptex Organization Projects page – current state

Use this prompt in Stitch (or any design iteration tool) to understand exactly what the Projects screen is today so we can iterate on layout, hierarchy, and polish.

---

## What this screen is

**Route:** `/organizations/:id/projects`  
**Context:** Inside an organization; user has already selected an org. The page is the main “Projects” tab in the org sidebar (alongside Overview, Teams, Security, etc.).  
**Purpose:** List all projects in the organization, filter/search, switch between grid and list view, create new projects, and open a project (navigates to project overview).

---

## Layout and chrome

- **Container:** `<main className="mx-auto max-w-7xl px-4 sm:px-6 lg:8 py-8">` — centered, max width 7xl, responsive padding.
- **No page title or description** — the content starts with the toolbar.
- **Toolbar (single row):**
  - **Left:** Search input, 320px wide (`w-80`). Placeholder: “Filter…”. Search icon left inside. When there’s text, a small “Esc” button on the right to clear.
  - **Right:** View toggle (Grid / List) as two icon buttons in a bordered group, then “Create Project” primary button (only if user has `manage_teams_and_projects`).
- **Content below:** Either a grid of project cards, a table (list view), loading skeletons, or empty state.

---

## Data shown per project

From the API, each project has (among others):

- **name** — project name
- **framework** — e.g. `react`, `nextjs`, `vue`, `python` — used for a small framework icon (Next, React, Vue, etc.)
- **repo_status** — `initializing` | `extracting` | `analyzing` | `finalizing` | `ready` | `error` (and other repo lifecycle states)
- **extraction_step** — when syncing: `queued`, `cloning`, `sbom`, `deps_synced`, `ast_parsing`, `scanning`, `uploading`, `completed`
- **status_name** — custom org status label (e.g. “Compliant”, “Under Review”) — from policy engine
- **status_color** — hex for custom status badge
- **is_compliant** — legacy boolean when no custom status
- **alerts_count** — number of alerts
- **health_score** — number (0–100)
- **created_at** — ISO date, displayed as “DD Mon YY” (e.g. “01 Dec 25”)
- **extraction_error** — shown in tooltip when status is “Failed”
- **team_ids** / **team_names** — used for search and display

---

## Grid view (default)

- **Layout:** CSS grid, 1 col on mobile, 2 on `md`, 3 on `lg`. Gap 4. Cards are clickable (navigate to project).
- **Card structure:**
  - **Row 1:** Framework icon (24px) + project name (truncate) + status badge + chevron right (on hover).
  - **Row 2:** Bell icon + “X alerts” (e.g. “0 alerts”, “1 alert”).
- **Status badge logic:**
  - In progress (initializing/extracting/analyzing/finalizing): “Creating” + spinner.
  - Error: “Failed” (red), tooltip = extraction_error or “Extraction failed”.
  - Custom status: badge with status_name and optional status_color (background 20%, border 40%).
  - Legacy: “COMPLIANT” (green) or “NOT COMPLIANT” (red).
- **No health score, no created date, no team names on the card** — only name, status, alerts.
- **Hover:** Card gets `hover:bg-background-card/80`; prefetch runs on mouse enter (100ms delay).

---

## List view (table)

- **Table:** Bordered card, full width. Header row with columns: **Project** | **Status** | **Alerts** | **Health Score** | **Created**.
- **Project column:** Framework icon (20px) + project name.
- **Status column:** Same badge logic as grid (Creating+spinner, Failed, custom status, COMPLIANT/NOT COMPLIANT).
- **Alerts column:** Bell icon + number.
- **Health Score column:** Plain number (e.g. 72).
- **Created column:** Formatted date “DD Mon YY”.
- **Row hover:** `hover:bg-table-hover`. Row click navigates to project.
- **Header:** `bg-background-card-header` (list) or `bg-[#141618]` (loading skeleton), uppercase small labels.

---

## Search / filter

- **Scope:** Filters by project name and team names (case-insensitive).
- **No filters** for status, framework, health band, or date — only one search box.
- **Escape** clears search and blurs input; “Esc” button visible when search has value.

---

## Empty state

- **When no projects (and no search):** Centered block: “No projects found”, short line of copy (“Get started by creating your first project.” or “No projects found.”), and “Create Project” button if user can create.
- **When search has no results:** Same layout, copy “No projects match your search criteria.”; no Create button.

---

## Create project

- **Trigger:** “Create Project” in toolbar (permission-gated).
- **Flow:** Opens **CreateProjectSidebar** (slide-in from right) — full flow: name, team, asset tier, connect repo (GitHub/GitLab/Bitbucket), monorepo scan, etc. Not a simple modal.
- **Edit project:** Different UI — opens **SlideInSidebar** with “Edit Project”, description “Update the project details below.” Fields: Project Name (text), Team (ProjectTeamSelect). Footer: Cancel + “Save Changes”. No repo or asset tier in edit.

---

## Loading state

- **Grid:** 3 skeleton cards (same structure as real cards but with `animate-pulse` placeholders).
- **List:** Table with 3 skeleton rows, same columns as real table.
- No global spinner; skeletons match the chosen view mode.

---

## Design tokens (Deptex)

- **Background:** `background` (page), `background-card` (cards, panels), `background-card-header` (table header), `table-hover` (row hover).
- **Text:** `foreground`, `foreground-secondary`.
- **Borders:** `border`, `border-border`.
- **Primary CTA:** `bg-primary text-primary-foreground`, green accent.
- **Status:** `success` (compliant), `destructive` (failed / not compliant), custom status uses `status_color` with 20% bg and 40% border.
- **Input:** `bg-background-card border border-border rounded-md`, focus ring primary.
- **Typography:** Inter; labels `text-xs font-semibold uppercase tracking-wider text-foreground-secondary`; card title `text-base font-semibold`.

---

## What we want to improve (for iteration)

- **Hierarchy:** No clear page title or short description; toolbar feels like the top of the page.
- **Grid cards:** Very minimal — only name, status, alerts. No health score, no team, no last updated/created, no repo indicator (connected/disconnected).
- **Density:** Grid might feel sparse; list is dense but plain.
- **Visual weight:** Status badges and “Creating” state are prominent; health score in list is just a number with no visual band (e.g. green/yellow/red).
- **Empty state:** Functional but not very inviting or guided.
- **Search:** Single box, no quick filters (e.g. by status, team, framework) or saved views.
- **Edit:** Edit is a separate sidebar with only name + team; create is a much heavier flow (name, team, asset tier, repo connection). Inconsistent.
- **Consistency:** List view shows Health + Created; grid does not. Consider aligning or making the grid richer.

---

## Technical notes (for implementation after design)

- **Component:** `frontend/src/app/pages/ProjectsPage.tsx`.
- **API:** `api.getProjects(organizationId)`, `api.getTeams(organizationId)`. Project type includes all fields listed above.
- **Navigation:** Click project → `navigate(\`/organizations/${id}/projects/${projectId}\`)` (project root; overview is default).
- **Permissions:** `manage_teams_and_projects` gates Create button and empty-state Create; edit/delete are not exposed on this page (edit is via sidebar when opening create with `editingProject` set).
- **Create flow:** `CreateProjectSidebar`; Edit flow: inline `SlideInSidebar` with name + `ProjectTeamSelect`.

---

## Copy reference

- Search placeholder: **Filter…**
- Clear search button: **Esc**
- Tooltips: **Grid view**, **List view**
- Primary button: **Create Project**
- Empty (no projects): **No projects found** / **Get started by creating your first project.** / **No projects found.**
- Empty (search): **No projects match your search criteria.**
- Edit sidebar title: **Edit Project**
- Edit sidebar description: **Update the project details below.**
- Edit labels: **Project Name**, **Team**
- Edit footer: **Cancel**, **Save Changes**
- Status labels: **Creating** (with spinner), **Failed**, **COMPLIANT**, **NOT COMPLIANT**, or custom **status_name**
- Alerts: **X alert** / **X alerts**
- Table headers: **Project**, **Status**, **Alerts**, **Health Score**, **Created**

Use this document as the single source of truth for “what we have” when iterating in Stitch or in code.
