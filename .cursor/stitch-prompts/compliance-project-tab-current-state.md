# Stitch prompt: Project Compliance tab — “Project” sub-tab (current state)

Use this prompt in Stitch (or any design iteration tool) to understand exactly what the **Project** sub-tab looks like today so we can iterate on layout, hierarchy, and polish.

---

## What this screen is

**Route:** `/organizations/:orgId/projects/:projectId/compliance/project`  
**Context:** Inside a project; user has already selected an org and a project. The page is the **Compliance** tab (project sidebar), and the **Project** item is the first section in the left compliance sidebar (alongside Policy Results, Updates, Export Legal Notice, Export SBOM).  
**Purpose:** Show project-level compliance status: active policy violations from the latest scan, blocked PRs (placeholder), and where policy is coming from (Policy source). Optional “Preflight Check” flow to test adding a package before adding it.

---

## Layout and chrome

- **Overall layout:** Two-column. **Left:** sticky `ComplianceSidepanel` (width ~208px, `w-52`), border-right, “Compliance” heading, nav items (Project, Policy Results, Updates, then separator, Export Legal Notice, Export SBOM). **Right:** scrollable content area.
- **Content container:** `px-6 py-6 mx-auto max-w-5xl` — padded, centered, max width 5xl.
- **Top-right of content (when on Project/Policy Results/Updates):** “Re-evaluate” outline button, small (`h-8 text-xs`), with RefreshCw icon. Shown only if user has settings permission and extraction is not in progress. Disabled for 5s after click and while `reevaluating`.
- **No global page title above the sidebar** — the title lives inside the content area per section.

---

## Project sub-tab content structure

When **Project** is the active section (`activeSection === 'project'`), the content area shows, in order:

### 1. Section header

- **Title:** “Project compliance” — `text-xl font-semibold text-foreground tracking-tight`.
- **Subtitle:** “Active violations from the latest scan.” — `text-sm text-foreground-secondary mt-1`.

### 2. One of three states (mutually exclusive)

#### State A: Extraction in progress

- **When:** `isExtracting` is true (realtime status !== 'ready').
- **UI:** Single card: `rounded-lg border border-border bg-background-card shadow-sm p-6`.
  - Left: 40×40 box with Loader2 spinner in `bg-background-subtle` and border.
  - Right: “Extraction in progress” (heading), “Compliance status will appear here once the scan completes.” (subtext).
- No violations list, no Blocked PRs, no Policy source in this state.

#### State B: No scan data yet

- **When:** `noExtraction` (dependencies.length === 0) and not extracting.
- **UI:** Centered empty state inside a card (`rounded-lg border border-border bg-background-card shadow-sm p-10 text-center`):
  - Icon: 48×48 box with Package icon in `bg-background-subtle`.
  - Heading: “No scan data yet”.
  - Body: “Connect a repository and run your first extraction to see compliance status and policy results.”
  - CTA: “Go to Settings” button (navigates to project settings).
- No violations list, no Blocked PRs, no Policy source in this state.

#### State C: Has extraction data (main view)

When there is extraction data and not extracting, the following three blocks appear in order.

---

### 3. Block: Active violations

- **Heading row:** “Active violations” (left), optional red Badge “X items” when `violatedDeps.length > 0`, and right-aligned outline button “Check a package” (Shield icon, `h-8 text-xs`) that opens the **Preflight** sidebar.
- **If zero violations:**  
  One card, centered content: CheckCircle2 (green), “No active violations”, “All dependencies comply with the current policy.”
- **If there are violations:**  
  Card with `divide-y` list. Each row:
  - Package icon (16px), package name (truncate), version Badge (secondary, small).
  - Up to 2 reason badges (category-based colors: License Violation, Malicious Package, Low Score, SLSA, Supply Chain, Other); text truncated to 30 chars.
  - ChevronRight. Row is clickable → navigates to dependency overview.
  - Only first 20 violations shown; footer line: “Showing 20 of X violations. View all in Policy Results” (link switches section to policy-results).

**Reason badge styling (by category):**  
License Violation (red), Malicious Package (darker red), Low Score (orange), SLSA (yellow), Supply Chain (purple), Other (zinc). Small `text-[10px] px-1.5 py-0.5 rounded border`.

---

### 4. Block: Blocked pull requests

- **Heading:** “Blocked pull requests” — `text-base font-semibold text-foreground mb-4`.
- **Content:** Single placeholder card, centered:
  - GitPullRequest icon (36px), “PR checks not configured”, “Enable webhooks in project or organization settings to see blocked PRs.”
- **No table or list** — this is a static placeholder for future webhook/PR check data.

---

### 5. Block: Policy source

- **Heading:** “Policy source” — `text-base font-semibold text-foreground mb-4`.
- **Content:** One card with `divide-y` rows. Each row:
  - **Label:** ShieldAlert icon + one of “Package Policy”, “Status Code”, “PR Check”.
  - **Badge:** “Inherited” (secondary) or “Custom” (default).  
  - *(Currently all three rows show “Inherited” — real inherited/custom logic can be wired later.)*

---

## Preflight Check (slide-in panel)

- **Trigger:** “Check a package” in the Active violations block (only when not extracting).
- **UI:** Full-screen overlay; right-side panel `max-w-[480px]`, fixed right/top/bottom, rounded-xl, shadow. Title “Preflight Check”, subtitle “Test if adding a package would affect compliance.”
- **Flow:** User picks ecosystem (dropdown), searches or enters package name, gets results; clicks “Check” on a result → sees “Allowed” or “Blocked” with reasons, package details (version, license, tier, downloads), and “Check Another Package” to reset. Close button in footer.
- **Not part of the “Project” tab layout itself** — it overlays the whole page when open.

---

## Design tokens (Deptex)

- **Backgrounds:** `background`, `background-card`, `background-card-header`, `background-subtle`.
- **Text:** `foreground`, `foreground-secondary`.
- **Borders:** `border`, `border-border`.
- **Cards:** `rounded-lg border border-border bg-background-card shadow-sm`; optional `divide-y divide-border` for lists.
- **Table/list row hover:** `hover:bg-table-hover`.
- **Badges:** `variant="destructive"` (red count), `variant="secondary"` (version, Inherited), `variant="success"` (allowed), category-colored small badges as above.
- **Buttons:** Outline small “Re-evaluate”, “Check a package”; primary only in empty state “Go to Settings”.
- **Typography:** Section title `text-xl font-semibold tracking-tight`; block headings `text-base font-semibold`; body `text-sm`, hints `text-xs`; uppercase labels elsewhere `text-xs font-semibold uppercase tracking-wider text-foreground-secondary`.

---

## Copy reference (Project sub-tab only)

- Section title: **Project compliance**
- Section subtitle: **Active violations from the latest scan.**
- Re-evaluate button: **Re-evaluate**
- Block heading: **Active violations**
- Button: **Check a package**
- Empty violations: **No active violations** / **All dependencies comply with the current policy.**
- Violations footer: **Showing 20 of X violations.** + link **View all in Policy Results**
- Block heading: **Blocked pull requests**
- Placeholder: **PR checks not configured** / **Enable webhooks in project or organization settings to see blocked PRs.**
- Block heading: **Policy source**
- Row labels: **Package Policy**, **Status Code**, **PR Check**
- Badges: **Inherited**, **Custom**
- Extraction state: **Extraction in progress** / **Compliance status will appear here once the scan completes.**
- No data: **No scan data yet** / **Connect a repository and run your first extraction to see compliance status and policy results.** / **Go to Settings**

---

## Technical notes (for implementation after design)

- **Component:** `frontend/src/app/pages/ProjectCompliancePage.tsx`. Project sub-tab is the block where `activeSection === 'project'`.
- **Data:** `dependencies`, `violatedDeps` (deps with `policy_result.allowed === false`), `project` (for status_name, policy_evaluated_at, status_violations), `useRealtimeStatus(organizationId, projectId)` for extraction state.
- **Navigation:** Violation row click → `navigate(\`/organizations/${orgId}/projects/${projectId}/dependencies/${dep.dependency_id}/overview\`)`. “View all in Policy Results” → `handleSectionSelect('policy-results')`. “Go to Settings” → project settings route.
- **Preflight:** `PreflightSidebar` in same file; opens via `showPreflight` state; uses `api.searchRegistry`, `api.preflightCheck`.
- **Permissions:** Re-evaluate and exports gated by `canManageSettings` (edit_settings or view_settings). Preflight/Check a package visible whenever there is extraction data (no extra permission).

---

## What we might improve (for iteration)

- **Hierarchy:** The “Project compliance” title and subtitle could be stronger; consider a short status pill or summary line (e.g. “Compliant” / “3 violations”) near the title.
- **Active violations:** List is dense; consider summary stats (e.g. by category) above the list, or a compact/expanded view toggle.
- **Blocked PRs:** Currently a placeholder; when wired, consider filters and a table similar to the Updates tab.
- **Policy source:** All three rows look the same (Inherited); when project overrides exist, “Custom” and maybe a link to diff or edit would help.
- **Empty / loading:** Align with other compliance sections (Policy Results, Updates) for consistency (e.g. same card style, same “extraction in progress” treatment).
- **Re-evaluate:** Could move next to the section title or into a small “Last evaluated: X ago” line to save top-right space.

Use this document as the single source of truth for “what we have” in the Project sub-tab when iterating in Stitch or in code.
