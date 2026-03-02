---
name: Phase 6 - Security Tab Core
overview: Tab rename, Depscore graph coloring, enriched nodes, Semgrep/TruffleHog parsing, 3 clickable sidebars, advanced filtering, historical timeline, smart version engine, org/team overhaul.
todos:
  - id: phase-6-core
    content: "Phase 6: Security Tab Core - Tab rename, Depscore-based graph coloring, richer graph nodes (Depscore/EPSS/KEV/reachability), Semgrep+TruffleHog parsing into DB (with post-pipeline finalization, metadata sanitization, secret redaction, Raw stripping), shared SecuritySidebar wrapper with 3 content components (permission-gated suppress/accept/unsuppress/unaccept, staleness indicators, banned version integration, AI buttons disabled until 6C), paginated findings endpoints, event deduplication, advanced filtering with URL params, historical vulnerability timeline with MTTR, smart version recommendation engine (OSV verification + release notes, coexists with latest-safe-version.ts), org/team security-summary aggregate endpoint, org/team security page overhaul (No Team bug fix), test suite (17 backend + 51 frontend in 4 files with React Flow mocks)"
    status: done
isProject: false
---

## Phase 6: Security Tab Core

**Goal:** Transform the "Vulnerabilities" tab into a comprehensive "Security" tab with Depscore-based graph coloring, richer clickable nodes, Semgrep/TruffleHog code-level findings parsed into structured tables, three contextual sidebars, advanced filtering, historical vulnerability tracking, and smart version recommendations.

**Scope boundary:** This phase covers all non-AI features. AI buttons ("Fix with AI", "Explain with Aegis", "Ask Aegis") are rendered in sidebars but disabled with tooltips until [Phase 6C](phase_06c_ai_aegis.plan.md) ships the BYOK + Aegis Copilot infrastructure. The Aegis panel itself is built in Phase 6C.

**Prerequisites:** Phase 4 (custom asset tiers for Depscore) and Phase 5 (compliance infrastructure) are complete.

### Tab Rename + Graph Node Enrichment

**Rename "Vulnerabilities" to "Security" across the app:**

- Navigation: update [ProjectTabs](frontend/src/components/ProjectTabs.tsx), route definitions in [routes.tsx](frontend/src/app/routes.tsx), breadcrumbs
- Route: `/organizations/:orgId/projects/:projectId/security` (add redirect from old `/vulnerabilities` route)
- Page component: rename `ProjectVulnerabilitiesPage.tsx` to `ProjectSecurityPage.tsx` (or update title/references)
- Org sidebar, team tabs: update label to "Security"
- All internal references and test files

**Switch graph coloring from severity-based to Depscore-based:**

Current coloring uses `getWorstSeverity()` which maps CVSS severity (critical/high/medium/low/none) to node border/glow colors. Replace with Depscore-based coloring throughout the security graph:

- **Depscore color brackets**: 75-100 = red (urgent), 40-74 = orange (moderate), 0-39 = gray (low), no vulns = green (healthy)
- Replace `getWorstSeverity()` with `getWorstDepscore()` that returns the highest Depscore among child vulnerabilities. When Depscore data is unavailable (e.g., before extraction has computed it), fall back to severity-based coloring.
- **Vulnerability node** border/glow: Depscore bracket color
- **Dependency node** border: worst Depscore of child vulnerability nodes
- **Project node** border/glow: worst Depscore across all child deps
- **Team node** (org graph): worst Depscore across all child projects
- **Edge colors**: match the Depscore bracket of the target vulnerability node
- Update `VulnProjectNode` severity map to use Depscore brackets instead of CVSS severity
- Update `buildDepAndVulnNodesAndEdges` edge coloring logic
- Update `reachableVulns()` to return Depscore alongside is_reachable for coloring calculations

**Enrich Vulnerability Nodes** ([VulnerabilityNode.tsx](frontend/src/components/supply-chain/VulnerabilityNode.tsx)):

Current: severity badge, OSV ID, aliases, summary.

Add:

- **Depscore badge** (primary color indicator): reuse existing `getDepscoreBadgeClass` -- this now drives the node border color too
- **Severity badge**: kept as a secondary indicator (smaller, inside the node)
- **EPSS percentage**: small gray badge, e.g., "EPSS 3.2%"
- **CISA KEV indicator**: red flame icon when `cisa_kev === true`
- **Reachability indicator**: shield icon - green outline if not reachable, red fill if reachable
- **"Fix available" indicator**: small green check icon if `fixed_versions` is non-empty

Data flow: the `VulnGraphDepNode.vulnerabilities[]` already has `is_reachable` but is missing `depscore`, `epss_score`, `cvss_score`, `cisa_kev`, `fixed_versions`. Update `loadProjectVulnerabilityGraphData` in [vulnerability-graph-data.ts](frontend/src/lib/vulnerability-graph-data.ts) to include these fields from `ProjectVulnerability`.

**Enrich Dependency Nodes** ([DependencyNode.tsx](frontend/src/components/supply-chain/DependencyNode.tsx) in vuln graph context):

Current: name, version, license, "not imported" badge.

Add:

- **Vulnerability count breakdown**: compact badges "3C 1H 2M" showing severity counts from child vulnerability nodes
- **Worst Depscore**: small badge showing the highest depscore of child vulns (color-coded by Depscore bracket -- this also drives node border color)
- **Clickable cursor**: `cursor-pointer` class when in security graph context

**Enrich Center Node** ([ProjectCenterNode.tsx](frontend/src/components/vulnerabilities-graph/ProjectCenterNode.tsx)):

Current: project name, worst severity glow, framework.

Add:

- **Security issue counts**: text below project name: "X vulns | Y code issues | Z secrets" (from Semgrep + TruffleHog counts)
- **Depscore-based glow**: border/glow color driven by worst Depscore (replaces worst severity glow)
- **Clickable cursor**: `cursor-pointer` class

**Make all nodes clickable:**

Add `onClick` handlers to each node component. The security page manages sidebar state:

- `selectedVulnerability: string | null` (vuln ID)
- `selectedDependency: string | null` (dep ID)
- `showProjectSidebar: boolean`

Only one sidebar open at a time. Clicking a different node type closes the current sidebar and opens the new one.

### Semgrep + TruffleHog Parsing and Display

**Database Tables:**

```sql
CREATE TABLE project_semgrep_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  file_path TEXT NOT NULL,
  start_line INTEGER,
  end_line INTEGER,
  severity TEXT, -- ERROR, WARNING, INFO
  message TEXT,
  cwe_ids TEXT[],
  owasp_ids TEXT[],
  category TEXT, -- e.g., "security", "correctness"
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, rule_id, file_path, start_line)
);

CREATE INDEX idx_psf_project ON project_semgrep_findings(project_id);
CREATE INDEX idx_psf_run ON project_semgrep_findings(extraction_run_id);

CREATE TABLE project_secret_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  detector_type TEXT NOT NULL, -- e.g., "AWS", "GitHub", "GenericPassword"
  file_path TEXT NOT NULL,
  start_line INTEGER,
  is_verified BOOLEAN DEFAULT false,
  is_current BOOLEAN DEFAULT true, -- true if found in HEAD, false if only in git history
  description TEXT,
  redacted_value TEXT, -- partial redaction for long secrets, **** for short ones
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, detector_type, file_path, start_line)
);

CREATE INDEX idx_psecf_project ON project_secret_findings(project_id);
CREATE INDEX idx_psecf_run ON project_secret_findings(extraction_run_id);
```

**Extraction Worker Changes** ([pipeline.ts](backend/extraction-worker/src/pipeline.ts)):

After running Semgrep (output already saved as `semgrep.json` in Supabase Storage), add parsing step:

```typescript
const sanitizeMetadata = (metadata: any) => {
  if (!metadata) return {};
  const safe = { ...metadata };
  delete safe.source;
  delete safe.fix;
  return safe;
};

const semgrepPath = path.join(reportsDir, 'semgrep.json');
if (fs.existsSync(semgrepPath)) {
  const semgrepOutput = JSON.parse(fs.readFileSync(semgrepPath, 'utf8'));
  const findings = (semgrepOutput.results ?? []).map((r: any) => ({
    project_id: projectId,
    extraction_run_id: runId,
    rule_id: r.check_id,
    file_path: r.path,
    start_line: r.start?.line,
    end_line: r.end?.line,
    severity: r.extra?.severity ?? 'INFO',
    message: r.extra?.message,
    cwe_ids: r.extra?.metadata?.cwe ?? [],
    owasp_ids: r.extra?.metadata?.owasp ?? [],
    category: r.extra?.metadata?.category ?? 'security',
    metadata: sanitizeMetadata(r.extra?.metadata),
  }));
  if (findings.length > 0) {
    await supabase.from('project_semgrep_findings').upsert(findings, {
      onConflict: 'project_id,rule_id,file_path,start_line'
    });
  }
  // NOTE: Stale findings cleanup is deferred to the post-pipeline finalization step
  // (see "Finalize Findings" below) to avoid data loss on mid-pipeline failures.
  log('scan', `Parsed ${findings.length} Semgrep findings`);
}
```

After running TruffleHog (output already saved as `trufflehog.json`), add parsing step. **Security fix: use conservative redaction (20-char minimum for partial reveal) and strip Raw field before storage upload:**

```typescript
const trufflePath = path.join(reportsDir, 'trufflehog.json');
if (fs.existsSync(trufflePath)) {
  const content = fs.readFileSync(trufflePath, 'utf8');
  const lines = content.trim().split('\n').filter(Boolean);

  const findings = lines.map((line: string) => {
    const f = JSON.parse(line);
    const raw = f.Raw ?? '';
    // Conservative redaction: only show partial for secrets >= 20 chars
    const redacted = raw.length >= 20 ? `${raw.slice(0, 4)}...${raw.slice(-4)}` : '****';
    return {
      project_id: projectId,
      extraction_run_id: runId,
      detector_type: f.DetectorName ?? 'Unknown',
      file_path: f.SourceMetadata?.Data?.Filesystem?.file ?? f.SourceMetadata?.Data?.Git?.file ?? 'unknown',
      start_line: f.SourceMetadata?.Data?.Filesystem?.line ?? f.SourceMetadata?.Data?.Git?.line ?? null,
      is_verified: f.Verified ?? false,
      is_current: !!(f.SourceMetadata?.Data?.Filesystem),
      description: `${f.DetectorName ?? 'Secret'} detected`,
      redacted_value: redacted,
    };
  });

  if (findings.length > 0) {
    await supabase.from('project_secret_findings').upsert(findings, {
      onConflict: 'project_id,detector_type,file_path,start_line'
    });
  }
  // NOTE: Stale findings cleanup is deferred to the post-pipeline finalization step
  // (see "Finalize Findings" below) to avoid data loss on mid-pipeline failures.

  // Strip Raw field from TruffleHog JSON before uploading to storage
  const sanitized = lines.map((line: string) => {
    const f = JSON.parse(line);
    delete f.Raw;
    return JSON.stringify(f);
  }).join('\n');
  fs.writeFileSync(trufflePath, sanitized, 'utf8');

  log('scan', `Parsed ${findings.length} TruffleHog findings`);
}
```

**Finalize Findings (post-pipeline cleanup):**

After the full pipeline succeeds (step 11 "Status" sets `extraction_step = 'completed'`), run a single cleanup pass that removes stale findings from **both** tables. This ensures that if extraction fails mid-pipeline (e.g., after Semgrep but before TruffleHog), findings from the previous successful run are preserved rather than deleted:

```typescript
// Only runs after extraction_step = 'completed'
await supabase.from('project_semgrep_findings')
  .delete()
  .eq('project_id', projectId)
  .neq('extraction_run_id', runId);

await supabase.from('project_secret_findings')
  .delete()
  .eq('project_id', projectId)
  .neq('extraction_run_id', runId);

log('finalize', 'Cleaned up stale findings from previous extraction runs');
```

This matches the existing pipeline pattern where `status = 'ready'` is only set on success.

**New API Endpoints** (in [projects.ts](ee/backend/routes/projects.ts)):

- `GET /api/organizations/:orgId/projects/:projectId/semgrep-findings` - returns parsed Semgrep findings with pagination (`?page=1&per_page=50`, default 50, max 200). Auth: project member (any role).
- `GET /api/organizations/:orgId/projects/:projectId/secret-findings` - returns parsed TruffleHog findings (redacted values only) with pagination (`?page=1&per_page=50`, default 50, max 100). Auth: requires `manage_projects` (team-level) or `manage_teams_and_projects` (org-level) -- secret findings are sensitive security data.

**Frontend Display:**

- Findings shown in the Project Security Sidebar when clicking the center node
- Each Semgrep finding: severity badge + rule category + file path:line + message
- Each TruffleHog finding: detector type badge + file path:line + verified/unverified indicator
- Counts displayed on the center node badge

### Advanced Filtering

Replace the single `ShowOnlyReachableCard` toggle with a full filter bar styled like the Dependencies tab filter dropdown:

**Filter options:**

- **Severity**: Checkboxes for critical, high, medium, low (multi-select)
- **Depscore Range**: Slider or threshold input (e.g., "Show only >= 40")
- **EPSS Threshold**: Input (e.g., "Show only >= 1%")
- **CISA KEV**: Toggle "Only KEV listed"
- **Fix Available**: Toggle "Has fix available"
- **Reachable Only**: Toggle (replaces current `ShowOnlyReachableCard`)
- **Dependency Type**: Dropdown - Direct / Transitive / Both
- **Date Range**: Date pickers for "Discovered after" / "Discovered before"

**Implementation:**

- Filter state managed in URL search params for shareability (`?severity=critical,high&depscore_min=40&kev=true`)
- Filtering logic applied in `useVulnerabilitiesGraphLayout.ts` - nodes that don't match are either hidden or dimmed (opacity 0.2 + non-interactive)
- Filter bar positioned at top of the Security page, below the project tabs
- "Active filters" count badge on the filter button
- "Clear all" button to reset

### Shared SecuritySidebar Architecture

All three security sidebars share a common wrapper component rather than being built as standalone components:

```
frontend/src/components/security/
  SecuritySidebar.tsx              -- shared wrapper (slide-in, width, close, footer slot)
  VulnerabilityDetailContent.tsx   -- vulnerability sidebar content
  DependencySecurityContent.tsx    -- dependency sidebar content
  ProjectSecurityContent.tsx       -- project sidebar content
```

`SecuritySidebar.tsx` handles:

- Slide-in animation (translate-x, `w-[26rem]`)
- Close button in header
- Sticky action footer slot (passed as a render prop)
- "Only one open at a time" state management via a single `activeSidebar: { type: 'vulnerability' | 'dependency' | 'project', id: string } | null` state on the Security page

Each content component receives its data as props and renders its own collapsible sections. The page component decides which content to render inside `SecuritySidebar` based on `activeSidebar.type`.

### Vulnerability Detail Content

**Trigger:** Click any vulnerability node in the graph. Sets `activeSidebar = { type: 'vulnerability', id: osvId }`.

**Content sections (rendered inside `SecuritySidebar`):**

1. **Header**: OSV ID (linked to external advisory) + close button
2. **Risk Badges Row**: Severity badge + Depscore badge + EPSS percentage + CISA KEV warning (red banner if active)
3. **Risk Assessment Card** (collapsible):
  - Reachability: "Imported in X files" or "Not directly imported" (with confidence level)
  - Asset Tier context: tier name + multiplier effect on Depscore
  - Exploit maturity: CISA KEV status, EPSS interpretation ("top 5% likelihood of exploitation")
4. **Description** (collapsible):
  - Full advisory text from `summary` field
  - "Explain with Aegis" button -- **disabled until Phase 6C** with tooltip "Configure AI in Organization Settings"
5. **Affected Code** (collapsible) -- **enhanced by Phase 6B**:
  - **When atom reachability data is available** (Phase 6B): Full `CodeImpactView` component showing entry points, data-flow arrows, vulnerable sink, syntax-highlighted code
  - **Fallback (no atom data)**: List of affected project dependencies with: name, version, direct/transitive badge. Under each dependency: list of files that import it (from `files_importing` on project_dependencies). File paths are clickable if we can link to the repo.
6. **Fix Options** (collapsible):
  - **Fix classification badges**:
    - "Same-major fix" (green badge) - fixed version available within the current major version (non-breaking)
    - "Major version bump" (yellow badge with warning icon) - fix requires a major version upgrade (potentially breaking)
    - "Workaround available" (blue badge) - advisory includes a documented workaround or mitigation
    - "No fix yet" (gray badge) - no fixed version available, only code-level mitigation possible
    - "Dev dependency" (dim badge) - vuln is in a dev dependency only (lower priority)
  - **Fix impact preview** (from `project_version_candidates` data): "Upgrading [package] to v4.17.21 also resolves: CVE-B (High), CVE-C (Medium)" -- shows all OTHER vulnerabilities in the same package that this fix would resolve.
  - **Recommended version** (from smart version recommendation engine): Shows the OSV-verified same-major safe version with "Fixes X/Y CVEs, 0 known new CVEs" label. Expandable to show release notes snippet. **Banned version guard**: if the recommended version is banned by the org or team, it is skipped and the next-best non-banned candidate is shown. If the ONLY safe version is banned, show: "Safe version v4.17.21 exists but is banned by your organization. Contact an admin or choose a different strategy." **Staleness indicator**: if `verified_at` is older than 48 hours, show subtle "Last verified X hours ago" label; if older than 7 days, show amber "May be outdated" badge.
  - **"Fix with AI"** primary button -- **disabled until Phase 6C** with tooltip "Configure AI in Organization Settings". Phase 7 enables the actual fix flow.
  - **"Bump Version"** secondary button - navigates to the dependency's supply chain tab
  - **"Pin Transitive"** option (shown only for transitive deps) - adds a resolution/override to lock the transitive dependency to a safe version
7. **Timeline** (collapsible):
  - Published date (from `published_at`)
  - Detected in project date (from `created_at` on pdv row)
  - MTTR metric if resolved (from `project_vulnerability_events`)
8. **References**:
  - NVD link (if CVE alias exists)
  - OSV link
  - GHSA link (if GHSA alias exists)
9. **Actions Footer** (sticky at bottom, **requires `manage_projects` (team) or `manage_teams_and_projects` (org)** -- buttons hidden for users without permission):
  - **"Suppress" / "Unsuppress" toggle** - when not suppressed: "Suppress" marks `suppressed = true`, `suppressed_by`, `suppressed_at` on the pdv row (hides from default view, visible with filter). When suppressed: shows "Unsuppress" which clears `suppressed`, `suppressed_by`, `suppressed_at`. Both actions log to `project_vulnerability_events`.
  - **"Accept Risk" / "Revoke Acceptance" toggle** - when not accepted: "Accept Risk" opens a reason dialog then marks `risk_accepted = true` with audit trail (user ID + timestamp + reason). When accepted: shows "Revoke Acceptance" which clears `risk_accepted`, `risk_accepted_by`, `risk_accepted_at`, `risk_accepted_reason` and logs a `risk_unaccepted` event.

**New backend endpoints:**

`GET /api/organizations/:orgId/projects/:projectId/vulnerabilities/:osvId/detail`

Returns:

- Full vulnerability data from `project_dependency_vulnerabilities`
- Affected project dependencies (joined from `project_dependencies`)
- Files importing each affected dependency (from import analysis)
- Fix version analysis (from `project_version_candidates`)
- Timeline events from `project_vulnerability_events`

`PATCH /api/organizations/:orgId/projects/:projectId/vulnerabilities/:osvId/suppress` - sets `suppressed = true`, `suppressed_by`, `suppressed_at`; logs `suppressed` event. Auth: `manage_projects` or `manage_teams_and_projects`.

`PATCH /api/organizations/:orgId/projects/:projectId/vulnerabilities/:osvId/unsuppress` - clears `suppressed`, `suppressed_by`, `suppressed_at`; logs `unsuppressed` event. Auth: same.

`PATCH /api/organizations/:orgId/projects/:projectId/vulnerabilities/:osvId/accept-risk` - sets `risk_accepted = true`, `risk_accepted_by`, `risk_accepted_at`, `risk_accepted_reason`; logs `accepted` event. Auth: same.

`PATCH /api/organizations/:orgId/projects/:projectId/vulnerabilities/:osvId/unaccept-risk` - clears all `risk_accepted`_* fields; logs `risk_unaccepted` event. Auth: same.

**Schema additions to `project_dependency_vulnerabilities`:**

```sql
ALTER TABLE project_dependency_vulnerabilities
  ADD COLUMN suppressed BOOLEAN DEFAULT false,
  ADD COLUMN suppressed_by UUID REFERENCES auth.users(id),
  ADD COLUMN suppressed_at TIMESTAMPTZ,
  ADD COLUMN risk_accepted BOOLEAN DEFAULT false,
  ADD COLUMN risk_accepted_by UUID REFERENCES auth.users(id),
  ADD COLUMN risk_accepted_at TIMESTAMPTZ,
  ADD COLUMN risk_accepted_reason TEXT;
```

### Dependency Security Content

**Trigger:** Click any dependency node in the security graph. Sets `activeSidebar = { type: 'dependency', id: depId }`.

**Content sections (rendered inside `SecuritySidebar`):**

1. **Header**: Package name + version badge + license badge + ecosystem icon (npm/PyPI/Maven/etc.) + close button
2. **Usage in Your Project** (collapsible):
  - Type: "Direct dependency" or "Transitive (via X -> Y -> this)"
  - Import count: "Imported in X files"
  - File list: each file path that imports this package (from import analysis)
  - If zombie (imported but unused in code): yellow "Not imported in your code" badge
3. **Current Vulnerabilities** (collapsible, sorted by Depscore descending):
  - Each vulnerability row: [Depscore badge] [Severity badge] CVE-ID + "fix available" green check if applicable
  - Click a vulnerability row -> switches to the Vulnerability Detail Sidebar
4. **Recommended Versions** (collapsible) -- powered by smart version recommendation engine:
  - **Remove this package** (shown prominently at top if usage analysis shows 0 imports): "This package is not used in your code. Remove it to eliminate X vulnerabilities."
  - **Current version**: version badge + vulnerability count + "X reachable" sub-count
  - **Same-major safe** (if available): version badge + "Fixes X/Y current CVEs" + "0 known new CVEs" green verified badge (or "Z known CVEs" yellow warning). Expandable to show release notes. **If this version is banned by the org/team**: show red "Banned" badge alongside the version.
  - **Fully safe** (if different from same-major): version badge + "Fixes all Y current CVEs" + verification status. "MAJOR UPGRADE" warning badge if major version bump. Same banned badge logic.
  - **Latest**: version badge + vulnerability count from OSV + publish date. Same banned badge logic.
  - **Fix impact summary** at bottom: "Upgrading to v4.17.21 resolves: CVE-A, CVE-B, CVE-C"
  - "View All Versions" link -> navigates to supply chain tab's version sidebar
  - **Banned version data source**: fetch `banned_versions` (org-level) and `team_banned_versions` (team-level for the project's owner team) via existing API endpoints. Cache per sidebar open.
  - **Staleness indicator**: each version candidate shows `verified_at` age -- subtle "Last verified X hours ago" label if older than 48h; amber "May be outdated" badge if older than 7 days. Frontend-only check against the `verified_at` timestamp.
5. **Watchtower Signals** (collapsible, only shown if package is on org's watchtower):
  - Anomaly score with color indicator (green/yellow/red)
  - Security checks: Registry integrity, Install scripts, Entropy (pass/warn/fail icons)
  - Last checked timestamp
  - "View Forensics" link -> navigates to Watchtower tab
6. **Actions Footer**:
  - "View Full Detail" button -> navigates to `/organizations/:orgId/projects/:projectId/dependencies/:depId`
  - "Bump to vX.Y.Z" button (if safe version exists) -> triggers version bump flow

**New backend endpoint:**

`GET /api/organizations/:orgId/projects/:projectId/dependencies/:depId/security-summary`

Returns:

- Dependency info (name, version, license, ecosystem, is_direct)
- Import analysis (file paths importing this package)
- Vulnerabilities affecting this dependency (with depscore, severity, fix status)
- Safe version recommendation (from `project_version_candidates`)
- Watchtower summary (if on watchtower)

### Project Security Content (Center Node)

**Trigger:** Click the center (project) node in the graph. Sets `activeSidebar = { type: 'project', id: projectId }`.

**Content sections (rendered inside `SecuritySidebar`):**

1. **Header**: Project name + overall security status badge + close button
2. **Vulnerability Summary** card:
  - Breakdown by severity: Critical (count), High (count), Medium (count), Low (count)
  - Total count + "X reachable" sub-count
  - Color-coded bars or mini chart
3. **Depscore Distribution** card:
  - Three buckets: 75-100 (urgent, red), 40-74 (moderate, yellow), 0-39 (low, gray)
  - Count in each bucket
4. **Code Issues (Semgrep)** (collapsible):
  - Count badge in header (red if any critical/high)
  - List of top findings (max 5, sorted by severity): severity badge + rule category + file path:line + message
  - Each finding expandable to show a mini code snippet (3-5 lines around the issue). Semgrep output includes the affected code -- stored in `project_semgrep_findings.metadata` and rendered with syntax highlighting.
  - Each finding has an **"Ask Aegis"** button -- **disabled until Phase 6C** with tooltip "Configure AI in Organization Settings"
  - "View all X findings" expandable
5. **Exposed Secrets (TruffleHog)** (collapsible):
  - Count badge in header (red if any verified)
  - List of findings: detector type badge + file path:line + verified/unverified badge
  - Each finding expandable to show a mini code snippet (3-5 lines around the secret, with the secret value replaced with `[REDACTED]`).
  - Each finding has an **"Ask Aegis"** button -- **disabled until Phase 6C**
  - CRITICAL: never show actual secret values, only redacted
  - Verified secrets get a red "Active" badge
  - `**is_current` handling**: Findings with `is_current = false` show guidance: "This credential was exposed in a previous commit. Rotate immediately." Show "Mark as rotated" button to dismiss. No "Remediate with AI" button (nothing to fix in current code). Findings with `is_current = true` show the standard finding display without the "Rotate" message.
6. **Priority Actions** card:
  - Pre-computed top 3 most urgent items:
  1. "Fix X critical reachable vulnerabilities" (if any)
  2. "Rotate X verified exposed secrets" (if any)
  3. "Address X high-severity code issues" (if any)
    ch item is clickable (navigates to relevant section)
7. **Actions Footer**:
  - "Re-evaluate" button (triggers policy re-evaluation, same as compliance tab)
  - "Ask Aegis" button -- **disabled until Phase 6C**

### Historical Vulnerability Timeline

**Database Table:**

```sql
CREATE TABLE project_vulnerability_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  osv_id TEXT NOT NULL,
  event_type TEXT NOT NULL, -- 'detected', 'resolved', 'suppressed', 'unsuppressed', 'accepted', 'risk_unaccepted', 'kev_added', 'epss_changed', 'depscore_changed', 'fix_available'
  metadata JSONB, -- event-specific data: { old_depscore, new_depscore } or { accepted_by, reason } etc.
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_pve_project_id ON project_vulnerability_events(project_id);
CREATE INDEX idx_pve_osv_id ON project_vulnerability_events(osv_id);
CREATE INDEX idx_pve_event_type ON project_vulnerability_events(event_type);
CREATE INDEX idx_pve_created_at ON project_vulnerability_events(created_at DESC);
```

**Events tracked:**

- **detected**: When a vulnerability is first found during extraction (automatically logged)
- **resolved**: When a vulnerability is no longer present after a re-scan (dependency upgraded)
- **suppressed**: When a user marks a vulnerability as suppressed
- **unsuppressed**: When a suppression is removed
- **accepted**: When a user marks vulnerability as accepted risk (with reason)
- **risk_unaccepted**: When a user revokes a previous risk acceptance
- **kev_added**: When a vulnerability is added to CISA KEV (detected during background monitoring in 6C)
- **epss_changed**: When EPSS score changes by >10% (detected during background monitoring in 6C)
- **depscore_changed**: When Depscore changes significantly (due to tier change, KEV addition, etc.)
- **fix_available**: When a new safe fix version is discovered (during background monitoring in 6C)

**Frontend display:**

- Timeline shown in the Vulnerability Detail Sidebar under the "Timeline" section
- Timeline chart on project overview (Phase 10): "Vulnerability trend over time" - line chart showing total active vulns by severity over time

**Metrics:**

- **MTTR (Mean Time To Remediation)**: calculated per project from detected -> resolved events
- Available in the Project Security Sidebar and project overview
- Exportable in security reports

**Event logging in extraction pipeline:**

After vulnerability parsing in populate-dependencies, compare new vulns against existing `project_dependency_vulnerabilities`:

- New osv_id not in existing rows -> insert `detected` event
- Existing osv_id no longer in scan results -> insert `resolved` event

**Idempotency guard (prevents duplicate events on QStash retries):** Before inserting a `detected` or `resolved` event, check whether one already exists within the last hour:

```typescript
const { data: existing } = await supabase
  .from('project_vulnerability_events')
  .select('id')
  .eq('project_id', projectId)
  .eq('osv_id', osvId)
  .eq('event_type', eventType)
  .gte('created_at', new Date(Date.now() - 3600_000).toISOString())
  .limit(1);

if (!existing?.length) {
  await supabase.from('project_vulnerability_events').insert({ ... });
}
```

Events that can legitimately repeat over time (`depscore_changed`, `epss_changed`, `kev_added`, `fix_available`) do not need the dedup check -- they represent real state changes.

After suppress/accept/unsuppress/unaccept-risk actions in the vulnerability detail API endpoints -> insert corresponding events.

### Smart Version Recommendation Engine

**Goal:** Provide verified, actionable version upgrade recommendations for each vulnerable package. Instead of a vague "safest version," compute specific candidate versions with OSV-verified safety status and release notes.

**How it works:**

For each vulnerable package during extraction:

1. **Collect fix data**: Aggregate `fixed_versions[]` across all CVEs for the package. Example:
  - CVE-A: fixed in >=4.17.21
  - CVE-B: fixed in >=4.17.20
  - CVE-C: fixed in >=5.0.0
2. **Compute candidate versions**:
  - **Same-major safe**: `max(4.17.21, 4.17.20) = 4.17.21` (highest fix version within current major). Fixes CVE-A and CVE-B but NOT CVE-C.
  - **Fully safe**: `5.0.0` (lowest version that fixes ALL CVEs). May be a major bump.
  - **Latest**: From registry metadata we already fetch during extraction.
3. **Verify candidates against OSV**: One batch API call per package:

```
POST https://api.osv.dev/v1/querybatch
{
  "queries": [
    { "package": { "ecosystem": "npm", "name": "lodash" }, "version": "4.17.21" },
    { "package": { "ecosystem": "npm", "name": "lodash" }, "version": "5.0.0" },
    { "package": { "ecosystem": "npm", "name": "lodash" }, "version": "5.2.1" }
  ]
}
```

Response tells us how many known CVEs exist for each candidate version. Store the count and IDs.

1. **Fetch release notes**: For packages with a linked GitHub repo (available in registry metadata):
  - Query GitHub Releases API: `GET /repos/{owner}/{repo}/releases/tags/v{version}`
  - Store the release notes markdown (truncated to ~2000 chars)
  - If no GitHub release exists, store a link to the package registry page for that version

**Storage:**

```sql
CREATE TABLE project_version_candidates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  package_name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  current_version TEXT NOT NULL,
  candidate_type TEXT NOT NULL, -- 'same_major_safe', 'fully_safe', 'latest'
  candidate_version TEXT NOT NULL,
  fixes_cve_count INTEGER NOT NULL,
  total_current_cves INTEGER NOT NULL,
  fixes_cve_ids TEXT[],
  known_new_cves INTEGER DEFAULT 0,
  known_new_cve_ids TEXT[],
  is_major_bump BOOLEAN DEFAULT false,
  is_org_banned BOOLEAN DEFAULT false,
  release_notes TEXT,
  release_notes_url TEXT,
  published_at TIMESTAMPTZ,
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, package_name, ecosystem, candidate_type)
);

CREATE INDEX idx_pvc_project_package ON project_version_candidates(project_id, package_name, ecosystem);
```

**Pipeline addition** ([workers.ts](ee/backend/routes/workers.ts) populate-dependencies callback):

After vulnerability parsing, add a new step:

```typescript
// For each package with vulnerabilities:
// 1. Aggregate fixed_versions across all CVEs
// 2. Compute same_major_safe, fully_safe candidates
// 3. Batch-query OSV for candidate versions
// 4. Fetch release notes from GitHub (if repo URL available)
// 5. Upsert into project_version_candidates
```

**Banned version exclusion:** Before finalizing candidates, query `banned_versions` (org-level) and `team_banned_versions` (for the project's owner team). Any candidate version that appears in the banned list is stored with `is_org_banned = true` so the UI can show "Safe version exists but is banned by your organization."

**Supply chain tab alignment (consolidation deferred):** `project_version_candidates` serves as the precomputed source for the Security tab and sidebars. The supply chain tab continues to use `[latest-safe-version.ts](ee/backend/lib/latest-safe-version.ts)` (which includes transitive dep checking, Watchtower quarantine, and security check filtering that `project_version_candidates` doesn't replicate). Consolidating these two systems into one is tracked as a follow-up task after Phase 6 ships. Until then, both systems coexist -- version candidates for Security tab, latest-safe-version for Supply Chain tab.

**Version candidates API endpoint:**

`GET /api/organizations/:orgId/projects/:projectId/version-candidates?page=1&per_page=50&package_name=lodash` - returns paginated version candidates. Optional `package_name` filter to scope to a single package. Response shape: `{ data: [...], total: N, page: 1, per_page: 50 }`.

**Cost:** One OSV API call per vulnerable package (free, fast). One GitHub API call per candidate version with release notes (rate-limited at 5000/hr with auth token). Adds ~10-30 seconds to extraction.

### Org & Team Security Pages Overhaul

Both the Organization Vulnerabilities page ([OrganizationVulnerabilitiesPage.tsx](frontend/src/app/pages/OrganizationVulnerabilitiesPage.tsx)) and Team Vulnerabilities page ([TeamAlertsPage.tsx](frontend/src/app/pages/TeamAlertsPage.tsx)) need the Phase 6 treatment.

**Rename:**

- Organization: "Vulnerabilities" -> "Security" in sidebar navigation and breadcrumbs
- Team: "Vulnerabilities" -> "Security" in team tabs
- Route updates: `/organizations/:orgId/security` (redirect from old `/vulnerabilities`), team equivalent

**Graph coloring -- Depscore-based:**

Apply the same Depscore coloring:

- Team nodes: colored by worst Depscore across child projects (75-100=red, 40-74=orange, 0-39=gray, none=green)
- Project nodes: colored by worst Depscore across child deps
- Replace `getWorstSeverity()` calls in `useOrganizationVulnerabilitiesGraphLayout.ts` and `useTeamVulnerabilitiesGraphLayout.ts` with `getWorstDepscore()`

**"No Team" bug fix:**

Current behavior: projects without a team are placed under a synthetic "No team" node (`UNGROUPED_TEAM_ID = 'org-ungrouped'`), AND get an extra direct edge from the org center to the project. This creates visual clutter and a confusing intermediary.

Fix in [useOrganizationVulnerabilitiesGraphLayout.ts](frontend/src/components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout.ts):

- Remove the `UNGROUPED_TEAM_ID` team node entirely
- Place ungrouped projects directly on the org ring at the same level as team nodes
- Edge: org -> project (direct, no intermediary "No team" node)
- Ungrouped projects use the same `VulnProjectNode` component (not `isTeamNode: true`)
- In [OrganizationVulnerabilitiesPage.tsx](frontend/src/app/pages/OrganizationVulnerabilitiesPage.tsx): remove the synthetic team list entry for `UNGROUPED_TEAM_ID`. Pass ungrouped projects as a separate flat list to the layout hook.

**Aggregate Security Summary Endpoint:**

To avoid N+1 API calls when loading the org/team graph (currently calls `loadProjectVulnerabilityGraphData` per project), add a single aggregate endpoint:

`GET /api/organizations/:orgId/security-summary` -- returns per-project security counts in one query:

```json
{
  "projects": [
    {
      "project_id": "...",
      "project_name": "...",
      "team_id": "...",
      "vuln_count": 12,
      "critical_count": 2,
      "reachable_count": 5,
      "worst_depscore": 87,
      "semgrep_count": 8,
      "secret_count": 1,
      "verified_secret_count": 0
    }
  ]
}
```

Backend: Single query joining `project_dependency_vulnerabilities`, `project_semgrep_findings`, and `project_secret_findings` with GROUP BY `project_id`. Use this for org/team center node labels and the initial graph layout. Full graph data is still loaded per-project when drilling down.

Team variant: `GET /api/organizations/:orgId/teams/:teamId/security-summary` (same shape, filtered by team membership).

**Enriched center nodes:**

- **Org center node**: show aggregated counts below org name: "X vulns | Y code issues | Z secrets" (summed from security-summary endpoint)
- **Team center node**: same aggregated counts for team's projects
- Both clickable: clicking opens a summary sidebar with security posture breakdown

**Advanced filter bar:**

Add the same filter bar (severity, Depscore range, EPSS threshold, KEV, fix available, reachable only). Additional org/team-specific filters:

- **Risk accepted / Suppressed**: filter by vuln status
- **Project status**: filter by project's compliance status (from policy engine)
- **Asset tier**: filter by project tier (Crown Jewels, External, Internal, Non-Production)

These filters apply to which PROJECT NODES are shown/dimmed. When a project is dimmed, its child dep/vuln nodes are also dimmed.

**Clickable project nodes:**

- Clicking a project node in the org/team graph navigates to that project's Security tab
- Or (for quick glance): opens an inline mini-sidebar showing the project's security summary

**Clickable team nodes (org graph only):**

- Clicking a team node navigates to that team's Security page

### Design Reference (Stitch AI Prompts)

**IMPORTANT: Stitch AI reference images are saved in the project assets folder. Use these as structural inspiration but adapt to Deptex's design system below.**

Reference mockups (NOT final style -- adapt colors and typography):

- Vulnerability sidebar: `assets/c__Users_hruck_..._image-e46a451f-...png`
- Project sidebar: `assets/c__Users_hruck_..._image-ce79d1e9-...png`
- Dependency sidebar: `assets/c__Users_hruck_..._image-81fe9dfc-...png`
- Aegis panel: `assets/c__Users_hruck_..._image-e1d4b8c4-...png` (used in Phase 6C)

**Deptex Design System (use for ALL components):**

- Background: `#09090b` (zinc-950)
- Card background: `#18181b` (zinc-900)
- Card header / elevated: `bg-background-card-header` (slightly lighter than card)
- Borders: `#27272a` (zinc-800), 1px solid
- Primary text: `#fafafa`
- Secondary text: `#a1a1aa` (zinc-400)
- Muted text: `#71717a` (zinc-500)
- Primary accent: `#22c55e` (green-500) -- buttons, links, positive indicators
- Destructive: `#ef4444` (red-500) -- critical severity, errors, alerts
- Warning: `#f59e0b` (amber-500) -- high severity, caution
- Border radius: 8px (cards), 6px (badges, buttons), 4px (small elements)
- Font: Inter 14px body, 13px secondary, 12px badges/labels. JetBrains Mono for CVE IDs, file paths, code, versions.
- No gradients, no shadows except very subtle `shadow-sm` on hover. No saturated card backgrounds.
- Style: ultra-minimal, Linear/Vercel-inspired. Dense but breathable. Every pixel deliberate.
- Existing sidebar pattern: slides in from right with `translate-x` transition, width `w-[26rem]` (~416px), full height, close X button in header. Reference: `CreateRoleSidebar.tsx`, `PolicyExceptionSidebar.tsx`.

**Stitch AI prompts for Vulnerability Detail Sidebar, Dependency Detail Sidebar, and Project Security Sidebar** are the same as documented in the original Phase 6 plan. See the reference images and adapt to the design system above.

### Recommended Implementation Order

1. **Database migrations** -- `project_semgrep_findings`, `project_secret_findings`, `project_vulnerability_events`, `project_version_candidates`, PDV schema additions (`suppressed`, `suppressed_by`, `suppressed_at`, `risk_accepted`, `risk_accepted_by`, `risk_accepted_at`, `risk_accepted_reason`)
2. **Extraction pipeline changes** -- Semgrep parsing (with metadata sanitization), TruffleHog parsing (with `extraction_run_id`, conservative redaction, Raw stripping), post-pipeline finalization step for stale findings cleanup
3. **Backend API endpoints** -- semgrep-findings (paginated), secret-findings (paginated, permission-gated), vulnerability detail, dependency security-summary, version candidates (paginated), suppress/unsuppress/accept-risk/unaccept-risk (permission-gated), org/team security-summary aggregate
4. **Shared SecuritySidebar wrapper** -- `SecuritySidebar.tsx` + three content components
5. **Graph enrichment** -- Depscore coloring, enriched nodes, vulnerability-graph-data.ts field additions
6. **Tab rename + routing** -- rename across app, add redirects
7. **Advanced filtering** -- filter bar component, URL param persistence, graph integration
8. **Sidebar content** -- VulnerabilityDetailContent, DependencySecurityContent, ProjectSecurityContent (with disabled AI buttons, permission-gated actions, staleness indicators, unsuppress/unaccept toggles)
9. **Timeline + Version Engine** -- events table population (with dedup guard), MTTR, OSV verification pipeline addition
10. **Org/Team overhaul** -- rename, Depscore coloring, "No Team" fix, enriched nodes, filters, aggregate endpoint integration
11. **React Flow test mocks + test suite** -- shared React Flow mock, 4 frontend test files (51 tests), 1 backend test file (17 tests)

### Phase 6 Core Test Suite

#### React Flow Mock Setup

Add `frontend/src/test/mocks/react-flow.ts` to provide a shared mock for all test files that render graph nodes:

```typescript
vi.mock('@xyflow/react', () => ({
  ReactFlow: ({ children }: any) => <div data-testid="react-flow">{children}</div>,
  useReactFlow: () => ({ fitView: vi.fn(), getNodes: vi.fn(() => []), getEdges: vi.fn(() => []) }),
  useNodesState: (initial: any) => [initial, vi.fn(), vi.fn()],
  useEdgesState: (initial: any) => [initial, vi.fn(), vi.fn()],
  Background: () => null,
  Controls: () => null,
  Handle: () => null,
  Position: { Top: 'top', Bottom: 'bottom', Left: 'left', Right: 'right' },
  MarkerType: { ArrowClosed: 'arrowclosed' },
}));
```

Import this mock in any test file that renders graph nodes.

#### Backend Tests (`ee/backend/routes/__tests__/security-api.test.ts`) -- 17 tests

Tests 1-5 (Semgrep/TruffleHog Parsing):

1. Parse valid Semgrep JSON output into `project_semgrep_findings` rows with `extraction_run_id` and sanitized metadata (no `source`/`fix` fields)
2. Parse valid TruffleHog JSONL output into `project_secret_findings` rows with conservatively redacted values (secrets < 20 chars show `****`)
3. Handle empty/missing Semgrep output gracefully (0 findings, no error)
4. Handle malformed TruffleHog output (skip invalid lines, log warning)
5. Re-extraction upserts new findings; stale findings only deleted during post-pipeline finalization (not mid-pipeline)

Tests 6-10 (Vulnerability Detail API):

1. `GET /api/.../vulnerabilities/:osvId/detail` returns full detail with affected deps, files, version candidates, and timeline events
2. Returns 404 for non-existent vulnerability
3. Suppress vulnerability sets `suppressed = true`, `suppressed_by`, `suppressed_at`
4. Accept risk sets `risk_accepted`, `risk_accepted_by`, `risk_accepted_at`, `risk_accepted_reason`
5. Suppressed vulnerabilities excluded from default queries (included with `?include_suppressed=true`)

Tests 11-12 (Timeline Events):

1. New vulnerability detected during extraction triggers `project_vulnerability_events` insert with `detected` type
2. Vulnerability resolved (no longer in scan) triggers `resolved` event

Tests 13-17 (Hardening):

1. `Raw` field is stripped from TruffleHog JSON before Supabase Storage upload
2. Duplicate `detected` events are not created on QStash retry (idempotency check skips if event exists within 1 hour)
3. Version candidates with banned versions are stored with `is_org_banned = true`
4. Suppress/unsuppress/accept-risk/unaccept-risk return 403 for users without `manage_projects` or `manage_teams_and_projects` permission
5. `GET /api/.../secret-findings` returns 403 for users without `manage_projects` or `manage_teams_and_projects` permission

#### Frontend Tests -- 4 files, 51 tests

`**frontend/src/components/security/__tests__/security-nodes.test.tsx**` (12 tests)

Tests 1-6 (Node Enrichment):

1. Vulnerability node renders Depscore badge, EPSS, KEV indicator, reachability icon, fix available
2. Dependency node renders severity count breakdown and worst depscore
3. Center node renders security issue counts (vulns + code issues + secrets)
4. All three node types show pointer cursor and respond to clicks
5. Clicking a vulnerability node opens VulnerabilityDetailContent inside SecuritySidebar
6. Clicking a dependency node opens DependencySecurityContent inside SecuritySidebar

Tests 7-12 (Depscore-based Coloring):

1. Vulnerability node border color matches Depscore bracket (75-100=red, 40-74=orange, 0-39=gray)
2. Dependency node border reflects worst Depscore of child vulns
3. Project center node glow reflects worst Depscore across all child deps
4. Edge colors match target vulnerability Depscore bracket
5. When Depscore data is unavailable, coloring falls back to severity-based
6. Team node (org graph) reflects worst Depscore across child projects

`**frontend/src/components/security/__tests__/security-filters.test.tsx**` (6 tests)

1. Severity filter hides/dims nodes that don't match
2. Depscore threshold filter works correctly
3. CISA KEV toggle shows only KEV-listed vulnerabilities
4. Multiple simultaneous filters combine correctly (AND logic)
5. Filter state persists in URL search params
6. "Clear all" resets all filters

`**frontend/src/components/security/__tests__/security-sidebars.test.tsx**` (17 tests)

Tests 19-24 (Core Sidebar Behavior):

1. Vulnerability detail content renders all sections with correct data
2. "Explain with Aegis" button is rendered but disabled with tooltip
3. Dependency sidebar shows vulnerability list sorted by Depscore
4. Project security content shows Semgrep findings and TruffleHog findings
5. Only one sidebar content is open at a time (switching node types closes current via SecuritySidebar wrapper)
6. Suppress/Accept Risk actions update UI immediately

Tests 25-28 (Banned Version Integration):

1. Recommended version in Vuln Detail content skips banned versions, shows next-best
2. If only safe version is banned, sidebar shows "banned by your organization" explanation
3. "Fix with AI" button rendered but disabled (Phase 6C/7 dependency)
4. Dependency Security content shows red "Banned" badge on banned recommended versions

Tests 29-35 (Hardening):

1. Empty state renders when project has 0 vulnerabilities
2. Secret findings section shows "Requires project management permission" for users without `manage_projects`
3. "Unsuppress" button shown when vuln is suppressed; "Suppress" shown when not
4. "Revoke Acceptance" button shown when risk is accepted; "Accept Risk" shown when not
5. Version candidate shows "Last verified X hours ago" when `verified_at` is older than 48 hours
6. Version candidate shows amber "May be outdated" badge when `verified_at` is older than 7 days
7. Secret findings with `is_current = true` do NOT show "Rotate credential" message (negative case of test 36)

Test 36 (Secret Finding Safety):

1. Secret findings with `is_current = false` show "Rotate credential" guidance instead of remediation button

`**frontend/src/components/security/__tests__/security-org-team.test.tsx**` (5 tests)

1. Org Security page uses Depscore-based coloring on all nodes
2. Ungrouped projects connect directly to org node (no "No team" intermediary)
3. Team Security page shows aggregated security counts (vulns + code issues + secrets)
4. Asset tier filter works on org Security page
5. Org security summary endpoint data renders correctly in center nodes (uses aggregate endpoint)

### Frontend API client additions

The following API functions must be added to [api.ts](frontend/src/lib/api.ts) as part of this phase:

- `getProjectSemgrepFindings(orgId, projectId, page?, perPage?)` -- calls `GET /api/organizations/:orgId/projects/:projectId/semgrep-findings` with pagination
- `getProjectSecretFindings(orgId, projectId, page?, perPage?)` -- calls `GET /api/organizations/:orgId/projects/:projectId/secret-findings` with pagination
- `getVulnerabilityDetail(orgId, projectId, osvId)` -- calls `GET /api/organizations/:orgId/projects/:projectId/vulnerabilities/:osvId/detail`
- `suppressVulnerability(orgId, projectId, osvId)` -- calls `PATCH .../vulnerabilities/:osvId/suppress`
- `unsuppressVulnerability(orgId, projectId, osvId)` -- calls `PATCH .../vulnerabilities/:osvId/unsuppress`
- `acceptVulnerabilityRisk(orgId, projectId, osvId, reason)` -- calls `PATCH .../vulnerabilities/:osvId/accept-risk`
- `unacceptVulnerabilityRisk(orgId, projectId, osvId)` -- calls `PATCH .../vulnerabilities/:osvId/unaccept-risk`
- `getDependencySecuritySummary(orgId, projectId, depId)` -- calls `GET /api/organizations/:orgId/projects/:projectId/dependencies/:depId/security-summary`
- `getProjectVersionCandidates(orgId, projectId, packageName?, page?, perPage?)` -- calls version candidates endpoint with pagination
- `getOrgSecuritySummary(orgId)` -- calls `GET /api/organizations/:orgId/security-summary`
- `getTeamSecuritySummary(orgId, teamId)` -- calls `GET /api/organizations/:orgId/teams/:teamId/security-summary`

