---
name: Phase 4 - Policy-as-Code Engine
overview: Org-defined statuses, isolated-vm sandbox, split policy editors, git-like policy versioning.
todos:
  - id: phase-4-policy
    content: "Phase 4: Policy-as-Code Engine + Custom Statuses - Org-defined statuses, isolated-vm sandbox with fetch(), split policy editors, status badges, git-like policy versioning with AI merge, org propagation, full test suite"
    status: pending
isProject: false
---
## Phase 4: Policy-as-Code Engine + Custom Statuses

**Goal:** Implement sandboxed policy execution with org-defined custom statuses. Instead of binary compliant/non-compliant, organizations define their own project statuses (e.g., "Safe", "Blocked", "Under Review") and policy code determines which status each project gets.

### 4A: Custom Status System

#### New `organization_statuses` table

- `id` UUID primary key
- `organization_id` UUID (FK)
- `name` TEXT (e.g., "Compliant", "Non-Compliant", "Under Review", "Blocked")
- `color` TEXT (hex color for badge, e.g., "#22c55e")
- `rank` INTEGER (lower = better. Used for ordering and "worst status wins" logic)
- `description` TEXT (nullable)
- `is_system` BOOLEAN (true for the 2 required statuses - can rename/recolor but not delete)
- `is_passing` BOOLEAN (whether this status counts as "passing" for GitHub Check Runs and compliance metrics)
- `created_at`, `updated_at`

**Seed statuses** on org creation:

- "Compliant" (color: green, rank: 1, is_system: true, is_passing: true)
- "Non-Compliant" (color: red, rank: 100, is_system: true, is_passing: false)

Orgs can add unlimited custom statuses between these: "Under Review" (yellow, rank: 50, is_passing: false), "Blocked" (red, rank: 90, is_passing: false), "Approved Exception" (blue, rank: 10, is_passing: true), etc.

#### New "Statuses" tab in Organization Settings

- New section in [OrganizationSettingsPage.tsx](frontend/src/app/pages/OrganizationSettingsPage.tsx)
- **UI pattern**: Follow the existing Roles table pattern in the same page
- Table columns: drag handle, color badge preview, name, description, passing/failing indicator, actions (edit/delete)
- System statuses show a lock icon, edit allowed (name/color) but delete disabled
- "Add Status" button opens inline form: name, color picker, description, is_passing toggle
- Drag-to-reorder updates `rank` values (same pattern as roles)
- **New permission**: `manage_statuses` added to the RBAC system (new role permission alongside existing ones like `manage_compliance`)

#### Replace `projects.is_compliant` and `projects.status`

- Add `projects.status_id` UUID (FK to `organization_statuses`) - replaces both `is_compliant` and the legacy `status` TEXT field
- Add `projects.status_violations` TEXT[] (array of violation messages from last policy run)
- Deprecate `projects.is_compliant` (keep for backward compat, derive from `organization_statuses.is_passing`)
- Add `projects.policy_evaluated_at` TIMESTAMPTZ (when policy was last run)

#### Status badges on project/team cards

- [ProjectsPage.tsx](frontend/src/app/pages/ProjectsPage.tsx): Replace "COMPLIANT"/"NOT COMPLIANT" labels with status badge (color + name from `organization_statuses`)
- [TeamProjectsPage.tsx](frontend/src/app/pages/TeamProjectsPage.tsx): Same replacement
- Team cards in org/team screens: Show aggregate (e.g., "3 Compliant, 1 Blocked")
- [CompliancePage.tsx](frontend/src/app/pages/CompliancePage.tsx): Replace binary counts with per-status breakdown

#### Status filter dropdown

- Add filter-by-status dropdown in project listing screens (styled like the existing filter dropdowns in the dependencies tab)
- Multi-select: filter projects by one or more statuses
- Show status color dot next to each option
- Works in: org projects page, team projects page, compliance page

#### Customizable Asset Tiers

New `organization_asset_tiers` table:

- `id` UUID primary key
- `organization_id` UUID (FK)
- `name` TEXT (e.g., "Crown Jewels", "External", "Internal", "Non-Production")
- `description` TEXT (nullable)
- `color` TEXT (hex color for badge)
- `rank` INTEGER (lower = more critical, for ordering)
- `is_system` BOOLEAN (true for the 4 defaults - can rename/recolor but not delete)
- `environmental_multiplier` DECIMAL (used in Depscore calculation, e.g., 1.5 for Crown Jewels, 0.6 for Non-Production)
- `created_at`, `updated_at`

**Seed tiers** on org creation:

- "Crown Jewels" (color: red, rank: 1, multiplier: 1.5, is_system: true)
- "External" (color: orange, rank: 2, multiplier: 1.2, is_system: true)
- "Internal" (color: blue, rank: 3, multiplier: 1.0, is_system: true)
- "Non-Production" (color: gray, rank: 4, multiplier: 0.6, is_system: true)

Orgs can add custom tiers (e.g., "Regulatory" with multiplier 1.8, "Sandbox" with multiplier 0.3).

**Replace** `projects.asset_tier` TEXT -> `projects.asset_tier_id` UUID (FK to `organization_asset_tiers`).

**"Asset Tiers" sub-tab** in the Statuses tab of org settings:

- Table columns: drag handle, color badge, name, description, multiplier value, actions (edit/delete)
- System tiers show a lock icon, edit allowed (name/color/multiplier) but delete disabled
- "Add Tier" button opens inline form: name, color picker, description, multiplier input
- Drag-to-reorder updates `rank` values
- When deleting a custom tier: dialog to reassign projects using that tier to another tier
- **New permission**: reuse `manage_statuses` for tier management (or add `manage_tiers` if separate control needed)

**Tier badges** on project cards: Show the tier name with its color, alongside the status badge.

**Tier filter dropdown**: Add filter-by-tier in project listing screens (same pattern as status filter).

#### Single Package Policy with Tier Context

The org defines ONE package policy code block (not per-tier). The policy function receives the project's asset tier as `context.tier`, allowing tier-aware logic within a single code block. This simplifies the architecture:

- No `organization_tier_policies` table needed - the single `package_policy_code` lives in its own table (see 4B)
- One Monaco editor for the Package Policy (no tier selector needed)
- Tier changes don't cause git-like versioning conflicts (the base code is the same for all tiers)
- Admins see the full policy in one place, including how different tiers are handled

**How project-level overrides work:**

- Project has `asset_tier_id` = Crown Jewels
- Org has a single `package_policy_code` that handles all tiers via `context.tier`
- Project can override with `effective_package_policy_code` (overrides the org's single package policy)
- If project's tier changes: the SAME code re-runs with the new `context.tier` value - no conflicts, no base code mismatch

#### Tier Change Cascade

When a project's asset tier is changed (e.g., Crown Jewels -> Non-Production), the following re-evaluation chain runs automatically:

1. **Re-run Package Policy** for all deps: same code, but `context.tier` now reflects the new tier
2. **Recalculate Depscores** for all vulnerabilities: new `environmental_multiplier` from the new tier
3. **Re-run Project Status**: deps have updated `policyResult` values + updated depscores
4. **Update project**: `status_id`, `status_violations`, `policy_evaluated_at`

No git-like versioning conflicts arise from tier changes because the base code is org-wide (not tier-specific).

#### Phase 4 Permissions

**Org-level permissions:**

- `manage_compliance` (existing): Edit org Package Policy, Status Code, PR Check Code. Accept/reject project policy change requests. Re-align projects after org policy update. Auto-accept "Apply for Exception" license changes.
- `manage_statuses` (new): CRUD on custom statuses AND asset tiers (closely related concepts, shared permission).

**Project-level access** (follows existing settings access model - owner team, org admin/owner, `manage_teams_and_projects`, or `manage_projects` on the owner team):

- Change a project's asset tier
- Click "Re-evaluate Policy"
- Request a project-level policy change (opens the code editor)

**Any project member** (even viewers):

- Use preflight check ("Check a Package")
- Click "Apply for Exception" on a license issue: creates a `project_policy_changes` record with `is_ai_generated = true`. If the user has org `manage_compliance`, the change is auto-created and auto-accepted (with a conflict check - if another change was accepted between page load and click, the AI merge suggestion is shown instead of blind auto-accept). If the user lacks `manage_compliance`, the change stays as pending for review.

**Visibility:**

- Org Settings Change History tabs: visible to users with `manage_compliance`
- Project-level policy info (in Compliance tab "Project" subtab): visible to any project member
- When a change is accepted or rejected, the author is notified (hooks into the notification system from Phase 9)

### 4B: Policy-as-Code Execution Engine

#### Sandbox architecture: `isolated-vm` with controlled `fetch()`

**Install**: `npm install isolated-vm` in the backend

**Create `ee/backend/lib/policy-engine.ts`:**

- Create V8 Isolate with 256MB memory limit
- Timeout: 30 seconds (increased from original 5s to allow external API calls)
- Inject a controlled `fetch()` function that proxies through the host Node.js process
  - The `fetch()` inside the sandbox calls back to the host via `isolated-vm` reference
  - Host performs the actual HTTP request (using Node.js `fetch`)
  - No URL restrictions (trust the org admin)
  - Individual fetch timeout: 10 seconds
  - Log all external API calls for audit trail
- Inject helper functions available in the sandbox:
  - `isLicenseAllowed(license, allowList)` - license matching utility
  - `isLicenseBanned(license, banList)` - inverse check
  - `semverGt(a, b)` / `semverLt(a, b)` - version comparison
  - `daysSince(dateString)` - age calculation (useful for maintenance checks)

#### Split policy code storage (3 separate tables)

Instead of storing all code blocks as columns on `organization_policies`, each code type gets its own dedicated table. This provides cleaner separation, independent RLS policies, and room for per-type metadata.

`**organization_package_policies` table:**

- `id` UUID primary key
- `organization_id` UUID (FK, UNIQUE)
- `package_policy_code` TEXT
- `updated_at` TIMESTAMPTZ
- `updated_by_id` UUID (FK to users)

`**organization_status_codes` table:**

- `id` UUID primary key
- `organization_id` UUID (FK, UNIQUE)
- `project_status_code` TEXT
- `updated_at` TIMESTAMPTZ
- `updated_by_id` UUID (FK to users)

`**organization_pr_checks` table:**

- `id` UUID primary key
- `organization_id` UUID (FK, UNIQUE)
- `pr_check_code` TEXT
- `updated_at` TIMESTAMPTZ
- `updated_by_id` UUID (FK to users)

Each table has one row per org. Seeded on org creation with default code. The old `organization_policies.policy_code` column is deprecated and migrated out.

Each code block is fully independent - different purpose, different context, different execution timing.

#### Policy Code Validation (on save - blocks save on failure)

**Endpoint:** `POST /api/organizations/:id/validate-policy` with `{ codeType, tierIdIfPackagePolicy, code }`

Reuses the same `isolated-vm` sandbox as production execution. Three checks run sequentially; save is blocked if any check fails.

**Check 1 - Syntax Compilation:**

- Compile the code in `isolated-vm`. If syntax error, return the error with line number.
- Result: `{ pass: true }` or `{ pass: false, error: "SyntaxError at line 12: Unexpected token '}'" }`

**Check 2 - Shape Validation (test run with sample data):**

- Generate a realistic sample context: a few mock deps (one with banned license, one malicious, one clean)
- Execute the function against the sample context
- Validate the return value shape:
  - Package Policy: must return `{ allowed: boolean, reasons: string[] }` (both fields required, correct types)
  - Status Code / PR Check: must return `{ status: string, violations: string[] }` where `status` matches a defined org status name
- Common failures caught: returning `undefined` (forgot return statement), returning `{ pass: true }` instead of `{ allowed: true }`, returning a status name that doesn't exist (with fuzzy suggestion: "Did you mean 'Blocked'?")

**Check 3 - Fetch Resilience (BLOCKS SAVE if fails):**

- Only runs if code contains `fetch(`
- **Pass 1**: Run with fetch mocked to succeed (returns `{ ok: true, json: () => ({}) }`) - verify the code works with a healthy API
- **Pass 2**: Run with fetch mocked to throw `new Error('Network request failed')` - simulate API down
- If Pass 2 throws an unhandled error: **save is blocked**. Error message: "Your code calls fetch() but crashes when the API is unreachable. Wrap fetch calls in try/catch with a fallback return value. Line N: unhandled error."
- If Pass 2 returns a valid shape: pass (the code handles failures gracefully)

**Validation output format (displayed in editor):**

```
[pass] Syntax: Valid JavaScript
[pass] Shape: Returns { allowed: boolean, reasons: string[] }
[pass] Test run: Returned { allowed: true, reasons: [] } for sample data
[fail] Fetch resilience: Code crashes when fetch() fails (line 5: TypeError: Cannot read property 'json' of undefined).
       Wrap fetch calls in try/catch. Save blocked.
```

On all checks passing, the code is saved. On any failure, the code is NOT saved and the validation results are shown inline in the editor with the specific error.

**Additional validation edge cases:**

- **Validation timeout**: Each validation check runs with a 5-second timeout (shorter than the 30s production timeout). Infinite loops during validation are caught early with error: "Policy code timed out during validation (5s limit)."
- **Deep type checking**: The shape check validates types recursively - `reasons` must be `string[]` (an actual array of strings), not just truthy. `{ allowed: true, reasons: "not an array" }` fails with: "Expected `reasons` to be string[], got string."
- **Function name validation**: The sandbox verifies the expected function name exists (`packagePolicy`, `projectStatus`, or `pullRequestCheck`). If the user writes `function myPolicy(ctx)` instead, error: "Expected function `packagePolicy` to be defined. Found: `myPolicy`."
- **Async handling**: `isolated-vm` requires explicit async support. If the code uses `fetch()` with `await`, the sandbox must resolve the `ivm.Reference` callback pattern. The engine wraps the function call to handle both sync and async returns transparently.
- **Empty/whitespace code**: Rejected immediately with "Policy code cannot be empty" - no sandbox execution needed.

#### Null/empty policy defaults

When a policy code table row exists but the code column is null/empty (or the row doesn't exist):

- `**package_policy_code`** is null/empty: All packages are allowed (`{ allowed: true, reasons: [] }`). No `packagePolicy()` runs.
- `**project_status_code`** is null/empty: Project defaults to the highest-ranked passing status (typically "Compliant"). No `projectStatus()` runs.
- `**pr_check_code`** is null/empty: All PRs pass. No `pullRequestCheck()` runs.
- **Zero dependencies** after extraction: `packagePolicy()` doesn't run (no deps to check). `projectStatus()` receives an empty `dependencies` array and should return "Compliant" (the default templates handle this).

**Sample test contexts** (generated per code type):

- Package Policy: `{ dependency: { name: "test-pkg", version: "1.0.0", license: "MIT", dependencyScore: 75, ... }, tier: { name: "Internal", rank: 3, multiplier: 1.0 } }`
- Status Code: `{ project: { name: "test", tier: { name: "Internal", rank: 3, multiplier: 1.0 } }, dependencies: [...5 mock deps with policyResults and vulns...], statuses: [...org statuses...] }`
- PR Check: `{ project: { name: "test", tier: { name: "Internal", rank: 3, multiplier: 1.0 } }, added: [...2 mock new deps...], updated: [...1 mock updated dep...], removed: [...1 mock removed...], statuses: [...] }`

#### When the policy chain runs (4 triggers)

1. **After extraction completes** (primary): All data is fresh. Run packagePolicy on every dep, store results, run projectStatus. The policy evaluation itself is fast (ms per dep in isolated-vm) - the expensive part is extraction.
2. **"Re-evaluate Policy" button click**: Re-runs the policy chain against existing DB data. No re-extraction. Just load -> evaluate -> update.
3. **Policy change accepted**: Automatically re-runs against existing data so the new policy takes effect immediately.
4. **Preflight check**: Runs packagePolicy on a single hypothetical dep. Instant. Some fields unavailable (reachability, filesImportingCount, isOutdated) - set to null in preflight context, noted in UI.

For triggers 2-4, the underlying data (vuln scan, reachability, scores) is NOT recalculated - only the policy functions re-run against what's already in the DB.

#### Data assembly (no denormalization)

**For Package Policy** (package-level + tier context):

```sql
SELECT pd.dependency_id, d.name, d.version, d.license, d.openssf_score,
       d.weekly_downloads, d.last_published_at, d.releases_last_12_months,
       dv.malicious_indicator, dv.slsa_level,
       d.registry_integrity_status, d.install_scripts_status, d.entropy_analysis_status,
       d.score AS dependency_score,
       oat.name AS tier_name, oat.rank AS tier_rank, oat.environmental_multiplier AS tier_multiplier
FROM project_dependencies pd
JOIN dependencies d ON pd.dependency_id = d.id
JOIN dependency_versions dv ON pd.dependency_version_id = dv.id
JOIN projects p ON pd.project_id = p.id
JOIN organization_asset_tiers oat ON p.asset_tier_id = oat.id
WHERE pd.project_id = $1
```

The tier info is the same for all deps in a project (fetched once, passed to each `packagePolicy()` call). Results are cacheable per-org: same package + same tier = same result.

**For Project Status** (enriched with project-specific data):

```sql
SELECT pd.*, d.name, d.version, d.license, d.score AS dependency_score,
       pd.is_direct, pd.is_dev_dependency, pd.files_importing_count,
       pd.is_outdated, pd.versions_behind, pd.policy_result,
       p.name AS project_name, oat.name AS tier_name, oat.rank AS tier_rank
FROM project_dependencies pd
JOIN dependencies d ON pd.dependency_id = d.id
JOIN projects p ON pd.project_id = p.id
JOIN organization_asset_tiers oat ON p.asset_tier_id = oat.id
WHERE pd.project_id = $1
```

Plus vulnerabilities from `project_dependency_vulnerabilities` (depscore, is_reachable, epss_score, cisa_kev, etc.).

The ONLY thing persisted back from Package Policy: `project_dependencies.policy_result` JSONB = `{ allowed: boolean, reasons: string[] }`.

#### Execution flow

```
Extraction completes (or re-evaluate / policy change / tier change triggers)
    |
    v
1. Load project's tier info (name, rank, multiplier from organization_asset_tiers)
2. Get package_policy_code (project's effective_package_policy_code if overridden, else from organization_package_policies)
3. Load all deps for project (package-level query)
4. For EACH dep: run packagePolicy() in isolated-vm with { dependency, tier }
   -> Write { allowed, reasons } to project_dependencies.policy_result
    |
    v
5. Get project_status_code (project's effective_project_status_code if overridden, else from organization_status_codes)
6. Load project-specific data (isDirect, isDevDep, vulns with reachability, etc.)
7. Build projectStatus context: all deps with policyResult + project-specific data
8. Run projectStatus() in isolated-vm
   -> Write status_id + violations to projects table
```

For PR checks:

```
PR webhook fires
    |
    v
1. Diff lockfiles to identify added/updated/removed deps
2. For each added/updated: look up package data from registry/DB, run packagePolicy()
3. Build pullRequestCheck context with policyResult per dep
4. Run pullRequestCheck() in isolated-vm
   -> Return status, map to GitHub pass/fail via is_passing
```

#### Function signatures

**Package Policy function** (stored in `organization_package_policies.package_policy_code`) - runs per-dependency, receives package data + tier context:

```javascript
function packagePolicy(context) {
  // context.dependency (package-level, from dependencies + dependency_versions):
  //   name, version, license,
  //   openSsfScore (0-10), weeklyDownloads, lastPublishedAt, releasesLast12Months,
  //   dependencyScore (0-100 reputation),
  //   maliciousIndicator (object|null: { source, confidence, reason }),
  //   slsaLevel (0-4),
  //   registryIntegrityStatus, installScriptsStatus, entropyAnalysisStatus ("pass"|"warning"|"fail")
  //
  // context.tier: { name, rank, multiplier } (from organization_asset_tiers via the project)
  // context.fetch: async function for external API calls
  // Returns: { allowed: boolean, reasons: string[] }
  //
  // NO project-specific data (no isDirect, isDevDependency, reachability, vulns).
  // NO vulnerability data - that belongs in the Status Code.
  // Same package + same tier = same result (cacheable per org).

  if (context.dependency.maliciousIndicator) {
    return { allowed: false, reasons: ['Package flagged as malicious'] };
  }

  if (context.tier.rank <= 2) { // Crown Jewels or External (critical tiers)
    const BANNED = ['GPL-3.0', 'AGPL-3.0'];
    if (BANNED.some(b => context.dependency.license?.includes(b)))
      return { allowed: false, reasons: [`Banned license for ${context.tier.name}: ${context.dependency.license}`] };
    if (context.dependency.dependencyScore < 40)
      return { allowed: false, reasons: [`Low score for ${context.tier.name}: ${context.dependency.dependencyScore}`] };
    if (context.dependency.slsaLevel < 1)
      return { allowed: false, reasons: [`No SLSA provenance for ${context.tier.name} project`] };
  }

  if (context.tier.rank === 3) { // Internal
    if (context.dependency.license?.includes('AGPL'))
      return { allowed: false, reasons: ['AGPL not allowed for Internal projects'] };
  }

  // Non-Production: only block malicious (already handled above)
  return { allowed: true, reasons: [] };
}
```

**Project Status function** (stored in `organization_status_codes.project_status_code`) - runs per-project with all project-specific data:

```javascript
function projectStatus(context) {
  // context.project: { name, tier: { name, rank, multiplier }, teamName }
  // context.statuses: ['Compliant', 'Non-Compliant', 'Under Review', ...] (available status names)
  // context.fetch: async function for external API calls
  //
  // context.dependencies: [{
  //   -- Package-level --
  //   name, version, license, dependencyScore,
  //   -- Package Policy result --
  //   policyResult: { allowed, reasons },
  //   -- Project-specific (from project_dependencies) --
  //   isDirect, isDevDependency, filesImportingCount, isOutdated, versionsBehind,
  //   -- Vulnerabilities (from project_dependency_vulnerabilities) --
  //   vulnerabilities: [{ osvId, severity, cvssScore, epssScore, depscore,
  //                       isReachable, cisaKev, fixedVersions, summary }]
  // }]

  const violations = [];
  const blocked = context.dependencies.filter(d => !d.policyResult.allowed);
  const reachableCritical = context.dependencies.filter(d =>
    d.vulnerabilities.some(v => v.severity === 'critical' && v.isReachable)
  );

  if (blocked.length > 0) {
    violations.push(...blocked.map(d => `${d.name}: ${d.policyResult.reasons.join(', ')}`));
  }
  if (reachableCritical.length > 0) {
    violations.push(...reachableCritical.map(d => `${d.name}: reachable critical vulnerability`));
  }

  if (blocked.length > 5 || reachableCritical.length > 0) return { status: 'Blocked', violations };
  if (blocked.length > 0) return { status: 'Under Review', violations };
  return { status: 'Compliant', violations: [] };
}
```

**PR Check function** (stored in `organization_pr_checks.pr_check_code`) - runs per-PR with package policy results:

```javascript
function pullRequestCheck(context) {
  // context.project: { name, tier: { name, rank, multiplier } }
  // context.added: [{ ..., policyResult: { allowed, reasons } }]
  // context.updated: [{ ..., policyResult: { allowed, reasons } }]
  // context.removed: [{ name, version }]
  // context.statuses: available status names
  // context.fetch: for external API calls

  const newViolations = [...context.added, ...context.updated].filter(d => !d.policyResult.allowed);
  if (newViolations.length > 0) {
    return { status: 'Blocked', violations: newViolations.map(d => `${d.name}: ${d.policyResult.reasons.join(', ')}`) };
  }
  return { status: 'Compliant', violations: [] };
}
```

The engine maps the returned `status` name to the org's `organization_statuses` table, then uses `is_passing` to translate to GitHub Check Run pass/fail.

#### Default policy templates

Seed on org creation with sensible defaults (one row per table):

`**organization_package_policies**`: Single code block with tier-aware logic:

- Block malicious packages for all tiers
- Crown Jewels / External (rank <= 2): Block GPL/AGPL, require score >= 40, require SLSA >= 1
- Internal (rank 3): Block AGPL only
- Non-Production (rank 4+): Only block malicious (already handled)
- (See the default `packagePolicy()` function in the signature section above)

`**organization_status_codes**`: "Blocked" if any reachable critical vulns or >5 disallowed deps, "Under Review" if 1-5 disallowed, "Compliant" if clean

`**organization_pr_checks**`: Block PRs that introduce disallowed packages or new critical vulnerabilities

#### Wire into extraction pipeline

In [pipeline.ts](backend/extraction-worker/src/pipeline.ts), after dependency upsert and vuln scan:

1. Load project's tier info (`name`, `rank`, `multiplier`) from `organization_asset_tiers` via `projects.asset_tier_id`
2. Fetch `package_policy_code` from `projects.effective_package_policy_code` (if overridden) or `organization_package_policies`
3. For EACH dependency: run `packagePolicy()` in sandbox with `{ dependency, tier }`, store `policyResult` on `project_dependencies.policy_result` JSONB
4. Fetch `project_status_code` from `projects.effective_project_status_code` (if overridden) or `organization_status_codes`
5. Build project status context: all deps with their `policyResult` embedded + project-specific data
6. Execute `projectStatus()` in sandbox with enriched context
7. If valid status returned: update `projects.status_id` and `projects.status_violations`
8. If policy error (syntax, runtime, timeout, invalid status name): set status to "Non-Compliant" with violation message explaining the policy error
9. Log results to `extraction_logs`

#### Wire into PR handler

In [handlePullRequestEvent](ee/backend/routes/integrations.ts):

1. For each added/updated dependency in the PR: run `packagePolicy()` to get per-dep `policyResult`
2. Build PR context with `policyResult` embedded on each dep
3. Execute `pullRequestCheck()` with enriched diff context
4. Map returned status to pass/fail using `is_passing`
5. Include status name + violations in GitHub Check Run output
6. Show specific status in the PR tab of the compliance page (not just pass/fail)

### 4C: Update Frontend - Code Editors and Org Settings Layout

The three code blocks live in two different org settings tabs:

**Policies tab** (sub-tabs: "Package Policy", "Pull Request Check", "Change History"):

- "Package Policy" sub-tab: Single Monaco editor for the org's one `package_policy_code`:
  - Context autocomplete for `context.dependency` fields: name, version, license, dependencyScore, openSsfScore, weeklyDownloads, lastPublishedAt, releasesLast12Months, maliciousIndicator, slsaLevel, registryIntegrityStatus, installScriptsStatus, entropyAnalysisStatus
  - Context autocomplete for `context.tier` fields: name, rank, multiplier (from the project's asset tier)
  - `fetch()` in autocomplete
  - Helper functions in autocomplete (`isLicenseAllowed`, `semverGt`, `daysSince`)
  - "Test Policy" button: pick a project, runs packagePolicy on each dep with that project's tier context, shows per-dep allowed/not results
  - **On save: 3-step validation** (syntax -> shape -> fetch resilience) from the validation endpoint in 4B. Results shown inline below the editor. Save blocked on any failure. See 4B "Policy Code Validation" for details.
- "Pull Request Check" sub-tab: Monaco editor for `pr_check_code`, with:
  - Context autocomplete for `context.added`, `context.updated`, `context.removed` (each dep includes `policyResult` + project-specific data like isDirect, vulns with reachability)
  - Status names in autocomplete
  - "Test" button: simulates a PR check against a project's current data
- "Change History" sub-tab: Table of all package policy + PR check change requests across all projects (filterable by code type and project)

**Statuses tab** (sub-tabs: "Statuses", "Asset Tiers", "Status Code", "Change History"):

- "Statuses" sub-tab: The custom status management table from Phase 4A (drag-to-reorder, add/edit/delete)
- "Asset Tiers" sub-tab: Custom tier management table (drag-to-reorder, add/edit/delete, multiplier input, color picker). System tiers locked from deletion.
- "Status Code" sub-tab: Monaco editor for `project_status_code`, with:
  - Context autocomplete for `context.dependencies[].policyResult` (package policy results embedded)
  - Context autocomplete for project-specific dep data: `isDirect`, `isDevDependency`, `filesImportingCount`, `isOutdated`, `versionsBehind`
  - Context autocomplete for `context.dependencies[].vulnerabilities[]`: severity, cvssScore, epssScore, depscore, isReachable, cisaKev
  - Context autocomplete for `context.project.tier`: name, rank, multiplier
  - Status names in autocomplete (from the Statuses sub-tab)
  - `fetch()` in autocomplete
  - "Test" button: pick a project, runs the full chain (packagePolicy per dep -> projectStatus), shows result
- "Change History" sub-tab: Table of all status code change requests across all projects (filterable by project)

Each code editor reuses the existing [PolicyCodeEditor.tsx](frontend/src/components/PolicyCodeEditor.tsx) component with different context definitions and autocomplete configs.

Update [PolicyAIAssistant.tsx](frontend/src/components/PolicyAIAssistant.tsx):

- AI assistant appears in all three code editors
- Knows which code type is being edited and adjusts suggestions accordingly
- Package Policy suggestions: "Block a license", "Flag low-score packages", "Add tier-specific rules", "Check external approval API"
- Status Code suggestions: "Threshold-based status assignment", "Custom status for dev-only violations"
- PR Check suggestions: "Block PRs with malicious packages", "Require minimum OpenSSF score for new deps"

#### Update policy documentation

Update the docs in [DocsPage.tsx](frontend/src/app/pages/DocsPage.tsx) `PoliciesContent()` - covered in Phase 12B:

- Document all three function signatures (`packagePolicy`, `projectStatus`, `pullRequestCheck`)
- Document the execution flow (package policy runs first, results feed into status + PR check)
- Document available context fields for each function type
- Document `fetch()` for external API calls with examples
- Document helper functions
- Document the custom status system
- Document how statuses map to GitHub Check Runs

### 4D: Git-like Policy Versioning System

Replace the simple accept/reject/revoke exception model with a git-inspired "commit chain" system. Project policies can deviate from the org policy like branches deviate from main, with full change history and revert capabilities.

#### New `project_policy_changes` table (replaces `project_policy_exceptions`)

- `id` UUID primary key
- `project_id` UUID (FK)
- `organization_id` UUID (FK)
- `code_type` TEXT ('package_policy' | 'project_status' | 'pr_check') - which code block this change applies to
- `author_id` UUID (FK - who requested the change)
- `reviewer_id` UUID (nullable FK - who accepted/rejected)
- `parent_id` UUID (nullable FK to self - previous accepted change of the SAME code_type for the SAME project)
- `base_code` TEXT (snapshot of the effective code for this code_type when this change was authored)
- `proposed_code` TEXT (the full code after this change)
- `message` TEXT (reason for the change, e.g., "Allow MIT license for internal tools")
- `status` TEXT ('pending', 'accepted', 'rejected')
- `is_ai_generated` BOOLEAN (true when created by one-click license exception)
- `ai_merged_code` TEXT (nullable - AI's suggested merged code when conflict detected)
- `has_conflict` BOOLEAN (true when `base_code` doesn't match current effective code at review time)
- `created_at` TIMESTAMPTZ
- `reviewed_at` TIMESTAMPTZ (nullable)

Each code type has its own independent commit chain per project. A project can override just the Package Policy while inheriting Status Code and PR Check from the org.

#### Project policy storage (3 independent overrides)

- Add `projects.effective_package_policy_code` TEXT (nullable) - null = inherited from org's `package_policy_code`
- Add `projects.effective_project_status_code` TEXT (nullable) - null = inherited from org's `project_status_code`
- Add `projects.effective_pr_check_code` TEXT (nullable) - null = inherited from org's `pr_check_code`
- Each is independently nullable: a project can override just one while inheriting the others
- Remove old exception fields: `projects.has_active_exception`, `projects.exception_status_id`
- Drop `project_policy_exceptions` table (replaced by `project_policy_changes`)

#### How the commit chain works

Each code type has its own chain. Example for Package Policy:

```
Org Package Policy (base) â† "main branch"
  â””â”€ Change #1: "Allow MIT license" [package_policy] (accepted)
       â””â”€ Change #2: "Allow ISC license" [package_policy] (accepted)
            â””â”€ Change #3: "Allow AGPL for internal" [package_policy] (pending)
```

Meanwhile Status Code and PR Check for the same project can be independently overridden or remain inherited.

**Creating a change:**

1. User opens project policy settings
2. Clicks "Request Change" -> opens the policy editor prefilled with the current effective policy
3. User modifies the code, writes a reason message
4. System saves: `base_code` = current effective policy, `proposed_code` = user's modified code
5. System checks other pending changes for this project: if any pending change modifies overlapping code, warns "This may conflict with pending change #X"

**Accepting a change (no conflict):**

1. Admin reviews the change in the relevant Change History tab (Policies tab or Statuses tab)
2. Admin sees diff: base_code vs proposed_code, with a `code_type` badge (Package Policy / Status Code / PR Check)
3. Admin clicks "Accept"
4. The corresponding effective code column is updated (e.g., `projects.effective_package_policy_code = proposed_code`)
5. `parent_id` is set to the previously accepted change of the same `code_type` (or null if first)
6. Project is re-evaluated with the new policy chain (packagePolicy per dep -> projectStatus)

**Accepting a change (conflict detected):**

1. Admin opens a pending change for review
2. System detects: this change's `base_code` doesn't match the current effective code for this `code_type` (another change was accepted since this one was authored)
3. `has_conflict` is set to true
4. **AI merge**: System calls the LLM with:
  - The org base code (for this code_type)
  - The current effective code (after previous accepted changes)
  - The pending change's proposed_code
  - Instruction: "Merge these policy changes. The current code already includes some modifications. Apply the intent of the proposed change on top of the current version."
5. AI generates `ai_merged_code` and stores it on the change record
6. Admin sees three panels: "Current Code", "Proposed Change", "AI Suggested Merge"
7. Admin can: Accept AI merge, manually edit the merge, or reject the change
8. On acceptance, the corresponding effective code column is updated (e.g., `effective_package_policy_code` = accepted code)

**Sequential acceptance (MIT + ISC example - both `code_type = 'package_policy'`):**

1. User A requests: allow MIT (base=org package policy, proposed=org+MIT) -> pending
2. User B requests: allow ISC (base=org package policy, proposed=org+ISC) -> pending
3. Admin accepts A -> `effective_package_policy_code`=org+MIT, change A accepted with parent=null
4. Admin opens B -> conflict! B's base (org) != effective (org+MIT)
5. AI merges: generates org+MIT+ISC
6. Admin accepts AI merge -> `effective_package_policy_code`=org+MIT+ISC, change B accepted with parent=A.id
7. Status Code and PR Check remain inherited from org (unaffected)

**Reverting:**

1. User views Change History for the project (filtered to a specific code type)
2. Clicks "Revert to this version" on any previous change (or "Revert to Organization Base")
3. System creates a NEW change record with the same `code_type`, `proposed_code` = that version's code (or null for org base)
4. If user has `manage_compliance`: auto-accepted immediately
5. If not: submitted as a pending change request
6. For revert to org base: the corresponding effective column is set to null (e.g., `effective_package_policy_code = null`)

#### Project Policy Settings UI

In the project's Compliance tab "Project" subtab (the Policy Source Card from 5A):

Shows a compact 3-row display for each code type:

- **Package Policy**: "Inherited from Organization" or "Custom (N changes)" with [View Diff] [Request Change] [Revert to Org] links
- **Status Code**: "Inherited from Organization" or "Custom (N changes)" with same links
- **PR Check**: "Inherited from Organization" or "Custom (N changes)" with same links

Each row has:

- A badge showing code type
- Inheritance status
- Pending changes count (if any)
- Action links (View Diff opens a modal comparing org base vs effective, Request Change opens the relevant code editor, Revert creates a revert commit)

#### Org Settings - Change History Tabs

The Change History lives in two places, one per settings tab:

**Policies tab -> "Change History" sub-tab:**

- Shows all `package_policy` and `pr_check` type changes across all projects
- Table styled like a git commit log:
  - Each row: code type badge (Package Policy / PR Check), status badge (pending/accepted/rejected), change message, project name link, author avatar + name, timestamp
  - Pending changes highlighted, sorted to top
- **Filters**: By code type, by status (Pending/Accepted/Rejected/All), by project
- Click a row -> opens the change detail view (diff, review actions)
- For pending changes with conflicts: show a "Conflict" warning badge

**Statuses tab -> "Change History" sub-tab:**

- Same layout as above but filtered to `project_status` type changes only
- Same filters (by status, by project) minus code type filter (only one type here)

#### Change History Visibility & Notifications

**Org Settings Change History** (both tabs): Only visible to users with `manage_compliance` permission. These users can see all changes across all projects, review pending changes, and take actions.

**Project-level Change History** (in the Compliance tab "Project" subtab, Policy Source Card): Visible to any project member. They can see the change history for their specific project, view diffs, and see the status of their own requests. Only users with `manage_compliance` can accept/reject from here.

**Notifications** (integrates with Phase 9 notification system):

- When a change is **accepted**: author receives notification ("Your [Package Policy] change for [Project Name] was accepted by [Reviewer]")
- When a change is **rejected**: author receives notification with rejection reason
- When a **conflict** is detected on a pending change: author receives notification ("Your pending change has a conflict - review needed")
- When an org policy is updated and projects need re-alignment: users with `manage_compliance` receive notification

#### Org Policy Propagation

When an admin updates any org-level code block (package policy, status code, or PR check):

1. After saving, check: are there projects with the corresponding effective code column not null?
2. If yes, show a dialog: "X projects have custom [Package Policy / Status Code / PR Check] that differs from the organization."
3. Dialog lists the affected projects with checkboxes
4. "Re-align Selected Projects" button: for each selected project, creates a new auto-accepted change that sets the corresponding effective code column to null (revert to org)
5. "Skip" button: leaves custom code unchanged
6. This only affects the specific code type being edited - if you update the org Package Policy, only projects with custom Package Policy are shown (Status Code and PR Check are unaffected)

### 4E: Policy-as-Code Test Suite

#### Edge case scenarios (each becomes a test):

**Policy definition lifecycle:**

1. No policy defined -> all projects get default "Compliant" status
2. New policy saved -> all projects re-evaluated on next extraction
3. Policy updated -> projects re-evaluated on next extraction (not retroactively)
4. Policy deleted (reset to empty) -> all projects get default "Compliant" status
5. Policy with syntax error saved -> policy save should fail with validation error
6. Policy returns invalid status name -> project set to "Non-Compliant" with violation "Policy returned unknown status 'xyz'"
7. Policy throws runtime error -> project set to "Non-Compliant" with violation "Policy execution error: {message}"
8. Policy times out (slow external API) -> project set to "Non-Compliant" with violation "Policy execution timed out after 30s"
9. Policy `fetch()` call returns error -> error propagated to policy code, policy handles it (or crashes -> scenario 7)
10. Policy `fetch()` call to unreachable URL -> fetch throws, policy handles or crashes

**Git-like policy change lifecycle (each test specifies `code_type`):**

1. First change requested on inherited project (`code_type='package_policy'`) -> `base_code` = org package policy, project still uses org while pending
2. Change accepted -> `projects.effective_package_policy_code` set to `proposed_code`, package policy re-runs per dep, then project status re-evaluated
3. Second change (same `code_type`) requested on already-modified project -> `base_code` = current effective code (not org)
4. Second change accepted -> effective code updated, `parent_id` points to first accepted change of same `code_type`
5. Change requested, another change of same `code_type` accepted first (conflict) -> `has_conflict` set to true at review time
6. AI merge suggested for conflicting change -> `ai_merged_code` populated, admin can accept/edit/reject
7. Revert to previous change -> new auto-accepted change with `proposed_code` = that change's code, same `code_type`
8. Revert to org base -> corresponding effective column set to null, project back to inherited for that code type
9. Change rejected -> no effect on effective code, change stays in history as rejected
10. Multiple pending changes for same project and same `code_type` -> all allowed, each checked for conflicts at acceptance
11. Changes for DIFFERENT `code_type`s on same project -> completely independent, no cross-type conflicts
12. Change authored by user with `manage_compliance` on a license exception -> auto-accepted (with conflict check)
13. Change authored by user without `manage_compliance` -> pending, requires admin review
14. Conflict resolution: change A adds MIT, change B adds ISC, both `code_type='package_policy'` based on org -> AI merges to org+MIT+ISC after A accepted first

**Package policy and tier tests:**

1. packagePolicy runs per dependency and stores `policy_result` JSONB on `project_dependencies`
2. packagePolicy receives `context.tier` with name, rank, multiplier from project's asset tier
3. Same package + same tier = same policyResult (cacheable)
4. projectStatus receives `policyResult` embedded on each dependency in context
5. Preflight check runs packagePolicy on hypothetical dep with project's tier context
6. "Apply for Exception" creates a change with `code_type='package_policy'` and `is_ai_generated=true`
7. "Apply for Exception" with `manage_compliance` -> auto-accepted if no conflict, shows AI merge if conflict (race condition)
8. Project tier changed -> full re-evaluation cascade: packagePolicy re-runs (same code, new tier), depscores recalculated, projectStatus re-runs
9. Project tier changed -> no git-like conflicts (base code is org-wide, not tier-specific)

**Org policy propagation:**

1. Org package policy updated, no projects with custom package policy -> no propagation dialog
2. Org package policy updated, 3 projects have custom package policy -> propagation dialog for those 3
3. Admin selects 2 of 3 projects to re-align -> those 2 get `effective_package_policy_code = null`
4. Org status code updated -> only projects with custom status code are shown in propagation (independent from package policy)
5. Re-aligned project's change history shows a "Reverted to Organization [Code Type]" entry

**Status management:**

1. Status created -> available in policy code `context.statuses` and in policy editor autocomplete
2. Status renamed -> all projects with that status updated, all references updated
3. Status deleted (non-system) -> projects with that status re-evaluated by policy
4. Status rank changed -> UI ordering updates
5. Status `is_passing` toggled -> compliance metrics recalculated for affected projects

**Validation tests:**

1. Syntax error -> save blocked with line number
2. Wrong return shape (`{ pass: true }` instead of `{ allowed: true }`) -> save blocked with specific message
3. Unknown status name returned in status/PR code -> save blocked with fuzzy suggestion ("Did you mean 'Blocked'?")
4. Code uses `fetch()` without `try/catch` -> save blocked with fetch resilience error
5. Code uses `fetch()` with `try/catch` fallback -> save allowed
6. Code without `fetch()` -> fetch resilience check skipped, save allowed
7. Empty/whitespace code -> save blocked with "Policy code cannot be empty"
8. Wrong function name (`function myPolicy` instead of `function packagePolicy`) -> save blocked
9. `reasons` field is string instead of `string[]` -> save blocked with type error
10. Validation timeout (infinite loop in code) -> caught at 5s with timeout error
11. Async function with `await fetch()` -> handled correctly by sandbox

**Concurrent scenarios:**

1. Policy runs during extraction while admin is editing policy -> uses the version fetched at extraction start
2. Two extractions for same project simultaneously -> last one wins (idempotent status update)
3. Status deleted while policy is running -> policy returns stale status name -> treated as scenario 6
4. Change accepted while another admin is reviewing a different pending change -> conflict detection runs at acceptance time, not at page load

**Permission tests:**

1. User with `manage_compliance` can edit org Package Policy, Status Code, PR Check Code
2. User without `manage_compliance` cannot edit org-level code (403)
3. User with `manage_statuses` can CRUD statuses and asset tiers
4. User without `manage_statuses` cannot modify statuses or tiers (403)
5. Any project member can request a policy change (pending)
6. Only `manage_compliance` users can accept/reject changes
7. Project settings access (owner team, org admin, `manage_teams_and_projects`) required for tier change and re-evaluate

#### Test files

`**ee/backend/lib/__tests__/policy-engine.test.ts`:**

- Tests 1-10 (policy execution scenarios)
- Tests 44-54 (validation scenarios)
- Test sandbox isolation (no filesystem, no require, no process access)
- Test `fetch()` proxying (mock external API)
- Test memory limit enforcement (policy that allocates too much RAM)
- Test timeout enforcement (30s production, 5s validation)
- Test helper functions (isLicenseAllowed, semverGt, daysSince)
- Test context data completeness (all expected fields present, including `context.tier`)
- Test effective policy resolution (inherited vs custom)
- Test null/empty policy defaults (all allowed, default Compliant)

`**ee/backend/routes/__tests__/policy-changes.test.ts`:**

- Tests 11-33 (git-like versioning lifecycle + package policy + tier tests)
- Tests 59-65 (permission enforcement)
- Test conflict detection accuracy (base_code comparison)
- Test AI merge endpoint (mock LLM response)
- Test revert chain integrity (parent_id chain is correct after reverts)
- Test org propagation logic (batch revert for selected projects)
- Test "Apply for Exception" auto-accept with conflict race condition

`**ee/backend/routes/__tests__/organization-statuses.test.ts`:**

- Tests 39-43 (status management)
- Test system status protection (can't delete Compliant/Non-Compliant)
- Test rank reordering
- Test permission enforcement (`manage_statuses` required)

`**frontend/src/__tests__/policy-editor.test.ts`:**

- Test Policies tab layout: Package Policy editor (single, with `context.tier` autocomplete) + PR Check editor + Change History
- Test Statuses tab layout: Statuses table + Asset Tiers table + Status Code editor + Change History
- Test autocomplete includes status names, tier fields, and context-appropriate fields per editor
- Test "Test Policy" button execution and result display
- Test validation feedback shown inline (syntax, shape, fetch resilience errors)
- Test save blocked when validation fails

`**frontend/src/__tests__/policy-change-history.test.ts`:**

- Tests 34-38 (org propagation UI)
- Test commit timeline rendering (accepted, pending, rejected entries with `code_type` badges)
- Test diff view between any two versions
- Test revert action creates new change
- Test conflict badge display on pending changes with `has_conflict = true`
- Test AI merge panel (three-panel view: current, proposed, AI suggestion)
