---
name: Phase 5 - Compliance Tab Overhaul
overview: Project Status subtab, preflight package check sidebar, AI-powered license exceptions.
todos:
  - id: phase-5-compliance
    content: "Phase 5: Compliance Tab Overhaul - New Project Status subtab, preflight package check sidebar (search + exact-lookup), AI-powered license exceptions (Tier 1 Gemini, diff confirmation), license obligations tracking, CycloneDX SBOM export, legal notice export"
    status: pending
isProject: false
---

## Phase 5: Compliance Tab Overhaul

**Goal:** Transform the compliance tab into a comprehensive compliance dashboard with a new Project Status overview subtab, a preflight package check sidebar, one-click license exceptions powered by AI, and proper SBOM/notice exports.

### Prerequisites (completed in pre-Phase 5 cleanup)

- `project_dependencies.policy_result` JSONB is exposed in the backend `fetchEnrichedDependenciesForProject()` SELECT and in the frontend `ProjectDependency` TypeScript interface in [api.ts](frontend/src/lib/api.ts)
- Rate limiting utility exists at [ee/backend/lib/rate-limit.ts](ee/backend/lib/rate-limit.ts) -- `checkRateLimit(key, maxRequests, windowSeconds)` backed by Redis. New Phase 5 endpoints (legal-notice, SBOM) should reuse this.
- Policy engine has a per-execution fetch count cap of 10 in [policy-engine.ts](ee/backend/lib/policy-engine.ts)
- Phase 4 policy endpoints are rate-limited: evaluate-policy (1/5min/project), validate-policy (10/min/user), preflight-check (30/min/user)
- Phase 4 migrations are consolidated in [phase4_policy_engine_consolidated.sql](backend/database/phase4_policy_engine_consolidated.sql)
- `StatusesSection.tsx` import of `PolicyCodeEditor` is fixed (named import)

### Frontend API client additions

The following API functions must be added to [api.ts](frontend/src/lib/api.ts) as part of this phase:

- `reEvaluateProjectPolicy(orgId, projectId)` -- calls `POST /api/organizations/:orgId/projects/:projectId/evaluate-policy`
- `searchRegistry(orgId, projectId, ecosystem, query)` -- calls new backend registry search proxy endpoint
- `downloadProjectSBOM(orgId, projectId)` -- calls `GET /api/organizations/:orgId/projects/:projectId/sbom` (returns blob)
- `downloadProjectLegalNotice(orgId, projectId)` -- calls `GET /api/organizations/:orgId/projects/:projectId/legal-notice` (returns text)
- `applyForException(orgId, projectId, packageName, version, reason)` -- calls new AI exception endpoint

The existing `preflightCheck(orgId, projectId, packageName, version)` in api.ts already exists and should be extended to accept an `ecosystem` parameter.

### 5A: New "Project" Subtab (Status Overview)

**Design reference:** Stitch AI mockup saved at `assets/c__Users_hruck_AppData_Roaming_Cursor_User_workspaceStorage_f61739c64cef43ebd9ea8666594e3869_images_image-235da840-be3b-4b4e-8fc9-b1703e872718.png`. Use as inspiration for layout (not exact styles - keep Deptex's existing design language).

**Navigation restructure:** Replace the current left sidebar navigation (`ComplianceSidepanel`) with top-level tabs. The tab order becomes: **Project** | Policy Results | Updates.

Move export buttons (SBOM, Legal Notice) out of the sidebar into a dropdown in the top-right action area of the page header (alongside the "Re-evaluate" button). The dropdown shows: "Export SBOM (CycloneDX)", "Export Legal Notice".

Add the new "Project" subtab to [ProjectCompliancePage.tsx](frontend/src/app/pages/ProjectCompliancePage.tsx).

**Status Card (top of page):**

- Large custom status badge (color + name from `organization_statuses`) showing the project's current status
- Violation count summary: "2 critical violations detected in the latest scan"
- Violation type tags below the summary (e.g., red "GPL-3.0 Detected" badge, orange "Unapproved Source" badge) - derived from `policyResult.reasons` across all deps
- `policy_evaluated_at` timestamp: "Last evaluated 3 hours ago"
- **"Re-evaluate" button** (top right of card, outline style): Triggers an on-demand re-run of the full policy chain (packagePolicy per dep -> projectStatus) without requiring a full extraction. Calls the existing `POST /api/organizations/:orgId/projects/:projectId/evaluate-policy` endpoint (already rate-limited to 1 per project per 5 minutes) which:
  1. Fetches current deps + vulns from DB
  2. Runs effective `packagePolicy()` on each dep (with tier context), stores results in `project_dependencies.policy_result`
  3. Runs effective `projectStatus()` with enriched deps
  4. Updates `projects.status_id`, `status_violations`, `policy_evaluated_at`
  5. Returns the new status + violations + per-dep policy results for instant UI update
- **Permissions**: Only visible to users with project settings access (owner team, org admin, `manage_teams_and_projects`). Shows a loading spinner while running. Disabled if extraction is currently in progress.
- **Edge cases**: Returns 409 if extraction is in progress. Returns immediately with "Compliant" if project has zero deps. Sets "Non-Compliant" with error message if policy engine throws. Debounce on frontend: disable button for 5 seconds after click to prevent spam.

**Active Violations section:**

- List of dependencies that failed the package policy (`policyResult.allowed === false`)
- Each row: package icon, package name, version badge, "Rule Broken: {rule name}" in red/orange, violation reason
- Count badge: "N items" in the section header
- Clicking a row navigates to the dependency in the Dependencies tab

**Blocked Pull Requests section (placeholder -- real PR data requires Phase 8):**

- Shows PRs that failed the PR check (status `is_passing === false`)
- Each row: PR icon, PR title + number, "opened by @author", status badge (e.g., "Blocked" in red), violation count
- Clicking a row navigates to the PR in the Updates subtab
- **Note:** Real PR webhook data is not available until Phase 8 (PR Management & Webhooks). For Phase 5, this section will always show the "PR checks not configured" empty state. Build the UI shell and data-binding so it works once Phase 8 wires in real PR data. Do NOT use mock data.
- Empty state: "No blocked pull requests" if all PRs pass, or "PR checks not configured" if no webhook is set up

**Policy Source Card (3 independent rows):**

Shows inheritance status for each code type independently:

- **Package Policy**: "Inherited" or "Custom (N changes)" with [View Diff] [Request Change] [Revert] links
- **Status Code**: "Inherited" or "Custom (N changes)" with same links
- **PR Check**: "Inherited" or "Custom (N changes)" with same links

Each row shows pending changes count badge if any. "View Diff" opens a modal comparing org base vs project effective for that code type. "Request Change" opens the relevant code editor in a sidebar. "Revert" creates a revert commit for that code type.

**Quick Stats Strip:**

- License issues count (with breakdown: banned, missing, unknown)
- Vulnerable dependencies count (by severity)
- Average dependency score
- Policy changes pending count

**Preflight Check button:** "Check a Package" button (outline style, with shield icon) opens the Preflight Check Sidebar (5B)

#### Empty and edge states

- **No extraction yet**: Show "No scan data available. Run your first extraction to see compliance status." with a link to trigger extraction. No stats, no violations, no PRs.
- **No policy defined**: Show "Compliant" status with a note: "No policy rules defined - all packages allowed by default." Link to org settings -> Policies tab.
- **Extraction in progress**: Show a progress indicator on the status card. Disable "Re-evaluate" button. Show "Extraction running..." badge.
- **Stale data**: If `policy_evaluated_at` is more than 24 hours old, show a subtle warning: "Policy data may be out of date" with a re-evaluate prompt.
- **PR checks not configured**: Blocked PRs section shows "PR checks not configured. Enable webhooks in organization settings."

### 5B: Preflight Check Sidebar

A modern animated sidebar (same pattern as Create Role sidebar from [OrganizationSettingsPage.tsx](frontend/src/app/pages/OrganizationSettingsPage.tsx)) that lets users test whether adding a package would affect the project's compliance status.

**Sidebar layout:**

1. **Ecosystem selector** at top: dropdown showing detected ecosystems for the project (npm, PyPI, Maven, Go, Cargo, RubyGems). Defaults to the primary ecosystem. Only ecosystems present in the project's deps are shown.
2. **Search bar**: placeholder depends on ecosystem -- "Search packages..." for ecosystems with search APIs (npm, Maven, Cargo, RubyGems), "Enter package name..." for exact-lookup ecosystems (PyPI, Go). Supports `package@version` syntax for specific versions.
3. **Search results**: For search-capable ecosystems: list of matching packages from the registry with: package name, latest version, license badge, weekly downloads, description snippet. Each result has a version dropdown to select a specific version (defaults to latest). For exact-lookup ecosystems: single package result returned directly (or "Package not found" error).
4. **"Run Policy Check" button** on each package result
5. **Results panel** (replaces search results after check runs):
  - Policy result: "Allowed" (green) or "Blocked" (red) badge with the specific violation reasons
  - Package details card: license, known vulnerabilities (from OSV), OpenSSF score, weekly downloads, dependency score (if in our DB, otherwise "N/A - not yet tracked")
  - Caveat notice: "Note: Reachability analysis and import count are not available in preflight checks."
  - "Check Another Package" button to go back to search

**Supported registries:**

Search-capable (query returns multiple results):

- **npm**: `https://registry.npmjs.org/-/v1/search?text={query}` for search, `https://registry.npmjs.org/{package}` for metadata
- **Maven**: `https://search.maven.org/solrsearch/select?q={query}` for search
- **Cargo**: `https://crates.io/api/v1/crates?q={query}` for search
- **RubyGems**: `https://rubygems.org/api/v1/search.json?query={query}` for search

Exact-name lookup only (no public search API):

- **PyPI**: `https://pypi.org/pypi/{package}/json` for metadata. Reuses the existing `fetchPypi()` from [registry-fetchers.ts](backend/src/lib/registry-fetchers.ts).
- **Go**: `https://proxy.golang.org/{module}/@latest` for metadata. Reuses the existing `fetchGolang()` from [registry-fetchers.ts](backend/src/lib/registry-fetchers.ts).

All registry calls are proxied through the backend to avoid CORS and to apply rate limiting.

**Behind the scenes:**

1. User searches (or enters exact name for PyPI/Go) -> backend proxies to the relevant registry API, returns formatted results
2. User selects a version and clicks "Run Policy Check" -> frontend calls the existing `POST /api/organizations/:orgId/projects/:projectId/preflight-check` endpoint (already rate-limited to 30/min/user) with `{ ecosystem, packageName, version }`
3. Backend:
  a. Fetches package metadata from registry (license, version info, downloads)
   b. Looks up known vulnerabilities from OSV for that package@version
   c. Checks our `dependencies` table for existing score data. If the package isn't tracked yet: OpenSSF score = null, dependency_score = null (noted in response as "Not yet tracked")
   d. Loads the project's tier info (name, rank, multiplier) from `organization_asset_tiers`
   e. Runs `packagePolicy()` on the hypothetical dependency with `{ dependency, tier }` - single-dep evaluation
   f. Returns: `{ policyResult: { allowed, reasons }, packageInfo: { license, vulns, score, ecosystem, ... } }`

**Preflight edge cases:**

- Package not found in registry: show "Package not found" error
- Package has no license info: pass `license: null` to policy, let policy decide (default templates block null licenses for critical tiers)
- Package not in our DB (no dependency_score): pass `dependencyScore: null`, noted in UI as "Score unavailable - package not yet tracked by Deptex"
- Extraction in progress: preflight still works (doesn't depend on extraction)
- No policy defined: all packages "Allowed" (noted in results: "No policy rules configured")
- Registry API down/slow: 10-second timeout per registry call, show error: "Could not reach {ecosystem} registry"

### 5C: Policy Results Tab (renamed from "Licenses")

Rename the current "Licenses" subtab to **"Policy Results"** to reflect that it now shows ALL per-dependency policy evaluation results, not just license issues. The policy engine checks licenses, malicious packages, reputation scores, SLSA, supply chain signals, and more.

In the Policy Results subtab of [ProjectCompliancePage.tsx](frontend/src/app/pages/ProjectCompliancePage.tsx):

1. Replace the current hardcoded compliance logic (`getComplianceStatus()` in `compliance-utils.ts`) with real data from `project_dependencies.policy_result` (per-dep package policy results from Phase 4, already available on the `ProjectDependency` frontend type). Deprecate and remove `getComplianceStatus()`, `isLicenseAllowed()`, `normalizeLicenseForComparison()`, `getIssueLabel()`, `getIssueBadgeVariant()`, and `getSlsaEnforcementLabel()` from compliance-utils.ts as they are superseded by the policy engine results.
2. **Table columns**: Package name + icon, version badge, license, policy status (Allowed/Blocked badge), violation reasons
3. **Sub-tabs**: "Issues" (only non-allowed deps, default) and "All Packages" (all deps with their policy status) - matches existing sub-tab pattern
4. **Filters**:
  - By policy result: Allowed / Not Allowed / All
  - By reason category: License Violation / Malicious Package / Low Score / SLSA / Supply Chain / Other
  - By direct/transitive: Direct / Transitive / All
  - Search by package name
5. **Reason tags** on each row: colored badges showing each reason from `policyResult.reasons` (e.g., red "Banned License: GPL-3.0", orange "Low Score: 25")
6. **"Apply for Exception" button** on each non-allowed dependency row:
  - Visible to **all project members** (not just settings access - any member can request)
  - On click: AI analyzes the current effective `package_policy_code` and generates a modified version that allows this specific package/license
  - **Diff confirmation step**: after AI generates the exception code, show a diff dialog (original policy vs AI-modified policy) for the user to review and confirm. This applies to ALL users, including those with `manage_compliance`. The user must explicitly click "Confirm" to proceed.
  - The AI-generated code is **validated** through the Phase 4B validation checks (syntax, shape, fetch resilience) after user confirms. If validation fails, show error toast: "Could not generate valid exception - please request manually."
  - Creates a policy change "commit" with `code_type = 'package_policy'` and message: "Allow {reason} (for {package_name}@{version})"
  - `is_ai_generated = true` on the change record
  - **If user has `manage_compliance` permission**: After diff confirmation, change is accepted (with conflict check per Phase 4). Package policy re-runs. If the dep IS now allowed: toast "Exception applied." If still blocked (AI mistake): toast "Exception applied but package still blocked - review the policy manually."
  - **If user does NOT have `manage_compliance`**: After diff confirmation, submitted as pending. Toast: "Exception requested - awaiting admin approval." Badge appears in Policies tab Change History.
  - **Full flow**: click "Apply for Exception" -> loading spinner -> AI generates code -> diff dialog (original vs modified) -> user clicks "Confirm" -> validation runs -> change created (accepted if `manage_compliance`, pending otherwise)
7. **LLM for Apply for Exception**: Uses **Tier 1 Gemini Flash** via `GoogleGenerativeAI` / `GOOGLE_AI_API_KEY` (Deptex pays, no BYOK dependency). Prompt includes the full current policy code + the specific violation to resolve. The AI must return the COMPLETE modified function, not a diff. If Gemini is unavailable, show error toast: "AI service temporarily unavailable - please request the exception manually."

### 5D: License Obligation Tracking

Beyond just allowed/banned, track what each license REQUIRES for legal compliance.

`**license_obligations` reference table:**

- `id` UUID primary key
- `license_spdx_id` TEXT (e.g., "MIT", "Apache-2.0", "GPL-3.0-only") - UNIQUE
- `requires_attribution` BOOLEAN (must include copyright notice)
- `requires_notice_file` BOOLEAN (must include NOTICE file)
- `requires_source_disclosure` BOOLEAN (must disclose source for modifications)
- `requires_license_text` BOOLEAN (must include full license text)
- `is_copyleft` BOOLEAN (modifications must use same license)
- `is_weak_copyleft` BOOLEAN (only linked code must use same license)
- `summary` TEXT (human-readable: "Requires copyright notice and license text in distributions")
- `full_text` TEXT (the complete license text from SPDX - bundled statically from [https://spdx.org/licenses/](https://spdx.org/licenses/))

**Seeded data:** Pre-populate for the ~50 most common SPDX identifiers (MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC, MPL-2.0, LGPL-2.1, LGPL-3.0, GPL-2.0, GPL-3.0, AGPL-3.0, Unlicense, CC0-1.0, etc.). License texts sourced statically from the official SPDX license list repository (open data, no ongoing sync needed).

**Seed file:** `backend/database/seed_license_obligations.sql` -- SQL INSERT statements for all ~50 licenses with obligation flags and full license texts. This is a one-time migration; packages using licenses not in the table will have their license name shown without full text in the legal notice. Note: full license texts (e.g. GPL-3.0 is ~35KB) make this a large file. Store the seed data as a separate JSON data file (`backend/database/data/spdx-obligations.json`) and load it via a TypeScript seed script rather than inlining all texts in SQL.

**UI in Policy Results tab:** Add a collapsible "License Obligations" section below the main table. Grouped by license type, shows:

- License name + obligation badges (Attribution, Source Disclosure, Copyleft, etc.)
- Count of dependencies using this license
- Expandable: list of packages + the full obligation summary

**Integration with Legal Notice export:** The `generateLegalNotice()` includes:

- Full license texts (from `license_obligations.full_text`) for copyleft licenses
- Obligation summary per license group

### 5E: SBOM Export (Real cdxgen SBOM from Storage)

Replace the current frontend-generated SBOM with the real cdxgen SBOM stored in Supabase Storage. The cdxgen output is comprehensive, industry-standard CycloneDX 1.5 and includes metadata the frontend-generated version lacks.

**New endpoint:** `GET /api/organizations/:orgId/projects/:projectId/sbom` in [projects.ts](ee/backend/routes/projects.ts) (EE route, follows existing route pattern).

**Auth:** Uses `authenticateUser` middleware + org membership check + project access verification (same pattern as other project GET endpoints). Any user who can view the project can download the SBOM (read-only export, no edit action).

1. Look up the latest extraction run for the project (from `extraction_jobs` table, `status = 'completed'`)
2. Fetch the SBOM file from Supabase Storage: `project-imports/{project_id}/{run_id}/sbom.json`
3. Return the file as a download with proper headers (`Content-Type: application/json`, `Content-Disposition: attachment; filename={project_name}-sbom.json`)
4. If no extraction has completed: return 404 with message "No SBOM available. Run an extraction first."

**Frontend changes:**

- Replace `generateSBOM()` call in [compliance-utils.ts](frontend/src/lib/compliance-utils.ts) with an API call to the new endpoint. Also deprecate/remove `generateOrgSBOM()` from the same file -- org-level SBOM export can iterate projects and download individually.
- Show extraction timestamp on the download button: "Download SBOM (from scan 3h ago)"
- Disable button if no extraction has completed, with tooltip: "Run an extraction first"
- CycloneDX format only for Phase 5 (SPDX conversion deferred to a future phase)

**Edge cases:**

- SBOM from old extraction while deps have been updated by a newer extraction: the SBOM always comes from the latest COMPLETED extraction, which is also the source of current dep data, so they stay in sync
- Very large SBOM files: show loading indicator on the download button
- Storage bucket access: backend uses service role key to fetch from private bucket, frontend never accesses storage directly

### 5F: Legal Notice Export

Replace the current frontend-only `generateLegalNotice()` in [compliance-utils.ts](frontend/src/lib/compliance-utils.ts) with a backend endpoint that produces a comprehensive legal attribution notice. This is generated on-the-fly from DB data (not from stored SBOM).

**New endpoint:** `GET /api/organizations/:orgId/projects/:projectId/legal-notice` in [projects.ts](ee/backend/routes/projects.ts) (EE route, follows existing route pattern). Backend generates the notice including license full texts from the `license_obligations` table.

**Auth:** Uses `authenticateUser` middleware + org membership check + project access verification (same pattern as SBOM endpoint). Any user who can view the project can download the legal notice.

**Rate limiting:** 5 requests/min per user per project using the existing `checkRateLimit()` from [rate-limit.ts](ee/backend/lib/rate-limit.ts) with key `legal-notice:${userId}:${projectId}`.

**Caching:** Cache the generated notice in Redis with key `legal-notice:${projectId}` and TTL of 1 hour. Invalidate on extraction completion (same pattern as dependency caches). This avoids repeated on-the-fly generation for large projects.

**Notice contents:**

1. Header: project name, generation date, Deptex version
2. All direct and transitive dependencies (from `project_dependencies`)
3. Grouped by license type (MIT, Apache-2.0, etc.)
4. Per-dependency: "Copyright: see package metadata" (copyright author/contributor extraction deferred to a future phase)
5. **License full text** for copyleft licenses (from `license_obligations.full_text`)
6. **Obligation summary** per license group (from `license_obligations.summary`)
7. Footer: "Generated by Deptex" with timestamp

**Edge cases:**

- Dependencies with unknown/null licenses: grouped under "Unknown License" section with a note
- License not in `license_obligations` table: show license name without full text, log a warning for admin
- Very large projects (500+ deps): on-the-fly generation is cached in Redis after first request (1h TTL, invalidated on extraction). Set a 30-second timeout on the endpoint as a safety net.

### 5G: Design Reference

**Stitch AI mockup:** `assets/c__Users_hruck_..._image-235da840-be3b-4b4e-8fc9-b1703e872718.png`

The Stitch mockup was used as initial inspiration. Key elements adopted from the design:

- Status card with large status badge, violation count, and type tags
- Active Violations list with per-dep rule breakdown
- Blocked Pull Requests section
- "Re-evaluate" button (top right, outline style)
- Preflight Check as a button that opens a sidebar (design showed it as a right panel, adapted to sidebar)

Elements from our plan NOT in the design (added on top):

- Policy Source Card with 3 independent code-type rows
- Quick Stats Strip
- Subtab navigation (Project | Policy Results | Updates)
- Edge state handling (no extraction, no policy, stale data, mid-extraction)

### 5H: Phase 5 Test Suite

All test numbers are Phase 5-specific (starting from 1, independent of Phase 4 numbering).

#### Project subtab tests (5A):

1. Status card shows correct custom status badge (color + name from org statuses)
2. Violation type tags derived from policyResult.reasons across all deps
3. "Last evaluated X ago" timestamp from `policy_evaluated_at`
4. "Re-evaluate" button triggers policy chain re-run and updates UI
5. "Re-evaluate" returns 409 if extraction in progress
6. "Re-evaluate" with zero deps returns "Compliant" immediately
7. "Re-evaluate" with policy engine error sets "Non-Compliant" with error message
8. "Re-evaluate" debounced: button disabled for 5s after click
9. "Re-evaluate" hidden for users without project settings access
10. Active Violations list shows only deps with `policyResult.allowed === false`
11. Clicking a violation row navigates to the dependency
12. Blocked PRs section renders correctly when PR data is present (data-binding test with mock PR records)
13. Blocked PRs shows "not configured" when no webhook is set up (default state until Phase 8)
14. Policy Source Card shows correct inheritance status per code type
15. Pending changes badge count is accurate per code type
16. Quick Stats counts match actual data (license issues, vuln deps, avg score, pending changes)
17. Empty state: no extraction yet shows appropriate message
18. Empty state: no policy defined shows "Compliant" with setup prompt
19. Stale data warning appears when `policy_evaluated_at` > 24 hours

#### Preflight Check tests (5B):

1. Ecosystem selector shows only ecosystems present in project's deps
2. Search-capable ecosystems (npm, Maven, Cargo, RubyGems) return search results from correct registry API
3. Exact-lookup ecosystems (PyPI, Go) accept full package name and return single result
4. PyPI/Go show "Enter package name..." placeholder (not "Search packages...")
5. Version selector allows checking specific versions
6. "Run Policy Check" calls backend endpoint with correct params
7. Results show correct policyResult (allowed/blocked with reasons)
8. Package not in our DB shows "Score unavailable - not yet tracked"
9. Package not found in registry shows error
10. Registry API timeout (10s) shows error message
11. Preflight works even during active extraction
12. Preflight with no policy defined shows "Allowed" with note

#### Policy Results tab tests (5C):

1. Table shows data from `project_dependencies.policy_result` (not hardcoded logic)
2. Old `getComplianceStatus()` logic in compliance-utils.ts is replaced
3. "Issues" sub-tab shows only non-allowed deps
4. "All Packages" sub-tab shows all deps with their policy status
5. Filter by reason category works (License / Malicious / Low Score / SLSA / Supply Chain)
6. Filter by direct/transitive works
7. Search by package name works
8. Reason tags show colored badges per `policyResult.reasons`
9. "Apply for Exception" visible to all project members
10. "Apply for Exception" calls Tier 1 Gemini Flash (not BYOK OpenAI)
11. "Apply for Exception" shows diff dialog (original vs AI-modified) before proceeding
12. "Apply for Exception" generates valid AI code (passes Phase 4B validation after user confirms diff)
13. "Apply for Exception" accepts for `manage_compliance` users after diff confirmation (no conflict)
14. "Apply for Exception" creates pending change for non-`manage_compliance` users after diff confirmation
15. "Apply for Exception" with conflict shows AI merge suggestion
16. "Apply for Exception" with validation failure shows error toast
17. "Apply for Exception" when Gemini unavailable shows "AI service temporarily unavailable" toast
18. After acceptance, dep re-evaluates and clears violation (or shows "still blocked" if AI mistake)

#### License Obligations tests (5D):

1. `license_obligations` table seeded with ~50 common SPDX licenses (via `seed_license_obligations.sql`)
2. Obligation badges shown per license group in collapsible section
3. Unknown licenses grouped under "Unknown License"

#### SBOM Export tests (5E):

1. `GET /api/organizations/:orgId/projects/:projectId/sbom` returns real cdxgen SBOM from storage (CycloneDX only)
2. Returns 404 if no completed extraction exists
3. Download button shows extraction timestamp
4. Download button disabled when no extraction completed
5. Any project viewer can download SBOM (auth check passes)
6. Unauthenticated request returns 401

#### Legal Notice tests (5F):

1. `GET /api/organizations/:orgId/projects/:projectId/legal-notice` returns grouped notice with license texts
2. Dependencies grouped by license type
3. Copyleft licenses include full text from `license_obligations`
4. Unknown licenses grouped with note
5. Per-dependency copyright line shows "Copyright: see package metadata"
6. Any project viewer can download notice (auth check passes)
7. Unauthenticated request returns 401
8. Rate limiting: 6th request within 1 minute returns 429

#### Test files:

`**ee/backend/routes/__tests__/compliance-api.test.ts`:**

- 5A/4-9: re-evaluate endpoint (triggers, 409, zero deps, error, permissions)
- 5B/6-12: preflight check endpoint (policy check, edge cases, registry errors)
- 5E/1-6: SBOM export endpoint (download, 404, auth)
- 5F/1-8: legal notice endpoint (generation, grouping, auth, rate limiting)

`**frontend/src/__tests__/compliance-project-tab.test.ts`:**

- 5A/1-3, 10-19: Project subtab UI (status card, violations, blocked PRs, edge states)
- 5A/14-16: Policy Source Card, Quick Stats

`**frontend/src/__tests__/compliance-preflight.test.ts`:**

- 5B/1-12: Preflight sidebar UI (ecosystem selector, search vs exact-lookup, results, edge cases)

`**frontend/src/__tests__/compliance-policy-results.test.ts`:**

- 5C/1-18: Policy Results tab, diff confirmation flow, Gemini AI, and Apply for Exception flow

`**frontend/src/__tests__/compliance-obligations.test.ts`:**

- 5D/1-3: License Obligations UI (seeding, badges, unknown licenses)

