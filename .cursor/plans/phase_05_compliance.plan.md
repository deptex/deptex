---
name: Phase 5 - Compliance Tab Overhaul
overview: Project Status subtab, preflight package check sidebar, AI-powered license exceptions.
todos:
  - id: phase-5-compliance
    content: "Phase 5: Compliance Tab Overhaul - New Project Status subtab, preflight package check sidebar, AI-powered one-click license exceptions, SBOM/notice verification, Stitch AI prompt"
    status: pending
isProject: false
---
## Phase 5: Compliance Tab Overhaul

**Goal:** Transform the compliance tab into a comprehensive compliance dashboard with a new Project Status overview subtab, a preflight package check sidebar, one-click license exceptions powered by AI, and proper SBOM/notice exports.

### 5A: New "Project" Subtab (Status Overview)

**Design reference:** Stitch AI mockup saved at `assets/c__Users_hruck_AppData_Roaming_Cursor_User_workspaceStorage_f61739c64cef43ebd9ea8666594e3869_images_image-235da840-be3b-4b4e-8fc9-b1703e872718.png`. Use as inspiration for layout (not exact styles - keep Deptex's existing design language).

**Navigation restructure:** Replace the current left sidebar navigation (`ComplianceSidepanel`) with top-level tabs. The tab order becomes: **Project** | Policy Results | Updates.

Move export buttons (SBOM, Legal Notice) out of the sidebar into a dropdown in the top-right action area of the page header (alongside the "Re-evaluate" button). The dropdown shows: "Export SBOM (CycloneDX)", "Export SBOM (SPDX)", "Export Legal Notice".

Add the new "Project" subtab to [ProjectCompliancePage.tsx](frontend/src/app/pages/ProjectCompliancePage.tsx).

**Status Card (top of page):**

- Large custom status badge (color + name from `organization_statuses`) showing the project's current status
- Violation count summary: "2 critical violations detected in the latest scan"
- Violation type tags below the summary (e.g., red "GPL-3.0 Detected" badge, orange "Unapproved Source" badge) - derived from `policyResult.reasons` across all deps
- `policy_evaluated_at` timestamp: "Last evaluated 3 hours ago"
- **"Re-evaluate" button** (top right of card, outline style): Triggers an on-demand re-run of the full policy chain (packagePolicy per dep -> projectStatus) without requiring a full extraction. Calls `POST /api/projects/:id/re-evaluate-policy` which:
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

**Blocked Pull Requests section:**

- Shows PRs that failed the PR check (status `is_passing === false`)
- Each row: PR icon, PR title + number, "opened by @author", status badge (e.g., "Blocked" in red), violation count
- Clicking a row navigates to the PR in the Updates subtab
- Empty state: "No blocked pull requests" if all PRs pass, or "PR checks not configured" if no webhook is set up

**Policy Source Card (3 independent rows):**

Shows inheritance status for each code type independently:

- **Package Policy**: "Inherited" or "Custom (N changes)" with [View Diff] [Request Change] [Revert] links
- **Status Code**: "Inherited" or "Custom (N changes)" with same links
- **PR Check**: "Inherited" or "Custom (N changes)" with same links

Each row shows pending changes count badge if any. "View Diff" opens a modal comparing org base vs project effective for that code type. "Request Change" opens the relevant code editor in a sidebar. "Revert" creates a revert commit for that code type.

**Action Items Card:**

- AI-analyzed list of what to fix to improve the project's status: e.g., "Remove 2 GPL-licensed dependencies to reach Compliant" or "Upgrade lodash to 4.18.0 to fix CVE-2024-XXXX"
- Each item links to the relevant dependency or vulnerability
- **Pre-computed** during extraction and re-evaluate: after the policy chain runs, the backend runs up to 10 hypothetical scenarios (remove the top violations one by one) and caches the results in `projects.action_items` JSONB column. This avoids expensive on-demand sandbox runs. Format: `[{ message: string, deps: string[], link: string }]`
- If the project is at the best status: show a checkmark with "All clear - no action items"

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
2. **Search bar**: "Search packages..." - searches the selected ecosystem's registry. Supports `package@version` syntax for specific versions.
3. **Search results**: List of packages from the registry with: package name, latest version, license badge, weekly downloads, description snippet. Each result has a version dropdown to select a specific version (defaults to latest).
4. **"Run Policy Check" button** on each package result
5. **Results panel** (replaces search results after check runs):
  - Policy result: "Allowed" (green) or "Blocked" (red) badge with the specific violation reasons
  - Package details card: license, known vulnerabilities (from OSV), OpenSSF score, weekly downloads, dependency score (if in our DB, otherwise "N/A - not yet tracked")
  - Caveat notice: "Note: Reachability analysis and import count are not available in preflight checks."
  - "Check Another Package" button to go back to search

**Supported registries:**

- **npm**: `https://registry.npmjs.org/-/v1/search?text={query}` for search, `https://registry.npmjs.org/{package}` for metadata
- **PyPI**: `https://pypi.org/pypi/{package}/json` for metadata, `https://pypi.org/search/?q={query}` (scrape or use simple API)
- **Go**: `https://pkg.go.dev/search?q={query}` (proxy through backend to avoid CORS)
- **Maven**: `https://search.maven.org/solrsearch/select?q={query}` for search
- **Cargo**: `https://crates.io/api/v1/crates?q={query}` for search
- **RubyGems**: `https://rubygems.org/api/v1/search.json?query={query}` for search

All registry calls are proxied through the backend to avoid CORS and to apply rate limiting.

**Behind the scenes:**

1. User searches -> backend proxies to the relevant registry API, returns formatted results
2. User selects a version and clicks "Run Policy Check" -> frontend calls `POST /api/projects/:id/preflight-check` with `{ ecosystem, packageName, version }`
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

1. Replace the current hardcoded compliance logic (`getComplianceStatus()` in `compliance-utils.ts`) with real data from `project_dependencies.policy_result` (per-dep package policy results from Phase 4)
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
  - The AI-generated code is **validated** through the Phase 4B validation checks (syntax, shape, fetch resilience) before saving. If validation fails, show error toast: "Could not generate valid exception - please request manually."
  - Creates a policy change "commit" with `code_type = 'package_policy'` and message: "Allow {reason} (for {package_name}@{version})"
  - `is_ai_generated = true` on the change record
  - **If user has `manage_compliance` permission**: Auto-accepted (with conflict check per Phase 4). Package policy re-runs. If the dep IS now allowed: toast "Exception applied." If still blocked (AI mistake): toast "Exception applied but package still blocked - review the policy manually."
  - **If user does NOT have `manage_compliance`**: Submitted as pending. Toast: "Exception requested - awaiting admin approval." Badge appears in Policies tab Change History.
7. **LLM for Apply for Exception**: Use the same LLM as the PolicyAIAssistant (GPT-4o-mini for simple license exceptions, GPT-4o for complex ones). Prompt includes the full current policy code + the specific violation to resolve. The AI must return the COMPLETE modified function, not a diff.

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

**Seeded data:** Pre-populate for the ~50 most common SPDX identifiers (MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC, MPL-2.0, LGPL-2.1, LGPL-3.0, GPL-2.0, GPL-3.0, AGPL-3.0, Unlicense, CC0-1.0, etc.). License texts bundled from the SPDX license list.

**UI in Policy Results tab:** Add a collapsible "License Obligations" section below the main table. Grouped by license type, shows:

- License name + obligation badges (Attribution, Source Disclosure, Copyleft, etc.)
- Count of dependencies using this license
- Expandable: list of packages + the full obligation summary

**Integration with Legal Notice export:** The `generateLegalNotice()` includes:

- Full license texts (from `license_obligations.full_text`) for copyleft licenses
- Obligation summary per license group
- Copyright notices where available from package metadata

### 5E: SBOM Export (Real cdxgen SBOM from Storage)

Replace the current frontend-generated SBOM with the real cdxgen SBOM stored in Supabase Storage. The cdxgen output is comprehensive, industry-standard CycloneDX 1.5 and includes metadata the frontend-generated version lacks.

**New endpoint:** `GET /api/projects/:id/sbom`

1. Look up the latest extraction run for the project (from `extraction_jobs` table, `status = 'completed'`)
2. Fetch the SBOM file from Supabase Storage: `project-imports/{project_id}/{run_id}/sbom.json`
3. Return the file as a download with proper headers (`Content-Type: application/json`, `Content-Disposition: attachment; filename={project_name}-sbom.json`)
4. If no extraction has completed: return 404 with message "No SBOM available. Run an extraction first."

**Frontend changes:**

- Replace `generateSBOM()` call in [compliance-utils.ts](frontend/src/lib/compliance-utils.ts) with an API call to the new endpoint
- Show extraction timestamp on the download button: "Download SBOM (from scan 3h ago)"
- Disable button if no extraction has completed, with tooltip: "Run an extraction first"
- Add SPDX format option: convert the CycloneDX SBOM to SPDX on the backend using a library like `@cyclonedx/cyclonedx-library` or a simple transformer
- **Permissions**: Any user who can view the project can download the SBOM and legal notice (read-only export, no edit action)

**Edge cases:**

- SBOM from old extraction while deps have been updated by a newer extraction: the SBOM always comes from the latest COMPLETED extraction, which is also the source of current dep data, so they stay in sync
- Very large SBOM files: show loading indicator on the download button
- Storage bucket access: backend uses service role key to fetch from private bucket, frontend never accesses storage directly

### 5F: Legal Notice Export

Update `generateLegalNotice()` in [compliance-utils.ts](frontend/src/lib/compliance-utils.ts) to produce a comprehensive legal attribution notice. This is generated on-the-fly from DB data (not from stored SBOM).

**New endpoint:** `GET /api/projects/:id/legal-notice` (backend generates to include license full texts from `license_obligations` table)

**Notice contents:**

1. Header: project name, generation date, Deptex version
2. All direct and transitive dependencies (from `project_dependencies`)
3. Grouped by license type (MIT, Apache-2.0, etc.)
4. **Copyright notices** where available (from npm `package.json` author/contributors fields, stored during extraction)
5. **License full text** for copyleft licenses (from `license_obligations.full_text`)
6. **Obligation summary** per license group (from `license_obligations.summary`)
7. Footer: "Generated by Deptex" with timestamp

**Permissions:** Same as SBOM export - any user who can view the project.

**Edge cases:**

- Dependencies with unknown/null licenses: grouped under "Unknown License" section with a note
- License not in `license_obligations` table: show license name without full text, log a warning for admin
- Very large projects (500+ deps): on-the-fly generation is still fast (string concatenation), but set a 30-second timeout on the endpoint

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
- Action Items Card (AI suggestions)
- Quick Stats Strip
- Subtab navigation (Project | Policy Results | Updates)
- Edge state handling (no extraction, no policy, stale data, mid-extraction)

### 5H: Phase 5 Test Suite

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
12. Blocked PRs section shows PRs with `is_passing === false`
13. Blocked PRs shows "not configured" when no webhook is set up
14. Policy Source Card shows correct inheritance status per code type
15. Pending changes badge count is accurate per code type
16. Action Items shows pre-computed suggestions from `projects.action_items`
17. Action Items shows "All clear" when project is at best status
18. Quick Stats counts match actual data (license issues, vuln deps, avg score, pending changes)
19. Empty state: no extraction yet shows appropriate message
20. Empty state: no policy defined shows "Compliant" with setup prompt
21. Stale data warning appears when `policy_evaluated_at` > 24 hours

#### Preflight Check tests (5B):

1. Ecosystem selector shows only ecosystems present in project's deps
2. Search returns results from correct registry API
3. Version selector allows checking specific versions
4. "Run Policy Check" calls backend endpoint with correct params
5. Results show correct policyResult (allowed/blocked with reasons)
6. Package not in our DB shows "Score unavailable - not yet tracked"
7. Package not found in registry shows error
8. Registry API timeout (10s) shows error message
9. Preflight works even during active extraction
10. Preflight with no policy defined shows "Allowed" with note

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
10. "Apply for Exception" generates valid AI code (passes Phase 4B validation)
11. "Apply for Exception" auto-accepts for `manage_compliance` users (no conflict)
12. "Apply for Exception" creates pending change for non-`manage_compliance` users
13. "Apply for Exception" with conflict shows AI merge suggestion
14. "Apply for Exception" with validation failure shows error toast
15. After auto-accept, dep re-evaluates and clears violation (or shows "still blocked" if AI mistake)

#### License Obligations tests (5D):

1. `license_obligations` table seeded with ~50 common SPDX licenses
2. Obligation badges shown per license group in collapsible section
3. Unknown licenses grouped under "Unknown License"

#### SBOM Export tests (5E):

1. `GET /api/projects/:id/sbom` returns real cdxgen SBOM from storage
2. Returns 404 if no completed extraction exists
3. SPDX format option converts correctly from CycloneDX
4. Download button shows extraction timestamp
5. Download button disabled when no extraction completed
6. Any project viewer can download SBOM

#### Legal Notice tests (5F):

1. `GET /api/projects/:id/legal-notice` returns grouped notice with license texts
2. Dependencies grouped by license type
3. Copyleft licenses include full text from `license_obligations`
4. Unknown licenses grouped with note
5. Any project viewer can download notice

#### Test files:

`**ee/backend/routes/__tests__/compliance-api.test.ts`:**

- Tests 4-8 (re-evaluate endpoint)
- Tests 50-55 (SBOM export endpoint)
- Tests 56-60 (legal notice endpoint)
- Tests 25-31 (preflight check endpoint)

`**frontend/src/__tests__/compliance-project-tab.test.ts`:**

- Tests 1-3, 9-21 (Project subtab UI)
- Tests 14-18 (Policy Source Card, Action Items, Quick Stats)

`**frontend/src/__tests__/compliance-preflight.test.ts`:**

- Tests 22-24, 26-31 (Preflight sidebar UI)

`**frontend/src/__tests__/compliance-policy-results.test.ts`:**

- Tests 32-46 (Policy Results tab and Apply for Exception flow)

`**frontend/src/__tests__/compliance-obligations.test.ts`:**

- Tests 47-49 (License Obligations UI)
