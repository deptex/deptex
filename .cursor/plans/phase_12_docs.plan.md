---
name: Phase 12 - Documentation Overhaul
overview: Update 4 existing docs, create 7 new docs, remove merged nav items.
todos:
  - id: phase-12-docs
    content: "Phase 12: Documentation Overhaul - Update 4 existing docs (Policies, Notifications, Integrations, Introduction), create 7 new docs (Vulnerabilities, Projects, Dependencies, Compliance, Quick Start, Organizations, SBOM Compliance), remove merged nav items"
    status: pending
isProject: false
---
## Phase 12: Documentation Overhaul

**Goal:** Update all existing docs to reflect the new features (custom statuses, scoring, AI fixing) and create all missing "coming soon" pages that are relevant to project features. Merge overlapping feature docs into their Core Concepts counterparts. Leave unrelated sections (Anomaly Detection, Security Agent, Teams, API Reference, Learn) as "coming soon."

**Files:** [DocsPage.tsx](frontend/src/app/pages/DocsPage.tsx), [docsConfig.ts](frontend/src/app/pages/docsConfig.ts)

### 12A: Navigation Config Changes

Update [docsConfig.ts](frontend/src/app/pages/docsConfig.ts):

- **Remove** "Dependency Tracking" (`dependency-tracking`) from the Features group (merged into Dependencies)
- **Remove** "Vulnerability Intelligence" (`vulnerability-intelligence`) from the Features group (merged into Vulnerabilities)
- Final Features group should be: SBOM Compliance, Anomaly Detection, Security Agent

### 12B: Update Policies Doc (MAJOR rewrite)

The current Policies doc references `projectCompliance(context)` returning `{ compliant: boolean }` and `pullRequestCheck(context)` returning `{ passed: boolean }`. This all changes with custom statuses and the 3-function split from Phase 4.

**Changes required:**

- Replace the two-function model with three functions: `packagePolicy(context)`, `projectStatus(context)`, `pullRequestCheck(context)`
- Document `packagePolicy`: receives `context.dependency` (package-level data) + `context.tier` (project's asset tier: name, rank, multiplier). Returns `{ allowed: boolean, reasons: string[] }`. Runs per-dependency.
- Rename `projectCompliance(context)` to `projectStatus(context)` - receives all deps with `policyResult` embedded. Returns `{ status: 'StatusName', violations: string[] }`
- `pullRequestCheck(context)` - receives added/updated/removed deps with `policyResult`. Returns `{ status: 'StatusName', violations: string[] }`
- Explain that all three code blocks are stored in separate tables (`organization_package_policies`, `organization_status_codes`, `organization_pr_checks`) and can be independently overridden per project
- Add a new section: **"Custom Statuses"** explaining that orgs define their own statuses (name, color, rank, `is_passing`) in Settings -> Statuses, and that policy functions return one of these status names
- Add a new section: **"Built-in Functions"** documenting:
  - `fetch(url, options)` - async HTTP requests to external APIs (any URL allowed, proxied through sandbox)
  - `isLicenseAllowed(license, allowlist)` - check license against an allowlist
  - `semverGt(a, b)` - semver comparison
  - `daysSince(dateString)` - days elapsed since a date
- Add new dependency context fields to `dependencyFields`:
  - `malicious_indicator` (object | null) - malicious package detection result with `source`, `confidence`, `reason`
  - `slsa_level` (number) - SLSA provenance level (0-4)
  - `is_dev_dependency` (boolean) - whether this is a dev-only dependency
  - `dependency_score` (number) - Deptex package reputation score (0-100) with SLSA and malicious multipliers applied
- Add new project context fields to `projectFields`:
  - `status` (string) - current custom status name
  - `status_is_passing` (boolean) - whether the current status is marked as passing
- Update `complianceContextFields` label from "projectCompliance" to "projectStatus"
- **Update ALL example policies** to return `{ status: 'StatusName', violations }` instead of `{ passed: boolean, violations }`:
  - License example: return `{ status: violations.length === 0 ? 'Compliant' : 'Non-Compliant', violations }`
  - Critical vulns example: return `{ status: ..., violations }`
  - OpenSSF example: return `{ status: ..., violations }`
  - Supply chain example: return `{ status: ..., violations }`
- **Add new example**: "Custom Status with External API" showing `fetch()` usage:

```javascript
async function projectStatus(context) {
  const violations = [];
  let approved = [];
  try {
    const resp = await fetch('https://internal-api.company.com/approved-packages');
    approved = await resp.json();
  } catch (e) {
    // Fetch resilience: if API is down, skip the approved-list check
  }
  if (approved.length > 0) {
    for (const dep of context.dependencies) {
      if (!approved.includes(dep.name)) {
        violations.push(`${dep.name} not in approved registry`);
      }
    }
  }
  if (violations.length > 10) return { status: 'Blocked', violations };
  if (violations.length > 0) return { status: 'Review Required', violations };
  return { status: 'Approved', violations: [] };
}
```

- **Add new example**: "Malicious Package Detection" using `malicious_indicator`:

```javascript
function projectStatus(context) {
  const violations = [];
  for (const dep of context.dependencies) {
    if (dep.malicious_indicator) {
      violations.push(
        `MALICIOUS: ${dep.name} (${dep.malicious_indicator.source}: ${dep.malicious_indicator.reason})`
      );
    }
  }
  if (violations.length > 0) return { status: 'Blocked', violations };
  return { status: 'Safe', violations: [] };
}
```

- Replace **Exception Applications** section with **"Policy Changes"** section documenting the git-like versioning system: how changes are requested, the commit chain model, conflict detection, AI-powered merge resolution, reverting to previous versions, and the difference between inherited vs custom project policies
- Update **API Endpoints** to add:
  - `GET /api/organizations/:id/statuses` - List custom statuses
  - `POST /api/organizations/:id/statuses` - Create custom status
  - `PUT /api/organizations/:id/statuses/:statusId` - Update custom status
  - `DELETE /api/organizations/:id/statuses/:statusId` - Delete custom status

### 12C: Update Notification Rules Doc (MAJOR rewrite)

The current doc has 10 event types, a basic context object, and 6 examples. Phase 9 expands this to 20 event types, a richer context with PR/batch fields, `fetch()` support, enhanced return values, validation on save, delivery tracking, and test/preview. This is a near-complete rewrite.

**Changes required:**

**Event types -- replace `notificationTriggerEvents` with the full Phase 9 catalog (20 events):**

- Keep existing: `vulnerability_discovered`, `dependency_added`, `dependency_updated`, `dependency_removed`, `license_violation`, `supply_chain_anomaly`, `new_version_available`, `security_analysis_failure`
- Update existing: `compliance_violation` (now references custom statuses, not binary compliant/non-compliant), `risk_score_changed` (unchanged)
- Add new events:
  - `vulnerability_severity_increased` - EPSS score jumped significantly, or CISA KEV flag added
  - `vulnerability_resolved` - Vuln no longer affects project (dep upgraded, removed, or advisory withdrawn)
  - `dependency_deprecated` - Upstream package marked as deprecated
  - `policy_violation` - Package policy returned `allowed: false` for a dependency
  - `status_changed` - Project custom status changed (e.g., "Compliant" -> "Blocked")
  - `extraction_completed` - Dependency extraction finished successfully
  - `extraction_failed` - Dependency extraction failed with error
  - `pr_check_completed` - PR guardrails check finished (pass or fail)
  - `malicious_package_detected` - Dependency flagged as potentially malicious
  - `ai_fix_completed` - AI-powered fix PR was generated for a vulnerability

**Context object -- update all field tables:**

- Update `notifContextProjectFields`:
  - Replace `is_compliant` (boolean) with `status` (string - custom status name) and `status_is_passing` (boolean)
  - Add `asset_tier_rank` (number), `team_name` (string | null)
- Update `notifContextPreviousFields`:
  - Replace `is_compliant` with `previous_status` (string | undefined), `previous_status_is_passing` (boolean | undefined)
- Add `notifContextDependencyFields` new entries: `malicious_indicator` (object | null), `slsa_level` (number), `is_dev_dependency` (boolean), `dependency_score` (number)
- Add entirely new `context.pr` section: `number`, `title`, `author`, `base_branch`, `head_branch`, `check_result`, `check_summary`, `deps_added`, `deps_updated`, `deps_removed`, `provider_url`. Present for `pr_check_completed` events.
- Add entirely new `context.batch` section: `total`, `by_type` (Record<string, number>), `events` (array of summaries). Present when multiple events are batched into a single notification.

**New section: "Built-in Functions":**

- Document that notification trigger code runs in the same isolated-vm sandbox as policy code
- `fetch(url, options)` - async HTTP requests to external APIs (same as policy engine, 10s per-fetch timeout)
- Explain the fetch resilience requirement: code using `fetch()` must handle network failures with try/catch or save is blocked

**New section: "Enhanced Return Values":**

- Document that trigger functions can return:
  - `true` / `false` (basic)
  - `{ notify: true, message?: string, title?: string, priority?: 'critical' | 'high' | 'normal' | 'low' }` (custom message)
- Example: returning a custom Slack message title based on severity

**New section: "Validation on Save":**

- Explain the 3-check validation: syntax compilation, shape validation (must return boolean or `{ notify }` object), fetch resilience
- Show the validation output format with pass/fail indicators
- Note that save is blocked if any check fails

**New section: "Event Batching":**

- Explain that high-volume events (many deps changed in one extraction) are grouped into a single summary notification
- Critical events (malicious_package_detected, CISA KEV vulns) are never batched
- Trigger code can access `context.batch` for batch-aware filtering

**New section: "Notification History":**

- Explain the History tab in Organization Settings -> Notifications
- What's tracked: event, rule, destination, status (delivered/failed/rate_limited/skipped), timestamps
- Retry button for failed deliveries
- 90-day retention

**New section: "Test and Preview":**

- Explain the "Test Rule" button in the rule editor
- How it runs the code against sample events and shows what would happen
- The "Send Test" button for sending a real test notification with `[TEST]` prefix

**Updated examples -- replace all 6 with new ones covering new features:**

1. "High Depscore Vulnerability Alert" (updated - same pattern)
2. "Critical Reachable Vulnerabilities Only" (updated - same pattern)
3. "Malicious Package Alert" (NEW) - notify immediately when `malicious_package_detected`
4. "Status Regression Alert" (NEW) - notify when status changes from passing to non-passing
5. "AI Fix Ready for Review" (NEW) - notify when `ai_fix_completed` with a PR link
6. "PR Check Failure Alert" (NEW) - notify when PR guardrails fail on Crown Jewels projects
7. "Batch-Aware Dependency Change Summary" (NEW) - filter on `context.batch` counts
8. "External API Check with Fetch" (NEW) - use `fetch()` to check an internal allowlist before notifying

### 12D: Update Integrations Doc

**Changes required:**

- Add new section: **"Pull Request Checks"** explaining:
  - How PR checks are triggered (dependency changes detected in PR)
  - How the `pullRequestCheck` policy function maps custom statuses to GitHub/GitLab/Bitbucket pass/fail (status `is_passing` = pass, not passing = fail)
  - What the check summary shows (status name, violation list)
- Add new section: **"GitLab and Bitbucket Webhooks"** explaining:
  - GitLab webhook setup for merge request events
  - Bitbucket webhook setup for pull request events
  - How incremental extraction works for new commits
- Add new section: **"AI-Powered Fixing"** explaining:
  - How Aider integration works at a high level
  - That fixes create PRs automatically in the connected repository
  - The review workflow for AI-generated fixes
- Add new webhook event types to the Event Types table (underscore format, matching internal event types):
  - `vulnerability_severity_increased` - EPSS or KEV changed on existing vuln
  - `vulnerability_resolved` - Vuln no longer affects project
  - `dependency_deprecated` - Upstream package marked deprecated
  - `policy_violation` - Package policy violation detected
  - `status_changed` - Project status changed
  - `compliance_violation` - Project transitioned to non-passing status
  - `extraction_completed` - Extraction finished successfully
  - `extraction_failed` - Extraction failed with error
  - `pr_check_completed` - PR compliance check finished
  - `malicious_package_detected` - Malicious package found
  - `ai_fix_completed` - AI fix PR created
  - `risk_score_changed` - Project health score crossed a threshold
- Update existing event types in the table to use underscore format consistently (e.g., `vulnerability.found` -> `vulnerability_discovered`, `vulnerability.resolved` -> `vulnerability_resolved`)

### 12E: Update Introduction Doc

**Changes required:**

- Update `introductionOffers` array to include:
  - Custom organization-defined statuses for project compliance
  - AI-powered vulnerability fixing with automated PR creation
  - Enhanced scoring: Dependency Score (package reputation) and Depscore (vulnerability risk)
  - Live extraction logs with real-time progress tracking
  - SLSA provenance verification and malicious package detection
- Update the opening paragraph to mention custom statuses and AI fixing

### 12F: Create Vulnerabilities Doc (NEW - absorbs "Vulnerability Intelligence")

This is a comprehensive doc covering everything about how Deptex handles vulnerabilities. Create `VulnerabilitiesContent` component.

**Sections:**

1. **Overview** - How Deptex discovers, enriches, and prioritizes vulnerabilities using dep-scan, OSV, NVD
2. **Depscore** - The composite risk scoring formula explained:
  - Formula: `baseImpact * threatMultiplier * environmentalMultiplier * dependencyContextMultiplier`
  - Base Impact: Normalized CVSS (0-10 mapped to 0-100)
  - Threat Multiplier: EPSS probability boost (1.0-1.5x), CISA KEV boost (1.3x)
  - Environmental Multiplier: Asset tier weight (Crown Jewels 1.5x, External 1.2x, Internal 1.0x, Non-Production 0.6x), reachability (unreachable 0.4x)
  - Dependency Context Multiplier (NEW): Directness (transitive 0.75x), environment (dev 0.4x), malicious (1.3x), package reputation (low score slight penalty)
  - Include a visual breakdown example showing how a CVSS 7.5 vuln scores differently across contexts
3. **Reachability Analysis** - How Deptex uses Semgrep for static analysis to determine if vulnerable code paths are actually reachable. Tiers: Reachable (confirmed call path), Potentially Reachable (same module imported), Unreachable (no import path), Unknown (analysis inconclusive)
4. **EPSS Scoring** - Explain the Exploit Prediction Scoring System: probability of exploitation in next 30 days, how it differs from CVSS
5. **CISA KEV** - Explain the Known Exploited Vulnerabilities catalog: actively exploited in the wild, mandatory remediation for US federal agencies, used as a strong threat signal
6. **Vulnerability Detail Sidebar** - Overview of what the vulnerability detail view shows: advisory info, affected versions, fix versions, affected code locations, reachability path, Depscore breakdown
7. **AI-Powered Fixing** - How Aider generates patches: clones repo, analyzes vulnerable code, generates fix, creates PR. Safety measures and human review workflow
8. **Background Monitoring** - How Deptex periodically checks for new vulnerabilities against existing dependencies without requiring a full re-extraction
9. **Version Management** - How Deptex shows safer versions, versions behind count, and upgrade paths

### 12G: Create Projects Doc (NEW)

Create `ProjectsContent` component.

**Sections:**

1. **Overview** - What a project represents in Deptex (a monitored repository)
2. **Creating a Project** - Connect to GitHub/GitLab/Bitbucket, select a repository, choose a team
3. **Extraction Pipeline** - What happens during extraction: clone -> SBOM generation (cdxgen) -> vulnerability scan (dep-scan) -> SAST analysis (Semgrep) -> secrets detection (TruffleHog) -> scoring. Mention each tool and what it produces
4. **Live Extraction Logs** - Real-time progress with color-coded log levels, historical run browsing
5. **Project Status** - How custom statuses are assigned by policy evaluation, what `is_passing` means, how exceptions work
6. **Project Settings** - Asset tier, policy inheritance (org vs project), repository settings, sync configuration
7. **Project Overview Dashboard** - What the overview screen shows: health score, compliance rate, top vulnerabilities, recent activity

### 12H: Create Dependencies Doc (NEW - absorbs "Dependency Tracking")

Create `DependenciesContent` component.

**Sections:**

1. **Overview** - How Deptex discovers and tracks dependencies from manifest files and lockfiles
2. **Dependency Score** - The package reputation formula explained:
  - Base score: OpenSSF Scorecard (40%), popularity/weekly downloads (30%), maintenance/releases (30%)
  - SLSA multiplier: SLSA level > 1 gets 1.05-1.1x bonus
  - Malicious multiplier: Flagged packages get 0.1x penalty (score 80 -> 8)
  - Score range: 0-100, higher is better
3. **Direct vs Transitive** - How Deptex distinguishes direct deps (in your manifest) from transitive (pulled in by other deps), and why it matters for risk assessment
4. **Dev vs Production** - How Deptex identifies dev-only dependencies and why they carry lower risk (0.4x weight in Depscore)
5. **Supply Chain Signals** - Registry integrity checks, install script analysis, entropy/obfuscation detection. What "pass", "warning", and "fail" mean
6. **Malicious Package Detection** - How Deptex checks packages against known malicious package databases, the `malicious_indicator` object (source, confidence, reason)
7. **SLSA Provenance** - What SLSA levels mean (0-4), how Deptex verifies build provenance
8. **Version Management** - Outdated detection, versions behind count, safe upgrade recommendations

### 12I: Create Compliance Doc (NEW)

Create `ComplianceContent` component.

**Sections:**

1. **Overview** - How Deptex approaches compliance: custom statuses + policy-as-code + license tracking
2. **Custom Statuses** - How organizations define their own statuses (Settings -> Statuses), with name, color, rank, and `is_passing` flag. How statuses are assigned by policy evaluation. Link to Policies doc for policy code details
3. **Policy Evaluation Flow** - Step by step: extraction completes -> policy code runs -> status assigned to project -> violations stored -> badges updated
4. **SBOM Export** - CycloneDX 1.5 and SPDX format support, how SBOMs are generated by cdxgen, export options from the Compliance tab
5. **Legal Notice Export** - How to generate a legal notice document listing all dependencies and their licenses
6. **License Tracking** - How Deptex identifies licenses per dependency, license compliance in the context of policy-as-code (using `isLicenseAllowed` helper or custom checks)
7. **Policy Changes (Git-like Versioning)** - How projects can deviate from the org policy through a commit-chain model, requesting changes, conflict resolution with AI merge, reverting to previous versions or back to org base, one-click license exceptions, and the Policy Change History view
8. **Preflight Check** - How to test whether adding a package would affect your project's compliance status before committing the change

### 12J: Create Quick Start Doc (NEW)

Create `QuickStartContent` component. A concise step-by-step guide:

1. **Create an Organization** - Sign up, create your first org
2. **Connect an Integration** - Go to Settings -> Integrations, connect GitHub (or GitLab/Bitbucket)
3. **Create a Project** - Click "New Project", select a repository, assign to a team
4. **Watch the Extraction** - Live logs show real-time progress as Deptex scans your repo
5. **Explore Your Dashboard** - Navigate the project overview: dependencies, vulnerabilities, compliance status
6. **Set Up Policies** (optional) - Go to Settings -> Policies to define custom compliance rules
7. **Define Custom Statuses** (optional) - Go to Settings -> Statuses to create org-specific status labels
8. **Configure Notifications** (optional) - Go to Settings -> Notification Rules to set up alerts

Each step should include a brief description (2-3 sentences) and reference the relevant detailed doc page.

### 12K: Create Organizations Doc (NEW)

Create `OrganizationsContent` component.

**Sections:**

1. **Overview** - What an organization is in Deptex, multi-org support
2. **Organization Settings** - General settings, branding, default configurations
3. **Custom Statuses** - The Statuses tab in Settings: creating statuses (name, color, rank, `is_passing`), reordering by drag, system statuses vs custom statuses, how statuses appear on project/team cards
4. **Roles and Permissions** - Overview of the RBAC system, key permissions including `manage_statuses`, `manage_compliance`, `manage_integrations`
5. **Members** - Inviting members, assigning roles, team membership
6. **Teams** - Brief overview of team scoping (link to Teams doc when it's built)
7. **Integrations Overview** - Brief mention of available integrations (link to Integrations doc for details)

### 12L: Create SBOM Compliance Doc (NEW)

Create `SBOMComplianceContent` component.

**Sections:**

1. **Overview** - What is a Software Bill of Materials and why it matters
2. **SBOM Generation** - How cdxgen generates SBOMs during the extraction pipeline, supported ecosystems (npm, pip, Go, Maven, Cargo, Bundler, etc.)
3. **CycloneDX Format** - CycloneDX 1.5 support, what's included (components, dependencies, vulnerabilities, licenses)
4. **SPDX Format** - SPDX format support, differences from CycloneDX
5. **Storage and Access** - SBOMs stored in Supabase Storage, accessible per extraction run
6. **Export Options** - Download from the Compliance tab, API access
7. **Legal Notice Generation** - Auto-generated notice files listing all dependencies and their license texts, useful for compliance with open-source license obligations
8. **Compliance Frameworks** - Brief mention of how SBOMs support EO 14028, NTIA minimum elements, EU CRA

### 12M: Update docMeta and renderContent

In [DocsPage.tsx](frontend/src/app/pages/DocsPage.tsx):

- Update `docMeta` descriptions for all updated/new sections to reflect new content
- Add cases to the `renderContent()` switch statement for all 7 new sections
- Remove standalone `docMeta` entries for `dependency-tracking` and `vulnerability-intelligence` (they'll 404 to "Not Found" since they're removed from nav)
- Update `helpDocLinks` to include new doc pages (Projects, Dependencies, Vulnerabilities, Compliance, Quick Start)

### Implementation Notes

- All new content components follow the same JSX pattern as existing ones (use `FieldTable`, code blocks in `<pre>`, card-based sections with `rounded-lg border border-border bg-background-card`)
- The Policies doc is the largest change due to the custom status overhaul
- New docs should cross-link to each other (e.g., Compliance links to Policies for code details, Vulnerabilities links to Dependencies for Depscore context factors)
- This file is already ~1300 lines. Consider splitting into separate files (e.g., `docs/VulnerabilitiesContent.tsx`) if DocsPage.tsx gets unwieldy. Alternatively, keep everything in one file for consistency with the current approach and let the switch statement route to components.
