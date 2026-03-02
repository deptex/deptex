---
name: Phase 8 - PR Management & Webhooks
overview: Manifest registry, smart push/scheduled extraction, PR tracking, GitLab/Bitbucket webhooks, repo lifecycle handling, watchtower-poller QStash migration, webhook deliveries audit trail, worker Fly.io migration strategy, full security hardening.
todos:
  - id: phase-8-pr
    content: "Phase 8: PR Management & Webhooks - Manifest registry, smart push extraction (sync_frequency + change detection), daily/weekly extraction scheduler (QStash), watchtower-poller QStash migration, project commits tracking, multi-ecosystem PR analysis, per-project check runs, smart comment system (edit existing), PR tracking table, PR guardrails via Phase 4 policy engine (no separate org_pr_guardrails table), webhook deliveries audit table, GitLab webhook + MR support, Bitbucket webhook + PR support, repo lifecycle event handling (rename/delete/transfer/default_branch), webhook health display, compliance tab real data (Updates sub-tab), security hardening (replay protection, size limits, concurrency caps, fork PRs), worker Fly.io migration strategy (watchtower-worker + parser-worker targets documented), 50 edge cases + 70 tests"
    status: pending
isProject: false
---

## Phase 8: PR Management and Webhooks

**Goal:** Build a rock-solid PR management and webhook system that intelligently handles pushes and pull requests across GitHub, GitLab, and Bitbucket, with proper monorepo support, per-project check runs, smart comment deduplication, full PR lifecycle tracking, scheduled extraction, repository lifecycle event handling, and zero edge-case surprises. Migrate the watchtower-poller to QStash cron for cloud-native operation.

**Key design decisions:**

- Separate check runs per affected project in a monorepo (e.g. "Deptex - packages/api", "Deptex - packages/web")
- Edit existing Deptex PR comment instead of posting new ones (one comment per PR, always up-to-date)
- Single aggregated comment with per-project sections (not one comment per project)
- PR checks available on ALL plans (Free, Pro, Enterprise) -- this is a core feature
- Always run checks on draft PRs (simpler, low cost)
- Only run PR checks on PRs targeting the default branch (skip PRs to feature branches)
- Push-only re-runs (no `/deptex recheck` comment commands -- push a commit to re-trigger)
- No advisory mode -- guardrails are binary: if enabled, they block
- `sync_frequency` column added in this phase with default `'on_commit'` (Phase 13 adds plan-tier restrictions)
- Detect all ecosystem manifests in change detection (future-proofed even though extraction currently only supports npm)
- **Phase 8 builds the daily/weekly extraction scheduler** (QStash cron) -- not deferred to Phase 13
- **Watchtower-poller migrated to QStash cron** -- eliminates the need for a dedicated 24/7 polling machine
- **Repository lifecycle events fully handled** -- renames, deletions, transfers, default branch changes, installation removal all update our DB
- **Security-first approach** -- strict webhook verification in production, replay protection for GitLab, comment/check-run size limits, concurrency caps for monorepos, fork PR handling, webhook endpoint rate limiting
- **Per-org extraction concurrency cap** of 10 jobs per push event to prevent monorepo explosion

**Extraction architecture (critical clarification):**

The current push handler calls `extractDependencies()` inline -- a lightweight lockfile-only parser that runs on the main backend. This is **wrong** for Phase 8. It only parses `package-lock.json` via GitHub API and gives incomplete data (no dep-scan, no Semgrep, no TruffleHog, no AST, no SBOM). Phase 8 replaces this with `queueExtractionJob()` which triggers the **full Fly.io extraction pipeline** (clone, cdxgen, dep-scan, AST, Semgrep, TruffleHog).

There are three distinct scenarios with different execution paths:

```
SCENARIO 1: Push/merge to default branch (manifest changed, sync_frequency allows)
  -> queueExtractionJob() -> Fly.io extraction worker (FULL pipeline)
  -> Clone -> cdxgen SBOM -> parse -> upsert deps -> queue populate -> AST -> dep-scan -> Semgrep -> TruffleHog -> upload
  -> populate-dependencies (QStash): npm registry + GHSA vulns + OpenSSF + policy evaluation
  -> Result: project fully re-scanned, all data fresh
  -> Cost: ~$0.13-0.19 per extraction, 2-15 minutes
  -> Frequency: controlled by sync_frequency (on_commit, daily, weekly, manual)

SCENARIO 2: PR opened/synchronize (NOT merged)
  -> NO extraction triggered
  -> Read base + head manifest/lockfile content via provider API (GitHub Contents, GitLab Files, Bitbucket Source)
  -> Compare deps: find added, bumped, removed, transitive changes
  -> Check each changed package against EXISTING vuln data in our DB (from last full extraction)
  -> Check licenses against org policies
  -> Create check runs + post/edit PR comment with results
  -> Cost: zero (just API calls to provider + DB reads)
  -> Duration: seconds

SCENARIO 3: Scheduled extraction (8N -- daily/weekly cron)
  -> Same as Scenario 1: queueExtractionJob() -> Fly.io full pipeline
  -> Triggered by QStash cron for projects with sync_frequency = 'daily' or 'weekly'
  -> Handles projects that opted out of on_commit extraction
```

The lightweight `extractDependencies()` in `workers.ts` is **deprecated** for push handling. It remains available for the `/api/workers/extract-deps` legacy endpoint but the push handler no longer calls it.

**Why full extraction on every qualifying push?** Without it, a project gets updated dep counts but no dep-scan vulns (only GHSA), no Semgrep findings, no TruffleHog secrets, no fresh SBOM, no reachability analysis. This makes the Security tab stale between full scans. The cost (~$0.15/push) is acceptable because `sync_frequency` controls how often it happens -- orgs that push frequently can set `daily` or `weekly` instead of `on_commit`.

**Why no extraction on PR events?** PR analysis is purely comparative -- we read the before/after manifest files via the provider's API and check changed packages against data we already have. This is fast (seconds) and free. The full extraction runs when the PR is actually merged (which triggers a push event).

**Current state (what exists):**

- GitHub webhook endpoint `POST /api/webhook/github` in [ee/backend/routes/integrations.ts](ee/backend/routes/integrations.ts)
- Events handled: `installation`, `installation_repositories`, `push`, `pull_request`, `repository`
- `handlePushEvent`: extracts ALL projects on every push (no manifest change detection, no sync_frequency check)
- `handlePullRequestEvent`: only detects `package.json`/`package-lock.json` (npm only), posts NEW comment every push (spam), one combined check run for all projects, ignores `pull_request_comments_enabled` toggle, no "in_progress" state
- `verifyGitHubWebhookSignature`: skips verification if `GITHUB_WEBHOOK_SECRET` not set
- `project_pr_guardrails` table: block_critical/high/medium/low_vulns, block_policy_violations, block_transitive_vulns
- `pull_request_comments_enabled` column on `project_repositories` (stored but never checked in handler)
- GitHub API helpers in [ee/backend/lib/github.ts](ee/backend/lib/github.ts): `createCheckRun`, `updateCheckRun`, `listCheckRunsForRef`, `createIssueComment`, `getCompareChangedFiles`
- Git provider abstraction in [ee/backend/lib/git-provider.ts](ee/backend/lib/git-provider.ts): `GitProvider` interface with `GitHubProvider`, `GitLabProvider`, `BitbucketProvider` (basic API calls only, no webhook/PR support)
- No GitLab or Bitbucket webhook handlers
- No PR tracking in our database
- No commit tracking in our database
- Compliance tab Updates section in [ProjectCompliancePage.tsx](frontend/src/app/pages/ProjectCompliancePage.tsx) uses mock data for Pull Requests and Commits sub-tabs

### 8A: Manifest File Registry

Create a shared manifest file registry used by both the push handler (change detection) and the PR handler (workspace detection). This replaces the current hardcoded `package.json`/`package-lock.json` matching.

**File:** `ee/backend/lib/manifest-registry.ts`

```typescript
export type EcosystemId = 'npm' | 'python' | 'go' | 'java' | 'rust' | 'ruby' | 'dotnet' | 'php';

export interface ManifestPattern {
  ecosystem: EcosystemId;
  filename: string;        // exact filename match (e.g. 'package.json')
  isLockfile: boolean;     // true for lockfiles, false for manifests
}

export const MANIFEST_PATTERNS: ManifestPattern[] = [
  // npm
  { ecosystem: 'npm', filename: 'package.json', isLockfile: false },
  { ecosystem: 'npm', filename: 'package-lock.json', isLockfile: true },
  { ecosystem: 'npm', filename: 'yarn.lock', isLockfile: true },
  { ecosystem: 'npm', filename: 'pnpm-lock.yaml', isLockfile: true },
  // Python
  { ecosystem: 'python', filename: 'requirements.txt', isLockfile: false },
  { ecosystem: 'python', filename: 'Pipfile', isLockfile: false },
  { ecosystem: 'python', filename: 'Pipfile.lock', isLockfile: true },
  { ecosystem: 'python', filename: 'pyproject.toml', isLockfile: false },
  { ecosystem: 'python', filename: 'poetry.lock', isLockfile: true },
  { ecosystem: 'python', filename: 'setup.py', isLockfile: false },
  { ecosystem: 'python', filename: 'setup.cfg', isLockfile: false },
  // Go
  { ecosystem: 'go', filename: 'go.mod', isLockfile: false },
  { ecosystem: 'go', filename: 'go.sum', isLockfile: true },
  // Java
  { ecosystem: 'java', filename: 'pom.xml', isLockfile: false },
  { ecosystem: 'java', filename: 'build.gradle', isLockfile: false },
  { ecosystem: 'java', filename: 'build.gradle.kts', isLockfile: false },
  { ecosystem: 'java', filename: 'gradle.lockfile', isLockfile: true },
  { ecosystem: 'java', filename: 'settings.gradle', isLockfile: false },
  { ecosystem: 'java', filename: 'settings.gradle.kts', isLockfile: false },
  // Rust
  { ecosystem: 'rust', filename: 'Cargo.toml', isLockfile: false },
  { ecosystem: 'rust', filename: 'Cargo.lock', isLockfile: true },
  // Ruby
  { ecosystem: 'ruby', filename: 'Gemfile', isLockfile: false },
  { ecosystem: 'ruby', filename: 'Gemfile.lock', isLockfile: true },
  // .NET
  { ecosystem: 'dotnet', filename: 'Directory.Packages.props', isLockfile: false },
  { ecosystem: 'dotnet', filename: 'packages.config', isLockfile: false },
  { ecosystem: 'dotnet', filename: 'packages.lock.json', isLockfile: true },
  // PHP
  { ecosystem: 'php', filename: 'composer.json', isLockfile: false },
  { ecosystem: 'php', filename: 'composer.lock', isLockfile: true },
];

const MANIFEST_FILENAMES = new Set(MANIFEST_PATTERNS.map(p => p.filename));

/**
 * Given a changed file path, return the workspace root and matched manifest,
 * or null if the file is not a manifest/lockfile.
 *
 * Examples:
 *   'package.json'                 -> { workspace: '', manifest: { ecosystem: 'npm', ... } }
 *   'packages/api/package.json'    -> { workspace: 'packages/api', manifest: { ecosystem: 'npm', ... } }
 *   'services/ml/requirements.txt' -> { workspace: 'services/ml', manifest: { ecosystem: 'python', ... } }
 *   'src/index.ts'                 -> null
 */
export function matchManifestFile(filePath: string): {
  workspace: string;
  manifest: ManifestPattern;
} | null {
  const filename = filePath.includes('/') ? filePath.split('/').pop()! : filePath;
  if (!MANIFEST_FILENAMES.has(filename)) return null;
  const manifest = MANIFEST_PATTERNS.find(p => p.filename === filename);
  if (!manifest) return null;
  const dirPart = filePath.includes('/') ? filePath.slice(0, filePath.lastIndexOf('/')) : '';
  return { workspace: dirPart, manifest };
}

/**
 * Given a list of changed file paths, return a map of workspace -> ecosystems
 * that had manifest/lockfile changes.
 */
export function detectAffectedWorkspaces(
  changedFiles: string[]
): Map<string, Set<EcosystemId>> {
  const result = new Map<string, Set<EcosystemId>>();
  for (const filePath of changedFiles) {
    const match = matchManifestFile(filePath);
    if (!match) continue;
    if (!result.has(match.workspace)) result.set(match.workspace, new Set());
    result.get(match.workspace)!.add(match.manifest.ecosystem);
  }
  return result;
}
```

### 8B: Sync Frequency and Push Event Intelligence

Rewrite [handlePushEvent](ee/backend/routes/integrations.ts) to be intelligent about WHEN and WHAT to extract.

**8B.1: Database migration -- sync_frequency column**

```sql
ALTER TABLE project_repositories
  ADD COLUMN sync_frequency TEXT NOT NULL DEFAULT 'on_commit';
-- Valid values: 'manual', 'on_commit', 'daily', 'weekly'
-- Phase 13 adds plan-tier restrictions (Free = manual only)
```

**8B.2: Rewritten handlePushEvent logic**

```
handlePushEvent(payload):
  1. Extract repo_full_name, ref, installation.id, before, after
  2. Skip if branch deleted (after is all zeros)
  3. Load all project_repositories where repo_full_name matches
  4. Filter to rows where ref === refs/heads/{default_branch}
  5. If no matching projects, return early

  6. Get installation token
  7. Call getCompareChangedFiles(token, repoFullName, before, after)
     - If Compare API fails (force push, 422): fall back to full extraction for all projects
  8. Use detectAffectedWorkspaces(changedFiles) to get workspace -> ecosystem map

  FOR EACH matched project:
    9.  Check sync_frequency:
        - 'manual': skip extraction, still record commit (step 13)
        - 'on_commit': proceed with extraction
        - 'daily' / 'weekly': skip extraction (handled by 8N scheduler), still record commit
    10. Check if this project's package_json_path is in the affected workspaces map
        - Also check: if root-level manifest changed AND this project's workspace is a subdirectory,
          treat as affected (root changes can affect all workspaces via hoisting)
    11. If affected AND sync_frequency allows: call queueExtractionJob() for this project
        - This queues a FULL Fly.io extraction (clone, cdxgen, dep-scan, AST, Semgrep, TruffleHog)
        - NOT the lightweight extractDependencies() -- that is deprecated for push handling
        - queueExtractionJob() already prevents duplicate jobs (skips if queued/processing exists)
        - The extraction worker picks up the job, runs the full pipeline, and calls queue-populate on completion
    12. If ANY file in this project's workspace changed (not just manifests) AND no extraction was queued:
        queue AST parsing via queueASTParsingJob()
        (this is for reachability -- code changes can make vulns reachable even without dep changes)
        (skip if extraction was queued in step 11, because the full pipeline includes AST analysis)
    13. Record commit in project_commits table (always, regardless of extraction)
    14. Invalidate project caches (extraction worker does this on completion, but also invalidate
        immediately for non-extraction data like commit counts)
```

**8B.3: Force push handling**

When `getCompareChangedFiles` returns a 422 (base SHA no longer exists):

- Log warning: "Force push detected, falling back to full extraction"
- Treat ALL workspaces as affected
- Extract all projects linked to this repo (with sync_frequency check still applied)

**8B.4: Root manifest change propagation**

If a root-level manifest changes (workspace = `''`), ALL projects in that repo should be treated as affected, because:

- npm workspace hoisting: root `package-lock.json` contains resolved versions for all workspaces
- Go workspace: root `go.work` affects all modules
- Root-level dependency changes cascade to sub-workspaces

**8B.5: Project Settings UI for sync_frequency**

In [ProjectSettingsPage.tsx](frontend/src/app/pages/ProjectSettingsPage.tsx) Repository section, add a "Sync Frequency" dropdown under the existing Automation section:

- Options: "On Every Commit" (`on_commit`), "Daily", "Weekly", "Manual Only"
- Default: "On Every Commit"
- Helper text: "Controls when Deptex re-extracts dependencies from this repository."
- Phase 13 will disable non-manual options on Free tier with an upgrade prompt

**API:** `PATCH /api/organizations/:id/projects/:projectId/repositories/settings` -- add `sync_frequency` to the accepted body fields (already exists for `pull_request_comments_enabled` and `auto_fix_vulnerabilities_enabled`).

**8B.6: Push handler safeguards**

- **Concurrency limit:** Before queuing extraction for a project, `queueExtractionJob` already checks for existing `queued`/`processing` jobs and skips duplicates. The push handler must use this (not call `extractDependencies` directly).
- **Per-org extraction cap:** Max 10 concurrent extraction jobs per org from a single push event. If a monorepo push affects more than 10 projects, queue the first 10, log a warning for the rest, and note that remaining projects will be picked up by the next scheduled extraction (8N) or next push.
- **Stale default_branch guard:** On every push event, compare `payload.repository.default_branch` with our stored `project_repositories.default_branch`. If they differ, update our DB before filtering. This is a belt-and-suspenders check alongside the `repository.edited` event handler (8P).
- **Installation scoping:** When loading `project_repositories` by `repo_full_name`, also filter by `installation_id` matching `payload.installation.id`. This prevents cross-org processing if multiple orgs have the same repo connected via different installations.
- **Payload size guard:** Add `express.json({ limit: '5mb' })` specifically for webhook routes. Payloads over 5MB are suspicious and should be rejected with 413.

### 8C: Project Commits Tracking

Track every commit that hits the default branch for each project. Powers the compliance tab Commits sub-tab.

**8C.1: Database schema**

```sql
CREATE TABLE project_commits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  sha TEXT NOT NULL,
  message TEXT,
  author_name TEXT,
  author_email TEXT,
  author_avatar_url TEXT,
  committed_at TIMESTAMPTZ,
  -- What happened when we processed this commit
  manifest_changed BOOLEAN NOT NULL DEFAULT false,
  extraction_triggered BOOLEAN NOT NULL DEFAULT false,
  extraction_status TEXT, -- 'success', 'failed', 'skipped'
  files_changed INTEGER,
  -- Compliance snapshot at time of commit
  compliance_status TEXT DEFAULT 'UNKNOWN', -- 'COMPLIANT', 'NON_COMPLIANT', 'UNKNOWN'
  dependencies_added INTEGER DEFAULT 0,
  dependencies_removed INTEGER DEFAULT 0,
  dependencies_updated INTEGER DEFAULT 0,
  -- Provider
  provider TEXT NOT NULL DEFAULT 'github', -- 'github', 'gitlab', 'bitbucket'
  provider_url TEXT, -- link to the commit on the provider
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_project_commits_project_id ON project_commits(project_id);
CREATE INDEX idx_project_commits_sha ON project_commits(sha);
CREATE UNIQUE INDEX idx_project_commits_project_sha ON project_commits(project_id, sha);
```

**8C.2: Recording commits from push events**

In the rewritten `handlePushEvent`, after processing each project:

- Extract commit info from the payload (`payload.commits` array for GitHub, or `payload.commits` for GitLab, `payload.push.changes[].new.target` for Bitbucket)
- For each commit in the push (there can be multiple if someone pushes multiple commits at once):
  - Upsert into `project_commits` with all available metadata
  - Set `manifest_changed` based on whether any manifest in this workspace was in the changed files
  - Set `extraction_triggered` and `extraction_status` based on what happened
- Handle the "squash merge" case: a single commit from a merged PR may represent many changes

**8C.3: API endpoint**

`GET /api/organizations/:id/projects/:projectId/commits` -- paginated, filterable by `compliance_status`, searchable by message/author. Returns the data needed by the compliance tab Commits sub-tab.

Query params: `status` (COMPLIANT/NON_COMPLIANT/UNKNOWN/ALL), `timeframe` (24H/7D/30D/ALL), `search`, `page`, `per_page`.

### 8D: Multi-Ecosystem PR Analysis

Extend [handlePullRequestEvent](ee/backend/routes/integrations.ts) to detect manifest changes across all ecosystems, not just npm.

**8D.1: Workspace detection rewrite**

Replace the current hardcoded `package.json`/`package-lock.json` matching:

```typescript
// BEFORE (current):
for (const filePath of changedFiles) {
  if (filePath === 'package.json' || filePath === 'package-lock.json') {
    affectedWorkspaces.add('');
    continue;
  }
  const match = filePath.match(/^(.+)\/(?:package\.json|package-lock\.json)$/);
  if (match) affectedWorkspaces.add(match[1]);
}

// AFTER:
const affectedWorkspaceMap = detectAffectedWorkspaces(changedFiles);
// affectedWorkspaceMap: Map<workspace, Set<EcosystemId>>
```

**8D.2: Per-ecosystem diff analysis (API-based, no extraction)**

**Important:** PR analysis does NOT trigger extraction. It reads manifest/lockfile content from the provider's API at the base and head SHAs, compares them, and checks changed packages against data already in our DB. This works across all three providers:

- **GitHub:** `GET /repos/{owner}/{repo}/contents/{path}?ref={sha}` via installation token
- **GitLab:** `GET /projects/{id}/repository/files/{path}?ref={sha}` via OAuth token (URL-encode path)
- **Bitbucket:** `GET /repositories/{workspace}/{repo}/src/{sha}/{path}` via OAuth token

The current PR handler reads `package.json` and `package-lock.json` from both base and head SHAs and computes added/bumped/transitive diffs. This logic needs to become ecosystem-aware:

- **npm** (already implemented): read `package.json` + lockfile, compute direct added/bumped + transitive changes. Check each changed package against `dependency_vulnerabilities` and `project_dependency_vulnerabilities` in our DB for vuln counts. Check licenses against org policies via `isLicenseAllowed()`.
- **Other ecosystems** (Python, Go, Java, Rust, Ruby, .NET, PHP): for now, detect that a manifest changed and report it in the comment as "Manifest file changed: `requirements.txt`" without deep diff analysis. Deep per-ecosystem diff analysis will be added as extraction support for each ecosystem lands (Phases 1-3).

This means the PR handler has two modes per workspace:

1. **Deep analysis** (npm): full dep diff, vuln checks, license checks, transitive analysis -- all from API reads + DB lookups
2. **Shallow analysis** (other ecosystems): flag that manifest changed, list which files, note that detailed analysis will be available once the ecosystem is fully supported

**Data freshness for PR checks:** PR analysis relies on vuln/license data from the LAST full extraction. If the project hasn't been extracted recently, the data may be stale. The PR comment includes a "Last scanned: {time ago}" footer. If >24 hours stale, add a note: "Vulnerability data may be outdated. Consider running a full scan."

**8D.3: Ecosystem detection on project_repositories**

Add `ecosystem` column to `project_repositories` (or derive it from which manifest files exist at `package_json_path`). For Phase 8, this can be derived dynamically from the changed files. When extraction supports more ecosystems, this becomes a stored value.

### 8E: Per-Project Check Runs

Replace the current single combined check run with separate check runs per affected project.

**8E.1: Check run naming**

Format: `Deptex - {project_name}` (e.g. "Deptex - packages/api", "Deptex - Web App")

If only one project is affected (most common case), the name is still `Deptex - {project_name}` for consistency.

**8E.2: Check run lifecycle**

Current behavior jumps straight to `completed`. New lifecycle:

```
1. PR event received (opened / synchronize / reopened)
2. For each affected project:
   a. Create check run with status='in_progress', name='Deptex - {project_name}'
   b. Run the analysis (vuln checks, policy checks, license checks)
   c. Update check run with status='completed', conclusion='success' or 'failure'
      Include detailed output in the check run body (summary + per-dep results)
3. If analysis crashes: update check run with conclusion='failure', output='Internal error'
```

**8E.3: Check run output format**

The check run `output` object:

- `title`: "Passed -- all checks clear" or "Failed -- 3 issues found"
- `summary`: Markdown summary with counts (X vulns, Y policy violations, Z transitive issues)
- `text`: Detailed per-dependency breakdown (same content as the PR comment section for this project)

**8E.4: Stale check run cleanup**

When a new push arrives (`synchronize` action), the old check runs for the previous SHA are automatically superseded by GitHub (they show as "stale"). We create new check runs for the new head SHA. No explicit cleanup needed.

**8E.5: Only PRs targeting default branch**

Before processing, check if `pr.base.ref` matches the project's `default_branch`. If not, skip. This avoids running checks on PRs between feature branches.

```typescript
// In handlePullRequestEvent, after loading project rows:
const row = projectRows.find(r => r.default_branch === pr.base.ref);
// Only process projects where the PR targets their default branch
```

**8E.6: Draft PR handling**

Process draft PRs the same as regular PRs. The `pull_request` webhook fires for drafts with `pr.draft === true`. No special logic needed -- we always run checks.

**8E.7: Fork PR handling**

When `pull_request.head.repo.fork === true` (or `head.repo.full_name !== base.repo.full_name`):

- The GitHub App installation token may not have access to the fork repo's files
- Strategy:
  1. Try reading head SHA files via the installation token (works if the fork's owner installed our App)
  2. If 404/403: fall back to base-branch-only analysis -- compare base branch deps against our DB, report in check run: "Fork repository -- head branch analysis unavailable. Showing base branch dependency state only."
  3. Still create the check run on the base repo (we always have access to the base repo)
  4. PR comment includes a note: "Full dependency diff unavailable for fork PRs without the Deptex GitHub App installed."
- GitLab MRs from forks: use the target project's OAuth token. If source project is inaccessible, same fallback.
- Bitbucket PRs from forks: same pattern.

**8E.8: Check run output size limit**

GitHub caps the check run `text` field at 65,535 characters. If the per-dependency breakdown exceeds this:

1. Truncate the `text` field with a summary and a "View full results in Deptex" link
2. The `summary` field (shorter) always fits -- keep it as the primary info
3. Test with a synthetic 200-dependency monorepo scenario to verify truncation works

### 8F: Smart Comment System

Replace the current "post new comment every time" behavior with an edit-existing-comment system.

**8F.1: Comment marker**

Every Deptex PR comment starts with a hidden HTML marker so we can find it later:

```markdown
<!-- deptex-pr-check -->
## Deptex Dependency Check

...
```

**8F.2: Find-and-edit flow**

```
1. List existing PR comments via API (GitHub: GET /repos/{owner}/{repo}/issues/{pr}/comments)
2. Search for a comment that:
   a. Was posted by the Deptex GitHub App (check comment.user.login matches the app's bot username)
   b. Contains the marker <!-- deptex-pr-check -->
3. If found: EDIT that comment (GitHub: PATCH /repos/{owner}/{repo}/issues/comments/{comment_id})
4. If not found: CREATE a new comment (current behavior)
```

**8F.3: Aggregated comment format**

Single comment with sections per affected project:

```markdown
<!-- deptex-pr-check -->
## Deptex Dependency Check

### packages/api (Project: "API Service")

**Packages updated:**
- **express** `4.18.2` -> `4.19.0` -- 0 vulnerabilities
- **lodash** `4.17.20` -> `4.17.21` -- 0 vulnerabilities

**Packages added:**
- **new-pkg** `1.0.0` -- license: MIT; 0 vulnerabilities

**Transitive dependencies (new/updated):**
- **sub-dep** `2.0.0` -- license: Apache-2.0; 1 high vulnerability

---

**This project cannot be merged until the above issues are resolved.**

---

### packages/web (Project: "Web App")

No dependency changes detected.

---

*Last updated: 2026-02-28 14:30 UTC | [View in Deptex](https://app.deptex.io/...)*
```

**8F.4: Respect pull_request_comments_enabled**

The current code ignores `pull_request_comments_enabled` on `project_repositories`. Fix:

```typescript
// Before posting/editing the comment:
const { data: repoSettings } = await supabase
  .from('project_repositories')
  .select('pull_request_comments_enabled')
  .eq('project_id', projectId)
  .single();

if (repoSettings?.pull_request_comments_enabled === false) {
  // Skip comment for this project (still run check runs)
}
```

If ALL projects have comments disabled, don't post/edit any comment. If SOME have comments disabled, only include sections for projects with comments enabled.

Check runs always run regardless of this toggle (they're a separate feature).

**8F.5: Idempotency on webhook retries**

GitHub retries webhook deliveries if it doesn't get a 200 within 10 seconds. The handler already returns 200 immediately, but `handlePullRequestEvent` runs asynchronously. If two retries arrive simultaneously:

- The find-and-edit flow handles this naturally: both will find the same comment and edit it, with the last write winning
- Check runs: `listCheckRunsForRef` + `updateCheckRun` handles this -- we always check for existing and update

No explicit locking needed because the operations are idempotent (same input = same output).

**8F.6: Comment body size limit**

GitHub PR comments cap at 65,536 characters. A monorepo with many projects and many dependency changes can exceed this.

- **Constant:** `MAX_COMMENT_LENGTH = 60000` (with 5,536 char buffer for safety)
- **Truncation strategy** (applied in order until under limit):
  1. Collapse transitive dependency sections to summary counts only (not per-dep listing)
  2. Cap each project section to 30 dependencies with "...and X more" footer
  3. If still too long: show only summary counts per project with a link to the Deptex dashboard for full results
- **GitLab MR notes:** Same 1MB limit but practically unbounded. Apply same truncation for consistency.
- **Bitbucket PR comments:** 32KB limit. Apply more aggressive truncation (cap at 20 deps per project).

**8F.7: Webhook delivery deduplication**

GitHub sends a unique `X-GitHub-Delivery` header with each webhook delivery. To prevent processing duplicate deliveries from retries:

- On webhook receipt, check Redis for key `webhook-delivery:{delivery_id}` (1-hour TTL)
- If key exists: return 200 immediately without processing (already handled)
- If key doesn't exist: set the key and proceed with processing
- If Redis is unavailable: proceed anyway (fail-open for availability; the idempotent handlers tolerate duplicates)
- GitLab: use `X-Gitlab-Event-UUID` header with same pattern
- Bitbucket: use `X-Request-UUID` header with same pattern

**8F.8: Webhook deliveries audit table**

In addition to Redis-based deduplication (which expires after 1 hour), persist a permanent record of all webhook deliveries for debugging and audit trail. This replaces "check Redis and hope it's still there" with a queryable history.

```sql
CREATE TABLE webhook_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  delivery_id TEXT NOT NULL,          -- X-GitHub-Delivery / X-Gitlab-Event-UUID / X-Request-UUID
  provider TEXT NOT NULL,             -- 'github', 'gitlab', 'bitbucket'
  event_type TEXT NOT NULL,           -- 'push', 'pull_request', 'repository', etc.
  action TEXT,                        -- 'opened', 'synchronize', 'closed', 'deleted', etc.
  repo_full_name TEXT,
  installation_id TEXT,
  processing_status TEXT NOT NULL DEFAULT 'received', -- 'received', 'processed', 'skipped', 'error'
  error_message TEXT,
  processing_duration_ms INTEGER,
  payload_size_bytes INTEGER,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_webhook_deliveries_delivery_id ON webhook_deliveries(delivery_id);
CREATE INDEX idx_webhook_deliveries_repo ON webhook_deliveries(repo_full_name);
CREATE INDEX idx_webhook_deliveries_created ON webhook_deliveries(created_at);
```

**Usage:**

- On every webhook receipt (after signature verification), insert a row with `status = 'received'`
- After processing completes, update to `'processed'` or `'error'` with `processing_duration_ms`
- If skipped (duplicate delivery ID, inactive repo, etc.): set `'skipped'`
- Retention: keep 30 days of deliveries. A daily cleanup job (piggyback on 8O watchtower cron) deletes rows older than 30 days
- Exposed to org admins via the Webhook Deliveries screen (see 8K.4)

This gives you a permanent audit trail that survives Redis TTL expiry, making it possible to debug "why didn't my push trigger extraction?" days after the fact.

### 8G: PR Tracking Table

Track PR lifecycle in our database so the compliance tab can show real PR data.

**8G.1: Database schema**

```sql
CREATE TABLE project_pull_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  pr_number INTEGER NOT NULL,
  title TEXT,
  author_login TEXT,
  author_avatar_url TEXT,
  status TEXT NOT NULL DEFAULT 'open', -- 'open', 'merged', 'closed'
  -- Check result from our guardrails
  check_result TEXT, -- 'passed', 'failed', 'pending', 'skipped' (null = not checked yet)
  check_summary TEXT, -- short summary: "2 critical vulns, 1 policy violation"
  -- Dependency change counts
  deps_added INTEGER DEFAULT 0,
  deps_updated INTEGER DEFAULT 0,
  deps_removed INTEGER DEFAULT 0,
  transitive_changes INTEGER DEFAULT 0,
  -- Guardrail details (what blocked it)
  blocked_by JSONB, -- e.g. { "critical_vulns": 2, "policy_violations": 1 }
  -- Provider info
  provider TEXT NOT NULL DEFAULT 'github',
  provider_url TEXT, -- link to the PR on the provider
  base_branch TEXT,
  head_branch TEXT,
  head_sha TEXT,
  -- Timestamps
  opened_at TIMESTAMPTZ,
  merged_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  last_checked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_project_prs_project_id ON project_pull_requests(project_id);
CREATE INDEX idx_project_prs_status ON project_pull_requests(status);
CREATE UNIQUE INDEX idx_project_prs_project_pr ON project_pull_requests(project_id, pr_number, provider);
```

**8G.2: Recording PRs from webhook events**

Upsert into `project_pull_requests` at multiple points:

1. **PR opened/synchronize/reopened** (in `handlePullRequestEvent`):
  - Upsert with status `'open'`, update `head_sha`, `last_checked_at`
  - After analysis: update `check_result`, `check_summary`, `blocked_by`, dep change counts
2. **PR closed** (add `closed` to handled actions in the webhook switch):
  - If `payload.pull_request.merged`: set status `'merged'`, set `merged_at`
  - If not merged: set status `'closed'`, set `closed_at`
3. **PR reopened** (already handled):
  - Set status back to `'open'`, clear `closed_at`

**8G.3: Handling the `closed` action**

Add `closed` to the handled PR actions in the webhook handler:

```typescript
case 'pull_request':
  if (['opened', 'synchronize', 'reopened'].includes(payload?.action)) {
    handlePullRequestEvent(payload).catch(/* ... */);
  }
  if (payload?.action === 'closed') {
    handlePullRequestClosedEvent(payload).catch(/* ... */);
  }
  break;
```

`handlePullRequestClosedEvent` is simple: look up the PR in `project_pull_requests` by repo + PR number, update status to `'merged'` or `'closed'`.

**8G.4: API endpoints**

1. `GET /api/organizations/:id/projects/:projectId/pull-requests` -- paginated, filterable by status, searchable by title/author
  - Query params: `status` (open/merged/closed/ALL), `check_result` (passed/failed/ALL), `timeframe`, `search`, `page`, `per_page`
2. `GET /api/organizations/:id/projects/:projectId/pull-requests/stats` -- returns counts: open PRs, failed checks, passed checks, merged this week

### 8H: PR Guardrails Inheritance and Policy Engine Integration

Wire the Phase 4 policy-as-code engine into the PR handler. The org defines `pr_check_code` (in `organization_pr_checks` table from Phase 4), projects inherit or override via `effective_pr_check_code`.

**8H.1: Execution flow in handlePullRequestEvent**

After computing the dep diff (added, bumped, removed, transitive):

```
1. Load the project's effective PR check code:
   a. If project has effective_pr_check_code (not null): use it
   b. Else: load from organization_pr_checks.pr_check_code
   c. If neither exists: fall back to project_pr_guardrails (current simple toggle behavior)

2. If PR check code exists (Phase 4 policy engine):
   a. Build the context object:
      context = {
        added: [{ name, version, policyResult, license, vulnCounts, isDirect }],
        updated: [{ name, oldVersion, newVersion, policyResult, license, vulnCounts }],
        removed: [{ name, version }],
        transitive: [{ name, version, policyResult, license, vulnCounts }],
        project: { name, tier },
        pr: { number, title, author, baseBranch, headBranch }
      }
   b. Execute pr_check_code in isolated-vm sandbox (reuse Phase 4 sandbox)
   c. The function returns { blocked: boolean, violations: string[], summary: string }
   d. Use the result to determine check run conclusion and comment content

3. If no PR check code (pre-Phase 4, or Phase 4 not yet implemented):
   a. Use the current project_pr_guardrails simple logic (vuln severity blocking, policy violations, transitive)
   b. This is the backward-compatible path
```

**8H.2: Org-level defaults via Phase 4 PR check code (no separate guardrails table)**

Phase 4 is already implemented. The `organization_pr_checks` table holds `pr_check_code` per org, and `DEFAULT_PR_CHECK_CODE` (from `policy-defaults.ts`) is seeded on org creation. This eliminates the need for a separate `organization_pr_guardrails` table -- the Phase 4 PR check code IS the org-level default.

Resolution order:

1. `projects.effective_pr_check_code` (project-level override, if not null)
2. `organization_pr_checks.pr_check_code` (org-level default from Phase 4)
3. `project_pr_guardrails` (legacy simple toggle fallback -- for orgs that haven't set up PR check code yet)
4. All-pass (no blocking)

The existing `project_pr_guardrails` table remains as a legacy fallback for orgs that predate Phase 4 or haven't written custom PR check code. Over time, this path becomes unused as orgs adopt policy-as-code. No new `organization_pr_guardrails` table is needed.

**8H.3: Migrating simple guardrails to PR check code**

For orgs that still use the simple `project_pr_guardrails` toggles, the handler translates them into equivalent logic at runtime:

```
If project has effective_pr_check_code or org has pr_check_code:
  -> Execute in Phase 4 sandbox (primary path)
Else if project has project_pr_guardrails row:
  -> Apply simple toggle logic (legacy path, same as current behavior)
Else:
  -> All-pass (no blocking)
```

This avoids a database migration and lets simple guardrails coexist cleanly with the policy engine.

### 8I: GitLab Webhooks and Merge Request Support

Add full webhook support for GitLab-connected repositories.

**8I.1: Webhook registration**

When a GitLab repo is connected to a project (in the connect-repo flow in [projects.ts](ee/backend/routes/projects.ts)):

```
1. Call GitLab API: POST /projects/:id/hooks
   - url: https://api.deptex.io/api/integrations/webhooks/gitlab
   - token: generate a random webhook secret, store in project_repositories.webhook_secret
   - push_events: true
   - merge_requests_events: true
   - enable_ssl_verification: true
2. Store the returned webhook ID in project_repositories.webhook_id (new column)
```

**8I.2: Webhook endpoint**

New route: `POST /api/integrations/webhooks/gitlab`

```typescript
router.post('/webhooks/gitlab', gitlabWebhookHandler);
```

**8I.3: Signature verification**

GitLab sends the webhook secret in the `X-Gitlab-Token` header. Verify:

```typescript
function verifyGitLabWebhookToken(req: Request): { valid: boolean; repoFullName: string | null } {
  const token = req.headers['x-gitlab-token'] as string;
  const repoFullName = req.body?.project?.path_with_namespace;
  if (!token || !repoFullName) return { valid: false, repoFullName: null };
  // Look up the expected token for this repo
  const { data } = await supabase
    .from('project_repositories')
    .select('webhook_secret')
    .eq('repo_full_name', repoFullName)
    .eq('provider', 'gitlab');
  return { valid: data?.some(r => r.webhook_secret === token), repoFullName };
}
```

**8I.4: Event handling**

GitLab webhook events:

- `Push Hook` -> `handleGitLabPushEvent`: same logic as GitHub push (detect affected workspaces, extract, record commits)
- `Merge Request Hook` -> `handleGitLabMergeRequestEvent`: same logic as GitHub PR, with differences:
  - Actions: `open`, `update`, `merge`, `close` (mapped to our opened/synchronize/merged/closed)
  - No Check Runs on GitLab: use **Commit Status API** instead (`POST /projects/:id/statuses/:sha`)
  - Commit statuses have: `state` (pending/running/success/failed), `name`, `description`, `target_url`
  - Comments: use GitLab **MR Notes API** (`POST /projects/:id/merge_requests/:mr/notes`, `PUT .../notes/:id`)
  - Find existing Deptex note by searching for the `<!-- deptex-pr-check -->` marker, edit it

**8I.5: GitLab API differences**

Key differences to account for:

- GitLab uses project IDs (numeric) not `owner/repo` format for API calls (but `path_with_namespace` is the full name)
- GitLab Compare API: `GET /projects/:id/repository/compare?from=sha1&to=sha2`
- GitLab file content: `GET /projects/:id/repository/files/:path?ref=sha` (URL-encode the path)
- GitLab MR diff: `GET /projects/:id/merge_requests/:mr/changes` returns changed files
- OAuth token refresh: GitLab tokens expire, use refresh_token flow before each API call batch

**8I.6: Database migration**

```sql
ALTER TABLE project_repositories ADD COLUMN webhook_id TEXT;
ALTER TABLE project_repositories ADD COLUMN webhook_secret TEXT;
ALTER TABLE project_repositories ADD COLUMN provider TEXT NOT NULL DEFAULT 'github';
```

(If `provider` column doesn't already exist -- check `organization_integrations` for the provider info that may already be joinable. Current codebase already has `provider` column via `migration_add_provider_to_project_repositories.sql`.)

**8I.7: GitLab replay protection**

GitLab's static `X-Gitlab-Token` header is weaker than HMAC -- if the token leaks, any payload can be replayed. Mitigations:

1. **Delivery UUID deduplication:** GitLab sends `X-Gitlab-Event-UUID` with each delivery. Store recent UUIDs in Redis with 1-hour TTL via the 8F.7 deduplication mechanism. Reject seen UUIDs.
2. **Webhook secret rotation:** The "Re-register Webhook" button (8K.3) generates a new secret and calls `PUT /projects/:id/hooks/:hook_id` to update it on GitLab's side. Old secret is immediately invalidated.
3. **Secret storage:** `webhook_secret` is stored in `project_repositories`. For Phase 8, store as plaintext (same as current `installation_id`). Phase 14 (Enterprise Security) can add encryption at rest if needed -- the column is only accessed server-side.

**8I.8: GitLab/Bitbucket OAuth token refresh hardening**

Both GitLab and Bitbucket OAuth tokens expire (GitLab: 2 hours, Bitbucket: 1-2 hours). The token refresh flow must be robust:

1. Before each API call batch, check `organization_integrations.token_expires_at` (new column if not present, or derive from token metadata)
2. If expired or within 5 minutes of expiry: refresh using `refresh_token`
3. If refresh succeeds: update `access_token`, `refresh_token`, `token_expires_at` in `organization_integrations`
4. If refresh fails with 401 (token revoked by user):
  - Set `organization_integrations.status = 'token_expired'`
  - Set `project_repositories.webhook_status = 'error'` for affected repos
  - Skip webhook processing with a log
  - Surface in frontend: "GitLab/Bitbucket connection expired -- please reconnect in Organization Settings > Integrations"
5. **Race condition prevention:** If two concurrent webhooks both try to refresh the same expired token, use a Redis lock (`refresh-token:{integration_id}`, 30s TTL) to serialize. The second caller waits up to 10s for the lock, then reads the freshly-refreshed token from DB.

### 8J: Bitbucket Webhooks and PR Support

Add full webhook support for Bitbucket-connected repositories.

**8J.1: Webhook registration**

When a Bitbucket repo is connected:

```
1. Call Bitbucket API: POST /repositories/{workspace}/{repo_slug}/hooks
   - url: https://api.deptex.io/api/integrations/webhooks/bitbucket
   - events: ["repo:push", "pullrequest:created", "pullrequest:updated", "pullrequest:fulfilled", "pullrequest:rejected"]
   - active: true
   - secret: generate random secret, store in project_repositories.webhook_secret
2. Store webhook UUID in project_repositories.webhook_id
```

**8J.2: Webhook endpoint**

New route: `POST /api/integrations/webhooks/bitbucket`

**8J.3: Signature verification**

Bitbucket signs webhooks with HMAC-SHA256 using the webhook secret. Header: `X-Hub-Signature`. Verification is similar to GitHub's `x-hub-signature-256`.

**8J.4: Event handling**

Bitbucket webhook events:

- `repo:push` -> `handleBitbucketPushEvent`: extract `push.changes[].new.target` for commit info, `push.changes[].new.name` for branch. Use Bitbucket Diff API to get changed files.
- `pullrequest:created` / `pullrequest:updated` -> `handleBitbucketPullRequestEvent`: same logic as GitHub PR, with differences:
  - No Check Runs: use **Build Status API** (`POST /repositories/{workspace}/{repo}/commit/{sha}/statuses/build`)
  - Build statuses have: `state` (INPROGRESS/SUCCESSFUL/FAILED), `name`, `description`, `url`
  - Comments: use Bitbucket **PR Comments API** (`POST /repositories/{workspace}/{repo}/pullrequests/{id}/comments`, `PUT .../comments/{id}`)
  - Find existing Deptex comment by `user.display_name` or content marker
- `pullrequest:fulfilled` (merged) / `pullrequest:rejected` (declined) -> update PR tracking table

**8J.5: Bitbucket API differences**

- Bitbucket uses `workspace/repo_slug` not `owner/repo`
- Diff API: `GET /repositories/{workspace}/{repo}/diffstat/{spec}` where spec is `base..head`
- File content: `GET /repositories/{workspace}/{repo}/src/{sha}/{path}`
- PR diff files: `GET /repositories/{workspace}/{repo}/pullrequests/{id}/diffstat`
- OAuth token refresh: Bitbucket tokens expire (1-2 hours), use refresh_token (same hardened flow as 8I.8)

**8J.6: Bitbucket webhook signature verification**

Bitbucket uses HMAC-SHA256 like GitHub (`X-Hub-Signature` header). This is payload-bound, so replay attacks produce the same result (idempotent -- no additional protection needed beyond HMAC verification). Apply the same 8F.7 deduplication via `X-Request-UUID` header as defense-in-depth.

**8J.7: Bitbucket webhook re-registration**

When the "Re-register Webhook" button is clicked (8K.3):

1. Delete the old webhook via `DELETE /repositories/{workspace}/{repo}/hooks/{webhook_uuid}`
2. Create a new webhook with a fresh secret
3. Update `project_repositories.webhook_id` and `webhook_secret`
4. If deletion fails (404 -- webhook already gone): proceed with creation

### 8K: Webhook Health Display

Basic webhook health indicators in project repository settings.

**8K.1: Track last webhook received**

Add columns to `project_repositories`:

```sql
ALTER TABLE project_repositories ADD COLUMN last_webhook_at TIMESTAMPTZ;
ALTER TABLE project_repositories ADD COLUMN last_webhook_event TEXT;
ALTER TABLE project_repositories ADD COLUMN webhook_status TEXT DEFAULT 'unknown';
-- webhook_status: 'active', 'inactive', 'unknown', 'error'
```

Update `last_webhook_at` and `last_webhook_event` on every incoming webhook for that repo. Set `webhook_status = 'active'`.

**8K.2: Inactive webhook detection**

Runs as part of the daily QStash watchtower job (8O) -- no separate cron needed:

- Query `project_repositories` where `webhook_status = 'active'` AND `last_webhook_at < NOW() - INTERVAL '7 days'`
- Set `webhook_status = 'inactive'`
- This indicates the webhook may have been removed or is broken
- Also check: repos with `webhook_status = 'error'` (from token refresh failures in 8I.8) -- surface these prominently in the UI

**8K.3: UI in project settings**

In the Repository section of [ProjectSettingsPage.tsx](frontend/src/app/pages/ProjectSettingsPage.tsx):

- Show "Webhook Status" indicator: green dot + "Active (last event: 2 min ago)" or yellow dot + "Inactive (no events in 7 days)" or grey dot + "Unknown"
- Show "Last Event" type: "push", "pull_request", etc.
- "Re-register Webhook" button: calls the provider API to re-create the webhook (for GitLab/Bitbucket where we manage webhook registration). For GitHub, webhooks are managed by the GitHub App itself so this isn't needed.

**8K.4: Webhook Deliveries screen in Organization Settings**

Add a "Webhooks" section to [OrganizationSettingsPage.tsx](frontend/src/app/pages/OrganizationSettingsPage.tsx) (new tab in the settings sidebar, after Integrations). This gives org admins visibility into all webhook activity across their connected repositories.

**Permission:** Requires `manage_integrations` (same as the Integrations tab).

**Add to `VALID_SETTINGS_SECTIONS`:** `'webhooks'`

**API endpoint:**

`GET /api/organizations/:id/webhook-deliveries` -- paginated, filterable. Returns deliveries for repos belonging to this org's projects.

Query params: `provider` (github/gitlab/bitbucket/ALL), `status` (received/processed/skipped/error/ALL), `event_type` (push/pull_request/repository/ALL), `repo` (repo_full_name filter), `timeframe` (1H/24H/7D/30D), `page`, `per_page` (default 50).

**UI layout:**

```
┌─────────────────────────────────────────────────────────────────┐
│  Webhooks                                                       │
│                                                                 │
│  ┌─ Summary Cards ────────────────────────────────────────────┐ │
│  │  Total (30d)    Processed    Errors    Skipped             │ │
│  │  1,247          1,201        12        34                  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─ Filters ──────────────────────────────────────────────────┐ │
│  │  [Provider ▾]  [Status ▾]  [Event ▾]  [Repo ▾]  [Time ▾] │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─ Deliveries Table ────────────────────────────────────────┐  │
│  │  Time          Provider  Event          Repo       Status │  │
│  │  2 min ago     GitHub    push           org/repo   ●      │  │
│  │  5 min ago     GitHub    pull_request   org/repo   ●      │  │
│  │  1 hour ago    GitLab    push           grp/repo   ●      │  │
│  │  3 hours ago   GitHub    pull_request   org/mono   ✕      │  │
│  │  ...                                                      │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Showing 1-50 of 1,247  [← Prev]  [Next →]                     │
└─────────────────────────────────────────────────────────────────┘
```

**Table columns:**


| Column     | Content                                                                            |
| ---------- | ---------------------------------------------------------------------------------- |
| Time       | Relative timestamp ("2 min ago"), full timestamp on hover                          |
| Provider   | GitHub/GitLab/Bitbucket icon + label                                               |
| Event      | Event type + action badge (e.g. "push", "pull_request · opened")                   |
| Repository | `repo_full_name`, links to the repo on the provider                                |
| Status     | Color-coded dot: green = processed, yellow = skipped, red = error, grey = received |
| Duration   | Processing time in ms (e.g. "142ms"), shown for processed/error                    |
| Size       | Payload size (e.g. "12.4 KB")                                                      |


**Error rows:** When status is `error`, show the `error_message` in an expandable row detail (click to expand). Red background tint on the row.

**Empty state:** "No webhook deliveries yet. Connect a repository and push a commit to see webhook activity here."

**Summary stats API:**

`GET /api/organizations/:id/webhook-deliveries/stats` -- returns counts by status for the selected timeframe. Powers the summary cards at the top.

**Design notes:**

- Follow the same table pattern as the Activities tab (filterable, paginated, time-relative)
- Status dots use the same green/yellow/red/grey convention as the per-project webhook health (8K.3)
- Errors are the primary use case -- the page should make it easy to spot and diagnose failed deliveries
- No actions on this page (read-only audit view). Re-registration happens in project settings (8K.3)

### 8L: Compliance Tab Integration

Wire real data into the Updates section of [ProjectCompliancePage.tsx](frontend/src/app/pages/ProjectCompliancePage.tsx), replacing mock data.

**8L.1: Pull Requests sub-tab**

Replace `mockPullRequests` with real data from `project_pull_requests`:

- Fetch via `GET /api/organizations/:id/projects/:projectId/pull-requests`
- Show: PR title + number, author avatar + login, status badge (Open/Merged/Closed), check result badge (Passed/Failed/Pending/Skipped), deps changed count, time ago
- Link each PR to the provider URL (`provider_url` column)
- Filters: status (All/Open/Merged/Closed), check result (All/Passed/Failed), timeframe (24H/7D/30D/All), search by title/author
- Sort: most recent first (by `updated_at`)

**8L.2: Commits sub-tab**

Replace `mockCommits` with real data from `project_commits`:

- Fetch via `GET /api/organizations/:id/projects/:projectId/commits`
- Show: commit message (truncated), author name + avatar, compliance status badge (Compliant/Non-compliant/Unknown), manifest changed indicator, extraction status, time ago
- Link each commit to the provider URL (`provider_url` column)
- Filters: compliance status, timeframe, search by message/author
- Sort: most recent first (by `committed_at`)

**8L.3: Project sub-tab -- Blocked PRs card**

The Project sub-tab (Phase 5) has a "Blocked PRs" card that shows PRs failing the PR check. Wire this to real data:

```typescript
// Query: open PRs with check_result = 'failed'
const { data: blockedPrs } = await supabase
  .from('project_pull_requests')
  .select('pr_number, title, author_login, check_summary, provider_url')
  .eq('project_id', projectId)
  .eq('status', 'open')
  .eq('check_result', 'failed');
```

**8L.4: Open PR count**

Show an open PR count badge next to the "Updates" tab label (e.g. "Updates (3)") when there are open PRs with failed checks. This gives immediate visibility into blocked PRs.

### 8N: Daily/Weekly Extraction Scheduler (QStash)

Phase 8B introduces `sync_frequency` with `daily` and `weekly` values, but nothing in the webhook-driven system triggers those. This section builds the QStash-based scheduler that actually runs scheduled extractions.

**8N.1: QStash cron schedule**

- **Schedule:** `0 */6` * * * (every 6 hours) -- catches daily projects at ~6h granularity, weekly at same
- **Target:** `POST /api/workers/scheduled-extraction`
- **Auth:** QStash signature verification (reuses existing `verifyQStashSignature` from [ee/backend/lib/qstash.ts](ee/backend/lib/qstash.ts)) OR `X-Internal-Api-Key`
- **Why every 6 hours?** Daily extraction doesn't need to-the-minute precision. Running every 6 hours means a project set to "daily" gets extracted within 6 hours of its 24-hour mark. More frequent (e.g. hourly) wastes QStash invocations; less frequent (e.g. every 12 hours) means daily projects could wait up to 36 hours.

**8N.2: Endpoint implementation**

Route: `backend/src/routes/scheduled-extraction.ts` (CE route, mounted outside `isEeEdition()` block)

```
POST /api/workers/scheduled-extraction:
  1. Verify QStash signature or X-Internal-Api-Key
  2. Query project_repositories WHERE:
     - (sync_frequency = 'daily' AND last_extracted_at < NOW() - INTERVAL '24 hours')
     OR (sync_frequency = 'weekly' AND last_extracted_at < NOW() - INTERVAL '7 days')
     AND status NOT IN ('repo_deleted', 'access_revoked', 'installation_removed')
  3. Group by organization_id
  4. For each org, cap at 5 projects per invocation (prevent single org monopolizing)
  5. For each eligible project:
     a. Call queueExtractionJob() (skips if job already queued/processing)
     b. Log to extraction_logs: "Scheduled extraction triggered (daily/weekly)"
  6. Overall cap: max 20 jobs per invocation (across all orgs)
  7. If more projects are eligible: they'll be picked up in the next 6-hour cycle
  8. Return JSON: { queued: N, skipped_duplicate: M, skipped_cap: K }
```

**8N.3: Database migration**

```sql
ALTER TABLE project_repositories ADD COLUMN last_extracted_at TIMESTAMPTZ;
```

This column is updated when extraction completes successfully (in the populate-dependencies callback or the extraction worker's completion handler). For existing repos, backfill from `project_repositories.updated_at` or leave NULL (NULL means "never extracted on schedule" -- the query treats NULL as eligible).

**8N.4: Interaction with push webhooks**

If a project has `sync_frequency = 'daily'` and receives a push webhook:

- The push handler skips extraction (per 8B.2 step 9) but still records the commit
- The scheduled extraction runs independently on its 6-hour cycle
- `last_extracted_at` is updated after extraction completes, resetting the 24h/7d clock

If a project has `sync_frequency = 'on_commit'`, the scheduler ignores it entirely.

**8N.5: Phase 13 integration**

Phase 13 (Billing) will add plan-tier restrictions:

- Free tier: `sync_frequency = 'manual'` only (no scheduled or on_commit)
- Pro tier: `on_commit` and `daily`
- Team/Enterprise: all options including `weekly`

The scheduler checks `sync_frequency` value, not the plan tier -- the restriction is enforced when the user sets the value in the UI (Phase 13 disables options).

### 8O: Watchtower-Poller Migration to QStash Cron

The watchtower-poller (`backend/watchtower-poller/`) currently runs as a 24/7 local process that checks Redis every 60 seconds but only fires a daily job once per 24 hours. This is wasteful. Migrate to a QStash cron that calls a backend endpoint once per day.

**8O.1: QStash cron schedule**

- **Schedule:** `0 4` * * * (daily at 4 AM UTC -- low-traffic window)
- **Target:** `POST /api/workers/watchtower-daily-poll`
- **Auth:** QStash signature verification OR `X-Internal-Api-Key`
- **Cost:** $0/month additional (QStash free tier covers daily cron; no dedicated machine vs ~$2/month for Fly.io)

**8O.2: Extract shared library**

Move the core logic from `backend/watchtower-poller/src/` into a shared library:

- **New file:** `backend/src/lib/watchtower-poll.ts`
- **Exports:** `runDependencyRefresh()`, `runPollSweep()`
- These functions currently live in `backend/watchtower-poller/src/dependency-refresh.ts` and `backend/watchtower-poller/src/index.ts`
- They depend on: Supabase client, Redis (for enqueuing `watchtower-new-version-jobs`), npm registry fetcher, GHSA batch fetch
- All dependencies are already available in the main backend

**8O.3: Endpoint implementation**

Route: `backend/src/routes/watchtower-daily-poll.ts` (CE route)

```
POST /api/workers/watchtower-daily-poll:
  1. Verify QStash signature or X-Internal-Api-Key
  2. Run runDependencyRefresh():
     - Fetch all unique direct dependency names from project_dependencies
     - For each: check npm registry for latest version
     - If version changed: update dependencies.latest_version, enqueue watchtower-new-version-job
     - GHSA batch fetch (up to 100 names per request) -> upsert dependency_vulnerabilities
  3. Run runPollSweep():
     - Fetch watched_packages with status = 'ready'
     - For each: git ls-remote to check for new commits
     - If new commits: incremental analysis (clone, extract commits, anomaly detection)
  4. Run webhook health check (8K.2):
     - Mark repos as inactive if no webhook in 7 days
  5. Return JSON: { deps_refreshed: N, vulns_updated: M, packages_polled: K, webhooks_marked_inactive: J }
```

**8O.4: Timeout considerations**

QStash allows up to 2 hours per HTTP invocation. For most orgs, the daily poll completes well within this. For very large orgs (500+ dependencies, 100+ watched packages):

- If the job risks timing out: split into batched QStash calls
- The endpoint can self-queue a continuation: `POST /api/workers/watchtower-daily-poll?offset=100`
- Each batch processes up to 100 dependencies and 50 watched packages

**8O.5: Deprecation of local poller**

- Mark `backend/watchtower-poller/` as deprecated in its README
- Keep it functional for local development (`npm run dev` still works for testing)
- All production use goes through the QStash cron endpoint
- The existing Redis sorted set (`watchtower-daily-poll`) scheduling is no longer needed in production but remains for local dev

**8O.6: Existing queues stay**

The QStash endpoint replaces ONLY the poller's scheduling loop. It still enqueues jobs to Redis for the watchtower-worker:

- `watchtower-new-version-jobs` (when a new npm version is found)
- `watchtower-jobs` (still enqueued by the backend when users add packages to watchlist)

The watchtower-worker on Fly.io continues consuming these queues unchanged.

**8O.7: Worker Fly.io migration strategy (broader context)**

Phase 8 migrates the watchtower-poller to QStash cron, but the overall strategy is to move ALL workers to Fly.io scale-to-zero. Here's the current state and target for each worker:


| Worker                | Current State                                      | Phase 8 Action                                                              | Future Target                                                                                                                                         |
| --------------------- | -------------------------------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Extraction worker** | Fly.io scale-to-zero, Supabase job queue           | No change (already done, Phase 2)                                           | Done                                                                                                                                                  |
| **Watchtower poller** | 24/7 local process, Redis sorted set scheduling    | **Migrate to QStash cron** (8O) -- no machine needed, just an HTTP endpoint | Done after Phase 8                                                                                                                                    |
| **Watchtower worker** | Standalone process, Redis `watchtower-jobs` queue  | No change in Phase 8                                                        | Phase 10B: Fly.io scale-to-zero with Supabase job table (same pattern as extraction worker). Start machine when `queueWatchtowerJob()` enqueues work. |
| **Parser worker**     | Standalone process, Redis `ast-parsing-jobs` queue | No change in Phase 8                                                        | Separate task: Fly.io scale-to-zero with Supabase job table. Start machine when `queueASTParsingJob()` enqueues work.                                 |


**Why not migrate watchtower-worker and parser-worker in Phase 8?**

- The poller is trivial to migrate (it's a cron trigger, not a long-running worker). QStash handles scheduling; the logic runs on the main backend.
- The watchtower-worker and parser-worker are long-running processes that clone repos and do heavy analysis. They need the full Fly.io scale-to-zero pattern: Supabase job table with atomic claim RPC, heartbeat, stuck detection, recovery endpoint -- the same infrastructure built for the extraction worker in Phase 2. This is meaningful work that belongs in its own scope.
- Phase 10B (Watchtower Refactor) is the natural home for the watchtower-worker migration since it's already refactoring Watchtower architecture.
- The parser-worker migration can be a standalone task anytime -- it's small and self-contained.

**Target architecture (all workers on Fly.io):**

```
QStash cron ──────────────> POST /api/workers/scheduled-extraction (main backend)
                                    │
                                    ▼
                            queueExtractionJob() → Supabase extraction_jobs
                                    │
                                    ▼
                            startExtractionMachine() → Fly.io extraction-worker (scale-to-zero)

QStash cron ──────────────> POST /api/workers/watchtower-daily-poll (main backend)
                                    │
                                    ▼
                            queueWatchtowerJob() → Redis watchtower-jobs (Phase 10B: Supabase)
                                    │
                                    ▼
                            [Phase 10B] startWatchtowerMachine() → Fly.io watchtower-worker (scale-to-zero)

Push/PR webhook ──────────> queueASTParsingJob() → Redis ast-parsing-jobs (future: Supabase)
                                    │
                                    ▼
                            [Future] startParserMachine() → Fly.io parser-worker (scale-to-zero)
```

This strategy eliminates all 24/7 worker machines. Every worker either runs on Fly.io scale-to-zero (pay per second of compute) or as a QStash cron hitting the main backend (free). The only 24/7 process is the main Express backend itself.

### 8P: Repository Lifecycle Event Handling

Currently, the GitHub webhook handler logs `repository` and `installation_repositories` events but takes no action. This means repo renames, deletions, transfers, and default branch changes silently break the system. This section adds proper handling for all lifecycle events.

**8P.1: Events to handle**

Add to the `switch` in `githubWebhookHandler` in [ee/backend/routes/integrations.ts](ee/backend/routes/integrations.ts):


| GitHub Event                | Action        | Handler                               | DB Update                                                                                                          |
| --------------------------- | ------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `repository`                | `deleted`     | `handleRepositoryDeletedEvent`        | Set `project_repositories.status = 'repo_deleted'` for all matching repos. Cancel any active extraction jobs.      |
| `repository`                | `renamed`     | `handleRepositoryRenamedEvent`        | Update `repo_full_name` from `payload.changes.repository.name.from` (old) to `payload.repository.full_name` (new). |
| `repository`                | `transferred` | `handleRepositoryTransferredEvent`    | Same as rename -- `repo_full_name` changes when ownership transfers. Also update `repo_id` if it changed.          |
| `repository`                | `edited`      | `handleRepositoryEditedEvent`         | If `payload.changes.default_branch` exists, update `project_repositories.default_branch` to new value.             |
| `repository`                | `archived`    | (log only)                            | No DB change. Push/PR events stop arriving naturally.                                                              |
| `installation_repositories` | `removed`     | `handleInstallationReposRemovedEvent` | Set `project_repositories.status = 'access_revoked'` for repos in `payload.repositories_removed`.                  |
| `installation`              | `deleted`     | (extend existing)                     | Also set `project_repositories.status = 'installation_removed'` for all repos using this `installation_id`.        |


**8P.2: Handler implementations**

```typescript
async function handleRepositoryDeletedEvent(payload: any) {
  const repoFullName = payload.repository?.full_name;
  if (!repoFullName) return;

  // Mark all project repos as deleted
  await supabase
    .from('project_repositories')
    .update({ status: 'repo_deleted', updated_at: new Date().toISOString() })
    .eq('repo_full_name', repoFullName);

  // Cancel any active extraction jobs for these projects
  const { data: repos } = await supabase
    .from('project_repositories')
    .select('project_id')
    .eq('repo_full_name', repoFullName);

  for (const repo of repos || []) {
    await supabase
      .from('extraction_jobs')
      .update({ status: 'cancelled' })
      .eq('project_id', repo.project_id)
      .in('status', ['queued', 'processing']);
  }

  console.log(`Repository deleted: ${repoFullName}. Marked ${repos?.length || 0} project repos as repo_deleted.`);
}

async function handleRepositoryRenamedEvent(payload: any) {
  const oldName = payload.changes?.repository?.name?.from;
  const newFullName = payload.repository?.full_name;
  const owner = payload.repository?.owner?.login;
  if (!oldName || !newFullName || !owner) return;

  const oldFullName = `${owner}/${oldName}`;
  const { count } = await supabase
    .from('project_repositories')
    .update({ repo_full_name: newFullName, updated_at: new Date().toISOString() })
    .eq('repo_full_name', oldFullName);

  console.log(`Repository renamed: ${oldFullName} -> ${newFullName}. Updated ${count || 0} project repos.`);
}

async function handleRepositoryEditedEvent(payload: any) {
  const repoFullName = payload.repository?.full_name;
  const defaultBranchChange = payload.changes?.default_branch;
  if (!repoFullName || !defaultBranchChange) return;

  const newDefaultBranch = payload.repository?.default_branch;
  const { count } = await supabase
    .from('project_repositories')
    .update({ default_branch: newDefaultBranch, updated_at: new Date().toISOString() })
    .eq('repo_full_name', repoFullName);

  console.log(`Default branch changed for ${repoFullName}: ${defaultBranchChange.from} -> ${newDefaultBranch}. Updated ${count || 0} project repos.`);
}

async function handleInstallationReposRemovedEvent(payload: any) {
  const removedRepos = payload.repositories_removed || [];
  for (const repo of removedRepos) {
    await supabase
      .from('project_repositories')
      .update({ status: 'access_revoked', updated_at: new Date().toISOString() })
      .eq('repo_full_name', repo.full_name);
  }
  console.log(`Installation repos removed: ${removedRepos.map((r: any) => r.full_name).join(', ')}`);
}
```

**8P.3: Extend handleInstallationDeleted**

The existing `handleInstallationDeleted` clears `organizations.github_installation_id` and sets `organization_integrations.status = 'disconnected'`. Add:

```typescript
// Also mark all project repos using this installation as disconnected
await supabase
  .from('project_repositories')
  .update({ status: 'installation_removed', updated_at: new Date().toISOString() })
  .eq('installation_id', String(installationId));
```

**8P.4: Guard in push/PR handlers**

Before processing a push or PR event, check the project repo's status:

```typescript
// Skip projects that are disconnected
const activeStatuses = ['pending', 'initializing', 'ready', 'error', 'cancelled'];
const activeProjects = projectRows.filter(r => activeStatuses.includes(r.status));
if (activeProjects.length === 0) return;
```

This prevents attempting extraction or API calls for repos that have been deleted, revoked, or whose installation was removed.

**8P.5: GitLab/Bitbucket lifecycle events**

GitLab and Bitbucket have equivalent events but with different webhook event types:

- **GitLab:** `Project Hook` events include `push`, `merge_request`, but NOT repo rename/delete/transfer (those are System Hooks, admin-only). For GitLab, rely on API call failures (404) to detect deleted/renamed repos and set `webhook_status = 'error'`.
- **Bitbucket:** `repo:updated` (name/description change), `repo:deleted`, `repo:transfer` events exist. Handle similarly to GitHub.

For Phase 8, implement full lifecycle handling for GitHub (which has the richest event set). GitLab/Bitbucket: handle gracefully when API calls fail due to missing repos -- set `webhook_status = 'error'` and log.

**8P.6: Frontend -- disconnected repo banner**

In [ProjectSettingsPage.tsx](frontend/src/app/pages/ProjectSettingsPage.tsx), when `project_repositories.status` is `'repo_deleted'`, `'access_revoked'`, or `'installation_removed'`:

- Show a warning banner at the top of the Repository section:
  - `repo_deleted`: "This repository has been deleted on {provider}. Please connect a different repository."
  - `access_revoked`: "The Deptex GitHub App no longer has access to this repository. Please re-install the App or connect a different repository."
  - `installation_removed`: "The Deptex GitHub App has been uninstalled from this organization. Please re-install to continue syncing."
- Disable the "Sync Now" and extraction buttons
- Show a "Disconnect Repository" button to cleanly remove the connection

### 8Q: Webhook Endpoint Security Hardening

Comprehensive security measures for all webhook endpoints.

**8Q.1: Strict verification in production**

Change `verifyGitHubWebhookSignature` behavior:

```typescript
function verifyGitHubWebhookSignature(req: express.Request): boolean {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === 'production') {
      console.error('CRITICAL: GITHUB_WEBHOOK_SECRET not set in production. Rejecting webhook.');
      return false;
    }
    console.warn('GITHUB_WEBHOOK_SECRET not set; skipping verification (dev mode only).');
    return true;
  }
  // ... existing HMAC verification ...
}
```

In production, missing webhook secrets cause rejection. In development, warn but allow (for local testing without ngrok signatures).

**8Q.2: Webhook endpoint rate limiting**

Add rate limiting to prevent abuse on webhook endpoints:

- **Per-IP rate limit:** 100 requests per minute per IP (generous enough for legitimate webhook bursts from GitHub/GitLab/Bitbucket)
- **Implementation:** Reuse the existing `checkRateLimit` from [ee/backend/lib/rate-limit.ts](ee/backend/lib/rate-limit.ts) (Redis-backed, fail-open)
- **Apply to:** `/api/webhook/github`, `/api/integrations/webhooks/gitlab`, `/api/integrations/webhooks/bitbucket`
- **GitHub IP allowlist:** Optionally, only accept webhooks from GitHub's published IP ranges (`GET https://api.github.com/meta` -> `hooks` array). This is a Phase 14 hardening -- for Phase 8, rate limiting is sufficient.

**8Q.3: Input validation**

Validate webhook payloads before processing:

- Required fields: `repository.full_name` (all events), `installation.id` (GitHub), appropriate event-specific fields
- File paths from changed files: sanitize to prevent path traversal (strip `..` segments, normalize slashes)
- Reject payloads missing critical fields with a 400 (after signature verification passes)

### 8M: Edge Cases, Error Handling, and Tests

**8M.1: Edge cases to handle**

**Webhook processing (1-8):**

1. **Concurrent webhook events for same PR**: Two `synchronize` events arrive simultaneously (fast consecutive pushes). The edit-existing-comment approach handles this naturally (last write wins). Check runs: create for new SHA, old SHA's check runs auto-stale. Deduplication via delivery ID (8F.7) catches true retries.
2. **Force push on PR**: `synchronize` event fires. The `base_sha` in Compare API may be invalid. Handle 422 by falling back: use the PR's `base.sha` (the target branch head) instead.
3. **Webhook delivery out of order**: GitHub/GitLab/Bitbucket don't guarantee delivery order. A `closed` event could arrive before `opened`. Solution: use upsert with `ON CONFLICT (project_id, pr_number, provider)`. The PR tracking row is created regardless of which event arrives first. Status transitions are all valid from any state (we trust the latest event's timestamp).
4. **Delayed webhook delivery**: Webhook arrives hours after the event (provider outage, network issues). The handler is idempotent -- late delivery produces the same result as on-time delivery. No special handling needed.
5. **Duplicate webhook delivery**: GitHub retries on timeout, GitLab/Bitbucket may also retry. Primary defense: delivery ID deduplication (8F.7). Secondary defense: all handlers are idempotent (same input = same output).
6. **Webhook payload size**: GitHub webhooks cap at 25MB. The main backend's `express.json()` has no explicit limit. Add `express.json({ limit: '5mb' })` for webhook routes (8B.6) -- anything over 5MB is suspicious.
7. **Webhook URL misconfigured**: GitLab/Bitbucket per-repo webhooks could point to wrong URL. Token verification catches this (invalid token = reject with 401). For GitHub, the App itself manages webhook URLs, so misconfiguration isn't possible.
8. **Webhook secret not set (production)**: Changed in 8Q.1 -- reject in production, warn-and-allow in development only.

**API and token failures (9-16):**

1. **Installation suspended/deleted mid-scan**: GitHub App installation suspended. API calls return 401/403. Catch in the check run creation step, log error. PR tracking row gets `check_result = 'error'` with note. Handler continues to the next project.
2. **GitHub primary rate limit** (5000/hour per installation): Check `x-ratelimit-remaining` header before each call. If <100 remaining, add 1-second delays between calls. If 0, wait until `x-ratelimit-reset` timestamp. Max 3 retries per API call with exponential backoff.
3. **GitHub secondary rate limit** (abuse detection): GitHub returns 403 with `retry-after` header when creating too many resources quickly (e.g. many check runs). Detect via response status 403 + `retry-after` header. Wait the specified time (usually 60s), then retry once. If still 403, skip remaining check runs and log.
4. **GitLab/Bitbucket rate limits**: GitLab: check `RateLimit-Remaining` header. Bitbucket: check `X-RateLimit-Remaining` header. Same backoff strategy as GitHub.
5. **Installation token expiry mid-PR-analysis**: Installation tokens expire after 1 hour. For very large monorepo PRs, check token age before each major API call. If >50 minutes old, request a fresh installation token.
6. **OAuth token refresh fails (GitLab/Bitbucket)**: Refresh token was revoked by user. Set `organization_integrations.status = 'token_expired'`, set `webhook_status = 'error'`, skip processing. Surface in UI (8I.8).
7. **OAuth token refresh race condition**: Two concurrent webhooks both try to refresh the same expired token. Redis lock serializes refreshes (8I.8).
8. **Compare API 404/422 for files**: File was deleted between diff detection and content fetch. Catch 404 on file reads and report: "File no longer exists at head SHA" in the comment. Don't crash the handler.

**Repository lifecycle (17-24):**

1. **Repo renamed on GitHub**: `repository.renamed` event fires. Handler updates `repo_full_name` (8P.1). Push/PR events that arrive with the new name work immediately. Events in flight with the old name may fail -- the rename handler runs before them since it's synchronous while push/PR are async.
2. **Repo deleted on GitHub**: `repository.deleted` event fires. Handler marks project repos as `repo_deleted` and cancels extraction jobs (8P.1). Subsequent push/PR events for this repo return 200 but skip processing (8P.4 guard).
3. **Repo transferred to another owner**: `repository.transferred` event fires. Treated as rename -- `repo_full_name` changes. Also update `repo_id` if GitHub changes it during transfer.
4. **Default branch changed**: `repository.edited` event fires with `changes.default_branch`. Handler updates stored `default_branch` (8P.1). Belt-and-suspenders: push handler also compares payload's `repository.default_branch` with stored value (8B.6).
5. **GitHub App removed from specific repos**: `installation_repositories.removed` event fires. Handler marks repos as `access_revoked` (8P.1). Push/PR events for these repos will fail with 404 -- the guard in 8P.4 skips them.
6. **GitHub App installation deleted**: Existing handler clears org-level data. Extended to also mark all `project_repositories` as `installation_removed` (8P.3).
7. **Repo archived on GitHub**: `repository.archived` event fires. Push events stop naturally (can't push to archived repos). PR events may still fire for existing PRs. No DB change needed -- extraction just won't happen because there are no pushes.
8. **Repo visibility changed (public to private or vice versa)**: No impact on webhook processing. The installation token works regardless of visibility. No special handling needed.

**PR-specific edge cases (25-32):**

1. **PR from fork (GitHub)**: Installation may not have access to fork repo. Fallback to base-branch-only analysis (8E.7). Still create check run with fork limitation note.
2. **PR from fork (GitLab/Bitbucket)**: Use target project's OAuth token. If source project inaccessible, same fallback as GitHub.
3. **Large PRs (100+ dependency changes)**: Cap comment detail to 50 dependencies per project section, add "...and X more dependencies changed" footer. Check run output has same cap (8E.8).
4. **PR targeting non-default branch**: Skip entirely (8E.5). Return early with no check runs or comments.
5. **Empty PR (no file changes)**: `getCompareChangedFiles` returns empty array. `detectAffectedWorkspaces` returns empty map. Handler returns early with no check runs or comments (correct behavior).
6. **Deleted workspace in PR**: A PR removes an entire workspace directory. The workspace IS detected as affected (file was "removed" in the diff). The handler detects that `head` doesn't have the manifest and reports: "Workspace removed in this PR."
7. **Dependabot/Renovate bot PRs**: These can generate 10+ PRs at once. Each gets processed independently. Per-installation rate limiting (edge case 10-11) prevents API exhaustion. No special handling -- bot PRs are treated the same as human PRs.
8. **PR auto-merge enabled**: GitHub may merge the PR immediately after checks pass. The `closed` event (with `merged = true`) fires right after. Both events are handled normally.

**Content and size limits (33-36):**

1. **PR comment exceeds 65,536 chars (GitHub)**: Truncation strategy in 8F.6 kicks in. Tested with synthetic 200-dependency scenario.
2. **PR comment exceeds 32KB (Bitbucket)**: More aggressive truncation (cap at 20 deps per project).
3. **Check run output exceeds 65,535 chars**: Same truncation strategy as comments (8E.8).
4. **Commit message exceeds column size**: Truncate `message` to 10,000 characters before insert into `project_commits`. Postgres TEXT is unbounded but cap for sanity.

**Monorepo and concurrency (37-42):**

1. **Monorepo with 50+ projects**: Single push triggers extraction for all affected projects. Per-org cap of 10 extraction jobs per push event (8B.6). Remaining projects picked up by next push or scheduled extraction.
2. **Root manifest change affects all workspaces**: If `package.json` at root changes, all projects in that repo are treated as affected (8B.4). Combined with the 10-project cap, large monorepos process in batches.
3. **Same project gets two push events within seconds**: `queueExtractionJob` prevents duplicate jobs (checks for existing `queued`/`processing` job). Second push records commits but skips extraction.
4. **PR opened and immediately force-pushed**: First `synchronize` check run becomes stale. Second event creates new check runs for new SHA. No conflict.
5. **Multiple organizations have same repo connected**: Push/PR events match by `repo_full_name` which may return rows from multiple orgs. Filter by `installation_id` (8B.6) to scope to the correct org.
6. **Race between PR `closed` and `synchronize`**: A push arrives just as the PR is being merged. Both events fire. The `synchronize` handler creates check runs. The `closed` handler marks the PR as merged. Both are idempotent -- final state is correct.

**Dependency analysis (43-46):**

1. **Private/scoped packages**: When `getVulnCountsForPackageVersion` or `getLicenseForPackage` fails for a private package, report as "Private package -- unable to check vulnerabilities" in the comment. Don't block on inability to check.
2. **Missing lockfile**: Workspace has manifest but no lockfile. Report in comment: "No lockfile found -- transitive dependency analysis unavailable. Only direct dependency changes are shown." Skip transitive checks for that workspace.
3. **Multiple projects sharing a repo -- partial guardrails**: Project A has guardrails enabled, Project B does not. The aggregated comment includes a section for Project A (with results) and shows "No guardrails configured" for Project B. Check run for Project A shows pass/fail; no check run for Project B.
4. **Non-npm ecosystem manifest changed**: Shallow analysis mode (8D.2). Report "Manifest file changed: `requirements.txt`" without deep diff. No blocking.

**Scheduled extraction (47-48):**

1. **Scheduled extraction for project with active extraction job**: `queueExtractionJob` already rejects duplicates. Scheduler logs "skipped -- job already in progress" and moves on.
2. **Scheduled extraction timeout**: QStash has 2-hour timeout. If the scheduler processes many orgs, it may approach the limit. The endpoint tracks elapsed time and self-queues a continuation with offset if >90 minutes elapsed (8O.4).

**Data integrity (49-50):**

1. **Org/project deleted between webhook receive and async processing**: All Supabase queries return null/empty. Each handler step null-checks results and exits gracefully. No crashes, no orphaned data.
2. **Organization plan downgraded mid-processing (Phase 13)**: For Phase 8, all features are on all plans. When Phase 13 adds restrictions, the extraction handler checks plan limits before queuing. For now, no-op.

**8M.2: Test plan**

Tests 1-5 (Manifest Registry):

1. `matchManifestFile` correctly identifies all ecosystem manifests (npm, Python, Go, Java, Rust, Ruby, .NET, PHP)
2. `matchManifestFile` returns null for non-manifest files (`.ts`, `.py`, `.go`, etc.)
3. `matchManifestFile` correctly extracts workspace paths for nested manifests
4. `detectAffectedWorkspaces` groups changed files by workspace and ecosystem
5. Root-level manifest changes are detected with workspace `''`

Tests 6-10 (Push Handler):

1. Push with lockfile change triggers extraction for that workspace only
2. Push with no manifest changes skips extraction, still records commit
3. Push with `sync_frequency = 'manual'` skips extraction, records commit
4. Push with `sync_frequency = 'on_commit'` triggers extraction when manifest changes
5. Force push (422 from Compare API) falls back to full extraction for all projects

Tests 11-15 (PR Handler):

1. PR with `package.json` change in one workspace only triggers check for that project
2. PR with changes in multiple workspaces creates separate check runs per project
3. PR comment is created on first run, edited on subsequent pushes
4. `pull_request_comments_enabled = false` suppresses comment but still creates check run
5. PR targeting non-default branch is skipped entirely

Tests 16-20 (Check Runs):

1. Check run created with `in_progress`, updated to `completed` with `success`
2. Check run created with `in_progress`, updated to `completed` with `failure` when guardrails block
3. Check run named `Deptex - {project_name}` per project
4. Stale check runs from previous SHA are superseded (no explicit cleanup needed)
5. Check run creation failure doesn't prevent comment from being posted

Tests 21-25 (PR Tracking):

1. PR opened -> `project_pull_requests` row created with status `open`
2. PR `synchronize` -> row updated with new `head_sha` and `last_checked_at`
3. PR merged (closed with merged=true) -> status set to `merged`, `merged_at` populated
4. PR closed (not merged) -> status set to `closed`, `closed_at` populated
5. API returns correct counts: open PRs, failed checks, passed checks

Tests 26-30 (Commit Tracking):

1. Push records commit in `project_commits` with correct metadata
2. Multi-commit push records all commits
3. Commit `manifest_changed` flag set correctly based on changed files
4. Commit `compliance_status` populated after extraction
5. API returns paginated, filterable commits

Tests 31-35 (GitLab):

1. GitLab push webhook triggers extraction for affected workspaces
2. GitLab MR webhook creates commit status (pending -> success/failed)
3. GitLab MR comment created with marker, edited on subsequent updates
4. GitLab webhook token verification rejects invalid tokens
5. GitLab token refresh works when access token expires

Tests 36-40 (Bitbucket):

1. Bitbucket push webhook triggers extraction for affected workspaces
2. Bitbucket PR webhook creates build status (INPROGRESS -> SUCCESSFUL/FAILED)
3. Bitbucket PR comment created with marker, edited on subsequent updates
4. Bitbucket webhook HMAC verification rejects invalid signatures
5. Bitbucket token refresh works when access token expires

Tests 41-45 (Edge Cases -- Content and Size):

1. Large PR (100+ deps) caps comment at 50 entries with "and X more" footer
2. PR comment exceeds 60,000 chars -- truncation strategy applied, fits under 65,536 limit
3. Check run output exceeds 65,535 chars -- truncated with "View in Deptex" link
4. Bitbucket PR comment truncated at 32KB with more aggressive limits
5. Commit message truncated to 10,000 chars before DB insert

Tests 46-50 (Edge Cases -- Dependency Analysis):

1. Private package reported as "unable to check" without blocking
2. Missing lockfile shows warning, skips transitive analysis
3. Deleted workspace in PR reported correctly without crash
4. Non-npm manifest change gets shallow analysis report
5. Multiple projects, partial guardrails: sections rendered correctly per project

Tests 51-55 (Scheduled Extraction -- 8N):

1. Daily sync: project with `sync_frequency = 'daily'` and `last_extracted_at` 25 hours ago gets queued
2. Daily sync: project with `last_extracted_at` 23 hours ago is NOT queued (not yet due)
3. Weekly sync: project with `last_extracted_at` 8 days ago gets queued
4. Per-org cap: org with 15 daily projects only gets 5 queued per invocation
5. Already-queued project is skipped by scheduler (no duplicate extraction jobs)

Tests 56-58 (Watchtower QStash Migration -- 8O):

1. QStash cron triggers `watchtower-daily-poll` endpoint; dependency refresh finds new npm version -> enqueues `watchtower-new-version-job`
2. Poll sweep detects new commits for watched package -> incremental analysis runs
3. Webhook health check marks repos inactive after 7 days with no webhook event

Tests 59-65 (Repository Lifecycle -- 8P):

1. `repository.renamed` event updates `repo_full_name` in `project_repositories`
2. `repository.deleted` event sets `status = 'repo_deleted'` and cancels active extraction jobs
3. `repository.edited` with `default_branch` change updates stored `default_branch`
4. `installation_repositories.removed` event sets `status = 'access_revoked'` for affected repos
5. Push handler auto-corrects `default_branch` when payload differs from stored value
6. Push/PR handlers skip projects with disconnected status (`repo_deleted`, `access_revoked`, `installation_removed`)
7. Frontend shows reconnect banner for disconnected repos (all three statuses)

Tests 66-70 (Security Hardening -- 8Q):

1. Webhook with invalid HMAC signature returns 401 (GitHub, Bitbucket)
2. Webhook with invalid token returns 401 (GitLab)
3. Missing `GITHUB_WEBHOOK_SECRET` in production rejects all webhooks
4. GitLab duplicate delivery (same `X-Gitlab-Event-UUID`) is rejected on second attempt
5. Fork PR creates check run with fork limitation note, no crash on inaccessible fork files

Tests 71-75 (Integration):

1. Full flow: push to monorepo -> only affected workspace extracted -> commit recorded -> compliance tab shows real data
2. Full flow: PR opened -> check runs created per project -> comment posted -> PR merged -> tracking table updated
3. GitLab full flow: push -> extraction -> MR opened -> commit status + note -> MR merged
4. Bitbucket full flow: push -> extraction -> PR created -> build status + comment -> PR merged
5. Webhook health: active repo shows green status, inactive (7+ days) shows yellow, error repos show red with reconnect prompt

### Phase 8 Database Migrations Summary

All new tables and columns added in Phase 8:

```sql
-- 8B: Sync frequency
ALTER TABLE project_repositories ADD COLUMN sync_frequency TEXT NOT NULL DEFAULT 'on_commit';

-- 8C: Commits tracking
CREATE TABLE project_commits ( ... );  -- see 8C.1 for full schema

-- 8F: Webhook deliveries audit
CREATE TABLE webhook_deliveries ( ... );  -- see 8F.8 for full schema

-- 8G: PR tracking
CREATE TABLE project_pull_requests ( ... );  -- see 8G.1 for full schema

-- 8H: No new table needed -- uses Phase 4 organization_pr_checks (already exists)

-- 8I/8J: Webhook management for GitLab/Bitbucket
ALTER TABLE project_repositories ADD COLUMN webhook_id TEXT;
ALTER TABLE project_repositories ADD COLUMN webhook_secret TEXT;
-- provider column already exists via migration_add_provider_to_project_repositories.sql

-- 8K: Webhook health
ALTER TABLE project_repositories ADD COLUMN last_webhook_at TIMESTAMPTZ;
ALTER TABLE project_repositories ADD COLUMN last_webhook_event TEXT;
ALTER TABLE project_repositories ADD COLUMN webhook_status TEXT DEFAULT 'unknown';

-- 8N: Scheduled extraction
ALTER TABLE project_repositories ADD COLUMN last_extracted_at TIMESTAMPTZ;
```

New valid `project_repositories.status` values (no schema change -- TEXT column):

- `'repo_deleted'` (8P: repository deleted on provider)
- `'access_revoked'` (8P: GitHub App removed from repo)
- `'installation_removed'` (8P: GitHub App installation deleted)

### Phase 8 New Files Summary

- `ee/backend/lib/manifest-registry.ts` -- manifest file pattern matching (8A)
- `ee/backend/routes/gitlab-webhooks.ts` -- GitLab webhook handler (8I)
- `ee/backend/routes/bitbucket-webhooks.ts` -- Bitbucket webhook handler (8J)
- `backend/src/routes/scheduled-extraction.ts` -- QStash cron endpoint for daily/weekly extraction (8N, CE route)
- `backend/src/routes/watchtower-daily-poll.ts` -- QStash cron endpoint for watchtower daily job (8O, CE route)
- `backend/src/lib/watchtower-poll.ts` -- extracted poller logic from watchtower-poller (8O, CE shared lib)
- `backend/database/project_commits_schema.sql` -- commits table (8C)
- `backend/database/webhook_deliveries_schema.sql` -- webhook audit table (8F)
- `backend/database/project_pull_requests_schema.sql` -- PR tracking table (8G)
- `backend/database/phase8_migrations.sql` -- ALTER TABLE additions (8B, 8I, 8J, 8K, 8N)

### Phase 8 Modified Files Summary

- `ee/backend/routes/integrations.ts` -- rewrite handlePushEvent (8B), rewrite handlePullRequestEvent (8D/8E/8F), add handlePullRequestClosedEvent (8G), add smart comment system (8F), add per-project check runs (8E), add repository lifecycle handlers (8P: handleRepositoryDeletedEvent, handleRepositoryRenamedEvent, handleRepositoryEditedEvent, handleInstallationReposRemovedEvent), extend handleInstallationDeleted (8P), add webhook delivery deduplication (8F.7), add payload size guard, add strict production verification (8Q)
- `ee/backend/lib/github.ts` -- add listIssueComments, updateIssueComment functions
- `ee/backend/lib/git-provider.ts` -- extend GitLabProvider and BitbucketProvider with webhook registration, commit status, MR/PR comments, token refresh with Redis lock
- `ee/backend/routes/projects.ts` -- add commits API, pull-requests API, update repo settings API for sync_frequency
- `ee/backend/routes/organizations.ts` -- add webhook-deliveries API and webhook-deliveries/stats API (8K.4)
- `frontend/src/app/pages/ProjectCompliancePage.tsx` -- replace placeholder with real API calls for PRs and commits
- `frontend/src/app/pages/ProjectSettingsPage.tsx` -- add sync frequency dropdown, webhook health display, disconnected repo banner (8P.6)
- `frontend/src/app/pages/OrganizationSettingsPage.tsx` -- add Webhooks section with deliveries table, summary cards, filters (8K.4)
- `backend/src/index.ts` -- mount scheduled-extraction and watchtower-daily-poll CE routes, add payload size limit for webhook routes
- `backend/load-ee-routes.js` -- mount GitLab and Bitbucket webhook routes

### Phase 8 QStash Schedules Summary


| Schedule              | Endpoint                                  | Frequency                       | Auth                                     |
| --------------------- | ----------------------------------------- | ------------------------------- | ---------------------------------------- |
| Scheduled extraction  | `POST /api/workers/scheduled-extraction`  | Every 6 hours (`0 */6 * * *`)   | QStash signature or `X-Internal-Api-Key` |
| Watchtower daily poll | `POST /api/workers/watchtower-daily-poll` | Daily at 4 AM UTC (`0 4 * * *`) | QStash signature or `X-Internal-Api-Key` |


---

