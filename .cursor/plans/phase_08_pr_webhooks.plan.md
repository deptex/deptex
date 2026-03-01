---
name: Phase 8 - PR Management & Webhooks
overview: Manifest registry, smart push extraction, PR tracking, GitLab/Bitbucket webhooks.
todos:
  - id: phase-8-pr
    content: "Phase 8: PR Management & Webhooks - Manifest registry, smart push extraction (sync_frequency + change detection), project commits tracking, multi-ecosystem PR analysis, per-project check runs, smart comment system (edit existing), PR tracking table, PR guardrails inheritance (Phase 4 policy engine), GitLab webhook + MR support, Bitbucket webhook + PR support, webhook health display, compliance tab real data (Updates sub-tab), edge cases + error handling + tests"
    status: pending
isProject: false
---
## Phase 8: PR Management and Webhooks

**Goal:** Build a rock-solid PR management and webhook system that intelligently handles pushes and pull requests across GitHub, GitLab, and Bitbucket, with proper monorepo support, per-project check runs, smart comment deduplication, full PR lifecycle tracking, and zero edge-case surprises.

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
        - 'daily' / 'weekly': skip extraction (handled by cron in Phase 13), still record commit
    10. Check if this project's package_json_path is in the affected workspaces map
        - Also check: if root-level manifest changed AND this project's workspace is a subdirectory,
          treat as affected (root changes can affect all workspaces via hoisting)
    11. If affected AND sync_frequency allows: call extractDependencies for this project
    12. If ANY file in this project's workspace changed (not just manifests): queue AST parsing
        (this is for reachability -- code changes can make vulns reachable even without dep changes)
    13. Record commit in project_commits table (always, regardless of extraction)
    14. Invalidate project caches on success
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

**8D.2: Per-ecosystem diff analysis**

The current PR handler reads `package.json` and `package-lock.json` from both base and head SHAs and computes added/bumped/transitive diffs. This logic needs to become ecosystem-aware:

- **npm** (already implemented): read `package.json` + lockfile, compute direct added/bumped + transitive changes
- **Other ecosystems** (Python, Go, Java, Rust, Ruby, .NET, PHP): for now, detect that a manifest changed and report it in the comment as "Manifest file changed: `requirements.txt`" without deep diff analysis. Deep per-ecosystem diff analysis will be added as extraction support for each ecosystem lands (Phases 1-3).

This means the PR handler has two modes per workspace:

1. **Deep analysis** (npm): full dep diff, vuln checks, license checks, transitive analysis
2. **Shallow analysis** (other ecosystems): flag that manifest changed, list which files, note that detailed analysis will be available once the ecosystem is fully supported

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

**8H.2: Backward compatibility**

Phase 8 must work BEFORE Phase 4 is implemented. The current `project_pr_guardrails` logic is the fallback:

- Load `project_pr_guardrails` for the project
- Check vuln thresholds, policy violations, transitive vulns
- This is exactly what the current code does

When Phase 4 lands, the `pr_check_code` path takes priority. The simple guardrails become the "default PR check code" seeded on org creation.

**8H.3: Org-level guardrails as defaults**

When a project has no `project_pr_guardrails` row AND no `effective_pr_check_code`:

- Fall back to org-level defaults
- For Phase 8 (pre-Phase 4): create an `organization_pr_guardrails` table with the same schema as `project_pr_guardrails`, seeded with all-false defaults on org creation
- Projects with no guardrails row inherit from the org

```sql
CREATE TABLE organization_pr_guardrails (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  block_critical_vulns BOOLEAN DEFAULT false,
  block_high_vulns BOOLEAN DEFAULT false,
  block_medium_vulns BOOLEAN DEFAULT false,
  block_low_vulns BOOLEAN DEFAULT false,
  block_policy_violations BOOLEAN DEFAULT false,
  block_transitive_vulns BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
```

Resolution order: `project_pr_guardrails` -> `organization_pr_guardrails` -> all-false (no blocking).

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

(If `provider` column doesn't already exist -- check `organization_integrations` for the provider info that may already be joinable.)

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
- OAuth token refresh: Bitbucket tokens expire (1-2 hours), use refresh_token

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

A background check (can piggyback on the existing watchtower-poller daily run):

- Query `project_repositories` where `webhook_status = 'active'` AND `last_webhook_at < NOW() - INTERVAL '7 days'`
- Set `webhook_status = 'inactive'`
- This indicates the webhook may have been removed or is broken

**8K.3: UI in project settings**

In the Repository section of [ProjectSettingsPage.tsx](frontend/src/app/pages/ProjectSettingsPage.tsx):

- Show "Webhook Status" indicator: green dot + "Active (last event: 2 min ago)" or yellow dot + "Inactive (no events in 7 days)" or grey dot + "Unknown"
- Show "Last Event" type: "push", "pull_request", etc.
- "Re-register Webhook" button: calls the provider API to re-create the webhook (for GitLab/Bitbucket where we manage webhook registration). For GitHub, webhooks are managed by the GitHub App itself so this isn't needed.

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

### 8M: Edge Cases, Error Handling, and Tests

**8M.1: Edge cases to handle**

1. **Concurrent webhook events for same PR**: Two `synchronize` events arrive simultaneously (fast consecutive pushes). The edit-existing-comment approach handles this naturally (last write wins). Check runs: create for new SHA, old SHA's check runs auto-stale.
2. **Force push on PR**: `synchronize` event fires. The `base_sha` in Compare API may be invalid. Handle 422 by falling back: use the PR's `base.sha` (the target branch head) instead.
3. **Large PRs (100+ dependency changes)**: Cap the comment detail to 50 dependencies, add "...and X more dependencies changed" footer. Check run output has the same cap.
4. **Private/scoped packages**: When `getVulnCountsForPackageVersion` or `getLicenseForPackage` fails for a private package, report as "Private package -- unable to check vulnerabilities" in the comment. Don't block on inability to check.
5. **Missing lockfile**: Workspace has manifest but no lockfile. Report in comment: "No lockfile found -- transitive dependency analysis unavailable. Only direct dependency changes are shown." Skip transitive checks for that workspace.
6. **Installation suspended/deleted mid-scan**: GitHub App installation suspended. API calls return 401/403. Catch in the check run creation step, log error. PR tracking row gets `check_result = 'error'` with note.
7. **Rate limiting**: GitHub API rate limit hit during PR check. Use `x-ratelimit-remaining` header to detect approaching limits. If hit, wait using `x-ratelimit-reset` header (retry after). Add exponential backoff (max 3 retries per API call).
8. **Webhook secret not set**: Currently `verifyGitHubWebhookSignature` returns `true` if secret is not set. Change to log a WARNING but still process (don't break existing setups). Add a health check that warns if `GITHUB_WEBHOOK_SECRET` is unset.
9. **Multiple projects sharing a repo (monorepo) -- partial guardrails**: Project A has guardrails enabled, Project B does not. The aggregated comment should include a section for Project A (with results) and either skip Project B or show "No guardrails configured" for Project B. The check run for Project A shows pass/fail, no check run created for Project B.
10. **Root manifest change affects all workspaces**: If `package.json` at root changes, all projects in that repo are treated as affected (8B.4). The PR comment shows sections for each affected project.
11. **PR targeting non-default branch**: Skip entirely (8E.5). Return early with no check runs or comments.
12. **Deleted workspace in PR**: A PR removes an entire workspace directory (including its manifest). The workspace IS detected as affected (file was "removed" in the diff). The handler should detect that `head` doesn't have the manifest anymore and report: "Workspace removed in this PR."
13. **Token expiry (GitLab/Bitbucket OAuth)**: Before each API call batch, check token expiry. If expired, use refresh_token to get a new access_token. If refresh fails (revoked), set `webhook_status = 'error'` and skip processing with a log.
14. **Webhook replay attacks**: GitHub webhook signatures are tied to the payload, so replays produce the same result (idempotent). GitLab tokens are static per-webhook. Bitbucket HMAC is payload-bound. No additional protection needed beyond signature verification.
15. **Org deleted between webhook receive and processing**: The async handler runs after 200 response. If the org/project is deleted mid-processing, Supabase queries return null. Handle gracefully with null checks at each step.
16. **Empty PR (no file changes)**: Some edge cases produce PRs with 0 changed files. `getCompareChangedFiles` returns empty array. `detectAffectedWorkspaces` returns empty map. Handler returns early with no check runs or comments (correct behavior).

**8M.2: Test plan**

Tests 1-5 (Manifest Registry):

1. `matchManifestFile` correctly identifies all ecosystem manifests (npm, Python, Go, Java, Rust, Ruby, .NET, PHP)
2. `matchManifestFile` returns null for non-manifest files (`.ts`, `.py`, `.go`, etc.)
3. `matchManifestFile` correctly extracts workspace paths for nested manifests
4. `detectAffectedWorkspaces` groups changed files by workspace and ecosystem
5. Root-level manifest changes are detected with workspace `''`

Tests 6-10 (Push Handler):
6. Push with lockfile change triggers extraction for that workspace only
7. Push with no manifest changes skips extraction, still records commit
8. Push with `sync_frequency = 'manual'` skips extraction, records commit
9. Push with `sync_frequency = 'on_commit'` triggers extraction when manifest changes
10. Force push (422 from Compare API) falls back to full extraction for all projects

Tests 11-15 (PR Handler):
11. PR with `package.json` change in one workspace only triggers check for that project
12. PR with changes in multiple workspaces creates separate check runs per project
13. PR comment is created on first run, edited on subsequent pushes
14. `pull_request_comments_enabled = false` suppresses comment but still creates check run
15. PR targeting non-default branch is skipped entirely

Tests 16-20 (Check Runs):
16. Check run created with `in_progress`, updated to `completed` with `success`
17. Check run created with `in_progress`, updated to `completed` with `failure` when guardrails block
18. Check run named `Deptex - {project_name}` per project
19. Stale check runs from previous SHA are superseded (no explicit cleanup needed)
20. Check run creation failure doesn't prevent comment from being posted

Tests 21-25 (PR Tracking):
21. PR opened -> `project_pull_requests` row created with status `open`
22. PR `synchronize` -> row updated with new `head_sha` and `last_checked_at`
23. PR merged (closed with merged=true) -> status set to `merged`, `merged_at` populated
24. PR closed (not merged) -> status set to `closed`, `closed_at` populated
25. API returns correct counts: open PRs, failed checks, passed checks

Tests 26-30 (Commit Tracking):
26. Push records commit in `project_commits` with correct metadata
27. Multi-commit push records all commits
28. Commit `manifest_changed` flag set correctly based on changed files
29. Commit `compliance_status` populated after extraction
30. API returns paginated, filterable commits

Tests 31-35 (GitLab):
31. GitLab push webhook triggers extraction for affected workspaces
32. GitLab MR webhook creates commit status (pending -> success/failed)
33. GitLab MR comment created with marker, edited on subsequent updates
34. GitLab webhook token verification rejects invalid tokens
35. GitLab token refresh works when access token expires

Tests 36-40 (Bitbucket):
36. Bitbucket push webhook triggers extraction for affected workspaces
37. Bitbucket PR webhook creates build status (INPROGRESS -> SUCCESSFUL/FAILED)
38. Bitbucket PR comment created with marker, edited on subsequent updates
39. Bitbucket webhook HMAC verification rejects invalid signatures
40. Bitbucket token refresh works when access token expires

Tests 41-45 (Edge Cases):
41. Large PR (100+ deps) caps comment at 50 entries with "and X more" footer
42. Private package reported as "unable to check" without blocking
43. Missing lockfile shows warning, skips transitive analysis
44. Concurrent webhook events for same PR don't produce duplicate comments
45. Deleted workspace in PR reported correctly without crash

Tests 46-50 (Integration):
46. Full flow: push to monorepo -> only affected workspace extracted -> commit recorded -> compliance tab shows real data
47. Full flow: PR opened -> check runs created per project -> comment posted -> PR merged -> tracking table updated
48. GitLab full flow: push -> extraction -> MR opened -> commit status + note -> MR merged
49. Bitbucket full flow: push -> extraction -> PR created -> build status + comment -> PR merged
50. Webhook health: active repo shows green status, inactive (7+ days) shows yellow

### Phase 8 Database Migrations Summary

All new tables and columns added in Phase 8:

```sql
-- 8B: Sync frequency
ALTER TABLE project_repositories ADD COLUMN sync_frequency TEXT NOT NULL DEFAULT 'on_commit';

-- 8C: Commits tracking
CREATE TABLE project_commits ( ... );  -- see 8C.1 for full schema

-- 8G: PR tracking
CREATE TABLE project_pull_requests ( ... );  -- see 8G.1 for full schema

-- 8H: Org-level guardrails
CREATE TABLE organization_pr_guardrails ( ... );  -- see 8H.3 for full schema

-- 8I/8J: Webhook management for GitLab/Bitbucket
ALTER TABLE project_repositories ADD COLUMN webhook_id TEXT;
ALTER TABLE project_repositories ADD COLUMN webhook_secret TEXT;
-- provider column may already exist via organization_integrations join

-- 8K: Webhook health
ALTER TABLE project_repositories ADD COLUMN last_webhook_at TIMESTAMPTZ;
ALTER TABLE project_repositories ADD COLUMN last_webhook_event TEXT;
ALTER TABLE project_repositories ADD COLUMN webhook_status TEXT DEFAULT 'unknown';
```

### Phase 8 New Files Summary

- `ee/backend/lib/manifest-registry.ts` -- manifest file pattern matching (8A)
- `ee/backend/routes/gitlab-webhooks.ts` -- GitLab webhook handler (8I)
- `ee/backend/routes/bitbucket-webhooks.ts` -- Bitbucket webhook handler (8J)
- `backend/database/project_commits_schema.sql` -- commits table (8C)
- `backend/database/project_pull_requests_schema.sql` -- PR tracking table (8G)
- `backend/database/organization_pr_guardrails_schema.sql` -- org-level guardrails (8H)
- `backend/database/phase8_migrations.sql` -- ALTER TABLE additions (8B, 8I, 8J, 8K)

### Phase 8 Modified Files Summary

- `ee/backend/routes/integrations.ts` -- rewrite handlePushEvent, rewrite handlePullRequestEvent, add handlePullRequestClosedEvent, add smart comment system, add per-project check runs
- `ee/backend/lib/github.ts` -- add listIssueComments, updateIssueComment functions
- `ee/backend/lib/git-provider.ts` -- extend GitLabProvider and BitbucketProvider with webhook registration, commit status, MR/PR comments
- `ee/backend/routes/projects.ts` -- add commits API, pull-requests API, update repo settings API for sync_frequency, add org guardrails endpoints
- `frontend/src/app/pages/ProjectCompliancePage.tsx` -- replace mock data with real API calls
- `frontend/src/app/pages/ProjectSettingsPage.tsx` -- add sync frequency dropdown, webhook health display
- `backend/load-ee-routes.js` -- mount GitLab and Bitbucket webhook routes

---