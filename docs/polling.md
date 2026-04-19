# Watchtower Polling: Design and Behavior

This document describes the **nightly polling** flow that checks for new package versions, syncs vulnerability data, and drives auto-bump PRs. It is the source of truth for intended behavior and for aligning implementation with security best practices.

---

## 1. Overview: States of Polling

The **Daily poll job** runs on a schedule (e.g. every 24 hours). Each run has two main phases:

| Phase | What runs | Scope |
|-------|-----------|--------|
| **1. Dependency refresh** | New-version check + vulnerability sync | Direct deps for “latest”; all deps for vulns |
| **2. Poll sweep** | GitHub commit polling for watched packages | All `watched_packages` with status `ready` |

Only **Phase 1** is “check for new package versions” and vulnerability sync. Phase 2 is about **source repos** (new commits), not npm releases.

---

## 2. Dependency Refresh (Phase 1) — Step by Step

### 2.1 Scope: Direct vs All Dependencies

- **Direct dependencies**  
  Rows in `project_dependencies` with `is_direct = true` and `source` in `['dependencies', 'devDependencies']`.  
  Used for:
  - Fetching **latest release** from npm (one call per package **name**).
  - Deciding when to enqueue **new_version** jobs and auto-bump.

- **All dependencies**  
  Every row in `dependencies` (direct + transitive).  
  Used for:
  - **Vulnerability sync**: fetch advisories and update `dependency_vulnerabilities` for every package name.

So: we **only** check for new **releases** on **direct** dependencies; we **sync vulnerabilities** for **all** dependencies in the table.

### 2.2 Checking for New Releases

- **Source of “latest”**: npm registry, one request per direct package name.
  - Endpoint: `GET https://registry.npmjs.org/<packageName>`.
  - We use `dist-tags.latest` (and `time[version]` for release date).
- **Rate limiting**: configurable delay between requests (`DEPENDENCY_REFRESH_DELAY_MS`, default 150ms) and concurrency cap (`DEPENDENCY_REFRESH_CONCURRENCY`, default 6) to avoid npm 429s.
- **Official releases only**:  
  We must **not** treat canary/experimental/RC as “latest” for auto-bump.  
  - **Intended behavior**: either use only a **stable** dist-tag (e.g. `latest` only when it points to a semver **stable** version), or resolve latest then filter with `semver.valid(version) && !semver.prerelease(version)`. If the current `dist-tags.latest` is a prerelease (e.g. `vcanary`), we should either skip treating it as a new release for bump purposes or resolve the latest **stable** version from `versions` + `time` (e.g. highest stable by publish date).
  - **Current implementation note**: we use `dist-tags.latest` as-is; adding a “stable-only” filter is a required improvement.

**Other ways to detect new releases (optional / future):**

- **GitHub Releases API**: for packages whose repo uses GitHub Releases, we could cross-check or backfill. Not a replacement for npm for installability.
- **npm registry `time`**: we already have it; can be used to derive “latest stable by date” if we move off raw `latest` tag for bump decisions.
- **Webhooks / notifications**: not used today; polling remains the source of truth.

### 2.3 When “Latest” Changes

- Compare npm’s latest (after stable filter) to `dependencies.latest_version` (and optionally `latest_release_date`).
- If **version string** changed:
  - Update `dependencies.latest_version` and `latest_release_date` for that name.
  - Ensure a `dependency_versions` row for the new version.
  - Enqueue **one** `new_version` job per package name (type `new_version`, with `dependency_id`, `name`, `new_version`, `latest_release_date`) to the **watchtower-new-version-jobs** queue.
- **Quarantine-expired**: for direct deps, if quarantine has expired for that dependency, enqueue a `quarantine_expired` job (same queue).

No new_version job when only the release **date** changed and the version string did not.

### 2.4 Auto-Bump After New Release

Handled by **watchtower-worker** when it processes a `new_version` or `quarantine_expired` job.

- **Candidates**: projects that have this dependency as a **direct** dep **and** have **auto_bump on** (true or null; explicit false is excluded). See `getCandidateProjectsForAutoBump`. So auto-bump only runs for projects with auto_bump enabled.
- **Vulnerability concern**: the **target version** must **not** be known-vulnerable; we check before creating any PR and skip bump if affected.
- **Org not on Watchtower for this package**: open bump PR to the new version (subject to the vuln check above).
- **Org on Watchtower for this package**: apply existing quarantine/watchlist logic (e.g. quarantine next release for 7 days, then allow; or use latest allowed, etc.). No change to that complicated behavior here; just ensure PR creation has fallbacks.
- **PR creation fallbacks** (branch already exists):
  - If branch creation fails with 422 “Reference already exists”:
    - List open PRs for that head ref. If an open PR exists, record it in `dependency_prs` and return that PR (no new branch/PR).
    - If no open PR, retry once with a **suffixed branch name** (e.g. timestamp).
    - If still failing, return a clear error: e.g. “A branch for this bump already exists on GitHub but no open PR was found. Delete the branch and try again.”
  - This behavior is implemented in the **backend** `create-bump-pr` and must be mirrored in the **watchtower-worker** `create-bump-pr` (worker uses GitHub App; both should behave the same).

### 2.5 Vulnerability Sync (All Dependencies)

- **Scope**: **all** dependency rows (all package names), not just direct.
- **Source**: we are **steering away from OSV**. Use **GitHub Advisory Database** only, via **GitHub GraphQL API** (GHSA), same source as `npm audit`. See `backend/src/lib/ghsa.ts`: `fetchGhsaVulnerabilitiesBatch(packageNames)`.
- **Batching**: GHSA supports up to 100 packages per GraphQL request. Batch all unique package names into chunks of 100 and call the API once per chunk (with optional short delay between chunks if rate-limiting is a concern). Align with how project extraction / populate uses GHSA (see `backend/src/routes/workers.ts` populate-dependencies).
- **Project extraction**: dependency list and “direct” vs transitive come from **extract-dependencies** (e.g. parsing lockfile/manifest). Polling does not re-extract; it uses existing `dependencies` and `project_dependencies`. Ensure extraction and GHSA use the same package names (npm names).
- **Sync semantics**:
  - **Upsert** (on dependency_id + osv_id) both **inserts new advisories** and **updates existing rows** when GHSA returns data (e.g. when firstPatchedVersion is set later). For each (dependency_id, advisory id) we store severity, summary, details, affected ranges, **fixed_versions** (e.g. firstPatchedVersion from GHSA).
  - When an advisory has a **patched version** and we already had that vuln stored: we **update** our row so `fixed_versions` (and affected ranges) reflect the fix. So “patched version is out” is reflected in the DB and UI (e.g. “upgrade to X to fix”).
- **Remove OSV**: in the poller, **do not** call OSV for vulnerability data. Use only GHSA (and optionally npm advisory bulk **only** if we keep it as a second source; otherwise GHSA-only is acceptable). Any code path that still calls OSV for the dependency-refresh vuln sync should be removed or gated off.

### 2.6 New Vulnerability Affecting a Current Version

- **Scenario**: a new advisory appears that affects the **current** version of a package used by a project (e.g. newest axios is vulnerable).
- **If the advisory has no fix yet** (“19.2.4 and down” — all current versions affected): we can only **record** the vuln and surface it; we cannot auto-fix by upgrade.
- **If a fix exists in a newer version**: we already have “bump to latest” flow; that will open an upgrade PR when we see the new release. No extra “downgrade” flow.
- **If the fix is in an *older* version** (downgrade path): e.g. “19.2.4 is vulnerable, 19.2.3 is fixed.”  
  - We **do not** implement “downgrade PR” today.  
  - **Possible future behavior**: if the **current** project version is affected and there exists a **patched** version that is **older** (or in the “last N stable” versions), consider opening a PR to **downgrade** to that patched version. This is a product/UX decision (downgrades can be surprising). Document as future work; no implementation required for current polling.

---

## 3. Worker Flow After New Version (Analysis Then Quarantine/Bump)

When the worker processes a `new_version` job, the order is:

1. **Analyze** the new release: `analyzePackageVersion` (registry integrity, install scripts, entropy). If any check fails, we store the error and do not proceed to bump.
2. **Update** dependency version analysis in the DB.
3. **Vulnerability check**: if the target version is affected by a known unfixed advisory, skip creating any bump PRs.
4. **Quarantine / bump**: `runAutoBumpPrLogic` — get candidates (projects with this dep as direct and **auto_bump on**), then for each: if org has package on Watchtower apply quarantine rules; if not (or when quarantine allows), create bump PR.

So the watchtower analysis (the three checks) and all the complicated quarantine/bump logic run in the worker **after** the poller has enqueued the new_version job; nothing is skipped.

---

## 4. Poll Sweep (Phase 2)

- **Input**: all `watched_packages` with status `ready`.
- **Per package**: resolve GitHub URL, call `checkForNewCommits`; if there are new commits, run incremental analysis and anomaly detection, update DB and `last_known_commit_sha`.
- This is **independent** of npm version polling and vulnerability sync.

---

## 5. Version Checks for Vulnerabilities (Semver Only)

All version comparisons for vulnerabilities use **semver** (e.g. `semver.coerce`, `semver.valid`, `semver.lt`, `semver.gte`, `semver.satisfies`). We do **not** use string comparison, so e.g. `1.13` is correctly treated as greater than `1.9`. See `backend/src/lib/semver-affected.ts` and `backend/watchtower-worker/src/semver-affected.ts`; tests in `backend/src/lib/__tests__/semver-affected.test.ts` cover 1.13 vs 1.9 style cases.

---

## 6. Security and Robustness

### 4.1 Vulnerability Checks Before Bump

- **Do not** auto-bump to a version that is **known vulnerable** (GHSA/advisory shows that version in affected range and no fix in that version). Check vulnerability data for the **target** version before creating the bump PR.
- Optionally: if the **current** project version is already vulnerable, prefer bump PRs that move to a **fixed** version (we already do that when “latest” is fixed).

### 4.2 Stable-Only Releases

- Avoid promoting **canary / prerelease** as “latest” for auto-bump. Filter by semver stable (no prerelease) or by dist-tag policy.

### 4.3 Rate Limits and Batching

- npm: delay + concurrency limit between registry calls.
- GHSA: batch up to 100 package names per GraphQL request; add delay between batches if needed (GitHub token increases rate limit).

### 4.4 PR and Branch Fallbacks

- Branch already exists: reuse existing open PR or retry with new branch name; clear error if branch exists but no PR.

### 4.5 What Snyk / Dependabot Do (Reference)

- **Dependabot**: Uses GitHub Advisory Database; creates **security update** PRs when an advisory affects a dependency, and **version update** PRs to keep deps current. Rebases PRs and limits open PRs.
- **Snyk**: Scans for vulns and creates upgrade PRs; often recommends patch/minor by default. Uses its own vuln DB plus ecosystem data.
- **We**: Use GHSA only (no OSV) for vulns; batch GHSA; only bump **direct** deps; add stable-only and “don’t bump to vulnerable” checks to avoid obvious flaws.

---

## 7. Implementation Checklist (Current vs Desired)

| Item | Status |
|------|--------|
| New-version check only for direct deps | ✅ |
| Delay + concurrency for npm | ✅ |
| Official releases only (stable, no canary) | ✅ (`fetchLatestNpmVersion` resolves latest stable from versions+time when dist-tags.latest is prerelease) |
| Vuln sync for **all** deps | ✅ (all names) |
| Use GHSA only (remove OSV) for poller vuln sync | ✅ (poller uses `ghsa.ts`, Phase 2 only) |
| Batch GHSA (e.g. 100 per request) | ✅ (chunks of 100 names per `fetchGhsaVulnerabilitiesBatch`) |
| Sync patched version into DB (fixed_versions) | ✅ (upsert includes fixed_versions) |
| Don’t auto-bump to a vulnerable target version | ✅ (worker checks `isTargetVersionVulnerable` before `runAutoBumpPrLogic`) |
| Branch-already-exists fallback in worker create-bump-pr | ✅ |
| Explicit org-on-watchtower vs not (only auto-bump when org does not have package on watchtower) | ✅ (documented and implemented: watchlist === null → create PR) |
| Downgrade PR when fix is in older version | ❌ Not implemented (documented as future) |

---

## 8. Related Code

- **Poller**: `backend/watchtower-poller/src/index.ts` (daily job), `dependency-refresh.ts` (refresh logic), `osv-checker.ts` (npm latest + currently OSV/npm advisories).
- **Worker**: `backend/watchtower-worker/src/index.ts` (new_version job, auto-bump), `create-bump-pr.ts` (PR + branch fallback), `github-app.ts` (listPullRequestsByHead).
- **GHSA**: `backend/src/lib/ghsa.ts` (batch fetch, filter by version, row shape).
- **Backend create-bump-pr**: `backend/src/lib/create-bump-pr.ts` (branch fallback reference).
- **Extraction**: `backend/src/routes/workers.ts` (extract-dependencies, populate-dependencies with GHSA batching).

---

## 9. Test Coverage

See **docs/polling-test-cases.md** for detailed test cases covering direct vs transitive, stable vs canary, version change, auto-bump conditions, watchtower/quarantine, PR fallbacks, vulnerability sync, batching, and edge cases.
