---
name: Phase 3 Extraction Enhancements
overview: Enhance the extraction pipeline with malicious package detection (via GHSA), SLSA provenance verification (npm), devDependency fix, outdated detection, scoring formula upgrades, and a comprehensive test suite. Removes container scanning (separate plan) and policy evaluation (deferred to Phase 4).
todos:
  - id: 3a1-malicious
    content: "3A.1: Add GHSA classification field to GraphQL query, propagate MALWARE flag to dependency_vulnerabilities and dependencies.is_malicious"
    status: completed
  - id: 3a2-slsa
    content: "3A.2: Add SLSA provenance check via npm attestations API in populateSingleDependency, store slsa_level on dependency_versions"
    status: completed
  - id: 3a3-outdated
    content: "3A.3: Calculate is_outdated and versions_behind in populate-dependencies flow, update on watchtower poller refresh"
    status: completed
  - id: 3a4-devdep
    content: "3A.4: Fix devDependency detection -- cross-reference SBOM with manifest files (package.json, pyproject.toml, pom.xml)"
    status: completed
  - id: 3b1-dep-score
    content: "3B.1: Add SLSA bonus and malicious penalty multipliers to calculateDependencyScore in workers.ts"
    status: completed
  - id: 3b2-depscore
    content: "3B.2: Add isDirect, isDevDependency, isMalicious, packageScore to Depscore formula (both backend and frontend copies)"
    status: completed
  - id: 3b3-frontend
    content: "3B.3: Update ScoreBreakdownSidebar with new multipliers, add is_outdated badge to dependency list"
    status: completed
  - id: 3c-tests
    content: "3C: Write comprehensive test suite -- pipeline, sbom, clone, depscore, scoring, integration tests"
    status: completed
  - id: migrations
    content: "DB migrations: classification on dependency_vulnerabilities, is_malicious on dependencies, slsa_level on dependency_versions, is_outdated + versions_behind on project_dependencies"
    status: completed
isProject: false
---

# Phase 3: Extraction Worker Enhancements (Revised)

**Scope:** Backend extraction worker + scoring formulas + minor frontend score display updates. No new pages or major frontend work.

**Removed from original plan:**

- **3A.3 Container Scanning** -- moved to its own future plan (needs separate Dockerfile tooling, new schema, UI for container type, docs updates)
- **3D Policy Evaluation** -- depends on Phase 4 tables (`organization_package_policies`, `organization_status_codes`, `organization_statuses`) that don't exist yet. Implement as part of Phase 4.
- **Socket.dev integration** -- replaced with free GHSA malware classification (see 3A.1)

---

## 3A: Pipeline Scanning Capabilities

### 3A.1: Malicious Package Detection (via GHSA -- FREE)

Instead of Socket.dev, leverage the GHSA `classification` field we already query but don't capture.

**Changes to [backend/src/lib/ghsa.ts](backend/src/lib/ghsa.ts):**

- Add `classification` to the GraphQL advisory fragment (line 58):

```
  advisory { ghsaId summary description severity publishedAt updatedAt classification identifiers { type value } }
  

```

- Add `classification` to `GhsaVuln` interface and `ghsaVulnToRow()`
- Propagate to `dependency_vulnerabilities` table via new column

**DB migration** (`backend/database/add_classification_to_dependency_vulnerabilities.sql`):

- `ALTER TABLE dependency_vulnerabilities ADD COLUMN classification TEXT DEFAULT 'GENERAL'`
- Values: `GENERAL` (normal vuln) or `MALWARE` (known malicious package)

**Pipeline integration** in [ee/backend/routes/workers.ts](ee/backend/routes/workers.ts) populate-dependencies flow:

- When upserting `dependency_vulnerabilities`, include `classification` from GHSA
- After upsert, check if any advisory has `classification = 'MALWARE'` for this dependency
- If so, set `dependencies.is_malicious = true` (new boolean column, default false)

**DB migration** (`backend/database/add_is_malicious_to_dependencies.sql`):

- `ALTER TABLE dependencies ADD COLUMN is_malicious BOOLEAN DEFAULT false`

**Cost: $0.** Uses existing GHSA API calls with one extra field.

### 3A.2: SLSA Provenance Verification (npm only for now)

**Limitation:** SLSA provenance attestations are currently only widely available for npm packages (via `--provenance` publish flag). PyPI has experimental support; other ecosystems have none. This feature will return `null` for non-npm packages.

**Approach:** Use the npm registry API to check for provenance attestations:

- `GET https://registry.npmjs.org/-/npm/v1/attestations/{name}@{version}`
- Returns attestations array with SLSA provenance predicateType
- Parse the SLSA build level from the attestation

**Integration point:** In [ee/backend/routes/workers.ts](ee/backend/routes/workers.ts) `populateSingleDependency()` -- runs during populate-dependencies flow (not during extraction pipeline), alongside npm registry fetch, GHSA, and OpenSSF scorecard.

**DB migration** (`backend/database/add_slsa_level_to_dependency_versions.sql`):

- `ALTER TABLE dependency_versions ADD COLUMN slsa_level INTEGER` (nullable, 0-4)

**Cost: $0.** npm registry API is free and unauthenticated.

### 3A.3: Outdated Dependencies Detection

**Where to compute:** In the populate-dependencies flow (`populateSingleDependency` in [ee/backend/routes/workers.ts](ee/backend/routes/workers.ts)), NOT during extraction. Reason: `latest_version` is already fetched there, and calculating during extraction means data is stale immediately. The watchtower poller also refreshes `latest_version` daily, which should trigger an update to these fields too.

**DB migration** (`backend/database/add_outdated_to_project_dependencies.sql`):

- `ALTER TABLE project_dependencies ADD COLUMN is_outdated BOOLEAN DEFAULT false`
- `ALTER TABLE project_dependencies ADD COLUMN versions_behind INTEGER DEFAULT 0`

**Logic:** After `latest_version` is known for a dependency, iterate over all `project_dependencies` rows for that dependency_id:

- Compare `project_dependencies.version` against `dependencies.latest_version` using semver
- Set `is_outdated = true` if current version < latest
- Calculate `versions_behind` by counting published versions between current and latest (from npm registry versions list, already partially fetched)

### 3A.4: devDependency Detection Fix

**Problem:** The SBOM parser in [backend/extraction-worker/src/sbom.ts](backend/extraction-worker/src/sbom.ts) line 155 sets `source: 'dependencies'` for ALL direct deps. CycloneDX SBOMs from cdxgen don't reliably distinguish devDependencies.

**Fix (ecosystem-aware):**

For **npm**: After SBOM parsing, read `package.json` from the cloned repo and cross-reference:

- Parse `devDependencies` keys from `package.json`
- For each parsed SBOM dep where `is_direct = true`, check if its name is in `package.json.devDependencies`
- If so, set `source = 'devDependencies'`

For **Python**: Check `pyproject.toml` (`[tool.poetry.dev-dependencies]` or `[project.optional-dependencies]`), `requirements-dev.txt`, `setup.py` extras_require

For **Maven**: Check `<scope>test</scope>` or `<scope>provided</scope>` in `pom.xml`

For **other ecosystems**: Leave as-is for now (most don't have a clear dev/prod split in their manifest files)

**Implementation location:** New step in [pipeline.ts](backend/extraction-worker/src/pipeline.ts) after SBOM parsing, before dep sync. Read manifest file, build dev-dependency set, patch parsed deps.

---

## 3B: Scoring Enhancements

### 3B.1: Dependency Score (package reputation) -- add multipliers

Update `calculateDependencyScore` in [ee/backend/routes/workers.ts](ee/backend/routes/workers.ts):

```typescript
function calculateDependencyScore(data: {
  openssfScore: number | null;
  weeklyDownloads: number | null;
  releasesLast12Months: number | null;
  slsaLevel: number | null;
  isMalicious: boolean;
}): ScoreBreakdown {
  // Existing base score (unchanged)
  const baseScore = 100 - openssfPenalty - popularityPenalty - maintenancePenalty;

  // SLSA bonus (no penalty for missing -- adoption is low)
  const slsaMultiplier = data.slsaLevel != null
    ? (data.slsaLevel >= 3 ? 1.1 : data.slsaLevel >= 1 ? 1.05 : 1.0)
    : 1.0;

  // Malicious penalty
  const maliciousMultiplier = data.isMalicious ? 0.15 : 1.0;

  const score = Math.min(100, Math.max(0,
    Math.round(baseScore * slsaMultiplier * maliciousMultiplier)));
  return { score, openssfPenalty, popularityPenalty, maintenancePenalty,
           slsaMultiplier, maliciousMultiplier };
}
```

**Note on malicious multiplier:** Changed from the original plan's tiered 0.1/0.2/0.5 approach to a single `0.15` for `is_malicious = true`. Reason: GHSA malware classification is binary (MALWARE or not) -- there's no severity level on the classification itself. A package flagged as MALWARE by GHSA is confirmed malicious, not speculative, so false positives are rare. Score 80 becomes 12, which is appropriate for confirmed malware.

### 3B.2: Depscore (per-vulnerability) -- add dependency context

Update both copies:

- [backend/extraction-worker/src/depscore.ts](backend/extraction-worker/src/depscore.ts)
- [frontend/src/lib/scoring/depscore.ts](frontend/src/lib/scoring/depscore.ts)

```typescript
export interface DepscoreContext {
  cvss: number;
  epss: number;
  cisaKev: boolean;
  isReachable: boolean;
  assetTier: AssetTier;
  isDirect: boolean;
  isDevDependency: boolean;
  isMalicious: boolean;
  packageScore: number | null;
}
```

New weights (appended after existing `environmentalMultiplier`):

- `isDirect`: direct = 1.0, transitive = 0.75
- `isDevDependency`: prod = 1.0, dev = 0.4
- `isMalicious`: malicious = 1.3, normal = 1.0
- `packageScore`: < 30 = 1.15, > 70 = 0.95, else 1.0

### 3B.3: Frontend score display updates

- Update `ScoreBreakdownSidebar` to show SLSA bonus and malicious penalty in the breakdown
- Update dependency list to show `is_outdated` badge and `versions_behind` count where applicable
- Both files MUST stay in sync with backend formulas

---

## 3C: Comprehensive Test Suite

### Unit tests (Jest, mock all externals)

`**backend/extraction-worker/src/__tests__/pipeline.test.ts`:**

- Each pipeline step in isolation (mock cdxgen, dep-scan, semgrep, trufflehog, git, supabase)
- Success path: each step completes and passes data to next
- Critical step failures abort pipeline (clone, SBOM, dep sync)
- Optional step failures log warnings and continue (dep-scan, Semgrep, TruffleHog)
- Cancellation check between steps
- All failure modes from Phase 2E-pipeline table

`**backend/extraction-worker/src/__tests__/sbom.test.ts`:**

- SBOM parsing fixtures for each ecosystem
- License extraction from various CycloneDX formats
- Direct vs transitive classification
- devDependency detection (with package.json cross-reference)
- Empty/malformed SBOM handling

`**backend/extraction-worker/src/__tests__/clone.test.ts`:**

- Mock `simple-git` for each provider
- Token generation and clone URL construction
- Retry logic, temp directory creation/cleanup

`**backend/extraction-worker/src/__tests__/depscore.test.ts`:**

- Existing formula produces same results for existing inputs (regression)
- New context factors: direct vs transitive, dev vs prod, malicious boost, reputation weight
- Edge cases: null packageScore, missing isDirect, etc.
- Transitive dev dep vuln reduced by ~70% from direct prod

`**backend/extraction-worker/src/__tests__/scoring.test.ts`:**

- Existing dependency score unchanged for packages without new data (regression)
- SLSA bonus: level 3 = 10% boost, level 1 = 5%, no SLSA = unchanged
- Malicious multiplier: is_malicious drops score by 85%
- Combined: malicious + no SLSA vs clean + SLSA 3

`**ee/backend/lib/__tests__/fly-machines.test.ts`** and `**ee/backend/lib/__tests__/job-recovery.test.ts`:**

- Only if not already written in Phase 2. If they exist, skip.

### Integration tests (requires Supabase)

`**backend/extraction-worker/src/__tests__/integration.test.ts`:**

- Tiny test repo fixture, full pipeline end-to-end (skip dep-scan/semgrep/trufflehog for speed)
- Verify DB state: dependencies, versions, edges, logs
- Verify SBOM uploaded to storage
- Verify project status is `ready`

---

## DB Migrations Summary


| File                                                   | Changes                                                                  |
| ------------------------------------------------------ | ------------------------------------------------------------------------ |
| `add_classification_to_dependency_vulnerabilities.sql` | `classification TEXT DEFAULT 'GENERAL'`                                  |
| `add_is_malicious_to_dependencies.sql`                 | `is_malicious BOOLEAN DEFAULT false`                                     |
| `add_slsa_level_to_dependency_versions.sql`            | `slsa_level INTEGER` (nullable)                                          |
| `add_outdated_to_project_dependencies.sql`             | `is_outdated BOOLEAN DEFAULT false`, `versions_behind INTEGER DEFAULT 0` |


---

## Files Changed Summary

**Backend (extraction worker):**

- `backend/extraction-worker/src/pipeline.ts` -- new devDep detection step after SBOM parse
- `backend/extraction-worker/src/sbom.ts` -- devDep cross-reference logic
- `backend/extraction-worker/src/depscore.ts` -- new DepscoreContext fields + weights

**Backend (API/workers):**

- `backend/src/lib/ghsa.ts` -- add `classification` to GraphQL query and interfaces
- `ee/backend/routes/workers.ts` -- `calculateDependencyScore` multipliers, SLSA fetch in populate, `is_malicious` flag, outdated calculation

**Frontend:**

- `frontend/src/lib/scoring/depscore.ts` -- mirror new DepscoreContext + weights
- `frontend/src/components/ScoreBreakdownSidebar.tsx` -- show SLSA + malicious in breakdown
- Dependencies list component -- `is_outdated` badge

**Migrations:**

- 4 new SQL files in `backend/database/`

**Tests:**

- 5-7 new test files in extraction worker and ee/backend

