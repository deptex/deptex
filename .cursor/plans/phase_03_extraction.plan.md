---
name: Phase 3 - Extraction Enhancements
overview: Malicious package detection, SLSA verification, container scanning, devDep detection, test suite.
todos:
  - id: phase-3-extraction
    content: "Phase 3: Extraction Enhancements - Malicious package detection, SLSA verification, container scanning, devDep detection, test suite"
    status: pending
isProject: false
---
## Phase 3: Extraction Worker Enhancements

**Goal:** Add missing capabilities and improve the extraction pipeline.

### 3A: Additional Scanning Capabilities

Research findings - add these to the pipeline in [pipeline.ts](backend/extraction-worker/src/pipeline.ts):

1. **Malicious Package Detection** - Integrate [Socket.dev API](https://socket.dev/) or use `npm audit signatures` for npm packages
  - Socket.dev has a free tier (250 packages/month) and API at ~$0.01/lookup above that
  - Alternative: Use `ossf/package-analysis` (free, open-source) for basic checks
  - Store result in a new `malicious_indicator` field on `project_dependencies`
2. **SLSA Provenance Verification** - Check if packages have SLSA provenance attestations
  - Use `slsa-verifier` CLI tool or npm `--provenance` flag
  - Store SLSA level in `dependency_versions.slsa_level`
  - Relevant for compliance scoring
3. **Container Image Scanning** - If the repo has Dockerfiles, scan base images
  - Use `grype` (already in dep-scan ecosystem) or `trivy` for container scanning
  - Store results as separate vulnerability type
4. **Outdated Dependencies Detection** - Compare current versions against latest
  - Already have `latest_version` on `dependencies` table
  - Add `is_outdated`, `versions_behind` fields to `project_dependencies`
  - Calculate during extraction
5. **devDependency Detection** - Fix the SBOM parser to correctly identify dev vs prod dependencies
  - Parse `package.json` directly to cross-reference with SBOM output
  - Update source field in [sbom.ts](backend/extraction-worker/src/sbom.ts) line 155

### 3B: Scoring Enhancements

#### Dependency Score (package-level reputation) - Multiplier approach

Current formula in [workers.ts](ee/backend/routes/workers.ts) (`calculateDependencyScore`):
`score = 100 - openssfPenalty - popularityPenalty - maintenancePenalty`

**Keep existing formula as the base score, then apply multipliers:**

```typescript
function calculateDependencyScore(data: {
  openssfScore: number | null;
  weeklyDownloads: number | null;
  releasesLast12Months: number | null;
  slsaLevel: number | null;         // NEW
  maliciousIndicator: object | null; // NEW
}): ScoreBreakdown {
  // Existing base score (unchanged)
  const baseScore = 100 - openssfPenalty - popularityPenalty - maintenancePenalty;
  
  // SLSA bonus: reward packages with provenance attestations
  const slsaMultiplier = data.slsaLevel != null
    ? (data.slsaLevel >= 3 ? 1.1 : data.slsaLevel >= 1 ? 1.05 : 1.0)
    : 1.0; // No penalty for missing SLSA (adoption is still low)
  
  // Malicious penalty: devastating multiplier for flagged packages
  const maliciousMultiplier = data.maliciousIndicator
    ? (data.maliciousIndicator.severity === 'critical' ? 0.1  // score 80 -> 8
       : data.maliciousIndicator.severity === 'high' ? 0.2    // score 80 -> 16
       : 0.5)                                                  // score 80 -> 40
    : 1.0;
  
  const score = Math.min(100, Math.max(0, Math.round(baseScore * slsaMultiplier * maliciousMultiplier)));
  return { score, openssfPenalty, popularityPenalty, maintenancePenalty, slsaMultiplier, maliciousMultiplier };
}
```

Update the score breakdown display in the frontend to show the new multipliers.

#### Depscore (per-vulnerability risk) - Add contextual factors

Current formula in [depscore.ts](backend/extraction-worker/src/depscore.ts):
`score = baseImpact * threatMultiplier * environmentalMultiplier`

**Add a new `dependencyContextMultiplier`:**

```typescript
export interface DepscoreContext {
  cvss: number;
  epss: number;
  cisaKev: boolean;
  isReachable: boolean;
  assetTierMultiplier: number; // CHANGED: was AssetTier enum, now custom multiplier from organization_asset_tiers
  isDirect: boolean;          // NEW
  isDevDependency: boolean;   // NEW
  isMalicious: boolean;       // NEW
  packageScore: number | null; // NEW (0-100 dependency reputation score)
}

// Directness: direct deps are more immediately exploitable
const DIRECTNESS_WEIGHT = { direct: 1.0, transitive: 0.75 };

// Dev/prod: dev deps rarely reach production
const ENVIRONMENT_WEIGHT = { production: 1.0, development: 0.4 };

// Malicious: known-malicious packages are actively exploited
const MALICIOUS_BOOST = 1.3;

// Low-reputation packages are riskier (unpatched longer, less scrutiny)
function packageReputationWeight(score: number | null): number {
  if (score === null) return 1.0;
  if (score < 30) return 1.15;  // bad reputation = slightly higher risk
  if (score > 70) return 0.95;  // good reputation = slightly lower risk
  return 1.0;
}

export function calculateDepscore(ctx: DepscoreContext): number {
  // Existing formula (unchanged)
  const baseImpact = cvss * 10;
  const threatMultiplier = ctx.cisaKev ? 1.2 : 0.6 + 0.6 * Math.sqrt(epss);
  const environmentalMultiplier = tierWeight * reachabilityWeight;
  
  // NEW: dependency context multiplier
  const directnessWeight = ctx.isDirect ? DIRECTNESS_WEIGHT.direct : DIRECTNESS_WEIGHT.transitive;
  const envWeight = ctx.isDevDependency ? ENVIRONMENT_WEIGHT.development : ENVIRONMENT_WEIGHT.production;
  const maliciousWeight = ctx.isMalicious ? MALICIOUS_BOOST : 1.0;
  const reputationWeight = packageReputationWeight(ctx.packageScore);
  const dependencyContextMultiplier = directnessWeight * envWeight * maliciousWeight * reputationWeight;
  
  const score = baseImpact * threatMultiplier * environmentalMultiplier * dependencyContextMultiplier;
  return Math.min(100, Math.round(score));
}
```

**Impact of these changes:**

- A critical vuln (CVSS 9.0) in a direct production dep with CISA KEV: Depscore ~100 (unchanged)
- Same vuln in a transitive dev dep: Depscore ~100 * 0.75 * 0.4 = ~30 (massive noise reduction)
- Same vuln in a malicious package: Depscore boosted by 1.3x (flags urgency)
- Vuln in low-reputation package: Depscore boosted by 1.15x (subtle but meaningful)

**CRITICAL:** Update BOTH copies of the depscore formula:

- `backend/extraction-worker/src/depscore.ts` (worker)
- `frontend/src/lib/scoring/depscore.ts` (frontend recalculation for simulations)

### 3C-scoring: Scoring test cases

Add to the test suite:

- Test existing dependency score formula still produces same results for packages without new data
- Test SLSA bonus: SLSA 3 package gets 10% boost, SLSA 1 gets 5%, no SLSA unchanged
- Test malicious multiplier: critical malicious flag drops score by 90%
- Test Depscore: direct prod dep vuln unchanged from before
- Test Depscore: transitive dev dep vuln reduced by ~70%
- Test Depscore: malicious flag boosts vuln score by 30%
- Test Depscore: edge cases (null packageScore, missing isDirect, etc.)

### 3D: Policy Evaluation in Extraction Pipeline

Add after dependency upsert and vuln scan in [pipeline.ts](backend/extraction-worker/src/pipeline.ts):

1. Load project's tier info, fetch `package_policy_code` from `organization_package_policies` (or project override)
2. Run `packagePolicy()` per dep with `{ dependency, tier }`, store `policy_result` on each `project_dependencies` row
3. Fetch `project_status_code` from `organization_status_codes` (or project override) and available statuses
4. Build full context: dependencies with policyResults, vulns, EPSS, CISA KEV, reachability, depscores, asset tier
5. Execute `projectStatus()` via the Phase 4 sandbox engine
6. Map returned status name to `organization_statuses.id`
7. Update `projects.status_id`, `projects.status_violations`, `projects.policy_evaluated_at`
8. Log result to `extraction_logs`: "Policy evaluated - status: Compliant" (or error details)

### 3C: Comprehensive Test Suite

#### Unit tests (mock all external tools and APIs)

`**backend/extraction-worker/src/__tests__/pipeline.test.ts`:**

- Test each pipeline step in isolation (mock cdxgen, dep-scan, semgrep, trufflehog, git, supabase)
- Test success path: each step completes and passes data to next step
- Test every failure mode listed in Phase 2E-pipeline:
  - Clone auth failures (401/403 from each provider)
  - Clone repo not found (404)
  - Clone branch not found
  - Clone timeout
  - cdxgen timeout
  - cdxgen empty SBOM
  - Supabase connection failure during dep sync (+ retry behavior)
  - dep-scan not installed / timeout / crash / no output
  - Semgrep OOM (exit code 137)
  - Semgrep not installed
  - TruffleHog not installed
  - Storage upload failure
- Test that critical step failures abort the pipeline and set job status to `failed`
- Test that optional step failures log warnings and pipeline continues
- Test that `extraction_logs` entries are written correctly for each step
- Test that `extraction_jobs` status transitions are correct: `queued` -> `processing` -> `completed`/`failed`

`**backend/extraction-worker/src/__tests__/sbom.test.ts`:**

- SBOM parsing fixtures for each ecosystem: npm, pip, maven, go, cargo, gem, composer, pub, hex, swift, nuget
- Test license extraction from various CycloneDX formats (string, array, object)
- Test direct vs transitive dependency classification
- Test dependency relationship edge extraction
- Test malformed SBOM handling (missing fields, invalid PURL)
- Test empty SBOM (0 components)

`**backend/extraction-worker/src/__tests__/clone.test.ts`:**

- Mock `simple-git` for each provider (GitHub, GitLab, Bitbucket)
- Test GitHub App token generation and clone URL construction
- Test GitLab OAuth token fetch from Supabase and clone URL construction
- Test Bitbucket token fetch and clone URL construction
- Test retry logic (3 attempts with backoff)
- Test temp directory creation and cleanup on success and failure
- Test custom GitLab URL (self-hosted)

`**backend/extraction-worker/src/__tests__/logger.test.ts`:**

- Test that each log method (info, success, warn, error) writes correct row to extraction_logs
- Test that logging failures don't crash the pipeline (fire-and-forget)
- Test correct human-readable messages for each pipeline step
- Test duration tracking
- Test metadata JSON structure

`**ee/backend/lib/__tests__/fly-machines.test.ts`:**

- Mock Fly.io Machines API responses
- Test happy path: find stopped machine, start it
- Test all machines busy: verify burst machine creation
- Test Fly API unreachable: verify retry logic (3x with backoff)
- Test Fly API rate limited (429): verify retry-after handling
- Test machine start failure: verify fallback to different machine
- Test FLY_API_TOKEN expired (401): verify error logging
- Test max burst limit enforcement

`**ee/backend/lib/__tests__/job-recovery.test.ts`:**

- Test stuck job detection: jobs in `processing` for >15 minutes get requeued
- Test max attempts enforcement: jobs exceeding max_attempts set to `failed`
- Test that `completed` and `cancelled` jobs are not touched
- Test concurrent recovery (two recovery runs don't double-requeue)

#### Integration tests (real tools, CI only)

`**backend/extraction-worker/src/__tests__/integration.test.ts`:**

- Uses a tiny test repository (committed as a fixture or hosted on GitHub)
- Runs the full pipeline end-to-end with real cdxgen (skip dep-scan/semgrep/trufflehog in CI for speed)
- Verifies database state after extraction: dependencies exist, versions exist, edges exist, logs exist
- Verifies SBOM was uploaded to storage
- Verifies project status is `ready`

#### Resilience / chaos tests (optional, for later)

- Simulate machine crash mid-pipeline: kill process, verify job is requeued by recovery cron
- Simulate Supabase outage during dep sync: verify retry and eventual failure with clear error
- Simulate dep-scan timeout: verify pipeline continues, vulns marked as "not scanned"
- Simulate all Fly machines busy + burst limit reached: verify job stays queued, no data loss
