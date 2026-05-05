# Plan Review — iac-container-v2-phase1

**Verdict: REWORK**

Plan reviewed: `.cursor/plans/iac-container-v2-phase1.plan.md`
Generated: 2026-05-02
Personas: **13** — skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, data-model-auditor, migration-safety-auditor, multi-tenant-design-auditor, rbac-design-auditor, worker-pipeline-auditor, failure-mode-hunter, competitor-reality-checker
Vote tally: **0 READY / 3 REVISE / 10 REWORK**
Findings: **17 P0 (post-scoring) / ~26 P1 / ~30 P2 / ~20 P3**
Debate: ~140 agreements, ~30 dissents, ~70 new R2 findings prompted by others

## Summary

The Phase 1 plan bundles three architecturally-distinct workstreams (IaC format expansion, registry credential plumbing, global digest cache) into one PR. Round 1 surfaced 131 findings; Round 2 escalated the most consequential ~17 to P0 with multi-persona consensus. The single most-cited concern is **cross-tenant credential leakage** via `project_configured_images.credentials_id` — the FK references `project_registry_credentials(id)` without enforcing same-project, allowing a worker to decrypt and use Org A's ECR/GCP/Azure root keys when scanning Org B's project. Compounding: a hard CI blocker (`project_container_findings.image_source` CHECK still hardcoded to `'dockerfile_base'`, so M8 cannot land green), a cache that hits 0% in production due to crane/Trivy digest format mismatch, a globally-readable cross-org pull-string leak (`image_reference_last_seen`), and seven new sub-step failure surfaces in M8 with no isolation envelope, no kill switches, no defined sub-step taxonomy, and a still-unresolved encryption-helper sharing mechanism (OQ-A).

10 of 13 personas voted REWORK — including all four data/tenancy auditors (data-model, migration-safety, multi-tenant, rbac), both pipeline auditors (worker-pipeline, failure-mode), the architect, the test-strategy-auditor, the scope-cutter, and the competitor-reality-checker. The 3 REVISE votes (skeptic, pragmatist, opportunity-scout) all explicitly scoped their REVISE to "needs structural cuts AND P0 fixes," which is REWORK by the skill's verdict rule (≥2 REWORK votes triggers REWORK).

The plan's *direction* is correct (extending IaC formats + per-project encrypted creds + configured-images table is the right shape, the brief's competitive framing holds, the milestone breakdown is conceptually sound). But multiple foundational decisions are unresolved, several invariants are wrong, and 5-6 unresolved scope debates would change the plan's structure regardless. Patch-during-review is insufficient — recommend re-running `/plan-feature` after applying the suggested patches below.

## Vote Tally

| Persona | Vote | Top concern | Rationale (excerpt) |
|---|---|---|---|
| skeptic | REVISE | architect-f4 | Direction correct; 17 multi-persona P0s — especially crane/Trivy digest mismatch making cache 0%-hit AND poisonable, cross-tenant cred FK gap, hardcoded image_source CHECK blocking M8 — must be patched. Flip to READY when those are resolved. |
| pragmatist | REVISE | pragmatist-r2-f7 | Plan bundles 3 distinct threads; ~half of P0s trace to cache+crane alone. Cutting cache+crane dissolves ~20 findings without hurting Phase 1 user value. Real surviving P0s are addressable in one revision pass. |
| scope-cutter | REWORK | scope-cutter-f5 + f9 + pragmatist-r2-f7 | Plan is unchanged from R1; bundling itself is the bug. Restructure as Phase 1a (formats) + Phase 1b (registries) + Phase 1.5 (cache when Phase 2 needs it). REVISE-by-patch is insufficient — the bundling needs structural rewrite. |
| architect | REWORK | architect-r2-f12 | Multiple foundational decisions unresolved: OQ-A still open at M5 + tsconfig won't compile relative imports; M8 sub-step taxonomy undefined so kill switches/observability/retry-classification fall out piecemeal; image_source CHECK blocks M8; cred FK doesn't enforce same project; ghcr namespace check on App-fallback unspecified. Pre-implementation architectural questions, not patch-ups. |
| test-strategy-auditor | REWORK | cross-tenant + cache-integrity test gap | Plan's testing section is silent on the eight test surfaces required to catch consensus P0 bugs (cross-org route tests, encryption round-trip, cred redaction, cache integrity, M8 sub-step matrix, populated-rollback, rollout sequencing, crane SIGKILL/checksum). Tests cannot be specified against a moving target — settle Debate A and M8 sub-step taxonomy first. |
| opportunity-scout | REVISE | DMA-1 / MTD-3 | Bones, scope, and Phase 2 compounding value are sound. Keep cache+crane (Debate A). 17 P0s are real tenancy/supply-chain bugs that MUST be patched; cheap opportunity adds (cache_hits counter, Test endpoint, audit log, kill switch) should land in revision. |
| data-model-auditor | REWORK | DMA-1 / MTD-3 | Migration text unchanged from R1, still ships 4 P0 data-model defects: cross-tenant FK gap, image_source CHECK still narrow blocking M8, image_reference_last_seen cross-org leak, trigger column-list bypass. Plus 6 P1 SQL gaps. Migration block at lines 79-215 needs structural edits before implementation. |
| migration-safety-auditor | REWORK | MSA-2 | ~16 confirmed cross-persona P0s untouched between rounds. Migration-specific: rollback re-adds narrow framework CHECK and is unrunnable on any DB where v2 has emitted helm/cfn finding; missing BEGIN/COMMIT atomicity; no rollout sequence; reaper claimed but unbuilt; rotation script doesn't enumerate PRC. Schema thread alone needs material restructuring. |
| multi-tenant-design-auditor | REWORK | MTD-1 | None of the consensus P0 multi-tenant findings addressed: image_reference_last_seen still globally readable, credentials_id FK still permits cross-tenant cred attachment, trigger column-list bypass, DOCKER_CONFIG dir lifecycle unspecified, M8 service-role reads without explicit .eq('project_id'), cache writes have no all-targets-completed guard. Shipping as-written would leak credentials, image identities, and findings across orgs. |
| rbac-design-auditor | REWORK | DMA-1 / MTD-3 | Plan still has unresolved P0 RBAC defects: cross-tenant cred FK (DMA-1/MTD-3), worker-side missing-project-filter (WPA-r2-1), and BYOK-vs-project-role gating mismatch (rbac-1) is structural perm-design call not typo. Cannot be patched during /implement — requires migration trigger redesign + permission gate swap + Tenancy Invariants section. |
| worker-pipeline-auditor | REWORK | WPA-r2-1 | M8 step 1 still reads PRC + PCI without explicit .eq('project_id') — worker-side cross-org cred leak. Compounded by 6 unresolved P0 pipeline bugs: digest probe before auth mint, no wall-clock cap, crane vs Trivy digest mismatch, classifyError gaps, undefined sub-step taxonomy, eager cred decrypt blast radius. M8 needs control-flow redesign — auth-before-probe, per-image isolation envelope, sub-step taxonomy section, wall-clock cap, normalization spec, project-scoped reads — not edits in place. |
| failure-mode-hunter | REWORK | FMH-r2-1 | Plan unchanged between rounds. Still contains 14+ P0 failure modes including M8's 7 sub-steps with no per-image isolation envelope (single throw takes down all subsequent images + v1 IaC path), unverified crane install as supply-chain compromise vector, missing kill switches for new subsystems. Failure-isolation architecture needs to be rewritten as first-class plan section, not amended. |
| competitor-reality-checker | REWORK | skeptic-f1 | 17 P0 findings unaddressed in plan including hard CI blocker (image_source CHECK). Layer on cross-tenant cred FK, image_reference_last_seen leak, broken digest normalization, no per-image envelope, no kill switches, no crane checksum, six unresolved scope debates. CR-1/CR-2/CR-3/CR-4 (DOCKER_AUTH_CONFIG stale, SAM/CDK detection, Aikido retest-after-apply, missing GitLab CR + Nexus) still unaddressed. |

## P0 — Fundamental Concerns

### 1. Cross-tenant credentials_id FK leak `[CONSENSUS 9/13]`
- **Plan section:** `Data Model > project_configured_images` (lines 144-156); `API Design > POST /configured-images`
- **Claim:** `project_configured_images.credentials_id UUID REFERENCES project_registry_credentials(id) ON DELETE SET NULL` is a pure existence FK — it does NOT verify the cred's `project_id` matches the configured-image's `project_id` (or even the same `organization_id`). A POST that attaches Org A's ECR keys to Org B's project succeeds at the DB layer; the worker then decrypts and uses Org A's creds when scanning for Org B. Trigger `enforce_project_scoped_org_id` only validates org_id of the row itself, not the FK target.
- **Evidence:** Plan line 149; M11 acceptance criteria don't mention same-project validation; service-role admin scripts and future internal RPCs would bypass any route validator.
- **Suggested patch:**
  - **DB layer:** Promote `project_registry_credentials` to `UNIQUE (id, project_id)` and replace the FK on `project_configured_images.credentials_id` with `FOREIGN KEY (credentials_id, project_id) REFERENCES project_registry_credentials(id, project_id) ON DELETE SET NULL`. This is enforced by Postgres regardless of code path.
  - **Application layer:** In M11 POST/PATCH route, validate `cred.project_id === image.project_id` and return 400 (clean UX before hitting the DB).
  - **Trigger layer:** On UPDATE of `project_id`, NULL out `credentials_id` (defense against cross-project move).
- **Flagged by:** DMA-1 (data-model), MTD-3 (multi-tenant)
- **Agreed with by:** skeptic, scope-cutter, architect, test-strategy, rbac, worker-pipeline, failure-mode, opportunity-scout, data-model

### 2. project_container_findings.image_source CHECK blocks M8 from landing `[CONSENSUS 6/13]`
- **Plan section:** `Data Model > phase27 migration body` (lines 79-215, omitted)
- **Claim:** Phase 25's `project_container_findings.image_source` is `CHECK (image_source IN ('dockerfile_base'))` — single value. M8 emits findings for configured-image scans which need `image_source='configured_image'` to satisfy the row contract, but the migration never widens the constraint. Every configured-image insert from the orchestrator violates 23514. The bug is silent until M8 runs against any configured-image fixture; CI fails, success criterion #4 (configured-image scan) is unreachable.
- **Evidence:** `backend/database/phase25_iac_container_scanning.sql` line 78. Plan's migration body adds new tables + widens framework CHECK + adds compliance_refs but never touches the image_source CHECK. M8 storage emit is unspecified for image_source value.
- **Suggested patch:**
  - Add to phase27 migration (inside MSA-1's BEGIN/COMMIT wrapper):
    ```sql
    ALTER TABLE project_container_findings DROP CONSTRAINT IF EXISTS project_container_findings_image_source_check;
    ALTER TABLE project_container_findings ADD CONSTRAINT project_container_findings_image_source_check
      CHECK (image_source IN ('dockerfile_base', 'configured_image'));
    ```
  - Mirror in rollback with same DELETE-rows-or-NOT-VALID handling MSA-2 mandates.
  - Update M8 storage emit + `storage.ts upsertContainerFindings` to set `image_source='configured_image'` for non-Dockerfile-derived scans.
  - Add to M1 acceptance: insert with `image_source='configured_image'` succeeds post-migration.
- **Flagged by:** skeptic-f1, DMA-r2-1, MSA-r2-1, MTD-r2-2 (4 personas, 4 lenses)

### 3. Crane / Trivy digest format mismatch `[CONSENSUS 5/13]`
- **Plan section:** `Data Model > container_image_scan_cache` (PK `image_digest TEXT`); `M6 Trivy image runner extension`; `M7 Scan-cache storage layer`
- **Claim:** Cache key is unnormalized `TEXT`. `crane digest` returns bare `sha256:abc...`. `parseTrivyImageOutput.imageDigest` sources from `Metadata.RepoDigests[0]` which is `repo/path@sha256:abc...`. Without normalization, lookups miss every time, cache hit rate is ~0%, M7 + M8 + M9 + the entire cache infrastructure becomes dead code with a maintenance bill. **Compounded:** plan trusts crane's pre-pull digest as authoritative, but a registry compromise or manifest-list image can return one digest at HEAD then serve different bytes at GET — opening cross-org cache poisoning. Cache identity must be the digest of bytes Trivy actually scanned (post-pull RepoDigests), not crane's pre-pull probe.
- **Evidence:** `backend/depscanner/src/scanners/trivy.ts:331` parseTrivyImageOutput sources from RepoDigests; plan's M6 step 3 says "Add helper resolveImageDigest using crane digest" without normalizing; plan's M7 lookup SQL is keyed solely on `image_digest`.
- **Suggested patch:**
  - Spell out the digest-normalization contract in M6: cache key = bare 64-hex (no `sha256:` prefix, no `repo@` prefix). Add `normalizeDigest(s: string): string` helper applied at every reader and writer.
  - Add CHECK to migration: `CHECK (image_digest ~ '^[a-f0-9]{64}(\+linux/(amd64|arm64))?$')` (with platform suffix for manifest lists).
  - **Cache key = digest TRIVY produced, never crane's.** Crane is purely a pre-pull probe; on disagreement, log structured warning and use Trivy's digest. Skip cache write if digests disagree (ambiguous identity).
  - Pin Trivy `--platform linux/amd64` to make manifest-list resolution deterministic.
  - Add unit test asserting `crane digest <ref>` and `parseTrivyImageOutput.imageDigest` for the same ref normalize to the same string.
- **Flagged by:** architect-f4, DMA-2, MTD-4, WPA-6 (4 personas)
- **Agreed with by:** failure-mode (FMH-r2-3 cache integrity hash extends this)

### 4. image_reference_last_seen — cross-org pull-string leak `[CONSENSUS 3/13]`
- **Plan section:** `Data Model > container_image_scan_cache` (line 176)
- **Claim:** `image_reference_last_seen TEXT NOT NULL` is populated with the literal pull string Org A used. Cache table is global (cross-org by design). When Org A scans `private-corp.example.com/internal-checkout-svc:v1.0`, that string is readable from any future code path that joins the cache or any future SQL injection / service-role compromise. Competitive-intel exfiltration vector. The column has zero functional role — cache lookup is by digest only.
- **Evidence:** Plan line 176 declares it `NOT NULL`; rationale comment claims "content-addressed safe" but that applies only to scan_results, not the user-controlled string.
- **Suggested patch:**
  - **Drop the column entirely.** Image reference is recoverable per-org from `extraction_logs WHERE organization_id = ?` joined by digest at debug time. No need to denormalize across orgs.
  - For forensics replacement, add `first_scanned_by_org_id UUID REFERENCES organizations(id) ON DELETE SET NULL` (NOT exposed via API; debug-only).
- **Flagged by:** MTD-1 (multi-tenant), DMA (data-model amplifies via DMA-9), failure-mode (FMH agrees)

### 5. Trigger column-list bypass `[CONSENSUS 2/13]`
- **Plan section:** `Data Model > triggers` (lines 137-139, 162-164)
- **Claim:** `BEFORE INSERT OR UPDATE OF project_id, organization_id` only fires when those columns appear in the SET clause. Any UPDATE not touching project_id/organization_id silently bypasses re-derivation. If a row was somehow inserted with mismatched org_id (manual surgery, future internal RPC, migration error), no future UPDATE will heal it. Phase 25's `enforce_finding_org_id` has the same shape.
- **Suggested patch:**
  - Change to `BEFORE INSERT OR UPDATE` (no column list) so org_id re-derives on every UPDATE. Cost: one extra SELECT per UPDATE on long-lived config tables (PRC + PCI) — modest given write volume.
  - Apply same fix to phase25's `enforce_finding_org_id` — **or** scope this to phase27's new triggers only (migration-safety-auditor partial-dissents on retroactive phase25 application; defer that to a separate migration).
- **Flagged by:** MTD-2, data-model-auditor (DMA-8 covers cross-project move case)

### 6. Missing kill switches for new subsystems `[CONSENSUS 4/13]`
- **Plan section:** `M8 — orchestrator extension`; `resolveKillSwitches` in v1 orchestrator
- **Claim:** v1 has two Redis kill switches (`kill:scanner:trivy`, `kill:scanner:checkov`). Phase 1 introduces three new failure surfaces — AWS STS, Azure oauth2/exchange, crane subprocess, plus per-cred decryption — but reuses the v1 switches. If STS gets throttled across the fleet OR crane segfaults on a malformed image OR a crypto regression breaks decrypt, the only escape is killing all of trivy globally — which kills v1 ghcr.io scanning that's been clean for 30 days.
- **Suggested patch:**
  - Add four new Redis kill switches to `resolveKillSwitches` in M8:
    - `kill:scanner:configured_images` — skips configured-image list, dockerfile path unchanged
    - `kill:scanner:registry_auth` — forces public/anon path, private images skip with `auth_disabled`
    - `kill:scanner:digest_cache` — bypass crane+cache, fall through to Trivy
    - `kill:scanner:cred_decrypt` — short-circuit decryptCredential, treat all creds as absent (preserves Dockerfile + ghcr-via-App paths)
  - Use Redis MGET (single round-trip) per WPA-r2-9 to keep step-entry latency bounded.
  - Test: each switch independently; pairwise interaction matrix.
- **Flagged by:** architect-f6, FMH-P0-1, opportunity-scout-f10 (subsumed)
- **Agreed with by:** multi-tenant (digest_cache is tenancy-critical; its blast radius is global)

### 7. Cache absorbs partial Trivy output → 7-day cross-org silent FN window `[CONSENSUS 5/13]`
- **Plan section:** `M7 Scan-cache storage layer`; `M8 step 4c (cache upsert)`
- **Claim:** Plan: "mint auth → run Trivy → upsert cache → emit findings." If Trivy exits non-zero with parseable-but-truncated SARIF (network mid-pull, OOM, registry timeout) AND the orchestrator treats partial parse as "N findings", cache absorbs the incomplete result. 7-day TTL = stale FN propagates. Cross-org cache means Org A's bad scan poisons Org B's view of the same digest for a week. **Single bad scan = week-long FN window across the entire customer base.**
- **Suggested patch:**
  - Specify cache-write contract in M7: `upsertContainerScanCache` is called ONLY when (a) Trivy exit code = 0, (b) `summary.warnings` empty for this image, (c) parser produced structurally-valid result, (d) Trivy's normalized digest matches crane's probe digest (when probe ran).
  - Test: parameterized over Trivy failure modes (exit=1+valid JSON, exit=0+truncated, timeout, kill-switch mid-scan, manifest-not-found, auth-401-mid-pull) — assert cache write spy NEVER called.
- **Flagged by:** FMH-P0-2, architect, data-model, multi-tenant, worker-pipeline (5 personas)

### 8. Eager step-start credential decryption blast radius `[CONSENSUS 4/13]`
- **Plan section:** `M8 step 1 (read all PRC at step start)`
- **Claim:** Plan reads ALL creds at step start, decrypts each. If `AI_ENCRYPTION_KEY` is rotated and a single cred's auth-tag fails, the loop throws — and unless wrapped per-cred, the whole IaC+container step dies, including v1 IaC paths (TF/K8s/Dockerfile) that don't depend on creds at all. One bad cred kills coverage for everything else.
- **Suggested patch:**
  - M8 step 1: decrypt creds **lazily per-image**, not eagerly at step start.
  - Per-cred decrypt failure: structured warning (`cred_decrypt_failed`) + add affected images to `skippedImages` + continue with remaining work.
  - Combines with FMH-r2-1 (per-image isolation envelope): wrap `scanOneImage(image, ctx)` in try/catch covering all 7 sub-steps, never rethrows to outer loop.
- **Flagged by:** FMH-P0-3, architect, multi-tenant, worker-pipeline (4 personas)

### 9. No total wall-clock cap on per-image loop `[CONSENSUS 2/13]`
- **Plan section:** `M8 orchestrator iteration`; pipeline integration
- **Claim:** v1 has per-image timeout (8min) but no aggregate cap on the loop. With 30 enabled configured images all missing cache, total = 30 × 8min = 240min, far past Fly machine slot (10min) and stuck-detection window (5min). Job re-claimed, double-scanned, marked stuck, churns until max_attempts=3.
- **Suggested patch:**
  - Per-project cap on enabled `project_configured_images` rows. Recommend **20** (worker-pipeline) over 50 (failure-mode original). Conservative pre-launch.
  - `CONTAINER_SCAN_TOTAL_BUDGET_MS` env (default 25min) breaks loop early; remaining images marked `skipped: budget_exhausted`.
  - Fly machine timeout ≥ budget.
- **Flagged by:** WPA-1, architect, failure-mode (escalated)

### 10. Service-role reads without `.eq('project_id')` → cross-org cred leak `[CONSENSUS 1/13, NEW R2]`
- **Plan section:** `M8 step 1`; `M8 step 2`
- **Claim:** Depscanner uses service-role Supabase key (no RLS). Plan M8 step 1 says "Read project_registry_credentials for the project once at step start" but doesn't specify the `.eq('project_id', projectId)` filter. A literal implementation `supabase.from('project_registry_credentials').select('*')` returns ALL creds across ALL orgs into worker memory. Same for `project_configured_images` at step 2.
- **Suggested patch:**
  - M8 acceptance criterion (mandatory): orchestrator MUST `.eq('project_id', projectId)` on both reads.
  - Unit test asserting cred-list query carries the project_id filter (spy supabase mock, assert `.eq()` called).
  - Companion test asserting orchestrator never holds plaintext for cred IDs not in the resolved scan-plan.
  - Add to plan a "Tenancy Invariants" section listing service-role .eq() rules as load-bearing.
- **Flagged by:** WPA-r2-1 (worker-pipeline, top concern of vote)
- **Agreed with by:** multi-tenant (sister to MTD-5/6), rbac

### 11. M8 sub-step taxonomy undefined `[CONSENSUS 1/13, NEW R2]`
- **Plan section:** `M8 — orchestrator extension`
- **Claim:** v1 emits one step label `container_scan` for orchestration. Phase 1 forks it into 5+ logically distinct sub-steps (decrypt creds, build auth envelope, digest probe, cache lookup, mint auth, Trivy pull, cache upsert). Round 1 + 2 found ~12 distinct new failure modes inside this single step. Without sub-step taxonomy decided **upfront**, kill switches, retry classification, structured logging, and stuck-detection are all piecemeal.
- **Suggested patch:**
  - Add an M8.0 milestone (before any M8 implementation): define sub-step taxonomy as `container_scan.<phase>` where phase ∈ {decrypt_creds, build_auth_envelope, digest_probe, cache_lookup, mint_auth, trivy_pull, cache_upsert}.
  - Each sub-step gets: own try/catch with per-sub-step warning; own kill-switch consultation (where relevant); own classifyError contribution; logger.warn first arg = sub-step name.
  - Failure must be identifiable from `extraction_step_errors` alone, no log-grep.
- **Flagged by:** architect-r2-f12 (architect, top concern of vote)
- **Agreed with by:** worker-pipeline (WPA-8 escalated to P1), test-strategy (M8 truth-table tests)

### 12. M8 has no per-image isolation envelope `[CONSENSUS 1/13, NEW R2]`
- **Plan section:** `M8 — orchestrator extension`
- **Claim:** With 7 sub-steps per image, ANY one of them (cred-read, cred-decrypt, auth-mint, digest-probe, cache-lookup, scan, cache-upsert) can throw. Without a per-image try/catch envelope wrapping all 7, an exception bubbles to the step level and aborts the entire container_scan step — including subsequent images and v1 IaC paths.
- **Suggested patch:**
  - Wrap per-image scan flow in a dedicated `scanOneImage(image, context): Promise<{findings|skipped}>` function.
  - try/catch covers ALL seven sub-steps. Each catch path emits typed skip-reason and structured warning, NEVER rethrows.
  - Outer loop only sees image-level results.
  - Test: inject throw into each of 7 sub-steps; assert (a) image skipped with right reason, (b) other images in same project still scan.
- **Flagged by:** FMH-r2-1 (failure-mode, top concern of vote)

### 13. Crane install supply-chain risk `[CONSENSUS 1/13, NEW R2]`
- **Plan section:** `M9 — Dockerfile update`
- **Claim:** Plan installs crane via curl from github.com/google/go-containerregistry/releases. No checksum verification, no GPG signature, no SLSA provenance check. Crane runs IN the worker that holds decrypted AWS root keys + GCP SA + Azure SP. Compromised crane = full credential exfiltration across every customer. Existing depscanner Dockerfile pins TruffleHog with `sha256sum -c` per house style.
- **Suggested patch:**
  - Pin crane release to specific tag (v0.20.2 already in plan, good) AND verify SHA256 checksum against checked-in expected hash.
  - Verify cosign signature (go-containerregistry releases ARE cosign-signed): `RUN cosign verify-blob --certificate-identity ... crane.tar.gz`.
  - Document expected hash in Dockerfile comment.
  - CI fails if Dockerfile updates the version without updating the hash.
  - Multi-arch: use `$(uname -m)` selector or `ARG TARGETARCH` for amd64/arm64.
- **Flagged by:** FMH-r2-2 (failure-mode), WPA-9, WPA-r2-10 (worker-pipeline merged)

### 14. OQ-A unresolved at M2; depscanner tsconfig won't compile relative imports `[CONSENSUS 1/13, NEW R2]`
- **Plan section:** `Open Questions OQ-A`; `M5 Registry auth resolver`
- **Claim:** Plan defers OQ-A to M5 with "Lean (a) duplicate the AES helper". But:
  - depscanner has its own tsconfig with `rootDir './src'` and no path alias to backend/src — relative imports (`../../../backend/src/lib/ai/encryption.ts`) won't compile.
  - decryptApiKey carries non-trivial key-rotation semantics (current+previous key fallback). Duplicating means worker silently produces wrong decryptions on rotation if both copies aren't updated.
  - Smoke test in both locations doesn't catch divergent rotation behavior — both can pass with key version 1.
  - rotateEncryptionKeys utility must enumerate `project_registry_credentials` too, otherwise the script's first run on a tenant with rotated AI keys silently fails to re-encrypt PRC rows.
- **Suggested patch:**
  - Resolve OQ-A in M2 (before M5 starts), pick option (b): **build-time copy at docker:prepare** the same way `database/schema.sql` is staged.
  - Add `scripts/sync-encryption.ts` that copies `backend/src/lib/ai/encryption.ts` → `backend/depscanner/src/lib/encryption.ts` at docker:prepare.
  - Add CI workflow `encryption-sync-check.yml` mirroring `schema-check.yml`: fails PRs touching the source without resyncing.
  - Add round-trip unit test in BOTH packages running against same checked-in fixture from `organization_ai_providers`. CI breaks if either copy diverges.
  - Extend `rotateEncryptionKeys` to walk `project_registry_credentials`. Test with populated PRC table.
- **Flagged by:** architect-r2-f11, skeptic-f5, multi-tenant-r2 (3 personas)
- **Agreed with by:** rbac, migration-safety, worker-pipeline (5 personas total)

### 15. Per-scan DOCKER_CONFIG dir lifecycle unspecified `[CONSENSUS 1/13, NEW R2]`
- **Plan section:** `M5 / M8 auth envelope`; `Decision 6 (DOCKER_AUTH_CONFIG)`
- **Claim:** If plan adopts CR-1's recommendation (per-scan ephemeral `DOCKER_CONFIG` directory replacing `DOCKER_AUTH_CONFIG` env), the plan still has no spec for HOW the directory is created, who owns it, how cleanup works on abnormal exit. Two concurrent scans in same worker collide; SIGKILL leaves cred residue on disk.
- **Suggested patch:**
  - Each scan gets `DOCKER_CONFIG = $(mktemp -d -t deptex-scan-XXXXXX)`. `chmod 0700`, owned by depscanner UID.
  - Process tree spawned with that env explicitly (no inheritance from worker process env).
  - On scan completion (success/failure/timeout), shred-then-rmtree in try/finally.
  - Combines with FMH-P0-3 (lazy decrypt): decrypt-write-config-scan-rmtree per image.
  - Or alternative: build ONE envelope per step entry containing all needed registry hosts, reuse across all crane + Trivy calls (WPA-3); rmtree on step exit.
- **Flagged by:** MTD-r2-1 (multi-tenant), CR-1 (competitor-reality), worker-pipeline (WPA-r2-3 + WPA-r2-7)

### 16. Plan bundles three independent threads `[CONSENSUS 2/13]`
- **Plan section:** Overall structure; `Implementation Tasks M1-M20`
- **Claim:** Plan combines IaC format expansion + registry credentials + global digest cache + configured images + compliance refs into a single ~3-4 week PR. Round 1 finding-density per thread is the strongest possible signal that the plan is over-bundled:
  - Cache thread alone: 14 R1 findings (skeptic-f3/f7/f9, architect-f3/f4, DMA-2/3/9, MSA-5/7, MTD-1/4/8, FMH-P0-2/P1-7/P1-10/P1-11/P1-15, WPA-6, opportunity-scout-f1, scope-cutter-f5/f10, plus pragmatist-f2)
  - Registry-cred thread: 10+ findings (DMA-1/4/6/7, MSA-9, MTD-3/5/6, rbac-1, FMH-P0-3/P1-5/P1-12, WPA-3/7)
  - IaC-format thread: 5+ findings (skeptic-f4/f6/f11, scope-cutter-f1, pragmatist-f4)
- **Suggested patch (one of):**
  - **Option A (scope-cutter-f5 / pragmatist-f2):** Drop `container_image_scan_cache` table, M7, M9 crane install, and cache parts of M6+M8 from Phase 1. Always run Trivy. Re-introduce cache + crane in Phase 2 alongside reachability where the join actually consumes them. Saves 3-4 days; dissolves ~20 findings.
  - **Option B (worker-pipeline mid-position):** Ship the cache TABLE + migration with no readers/writers (~15 LOC of SQL); drop M7 storage code, M9 crane install, M8 cache lookup/upsert. Trivy runs every time. Phase 2 wires in readers when reachability needs them. Avoids migration churn while accepting the complexity-reduction.
  - **Option C (scope-cutter-f9 / pragmatist-r2-f7):** Phase 1a (formats only — M2/M3/M4/M12-M16) ships first in ~1.5 weeks; Phase 1b (registries + configured images, no cache) follows; Phase 1.5 (cache) when Phase 2 needs it.
  - **THIS IS DEBATE A — see Open Debates below.**
- **Flagged by:** scope-cutter (originator), pragmatist (escalated to P0)

### 17. classifyError doesn't know about new failure modes `[CONSENSUS 1/13, NEW R2]`
- **Plan section:** `M8 orchestrator extension`; existing `with-timeout.ts` classifyError
- **Claim:** Phase 1 introduces ~6 new soft-fail paths (cred decrypt fail, ECR throttle, Azure oauth 401, manifest-not-found, crane HEAD timeout, Trivy partial output). Existing classifyError only knows v1 classifications. Unclassified soft-fails bubble to scan_jobs error → recovery cron retries up to max_attempts=3. Three retries × 8min × 30 images = pipeline burns budget retrying permanent decrypt failures.
- **Suggested patch:**
  - M8 acceptance: extend classifyError with new tags:
    - `auth_throttled` (RETRYABLE, exponential, max 3)
    - `auth_config_invalid` (PERMANENT, skip)
    - `registry_unavailable` (RETRYABLE, 1 retry)
    - `image_unavailable` (PERMANENT, skip)
    - `partial_trivy_output` (PERMANENT, no cache write)
    - `cred_decrypt_panic` (PERMANENT TERMINAL — don't retry SCAN_JOB)
    - `cred_auth_mint_panic` (PERMANENT TERMINAL)
    - `cache_integrity_failure` (RETRYABLE as cache miss + warning)
    - `helm_no_default_values` (PERMANENT, skip chart)
  - Document table in M8 mapping (failure → retryable | retry_count | cache_write_allowed | skipped_image_reason).
  - Test: parameterized over each error class, assert recovery-cron behavior matches policy.
- **Flagged by:** WPA-r2-2, FMH-P1-14 (escalated)

## P1 — High-Priority Gaps

(Condensed; full content in suggested patches section.)

### Tenancy & Security

- **rbac-1** — Cred mutations gated by `checkProjectManagePermission` (team-role); BYOK precedent uses org-level `manage_integrations`. Equal blast-radius creds (AWS root, GCP SA, Azure SP) under weaker gate. **Patch:** swap to `checkOrgManageIntegrations` for cred CRUD; configured-images stay project-scoped.
- **MTD-9 / rbac-r2-3** — PATCH allow-list missing — `.update(req.body)` patterns enable field smuggling. **Patch:** `pickAllowed(body, ['display_name'])` helper at route entry, throws 400 on extra keys.
- **MTD-r2-4** — ECR Redis cache key keyed by `<account_id>:<region>` is cross-org sharable for multi-org AWS accounts. **Patch:** key on `<credId>:<account_id>:<region>` so STS audit trail is attributable.
- **DMA-r2-4 / DMA-6** — No composite CHECK on (registry_type, credential_shape) pair. **Patch:** add `CHECK ((registry_type, credential_shape) IN (...))` enumerating valid pairs.

### Migration safety

- **MSA-1** — Migration not wrapped in BEGIN/COMMIT. **Patch:** wrap entire phase27 body.
- **MSA-2** — Rollback re-adds narrow framework CHECK; fails on populated v2 rows. **Patch:** wrap rollback in BEGIN/COMMIT; DELETE-or-NOT-VALID for populated tables; mirror for image_source CHECK; FK-aware drop order with CASCADE.
- **MSA-3** — Worker rollout sequencing not specified. **Patch:** add §Rollout Sequence: (1) MCP migration, (2) backend deploy, (3) depscanner deploy, (4) frontend deploy. Each reversible.
- **MSA-7 / FMH-P1-15** — 30-day reaper claimed in comment but never implemented. **Patch:** ship `cleanup_container_image_scan_cache()` SQL function + Supabase pg_cron / QStash schedule in same PR.
- **MSA-9 / WPA-r2-7** — `rotateEncryptionKeys` doesn't enumerate PRC table. **Patch:** extend rotation utility; integration test with populated PRC.

### Data Model

- **DMA-r2-2 / architect-f3** — Cache lacks `scanner` discriminator (PSC precedent has it). **Patch:** add `scanner TEXT NOT NULL CHECK (scanner IN ('trivy'))` + `PRIMARY KEY (image_digest, scanner)`.
- **DMA-r2-3 / FMH-P1-7** — `scan_results` JSONB has no row-size cap. **Patch:** STORAGE EXTENDED + CHECK `octet_length <= 1048576` + parser truncates to top-N findings sorted by severity desc.
- **MTD-r2-5** — Composite cache key (image_digest_normalized, scanner_version, trivy_db_version_day). **Patch:** include trivy_db_version_day in PK to address skeptic-f7 CVE-freshness.
- **DMA-r2-5 / MTD-8** — No `first_scanned_by_org_id` for forensics. **Patch:** add column + comment documenting forensics-only role.
- **DMA-7 / DMA-r2-7** — No `last_used_at` on PRC. **Patch:** worker updates once per pipeline run after successful auth.

### Worker Pipeline

- **WPA-r2-3** — Auth-after-probe ordering wrong; private images can't probe without auth. **Patch:** M8 reorder — (a) build auth, (b) crane digest WITH auth env, (c) cache lookup, (d) on miss → Trivy with same auth, (e) upsert from Trivy's RepoDigests.
- **WPA-r2-4 / WPA-1 / FMH-P1-8** — Per-project image cap. **Patch:** lock at 20 (not 50) at POST; CONTAINER_SCAN_TOTAL_BUDGET_MS at 25min.
- **WPA-r2-6 / WPA-8** — Sub-step taxonomy promoted from P2 to P1. **Patch:** sub-step labels in extraction_step_errors + logger; failure isolatable from logs alone.
- **CR-1** — DOCKER_AUTH_CONFIG no longer canonical Trivy auth. **Patch:** per-scan ephemeral DOCKER_CONFIG dir filtered to needed registries; cleanup in try/finally.
- **architect-f7 / MTD-7 / WPA-5 / FMH-P1-12** — ghcr namespace check on App-token fallback unspecified. **Patch:** state as hard invariant in M8: explicit cred bypasses namespace check; App fallback PRESERVES it. 4-state matrix unit-tested.
- **FMH-r2-3** — No cache integrity hash. **Patch:** `scan_results_hash TEXT NOT NULL` = sha256 of canonicalized JSON; lookupContainerScanCache verifies on read; mismatch → log warning + treat as miss.
- **FMH-r2-4** — Crane subprocess: no SIGKILL backstop, no maxBuffer. **Patch:** execFile with explicit timeout + killSignal: SIGKILL + maxBuffer: 65536.
- **FMH-r2-5** — STS thundering herd. **Patch:** Redis SETNX singleflight lock; loser polls cache for 8s.
- **FMH-r2-7** — Cred decrypt panic should be terminal. **Patch:** classifyError tag `cred_decrypt_panic` as PERMANENT TERMINAL (don't retry SCAN_JOB).

### Test strategy

- **TSA-r2-3 / architect-f4** — Digest normalization round-trip. **Patch:** unit test feeds 4 input shapes (bare hex, sha256:hex, repo@sha256:hex, registry/repo@sha256:hex) and asserts identical canonical key.
- **TSA-r2-4 / DMA-1 / MTD-3** — Same-project FK enforcement test. **Patch:** 3 separate tests in M11 acceptance covering POST cross-project / PATCH cross-project / direct service-role bypass.
- **test-strategy-auditor-f1 / WPA-r2-7** — Encryption round-trip tests. **Patch:** check in fixture file ciphertext.json with known plaintext; both packages decrypt to same value.
- **test-strategy-auditor-f3** — Credential redaction in API responses. **Patch:** parameterized test over forbiddenKeys array; recursive deep absence check.
- **test-strategy-auditor-f4** — Cross-org tenant isolation tests. **Patch:** 404-not-403 for cross-org GET/DELETE; URL-with-mismatched-org test.
- **test-strategy-auditor-f12 / WPA-5** — Ghcr precedence 5-case matrix.

### Other

- **CR-2** — SAM scanned via Transform header (not 'compiled CFN'); CDK requires `cdk synth` not in plan. **Patch:** soften UI copy; drop CDK from Phase 1 OR add cdk synth M-task.
- **CR-3** — Aikido has retest-after-apply in 2026; brief framing stale. **Patch:** reframe Phase 4 wedge as "verify pre-PR" specifically.
- **architect-r2-f17** — Framework enum drift across 4-7 places. **Patch:** export `IAC_FRAMEWORKS as const` from one location; readers import.
- **architect-r2-f16 / DMA-4** — Cred-rotation UX undefined. **Patch:** ship rotate-in-place via `PATCH /:credId/rotate` endpoint; ON DELETE RESTRICT for credentials_id FK forces explicit disable before delete.
- **opportunity-scout-r2 promoted to P1 (rbac-r2-4)** — Audit-log emission for cred CRUD + per-scan decrypt.
- **MTD-r2-6** — Decrypt budget per orchestrator-run (cap at 200 decrypts) protects neighbour tenants on same Fly machine.

## P2 — Quality Gaps (condensed)

- skeptic-f3: crane perf unmeasured spike.
- skeptic-f4 / scope-cutter-f6 / pragmatist-r2-f8: compliance_refs from undocumented `metadata.benchmark` — parser-fragile, untested foundation.
- skeptic-f6 / scope-cutter-f2 / CR-2: SAM/CDK silently swapped for GH Actions/Kustomize without explicit brief amendment.
- skeptic-f7 / FMH-r2-8: Trivy DB freshness within 7-day TTL — cache hit could miss new CVEs.
- skeptic-f8 / opportunity-scout-f2 / pragmatist-r2-f11: No "Test cred" endpoint — silent failure mode for misconfigured creds.
- skeptic-f9 / WPA-4: R1's "12h in-memory ECR cache" incoherent on Fly scale-to-zero.
- skeptic-f11: CFN detector 4kb head-cap will FN on real-world templates with extensive Mappings/Parameters blocks.
- DMA-r2-6: enforce_finding_org_id reuse vs new function duplication.
- MSA-r2-2 to MSA-r2-8: migration determinism, FK ordering, MCP transaction semantics, schema:dump rebase trap, key rotation timing.
- MTD-r2-7: cred-display join could surface another project's display_name on cross-project move.
- MTD-r2-8: GH Actions detector globs `**/.github/workflows/` — should restrict to repo root only.
- MTD-r2-9: cred display_name phishing surface (mitigated if rbac-1 adopted).
- rbac-3: cred metadata visibility to broad checkProjectAccess.
- rbac-4: explicit doc that decryption has no HTTP surface.
- rbac-r2-7: ESLint/grep guard preventing route files from importing decryptApiKey.
- WPA-7: Quay/Harbor/JFrog non-standard auth flows.
- WPA-r2-8: crane install layer caching.
- WPA-r2-9: Redis MGET batching for kill switches.
- FMH-P1-4: Supabase 503 during cred read.
- FMH-r2-6: configured-image enable-toggle race.
- FMH-r2-9: Helm chart with required (no-default) values renders to placeholder strings.
- FMH-r2-10: success-side observability (auth_minted ratio, registry-type latency p95).
- CR-r2-1: aws_oidc_role schema slot for future (OIDC role assume vs long-lived AWS keys).
- CR-r2-2: Pulumi missing from format set.
- CR-r2-3: registry creds should be ORG-scoped (escalation of rbac-2).
- CR-r2-4: HOSTNAME_TO_REGISTRY_TYPE central registry table.
- CR-r2-5: Success Criterion #2 (test all 8 registries live) takes ~1 day of cred procurement.
- TSA-r2-1: kill switch matrix (8-row truth table).
- TSA-r2-9: Frontend credential field redaction test.
- TSA-r2-10: Detector ambiguity fixtures.

## P3 — Nits & Opportunities

- skeptic-f10: framework-icon component name verification.
- skeptic-f12: Phase 6.5 Dockerfile rebase concern.
- pragmatist-f3 (revised): UI section consolidation.
- scope-cutter-f4 (Debate B disputed): cred shape collapse.
- scope-cutter-f7: PATCH endpoint surface reduction.
- scope-cutter-r2-f6: framework-icon set shrinks if Kustomize/SAM/CDK dropped.
- DMA-9: cache ops indexes (defer).
- architect-f5: Dockerfile crane install style/comment.
- architect-r2-f18: crane install multi-arch + checksum (subsumes WPA-9).
- architect-r2-f19: API design RBAC table per-route.
- opportunity-scout-f1, f3, f5, f6, f7, f8: cache hit-rate counter, last-scanned status, SBOM persistence, image attribution, infra_types persistence, examples fixture.
- opportunity-scout-f9 (escalated to P1 in rbac-r2-4): audit log.
- opportunity-scout-f10 (subsumed by FMH-P0-1): cache kill switch.
- competitor-reality-checker CR-5 (Endor numbers stale), CR-6 (GH Actions Trivy doc), CR-7 (public.ecr.aws auth opt-in), CR-8 (GCR/AR aliases).

## Open Debates (Disputed Findings)

These have unresolved cross-persona disagreement; **the rework pass needs to lock these decisions explicitly** before re-planning M2/M5/M6/M7/M8.

### Debate A: Drop cache + crane from Phase 1 `[DISPUTED 4 for / 5 against]`
- **In favor (REWORK driver):** scope-cutter, pragmatist (escalated to P0), failure-mode (partial — keep behind kill switch).
- **Against:** opportunity-scout (only Phase 1 work that compounds into Phase 2; cheap incremental hardening dominates), test-strategy (cache is testable in isolation; cutting removes 4-5 specified test cases), multi-tenant (deferring loses tenancy hardening), data-model (table shape is fine; just fix it), worker-pipeline (compromise: ship table without readers/writers).
- **Plan section:** `Data Model > container_image_scan_cache`; M7; M9 crane install; M8 cache lookup
- **Mid-positions exist:** WPA's "ship table+migration but no readers/writers" + architect's "keep cache, drop crane probe + cross-org global claim" both viable.
- **Your call:** Cut entirely (~3-4 days saved, ~20 findings dissolve, Phase 2 owns the cache contract) vs ship table-only (no migration churn) vs ship with all P0 hardening (cache integrity + digest normalization + scanner discriminator + first_scanned_by + reaper + drop image_reference_last_seen).

### Debate B: Collapse 5 cred shapes to 3 `[DISPUTED 2 for / 4 against]`
- **In favor:** scope-cutter, pragmatist (refined: keep aws_keys, collapse GCP+Azure into 'token' shape with worker-side parsing).
- **Against:** worker-pipeline (cloud-native auth REQUIRES STS/oauth2/exchange; can't paste basic auth at ECR), multi-tenant (shape-as-discriminator weakens tenancy), failure-mode (collapse hides shape errors at INSERT; surfaces at scan-time), competitor-reality (cred-shape proliferation matches actual auth protocols).
- **Your call:** Keep 5 shapes (matches real auth protocols, early validation feedback) vs collapse (simpler form variants, less test-matrix surface).

### Debate C: Drop Quay/Harbor/JFrog from registry list `[DISPUTED 3 for / 1 against]`
- **In favor:** scope-cutter, pragmatist, architect partial (no test creds available).
- **Against:** competitor-reality CR-4 (wants to ADD gitlab_cr + nexus instead — Snyk ships them).
- **Mid-position:** keep schema slots for all (so future addition is non-migration), ship live testing only with cloud big-4 + custom + ghcr.
- **Your call:** Drop long-tail registries from Phase 1 entirely OR keep schema slots and ship with subset of live test creds.

### Debate D: Phase 1a / 1b split `[DISPUTED 2 for / 2 against]`
- **In favor:** scope-cutter (promoted from P1 fallback to P1 default), pragmatist.
- **Against:** worker-pipeline (forces ScannersPanel to ship without "add registry credential", users pulling private images during 1a window have no path forward), migration-safety (fragments schema migration).
- **Mid-position (worker-pipeline):** Phase 1 = formats + registry creds + configured images (NO CACHE); Phase 1.5 = cache when Phase 2 needs it. This reconciles Debate A's compromise too.
- **Your call:** Split into 1a/1b OR keep single PR with cache cut OR keep single PR with cache hardened.

### Debate E: Defer compliance_refs to Phase 3 `[DISPUTED 3 for / 2 against]`
- **In favor:** scope-cutter, pragmatist, skeptic (parser-fragility on undocumented Checkov metadata; no observed user demand).
- **Against:** opportunity-scout (cheapest enterprise pitch differentiator; keep badges, defer filter chip), competitor-reality (top-3 enterprise checkbox).
- **Plan section:** `Data Model > project_iac_findings.compliance_refs JSONB`; M4 step 3-4; M16 badge strip
- **Your call:** Cut column + parser + UI badges (defer to Phase 3 with proper compliance pipeline) OR keep store-into-existing-metadata + defer dedicated UI to Phase 3 OR keep full Phase 1 plan + invest in Checkov fixture spike first.

### Debate F: Drop Kustomize `[DISPUTED 2 for / 1 partial]`
- **In favor:** scope-cutter, pragmatist (not in brief Decision 4's locked list; not in Snyk/Aikido headlines).
- **Against:** architect partial (treat kustomization.yaml as kubernetes-framework files; coverage for free without separate detector + chip + label switch + icon).
- **Your call:** Drop Kustomize entirely OR fold into kubernetes detector.

## Suggested Plan Amendments

The patches below are concrete edits to apply during the rework pass. Each cites the originating finding(s) and the consensus tag.

### Patch 1 — Cross-tenant credentials_id FK (DMA-1 / MTD-3) [CONSENSUS 9/13]

**Plan section:** `Data Model > project_configured_images`

```sql
-- Add to phase27 migration after PRC creation:
ALTER TABLE project_registry_credentials
  ADD CONSTRAINT prc_id_project_uq UNIQUE (id, project_id);

-- Replace the credentials_id single-column FK with composite:
-- (in CREATE TABLE project_configured_images, change line 149 to:)
  credentials_id UUID,
  ...
  FOREIGN KEY (credentials_id, project_id)
    REFERENCES project_registry_credentials(id, project_id)
    ON DELETE SET NULL,

-- Add cross-project move guard trigger:
CREATE OR REPLACE FUNCTION pci_null_credentials_id_on_project_move() RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.project_id != OLD.project_id THEN
    NEW.credentials_id := NULL;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS pci_null_creds_on_project_move ON project_configured_images;
CREATE TRIGGER pci_null_creds_on_project_move
  BEFORE UPDATE OF project_id ON project_configured_images
  FOR EACH ROW EXECUTE FUNCTION pci_null_credentials_id_on_project_move();
```

Application layer (M11 POST/PATCH): validate `cred.project_id === image.project_id` server-side, return 400.

### Patch 2 — image_source CHECK widening (skeptic-f1 / DMA-r2-1 / MSA-r2-1) [CONSENSUS 6/13]

**Plan section:** `Data Model > phase27 migration body`

```sql
-- Add inside the same BEGIN/COMMIT as the framework CHECK widening:
ALTER TABLE project_container_findings DROP CONSTRAINT IF EXISTS project_container_findings_image_source_check;
ALTER TABLE project_container_findings ADD CONSTRAINT project_container_findings_image_source_check
  CHECK (image_source IN ('dockerfile_base', 'configured_image'));

-- Mirror in rollback:
DELETE FROM project_container_findings WHERE image_source = 'configured_image';
ALTER TABLE project_container_findings DROP CONSTRAINT IF EXISTS project_container_findings_image_source_check;
ALTER TABLE project_container_findings ADD CONSTRAINT project_container_findings_image_source_check
  CHECK (image_source IN ('dockerfile_base'));
```

M8 storage emit: `image_source='configured_image'` for non-Dockerfile-derived scans. M1 acceptance: post-migration insert with `image_source='configured_image'` succeeds.

### Patch 3 — Digest normalization (architect-f4 / DMA-2 / MTD-4 / WPA-6) [CONSENSUS 5/13]

**Plan section:** `M6 Trivy image runner extension`; `Data Model > container_image_scan_cache`

Add to M6 (before steps 1-3):
```typescript
// New helper: M6 step 0
export function normalizeDigest(s: string): string {
  // Accepts: bare hex, sha256:<hex>, <repo>@sha256:<hex>, <registry>/<repo>@sha256:<hex>
  // Returns: bare 64-hex (no prefix)
  const m = s.match(/(?:^|@sha256:|^sha256:)([a-f0-9]{64})$/);
  if (!m) throw new Error(`invalid digest: ${s}`);
  return m[1];
}
```

Migration:
```sql
-- Replace plain TEXT image_digest PK with normalized form:
image_digest TEXT NOT NULL CHECK (image_digest ~ '^[a-f0-9]{64}(\+linux/(amd64|arm64))?$'),
```

M7/M8: cache key = normalizeDigest(parseTrivyImageOutput.imageDigest), NEVER crane's pre-pull digest. Crane is purely a probe; on disagreement, log warning + use Trivy's digest. Skip cache write when probe and scan disagree.

Pin Trivy `--platform linux/amd64` in M6.

Test: `expect(normalizeDigest('sha256:'+hex)).toBe(normalizeDigest('repo/path@sha256:'+hex)).toBe(normalizeDigest(hex))`.

### Patch 4 — Drop image_reference_last_seen + add forensics columns (MTD-1 / DMA-r2-5 / MTD-8) [CONSENSUS 3/13]

**Plan section:** `Data Model > container_image_scan_cache`

Replace:
```sql
image_reference_last_seen TEXT NOT NULL,
```
With:
```sql
-- Forensics-only columns. NEVER exposed via API. Used only for incident response.
-- ON DELETE SET NULL because org deletion shouldn't cascade-delete shared cache rows.
first_scanned_by_org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
first_scanned_run_id TEXT,
```

Worker writes these once at INSERT (not in UPSERT SET clause). API never returns them. SQL header comment: "Attribution columns for incident response. NEVER read by user-facing paths."

Recovery of pull-string for debugging happens via `extraction_logs WHERE organization_id = ?` joined by digest.

### Patch 5 — Trigger column-list scope (MTD-2) [CONSENSUS 2/13]

**Plan section:** `Data Model > triggers`

Change:
```sql
CREATE TRIGGER project_registry_credentials_enforce_org_id
  BEFORE INSERT OR UPDATE OF project_id, organization_id ON project_registry_credentials
  ...
```
To:
```sql
CREATE TRIGGER project_registry_credentials_enforce_org_id
  BEFORE INSERT OR UPDATE ON project_registry_credentials
  ...
```

(Same change for project_configured_images trigger.)

Migration-safety partial-dissents on retroactively applying same fix to phase25's `enforce_finding_org_id` — defer that to a separate migration.

### Patch 6 — Kill switches for new subsystems (FMH-P0-1 / architect-f6) [CONSENSUS 4/13]

**Plan section:** `M8 — orchestrator extension`; `resolveKillSwitches`

Extend KillSwitchContext + Redis lookups in M8:
```typescript
interface KillSwitchContext {
  iacEnabled: boolean;
  containerEnabled: boolean;
  trivyKilled: boolean;
  checkovKilled: boolean;
  // NEW Phase 1 surgical levers:
  configuredImagesKilled: boolean;     // skips configured-image list, dockerfile path unchanged
  registryAuthKilled: boolean;         // forces public/anon path
  digestCacheKilled: boolean;          // bypass crane+cache, fall through to Trivy
  credDecryptKilled: boolean;          // short-circuit decrypt; treat all creds as absent
  redisFallback: boolean;
}
```

Use Redis MGET (per WPA-r2-9) to fetch all switches in one round-trip.

M8 acceptance: 8-row truth table parameterized over (configured_images, registry_auth, digest_cache, cred_decrypt) with assertions on which scan paths run, DB writes, skip-reasons.

### Patch 7 — Cache write contract (FMH-P0-2) [CONSENSUS 5/13]

**Plan section:** `M7 Scan-cache storage layer`; `M8 step 4c`

Specify in M7:
```typescript
// upsertContainerScanCache MUST only be called when ALL of:
//   1. Trivy exit code === 0
//   2. summary.warnings empty for this image
//   3. parser produced structurally-valid result (no truncation marker)
//   4. crane probe digest (when probe ran) matches parseTrivyImageOutput's normalized digest
async function upsertContainerScanCache(...): Promise<void> {
  // Implementation — caller is responsible for the four guards.
}
```

M8 acceptance test (parameterized over Trivy failure modes): assert upsert spy NEVER called on:
- Trivy exit=1
- exit=0 + truncated JSON
- exit=0 + parser threw
- timeout
- kill-switch mid-scan
- manifest-not-found
- auth-401-mid-pull
- crane-probe / Trivy-digest disagreement

### Patch 8 — Lazy per-image decryption (FMH-P0-3) [CONSENSUS 4/13]

**Plan section:** `M8 step 1`

Replace M8 step 1 ("Read PRC for project once at step start") with:
1. Read PRC list (metadata only — no decryption) with explicit `.eq('project_id', projectId)`.
2. Read configured_images list with explicit `.eq('project_id', projectId).eq('enabled', true)`.

Defer decryption to per-image scope inside `scanOneImage`. On per-cred decrypt failure: structured warning `cred_decrypt_failed` + add image to `skippedImages` + continue.

Combine with Patch 12 (per-image isolation envelope).

### Patch 9 — Total wall-clock cap + per-project image cap (WPA-1 / FMH-P1-8 / WPA-r2-4) [CONSENSUS 2/13]

**Plan section:** `M8 / M11`

M11 acceptance: enforce `project_configured_images` count <= 20 per project at POST. Return 400 with explicit "Project limit of 20 configured images reached. Disable or delete entries before adding more." (Lower than FMH-P1-8's 50; matches Fly machine slot math.)

M8: add `CONTAINER_SCAN_TOTAL_BUDGET_MS` env (default 25min). Loop breaks early when exceeded; remaining images marked `skipped: budget_exhausted`.

Test: 21st POST returns 400; mocked extraction with 20 images each 90s asserts step finalizes inside budget.

### Patch 10 — Service-role reads with .eq() (WPA-r2-1) [CONSENSUS 1/13, NEW]

**Plan section:** `M8 step 1+2`

Add to M8 acceptance criteria as a load-bearing invariant:
- Every `supabase.from('project_registry_credentials').select(...)` and `supabase.from('project_configured_images').select(...)` MUST chain `.eq('project_id', projectId)`.

Add to plan a new "Tenancy Invariants" section listing this rule with cross-references.

Unit test: spy supabase mock; assert `.eq('project_id', ...)` was called on every cred-list / configured-image-list query.

### Patch 11 — M8 sub-step taxonomy decision (architect-r2-f12) [CONSENSUS 1/13, NEW]

**Plan section:** Insert as new M8.0 (before M8 implementation)

Define:
```
container_scan.<phase>  where phase ∈ {
  decrypt_creds,
  build_auth_envelope,
  digest_probe,
  cache_lookup,
  mint_auth,
  trivy_pull,
  cache_upsert
}
```

Each sub-step:
- Own try/catch with per-sub-step warning
- Own kill-switch consultation (where applicable)
- Own classifyError contribution
- Logger.warn first arg = sub-step name
- Failure isolatable from `extraction_step_errors` alone

Acceptance: induce each soft-fail; assert exactly one extraction_step_errors row with the right sub-step name.

### Patch 12 — Per-image isolation envelope (FMH-r2-1) [CONSENSUS 1/13, NEW]

**Plan section:** `M8 — orchestrator extension`

Wrap per-image flow in:
```typescript
async function scanOneImage(image, ctx): Promise<{findings: ContainerFinding[]} | {skipped: SkippedImage}> {
  try {
    // All 7 sub-steps (decrypt, build_auth, digest_probe, cache_lookup, mint_auth, trivy_pull, cache_upsert)
    // wrapped here. Each catch path emits typed skip-reason; NEVER rethrows.
  } catch (err) {
    // Structured warning + skip-reason routing per Patch 11 sub-step + classifyError tag.
    return { skipped: { ... } };
  }
}
```

Outer loop sees only `{findings | skipped}`; never throws.

Test: inject throw into each sub-step; assert (a) image skipped, (b) other images still scan.

### Patch 13 — Crane install supply-chain hardening (FMH-r2-2 / WPA-r2-10) [CONSENSUS 1/13, NEW]

**Plan section:** `M9 — Dockerfile update`

```dockerfile
# Crane (go-containerregistry) for HEAD-only manifest digest probe.
# Pinned tarball + checksum + cosign signature. Multi-arch: amd64 today, arm64 reserved.
ARG CRANE_VERSION=v0.20.2
ARG CRANE_SHA256=<actual-sha256>
RUN curl -sSfL https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_Linux_$(uname -m | sed 's/x86_64/x86_64/;s/aarch64/arm64/').tar.gz \
  -o /tmp/crane.tar.gz \
  && echo "${CRANE_SHA256}  /tmp/crane.tar.gz" | sha256sum -c - \
  && tar -xzf /tmp/crane.tar.gz -C /usr/local/bin crane \
  && rm /tmp/crane.tar.gz \
  && chmod +x /usr/local/bin/crane \
  && crane version
# Optional: cosign verify-blob if cosign is installed.
```

CI: fail Dockerfile updates that change CRANE_VERSION without updating CRANE_SHA256.

### Patch 14 — Resolve OQ-A in M2 (architect-r2-f11 / skeptic-f5 / WPA-r2-7) [CONSENSUS 5/13]

**Plan section:** `Open Questions OQ-A`; new M2.5

Resolve OQ-A inline: option (b) — build-time copy at `docker:prepare`, mirroring schema.sql staging pattern.

Add M2.5:
1. `scripts/sync-encryption.ts` copies `backend/src/lib/ai/encryption.ts` → `backend/depscanner/src/lib/encryption.ts` at docker:prepare.
2. New CI workflow `encryption-sync-check.yml` mirroring `schema-check.yml`: fails PRs touching the source without resyncing.
3. Round-trip unit test in BOTH packages running against checked-in fixture from `organization_ai_providers`.
4. Extend `rotateEncryptionKeys` to enumerate `project_registry_credentials`. Integration test with populated PRC.

Delete OQ-A from open questions.

### Patch 15 — DOCKER_CONFIG dir lifecycle (MTD-r2-1 / CR-1) [CONSENSUS 3/13]

**Plan section:** `M5 / M6 / M8 auth envelope`

Replace DOCKER_AUTH_CONFIG envelope approach with per-step ephemeral DOCKER_CONFIG directory:

```typescript
// M5: writeEphemeralDockerConfig(tempDir, [['hostname', credEntry], ...])
//     returns DOCKER_CONFIG path. chmod 0700, owned by depscanner UID.

// M8 step entry:
//   const dockerConfigDir = await mkdtemp(path.join(os.tmpdir(), 'deptex-scan-'));
//   try {
//     await writeEphemeralDockerConfig(dockerConfigDir, allCredsForProject);
//     // run scans with DOCKER_CONFIG=$dockerConfigDir set
//   } finally {
//     await fs.rm(dockerConfigDir, { recursive: true, force: true });
//   }
```

Build envelope ONCE per step entry from successfully-decrypted creds (per-cred decrypt failure → skip cred, log warning, continue per Patch 8).

### Patch 16 — Migration atomicity (MSA-1 / MSA-2) [CONSENSUS 3/13]

**Plan section:** `Data Model > phase27 migration / rollback`

Wrap entire phase27 migration body in `BEGIN; ... COMMIT;`.

Wrap rollback in `BEGIN; ... COMMIT;`.

Rollback handles populated tables:
- DELETE FROM project_iac_findings WHERE framework NOT IN ('terraform','kubernetes','dockerfile') BEFORE re-adding narrow CHECK
- DELETE FROM project_container_findings WHERE image_source = 'configured_image' BEFORE re-adding narrow image_source CHECK
- Drop tables in FK dependency order with CASCADE: container_image_scan_cache → project_configured_images → project_registry_credentials

Document: this migration is single-PR-atomic; do not split table creation from trigger creation across PRs.

### Patch 17 — Worker rollout sequencing (MSA-3) [CONSENSUS 3/13]

**Plan section:** New `Rollout Sequence` section

Add explicit ordering:
1. Apply phase27 migration via Supabase MCP.
2. Deploy backend with extended `scanner-findings.ts` framework filter whitelist (M12).
3. Deploy new depscanner image (M9 Dockerfile + M3-M8 worker code).
4. Deploy new frontend (M13-M18).

Each step reversible. Run `npm run schema:dump` + force-add diff to next commit after every rebase against main (per `feedback_schema_dump_rebase.md`).

### Patch 18 — RBAC org-level gate for cred mutations (rbac-1) [CONSENSUS 3/13]

**Plan section:** `API Design > Endpoints` table

Replace single "manage_projects" perm column with per-route table:

| Route | Method | Perm Required |
|---|---|---|
| `/registry-credentials` | GET | checkProjectAccess |
| `/registry-credentials` | POST | **checkOrgManageIntegrations** |
| `/registry-credentials/:credId` | PATCH | **checkOrgManageIntegrations** |
| `/registry-credentials/:credId` | DELETE | **checkOrgManageIntegrations** |
| `/registry-credentials/:credId/test` | POST | **checkOrgManageIntegrations** |
| `/registry-credentials/:credId/rotate` | PATCH | **checkOrgManageIntegrations** |
| `/configured-images` | GET | checkProjectAccess |
| `/configured-images` | POST | checkProjectManagePermission |
| `/configured-images/:id` | PATCH | checkProjectManagePermission |
| `/configured-images/:id` | DELETE | checkProjectManagePermission |
| `/iac-findings` | GET | checkProjectAccess (existing) |

New helper: `checkOrgManageIntegrations(userId, orgId)` mirrors existing `hasManageIntegrations()` from organizations.ts.

### Patch 19 — Test gaps consolidated (TSA findings) [CONSENSUS 4 personas]

**Plan section:** `Testing & Validation Strategy`

Add specific test specifications:
- **Encryption round-trip** (TSA-r2-11 / WPA-r2-7): checked-in `ciphertext.json` fixture; test in BOTH packages decrypts to known plaintext.
- **Cred redaction** (test-strategy-auditor-f3): `forbiddenKeys` array (`encrypted_credentials, password, access_key_id, secret_access_key, session_token, service_account_json, client_id, client_secret, tenant_id, token, username`); recursive deep-absence check on POST/LIST/PATCH responses.
- **Cross-org tenant isolation** (test-strategy-auditor-f4): 404-not-403 for cross-org GET/DELETE; URL-with-mismatched-org test.
- **Same-project FK enforcement** (TSA-r2-4): 3 separate tests in M11 acceptance (POST cross-project, PATCH cross-project, direct service-role bypass).
- **Digest normalization round-trip** (TSA-r2-3): 4 input shapes → identical canonical key.
- **Cache poisoning regression** (TSA-r2-2): parameterized over Trivy failure modes; spy upsert assert call_count = 0.
- **Kill switch matrix** (TSA-r2-1): 4-key truth table = 16 rows; assert scan paths + DB writes + skip-reasons.
- **PATCH allow-list** (TSA-r2-5): forbidden-field array iterated via parameterized test.
- **DOCKER_AUTH_CONFIG/DOCKER_CONFIG envelope composition** (TSA-r2-6): 3 mock creds (ECR + GCR + Docker Hub); spy crane and Trivy invocations; assert per-host correctness.
- **STS rate-limit / throttle** (TSA-r2-7): mock STS 429; assert 3-attempt exponential backoff + soft-fail with skipped-reason.
- **Per-project image cap** (TSA-r2-8): boundary tests at 19/20/21; enabled vs disabled count policy documented.
- **Detector ambiguity fixtures** (TSA-r2-10): JSON with both ARM and CFN markers; Helm chart with K8s YAML in templates/; kustomization.yaml inside helm chart; etc.
- **Migration on populated table** (TSA-r2-f8): 10000 rows; apply migration; assert all pass; insert helm succeeds; insert non-real-framework gets 23514.
- **Rollback on populated table** (TSA-r2-f9): containing v2 framework values; document chosen behavior (fail loudly OR DELETE first).
- **ghcr precedence 5-case matrix** (TSA-r2-f12 + WPA-5).
- **Frontend form-shape switch** (test-strategy-auditor-f10): registry_type ecr→gcr → assert AWS fields cleared, SA JSON appears.

## Findings by Axis (Cluster)

| Axis | Count | Highest sev | Top personas |
|---|---|---|---|
| cross-tenant cred / cache leak | 8 | P0 | data-model, multi-tenant, rbac, worker-pipeline |
| missing kill switch / soft-fail granularity | 6 | P0 | failure-mode, architect, multi-tenant, opportunity-scout |
| cache infrastructure (key normalization, poisoning, partial output, scanner discriminator, row size, reaper) | 16 | P0 | architect, data-model, failure-mode, multi-tenant, worker-pipeline |
| migration safety (atomicity, rollback, sequencing, rotation) | 9 | P1 | migration-safety, test-strategy |
| auth shape / DOCKER_AUTH_CONFIG / DOCKER_CONFIG | 5 | P1 | competitor-reality, multi-tenant, worker-pipeline |
| M8 architecture (sub-step taxonomy, isolation envelope, classifyError, total budget) | 8 | P0 | architect, failure-mode, worker-pipeline, test-strategy |
| encryption helper (OQ-A, rotation, sync) | 4 | P0 | architect, skeptic, multi-tenant, rbac |
| supply chain (crane checksum, cosign, multi-arch) | 3 | P0 | failure-mode, worker-pipeline |
| RBAC gate level | 3 | P1 | rbac, architect, multi-tenant |
| test specification (round-trip, redaction, cross-org, cache integrity) | 16 | P0 | test-strategy |
| scope (cache cut, registry cut, shape collapse, format cut, phase split, compliance defer) | 12 | P0 | scope-cutter, pragmatist, competitor-reality (against) |
| competitor-reality (DOCKER_AUTH_CONFIG, SAM/CDK, Aikido retest, missing registries) | 8 | P1 | competitor-reality |
| frontend (form-shape, rendering, redaction) | 4 | P1 | test-strategy, opportunity-scout |
| schema/data-model (CHECK constraints, composite, indexes, normalization) | 9 | P0 | data-model |
| opportunity (cache hits counter, Test endpoint, audit log, image attribution, examples fixture) | 8 | P3 | opportunity-scout |

## Persona Coverage Map

| Persona | R1 findings | R1 clean lenses | R2 +1s | R2 -1s | R2 new | Vote |
|---|---|---|---|---|---|---|
| skeptic | 12 (1 P0) | 6 | 22 | 7 | 9 | REVISE |
| pragmatist | 6 | 4 | 16 | 9 | 6 | REVISE |
| scope-cutter | 11 (1 P0) | 9 | 11 | 16 | 8 | REWORK |
| architect | 10 (1 P0) | 11 | 11 | 7 | 9 | REWORK |
| test-strategy-auditor | 16 (4 P0) | 6 | 14 | 4 | 16 | REWORK |
| opportunity-scout | 10 | 7 | 11 | 14 | 5 | REVISE |
| data-model-auditor | 9 (1 P0) | 7 | 6 | 2 | 6 | REWORK |
| migration-safety-auditor | 9 | 7 | 8 | 2 | 8 | REWORK |
| multi-tenant-design-auditor | 9 (4 P0) | 5 | 11 | 2 | 9 | REWORK |
| rbac-design-auditor | 6 | 6 | 14 | 2 | 9 | REWORK |
| worker-pipeline-auditor | 10 (1 P0) | 6 | 9 | 4 | 10 | REWORK |
| failure-mode-hunter | 15 (3 P0) | 7 | 12 | 3 | 10 | REWORK |
| competitor-reality-checker | 8 | 5 | 10 | 5 | 5 | REWORK |
| **Total** | **131 (15 P0)** | **86** | **155** | **77** | **110** | **0/3/10** |

## Recommended Next Step

**Verdict: REWORK** — return to `/plan-feature` with the suggested patches above as input.

Specifically:
1. **Lock the open scope debates first** (Debates A-F): pick a position, document rationale. Recommend Debate A's worker-pipeline mid-position ("ship cache table+migration, no readers/writers; Phase 1.5 wires readers when Phase 2 reachability needs them") + Debate D's WPA mid-position ("Phase 1 = formats + creds + configured images, no cache flow; Phase 1.5 = cache") because they reconcile the largest set of dissents at lowest cost.
2. **Apply Patches 1-19** to the plan file as concrete edits.
3. **Add new sections** to the plan: §Tenancy Invariants (per Patch 10), §Rollout Sequence (Patch 17), §M8 Sub-Step Taxonomy (Patch 11), §Cache Write Contract (Patch 7).
4. **Re-run `/review-plan iac-container-v2-phase1`** after edits — most of the P0 findings would be resolved or moot post-patches; verdict should flip to READY or REVISE.
5. After flip, run `/implement` against the patched plan.

Skipping the patch pass and running `/implement` against the current plan would land 17 known P0 bugs including cross-tenant credential leakage, a 0%-hit cache, a migration that can't roll back cleanly, and a worker-side step that crashes the entire IaC+container pipeline on any single bad credential. Don't.
