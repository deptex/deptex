# Plan Review — malicious-packages-v2

Verdict: **REVISE**
Plan reviewed: `.cursor/plans/malicious-packages-v2.plan.md`
Generated: 2026-05-02
Personas: 12 — skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, data-model-auditor, migration-safety-auditor, multi-tenant-design-auditor, worker-pipeline-auditor, ai-cost-auditor, competitor-reality-checker
Process: Round 1 (independent findings) only — Round 2 (debate) and Round 3 (vote) skipped due to token-budget threshold (~1M+ tokens estimated for full 3-round pass with 12 personas reading the full R1 transcript). The natural multi-persona consensus visible in R1 (4 personas independently flagged the callgraph issue; 3 personas flagged OSSF CHECK widening; 4 personas flagged the JSONB-vs-booleans tradeoff) provides sufficient signal to call the verdict.
Findings: **7 P0 critical / ~22 P1 high / ~25 P2 medium / ~15 P3 low**

## Summary

Plan is architecturally sound at the data-model and pipeline levels but has **seven concrete P0 issues** that will cause /implement to fail or silently misbehave. The most important: the plan's reachability filter depends on a callgraph that the cited storage (`taint_engine_runs`) doesn't actually persist, AND Phase 6's rollout-pct + circuit-breaker gates mean most production extractions won't have a callgraph available — flagged independently by **4 of 12 personas**. Other P0s: missing OSSF source CHECK widening (3-persona consensus), capability scan languages exceed CHECK ecosystem set, allowlist suppression after recompute leaves `is_malicious` denorm wrong, anonymous CHECK rename hazard, reachability soft-fail loses entire finding (not just nulls the column), and maintainer-signal cross-org fan-out has undefined `organization_id` derivation. **All seven have concrete suggested patches** — none require re-`/plan-feature`. Recommend applying the suggested patches and running one more focused pass before `/implement`.

## P0 — Fundamental Concerns

### P0-A: Reachability filter relies on a callgraph that isn't persistable and a Phase 6 engine that's rollout-gated off in production `[CONSENSUS 4/12]`

- **Plan section:** Codebase Analysis > Reusable code identified; Implementation Tasks > M1a.3; Risks > R7
- **Claim:** Plan says reachability resolver "reuses the callgraph that the existing taint_engine step already builds (read from `taint_engine_runs` storage or invoke `buildCallgraph` if not cached)." Verified against actual code:
  1. `taint_engine_runs` is telemetry only — columns are `callgraph_build_ms`, `flows_emitted`, etc. No callgraph artifact is stored.
  2. The callgraph holds `ts.Program` which is explicitly **non-serializable** (`callgraph.ts:75-76`).
  3. The taint_engine step is gated by `shouldRunTaintEngineForOrg` (`pipeline.ts:1869`) with `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT` defaulting to 0 in production — most production extractions never build the callgraph at all.
  4. The taint_engine block scopes `engineResult` inside an inner `try`, so the malicious-scan step at line 2163 has no reference to it even when it does run.
- **Evidence:** `backend/depscanner/src/taint-engine/storage.ts:200-228` (writeRun is telemetry-only); `backend/depscanner/src/taint-engine/callgraph.ts:73-82` (CallgraphContext is non-serializable); `backend/depscanner/src/pipeline.ts:1862` (rollout pct gate).
- **Suggested patch:** Pick ONE explicit strategy and document it in M1a.3:
  - **(A) Self-contained reachability pass** — Build a lightweight import-map + per-language callgraph inside `runMaliciousScan` itself, using the same tree-sitter primitives the taint engine uses but without the YAML framework specs / propagation. Limits v2 to `unimported / imported_unused / module / function` tiers; `data_flow` only when the rollout-gated taint engine ran. This is the **recommended** path because it's deterministic, doesn't depend on rollout state, and matches Decision 5's sync invariant.
  - **(B) Lift propagation.callgraph out of the taint_engine try-block** as a pipeline-scoped `callgraphForReachability` variable; pass into `runMaliciousScan`. Document explicitly: when null (rollout=0, circuit-breaker open, engine no-op'd), reachability_level=null on all findings.
  - **(C) Persist callgraph in a new `taint_engine_callgraphs` table** keyed by (project_id, run_id). Heavy and over-engineered for v2.
- **Consensus:** skeptic-f1, skeptic-f2 (Phase 6 shadow-mode angle), worker-pipeline P0-callgraph-not-persisted, architect ARCH-P0-001.

### P0-B: OSSF source CHECK widening missing from the migrations list `[CONSENSUS 3/12]`

- **Plan section:** Data Model > Migrations; Implementation Tasks > M2.1
- **Claim:** Plan adds `'ossf'` as a feed source but does NOT include the necessary CHECK relaxes in the four-migration list:
  1. `known_malicious_packages_source_chk` currently `CHECK (source IN ('osv','ghsa'))` — first OSSF row write throws.
  2. `mfsr_source_chk` on `malicious_feed_sync_runs.source` same constraint — first sync-run row throws.
  3. M2.1 buries the change in prose: "feed-sync run constraint relaxed via the `_reachability.sql` migration" — but the reachability migration only ALTERs `project_malicious_findings`.
- **Evidence:** `backend/database/malicious_packages_v1.sql:35-36` and `:150-151`; plan §Migrations only lists 4 files, none mentioning the source CHECKs.
- **Suggested patch:** Add a fifth migration file `malicious_packages_v2_ossf_source.sql`:
  ```sql
  ALTER TABLE public.known_malicious_packages
    DROP CONSTRAINT IF EXISTS known_malicious_packages_source_chk;
  ALTER TABLE public.known_malicious_packages
    ADD CONSTRAINT known_malicious_packages_source_chk CHECK (source IN ('osv','ghsa','ossf'));

  ALTER TABLE public.malicious_feed_sync_runs
    DROP CONSTRAINT IF EXISTS mfsr_source_chk;
  ALTER TABLE public.malicious_feed_sync_runs
    ADD CONSTRAINT mfsr_source_chk CHECK (source IN ('osv','ghsa','ossf'));
  ```
  Apply BEFORE the OSSF ingestor code ships. Update §Migrations section to list it explicitly.
- **Consensus:** data-model DM-P0-2, architect ARCH-P1-003 (graded P1, escalated to P0 by consensus), migration-safety P0-3.

### P0-C: `apply_malicious_allowlist` ecosystem canonicalization mismatch silently fails for Ruby/Pip/Go entries

- **Plan section:** Data Model > apply_malicious_allowlist RPC
- **Claim:** RPC joins on `oma.ecosystem = lower(d.ecosystem)`. The allowlist column has a CHECK locking to lowercase canonicals (`rubygems`, `pypi`, `golang`). But `dependencies.ecosystem` may store raw values like `'gem'`, `'pip'`, `'go'` from older SBOMs — `lower()` doesn't canonicalize. An admin allowlisting a Ruby package will see findings keep firing because the JOIN never matches.
- **Evidence:** v1's `recompute_dependency_is_malicious` uses the same `lower(d.ecosystem)` pattern; if `malicious_packages_ecosystem_canonicalize.sql` already canonicalized `dependencies.ecosystem`, this is fine — but plan must verify and document.
- **Suggested patch:** Either:
  - **(A)** Verify `malicious_packages_ecosystem_canonicalize.sql` already lowercases all `dependencies.ecosystem` rows + add a note to the RPC SQL explaining the mirror with v1's `recompute_dependency_is_malicious`.
  - **(B)** Use `public.canonicalize_malicious_ecosystem(d.ecosystem)` instead of `lower(d.ecosystem)` to be canonicalize-correct against any non-lowercase legacy values (`'gem'`, `'pip'`, `'go'`).
  - **Add a regression test fixture:** allowlist a `'gem'`-ecosystem dep + `'rubygems'`-ecosystem allowlist row; assert match.
- **Source:** data-model DM-P0-1 (high confidence).

### P0-D: Allowlist suppression happens after `recompute_dependency_is_malicious` — `is_malicious` denorm stays wrong

- **Plan section:** Data Model > apply_malicious_allowlist RPC; Implementation Tasks > M0.5
- **Claim:** Worker calls `insert_malicious_findings_with_recompute` (which runs `recompute_dependency_is_malicious` setting `is_malicious=true`), THEN `apply_malicious_allowlist` (which only flips PMF.suppressed=true). The denorm doesn't get re-recomputed. Result: allowlisted findings show suppressed but `dependencies.is_malicious=true` everywhere it's read (project dep cards, org graph multiplayer view, security tab counts).
- **Evidence:** `recompute_dependency_is_malicious` (v1.sql:158-183) checks `EXISTS (... WHERE suppressed=false AND risk_accepted=false)` — needs to re-run after suppress flips.
- **Suggested patch:** Add a second `recompute_dependency_is_malicious` call inside `apply_malicious_allowlist` after the UPDATE:
  ```sql
  -- After the UPDATE...FROM block:
  IF affected_dep_ids IS NOT NULL THEN
    PERFORM public.recompute_dependency_is_malicious(affected_dep_ids);
  END IF;
  ```
  Note: the recompute will keep `is_malicious=true` for deps still matched by `known_malicious_packages` (the second EXISTS clause). That's correct — feed-flagged packages stay flagged regardless of per-project allowlist.
- **Source:** architect ARCH-P1-006 (graded P1, escalated to P0 — affects every org's UI denorm).

### P0-E: Capability scan covers 8 languages but CHECK only allows 7 ecosystems

- **Plan section:** Data Model > package_capabilities CHECK; Implementation Tasks > M1b.3
- **Claim:** M1b.3 ships per-language detectors `{js, py, java, go, ruby, php, rust, csharp}` (8 languages). The `pc_ecosystem_chk` only allows `('npm','pypi','maven','golang','rubygems','github-actions','vscode')` (7 ecosystems). PHP=composer, Rust=cargo, C#=nuget — all rejected by CHECK.
- **Evidence:** Plan line 161 (CHECK) vs plan line 502 (M1b.3 file list); `backend/src/lib/malicious/ecosystem.ts:16-23` confirms the canonical type.
- **Suggested patch:** Pick one:
  - **(A) Scope-cut M1b.3 to 5 ecosystems** (`{js, py, java, go, ruby}`) — matches the existing canonical set exactly. Cleanest for v2.
  - **(B) Extend the canonical ecosystem set** to include `composer`, `cargo`, `nuget` everywhere (`backend/src/lib/malicious/ecosystem.ts`, `backend/depscanner/src/malicious/ecosystem.ts`, all CHECK constraints in v1 + v2 migrations, GuardDog dispatch in `guarddogCliVerb`). Bigger surface but ships full Phase-6-language parity.
- **Source:** architect ARCH-P0-002.

### P0-F: Reachability soft-fail in pipeline loses entire finding instead of nulling the column

- **Plan section:** Implementation Tasks > M1a.3 (Pipeline integration)
- **Claim:** `runMaliciousScan` per-package try wraps feed lookup + GuardDog and pushes to `pending` array on success (`malicious-scan.ts:111-206`). The catch at line 198 increments `failed++` and skips `pending.push` entirely. Plan inserts `computeReachability` between `pending.push` and `insertFindingsBatch`, but if reachability throws, the WHOLE package's findings get dropped — not just the reachability column nullified. Plan claims "soft-fail mirrors v1" but v1's invariant is per-package, not per-resolution-stage.
- **Evidence:** `backend/depscanner/src/malicious-scan.ts:111-206`.
- **Suggested patch:** Wrap each `computeReachability` call in its own nested try/catch that captures into `reachability_level: null, reachability_details: { error: 'compute_failed' }` and continues. Add an explicit acceptance criterion to M1a.3: "When `computeReachability` throws on a single finding, the remaining pending findings still insert correctly with `reachability_level=null`."
- **Source:** worker-pipeline P0-soft-fail-loses-finding.

### P0-G: Maintainer-signal cross-org fan-out has no documented per-row `organization_id` derivation

- **Plan section:** Implementation Tasks > M1c.2
- **Claim:** Plan says "writes findings to `project_malicious_findings` with `scanner='maintainer'` for any project containing that dep" but is silent on HOW the route maps a global maintainer signal (per dependency_id) to per-project per-org PMF rows. A naive impl that uses a single `organization_id` variable, or pulls it from the dependency, would fan out cross-tenant. The PMF `enforce_pmf_org_consistency` trigger catches the mismatch but causes hard-fails instead of correct fan-out.
- **Suggested patch:** Add to M1c.2 acceptance criteria: "Fan-out query MUST `JOIN project_dependencies → projects` to derive `organization_id` per row; never inserts a constant or caller-supplied `organization_id`. Test asserts that running maintainer-signal-sync against a dependency present in 2+ orgs writes findings under each project's correct `organization_id`, and the PMF trigger fires zero exceptions."
  Example query shape:
  ```sql
  INSERT INTO project_malicious_findings (project_id, organization_id, ...)
  SELECT pd.project_id, p.organization_id, ...
  FROM project_dependencies pd
  JOIN projects p ON p.id = pd.project_id
  WHERE pd.dependency_id = $signal_dep_id
  ```
- **Source:** multi-tenant MT-1.

## P1 — High-Priority Gaps

### Architecture / Pattern fit

- **`checkOrgMembership` doesn't exist as a helper anywhere in `backend/src/`** `[CONSENSUS 2/12]` — Plan API table cites it for capability + allowlist GET routes. Existing pattern is inline `organization_members` SELECT (see `project-access.ts:30-36`). Either create the helper in `backend/src/lib/project-access.ts` or write it inline. (skeptic-f3, multi-tenant MT-2)

- **`PendingFinding` type extension missing from plan** — Plan extends `insert-finding.ts` with `severityForMaintainerSignal` + `upsertCapabilityCache` but doesn't list extending the `PendingFinding` type with `reachability_level` / `reachability_details` / scanner-union widening to `'maintainer'`. Without this, TS compile fails or fields silently drop. Add explicit task between M1a.2 and M1a.3. (architect ARCH-P1-005)

- **Maintainer-signal cron `extraction_run_id` strategy unspecified** `[CONSENSUS 2/12]` — Cron has no extraction context. Without one, the natural key `(project_id, project_dependency_id, rule_id, scanner, extraction_run_id)` breaks idempotency or duplicates. Suggested: synthetic `'maintainer-cron:' + ISO_DATE_TRUNC_DAY` + relax conflict key for `scanner='maintainer'`. (worker-pipeline P2-cron-extraction-run-id-strategy, architect ARCH-P1-004)

- **Maintainer signals require historical-snapshot store the codebase doesn't have** — "email_changed_in_last_30d", "maintainer_changed_in_last_30d" need a baseline DB. M1c.1's "Complexity: L" undersells this — it's a new subsystem (table + cron + diff logic + retention). Either spin into its own data-model section with `package_maintainer_snapshots` table OR scope-cut to stateless signals only (`account_age_days`, `install_script_present`) for v2. (skeptic-f4)

- **Worker→backend dispatch shim bypassed by maintainer-signal cron** — v1's notification dispatch fires only when worker-side `result.inserted_findings > 0`. Daily cron at backend writes findings directly without the shim — new critical findings land silently for up to 10 minutes (until reconcile-stuck-notifications cron sweeps), or never. M1c.2 must explicitly write `notification_events` row + trigger dispatch. (worker-pipeline P2-dispatch-shim-for-maintainer-findings)

- **Capability scan misses cache-hit path** — When GuardDog cache hits, `cache.fetch()` is never called and there's no unpacked dir. Plan says capability scan "reuses GuardDog's unpacked tarball" but in steady-state (cache warm) there IS no unpack. Effective capability coverage drops to ~0% after the first sweep. **Fix:** Decouple unpack from GuardDog's cache decision: `const needsUnpack = !cachedGuarddog || !cachedCapabilities`; both consumers share the unpack. (worker-pipeline P1-capability-scan-misses-cache-hits)

- **`runMaliciousScan` signature missing `workspaceRoot` + callgraph context** — Reachability needs the user's source tree (not the tarball). Plan doesn't specify the new fields on `MaliciousScanContext`. (worker-pipeline P1-runMaliciousScan-needs-workspaceRoot)

### Data Model

- **`auth.users` FK without `ON DELETE` clause blocks user deletion** — `organization_malicious_allowlist.added_by uuid NOT NULL REFERENCES auth.users(id)` — if a user offboards, Supabase Auth deletion fails with FK violation. Make `added_by` nullable + `ON DELETE SET NULL`; add `added_by_email text` for frozen audit identity. (DM-P1-2)

- **`package_capabilities` natural key prevents per-scanner-version history** — UPSERT on scanner upgrade overwrites prior result, losing detection-rate-regression visibility. Either include `scanner_version` in UNIQUE (2x storage on upgrade) OR add a `package_capabilities_history` audit table. Decide explicitly. (DM-P1-3)

- **`idx_pc_high_signal` partial index covers only 3 of 15 capability columns** `[CONSENSUS 2/12]` — Plan claims it's for "future policy-composition queries" but native_addon_load (high signal), filesystem_write (mid), install_script (mid) aren't covered. Either expand or drop the index until a query needs it (YAGNI). (DM-P1-4, scope-cutter SC-7)

- **`idx_pmf_reachability` cold-start performance** — All v1 findings start with `reachability_level=null`. After v2 deploys, the bulk of in-flight findings have NULL reachability — the partial index is correctly hit but selectivity is poor. Plan's "<200ms p95" claim is plausible only AFTER reachability backfill completes — not specified. **Fix:** Either run a one-shot backfill on deploy, or accept the cold-start window and revise the NFR. (DM-P1-5)

- **15 boolean columns vs JSONB tradeoff** `[CONSENSUS 4/12]` — Plan locks 15 columns; adding tag #16 = ALTER TABLE. JSONB would let detector evolve without schema churn. Tradeoff: indexability for policy queries. Plan should make the decision explicit (boolean now + locked, vs JSONB now + GIN later). (pragmatist-f1, scope-cutter SC-1, skeptic-f12, DM-P2-3)

- **Allowlist `version_range` is exact-string-match but column name implies ranges** `[CONSENSUS 3/12]` — Admin types `>=2.0.0` expects range matching, gets nothing. M0.1 ships a vulnerableVersionRange parser already — wire it into `apply_malicious_allowlist` OR rename column to `version` (singular) and force exact match in UI. (pragmatist-f4, skeptic-f6, DM-P2-2)

### Migration Safety

- **Anonymous CHECK rename hazard on `project_malicious_findings_scanner_check`** — v1 declared inline anonymous CHECK; auto-generated name MAY match `project_malicious_findings_scanner_check` but is environment-dependent (PGLite vs Postgres can differ). `DROP CONSTRAINT IF EXISTS` could be a silent no-op, leaving the old CHECK in force. **Fix:** Query `pg_constraint` to find the actual name first; or use a DO block to find + drop dynamically; or write a verification query asserting only one CHECK on `scanner` post-migration. (migration-safety P0-1)

- **Hot rollout creates a partial-deploy window where worker writes scanner='maintainer' before CHECK relax applies** — Plan's "single PR, hot rollout" means migrations and worker code land together. If migrations apply BEFORE worker (the safe direction), fine. If worker deploys FIRST or concurrently, INSERTs hit `CHECK violation` and silently soft-fail per package. **Fix:** Add explicit §Rollout section: "Step 1: Apply all migrations via MCP. Step 2: Verify schema dump. Step 3: Merge PR (worker + backend deploy). Step 4: Verify pipeline run on test repo." (migration-safety P0-2)

- **No reversibility / down migrations specified** — Forward-only. Acceptable for solo-user pre-launch but should be called out explicitly so reviewers know rollback requires git revert + manual RPC restore. (migration-safety P1-1)

- **Allowlist `apply_malicious_allowlist` non-deterministic on multi-match** — When 2+ allowlist entries match same finding, Postgres UPDATE...FROM picks one arbitrarily; `suppressed_reason='allowlist:<id>'` cites a different entry on different runs. **Fix:** DISTINCT ON (pmf.id) the FROM clause with explicit ORDER BY, or restructure to per-finding subquery. (DM-P1-1)

### Cost / Performance

- **Reachability cost budget math wrong** `[CONSENSUS 2/12]` — Plan budgets 800ms p95 × ~10 findings = 8s, but the resolver runs per PACKAGE not per finding for the "unimported" early-exit. 1500 pkgs × 200ms = 5min — orders of magnitude over the ≤60s extraction-time-delta SLO. **Fix:** Either bound reachability to FINDINGS only (clarify scope; only resolve on packages that produced a finding), or raise budget to ≤180s extra and instrument the breakdown, or async path. (skeptic-f5, worker-pipeline P1-cost-budget-math-wrong)

- **AI Explain prompt-injection vector via registry metadata** — Maintainer-signal Explain prompt pulls `maintainer.name`, `maintainer.email`, `author` from registry — attacker-influenceable. v1's `<package>` untrusted-data delimiter wraps source code only; new branch must wrap registry metadata too. **Fix:** Plan must require the maintainer-signal Explain branch to route all registry-derived strings through the existing untrusted-data-delimiter pattern. Add a unit test with fixture maintainer name "IGNORE PREVIOUS INSTRUCTIONS". (ai-cost P1)

- **AI Explain cache key wrong for time-sensitive maintainer signals** — Cache keys on `(package, version, ecosystem, scanner='ai_review')`. Maintainer signals are time-sensitive (signals decay over 30 days) but the cache returns Day-1 narrative forever. **Fix:** For `scanner='maintainer'`, either add 7-day TTL OR include `prompt_input_sha256` in cache lookup (already computed, just not compared on read). (ai-cost P1)

- **GHSA point-budget math optimistic** — R6 says "350 points" but GraphQL points are query-complexity-based, not 1/page. Per-page cost is 5-15 points. **Fix:** Add backoff loop on 429 + measure points-consumed in M3.1; report in PR description. (skeptic-f13)

### Testing

- **Tenant-isolation tests missing on every new route** `[CONSENSUS 2-4/12]` — Plan says "covers permission gates" but doesn't enumerate cross-org 404 cases for: GET allowlist, POST allowlist, DELETE allowlist, GET capabilities, DELETE allowlist by entryId-belonging-to-other-org. Existing v1 tests (`malicious.test.ts:66-75`) provide the pattern — must be replicated. (TSA-1, TSA-2, TSA-4, MT-4)

- **INTERNAL_API_KEY enforcement test missing on `maintainer-signal-sync`** — v1's INTERNAL_API_KEY test only covers feed-sync. Plan says "happy path + INTERNAL_API_KEY check" for the new route but doesn't enumerate the 401-without-key + 401-wrong-key cases. (TSA-3)

- **`apply_malicious_allowlist` RPC tenant-scoping test missing at PGLite level** — Need DB-level test: seed two orgs with allowlist + finding for same package; call RPC with org A; assert ONLY org A finding flips. Cannot exercise via supabase mock. (TSA-4)

- **Idempotency test on maintainer-signal-sync re-runs missing** — Cron will re-run; second run must not duplicate findings. Plan doesn't specify. (TSA-7)

- **Capability cross-org cache reuse test missing** — Global cache invariant: org A scanning evil@1.0.0 writes a row that org B reuses (no re-scan). Must mock `detectCapabilities` and assert callCount===1. (TSA-11)

- **Test infra gotcha: `setTableResponse` doesn't scope by filter chain** — Cross-tenant tests rely on the org_members 404 gate, not on cleverly-scoped mock returns. Plan should add a one-line note. (TSA-19)

### Competitive Positioning

- **"Reachability granularity finer than competitors expose" claim is materially false** — Both Socket and Endor already expose `imported_unused`-equivalent (Socket: "dead", Endor: "Unreachable Dependency"). Deptex's tier is renaming, not novelty. **Fix:** Drop the differentiation paragraph; reframe as "unified vocabulary across feed/guarddog/maintainer findings + open-core". (competitor-reality P0-reachability-granularity-claim-false)

- **"Mirrors Endor's tiered model" misrepresents Endor's actual output** — Endor uses 3 labels per tier (`Reachable / Unreachable / Potentially Reachable`), NOT a 5-rung ladder. **Fix:** Drop "mirrors Endor"; consider adding a `potentially_reachable` enum value to capture the dynamic-dispatch / metaprogramming cases Phase 6 can't resolve. Both Socket and Endor have this as a first-class label. (competitor-reality P0-endor-mirror-claim-inaccurate, P1 missing-potentially-reachable)

- **Capability tag list mostly Deptex-original, not "matches Socket's branding"** — Overlap is ~6 of 15. Socket-canonical tags `obfuscated_code, suspicious_strings, minified_files, high_entropy_strings, telemetry` are absent. **Fix:** Reframe as "Socket-inspired but Deptex-curated"; explicitly decide whether the 5 missing Socket signals are intentionally excluded (because GuardDog covers them) — if so, document. (competitor-reality P1)

- **"Endor's banned authors / compromised domains pattern" not verifiable in current Endor docs** — Likely from older Endor marketing. Either cite the older source explicitly or soften framing. (competitor-reality P1)

- **"Shai-Hulud-class detection" overpromises** — Token-theft-without-ownership-change is a known FN class for v2's signal set. Reframe to "account-takeover signal class". (competitor-reality P2)

### Scope & PR Shape

- **Single-PR ambition is materially wider than v1** `[CONSENSUS 3/12]` — 6 milestones × M-to-L tasks across DB + worker + 3 frontend surfaces + 8-language detectors + maintainer cron is 2-3× v1's 15-commit PR. Reviewer fatigue + critical-review surface area suggest split. **Suggested split:** PR-1 = M0 (Tier-A v1 finish + allowlist) — small, low-risk, closes carried-over debt. PR-2 = M1a + M1b (reachability + capabilities — frontier-parity headline). PR-3 = M1c (maintainer signals — riskiest). PR-4 = M2 + M3 (ops). (skeptic-f11, scope-cutter SC-8, pragmatist-f11)

## P2 — Quality Gaps

(Condensed; see persona reports for full evidence.)

- **`reachability_details` JSONB has no shape constraint** — soft-schema drift risk; add CHECK or document shape in migration comment. (DM-P2-1)
- **Allowlist `reason` server-side min-length missing** — frontend requires min 10 chars; DB column has no CHECK. Add `CHECK (length(trim(reason)) >= 10)`. (DM-P2-4, contradicted by pragmatist-f10 which calls min-10 "form-validation theater" — disputed below)
- **Tarball-cleanup race with parallel-batch capability scan** — plan should specify capability scan runs SYNCHRONOUSLY after `runGuardDog` returns in same iteration. (worker-pipeline P1-tarball-cleanup-race)
- **Drawer wiring conflates two refactors** — UX undefined for "row chevron expands inline + package-name click opens drawer". Lock the UX in plan. (skeptic-f9)
- **Cold-start cost on Fly scale-to-zero not addressed** — stuck-job recovery has 5-min threshold; per-package heartbeat may need explicit calls inside reachability resolver. (worker-pipeline P2-cold-start-not-considered)
- **Pipeline integration line-comment marker over line numbers** — line numbers will drift; reference `// === STEP: Malicious-package scan` instead. (worker-pipeline P2-pipeline-line-comment-mismatch)
- **`scanner_version` should be in `package_capabilities` UNIQUE** — see DM-P1-3 above; trade off elaborated.
- **PMF trigger compatibility with new columns** — verified safe but should be affirmed in plan. (MT-7)
- **Capability scan transitive deps: scan-all default may scale poorly on monorepos** — open question deferred to /implement; could re-evaluate. (Open Question 3 in plan)
- **Suppress reason format `'allowlist:<uuid>'` is free-form** — consider typed `suppressed_source` enum + `suppressed_source_id`. (migration-safety P2-4)
- **AI Explain steady-state cost ceiling not specified** — locked to gemini-2.5-flash, ~$6.75/mo at 100 orgs current pricing. Document the ceiling. (ai-cost P2)
- **Model-tier ambiguity for maintainer Explain** — explicitly state stays on Tier 1, not Tier 2 BYOK. (ai-cost P2)
- **Allowlist UX claim "Snyk + Socket" imprecise** — Socket has tiered Alert Actions, richer than flat allowlist. Drop Socket from comparator. (competitor-reality P2)
- **Migration files combine M0.6 + M1a.4 in one `_rpcs.sql`** — couples reachability and allowlist RPC migrations. Split into two files for cleaner ordering. (migration-safety P1-4)
- **OSSF feed-sync deliverable plan-acknowledged as ~useless** `[CONSENSUS 2/12]` — Brief admits "OSSF is duplicative with OSV upstream". Plan even has a watchpoint to drop it after first week. **Cut entirely** OR replace with the Datadog dataset (26k confirmed, more genuinely additive). (skeptic-f8, scope-cutter — semi-disputed by pragmatist-f6)

## P3 — Nits & Opportunities

(Selected highlights from opportunity-scout's 10 findings; full list in `tasks/aaa898f13d004e6ce.output`.)

- **OPP-1:** Emit one structured log line per finding emission with reachability + capability + scanner metadata. Unlocks Endor-style noise-rate dashboards. ~30 min.
- **OPP-2:** Surface allowlist auto-suppression count in extraction-run summary. Proves the feature is doing its job.
- **OPP-3:** CSV export from the allowlist table. SOC 2 / quarterly audit support.
- **OPP-4:** Add `signal_kind` column on `project_malicious_findings` so future flow-builder can compose policies on the specific signal (e.g., `'maintainer_email_change'`) instead of coarse `scanner='maintainer'`. Cheaper now than backfill later.
- **OPP-5:** Reachability-distribution stat row above findings table. Makes the "noise reduction" UX self-evident.
- **OPP-7:** Persist `entry_points + call_chain` from `reachability_details` as `{file, line, symbol}` tuples (not bare strings) so future Aegis fix prompts can paste actual file-line paths.
- **OPP-8:** Standardize `User-Agent: deptex-depscanner/<version>` on all outbound feed/registry pulls. Good citizenship + future "verified scanner" relationships with registries.
- **OPP-9:** Capture per-package `scan_duration_ms` in `package_capabilities` so the "interesting files only" optimization decision becomes a SQL query rather than an open question.

## Open Debates (Disputed Findings)

### `MaliciousAllowlistSection` reason min-length validation

- **In favor (server CHECK):** DM-P2-4 — defense-in-depth audit trail value
- **Against (drop the rule):** pragmatist-f10 — "form-validation theater" for a solo-user pre-launch product
- **Plan section:** Frontend Design > Allowlist UI
- **Your call:** keep the validation if audit trail is load-bearing; drop if focused on shipping speed.

### M2 (OSSF feed) inclusion

- **In favor of cut:** skeptic-f8, scope-cutter SC-1 — duplicative, plan even has watchpoint to drop
- **Against (keep):** pragmatist-f6 (semi-keep — at minimum keep M2.1 sync function as one-shot validation, drop the cron + watchdog)
- **Plan section:** Implementation Tasks > M2
- **Your call:** if you want to honor the brief's "max coverage" decision, keep all three M2 tasks; if you want the smallest reviewable PR, cut M2 entirely and revisit if production data shows an OSV gap.

### Capability detection columns vs JSONB

- **In favor of JSONB:** pragmatist-f1, skeptic-f12 (high confidence)
- **In favor of booleans:** original plan + DM-P1-3 (booleans are cheaper for indexed policy-composition queries)
- **In favor of hybrid:** scope-cutter SC-1 — boolean for top-5 high-signal, JSONB for the rest
- **Plan section:** Data Model > package_capabilities
- **Your call:** if v2's `decision 14` (defer policy composition) actually holds, JSONB is the right call — no v2 query filters on individual columns. If you suspect policy composition lands within 1-2 quarters, keep booleans.

### M1c (Maintainer signals) inclusion

- **In favor of cut/defer:** pragmatist-f2, scope-cutter SC-2 — ships with synthetic-fixture-only validation (zero real-world signal); deserves its own focused PR after v2's reachability+capability story burns in
- **Against (keep):** original plan — frontier parity claim depends on it; Shai-Hulud-relevance angle
- **Plan section:** Implementation Tasks > M1c
- **Your call:** if you cut M1c, v2 collapses to ~3 weeks of work and the "Endor maintainer-signal parity" claim drops. If you keep, accept the synthetic-fixture acceptance bar and address the cross-org fan-out P0 + the historical-snapshot subsystem P1 first.

### Drawer wiring (M1b.8)

- **In favor of cut:** scope-cutter SC-6 — UX polish, capabilities reachable from dependencies page anyway
- **In favor of keep:** original plan — matches user-stated preference
- **Plan section:** Implementation Tasks > M1b.8
- **Your call:** if you cut, v2 capabilities visible only via dependencies page in v2 (acceptable); cuts ~1 day of state-management refactor. If you keep, lock the UX explicitly first.

### `data_flow` reachability tier

- **In favor of cut:** scope-cutter SC-3 — most expensive tier, lowest marginal utility for malicious-package use case
- **Against:** original plan — completes the Endor-style ladder
- **Plan section:** Data Model > reachability CHECK
- **Your call:** cutting eliminates the order-of-operations dependency on taint_engine entirely (callgraph-only resolution covers `unimported / imported_unused / module / function`). Strongly recommend cut given P0-A.

## Suggested Plan Amendments

(Ordered by criticality — apply at least Patches 1-7 before `/implement`.)

### Patch 1 — Reachability decoupled from `taint_engine_runs` storage `[P0-A]`

In M1a.3, replace "read from `taint_engine_runs` storage or invoke `buildCallgraph` if not cached" with:

> **Reachability resolution architecture:** `runMaliciousScan` builds its own self-contained per-language callgraph using `tree-sitter-extractor` + `import-mapping` primitives, scoped to the workspaceRoot. The callgraph is cached in-process for the duration of the run (single project = single callgraph build). This is independent of the Phase 6 taint_engine step's rollout-pct + circuit-breaker gates — reachability filter works on every extraction regardless of taint_engine state.
>
> **Tier resolution:**
> - `unimported`: package not in import map → no work needed.
> - `imported_unused`: package in import map but no symbol referenced → tree-sitter scan of source files.
> - `module`: symbol referenced but not called → callgraph node exists, no incoming call edges.
> - `function`: callgraph has incoming call edge → resolved.
> - `data_flow`: ONLY when Phase 6 taint engine ran AND a `Flow` row in `project_reachable_flows` references the malicious symbol — otherwise downgrade to `function`.

### Patch 2 — OSSF source CHECK widening migration `[P0-B]`

Add fifth migration file `malicious_packages_v2_ossf_source.sql` to §Migrations:

```sql
ALTER TABLE public.known_malicious_packages
  DROP CONSTRAINT IF EXISTS known_malicious_packages_source_chk;
ALTER TABLE public.known_malicious_packages
  ADD CONSTRAINT known_malicious_packages_source_chk
  CHECK (source IN ('osv','ghsa','ossf'));

ALTER TABLE public.malicious_feed_sync_runs
  DROP CONSTRAINT IF EXISTS mfsr_source_chk;
ALTER TABLE public.malicious_feed_sync_runs
  ADD CONSTRAINT mfsr_source_chk
  CHECK (source IN ('osv','ghsa','ossf'));
```

Apply BEFORE the OSSF ingestor code ships. Update §Migrations list to include this fifth file.

### Patch 3 — `apply_malicious_allowlist` ecosystem canonicalization + post-update recompute `[P0-C, P0-D]`

Replace the RPC body in §Data Model with:

```sql
CREATE OR REPLACE FUNCTION public.apply_malicious_allowlist(p_org_id uuid, p_extraction_run_id text)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
  v_suppressed integer;
  v_dep_ids uuid[];
BEGIN
  WITH allowlisted AS (
    UPDATE public.project_malicious_findings pmf
    SET
      suppressed = true,
      suppressed_at = now(),
      suppressed_reason = 'allowlist:' || (
        SELECT oma.id::text FROM public.organization_malicious_allowlist oma
        INNER JOIN public.project_dependencies pd ON pd.id = pmf.project_dependency_id
        INNER JOIN public.dependencies d ON d.id = pd.dependency_id
        WHERE oma.organization_id = p_org_id
          AND oma.revoked_at IS NULL
          AND oma.package_name = d.name
          AND oma.ecosystem = public.canonicalize_malicious_ecosystem(d.ecosystem)
          AND (oma.version_range IS NULL OR oma.version_range = pd.version)
        ORDER BY (oma.version_range IS NULL) ASC, oma.added_at DESC  -- prefer most-specific match
        LIMIT 1
      )
    FROM public.organization_malicious_allowlist oma
    INNER JOIN public.project_dependencies pd ON pd.id = pmf.project_dependency_id
    INNER JOIN public.dependencies d ON d.id = pd.dependency_id
    WHERE pmf.organization_id = p_org_id
      AND pmf.extraction_run_id = p_extraction_run_id
      AND pmf.suppressed = false
      AND oma.organization_id = p_org_id
      AND oma.revoked_at IS NULL
      AND oma.package_name = d.name
      AND oma.ecosystem = public.canonicalize_malicious_ecosystem(d.ecosystem)
      AND (oma.version_range IS NULL OR oma.version_range = pd.version)
    RETURNING pmf.id, pmf.dependency_id
  ),
  suppressed_count AS (SELECT count(*) AS n, array_agg(DISTINCT dependency_id) AS dep_ids FROM allowlisted)
  SELECT n, dep_ids INTO v_suppressed, v_dep_ids FROM suppressed_count;

  -- Re-recompute is_malicious for affected dependencies so denorm reflects suppression.
  IF v_dep_ids IS NOT NULL AND array_length(v_dep_ids, 1) > 0 THEN
    PERFORM public.recompute_dependency_is_malicious(v_dep_ids);
  END IF;

  RETURN v_suppressed;
END;
$$;
```

Changes: (1) `canonicalize_malicious_ecosystem(d.ecosystem)` instead of `lower(d.ecosystem)` — fixes `'gem'`/`'pip'`/`'go'` non-matches. (2) Deterministic `suppressed_reason` cite via subquery + ORDER BY. (3) Post-update `recompute_dependency_is_malicious` so `is_malicious` denorm reflects allowlist.

### Patch 4 — Capability ecosystem CHECK alignment `[P0-E]`

Pick ONE and document explicitly in §Data Model:

**Option A (recommended for v2 simplicity):**
> Reduce M1b.3 detector languages to `{js, py, java, go, ruby}` (5 ecosystems matching the canonical set). PHP/Rust/C# capability detection deferred to v3 alongside ecosystem set expansion.

**Option B:**
> Add a sixth migration file `malicious_packages_v2_ecosystem_widen.sql` that drops + re-adds CHECK constraints on `known_malicious_packages.ecosystem`, `package_security_cache.ecosystem`, `package_capabilities.ecosystem`, `organization_malicious_allowlist.ecosystem`, `project_malicious_findings.ecosystem` (if any) to add `'composer','cargo','nuget'`. Update `backend/src/lib/malicious/ecosystem.ts` and `backend/depscanner/src/malicious/ecosystem.ts` `CanonicalEcosystem` type. Update `guarddogCliVerb` dispatch (will need to either return null or route to a new no-op for these — verify GuardDog 2.9.0 doesn't support these ecosystems anyway).

### Patch 5 — Reachability soft-fail nests its own try/catch `[P0-F]`

In M1a.3, add explicit acceptance:

> **Reachability resolution wraps its own try/catch.** Inside the per-package loop in `runMaliciousScan`, immediately after `pending.push(...)` and before `insertFindingsBatch`, the call to `computeReachability(...)` MUST be wrapped:
> ```ts
> let reachability_level: ReachabilityLevel | null = null;
> let reachability_details: any = null;
> try {
>   const r = computeReachability(callgraph, importMap, pkg.name, pkg.ecosystem);
>   reachability_level = r.level;
>   reachability_details = r.details;
> } catch (e: any) {
>   reachability_details = { error: 'compute_failed', message: e?.message ?? String(e) };
> }
> // assign onto the most-recent pending entry
> ```
> Acceptance test: when `computeReachability` throws, the pending findings still insert with `reachability_level=null`. Wrap separately from the per-package outer try (which counts the package as failed and skips pending.push).

### Patch 6 — Maintainer-signal cross-org fan-out spec `[P0-G]`

In M1c.2, replace "writes findings to `project_malicious_findings` for any project containing that dep" with:

> **Per-row `organization_id` derivation:** Fan-out query MUST `JOIN project_dependencies → projects` to derive `organization_id` per project row; never insert a constant or caller-supplied `organization_id`.
>
> ```sql
> INSERT INTO project_malicious_findings (
>   project_id, organization_id, extraction_run_id, project_dependency_id,
>   dependency_id, rule_id, scanner, severity, message
> )
> SELECT
>   pd.project_id,
>   p.organization_id,            -- derived from the project, NEVER from caller
>   'maintainer-cron:' || to_char(now(), 'YYYY-MM-DD'),
>   pd.id,
>   pd.dependency_id,
>   'maintainer:' || $signal_kind,
>   'maintainer',
>   $severity,
>   $message
> FROM project_dependencies pd
> JOIN projects p ON p.id = pd.project_id
> WHERE pd.dependency_id = $signal_dep_id
> ON CONFLICT (project_id, project_dependency_id, rule_id, scanner, extraction_run_id) DO NOTHING;
> ```
>
> **Acceptance test:** running maintainer-signal-sync against a dependency present in 2+ orgs writes findings under each project's correct `organization_id`; the PMF `enforce_pmf_org_consistency` trigger fires zero exceptions.
>
> **Notification dispatch:** route also writes a `notification_events` row + triggers `/api/workers/dispatch-notification` so maintainer findings don't wait 10 minutes for the reconciler.

### Patch 7 — Capability scan decoupled from GuardDog cache decision `[P1]`

In M1b.4, replace the cache-hit assumption:

> **Unpack-once-share pattern.** At the top of the per-package loop, decide whether unpack is needed by checking BOTH caches:
> ```ts
> const cachedGuarddog = await readGuardDogCache(supabase, pkg.name, pkg.version, canonical);
> const cachedCapabilities = await readCapabilityCache(supabase, pkg.name, pkg.version, canonical);
> const needsUnpack = cachedGuarddog.length === 0 || cachedCapabilities === null;
> if (needsUnpack) {
>   const entry = await cache.fetch(canonical, pkg.name, pkg.version);
>   // run GuardDog OR capability scan against entry.dir, depending on which cache was missing
> }
> ```
> Both consumers share the unpack. Capability scan runs SYNCHRONOUSLY after `runGuardDog(entry.dir, ...)` returns, in the same per-package iteration, before the next loop turn. NEVER call `cache.cleanupEntry` per-package.

### Patch 8 — Anonymous CHECK rename hazard mitigation `[P1]`

In `malicious_packages_v2_reachability.sql` (or wherever scanner CHECK is widened), replace `DROP CONSTRAINT IF EXISTS project_malicious_findings_scanner_check` with a DO block that finds the actual CHECK by signature:

```sql
DO $$
DECLARE
  v_constraint_name text;
BEGIN
  SELECT conname INTO v_constraint_name
  FROM pg_constraint c
  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
  WHERE c.conrelid = 'public.project_malicious_findings'::regclass
    AND c.contype = 'c'
    AND a.attname = 'scanner';
  IF v_constraint_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE public.project_malicious_findings DROP CONSTRAINT %I', v_constraint_name);
  END IF;
END $$;

ALTER TABLE public.project_malicious_findings
  ADD CONSTRAINT project_malicious_findings_scanner_check
  CHECK (scanner IN ('feed','guarddog','maintainer'));
```

### Patch 9 — Add explicit §Rollout section `[P1]`

After §Migrations, add:

> ## Rollout
>
> v2 ships hot (no feature flag) but migrations land first to avoid the partial-deploy hazard:
>
> 1. **Apply all 5 migrations via Supabase MCP** in filename-sorted order:
>    - `malicious_packages_v2_org_allowlist.sql`
>    - `malicious_packages_v2_capabilities.sql`
>    - `malicious_packages_v2_ossf_source.sql`
>    - `malicious_packages_v2_reachability.sql`
>    - `malicious_packages_v2_rpcs.sql`
> 2. **Refresh schema dump:** `cd backend/depscanner && npm run schema:dump`
> 3. **Verify schema dump is committed in the same PR** — CI gate fails otherwise.
> 4. **Merge PR** — worker + backend deploy.
> 5. **Verify pipeline run** on `deptex-test-npm` smoke.
> 6. **Rollback path:** revert worker + backend code; keep new tables + columns (no data loss); CHECK relaxes are forward-only and harmless without worker writes; old RPC restored from git.

## Findings by Axis

| Axis | Count | Highest severity | Personas |
|---|---|---|---|
| phantom-dependency / callgraph | 4 | P0 | skeptic, worker-pipeline, architect (×2 angles) |
| migration-safety | 6 | P0 | migration-safety, data-model, architect |
| competitive-claim-false | 5 | P0 | competitor-reality |
| missing-tenant-test | 5 | P1 | test-strategy, multi-tenant |
| scope-cut-candidate | 8 | P2 | pragmatist, scope-cutter, skeptic |
| premature-flexibility | 5 | P1 | pragmatist, scope-cutter, skeptic, DM |
| missing-cost-bound | 4 | P1 | skeptic, worker-pipeline, ai-cost |
| invented-helper | 2 | P1 | skeptic, multi-tenant |
| RPC-correctness | 4 | P0 | data-model, architect, multi-tenant |
| capability-CHECK-mismatch | 1 | P0 | architect |
| dispatch / notifications gap | 2 | P1 | worker-pipeline |
| missing-historical-snapshot | 1 | P1 | skeptic |
| frontend-state-undefined | 1 | P2 | skeptic |
| opportunities | 10 | P3 | opportunity-scout |

## Persona Coverage Map

(R1 only; Round 2/3 skipped due to budget threshold.)

| Persona | R1 findings | Highest severity | Focus areas |
|---|---|---|---|
| skeptic | 13 | P0 (×2) | Phantom callgraph, Phase 6 rollout, allowlist semantics, scope sizing |
| pragmatist | 11 | P1 (×3) | Capability table shape, M1c entire-cut, retention pruner cut |
| scope-cutter | 8 | P2 (×6) | Tag count, M1c, drawer wiring, retention, M3.3, PR split |
| architect | 8 | P0 (×2) | Callgraph reuse, capability CHECK ecosystem, allowlist recompute, OSSF CHECK |
| test-strategy-auditor | 19 | P1 (×8) | Tenant isolation, INTERNAL_API_KEY, idempotency, PGLite RPC tests |
| opportunity-scout | 10 | P3 (×10) | Logging, signal_kind column, CSV export, distribution stats |
| data-model-auditor | 10 | P0 (×2) | Allowlist canonicalization, OSSF CHECK, FK ON DELETE, scanner_version history |
| migration-safety-auditor | 16 | P0 (×4) | Anonymous CHECK rename, deploy ordering, hidden CHECK, transaction atomicity |
| multi-tenant-design-auditor | 7 | P0 (×1) | Maintainer cross-org fan-out, checkOrgMembership, allowlist DELETE org-match |
| worker-pipeline-auditor | 10 | P0 (×2) | Callgraph not persistable, soft-fail loses finding, capability cache miss |
| ai-cost-auditor | 5 | P1 (×2) | Cache TTL on time-sensitive signals, prompt-injection via registry metadata |
| competitor-reality-checker | 8 | P0 (×2) | Reachability granularity claim false, Endor mirror inaccurate, capability tag claim |

## Recommended Next Step

**REVISE.** Apply at least Patches 1–7 to `.cursor/plans/malicious-packages-v2.plan.md` before `/implement`. Patches 8–9 are operational hardening that should also land but won't block forward progress.

Suggested sequencing:
1. **Apply Patches 1–7** to the plan file (you can ask "apply patches 1-7" and I'll edit them in).
2. **Resolve the 6 Open Debates** (capability JSONB-vs-booleans, M2 inclusion, M1c inclusion, drawer wiring, data_flow tier, allowlist reason min-length). These are 1-3 minutes each via `AskUserQuestion`.
3. **Re-run `/review-plan malicious-packages-v2 --no-debate`** with a smaller persona set focused on the patched sections (recommend 6: skeptic, pragmatist, architect, data-model-auditor, migration-safety-auditor, worker-pipeline-auditor) to verify patches don't introduce new issues.
4. **`/create-worktree malicious-packages-v2`** + `/implement`.

If you want to stay in single-PR shape, the suggested split (PR-1 = M0 prereq, PR-2 = M1a + M1b headline, PR-3 = M1c maintainer, PR-4 = M2 + M3 ops) becomes a stronger argument once Patches 1–7 land — each PR becomes more reviewable and the high-risk M1c can be evaluated against M1a/M1b's burned-in data.
