# Plan Review — dast

Verdict: **REWORK**
Plan reviewed: `.cursor/plans/dast.plan.md` (mtime 2026-04-29)
Generated: 2026-04-29
Personas: 8 — skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, data-model-auditor, worker-pipeline-auditor
Vote tally: 0 READY / 2 REVISE / 6 REWORK
Findings: 7 P0 (post-scoring) / 18 P1 / 14 P2 / 11 P3
Debate: ~35 agreements, ~14 dissents, ~24 new R2 findings prompted by others

## Summary

The plan ships an ambitious v1 (worker rename + selective pipeline mode + 3 tables + 8 routes + 13 frontend components + Aegis tool + merged Confirmed Exploitable card) but the swarm identified 7 P0 architectural flaws with strong cross-persona consensus. The single biggest issue: the plan extends `extraction-worker` (rename + `payload.mode` + dual poll loops + bundled ZAP image) when the aider-worker precedent and runtime-shape constraints all point unambiguously to **scaffolding `deptex-dast` as a sibling Fly app** — six of eight personas converged on this fix independently. Compounding architectural issues: atomic-commit semantics broken (UNIQUE missing dast_run_id; active pointer deferred), cross-link FKs to ephemeral row UUIDs that null between scans, no RLS on Realtime-published tables (cross-tenant broadcast vector), no SSRF validation at any layer, and a heartbeat-blocking execSync risk that produces double-runs against customer URLs. Six personas voted REWORK; two voted REVISE on the assumption the rework would not be too disruptive. The plan needs a structural rewrite, not a patch list.

## Vote Tally

| Persona | Vote | Top concern | Rationale |
|---|---|---|---|
| skeptic | REWORK | skeptic-f3 + data-model-auditor-f10 | Cross-link is the entire differentiator and it ships broken; FK to ephemeral row UUIDs SET NULL between scans, +50 line magic number, route normalization unspecified. |
| pragmatist | REWORK | pragmatist-f1 + architect-f1 | Renaming extraction-worker mid-flight is gratuitous when sibling-app precedent already solves dispatch; this single decision collapses ~10 P0/P1 findings. |
| scope-cutter | REWORK | scope-cutter-f2 + pragmatist-f8 | v1 includes merged card, Aegis tool, phase-2/3/4 columns, 13 frontend components — none belong in MVP given cross-link match rate is unproven. |
| architect | REWORK | architect-f5 + data-model-auditor-f14 | Atomic-commit broken in two compounding ways; UNIQUE missing dast_run_id, active_dast_run_id deferred after Phase 19 already proved partial-visibility ships bugs. |
| test-strategy-auditor | REVISE | test-strategy-auditor-f1 | Core scaffolding is testable but missing explicit matrices for SSRF/RLS/RPC concurrency/heartbeat — adding test specs is P1 patch, not redirection. |
| opportunity-scout | REVISE | opportunity-scout-f1 | Sibling-app pivot unlocks right shape; cheap forward-compat hooks needed now to avoid v2 migration churn. |
| data-model-auditor | REWORK | data-model-auditor-f4 | FK to ephemeral UUIDs nulling between scans + broken atomic-commit/UNIQUE + no RLS on 3 Realtime tables = structural data-layer flaw. |
| worker-pipeline-auditor | REWORK | worker-pipeline-auditor-f5 | Heartbeat dying during execSync ZAP causes 5-min stuck detector to re-dispatch and double-run scans against customer targets; combined with no remote SIGTERM and no org cap, worker lifecycle needs redesign. |

## P0 — Fundamental Concerns (7)

### worker-architecture: Sibling Fly app, not rename + selective mode `[CONSENSUS 7/8]`
- **Plan section:** Implementation Tasks → Worker plumbing (Tasks 1-2, 7, 9); Architecture Decisions
- **Claim:** Plan renames `extraction-worker` to `depscanner`, adds `payload.mode='extraction'|'dast-only'|'full'` to `extraction_jobs`, bundles ZAP into the existing image, and adds a second poll loop. Six personas independently converged on the opposite design: keep `extraction-worker` named as-is; scaffold `deptex-dast` as a sibling Fly app per the aider-worker precedent. Different runtime shape (network-egress + ZAP image vs. CPU-bound static analysis on a 50GB VDB mount + performance-8x machine). Cold-start cost of ZAP image is paid by 95% extraction-only traffic. `claim_extraction_job` doesn't filter on `payload.mode` (verified at `extraction_jobs_schema.sql:39-55`), so the dual-dispatch in plan as written is actively broken.
- **Evidence / alternative:** aider-worker is the canonical precedent — separate Fly app, separate image, separate fly.toml, claims `project_security_fixes` via `claim_fix_job`. DAST is structurally identical (own table `dast_jobs`, own RPCs already proposed). Plan even cites aider as the analog.
- **Suggested patch:** Replace Tasks 1, 2, 9 with: "Scaffold `backend/dast-worker/` modeled on aider-worker. New Fly app `deptex-dast` with own Dockerfile (`FROM ghcr.io/zaproxy/zaproxy:stable` only). New worker entry polls `claim_dast_job` exclusively. extraction-worker is untouched. All `payload.mode` language deleted."
- **Flagged by:** pragmatist-f1, scope-cutter-f1, architect-f1/f2/f6, skeptic-f2, worker-pipeline-auditor-f1/f2/f3, plus R2 consolidation findings architect-r2-f1, pragmatist-r2-f1, worker-pipeline-auditor-r2-f1.

### atomic-commit-broken: UNIQUE missing dast_run_id + active pointer deferred `[CONSENSUS 5/8]`
- **Plan section:** Data Model → `project_dast_findings.sql` UNIQUE constraint; Open Questions → `projects.active_dast_run_id`
- **Claim:** Two compounding bugs. (1) `UNIQUE(project_id, rule_id, endpoint_url, http_method)` does NOT include `dast_run_id`, so the upsert overwrites prior-run rows in place and the "DELETE WHERE dast_run_id <> current_run" step deletes nothing — silent partial mutation, no run versioning. (2) The plan defers `projects.active_dast_run_id` as an "open question, probably yes" — but Phase 19's atomic-commit pattern was specifically introduced to fix the partial-visibility bug (mid-scan rows visible). Punting reintroduces it. Suppression carry-forward is also broken: the unique key won't survive route variations (`/users/123` vs `/users/456`).
- **Evidence / alternative:** Phase 19 (`phase19_atomic_commit.sql`) adopts `UNIQUE(... extraction_run_id)` + active pointer + `commit_extraction` RPC across all finding tables. project_reachable_flows uses `UNIQUE(project_id, extraction_run_id, purl, ...)`. This is the established convention; the plan diverges without justification.
- **Suggested patch:** Mandate atomic-commit semantics: `UNIQUE NULLS NOT DISTINCT (project_id, rule_id, handler_file_path, handler_function_name, vulnerability_type, dast_run_id) WHERE handler_file_path IS NOT NULL` (resolved findings) + fallback partial UNIQUE for unresolved findings on (project_id, rule_id, endpoint_url, http_method, dast_run_id). Add `projects.active_dast_run_id TEXT` column. New `commit_dast_run(p_project_id, p_dast_run_id)` RPC modeled on `commit_extraction` carries forward `status`/`risk_accepted_*` by stable identity before swapping the active pointer atomically.
- **Flagged by:** data-model-auditor-f1/f14, architect-f5, plus R2 architect-r2-f2, data-model-auditor-r2-f2, skeptic-f9 (refined).

### cross-link-broken: FK to ephemeral row UUIDs + +50 magic number + route-pattern matching `[CONSENSUS 5/8]`
- **Plan section:** Implementation Tasks → Task 8 cross-link logic; Data Model → `project_dast_findings.linked_sast_finding_id`/`linked_sca_finding_id`
- **Claim:** The differentiator (Confirmed Exploitable card) sits on three broken mechanisms: (a) `linked_sast_finding_id REFERENCES project_semgrep_findings(id) ON DELETE SET NULL` — but Semgrep findings are deleted-and-reinserted per extraction run; the FK silently nulls between scans, the differentiator card disappears. (b) `start_line BETWEEN handler_line AND handler_line + 50` is a hardcoded magic number that over-merges in tightly-packed router files (Express routinely defines 5-10 handlers in 200 lines) and under-merges when handlers dispatch to helpers >50 lines away. (c) Route-pattern matching is naive equality — ZAP returns `/users/123`, `project_entry_points.route_pattern` stores `/users/:id` (or `/{id}` Spring, `/:id(.:format)` Rails). Naive equality matches 0%.
- **Evidence / alternative:** project_semgrep_findings churn confirmed in pipeline (delete-WHERE-extraction_run_id-stale). Nothing in the plan describes a route normalization step. The `+50` value has no rationale in the plan; pure heuristic.
- **Suggested patch:** Three-part fix. (a) Drop FK columns; replace with stable-identity columns: `linked_sast_rule_id TEXT, linked_sast_file_path TEXT, linked_sast_start_line INTEGER` and `linked_sca_osv_id TEXT, linked_sca_project_dependency_id UUID`. Re-resolve to live UUIDs at read-time. (b) Replace the +50 line window with a containing-function lookup: extend `project_semgrep_findings` to store `containing_function_name` (matching `project_usage_slices.containing_method` precedent) and join on `(handler_file_path = file_path AND handler_function_name = containing_function_name)`. Until that ships, **cut SAST cross-link from v1 entirely**; ship DAST↔SCA only (cleaner join via reachable_flows). (c) Build `lib/route-matcher.ts` with `normalizeRoute(framework, pattern)` + `matchRoute(zapUrl, pattern)`; framework-aware regex per `entry_points.framework`. Acceptance test: corpus of ≥20 (concrete URL, route pattern, framework) tuples covering 8 supported langs.
- **Flagged by:** skeptic-f3/f4, data-model-auditor-f4/f10, scope-cutter-r2-f3, plus R2 data-model-auditor-r2-f4 (escalated to P0), architect-r2-f5, skeptic-r2-f3.

### ssrf-+-rls-gaps: No URL validation at any layer; Realtime broadcasts cross-tenant `[CONSENSUS 4/8]`
- **Plan section:** API Design → POST scan; Migrations 1-3 (Realtime publication); Aegis Task 14
- **Claim:** Two compounding security gaps. (1) `target_url` is user-supplied and gets passed to ZAP, which performs HTTP requests against it. The plan validates it at zero layers. A worker on Fly scanning `http://169.254.169.254/latest/meta-data` exfiltrates Fly metadata. Fly's `*.internal` hostnames + `fdaa::/16` 6PN expose Deptex's own services. Aegis tool compounds: prompt-injected target_url from repo content. (2) Three new tables added to `supabase_realtime` publication with zero RLS policies — Realtime broadcasts INSERT/UPDATE payloads to ANY authenticated subscriber regardless of project_id filter. The frontend filter is advisory; PostgREST/Realtime do not enforce it server-side without RLS.
- **Evidence / alternative:** Plan §Risks does not flag SSRF. extraction_jobs (extraction_jobs_schema.sql:26-36), project_dependency_vulnerabilities, and other tenant tables all enable RLS. Plan migrations contain zero `ENABLE ROW LEVEL SECURITY` or `CREATE POLICY` statements but explicitly add tables to `supabase_realtime`.
- **Suggested patch:** Add `validateExternalUrl()` helper in `backend/src/lib/url-guard.ts`: block loopback, RFC1918, link-local, IMDS (`169.254.169.254`), Fly-internal (`*.internal`, `fdaa::/16`), file://, gopher://, javascript:, non-http(s) schemes. Resolve hostname pre-scan; validate resolved IP, not just literal (DNS-rebind defense). Validate at three layers: PUT /config, queue_dast_job RPC (plpgsql defense-in-depth), dast-worker pre-flight before spawning ZAP. ALSO: Enable RLS in the same migration that adds Realtime publication: `ALTER TABLE <t> ENABLE ROW LEVEL SECURITY; CREATE POLICY <t>_org_select ON <t> USING (organization_id IN (SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()));` for all three new tables. Add organization_id column to `project_dast_findings` (currently missing) for RLS efficiency.
- **Flagged by:** test-strategy-auditor-f12/f7, data-model-auditor-f5/f13/f18, plus R2 skeptic-r2-f2, test-strategy-auditor-r2-f1/r2-f2, data-model-auditor-r2-f1, worker-pipeline-auditor-r2-f6.

### heartbeat-broken-by-execsync: ZAP scan double-runs against customer URLs `[CONSENSUS 3/8]`
- **Plan section:** Implementation Tasks → Task 7 ZAP container integration; Task 9 worker job loop
- **Claim:** ZAP scans run 5-30 minutes. Existing pipeline pattern (`backend/extraction-worker/src/pipeline.ts:6,139`) uses `execSync` for shell-out. The heartbeat is a `setInterval` in the same process (`extraction-worker/src/index.ts:40-46`). If `runZap()` uses `execSync`, the event loop blocks for 5-30min, the heartbeat never fires, the recovery cron requeues at 5min, a second worker claims the same project, and the scan double-runs against the customer's URL. The plan does not specify spawn vs execSync.
- **Evidence / alternative:** `pipeline.ts:139` already uses execSync for npm install (minutes-scale). ZAP `full-scan.py` is 20-30min. `setInterval` doesn't fire while the event loop is blocked.
- **Suggested patch:** Mandate `child_process.spawn` (or `execa` async) for ZAP invocation in Task 7 acceptance. Add explicit acceptance: "heartbeat_at on dast_jobs continues to update every 60s during a 25-min scan against a slow target, verified manually." Recovery cron threshold for DAST should be `> timeout_minutes + 2`, not `5min` (because legitimate ZAP scans exceed 5min). Recovery must call `stopFlyMachine(machine_id)` BEFORE flipping DB status — backend cron cannot SIGTERM the remote subprocess otherwise.
- **Flagged by:** worker-pipeline-auditor-f5 (escalated to P0), test-strategy-auditor-r2-f3, worker-pipeline-auditor-r2-f4, skeptic-f7, worker-pipeline-auditor-f9/r2-f3.

### aegis-tool-cut-from-v1: scan_dast has no rate limit, no cost cap, prompt-injection-controllable URL `[CONSENSUS 4/8]`
- **Plan section:** Implementation Tasks → Task 14 Aegis `scan_dast` tool
- **Claim:** Plan registers `scan_dast` at `permissionLevel: 'moderate'` with no approval flow, no rate limit, no cost cap, no SSRF validation specific to the tool path. DAST is the textbook dangerous Aegis tool: it sends attack payloads at a customer-controlled URL. With LLM-controlled args, prompt injection from scanned repo content can redirect the URL. Brief's persona ordering rates Aegis third; opportunity-scout dissents and wants gated ship instead of cut.
- **Evidence / alternative:** Brief line 214 itself acknowledges "DAST scan trigger considered medium risk, may require approval for first run." `aegis_approval_requests` table exists for exactly this case.
- **Suggested patch:** Cut Task 14 from v1 entirely. Defer `scan_dast` tool to phase 2 alongside (a) `'dangerous'` permission level, (b) approval flow on first run, (c) target URL read from `project_dast_config.default_target_url` only — never from LLM-controlled tool params, (d) per-org rate limit. Aegis can read findings via existing find-tools; users trigger scans from the Scanning tab in v1.
- **Flagged by:** pragmatist-f5 (escalated P0), scope-cutter-f3 (escalated P0), scope-cutter-r2-f2, skeptic-f10/r2-f4, test-strategy-auditor-f6/r2-f1.
- **Dissent:** opportunity-scout — "ship gated, not cut: dogfooding signal source"; the consensus position is that gating cannot land safely without rate-limit/cost-cap infrastructure that's also out of v1 scope.

### confirmed-exploitable-card-→-badge: M-task gated on unproven match rate `[CONSENSUS 3/8]`
- **Plan section:** Frontend Design → Confirmed Exploitable merged card; Implementation Tasks → Task 12
- **Claim:** Plan ships three components (`<ConfirmedExploitableCard>` + header + tabs) plus client-side grouping plus hide-constituent-rows logic — all gated on a quantitative success target ("≥50% of triaged DAST findings collapse with at least one other finding") that requires real scans on real projects to validate. Until you've measured the overlap rate on actual data, building a card UI that hides individual findings is risk-on-risk: cross-link false positives become hidden findings the security engineer needed to see. Client-side grouping also breaks under pagination (50/page default) — DAST and SAST findings for the same handler can land on different pages.
- **Evidence / alternative:** Plan's own §Risks: "Cross-link false positives. Regex/pattern match between ZAP endpoint_url and project_entry_points.route_pattern can over-merge findings on dynamic routes."
- **Suggested patch:** v1: render `<Badge>Confirmed Exploitable</Badge>` on individual DAST rows where `linked_sast_*` or `linked_sca_*` is non-null. Don't hide constituent rows. Don't build the 3-tab evidence component. Materialize cross-link at write-time (server-side) so the badge data is in the row, not computed client-side. Phase 2: actually merge the rows once cross-link false-positive rate is measured against real projects.
- **Flagged by:** pragmatist-f8, scope-cutter-f2, skeptic-r2-f3 (refined).

## P1 — High-Priority Gaps (consolidated)

| ID | Plan section | Claim |
|---|---|---|
| `phase-2-columns-strip` (pragmatist-f2 + scope-cutter-f4 + data-model-auditor-f8/r2-f6) | Data Model migrations | 15+ phase-2/3/4 columns ship with no v1 writer (scan_engine='nuclei'\|'both', auth_strategy variants, encrypted_credentials, target_urls[], scan_on_extraction, suppressed/risk_accepted booleans, status enum 'fixed', depscore). Strip to v1-only. |
| `frontend-batch` (pragmatist-f4 + skeptic-f8 + architect-f13) | Implementation Tasks 10-13 | 13 frontend components in monolithic batch violates `feedback_visual_redesign_iteration` ("ship ONE piece first, sign-off, iterate"). Split into 3 PRs: (1) Scanning tab, (2) Security tab DAST chip + last-scan strip, (3) Confirmed Exploitable badge. |
| `org-cap-missing` (data-model-auditor-f3 + worker-pipeline-auditor-f6) | Data Model → queue_dast_job RPC | 1-per-project cap missing org-level cap. queue_fix_job precedent: `PERFORM 1 FROM organizations WHERE id = X FOR UPDATE; SELECT COUNT(*) WHERE organization_id = X AND status IN ('queued','processing'); IF count >= 3 THEN RAISE`. |
| `status-enum-divergence` (architect-f3 + data-model-auditor-f7/r2-f3) | Data Model → dast_jobs.sql | `'timeout'` status diverges from extraction_jobs convention. Use status='failed' + error_category='timeout'. Also: `error_message` should be `error` (match extraction_jobs); attempts/max_attempts defaults differ from extraction. |
| `run_id-type-divergence` (architect-f4/r2-f3 + data-model-auditor-f2) | Data Model → all DAST tables | `dast_run_id UUID` diverges from `extraction_run_id TEXT` convention. Forces cross-table casts. Change to `dast_run_id TEXT`. |
| `recovery-rpcs-missing` (worker-pipeline-auditor-f4) | Migrations → `dast_jobs.sql` | Missing `recover_stuck_dast_jobs()` and `fail_exhausted_dast_jobs()` RPCs. Recovery cron has nothing to call. |
| `recovery-machine-stop` (worker-pipeline-auditor-r2-f3 + skeptic-f7) | Implementation Tasks → Task 6 | Recovery cron must call `stopFlyMachine(machine_id)` before flipping DB status, else zombie ZAP keeps hammering customer URL. |
| `claim-rpc-setof` (worker-pipeline-auditor-f8) | Data Model → claim_dast_job | `RETURNS dast_jobs` (singular) breaks pattern; both claim_extraction_job and claim_fix_job use `RETURNS SETOF`. |
| `claim-rpc-index` (data-model-auditor-f6) | Data Model → dast_jobs partial index | Partial index covers `status` but `claim_dast_job` ORDERs by `created_at`; need `(created_at) WHERE status='queued'` for FIFO seek. |
| `default-target-invariant` (data-model-auditor-f9/r2-f6) | Data Model → project_dast_config | `default_target_url ∈ target_urls` invariant only at API; add `CHECK (default_target_url IS NULL OR default_target_url = ANY(target_urls))`. |
| `cross-tenant-tests` (test-strategy-auditor-f1) | Testing Strategy | Per-endpoint cross-tenant test missing for all 7 routes. (Disputed — pragmatist+scope-cutter argue one test on auth middleware suffices.) |
| `rpc-concurrency-tests` (test-strategy-auditor-f2) | Testing → Task 15 | claim_dast_job race + queue_dast_job cap need real-DB tests, not Supabase mocks. |
| `cross-link-fixture-matrix` (test-strategy-auditor-f3/r2-f5) | Testing → Task 15 | Cross-link unit test single happy-path; need negative cases (adjacent handler, dynamic-route normalization, line-boundary, cross-project, NULL handler, HTTP method mismatch). |
| `docker-vs-source-e2e` (test-strategy-auditor-f4 escalated P0) | Testing → Tasks 7+17 | Source-tree e2e can't catch Dockerfile regressions per `feedback_docker_vs_source_e2e`. Run task acceptance against built Docker image, not source tree. |
| `task-2-mode-coverage` (test-strategy-auditor-f9) | Testing → Task 2 | Subsumed by sibling-app fix (Task 2 disappears). If kept, missing dast-only/full/legacy/unknown coverage. |
| `redaction-tests` (test-strategy-auditor-f8) | Testing → Task 15 | Redaction regex has zero tests against AWS keys/JWTs/connection strings/session cookies. |
| `realtime-tenant-test` (test-strategy-auditor-f7) | Testing → Task 13 | Subsumed by RLS fix (P0 cluster). |
| `ci-scripted-smoke` (test-strategy-auditor-f13) | Testing | "Scripted smoke" referenced but not defined as CI gate; manual e2e (Task 17) doesn't catch iteration-day regressions. |

## P2 — Quality Gaps

- **client-side-merge-pagination** (skeptic-f5 + architect-f9 + data-model-auditor-f15) — Materialize merge server-side at write-time; client grouping breaks under pagination boundary.
- **handler-naming-inconsistency** (data-model-auditor-f11) — `handler_file_path` vs `entry_point_file` vs `handler_name` (3 names for the same concept across tables); align before ship.
- **redaction-store-nothing** (skeptic-f6) — v1 should not store response bodies at all; defer evidence storage to phase 2 with TruffleHog redaction.
- **internal-routes-trim** (pragmatist-f3 + scope-cutter-f5) — 8 routes is ~2x v1 needs; cancel route can defer (1-concurrent + 30min timeout suffices), inline Fly start in POST scan.
- **realtime-cut-cheap** (scope-cutter-f6) — Realtime sub for 5-30min scans is marginal; polling-only fine. Disputed by test-strategy.
- **permission-helper-duplicate** (architect-f7 + scope-cutter-f7) — Don't fork `checkProjectIntegrationsPermission`; parameterize the existing helper or reuse `checkProjectManagePermission` for v1.
- **cross-link-telemetry** (opportunity-scout-f4 escalated P1, data-model-auditor-r2-f5) — Persist `cross_link_metadata JSONB` so the +50 heuristic is tunable post-ship without re-scanning.
- **single-target-url** (scope-cutter-f8) — `target_urls TEXT[]` + `default_target_url` is phase-2 surface; v1 single `target_url TEXT`. Disputed by opportunity-scout.
- **active_extraction_run_id-filter** (architect-f8) — Cross-link must filter `WHERE extraction_run_id = projects.active_extraction_run_id`; else reads pending/orphan runs.
- **suppression-carry-forward-test** (test-strategy-auditor-f14) — Upsert SET clause must NOT include suppression columns; test that suppressed=true survives re-scan.
- **recovery-edge-cases** (test-strategy-auditor-f10) — Recovery test single happy path; missing exhausted-attempts/cancelled/fresh-heartbeat cases.
- **encrypted-creds-invariants** (data-model-auditor-f16) — `encrypted_credentials`/`encryption_key_version`/`auth_strategy` not constrained together.
- **80%-coverage-theater** (pragmatist-f10) — Cut 80% coverage + k6 + Realtime SLA targets for solo-pre-launch; keep targeted SSRF + tenant-isolation tests.
- **adoption-metrics-aspirational** (skeptic-f11) — Replace post-launch ≥1-scan/week target with technical-correctness gates (cross-link FP rate <10%, route normalization >80%, redaction zero credential leak).

## P3 — Nits & Opportunities

- skeptic-f8: Frontend Task 11 batches three pieces; ship one (revisits as P1 cluster patch).
- skeptic-f12: Cross-link silently 0%s when project_entry_points isn't populated; add match-rate banner.
- pragmatist-f11: Brief still references `project_routes` (plan supersedes); update brief.
- architect-f11: Recovery should be `dast-recovery.ts` + dedicated RPCs, not bolted onto fix-recovery.ts.
- architect-f12: Brief still has BYTEA + `encrypted_api_key` divergence; bookkeeping after scope locks.
- data-model-auditor-f12: Recovery index doesn't cover attempts/max_attempts; minor planner cost.
- data-model-auditor-f17: `run_id` column unused; either drop (max_attempts=1) or wire to recovery regeneration.
- opportunity-scout-f2: Persist ZAP raw JSON + SARIF for compliance/replay; phase-2 win.
- opportunity-scout-f3: Org-level DAST coverage signal endpoint; ~2 hours.
- opportunity-scout-f5: `list_dast_findings` Aegis tool (read-only, `'safe'` level) — defer with the `scan_dast` cut.
- opportunity-scout-f6: Structured redaction event log JSONB metadata.
- opportunity-scout-f8: Persist synthesized OpenAPI stub for schema-drift detection.
- test-strategy-auditor-f15: Multiple Security tab states (config-no-jobs/failed-zero-findings/disabled) not covered.
- worker-pipeline-auditor-f10: Task 2 acceptance covers only mode='extraction'; subsumed by sibling-app fix.

## Open Debates (Disputed)

### Pre-allocate internal dispatch endpoint? `[DISPUTED 1 for / 4 against]`
- **In favor:** opportunity-scout — `trigger_source` enum already declares 'scheduled'/'on_extraction'; cheap MVP hook avoids phase-2 schema churn.
- **Against:** skeptic, pragmatist, scope-cutter, worker-pipeline-auditor — premature flexibility; enum cost ≠ endpoint cost (auth surface, INTERNAL_API_KEY check, test matrix).
- **Plan section:** API Design.
- **Recommendation:** skip in v1; phase 2 adds the endpoint when QStash schedules wire up.

### Pre-allocate commit_sha/pr_number/branch columns? `[DISPUTED 1 for / 3 against]`
- **In favor:** opportunity-scout — phase-3 PR-check integration cheap if columns pre-allocated.
- **Against:** skeptic, architect, data-model-auditor — speculative shape; phase-3 likely wants FK to pull_requests/checks table, not denormalized columns.
- **Recommendation:** skip in v1; phase 3 designs the proper join shape.

### Cut Aegis `scan_dast` tool entirely vs gated ship? `[DISPUTED 4 for cut / 1 for gated]`
- **In favor of cut:** pragmatist, scope-cutter, skeptic, test-strategy-auditor — no rate limit/cost cap/proper RBAC in v1; security risk.
- **In favor of gated:** opportunity-scout — dogfood signal source; ship with `'dangerous'` permission + approval flow.
- **Recommendation:** cut. Gated ship requires rate-limit + cost-cap infrastructure that's also out of v1 scope; the gating won't land safely.

### Single `target_url TEXT` vs `target_urls TEXT[]` for v1? `[DISPUTED 1 for array / 4 for single]`
- **In favor of array:** opportunity-scout — multi-env (staging/prod) is a "permanent capability axis," competitor wedge.
- **In favor of single:** scope-cutter, pragmatist, data-model-auditor — phase-2 multi-env surface; single TEXT now, ALTER TABLE later.
- **Recommendation:** single TEXT in v1. Array doesn't unlock anything until scan-target-picker UI ships, which is phase 2.

### Per-endpoint cross-tenant tests vs single auth-middleware test? `[DISPUTED 1 for full matrix / 2 against]`
- **In favor of full matrix:** test-strategy-auditor — per-route belt-and-suspenders.
- **Against:** pragmatist, scope-cutter — solo pre-launch; one auth-middleware test covers the path.
- **Recommendation:** one targeted test on POST /scan + GET /findings (the highest-risk routes). Belt without the suspenders.

## Suggested Plan Amendments

These collapse the P0 + P1 consensus into copy-pasteable plan sections. Apply selectively.

### Patch 1 — Sibling Fly app (replaces Tasks 1, 2, 9)

**Concern:** Worker rename + payload.mode + dual poll loop is the wrong architecture; sibling-app per aider precedent is consensus.

**Recommended replacement for Implementation Tasks 1-2 and 9:**

> **Task 1 — Scaffold dast-worker as sibling Fly app (M)**
> - New directory `backend/dast-worker/` modeled on `backend/aider-worker/`. Own `Dockerfile FROM ghcr.io/zaproxy/zaproxy:stable` plus a tiny Node entrypoint.
> - New Fly app `deptex-dast`. Env vars: `FLY_DAST_APP`, `FLY_DAST_POOL_SIZE`. Add `DAST_CONFIG` constant in `backend/src/lib/fly-machines.ts` modeled on `AIDER_CONFIG` (cpus=4, memory_mb=8192, cpu_kind='shared').
> - Worker entry polls `claim_dast_job(machine_id)` exclusively. Single loop. Heartbeat 60s setInterval. ZAP via `child_process.spawn` async wait — never `execSync`.
> - extraction-worker is **untouched** — no rename, no `payload.mode`, no second poll loop.
> - Acceptance: `deptex-dast` machine pulls a queued dast_jobs row, runs ZAP against a target, writes findings to `project_dast_findings`, marks job completed. Heartbeat advances every 60s during a 25-min scan against a slow target.

### Patch 2 — Atomic-commit semantics (replaces UNIQUE + open question)

**Concern:** UNIQUE missing run_id + active pointer deferred = partial-visibility bug + broken suppression carry-forward.

**Recommended changes:**

> **Migration `dast_jobs.sql`:** change `run_id UUID` to `run_id TEXT NOT NULL DEFAULT generate_dast_run_id()` (helper function: `'dast_' || gen_random_uuid()::text`). Match `extraction_run_id TEXT` convention.
>
> **Migration `project_dast_findings.sql`:** change `dast_run_id UUID` to `dast_run_id TEXT NOT NULL`. Replace UNIQUE with two partial indexes:
> ```sql
> CREATE UNIQUE INDEX project_dast_findings_resolved
>   ON project_dast_findings(project_id, rule_id, handler_file_path, handler_function_name, vulnerability_type, dast_run_id)
>   WHERE handler_file_path IS NOT NULL;
> CREATE UNIQUE INDEX project_dast_findings_unresolved
>   ON project_dast_findings(project_id, rule_id, endpoint_url, http_method, vulnerability_type, dast_run_id)
>   WHERE handler_file_path IS NULL;
> ```
> Note: per `feedback_postgrest_partial_unique_inference`, supabase-js `onConflict` won't work with these partial indexes. Use lookup-then-update pattern in dast-worker pipeline.
>
> **New migration `projects_active_dast_run.sql`:** `ALTER TABLE projects ADD COLUMN active_dast_run_id TEXT, ADD COLUMN previous_dast_run_id TEXT;`
>
> **New RPC `commit_dast_run(p_project_id UUID, p_dast_run_id TEXT)`:** carries forward `status`/`risk_accepted_*` from prior active run by stable identity, then atomically swaps `projects.active_dast_run_id`. Modeled on `commit_extraction` in phase19_2_commit_extraction_rpc.sql.

### Patch 3 — Cross-link rewrite (replaces FK + +50 + naive route matching)

**Concern:** FK to ephemeral row UUIDs SETs NULL between scans; +50 line magic number over-merges; route-pattern matching is naive equality.

**Recommended changes:**

> **Migration `project_dast_findings.sql`:** drop `linked_sast_finding_id`, `linked_sca_finding_id` FK columns. Replace with stable-identity columns:
> ```sql
> linked_sast_rule_id TEXT,
> linked_sast_file_path TEXT,
> linked_sast_start_line INTEGER,
> linked_sast_match_method TEXT, -- 'function_name' | 'line_window' | 'none'
> linked_sca_osv_id TEXT,
> linked_sca_project_dependency_id UUID REFERENCES project_dependencies(id) ON DELETE SET NULL,
> cross_link_metadata JSONB DEFAULT '{}', -- { method, distance, confidence }
> ```
>
> **v1 cross-link scope:** Cut SAST cross-link from v1. Ship DAST↔SCA only via `project_reachable_flows` join (cleaner: package + version on dependency side, no line-window heuristic).
>
> **Phase 2 SAST cross-link (deferred):** First add `containing_function_name TEXT` to `project_semgrep_findings` (matching `project_usage_slices.containing_method` precedent). Then join SAST↔DAST on exact `(file_path, containing_function_name)` match — no `+50 line` heuristic.
>
> **New `lib/route-matcher.ts`:** framework-aware regex compiler. `normalizeRoute(framework, pattern)` returns matcher RegExp; `matchRoute(zapUrl, pattern, framework)` returns boolean. Acceptance test corpus: ≥20 (concrete URL, route pattern, framework) tuples covering Express/Fastify/FastAPI/Spring/Rails/Gin/Sinatra/Laravel.
>
> **Materialize cross-link at write-time** in dast-worker pipeline. Frontend renders pre-joined data, no client-side merge logic.

### Patch 4 — SSRF + RLS hardening

**Concern:** No URL validation at any layer; no RLS on Realtime-published tables.

**Recommended additions:**

> **New `backend/src/lib/url-guard.ts`:** `validateExternalUrl(url: string): { valid: boolean; reason?: string }`. Rejects: loopback (127.0.0.0/8, ::1), RFC1918 (10/8, 172.16/12, 192.168/16), link-local (169.254/16), IMDS (169.254.169.254), Fly-internal (`*.internal`, `fdaa::/16`, `2001:db8::/32`), file://, gopher://, javascript:, non-http(s) schemes. Resolve hostname via DNS pre-scan; validate the resolved IP, not just the literal (DNS-rebind defense).
>
> **Three-layer enforcement:** (1) PUT /config rejects bad URLs with 422; (2) `queue_dast_job` plpgsql adds a CHECK calling a defense-in-depth wrapper; (3) dast-worker calls `validateExternalUrl()` before launching ZAP.
>
> **In all three migrations**, before `ALTER PUBLICATION supabase_realtime ADD TABLE`:
> ```sql
> ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
> CREATE POLICY <t>_org_select ON <t> FOR SELECT
>   USING (organization_id IN (SELECT om.organization_id FROM organization_members om WHERE om.user_id = auth.uid()));
> ```
>
> **Add `organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE`** to `project_dast_findings` (currently missing), populated from dast_jobs at write-time.

### Patch 5 — Status enum + column conventions

**Concern:** `'timeout'` status, `error_message`, attempts/max_attempts defaults, `RETURNS dast_jobs` (singular) all diverge from existing job-table conventions.

**Recommended changes:**

> Drop `'timeout'` from `dast_jobs.status` CHECK. Use `status='failed'` + `error_category='timeout'` (matches project_security_fixes pattern). Rename `error_message TEXT` to `error TEXT` (match extraction_jobs). `claim_dast_job RETURNS SETOF dast_jobs` (match claim_extraction_job + claim_fix_job pattern).
>
> Add to `dast_jobs.sql`: `recover_stuck_dast_jobs()` and `fail_exhausted_dast_jobs()` RPCs mirroring extraction equivalents. Threshold for stuck: `heartbeat_at < NOW() - (timeout_minutes + 2 minutes)`, NOT 5min — legitimate ZAP scans exceed 5min.
>
> **Recovery cron must call `stopFlyMachine(machine_id)`** before flipping DB status. Add to recovery acceptance: "stuck DAST job's machine is stop()'d as part of recovery."

### Patch 6 — Strip phase-2/3/4 columns from v1 migrations

**Concern:** 15+ unused columns ship with no v1 writer; recreate the `status` + `suppressed BOOLEAN` legacy mistake.

**Recommended cuts:**

> **`dast_jobs.sql`:** Drop `scan_engine` discriminator (hardcode `'zap'` in worker until phase 2). Drop `auth_strategy` non-anon CHECK values. `attempts`/`max_attempts` keep but change defaults to match extraction_jobs (3/3) — DAST will use `max_attempts=1` set by `queue_dast_job` if needed.
>
> **`project_dast_config.sql`:** Drop `target_urls TEXT[]` (use single `target_url TEXT`). Drop `default_target_url`. Drop `encrypted_credentials`, `encryption_key_version`. Drop `scan_engines TEXT[]`. Drop `scan_on_extraction`. Constrain `auth_strategy` CHECK to `('anon')` only.
>
> **`project_dast_findings.sql`:** Drop `suppressed BOOLEAN` and `risk_accepted BOOLEAN` columns (use `status` enum only — `'open'|'suppressed'|'risk_accepted'|'fixed'`). Keep `risk_accepted_by/at/reason` for audit trail. Drop `depscore` until you have a writer.

### Patch 7 — Frontend split (3 PRs, not 1)

**Concern:** 13-component monolithic batch violates `feedback_visual_redesign_iteration`.

**Recommended phasing:**

> **PR 1 (M):** Project Settings → "Scanning" tab. Inline `<DastScanningTab>` containing config form (target URL input + Save), "Scan now" button, scan history table reusing existing `<RunRow>`. Browser sign-off before PR 2.
> **PR 2 (M):** Security tab DAST chip filter + last-scan strip + empty state. Extend existing `<VulnerabilityExpandableTable>` to render DAST rows. Browser sign-off before PR 3.
> **PR 3 (S):** Confirmed Exploitable badge on rows where `linked_*` is non-null. **No dedicated card, no 3-tab evidence component, no hide-constituent-rows logic** — defer to v2.

## Findings by Axis

| Axis | Count | Highest severity | Personas |
|---|---|---|---|
| worker-architecture | 11 | P0 | skeptic, pragmatist, scope-cutter, architect, worker-pipeline-auditor |
| atomic-commit / data-model | 9 | P0 | data-model-auditor, architect, skeptic |
| cross-link mechanics | 8 | P0 | skeptic, data-model-auditor, scope-cutter, architect |
| ssrf / rls / security | 7 | P0 | test-strategy-auditor, data-model-auditor, skeptic, worker-pipeline-auditor |
| scope cuts (Aegis tool, card, columns) | 9 | P0 | scope-cutter, pragmatist, skeptic |
| heartbeat / recovery / lifecycle | 6 | P0 | worker-pipeline-auditor, test-strategy-auditor, skeptic |
| schema convention drift | 7 | P1 | architect, data-model-auditor |
| test coverage gaps | 9 | P1 | test-strategy-auditor |
| frontend phasing / UX | 4 | P1 | pragmatist, scope-cutter, skeptic, architect |
| forward-compat hooks | 5 | P3 | opportunity-scout |

## Persona Coverage Map

| Persona | R1 findings | R1 clean lenses | R2 +1s | R2 -1s | R2 new | Vote |
|---|---|---|---|---|---|---|
| skeptic | 12 (2 P0, 5 P1) | 6 | 5 | 3 | 4 | REWORK |
| pragmatist | 12 (1 P0, 4 P1) | 7 (malformed — listed personas, not lenses) | 7 | 5 | 4 | REWORK |
| scope-cutter | 8 (1 P0, 2 P1) | 7 | 7 | 5 | 3 | REWORK |
| architect | 13 (3 P0, 5 P1) | 7 | 7 | 4 | 5 | REWORK |
| test-strategy-auditor | 15 (3 P0, 8 P1) | 6 | 7 | 2 | 5 | REVISE |
| opportunity-scout | 8 (0 P0, 0 P1) | 3 | 4 | 0 | 4 | REVISE |
| data-model-auditor | 18 (3 P0, 8 P1) | 6 | 6 | 3 | 6 | REWORK |
| worker-pipeline-auditor | 10 (2 P0, 5 P1) | 5 | 6 | 2 | 6 | REWORK |

## Recommended Next Step

**REWORK.** Six of eight personas voted REWORK. The plan as written has fundamental architectural flaws — the worker rename, dual-dispatch, atomic-commit, and cross-link mechanics all need structural changes, not patches. The recommended path:

1. **Re-run `/plan-feature`** against the brief with the seven amendment patches above pre-applied. The biggest single decision is the sibling-Fly-app pivot (Patch 1), which collapses ~10 P0/P1 findings on its own.
2. Optionally re-run `/interview` for the disputed scope items: target_url single vs array, Aegis tool cut vs gated. Answer can come from Henry without a full interview.
3. After the rewrite, this review can be re-run on the new plan.

Alternative if you want to push through faster: apply Patches 1-7 to `dast.plan.md` directly and re-review with `--no-debate` to confirm the rework lands cleanly. The two REVISE voters (test-strategy-auditor, opportunity-scout) would likely flip to READY with the patches applied; the six REWORK voters would likely flip to REVISE.

The brief itself (`feature-brief-dast.md`) does not need changes — the problem framing and competitive analysis hold. The damage is in the plan's resolution of architectural decisions. The brief's Phase 2/3/4 scoping is also correct — the plan was over-eager in pulling phase-2 columns into v1 schema.
