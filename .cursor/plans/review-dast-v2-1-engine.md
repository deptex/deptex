# Plan Review — dast-v2-1-engine

**Verdict: REWORK** (unanimous, 12/0/0)
Plan reviewed: `.cursor/plans/dast-v2-1-engine.plan.md`
Generated: 2026-05-02
Personas: 12 — skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, data-model-auditor, migration-safety-auditor, failure-mode-hunter, multi-tenant-design-auditor, worker-pipeline-auditor, ux-walker
Vote tally: **0 READY / 0 REVISE / 12 REWORK**
Findings: ~28 P0 / ~55 P1 / ~25 P2 / ~10 P3 (post-Round-2 scoring)
Debate: ~70 agreements, ~12 dissents, ~30 new findings prompted by other personas across Round 2

---

## Summary

The plan as written cannot survive `/implement` without burning days. **Five independent P0 clusters block implementation**, all with strong cross-persona consensus and none patchable inline: (1) migration safety — single destructive cutover with 6 simultaneous signature breaks, no deploy DAG, no shadow window; (2) credential silent-fail surfaces — worker has no symmetric guard for missing/stale `DAST_CREDENTIAL_KEY`, decryption blast radius across all tenants, no per-scan audit trail; (3) cross-tenant validation gaps at all three layers (route, RPC, worker decrypt-time); (4) ZAP/Nuclei silently inverts brief decision 3 (parallel → sequential) without measured rationale, plus DAST_CONFIG sizing edit absent from any task means SPA scans OOM on first run; (5) `ActiveScanOptInDialog` only fires on `scan_profile='full'` but `auto` is the default and runs full active scan — destructive opt-in is dead code on the default path. The unanimous recommendation is to **re-segment v2.1 into ordered slices** (v2.1a additive migration + ZAP-only auth/SPA/scope; v2.1b destructive cleanup after shadow; v2.1c Nuclei or split-jobs; v2.1d recorded-login HAR) and re-run `/review-plan` on the resequenced trio.

---

## Vote Tally

| Persona | Vote | Top concern | Rationale (one sentence) |
|---|---|---|---|
| skeptic | REWORK | pragmatist-r2-f14 | Six personas converged on REWORK with independent triangulation on three scope cuts plus a brief-decision-3 silent override that needs `/brainstorm` not `/implement`. |
| pragmatist | REWORK | pragmatist-r2-f14 | Five independent P0 clusters block `/implement` and none can be fixed by inline patches; 12-patch debt already captured. |
| scope-cutter | REWORK | pragmatist-r2-f14 | Cross-persona convergence is decisive — three personas independently land on the same cut set; v2.1 cannot ship as one plan without unsafe blast radius. |
| architect | REWORK | architect-r2-f3 | Plan compounds 6 load-bearing signature breaks into a single migration with no deploy DAG; that alone forces REWORK. |
| test-strategy-auditor | REWORK | test-strategy-auditor-f1 | The 4 highest-blast-radius failure modes (cross-tenant, rotation race, silent-anonymous-fallback, header_rules secret-leak) have zero acceptance criteria. |
| opportunity-scout | REWORK | cross-persona-p0-cluster | My P3 prep findings are non-blocking, but the other personas' P0 cluster is severe enough to block on its own merits. |
| data-model-auditor | REWORK | migration-safety-two-phase-split | The migration shape itself is wrong, not merely under-polished — that's REWORK, not REVISE. |
| migration-safety-auditor | REWORK | phase24a-destructive-monolith | A 4-6hr rewrite splitting one migration into two phases + wrapper RPCs + drain runbook + deploy DAG is structural amendment, not patch-level revision. |
| failure-mode-hunter | REWORK | failure-mode-hunter-r2-n1 | Compound silent-failure interactions can discard a 30-minute ZAP scan with no error surfaced and the scan_job marked completed. |
| multi-tenant-design-auditor | REWORK | multi-tenant-design-auditor-f1 | A cross-tenant credential leak is a single missing WHERE clause away; plan ships without three-layer guard, RLS write-policy, or tenant-drift assertion at decrypt time. |
| worker-pipeline-auditor | REWORK | p0-migration-two-phase-split | Plan as written would walk depscanner machines into multiple unrecoverable failure modes the moment phase24a applies. |
| ux-walker | REWORK | auto-active-escalation-bypasses-opt-in-dialog | First-time user who never touches profile picker triggers active fuzz against staging without ever seeing the warning that exists for exactly that scenario. |

---

## P0 — Fundamental Concerns

### Cluster 1: Migration safety — single destructive cutover with no shadow window `[CONSENSUS 6/12]`

- **Plan section:** Data Model → Migration file (steps 1–13), Risks R5
- **Claim:** phase24a bundles 6 simultaneous signature breaks (commit_dast_run RPC, queue_scan_job RPC, `projects.active_dast_run_id` drop, `findings.target_id` NOT NULL flip, `scan_jobs.target_id` add + CHECK rewrite, partial unique index recomposition) into one atomic apply. Migration step 4 backfills `findings.target_id` via `projects.active_dast_run_id` — only matches active-run findings; previous-run + orphaned findings get NULL, step 5 NOT NULL aborts mid-migration. R5 mitigation ("synthetic target rows") contradicts step 4 ("use `projects.active_dast_run_id`"). DROP+RE-ADD on `scan_profile`/`scan_timeout_minutes` silently destroys customer settings. CREATE UNIQUE INDEX without CONCURRENTLY holds ACCESS EXCLUSIVE.
- **Evidence:** `data-model-auditor-f1/f2/f3/f4/f8`, `migration-safety-auditor-f1/f2/f3/f4`, `architect-f3/r2-f3`, `pragmatist-f2/r2-rev2`, `failure-mode-hunter-r2-n2`, `worker-pipeline-auditor-r2-f10`, `skeptic-f5`. Nine independent P0 findings + concrete consensus patch.
- **Suggested patch:** **Two-phase migration mirroring Phase 6 atom-retirement.**
  - **phase24a (additive only):** create `project_dast_targets` + `project_dast_credentials` + `scope_config` JSONB; add `target_id` NULLABLE on findings + scan_jobs; ADD COLUMN (not DROP+RE-ADD) for `scan_profile`/`scan_timeout_minutes`; create new `commit_dast_run(p_target_id UUID, p_dast_run_id TEXT)` ALONGSIDE old `commit_dast_run(p_project_id, p_dast_run_id)`; old wraps new via SECURITY DEFINER:
    ```sql
    CREATE OR REPLACE FUNCTION commit_dast_run(p_project_id UUID, p_dast_run_id TEXT) RETURNS VOID AS $$
    DECLARE v_target_id UUID;
    BEGIN
      SELECT id INTO v_target_id FROM project_dast_targets
      WHERE project_id = p_project_id ORDER BY created_at LIMIT 1;
      PERFORM commit_dast_run(v_target_id, p_dast_run_id);
    END; $$ LANGUAGE plpgsql;
    ```
  - **Two-pass backfill:** pass 1 creates one synthetic-legacy `project_dast_targets` row per project, sets `findings.target_id = legacy_target_id` for all unmatched rows; pass 2 attempts URL-match upgrade where `findings.endpoint_url` host matches a real target row.
  - **Soak ≥7 days** with both pointers (`projects.active_dast_run_id` + `project_dast_targets.active_dast_run_id`) double-written. Frontend + worker confirmed consistent.
  - **phase24b (destructive, one release later):** flip `findings.target_id` NOT NULL after orphan sweep; drop `projects.active_dast_run_id`/`previous_dast_run_id`; drop wrapper RPCs; verify via `SELECT calls FROM pg_stat_user_functions WHERE funcname='commit_dast_run' AND pronargs=2 AND proargtypes[0]='uuid'::regtype` shows 0 calls in last 24h.
- **Flagged by:** data-model-auditor, migration-safety-auditor, architect, pragmatist, failure-mode-hunter, worker-pipeline-auditor, skeptic
- **Disputes:** None — universal consensus on shape.

---

### Cluster 2: Credential silent-fail / rotation race / blast radius `[CONSENSUS 7/12]`

- **Plan section:** Codebase Analysis (encryption pattern), Task 2, Task 8, `dast-encryption.ts`
- **Claim:** Worker has no symmetric guard for missing/stale `DAST_CREDENTIAL_KEY`. When target.has_credentials=true AND worker key unset/rotated-out, decrypt throws → exception swallow → falls into anonymous branch → ships findings tagged `auth_state='authenticated'` because cred row existed when state assigned. Customer sees green scan with fictitious "authenticated" chip on every finding. AES rotation has no per-machine pinning — Fly machine baked at deploy with old env var while DB rotates atomically; non-deterministic per-machine outcome under load. Decryption inside depscanner = single worker holds decrypt key for every tenant's creds (largest cross-tenant attack surface in v2.1). Decrypted plaintext can land in `scan_jobs.payload`/error logs/QStash with no architectural invariant prohibiting it.
- **Evidence:** `failure-mode-hunter-f1/f3/r2-n5`, `test-strategy-auditor-f2/r2-f8/r2-f9`, `multi-tenant-design-auditor-r2-a1/a2`, `architect-f7/r2-r1/r2-f2`, `worker-pipeline-auditor-r2-f9`, `data-model-auditor-r2-f5`, `skeptic-r2-f1`
- **Suggested patch:**
  1. **Worker hard-fails (NOT silent anonymous)** when `target.has_credentials=true` AND (a) `isDastEncryptionConfigured()=false` → `error_category='dast_credential_key_missing'`; (b) `decryptCredential` throws after current+prev fallback → `error_category='dast_credential_key_stale'`. Acceptance: "pipeline never runs anonymous scan when target.has_credentials=true."
  2. **Decryption stays at worker** (architect withdraws f7 per failure-mode-hunter dissent — moving to API route makes leak surface STRICTLY worse via QStash payload + scan_jobs.payload queryable JSONB + admin endpoints). Three guards: decrypt-just-before-spawn (plaintext exists only inside `buildAutomationYaml()` call frame); `Buffer.fill(0)` zero-out immediately after YAML emission; `DAST_CREDENTIAL_KEY` env var on depscanner only (never backend API or QStash payload).
  3. **Architectural invariant (test-enforced):** decrypted plaintext NEVER in (a) `scan_jobs.payload`, (b) `scan_jobs.error_details`, (c) extraction_logs/dast_logs rows, (d) worker stderr/stdout, (e) QStash payload, (f) crash trace dumps. Test: structured-log scrub regex over fixture run; assert no payload/token/password/har_json substring in any log row.
  4. **Per-scan credential audit trail** (replaces withdrawn `data-model-auditor-f7` cred rotation history): `scan_jobs.credential_id UUID REFERENCES project_dast_credentials(id) ON DELETE SET NULL` + `scan_jobs.credential_payload_hash TEXT` (SHA-256 of encrypted payload). Worker captures snapshot at job-claim time, never re-reads. Eliminates TOCTOU + credential-replace-during-in-flight race + rotation-recovery blindness in one column.
  5. **Encryption parity health probe:** worker startup probes `isDastEncryptionConfigured()`; on false, `claim_scan_job` filters out DAST jobs (filter at claim time, not at decrypt time → backpressure on queue rather than per-job silent failure).
- **Flagged by:** failure-mode-hunter, test-strategy-auditor, multi-tenant-design-auditor, architect, worker-pipeline-auditor, data-model-auditor, skeptic
- **Disputes:** Architect originally proposed decrypt-at-API-route (f7); failure-mode-hunter dissented; architect withdrew patch direction in r2-r1.

---

### Cluster 3: Cross-tenant validation gaps `[CONSENSUS 5/12]`

- **Plan section:** API Design (7 targetId-bearing endpoints), Data Model (RLS), Task 8 (worker)
- **Claim:** Plan describes `resolveProjectAccess(userId, projectId)` but never says route MUST also verify `target.project_id = :projectId AND target.organization_id = resolved_organization_id`. FK alone doesn't guarantee project ownership; user with `manage_projects` on Project A could pass targetId of Project B. `queue_scan_job` RPC validates target.project_id but is silent on org. `scan_jobs.target_id ON DELETE SET NULL` has no constraint that `scan_jobs.organization_id = target.organization_id`. Worker bypasses RLS via service-role with no second-line org check at decrypt time. Both new tables have SELECT-only RLS, no INSERT/UPDATE/DELETE WITH CHECK clauses (acceptable today via service-role bypass; broken under self-host NFR with anon key + RLS as enforcement boundary). Plan never addresses Supabase Realtime tenancy — default channels not RLS-enforced.
- **Evidence:** `multi-tenant-design-auditor-f1/f2/f3/r2-f9/r2-f10`, `test-strategy-auditor-f1/r2-f1`, `data-model-auditor-f6` (promoted P1→P0), `failure-mode-hunter-r2-a8`
- **Suggested patch (three-layer enforcement, all three required):**
  1. **Route layer:** every targetId-bearing endpoint runs `loadTargetOrDeny(targetId, projectId, organizationId)` returning 404 (not 403, not 422 — 404 prevents existence enumeration; same elapsed time within 50ms whether target exists in other tenant or doesn't exist) on mismatch.
  2. **RPC layer:** `queue_scan_job` validates `(target.project_id, target.organization_id) = (p_project_id, p_organization_id)`, RAISE on mismatch.
  3. **Worker layer:** at credential-load time, worker SELECTs target + project + scan_jobs in single query and asserts all three `organization_id`s match. On mismatch: abort with `error_category='tenant_drift_detected'`, include the three observed org IDs in error_payload, do NOT decrypt.
  4. **RLS WITH CHECK clauses** on INSERT/UPDATE for both `project_dast_targets` and `project_dast_credentials` mirroring SELECT USING expression. Cheap defense-in-depth; mandatory for self-host path.
  5. **Realtime tenancy:** subscriptions use Supabase Realtime RLS-aware private channels with auth token + table RLS evaluated server-side, OR backend proxies updates via SSE with `authenticateUser`. Cross-tenant test: subscribe with Org A JWT, write `project_dast_targets` row in Org B, assert NO event fires on Org A's channel.
  6. **Cross-tenant test coverage:** every targetId-bearing endpoint gets parametrized cross-tenant case (Org A user + Org B targetId → 404). Plan's `/permission|access/i` regex (line 619) is structurally incapable of catching cross-tenant bug — `resolveProjectAccess` returns 200 (not 403) on cross-project targetId because the user IS authorized for their own project; demoting test signal to P1 would invert audit-vs-grep posture.
- **Flagged by:** multi-tenant-design-auditor, test-strategy-auditor, data-model-auditor, failure-mode-hunter
- **Disputes:** Skeptic R2 argued test-f1 should demote P0→P1 (control absence is the actual P0); test-strategy-auditor refused, refined claim. Final position: both stay P0, coupled.

---

### Cluster 4: ZAP/Nuclei structural split + sequential-vs-parallel brief override `[CONSENSUS 5/12]`

- **Plan section:** Task 7 acceptance, Risks R3, brief decision 3
- **Claim:** Brief decision 3 explicitly locks "Nuclei runs in parallel inside the same depscanner Fly machine." Plan silently inverts to sequential with one-line code comment ("ZAP active scan saturates the network and Nuclei adds noise") and zero data. R3 mitigation says "revisit parallelization in v2.2 once we see real numbers" — meaning plan ships an unmeasured architectural inversion of a locked brief decision and parks validation to NEXT plan. Sequential ZAP→Nuclei in one job: (a) doubles wall-clock against the 30-min default ceiling (skeptic-f4); (b) creates compound silent-failure surface where Nuclei timeout + cancellation polling + cold-start retries can discard 25-min ZAP work with no error (failure-mode-hunter-r2-n1); (c) ZAP and Nuclei have different machine-shape requirements (ZAP browserBased wants 16GB perf-4x, Nuclei is fine on shared-cpu-2x 4GB) but plan provisions one machine for both. **Compounded by DAST_CONFIG sizing entirely missing from any task** — plan line 691 says "bump to performance-4x" but no task edits `fly-machines.ts`; SPA scan against Juice Shop will OOM on shared-cpu-4x 8GB the first time it runs.
- **Evidence:** `architect-f1/r2-f1/r2-r3`, `skeptic-f1/f4/r2-f2`, `worker-pipeline-auditor-f1/r2-f12`, `failure-mode-hunter-f6/r2-r1/r2-n1`, `pragmatist-f5/f6/r2-rev3`, `scope-cutter-f2`
- **Suggested patch (two competing options — pick one):**
  - **Option A (architect-locked):** Split into two scan_jobs (`type='dast_zap'`, `type='dast_nuclei'`) on separate Fly machines with independent shape dispatch. `queue_scan_job` creates BOTH rows in one transaction with shared `dast_run_id` + same `target_id`. `DAST_CONFIG_ZAP=perf-4x 16GB`, `DAST_CONFIG_NUCLEI=shared-cpu-2x 4GB`. `commit_dast_run` blocks until both rows are status='completed' OR one is 'failed' AND other is 'completed' (partial-success semantics). Dedup runs at commit-time inside RPC. Eliminates rate-limit interaction + cold-start regression + machine-shape mismatch + brief decision 3 violation.
  - **Option B (scope-cutter + pragmatist + 5-persona consensus):** Defer Nuclei to v2.1c entirely. v2.1 ships `engine='zap'` only; widen CHECK to allow `'nuclei'/'merged'` but never insert. Removes 3 of 7 worker-boundary risks per worker-pipeline-auditor: subprocess kill chain + partial-failure data loss + scan_timeout fitting + cold-start image bump + dedup ordering + template-staleness UI.
- **DAST_CONFIG sizing patch:** Add explicit Task 4.5 editing `backend/src/lib/fly-machines.ts`. Branch on `target.detected_runtime` at machine-start time (not worker-time): `detected_runtime='unknown'` OR `'spa'` → perf-4x 16GB; `'classic'` → shared-cpu-4x 8GB. First-ever scan of unknown-runtime target gets perf-4x; second scan with cached `detected_runtime='classic'` downsizes. SPA detection moves to API route POST /scan (cheap HEAD+GET probe <2s) so machine-shape dispatch picks the right size BEFORE provisioning. Acceptance: "SPA scan against Juice Shop completes without OOM."
- **Flagged by:** architect, skeptic, worker-pipeline-auditor, failure-mode-hunter, pragmatist, scope-cutter
- **Disputes:** Skeptic R2 argued sub-cap split (1/proj, 5/org max-2-SPA); worker-pipeline-auditor + pragmatist + architect-r2-f10 dissented (breaks queue-as-single-gate invariant). Final: hold cap at 5/org; route via orchestrator detection at queue time per pragmatist-f6/architect-f5.

---

### Cluster 5: ActiveScanOptInDialog hole + auto-active escalation `[CONSENSUS 5/12]`

- **Plan section:** Task 10 acceptance (line 612), Data Model `scan_profile` default (line 165), brief decision 6
- **Claim:** ActiveScanOptInDialog "blocks scan trigger when scan_profile=full AND user has not previously confirmed for this target." But auto profile is the DEFAULT (line 165) and brief decision 6 says auto runs full active scan when reachable. First-time user who never changes profile triggers full active fuzz against staging WITHOUT seeing the destructive dialog — the very first-time-UX risk the dialog exists to mitigate. localStorage-only opt-in doesn't survive cleared storage, doesn't survive webhook-queued scans, doesn't survive cross-device. Webhook-triggered scan path bypasses any frontend-only opt-in. Combined: queue delay can mean a scan kicks off hours after consent context lost.
- **Evidence:** `ux-walker-f5/r2-f7-dissent`, `skeptic-r2-f3`, `failure-mode-hunter-r2-n4`, `scope-cutter-f4/r2-f7`, `pragmatist-r2-f8-agreement`
- **Suggested patch (two competing options — both safe):**
  - **Option A (scope-cutter-r2-f7, simpler):** Cut auto-active-escalation entirely. `auto` profile is passive-only in v2.1; explicit `scan_profile='full'` is the sole path to active scan. Eliminates dialog hole at source — auto never escalates without explicit user choice. Brief decision 6 revisited: auto = "passive on first scan, active after explicit opt-in via profile=full."
  - **Option B (failure-mode-hunter-r2-n4, more durable):** Server-side `project_dast_targets.active_scan_consent_at TIMESTAMPTZ` column. `queue_scan_job` RPC RAISEs if `scan_profile` resolves to active AND `target.active_scan_consent_at IS NULL`. UI dialog writes the consent. Webhook-triggered scans fail loud with `error_category='consent_required'` until first manual confirmation. Re-validates at job-claim time (not just queue time) so consent revocation between queue and claim cancels the scan.
- **Flagged by:** ux-walker, skeptic, failure-mode-hunter, scope-cutter, pragmatist
- **Disputes:** None on the existence of the hole; only on choice of fix (A or B).

---

## P1 — High-Priority Gaps

The following are P1 findings worth patching before `/implement` once the P0 clusters resolve. Listed by axis cluster:

### YAML AF rewrite without feature flag
- **architect-f2/r2-f5, pragmatist-f3, test-strategy-auditor-f11, worker-pipeline-auditor-f2/r2-f11, scope-cutter-r2-f12**
- Plan line 569 deletes helper-script path outright; R1 mitigation said keep it behind a flag. Patch: `organizations.dast_runner_mode TEXT NULL CHECK (IN ('helper_script','automation_framework',NULL))` + global default env var; helper as default for one release; flip after Juice Shop reproduces v1 anonymous-baseline finding count within ±10%. Drop helper + flag in phase24b. Per-org override gives staged rollout (Phase 6 shadow shape).

### authentication_lost as job-state, not finding
- **architect-f9, ux-walker-r2-f1, failure-mode-hunter-r2-a, test-strategy-auditor-r2-f5**
- Move from `project_dast_findings` to `scan_jobs.error_category='auth_failed'`. UI banner reads from scan_jobs row with "Edit indicators" deep-link to `/settings/scanning?targetId=X` (auto-opens EditDialog scrolled to the indicator field). Findings collected before auth loss stay tagged `auth_state='authentication_lost'` (correct in plan); remove the synthetic finding row entirely. Eliminates pollution of count rollup, SLA timer, cross-link denominator. Worker-pipeline-auditor agrees this consolidates source-of-truth on scan_jobs (heartbeat path + retry policy). ux-walker withdraws own r1-f3 (replaced by banner approach).

### scope_config secret-bypass + ReDoS
- **failure-mode-hunter-f2/r2-n3, test-strategy-auditor-f3/r2-f10, pragmatist-f7, scope-cutter-r2-f13**
- (1) Reject sensitive header names (`Authorization`, `Cookie`, `X-Api-Key`, `X-Auth-Token`, `X-CSRF-Token`, regex `/token|secret|password|key/i`) at PUT time with 422 "use credential panel for sensitive headers." Otherwise org with no `DAST_CREDENTIAL_KEY` configured can stash JWT in `scope_config.header_rules` as a key-encryption-bypass workaround. (2) Cap individual regex length at 256 chars; reject patterns containing nested unbounded quantifiers (`(.+)+`, `(a*)*`) via static check; safe-regex2 / re2 compile-and-test on 1000-char synthetic URL with 100ms timeout. ZAP applies regex on every URL via Java NFA — `^(a+)+$` hangs ZAP thread + saturates 3 burst Fly machines.

### Subprocess control plane (cancellation + auth-loss abort + Nuclei kill chain)
- **failure-mode-hunter-f10, worker-pipeline-auditor-f3/f7, test-strategy-auditor-r2-f5**
- Single `spawnExternal` returning `{process, abort()}` handle. `abort()` does `process.kill(-pid, 'SIGTERM')` + 10s timer + `process.kill(-pid, 'SIGKILL')` for entire process group (Nuclei may spawn protocols/code template subprocesses that survive parent SIGTERM). Pipeline holds the handle and calls `abort()` on (a) cancellation poll between phases, (b) >3 `loggedOutIndicator` hits in real time via stderr-watcher → `onStderrLine(line)` callback, (c) scan_timeout. Frontend ScanNowButton becomes stateful Idle/Running/'Stop scan'; PATCH scan_jobs SET cancellation_requested=true; max-time-to-stop ≤30s. auth_lost threshold also gates on response status (only count 200/302/401; ignore 5xx + 4xx-other-than-401) + debounce window (4 trips must be in 5-min window AND no successful indicator-clear in between).

### Partial-failure data loss + preliminary results
- **failure-mode-hunter-f9/r2-r2/r2-n1, worker-pipeline-auditor-f4/r2-f4**
- Persist ZAP raw results to a `dast_partial_results` table keyed by `(scan_job_id, engine='zap')` with TTL 24h IMMEDIATELY after ZAP phase completes (before Nuclei). On retry, pipeline reads that row and skips re-running ZAP. On any subsequent failure (Nuclei timeout, SIGTERM, cold-start retry), preliminary→active promotion at commit OR `partial_results=true` marker on scan_jobs surfaces "Scan partially completed: 30 ZAP findings, Nuclei timed out." Resolved by Cluster 4 Option A (split jobs) by construction; falls back to this if Option B (defer Nuclei) lands instead.

### Concurrency cap + queueing UX
- **failure-mode-hunter-f5, ux-walker-f9**
- 5/org cap with maxBurst=3 = 2 jobs queue with no UI. Either: (a) when ≥maxBurst, return scan_jobs row with `status='queued'` + `queue_position` field; UI renders "Queued: 2 ahead" badge; OR (b) raise `FLY_DAST_MAX_BURST` to 5 to match cap. Per-target sibling rows show button disabled with tooltip "Waiting on target X scan to finish (1 scan per project at a time)."

### SPA detect cache invalidation + UX
- **architect-r2-f4, ux-walker-f6/f7, failure-mode-hunter-f4**
- Add `detected_runtime_ttl_at TIMESTAMPTZ` to `project_dast_targets` (default `NOW() + INTERVAL '30 days'`). Skip probe when cached AND non-unknown AND within TTL. Add force_recheck endpoint `POST /targets/:id/recheck-runtime` + UI affordance (tooltip on Unknown pill: "We couldn't reach target HTML; classic spider mode used. Re-probe?"). On runtime flip mid-scan (probe says spa, cached classic), emit `dast_runtime_drift` warning row and re-queue at correct machine shape (one-time, not loop). After first scan that detects SPA, surface one-time hint banner: "SPA detected — next scan will use real-browser crawling (~5-10 min longer, performance-4x machine)."

### Pre-migration drain runbook + deploy DAG
- **worker-pipeline-auditor-r2-f10, migration-safety-auditor-r2-n1**
- New Task 1.5 "Deploy DAG + verification queries":
  1. Set `INTERNAL_DAST_PAUSED=true` env on API → POST /dast/scan returns 503
  2. Wait until `SELECT COUNT(*) FROM scan_jobs WHERE type='dast' AND status IN ('queued','processing') = 0` (poll, max 60min, kill stuck via `fail_exhausted_scan_jobs` cron)
  3. Roll out depscanner image with dual-call shim (handles BOTH old and new commit_dast_run signatures)
  4. Apply phase24a via Supabase MCP
  5. Roll out API with new queue_scan_job call shape + new route reads off project_dast_targets
  6. Unset INTERNAL_DAST_PAUSED
  7. Monitor ≥7 days (≥30 days for prod) — verify `SELECT calls FROM pg_stat_user_functions WHERE funcname='commit_dast_run' AND pronargs=2 AND proargtypes[0]='uuid'::regtype` shows 0 calls in last 24h
  8. Apply phase24b
- Step 3→4 sequence non-negotiable.

### JWT short-lived expiry + login-probe validation
- **skeptic-f8/f10, ux-walker-f10, test-strategy-auditor-r2-f8**
- (1) At credential PUT time, decode JWT (no signature verification needed), inspect `exp` claim, reject 422 if `(exp - now) < 1.5x scan_timeout_minutes`. Forces enforcement at save time; failure mode visible inside same UX session (vs documentation-as-guard which is unenforceable). (2) When user submits credentials, route does one-shot login probe (form auth: POST username+password to login_url; check response body matches `logged_in_indicator` AND does NOT match `logged_out_indicator`). If both regexes fire on same response, return 422 'logged_out_indicator matches the post-login page; fix your regex' BEFORE the credential is saved. Add 'Test against URL' button next to indicator inputs (Burp Enterprise pattern).

### Multi-tenant DTO redaction concrete caps
- **multi-tenant-design-auditor-f4/r2-f11**
- Lock summary shape: token_prefix = first 8 chars + `…` (NOT 12 — JWT `eyJhbGciOi` is exactly 10 chars and reveals algorithm); username masked first-char + `***@<domain after @>` truncated to 24 chars total; cookie_names array capped at 10 items, each name truncated to 32 chars; last_step_url = scheme + host only (NEVER path/query/fragment); `har_filename` DROPPED entirely from DTO. Add unit-test fuzzer: 1000 random plausible tenant identifiers (UUIDs, slugs, org names) injected into each field; assert NO summary output contains a substring of length ≥8 from the original input.

### Privilege-boundary expansion
- **pragmatist-r2-f15**
- Credential PUT gated by `manage_projects` means anyone with project-edit access can swap a target's encrypted login credentials and exfiltrate cleartext via worker scan-failure logs. Pre-v2.1 nobody could store creds; post-v2.1 `manage_projects` holders gain effective access to target login credentials. Either (a) gate credential PUT by `manage_integrations` (existing perm closer to "handles secrets") for v2.1 — minimal added surface, no new perm to migrate; or (b) explicit acknowledgement in plan + Slack ping to Henry that v2.1 expands `manage_projects` holders' effective access.

---

## P2 — Quality Gaps (condensed)

- **scope_config split:** `header_rules` should live in dedicated `project_dast_header_rules` table with encrypted values (architect-f6) — pairs with the secret-bypass guard above.
- **Per-target scan_profile:** Brief user story implies it (staging weekly active / prod monthly quick); plan keeps project-wide. Defer to v2.2 with scheduling per scope-cutter-r2-f11. (`pragmatist-f8`, `ux-walker-r2-f6`)
- **Realtime tenancy unaddressed:** `multi-tenant-design-auditor-r2-f10` — frontend channels not RLS-enforced by default.
- **`label TEXT` no UNIQUE:** `data-model-auditor-f10` — `UNIQUE NULLS NOT DISTINCT (project_id, label)` so two targets in same project can't both be "staging."
- **PGLite migration coverage:** `migration-safety-auditor-r2-n2` extends test-strategy-auditor-f9 — must exercise both phases of the migration, not just additive.
- **Realtime double-write during shadow window:** `migration-safety-auditor-r2-n3` — frontend feature flag or debounce union of channels.
- **DastCredentialSummaryDTO reduction:** `scope-cutter-r2-f14` proposes reducing to just `has_credentials` boolean, killing mt-f4/f5 redaction work. Cleaner but loses information density.

---

## P3 — Nits & Opportunities

- **opportunity-scout-f1:** Add `linked_sast_finding_id UUID REFERENCES project_semgrep_findings(id) ON DELETE SET NULL` in phase24a — saves a v2.3 ALTER. Cheap forward-prep.
- **opportunity-scout-f2:** `cross_link_methods TEXT[]` array instead of `linked_sca_osv_id` boolean — v2.3 SAST link becomes append, not boolean rewrite.
- **opportunity-scout-f3:** Reserve `trigger_source` enum values `'scheduled','on_deploy'` now to avoid v2.2 CHECK shuffle.
- **opportunity-scout-f4:** Per-engine run metrics on scan_jobs.metadata — surface in Scanning history tooltip.
- **opportunity-scout-f6:** Empty stub flow-builder event-schemas entries (`dast.finding.created` etc) for v2.2 prep — 1hr.
- **opportunity-scout-f7:** Slack notification dispatcher hook on `authentication_lost` — five-line add per `feedback_slack_notifications`.
- **opportunity-scout-f9:** Stable `finding_signature` column for v2.3 cross-target deep-links.
- **ux-walker P3s:** auth_state suppression flag, `consecutive_lost_count` in banner, engine='merged' tooltip, migration-failure surface.
- **skeptic-f7:** `nuclei_templates_version` column on scan_jobs (moot if Nuclei deferred).

---

## Open Debates (Disputed Findings)

These need Henry's judgment — consensus didn't form.

### Multi-target cut `[DISPUTED — 2 for / 4 against]`
- **In favor of cutting:** scope-cutter (f3 + r2-f16), pragmatist (f1 thinner-slice if SPA stays, qualified)
- **Against:** architect (r2-d1: deferring = TWO breaking migrations not one), ux-walker (r2-f7: cuts mask first-time UX risks; cut Nuclei + recorded instead), skeptic (r2 dissent: cutting multi-target means doing brittle backfill twice), failure-mode-hunter (implicit via consensus on additive-phase24a path)
- **Plan section:** Data Model → `project_dast_targets`, Implementation Tasks 1+9, brief decision 7
- **Your call:** Architectural argument (single cleaner migration) carries more weight than the scope argument here, especially since the additive-phase24a path makes multi-target inexpensive to land alongside auth/SPA/scope. **Lean: hold multi-target in v2.1; cut Nuclei + recorded-login instead.**

### test-f1 severity (cross-tenant tests P0 vs P1) `[DISPUTED — 6 for P0 / 1 for P1 demotion]`
- **In favor of P0:** test-strategy-auditor (refuses demotion; refined claim), multi-tenant-design-auditor, data-model-auditor, failure-mode-hunter, ux-walker (implicit), worker-pipeline-auditor (implicit)
- **For P1 demotion:** skeptic (test absence is second-order to control absence per `multi-tenant-design-auditor-f1`)
- **Plan section:** Task 11 acceptance, line 619 (`/permission|access/i` regex)
- **Your call:** Coupling argument is decisive — plan's stated test pattern is structurally incapable of catching cross-tenant bug (200 not 403 returned). Demoting test signal would invert audit-vs-grep posture. **Lean: P0 stands.**

### Concurrency cap shape `[DISPUTED — 1 for sub-cap split / 4 against]`
- **For sub-cap split (1/proj, 5/org max-2-SPA):** skeptic-f2
- **Against:** worker-pipeline-auditor-r2-f8 (breaks queue-as-single-gate invariant), pragmatist-r2-d (gold-plating), architect-f10 (hold cap at 3 OR 5 simple), failure-mode-hunter-f5 (queue UI is the right fix, not sub-cap)
- **Your call:** Sub-cap requires queue layer to know SPA-vs-classic class at admit time, but SPA detection runs inside worker. **Lean: hold at 5/org or 3/org; route via orchestrator detection per pragmatist-f6/architect-f5; instrument duration p95; revisit in v2.2.**

### CONCURRENTLY index rebuild `[DISPUTED — 1 self-dissent]`
- **Originally:** migration-safety-auditor-f7 (CREATE UNIQUE INDEX without CONCURRENTLY holds ACCESS EXCLUSIVE)
- **Self-dissent in R2:** Drain-the-queue runbook eliminates concurrent writers; sub-10K rows means ACCESS EXCLUSIVE ≤1s acceptable; CONCURRENTLY forces splitting migration across transactions
- **Your call:** Drain runbook is required anyway for signature-break safety. **Lean: drop CONCURRENTLY recommendation; standard CREATE UNIQUE INDEX behind drain.**

### Decrypt at API route vs worker `[RESOLVED via R2 dissent → withdrawal]`
- **Originally architect-f7:** Move decryption to API route to shrink blast radius
- **Failure-mode-hunter-r2-d1 dissented:** QStash payload + scan_jobs.payload (queryable JSONB) + admin endpoints + worker stderr logging makes API-route-decrypt strictly worse leak surface
- **Architect r2-r1:** Withdrew patch direction; accepted dissent
- **Lean: keep decryption at worker** + decrypt-just-before-spawn + `Buffer.fill(0)` zero-out + `DAST_CREDENTIAL_KEY` env on depscanner only.

---

## Suggested Plan Amendments

The swarm produced concrete patches for nearly every P0/P1 finding. The recommended re-segmentation:

### v2.1a — Engine foundation (additive only)
- Tasks: 1 (additive migration phase24a only), 2 (encryption + form/JWT/cookie payloads only — recorded-login deferred), 3 (targets + form/JWT/cookie cred CRUD only), 5 (AF YAML behind `DAST_RUNNER_MODE` flag, default `helper_script`), 8 (pipeline using helper for one release; AF behind flag), 9 (multi-target shell + form/JWT/cookie panels — no RecordedLoginWizard, no DastScopePanel header_rules), 11-partial (cross-tenant tests + encryption rotation + silent-anonymous-fallback + auth_state state machine + migration backfill PGLite)
- Acceptance includes:
  - Pre-migration drain runbook (Task 1.5)
  - Wrapper RPC SQL for `commit_dast_run` and `queue_scan_job`
  - Three-layer cross-tenant validation (route + RPC + worker)
  - Worker hard-fails on missing/stale `DAST_CREDENTIAL_KEY`
  - DAST_CONFIG branched on `target.detected_runtime` at queue time (Task 4.5)
  - `auto` profile = passive-only (or `active_scan_consent_at` server-side gate)
  - Architectural invariant: decrypted plaintext NEVER in scan_jobs.payload/logs/QStash + structured-log scrub regex test
  - Per-scan `credential_id` + `credential_payload_hash` columns on scan_jobs (replaces credential rotation history)

### v2.1b — Migration cleanup (destructive phase24b, after 7-30 day shadow)
- Drop `projects.active_dast_run_id`/`previous_dast_run_id`
- Flip `findings.target_id` NOT NULL after orphan sweep
- Drop wrapper RPCs after `pg_stat_user_functions` shows 0 calls
- Drop `DAST_RUNNER_MODE=helper_script` after Juice Shop reproduces v1 finding count ±10%

### v2.1c — Hybrid engine OR Nuclei defer
- **Decision needed:** architect-r2-f1 split-jobs (`type='dast_zap'`, `type='dast_nuclei'`) OR scope-cutter-f2 defer-Nuclei-entirely
- Brief decision 3 needs `/brainstorm` revisit either way (sequential silently overrode parallel; needs measured rationale or restored)

### v2.1d — Recorded-login HAR (after first customer SSO ask)
- `dast-har.ts` sanitizer (with full negative-test matrix per test-strategy-auditor-f12)
- RecordedLoginWizard with stripped-fields list (per ux-walker-f2)
- ZAP `sequence-import` job in YAML AF
- HAR canonicalization (Q1 in plan)

---

## Findings by Axis

| Axis | Count | Highest severity | Personas |
|---|---|---|---|
| migration-safety / signature-break | 9 | P0 | data-model-auditor, migration-safety-auditor, architect, pragmatist, failure-mode-hunter, worker-pipeline-auditor, skeptic |
| credential silent-fail / blast-radius | 7 | P0 | failure-mode-hunter, test-strategy-auditor, multi-tenant-design-auditor, architect, worker-pipeline-auditor, data-model-auditor, skeptic |
| cross-tenant validation gaps | 5 | P0 | multi-tenant-design-auditor, test-strategy-auditor, data-model-auditor, failure-mode-hunter |
| ZAP/Nuclei structural / sequential override | 6 | P0 | architect, skeptic, worker-pipeline-auditor, failure-mode-hunter, pragmatist, scope-cutter |
| DAST_CONFIG sizing / SPA OOM | 4 | P0 | worker-pipeline-auditor, architect, failure-mode-hunter, skeptic |
| ActiveScanOptInDialog hole / consent | 5 | P0 | ux-walker, skeptic, failure-mode-hunter, scope-cutter, pragmatist |
| YAML AF feature flag missing | 5 | P1 | architect, pragmatist, test-strategy-auditor, worker-pipeline-auditor, scope-cutter |
| auth_state semantics (job-state vs finding) | 4 | P1 | architect, failure-mode-hunter, ux-walker, test-strategy-auditor |
| subprocess control plane | 3 | P1 | failure-mode-hunter, worker-pipeline-auditor, test-strategy-auditor |
| partial-failure data loss | 2 | P1 | failure-mode-hunter, worker-pipeline-auditor |
| scope_config secret bypass + ReDoS | 4 | P1 | failure-mode-hunter, test-strategy-auditor, pragmatist, scope-cutter |
| privilege-boundary expansion | 1 | P1 | pragmatist |
| testing surface untested | 17 | P0 | test-strategy-auditor (uniquely large per-persona count) |
| forward-prep / opportunity | 10 | P3 | opportunity-scout (uniquely non-blocking) |

---

## Persona Coverage Map

| Persona | R1 findings | R1 clean lenses | R2 +1s given | R2 -1s given | R2 new | Vote |
|---|---|---|---|---|---|---|
| skeptic | 10 (1 P1-flag) | 7 | 10 | 3 | 3 | REWORK |
| pragmatist | 10 (2 P0) | 7 | 9 | 4 | 3 | REWORK |
| scope-cutter | 6 (2 P1 cuts) | 11 | 7 | 4 | 4 | REWORK |
| architect | 10 (2 P0) | 10 | 11 | 3 | 5 | REWORK |
| test-strategy-auditor | 17 (5 P0) | 6 | 7 | 1 | 3 | REWORK |
| opportunity-scout | 10 (P3 only) | 11 | did not debate (no P0/P1 of own) | – | – | REWORK |
| data-model-auditor | 13 (4 P0) | 8 | 6 | 2 | 1 | REWORK |
| migration-safety-auditor | 15 (4 P0) | 0 | 9 | 1 (self) | 3 | REWORK |
| failure-mode-hunter | 12 (3 P0) | 3 | 11 | 3 | 5 | REWORK |
| multi-tenant-design-auditor | 11 (5 P1) | 4 | 6 | 2 (incl. 1 self) | 2 | REWORK |
| worker-pipeline-auditor | 11 (2 P0) | 4 | 6 | 2 | 2 | REWORK |
| ux-walker | 18 (5 P0) | 9 | 6 | 2 | 6 | REWORK |

---

## Recommended Next Step

**Verdict is REWORK with a unanimous 12/0/0 vote and well-specified rewrite condition.** The fixes are not hand-wavy — the swarm produced concrete patches for every P0 cluster. The right path is:

1. **Re-segment the plan** into v2.1a / v2.1b / v2.1c / v2.1d as detailed in *Suggested Plan Amendments* above. Multi-target stays in v2.1a (architectural argument wins); recorded-login + Nuclei defer to later slices.
2. **Revisit brief decision 3** (`/brainstorm` if needed) — sequential vs parallel ZAP/Nuclei needs either measured rationale or restored parallel intent. Pair with brief decision 6 (`auto` profile semantics — passive-only vs active-on-reachable).
3. **Re-run `/plan-feature dast-v2-1a-engine`** with the locked patches:
   - Two-phase migration (phase24a additive + 7-30 day shadow + phase24b destructive)
   - Wrapper RPC SQL for `commit_dast_run` and `queue_scan_job`
   - Three-layer cross-tenant validation (route + RPC + worker decrypt-time)
   - Worker hard-fails on missing/stale `DAST_CREDENTIAL_KEY` + per-scan `credential_id` audit
   - Architectural invariant: decrypted plaintext NEVER in payload/logs + structured-log scrub regex test
   - DAST_CONFIG branched on detected_runtime at queue time (Task 4.5)
   - `auto` profile = passive-only (option A) OR `active_scan_consent_at` server-side gate (option B)
   - DAST_RUNNER_MODE feature flag for AF YAML rewrite
   - Pre-migration drain runbook + deploy DAG with `pg_stat_user_functions` verification
4. **Re-run `/review-plan dast-v2-1a-engine`** before `/implement`. The sliced version should land a READY or REVISE verdict.

Estimated effort to reach READY: **~6-10 hours of plan amendment** (2-3 hours per major patch cluster, plus re-segmentation). The destination is locked; writing the destination IS the rework, but it's bounded.
