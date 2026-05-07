# Plan Review — iac-container-scanning (post-patch)

**Verdict: REVISE**
Plan reviewed: `.cursor/plans/iac-container-scanning.plan.md` (patched against prior REWORK review)
Generated: 2026-04-29 UTC
Personas: 10 — skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, data-model-auditor, multi-tenant-design-auditor, worker-pipeline-auditor, rollback-planner
Vote tally: **1 READY / 9 REVISE / 0 REWORK** (was 1 / 4 / 6)
Findings: **9 P0** / **20 P1** / **24 P2** / **9 P3** (62 total)
Debate: skipped (`--no-debate`)

## Summary

The 6 patches landed cleanly — every persona's clean_lenses confirmed scope cuts (cred store, configured-images, cache, AI explainer, compliance_refs, extra frameworks), schema fixes (UNIQUE shape, fingerprints, finalize_extraction RPC carry-forward), and operational additions (kill switches, feature flags, tenant-isolation tests). **Zero personas voted REWORK** — this was a successful REWORK→REVISE pass.

The remaining 9 P0s are not architectural rethinks; they're **concrete implementer traps** that emerged from looking closer at the patched plan. Three classes:

1. **Schema/upsert mechanics** — the new functional UNIQUE index using `COALESCE(start_line, -1)` and the GENERATED `vulnerability_id` column conflict with supabase-js's `onConflict` API (which can only target plain column-list indexes and rejects GENERATED ALWAYS values in payloads). Fixable by switching to a stored generated column for `start_line_key` and scrubbing `vulnerability_id` from the upsert payload.
2. **Multi-tenancy edges from the surviving container scan** — Dockerfile FROM lets a malicious tenant write `FROM ghcr.io/victim-org/private-image:latest`; the worker would attempt to authenticate the pull with the project's GitHub App installation. Plus, `organization_id` denormalization is correct but the resolution path isn't pinned to `(SELECT organization_id FROM projects WHERE id = projectId)`, opening mis-attribution risk. Both patchable in M2 acceptance.
3. **Test coverage gaps for the new infrastructure** — kill switches, the 7th endpoint (scanner-summary, missing from the prior tenant-isolation enumeration), and the finalize_extraction RPC amendment all lack named tests. Three rows added to the mapping table closes this.

Plus one **multi-stage Dockerfile bug** (worker picks first FROM, but production-shipping image is the LAST FROM), one **down-migration self-sufficiency gap** (rollback file has a manual-paste placeholder for the prior RPC body), and several P1 polish items.

**Recommended path:** apply the 9 P0 patches below, optionally apply the high-value P1s (Helm/M0 cuts, fingerprint scanner column, RPC tuple fallback). Re-run `/review-plan --no-debate` to confirm READY before `/implement`. Estimated patch effort: 1-2 hours for schema + RPC + test mapping; 0.5 day to write the multi-stage parser correctly.

## Vote Tally

| Persona | Vote | Top concern | Rationale |
|---|---|---|---|
| skeptic | REVISE | skeptic-f4 | Prior P0s cleared; new P1s on infra_types write-path + fingerprint stability worth pinning |
| pragmatist | REVISE | pragmatist-f1 | Scope realistic now; M0 still unfundable in 0.5d; Helm low-value |
| scope-cutter | REVISE | scope-cutter-f1 | Plan shippable; rollout allowlist + scanner-summary still cuttable |
| architect | REVISE | architect-f2 | Patterns align; fingerprint-only carry-forward diverges from semgrep tuple-fallback |
| test-strategy-auditor | REVISE | test-strategy-auditor-f2 | 3 P0s all "add named tests", not architectural |
| opportunity-scout | READY | opportunity-scout-f6 | All P3 enhancements; none block v1 |
| data-model-auditor | REVISE | data-model-auditor-f1 | 2 P0s are concrete supabase-js incompatibilities — fixable in schema |
| multi-tenant-design-auditor | REVISE | multi-tenant-design-auditor-f1 | Cache + IDOR P0s gone; Dockerfile FROM + org_id resolution remain |
| worker-pipeline-auditor | REVISE | worker-pipeline-auditor-f1 | Pipeline sound; multi-stage Dockerfile parsing must be fixed |
| rollback-planner | REVISE | rollback-planner-f1 | Section exists; down-migration placeholder + bad-data DELETE need hardening |

## P0 — Fundamental Concerns

> All 9 P0s are surgical patches, not architectural rethinks. None triggered a REWORK vote.

### 1. Functional UNIQUE index incompatible with supabase-js onConflict
- **Plan section:** `Data Model > Migration > idx_piacf_unique`; `M2 > scanners/storage.ts`
- **Claim:** `idx_piacf_unique` uses `COALESCE(start_line, -1)` — a functional/expression index. supabase-js `.upsert({ onConflict: 'project_id,rule_id,file_path,start_line,extraction_run_id' })` forwards a column-list to PostgREST's on_conflict param, which resolves to a UNIQUE *index* by column-name match. PostgREST cannot target functional indexes. Same class as `feedback_postgrest_partial_unique_inference.md` memory.
- **Suggested patch:** Add a stored generated column `start_line_key INTEGER NOT NULL GENERATED ALWAYS AS (COALESCE(start_line, -1)) STORED`. Put `start_line_key` in the UNIQUE. `onConflict` targets it as a plain column. Mirrors the `vulnerability_id` GENERATED column already adopted for `idx_pcf_unique`. Add M1 acceptance: insert two findings with NULL start_line via supabase-js, assert second is UPDATE not duplicate INSERT.
- **Flagged by:** data-model-auditor-r2-f1

### 2. GENERATED ALWAYS vulnerability_id rejects upsert payloads
- **Plan section:** `Data Model > Migration > project_container_findings`; `M2 > scanners/storage.ts`
- **Claim:** `vulnerability_id` is `GENERATED ALWAYS AS (COALESCE(osv_id, cve_id, 'unknown:' || md5(...))) STORED`. Postgres rejects INSERT/UPDATE that supplies an explicit value for a `GENERATED ALWAYS` column (other than `DEFAULT`). If the upsert payload is built by spreading scanner output that contains a `vulnerability_id`-shaped field, the INSERT will fail with `cannot insert into column vulnerability_id`.
- **Suggested patch:** Add explicit M2 storage.ts instruction: scrub `vulnerability_id` from payload before `.upsert()`. Add unit test asserting row builder omits it. (Don't switch to `GENERATED BY DEFAULT` — `ALWAYS` is the right invariant.)
- **Flagged by:** data-model-auditor-r2-f2

### 3. Dockerfile FROM enables cross-tenant private-image pull
- **Plan section:** `User Flows step 6`; `M2 > Container scan`; `Dependencies`
- **Claim:** A malicious user in Org A who controls a project's Dockerfile can write `FROM ghcr.io/victim-org/private-image:latest`. The worker, holding the project's GitHub App installation token, attempts the pull. Two failure modes: (1) pull succeeds and Trivy writes the victim's CVE list into Org A's `project_container_findings`, attributable via `image_reference`; (2) pull fails but error logs leak existence/manifest metadata. Returns the cross-tenant leak through the FROM line that the cache cut closed elsewhere.
- **Suggested patch:** Add to M2: (a) For ghcr.io FROM with `<owner>` ≠ project's GitHub App installation account login → skip the pull, log warn, do NOT fall back to anonymous. (b) For non-Docker-Hub-public registries → skip with `step_metadata.skipped_image=private_registry_unsupported_at_v1`. (c) Add backend test: Dockerfile with `FROM ghcr.io/different-org/foo` produces zero container findings + warn step_error. (d) Surface skipped images in `/scanner-summary` so the UI doesn't silently drop them.
- **Flagged by:** multi-tenant-design-auditor-r2-f1

### 4. Worker `organization_id` resolution path unspecified
- **Plan section:** `M2 > scanners/storage.ts`; `Data Model > organization_id columns`
- **Claim:** `upsertIaCFindings(supabase, projectId, organizationId, runId, findings)` takes `organizationId` as a parameter without specifying where the worker resolves it. Must be `(SELECT organization_id FROM projects WHERE id = projectId)` — not from extraction job metadata, not from environment, not from repo content. Otherwise corrupted job records can write findings under wrong org_id, silently surfacing in v1.5 org-rollup queries.
- **Suggested patch:** Either (a) storage.ts MUST resolve via `SELECT FROM projects` inside the helper (not accept as caller param), or (b) add a `BEFORE INSERT` trigger setting `NEW.organization_id = (SELECT organization_id FROM projects WHERE id = NEW.project_id)` so the column is server-derived. Add acceptance test: pass tampered organization_id, assert helper rejects/overrides.
- **Flagged by:** multi-tenant-design-auditor-r2-f2

### 5. Multi-stage Dockerfile selects wrong FROM
- **Plan section:** `User Flows step 6`; `Pipeline Integration > Order`; `M2 > container scan`
- **Claim:** Plan says "parse Dockerfile FROM" (singular) everywhere. Multi-stage builds — extremely common in Node/Python/Go — have multiple FROM directives. If the worker pulls the FIRST FROM (`FROM node:20 AS builder` in a Node→nginx multi-stage), it scans the build-time image instead of the runtime image, producing CVE findings for packages that never ship to production. False-positive avalanche on day one against any real multi-stage repo.
- **Suggested patch:** Replace every "parse Dockerfile FROM line" with "parse Dockerfile FROM directives; v1 selects the FINAL stage image (last FROM) — that's what ships to production." Add M2 acceptance: multi-stage fixture with `FROM node:20 AS builder` + `FROM nginx:alpine` produces findings against nginx, not node. Add adversarial fixtures: multi-stage with intermediate `FROM scratch`, `FROM` with `--platform`, `FROM` with digest pin.
- **Flagged by:** worker-pipeline-auditor-r1-f1

### 6. Down-migration is not self-sufficient
- **Plan section:** `Data Model > Down-migration`; `Rollback & Rollout > Down-migration`
- **Claim:** Rollback SQL contains literal placeholder `-- Restore RPC first (paste prior body here as part of rollback execution)`. The procedure reads "Restore finalize_extraction body from phase19_3 (paste prior body)." A rollback file that requires a human to paste the prior RPC body during an outage is a runbook stub, not a rollback. If steps run in wrong order (drop tables before restoring RPC), `finalize_extraction` throws `relation does not exist` on the next extraction.
- **Suggested patch:** At M1, capture the current `finalize_extraction` body verbatim into a sibling snapshot file `phase19_3_finalize_extraction_rpc_snapshot.sql` (or inline at top of rollback file as `CREATE OR REPLACE FUNCTION` heredoc). Reorder rollback to: 1) restore RPC with prior body, 2) DROP TABLE ..., 3) DROP COLUMN — single transaction. Add M1 acceptance: rollback runs end-to-end via single `psql` invocation, no manual paste.
- **Flagged by:** rollback-planner-r2-f1, skeptic-f7

### 7. Kill-switch behavior has no named test
- **Plan section:** `Rollback & Rollout > Kill switches`; `Testing & Validation Strategy`; `Success Criteria > Test mapping`
- **Claim:** Plan adds Redis kill switches + env feature flags + rollout allowlist. Success Criteria bullet "Kill switches and rollout allowlist function as documented" has NO row in the mapping table — violates the table's stated invariant "(All map to a named test in the table above.)"
- **Suggested patch:** Add three rows to mapping table: kill-switch flip → next-run step warn; feature flag false → step entry skipped; rollout allowlist excludes non-listed org → step skipped. Files: `extraction-worker/test/kill-switch.test.ts`, `feature-flag.test.ts`, `rollout-allowlist.test.ts`.
- **Flagged by:** test-strategy-auditor-r2-f1

### 8. Tenant-isolation enumeration off-by-one (scanner-summary unprotected)
- **Plan section:** `API Design > Endpoints (6 total)` header; `Testing > Tenant isolation`; `Success Criteria > Test mapping`
- **Claim:** API Design table header says "6 total" but contains 7 rows. Testing strategy says "for each of the 6 mutation/list routes". Mapping table says "Tenant isolation on all 6 routes". `GET /scanner-summary` is the 7th endpoint and is NOT in the enumerated tenant-isolation test set. A cross-tenant leak there exposes finding counts for foreign projects without any data row appearing.
- **Suggested patch:** Three coordinated edits: (1) Fix header to "(7 total)". (2) Test bullet: "for each of the 7 endpoints (3 IaC + 3 container + scanner-summary)". Add explicit case: "GET /scanner-summary with foreign projectId → 403". (3) Mapping row: "Tenant isolation on all 7 routes (incl. scanner-summary)".
- **Flagged by:** test-strategy-auditor-r2-f2, pragmatist-f6

### 9. finalize_extraction RPC amendment has no SQL-level test
- **Plan section:** `Data Model > Patch 3: amend finalize_extraction RPC`; `M1 acceptance`; `Testing > Worker integration > Soft-switch carry-forward`
- **Claim:** Patch 3 is the highest-risk migration change — adds two CTEs to a Postgres function that already carries forward 3 other tables. Plan tests it ONLY through e2e fixture extraction. Three blind spots: (a) e2e passes if upsert path also preserves rows (fingerprint match → idempotent upsert lands same status), (b) syntactic mistake in new CTEs could break existing 3-table carry-forward (regression), (c) M1 acceptance says "manual SQL ignore + rerun test" — manual = won't run in CI.
- **Suggested patch:** Add dedicated RPC unit test (Postgres-level, against PGLite or test schema): `backend/database/__tests__/finalize-extraction-phase23.test.sql` with cases: (1) IaC fingerprint carry-forward, (2) Container fingerprint carry-forward, (3) **Regression guard** — assert existing semgrep + secret + dep-vuln carry-forward still works after RPC amendment, (4) NULL fingerprint case → status NOT carried (intentional). Change M1 acceptance from "manual" to "automated test in CI".
- **Flagged by:** test-strategy-auditor-r2-f3

## P1 — High-Priority Gaps

### Plan ambiguity (5)
- **architect-f2** — fingerprint-only carry-forward diverges from semgrep tuple-fallback precedent (`phase19_3_finalize_extraction_rpc.sql` lines 353-374). Either match the pattern (add tuple-fallback CTEs) or document why divergence is intentional.
- **architect-f5** — `projects.infra_types` write coordination ambiguous: inside RPC vs worker-after-RPC. Pick one explicitly. (a) Extend RPC signature to take `p_infra_types TEXT[]`. (b) Worker UPDATE after RPC returns + document the failure window.
- **skeptic-f4** — same ambiguity as architect-f5 from a different angle. Resolve once.
- **architect-f1** — `organization_id NOT NULL` on new tables but not on existing finding tables creates pattern inconsistency. Document rationale OR backfill onto existing tables in a follow-up migration.
- **data-model-auditor-f3** — fingerprint partial UNIQUE indexes need explicit `WHERE fingerprint IS NOT NULL` predicate inside finalize_extraction CTE join (raw SQL, not ORM helper). Document in M1 acceptance.

### Scope (3)
- **pragmatist-f1** — M0 benchmark milestone unfundable in 0.5 day without `deptex-test-iac` / `deptex-test-container` fixtures (which don't exist). Either: cut M0, use upstream-doc defaults, retune from production data; OR budget M0 to 1 day including fixture creation.
- **pragmatist-f2** — Helm at v1 produces low-value findings (default-values rendering). Cut from 4 frameworks to 3 (TF + K8s + Dockerfile). Saves a framework, a fixture, an icon, an open question, the Helm rendering issue.
- **scope-cutter-f1** — `SCANNERS_ROLLOUT_ALLOWLIST` is speculative for a 1-user v1 (per memory `feedback_solo_user_prelaunch.md`). Kill switches + env flags already cover rollback. Cut the allowlist + matching M2 test.

### Multi-tenant (1)
- **multi-tenant-design-auditor-f3** — rescan button permission gating unspecified. Three render sites all say "reuses existing rescan endpoint" without naming the permission. Risk: viewer-role member sees button, gets 403 toast (UX failure) OR existing endpoint isn't tightly gated and viewers can trigger billable extractions. Add: client-side hide based on permission; server-side test that user A in org X cannot POST rescan to project B in org Z.

### Test coverage (3)
- **test-strategy-auditor-f4** — M0 benchmark numbers one-shot; no CI re-verification. Future Trivy/Checkov bumps that get 3× slower silently move wall-clock past timeout. Either promote benchmark to CI smoke job, or persist numbers in `benchmark.snapshot.json` with a Dockerfile-bump reminder.
- **test-strategy-auditor-f5** — Docker smoke test misses Trivy DB acquisition path + Checkov pip-conflict mid-scan. Replace `--version` checks with 1-rule fixture scans inside the actual built image.
- **test-strategy-auditor-f6** — scanner-summary correctness test in Backend bullet but absent from mapping table.

### Rollback / operations (4)
- **rollback-planner-f2** — Redis kill-switch has no fallback if Redis itself is unreachable. Specify: 1s timeout + try/catch → fall back to env flag value; log warn on every Redis fallback.
- **rollback-planner-f3** — `SCANNERS_ROLLOUT_ALLOWLIST` env-only. Each stage requires worker redeploy. Add Redis-overridable `rollout:scanners:allowlist` Set; union both sources at step entry.
- **rollback-planner-f4** — Bad-data recovery `DELETE WHERE scanner_version` indiscriminately wipes user suppressions/risk-accepts. Document tradeoff; add two-stage procedure: backup decisions → purge → restore via fingerprint match.
- **rollback-planner-f5** — M0 has no feedback path back to M2 timeouts. Make M2 explicitly depend on M0; document loop "post-rollout warn rate > 5% → kill switch → adjust env → redeploy → unkill".

### Misc (4)
- **skeptic-f2** — `idx_piacf_fingerprint` partial UNIQUE missing `scanner` column. If Checkov + Trivy ever produce identical fingerprint strings (unlikely but possible), second insert silently replaces first. Either namespace via prefix + add CHECK constraint, OR include `scanner` in the partial UNIQUE.
- **skeptic-f3** — risk-accept routes documented as "project member" only. Existing semgrep/secret risk-accept patterns may use `manage_projects` or `manage_policies` — verify parity with one-line audit task.
- **skeptic-f5** — ghcr.io token mint mechanism not in M2. Either cut ghcr.io private support entirely (public-only at v1) OR explicitly point M2 at the existing GitHub App installation-token-mint path in `backend/src/lib/github`.
- **worker-pipeline-auditor-f2** — image-size fork-point worded as deferred "if". Pin: HARD GATE at 500MB → if exceeded, file follow-up plan, decision-owner = Henry.

### Schema (1)
- **data-model-auditor-f4** — fingerprint NULL-fallback policy documented for the table but not enforced in scanner code. Implementer might synthesize a degenerate fingerprint like `checkov::Dockerfile` that collides across unrelated findings. Add explicit policy + unit test: empty resource_address → `iac_fingerprint = null`, never a degenerate string.

## P2 — Quality Gaps

- **skeptic-f1** — M0 fixture realism (covered by P1 pragmatist-f1).
- **skeptic-f6** — Trivy DB on /data volume is a small piece of shared mutable state; document refresh cadence + download-failure behavior.
- **skeptic-f8** — `storage.ts` duplicates existing semgrep/secret upsert patterns; audit for shared helper opportunity.
- **pragmatist-f3** — `assertNever` introduction underdescribed; M4 needs to scope the if-chain → switch refactor (~17 sites in `VulnerabilityExpandableTable.tsx` per pragmatist's grep).
- **pragmatist-f4** — `InfraScannerTile` on project overview is uncommitted scope from opportunity-scout; consider cutting.
- **pragmatist-f5** — v1.5 deferral list verbose; trim parenthetical justifications.
- **pragmatist-f7** — `scanners/storage.ts` overkill for 2 functions; inline into checkov.ts/trivy.ts.
- **scope-cutter-f2** — scanner-summary endpoint + InfraScannerTile not v1-essential.
- **scope-cutter-f3** — `organization_id` denormalization without v1 consumer is dead weight at v1.
- **scope-cutter-f5** — down-migration overengineered; kill switches already cover rollback (debate against P0 #6's hardening — pick one direction).
- **architect-f3** — fingerprint format invariant in prose, no DB-level enforcement; add unit test asserting fingerprint shape.
- **architect-f4** — `runScannerSubprocess` signature drops `logger` + `verbose-log` from `runDepScan`; restore them and remove `parser` from helper concerns.
- **test-strategy-auditor-f7** — detect-infra fixture count drift (M5 says 10, bullet enumerates 5 positives only).
- **data-model-auditor-f5** — future GIN-on-infra_types add must use `CREATE INDEX CONCURRENTLY`; document.
- **data-model-auditor-f6** — `(organization_id, status, depscore DESC NULLS LAST)` composite indexes serve no v1 query; defer or document.
- **multi-tenant-design-auditor-f4** — `organization_id` column dead weight at v1 (no v1 query exercises invariant); add v1 read path OR defer index.
- **multi-tenant-design-auditor-f5** — Trivy auth flag (`--username/--password` vs `DOCKER_AUTH_CONFIG`) leakage path; require `DOCKER_AUTH_CONFIG` env to keep token out of argv.
- **worker-pipeline-auditor-f3** — `runScannerSubprocess` heartbeat interval not pinned; default to 60s + drop `parser` from helper.
- **worker-pipeline-auditor-f4** — Checkov requires `helm` CLI on PATH for Helm rendering; not in Dockerfile bullet. (Falls out if pragmatist-f2 cuts Helm.)
- **rollback-planner-f6** — Rollback procedure has no verification step.
- **scope-cutter-f6** — v1.5/v2 markers throughout plan are bookkeeping pollution; trim.
- **scope-cutter-f4** — `runScannerSubprocess` extraction in M2 is premature; defer to v2.1.

## P3 — Nits & Opportunities

### Opportunities (opportunity-scout, all P3)
- **f1** — Aegis Fix Agent Dockerfile stub (~1 day; Fix Agent shipped 2026-04-29; flips OSS-launch story from detection-only to detection+fix).
- **f2** — `v_iac_coverage_stats` SQL view in M1 (~30 min; pre-stages v2.17 marketing wedge).
- **f3** — `v_scanner_summary` view to make /scanner-summary single index-scan (~20 min; answers Open Question by construction).
- **f4** — Container reachability via tree-sitter is **NOT** a 1-day lift; cross-namespace mismatch (tree-sitter parses source-package usage, not OS-package usage). Future v2 expansion item should be reworded.
- **f5** — Per-scanner `step_metadata` emission for ops + future v2.12 priority.
- **f6** — Repo-connect preview detect-infra timing problem (badges populate post-extraction, not pre-connect — defeats the Aikido onboarding wedge claim).
- **f7** — OSS-launch doc deferred to existing `future_oss_launch_prep.md` checklist.
- **f8** — Image-staleness signal in container card (~3 hours; differentiation against Snyk/Aikido).

## Open Debates (Disputed Findings)

None. The 9 REVISE / 1 READY / 0 REWORK split reflects severity calibration on a plan that's directionally correct.

One genuine cross-persona tension worth flagging:
- **scope-cutter-f5** says cut the down-migration entirely (kill switches cover rollback).
- **rollback-planner-r2-f1** says harden the down-migration (capture prior RPC body verbatim, single-transaction).
- **Resolution:** these aren't contradictory if read carefully. Rollback path = (1) flip kill switches → no new rows; (2) for permanent abandonment, `git revert` the migration commit. The current rollback SQL file's manual-paste placeholder is fragile *if used*. So either delete the file (scope-cutter's path) and document `git revert` as the abandonment path, OR keep the file and harden it (rollback-planner's path). Pick one and commit.

## Suggested Plan Amendments

### Patch A — Fix functional UNIQUE incompatibility (P0 #1)

Add to `phase23_iac_container_scanning.sql`:
```sql
ALTER TABLE project_iac_findings
  ADD COLUMN start_line_key INTEGER NOT NULL
  GENERATED ALWAYS AS (COALESCE(start_line, -1)) STORED;

DROP INDEX IF EXISTS idx_piacf_unique;
CREATE UNIQUE INDEX idx_piacf_unique
  ON project_iac_findings (project_id, rule_id, file_path, start_line_key, extraction_run_id);
```
M2 storage.ts `onConflict: 'project_id,rule_id,file_path,start_line_key,extraction_run_id'`. Add M1 acceptance: insert two findings with NULL start_line via supabase-js, assert second is UPDATE.

### Patch B — Scrub vulnerability_id from upsert payload (P0 #2)

Add to M2 task list:
> When upserting into `project_container_findings`, scrub `vulnerability_id` from the row payload before `.upsert()` (it is `GENERATED ALWAYS`). Unit test: row builder explicitly omits `vulnerability_id`.

### Patch C — Dockerfile FROM namespace validation (P0 #3)

Add to M2 (new section "Container scan tenant safety"):
```
For each FROM line resolved during container scan:
- If FROM image is on docker.io/<library/...> (public Docker Hub) → pull anonymously, scan.
- If FROM image is on ghcr.io/<owner>/...:
  - Resolve <owner>; verify <owner> matches the GitHub App installation account login attached to the project (projects.github_installation_id → installation.account.login).
  - On mismatch → skip pull, log warn step_metadata.skipped_image=ghcr_namespace_mismatch, do NOT fall back to anonymous.
- Any other private-shaped registry host → skip with step_metadata.skipped_image=private_registry_unsupported_at_v1.
- Surface skipped images via /scanner-summary so users see them in UI.
```
Add M5 acceptance test: Dockerfile with `FROM ghcr.io/different-org/foo` produces zero container findings + warn `step_error`.

### Patch D — organization_id resolution invariant (P0 #4)

Add to M2 storage.ts spec:
> `upsertIaCFindings` and `upsertContainerFindings` MUST resolve `organization_id` via `SELECT organization_id FROM projects WHERE id = $projectId` inside the helper (not accept as caller param). Negative test: passing a tampered organization_id is rejected/overridden by the resolved value.

OR add a `BEFORE INSERT` trigger:
```sql
CREATE OR REPLACE FUNCTION enforce_finding_org_id() RETURNS TRIGGER AS $$
BEGIN
  NEW.organization_id := (SELECT organization_id FROM projects WHERE id = NEW.project_id);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER project_iac_findings_org_id_enforce
  BEFORE INSERT OR UPDATE ON project_iac_findings
  FOR EACH ROW EXECUTE FUNCTION enforce_finding_org_id();
-- same for project_container_findings
```

### Patch E — Multi-stage Dockerfile final-stage selection (P0 #5)

Replace every "parse Dockerfile FROM line" → "parse Dockerfile FROM directives; v1 selects the FINAL stage image (last FROM in order), not the first; this is the production-shipping image. Multi-stage builders intermediate stages are NOT scanned at v1."

Add fixture cases: multi-stage with `FROM scratch` intermediate, `FROM` with `--platform=linux/amd64`, `FROM` with `@sha256:...` digest pin.

### Patch F — Self-sufficient down-migration (P0 #6)

At M1, capture verbatim: paste the current `finalize_extraction` body into the rollback SQL file as the first `CREATE OR REPLACE FUNCTION ...` block (no `...` placeholder). Reorder rollback to: (1) restore RPC, (2) DROP TABLE, (3) DROP COLUMN — single transaction. Add M1 acceptance: rollback SQL runs end-to-end via `psql -f` against staging copy with no manual paste step; subsequent extraction completes successfully.

### Patch G — Three new test mapping rows (P0 #7, #8, #9)

Add to `Success Criteria → Test mapping`:
| Success criterion | Named test | File |
|---|---|---|
| Kill switch (Redis) flipped → next-run step warn | kill-switch e2e | `extraction-worker/test/kill-switch.test.ts` |
| Feature flag (`SCANNERS_*_ENABLED=false`) disables step | flag-gate e2e | `extraction-worker/test/feature-flag.test.ts` |
| Rollout allowlist excludes non-listed org → step skipped | allowlist e2e | `extraction-worker/test/rollout-allowlist.test.ts` |
| Tenant isolation on all 7 routes (incl. scanner-summary) | per-route 403 test | `backend/src/routes/__tests__/scanner-findings.test.ts` |
| scanner-summary returns correct rollup counts | rollup correctness | (same file) |
| finalize_extraction RPC carry-forward (IaC + container fingerprint match, regression guard for existing tables, NULL fingerprint policy) | RPC unit test | `backend/database/__tests__/finalize-extraction-phase23.test.sql` |

Fix API Design header from "(6 total)" → "(7 total)". Update Testing > Backend bullet from "for each of the 6 mutation/list routes" → "for each of the 7 endpoints (3 IaC + 3 container + scanner-summary)".

## Findings by Axis

| Axis | Count | Highest severity | Personas |
|---|---|---|---|
| upsert-target-mismatch / supabase-js-incompat | 3 | P0 | data-model-auditor |
| cross-tenant-leak (post-cuts) | 2 | P0 | multi-tenant-design-auditor |
| missing-test / coverage-gap | 7 | P0 | test-strategy-auditor |
| dockerfile-parsing | 1 | P0 | worker-pipeline-auditor |
| down-migration / rollback-realism | 4 | P0 | rollback-planner, skeptic |
| pattern-divergence / inconsistency | 3 | P1 | architect, skeptic |
| scope-still-trim-able | 5 | P1 | pragmatist, scope-cutter |
| infra_types-write-path-ambiguity | 2 | P1 | architect, skeptic |
| operational-gap / fallback / verification | 5 | P1 | rollback-planner |
| rbac-permission-detail | 2 | P1 | skeptic, multi-tenant-design-auditor |
| premature-abstraction / dead-weight | 4 | P2 | scope-cutter, multi-tenant-design-auditor |
| documentation / bookkeeping | 4 | P2/P3 | scope-cutter, pragmatist |
| opportunity (P3) | 8 | P3 | opportunity-scout |

## Persona Coverage Map

| Persona | R1 findings | P0 count | R1 clean lenses | Vote |
|---|---|---|---|---|
| skeptic | 8 | 0 | 12 | REVISE |
| pragmatist | 7 | 0 | 21 | REVISE |
| scope-cutter | 6 | 0 | 11 | REVISE |
| architect | 5 | 0 | 10 | REVISE |
| test-strategy-auditor | 7 | 3 | 6 | REVISE |
| opportunity-scout | 8 | 0 | 13 | READY |
| data-model-auditor | 6 | 2 | 11 | REVISE |
| multi-tenant-design-auditor | 5 | 2 | 9 | REVISE |
| worker-pipeline-auditor | 4 | 1 | 8 | REVISE |
| rollback-planner | 6 | 1 | 8 | REVISE |
| **Total** | **62** | **9** | **109** | 1R / 9Rev / 0Rew |

The clean_lenses count (109) vs findings count (62) shows the patches landed broadly — every persona had more areas they actively cleared than concerns they raised.

## Recommended Next Step

Apply Patches A–G (the 9 P0 fixes) directly to `iac-container-scanning.plan.md`. Estimated effort:
- Patches A + B + D (schema/upsert): ~30 min plan edit + ~30 min M1/M2 spec
- Patch C (Dockerfile FROM namespace check): ~30 min spec, ~half-day implementation in M2
- Patch E (multi-stage Dockerfile): ~15 min plan edit, ~half-day implementation in M2
- Patch F (down-migration self-sufficiency): ~15 min plan edit
- Patch G (test mapping): ~15 min plan edit

Optionally apply high-value P1s:
- Cut M0 + Helm + rollout allowlist (~15 min, drops v1 to ~9-10 days)
- Resolve infra_types write-path ambiguity (5 min wording)
- Pin runScannerSubprocess signature with logger param (5 min wording)
- Add fingerprint scanner column to partial UNIQUE (5 min schema edit)
- Resolve scope-cutter-f5 vs rollback-planner-r2-f1 debate (pick one rollback path, document)

Then re-run `/review-plan --no-debate` to confirm READY (or skip to `/implement` if confident — at this point patches are mostly mechanical and the architecture is settled).

If you'd like, say "apply patches" and I'll edit the plan with all P0 patches.
