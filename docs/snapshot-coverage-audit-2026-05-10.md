# Snapshot Coverage Audit — 2026-05-10

**Scope.** Every fixture under `depscanner/fixtures/` and every JSON output the
extraction CLI emits, mapped against the `DEFAULT_IGNORE_FIELDS` in
`depscanner/test/snapshot.ts:68-103` and the per-fixture
`snapshot-ignore.json`. The question this audit answers: when a contributor
edits a framework spec or pipeline step, will the snapshot suite reliably
catch the regression, or will load-bearing fields slip through as
"ignored noise"?

**Source of truth.** `depscanner/src/cli/output.ts` is the writer for every
file under `snapshots/`. Eight files exist in the pipeline contract:

| File | Writer | Source table |
|------|--------|--------------|
| `summary.json` | `output.ts:102` | synthesised (counts + finalize) |
| `deps.json` | `output.ts:103` | `project_dependencies` |
| `vulns.json` | `output.ts:104` | `project_dependency_vulnerabilities` |
| `semgrep.json` | `output.ts:105` | `project_semgrep_findings` |
| `secrets.json` | `output.ts:106` | `project_secret_findings` |
| `reachable_flows.json` | `output.ts:107` | `project_reachable_flows` |
| `entry_points.json` | `output.ts:108` | `project_entry_points` |
| `generated_rules.json` *(opt)* | `output.ts:114` | `organization_generated_rules` |
| `rule_generation_telemetry.json` *(opt)* | `output.ts:118` | derived from `scan_jobs` |

`generated_rules.json` and `rule_generation_telemetry.json` are only emitted
when at least one row exists, so absence is expected on minimal fixtures.

---

## 1. Per-fixture snapshot coverage

| Fixture | summary | deps | vulns | semgrep | secrets | reachable_flows | entry_points | generated_rules | rule_gen_telemetry |
|---------|:-------:|:----:|:-----:|:-------:|:-------:|:---------------:|:------------:|:---------------:|:------------------:|
| `test-empty` | n/a (`expectClean=false`, exit 2 — pipeline never finalises) |
| `test-minimal-npm` | YES | YES | YES (5 rows) | YES ([]) | YES ([]) | YES ([]) | YES ([]) | NO | NO |
| `test-npm` *(slow)* | YES | YES (1374 lines) | YES (1328 lines) | NO | YES (1 row) | YES ([]) | YES ([]) | NO | NO |
| `test-python` *(slow)* | YES | YES | YES | NO | YES ([]) | YES ([]) | YES ([]) | NO | NO |
| `test-java` *(slow)* | YES | YES | YES | NO | YES ([]) | YES ([]) | YES ([]) | NO | NO |
| `test-go` *(slow)* | YES | YES | YES | NO | YES ([]) | YES ([]) | YES (2 routes) | NO | NO |

**Findings.**
- `semgrep.json` is snapshotted on `test-minimal-npm` only. The four slow
  fixtures all emit semgrep output but never wrote a snapshot — a Semgrep
  rule regression on Python/Go/Java/larger-npm goes unnoticed.
- `generated_rules.json` and `rule_generation_telemetry.json` have zero
  coverage. Even `test-minimal-npm` doesn't trigger rule generation, so an
  AI-rule-gen regression (Phase 5 / Phase 6.5) only fails through
  separate test suites.
- `entry_points.json` is meaningful only on `test-go` (2 rows). Every other
  fixture has `[]`. Express, FastAPI, Spring, Flask, Django, Rails, Sinatra
  framework specs ship **without an end-to-end snapshot** that locks the
  contract between `framework_models/*.yaml` and the `entry_points` table.
- `reachable_flows.json` is `[]` on every fixture. There is no fixture in
  this directory tree where a reachable flow snapshot exists. The 34
  framework fixtures at `depscanner/test/fixtures/frameworks/<slug>/` are
  consumed by the taint-engine preflight (`npm run test:taint-engine-all`),
  **not** by the snapshot runner, and they only test the engine — not the
  CLI binding from input to `reachable_flows.json`.

---

## 2. Per-file load-bearing fields (pinned vs leaking vs ignored)

The `stripIgnored` walker recurses into objects and arrays, dropping any key
present in `DEFAULT_IGNORE_FIELDS ∪ fixtureIgnore`. There is no path-aware
matching — a key called `id` is stripped wherever it appears.

### 2.1 `vulns.json`

**Currently pinned (good — these would catch real regressions):**
- `osv_id`, `severity`, `summary`, `fixed_versions`
- `is_reachable`, `reachability_level`, `reachability_status`,
  `reachability_details`
- `depscore`, `base_depscore_no_reachability`, `contextual_depscore`
- `epd_factor`, `epd_depth`, `epd_alpha`, `epd_confidence_tier`,
  `epd_model`, `epd_schema_version`, `epd_prompt_version`, `epd_status`
- `entry_point_classification`, `entry_point_weight`
- `sink_precondition`, `sanitization_postcondition`, `is_sanitized`
- `status`, `suppressed`, `risk_accepted`, `re_review_reasons`

**Currently ignored (intentional — daily-drift volatile):**
- `epss_score`, `cvss_score`, `cisa_kev`, `published_at`

**Leaking through (BUG — these fields are in committed snapshots despite the
ignore list):**
- `epss_score`, `published_at`, `cvss_score`, `cisa_kev` in
  `fixtures/test-npm/snapshots/vulns.json` and the other slow-fixture
  snapshots. The ignore list was added after these snapshots were
  bootstrapped; the older snapshots were never re-stripped.
- **Action:** re-strip every committed snapshot with the current ignore
  list. Done as a follow-up commit so the diff is auditable.

**Still missing from the ignore list (recommendations):**
- `last_vuln_check_at`, `last_webhook_at` (already in ignore — OK).
- `aliases` is null today but is a list keyed off live GHSA data — when
  GHSA backfills CVE → GHSA aliases this will flip and cause diff churn.
  **Recommendation:** keep pinning `aliases` and accept the regen; this
  is a real signal that GHSA data changed.

### 2.2 `deps.json`

**Pinned:** `name`, `version`, `is_direct`, `source`, `environment`,
`is_outdated`, `versions_behind`, `namespace`, `files_importing_count`,
`policy_result`.

**Ignored (intentional):** `id`, `project_id`, `dependency_id`,
`dependency_version_id`, `created_at`, `updated_at`, `first_seen_at`,
`last_seen_at`, `ast_parsed_at`, `policy_evaluated_at`,
`ai_usage_analyzed_at`.

**Pinned but field is null on every fixture:** `ai_usage_summary`,
`ai_usage_analyzed_at` (null today; will tick once Aegis usage analysis
runs against fixtures — acceptable churn).

**No fields leaking.** The ignore list covers deps.json correctly.

### 2.3 `reachable_flows.json`

Every committed snapshot is `[]`. The schema-pinning analysis below is
**aspirational** — no current fixture exercises it.

**Should pin (per `cve-targeted-flow-fixtures/*/spec.json` shape):**
- `osv_id`, `flow_signature_hash` (hash of source→sink path)
- `source_class`, `source_method`, `source_file`, `source_line`
- `sink_class`, `sink_method`, `sink_file`, `sink_line`
- `sanitizer_chain` (ordered list of sanitizer names hit between
  source and sink — empty list locked is just as load-bearing as a
  filled list)
- `flow_length`, `reachability_source` (`framework_model` /
  `cve_targeted` / `generic`)
- `entry_point_file`, `entry_point_tag`, `framework`

**Should ignore:**
- `id`, `project_id`, `extraction_run_id` (already in default list)
- `created_at`, `updated_at`, `detected_at` (already in default list)
- `flow_extracted_at`, `confidence_calibrated_at` (NOT in default list
  today — add when first reachable-flow fixture lands)

### 2.4 `entry_points.json`

Currently only `test-go` has rows.

**Pinned (verified against test-go/snapshots/entry_points.json):**
- `file_path` (note: contains `/workspace/` — a Docker bind-mount artifact
  that is stable across runs, NOT a contributor-local path. Safe to pin.)
- `line_number`, `framework`, `handler_name`, `http_method`,
  `route_pattern`, `entry_point_type`, `classification`,
  `authenticated`, `auth_mechanism`, `middleware_chain`, `metadata`.

**No fields leaking.** This is the most disciplined snapshot file today.

**Field-rename risk:** if `entry_point_type` is renamed to `tag` in the
schema (proposed in entry-point classifier roadmap), the snapshot diff
will catch it loud — good.

### 2.5 `summary.json`

**Pinned:** `schema_version`, `project_name`, `ecosystem`,
`*_count` (dependencies, vulnerabilities, semgrep, secrets,
reachable_flows, entry_points), `finalize_summary.reap.*_deleted`,
`finalize_summary.{vulns_new, deps_removed, sla_computed,
vulns_reopened, rereview_enabled, vulns_critical_new,
vulns_carried_forward, vulns_re_review_fired}`.

**Ignored:** `organization_id`, `project_id`, `extraction_run_id`,
`duration_ms`, plus per-fixture `active` + `previous` (inside
`finalize_summary.reap`).

**No fields leaking** but **gap:** `finalize_summary.vulns_new` etc. are
pinned numbers — a pipeline step that double-counts will produce a
diff. Good. `finalize_summary.reap.*_deleted` are pinned to 0 today on
every fresh fixture (no prior run) — a reap-logic regression that
flips them to N would surface immediately.

### 2.6 `semgrep.json`

Only `test-minimal-npm` snapshots this file (`[]`). The strip walker
strips: `id`, `project_id`, `dependency_id`, `created_at`, `updated_at`,
`detected_at`.

**Schema check (against `src/scanners/semgrep.ts` + DB schema):**
- Load-bearing: `rule_id`, `severity`, `file_path`, `start_line`,
  `end_line`, `code_snippet`, `message`, `metadata.cwe`, `metadata.owasp`,
  `is_reachable`, `reachability_level`, `depscore`, `status`,
  `suppressed`, `risk_accepted`.
- Volatile: `metadata.semgrep_version` (would diff on every Semgrep
  upgrade — add to ignore list when first semgrep fixture lands).
  **Not currently in `DEFAULT_IGNORE_FIELDS`** but `[]` snapshots hide
  this gap.

### 2.7 `secrets.json`

Only `test-npm` has a non-empty snapshot (1 row).

**Pinned:** `detector_type`, `file_path`, `start_line`, `is_verified`,
`is_current`, `description`, `redacted_value`, `depscore`, `status`,
`code_snippet`.

**Risk:** `code_snippet` includes the literal file bytes around the
match. If the contributor changes `config/secrets.js` (the synthetic
secrets file inside `test-npm/`), the snippet drifts — but that's
**intentional**, since changing the fixture should change the
snapshot. Don't add to ignore.

**Risk:** `redacted_value` is computed by TruffleHog. A TruffleHog
upgrade that changes redaction width (`post...5432` → `pos...432`)
would diff. That IS load-bearing (we promise redaction shape to UI).
Keep pinned.

### 2.8 `generated_rules.json` *(no current fixture exercises this)*

Schema (per `organization_generated_rules` table):
- Pin: `vuln_class`, `osv_id`, `dependency_name`, `rule_yaml` (string —
  full rule body), `validation_status`, `validation_breakdown`,
  `confidence`, `generation_source`.
- Ignore: `id`, `organization_id`, `rule_id` (UUID), `created_at`,
  `generated_at`, `generation_cost_usd` (drifts with provider pricing),
  `generation_model_version`.

**Recommendation:** add `generation_cost_usd`,
`generation_model_version`, `generated_at`, `rule_id` to
`DEFAULT_IGNORE_FIELDS` proactively. They will exist as soon as one
rule-gen fixture lands; ignoring them up-front avoids re-strip churn.

### 2.9 `rule_generation_telemetry.json` *(no current fixture)*

Schema (per `extractRuleGenTelemetry` in `output.ts:136-153`):
- Pin: `status`, `rules_total_detectable`, `rules_matched`,
  `generated_this_scan`, `validation_breakdown`.
- Ignore: `extraction_run_id` (already in default), `generation_cost_usd`
  (drifts with pricing — add to default ignore).

---

## 3. Critical gaps (priority-ordered)

| # | Gap | Impact | Fix surface |
|---|-----|--------|-------------|
| 1 | Old `vulns.json` snapshots still contain `epss_score`, `cvss_score`, `cisa_kev`, `published_at` despite the ignore list. | False-positive diffs every day as live EPSS/NVD data drifts. | Re-strip and re-commit. |
| 2 | No reachable-flow snapshot ANYWHERE. The single most important contract (framework spec → flow) is untested end-to-end. | Editing `express.yaml` produces a green default suite. | Add Express reachable fixture (covered in `docs/contributor-test-infra-plan.md` §2). |
| 3 | `semgrep.json` only snapshotted on minimal-npm. No coverage for Python / Java / Go semgrep findings. | Semgrep pack regressions land silently. | Bootstrap snapshots for the four slow fixtures (one-shot `--update` per fixture). |
| 4 | `entry_points.json` has zero coverage outside `test-go`. 33 framework specs ship untested at the snapshot layer. | Spec rename / source-list narrowing goes unnoticed. | Add 10+ small fixtures (this marathon tick). |
| 5 | `generated_rules.json` + `rule_generation_telemetry.json` have zero coverage. | Phase 5 / Phase 6.5 regressions land silently. | Add a rule-gen fixture with a known CVE that triggers generation. Deferred. |
| 6 | `generation_cost_usd`, `generation_model_version`, `generated_at` not in `DEFAULT_IGNORE_FIELDS`. | First rule-gen fixture would diff on every regen. | Proactive add (this tick). |
| 7 | `semgrep_version`, `flow_extracted_at` not in `DEFAULT_IGNORE_FIELDS`. | First semgrep / flow fixture would diff on tool upgrade. | Proactive add (this tick). |
| 8 | No meta-test for the snapshot runner itself (bootstrap path, diff-detection path, ignore-list path). | Runner bugs (like the `--diff-only` precedence bug fixed earlier) silently break the suite. | Add `test/snapshot.test.ts` jest suite (this tick). |

---

## 4. Recommended `DEFAULT_IGNORE_FIELDS` additions (this tick)

```diff
  const DEFAULT_IGNORE_FIELDS = new Set([
    'id',
    ...
    'epss_score',
    'cvss_score',
    'cisa_kev',
    'published_at',
+   // Rule generation — drifts with AI provider pricing and model rotation.
+   // The pinned-value list (vuln_class, osv_id, rule_yaml, validation_*)
+   // is what we promise the contract on.
+   'generation_cost_usd',
+   'generation_model_version',
+   'generated_at',
+   'rule_id',
+   // Tool version stamps — drift on Semgrep / TruffleHog / cdxgen upgrade
+   // without semantic change. The finding's file:line + rule_id + severity
+   // is what we contract on; the tool version inside metadata is noise.
+   'semgrep_version',
+   'trufflehog_version',
+   'cdxgen_version',
+   // Flow timestamps — added when reachable-flow snapshots land.
+   'flow_extracted_at',
+   'confidence_calibrated_at',
  ])
```

Adding these now is free — every field is either absent or null on every
current fixture. The cost of adding later is `--update` churn against
every fixture that picks up rule-gen / semgrep output.

---

## 5. Out of scope

- **34 framework fixtures at `test/fixtures/frameworks/`.** They are
  consumed by the taint-engine preflight, not the snapshot runner. Cross-
  wiring them into the snapshot suite is a separate plan (Section 7 of
  `docs/contributor-test-infra-plan.md`).
- **Field-path-aware ignore matching.** `stripIgnored` is key-name-based,
  so adding `created_at` to the ignore list strips it everywhere. That
  is a coarse semantic but correct for every current field. A nested-
  path syntax (`vulns[].metadata.semgrep_version`) is future work if a
  load-bearing field ever collides with an unrelated volatile sibling.
- **88-CVE corpus snapshots.** Out of scope per marathon brief — Wave-7
  has a separate agent on that corpus.
