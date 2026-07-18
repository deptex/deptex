# Evaluate Findings

You are running a multi-agent **findings quality review** of a real Deptex scan. For a given project's active extraction run, you pull every finding we'd show the user, read the *actual source the finding points at*, cross-check it against the live DB context (reachability, taint flows, EPD entry-point class, scores), and judge each one: is this a true positive, a false positive, noise, a duplicate, mis-scored, or correctly-found-but-badly-presented?

This is `/criticalreview` pointed at **live findings data** instead of a code diff. The goal is the same bar Henry keeps repeating: **minimal noise for the user.** Every finding we surface should be real, correctly classified, de-duplicated, and presented honestly. Anything that fails that bar is a finding *about the scanner*, with a concrete recommended fix.

**This skill never auto-fixes.** It gathers verdicts and hands them back to Henry to discuss and fix together. (That is the whole point — he said "come back to me with the results and we'll talk about it and fix it.")

This command is Deptex-specific. It knows the scan schema, the reachability ladder, and the real noise classes we've hit (absence-check FPs, cross-scanner duplicates, stale-run rows, flow mis-attribution).

## Invocation

Parse arguments from the user's message:
- `/evaluate-findings` — resolve the project from context (the one Henry's currently looking at / the active dogfood project). If ambiguous, list candidate projects and ask which one.
- `/evaluate-findings <project-name-or-id>` — evaluate that project's active run.
- `/evaluate-findings <project> --scanner=<sca|semgrep|secrets|iac|container|dast>` — scope to one finding source.
- `/evaluate-findings <project> --noise-only` — only surface findings that fail the bar (FP / NOISE / DUPLICATE / BAD_DATA / MISLEADING); skip clean true-positives in the report body.
- `/evaluate-findings <project> --deep` — one evaluator agent per finding (max fan-out). Default clusters by dependency/file first to save tokens.

## Phase 0 — Resolve project + active run

All scan data is **per extraction run**. Only the active run is user-visible. Never evaluate stale-run rows.

1. Resolve the project id. If given a name, look it up via the Supabase MCP:
   ```sql
   SELECT id, name, organization_id, active_extraction_run_id
   FROM projects WHERE name ILIKE '%<arg>%';
   ```
   If no arg and the context names a project (e.g. the one in a screenshot), use that. If still ambiguous, list `projects` (id, name, last_scan) and ask.
2. Capture `active_extraction_run_id`. If it's NULL, stop: "Project has no completed scan — nothing to evaluate."
3. Identify the repo source so evaluators can read the real code (Phase 2).

**Dogfood quick-reference** (current corpus — remove when the dogfood phase closes):
- Supabase project ref: `avvqoafdovhyssxntmfi`
- dogfood-express: project `5ff8b1c6-19f6-4a72-a06e-74b9ff90c4c4`, org `5a7b7c20-8d56-4005-9a8e-9ee63391b102`, source at `depscanner/test-repos/express/`
- The other 11 fixtures live under `depscanner/test-repos/<framework>/`.

## Phase 1 — Gather every finding (scoped to the active run)

Query each finding source via the Supabase MCP, always filtering `extraction_run_id = <active>` (and `project_id`). This is the exact surface the user sees:

| Source | Table | Key columns to pull |
|---|---|---|
| SCA / dependency CVEs | `project_dependency_vulnerabilities` (PDV) | `osv_id, severity, reachability_level, is_reachable, runtime_confirmed_at, depscore, contextual_depscore, cvss_score, epss_score, cisa_kev, entry_point_classification, epd_status, suppressed, aliases, summary, fixed_versions, project_dependency_id` |
| Taint flows (per CVE) | `project_reachable_flows` | `osv_id, entry_point_file, entry_point_line, entry_point_method, entry_point_tag, sink_file, sink_line, sink_method, flow_length, reachability_source, flow_signature_hash, flow_nodes` |
| SAST | `project_semgrep_findings` | `rule_id, severity, file_path, start_line, cwe_ids, category, code_snippet` |
| Secrets | `project_secret_findings` | (TruffleHog) `detector_type, file_path, verified` |
| IaC | the Checkov findings table | `rule_id, severity, file_path, resource` |
| Container | the container/image CVE table | `osv_id, base_image, severity` |
| DAST | `project_dast_findings` | keyed by `dast_run_id` (not `extraction_run_id`); `alert, url` |

Notes / gotchas (verified — don't re-derive):
- PDV is the source of truth for what shows as a "finding" + its reachability/score. **A vuln is auto-triaged ("Auto Ignored") when** `reachability_level ∈ {unreachable}` OR `is_reachable=false` (→ Not reachable), or `reachability_level=module` (→ Not confirmed reachable); `confirmed`/`data_flow` and `runtime_confirmed_at` stay active.
- `project_reachable_flows.osv_id` ties a flow to its CVE. Two CVEs on one dependency that share a sink each own separate flow rows — do not treat them as one.
- `project_dependencies` uses `environment` (not `is_dev`) and has `removed_at`; PDV does **not** have `removed_at`. `extraction_run_id` is text.
- Cross-scanner overlap is real: Checkov owns IaC (k8s + Dockerfile via `CKV_*`); Semgrep's `yaml.kubernetes.*` / `dockerfile.*` packs double-report the same misconfig. We already filter those in `depscanner/src/pipeline-steps/semgrep.ts`.

Build a **findings inventory** (held in working memory): one row per finding with its source, identifier, location, severity, and the reachability/score/EPD context.

## Phase 2 — Get the real source

Evaluators must read the code, not guess. Resolve the working tree:
- **Dogfood project** → `depscanner/test-repos/<framework>/` (already on disk).
- **Real project** → clone the connected repo at the scanned commit (use the repo integration / `git clone`), or read the uploaded source from the `project-imports` storage bucket for that run. If neither is available, flag that evaluators are running **doc-only** (lower confidence) and proceed.

## Phase 3 — Fan out evaluators (parallel)

Cluster the inventory first (default): group by `dependency` (SCA) or by `file` (SAST/IaC/secrets) so co-located findings are judged together (this is how you catch duplicates and same-root-cause clusters). In `--deep` mode, one agent per finding.

Spawn evaluators **in parallel** as `general-purpose` subagents (one tool-call batch). Each gets the stable project/run context first (cache-friendly), then its cluster. Each evaluator MUST:
1. Read the exact file(s)/line(s) the finding points at.
2. Reconcile the DB context (reachability, flows, EPD class, scores) against what the code actually does.
3. Judge against the rubric below.
4. Return strict JSON (no prose):

```json
{
  "finding_id": "<source>:<identifier>@<file:line>",
  "verdict": "TRUE_POSITIVE | FALSE_POSITIVE | NOISE | MISCLASSIFIED_REACHABILITY | DUPLICATE | BAD_DATA | MISLEADING_PRESENTATION",
  "confidence": "high | medium | low",
  "what_user_sees": "<one line: how it renders today>",
  "ground_truth": "<what the code actually does — cite file:line>",
  "why": "<the gap, in one or two sentences>",
  "recommended_action": "<concrete: filter rule X / reclassify to <level> / cluster with <other finding> / fix scorer / fix endpoint <file:line> / fix fixture / add contextual summary / keep as-is>",
  "duplicate_of": "<finding_id or null>"
}
```

### Rubric (the noise taxonomy)

- **TRUE_POSITIVE** — real, reachable (or correctly unreachable), correctly scored, honestly presented. Keep.
- **FALSE_POSITIVE** — describes a vuln that is not actually exploitable in *this* code. (e.g. CSRF "missing middleware" on a GET-only / token-auth API; a sink that's guarded by a sanitizer the rule missed.)
- **NOISE / low-signal** — context-blind best-practice nudge that fires on nearly every project (absence checks, INFO-severity "audit" rules with no reachability signal). Real-but-not-worth-a-line.
- **MISCLASSIFIED_REACHABILITY** — the reachability level is wrong vs. the code: marked reachable/`module` but no real usage (should be unreachable), or marked unreachable but there's a genuine call path (should be ≥ module). This is the highest-value class — it's the core product promise.
- **DUPLICATE** — same root cause as another finding: same dep+sink across two advisories, or one misconfig reported by two scanners. Should be clustered/deduped, not listed N times.
- **BAD_DATA** — stale-run row, wrong/missing field, score off, flows mis-attributed. A pipeline/endpoint bug, not a scanner-rule problem.
- **MISLEADING_PRESENTATION** — correct finding, confusing display: anchored on the wrong line, severity not contextualized, flows from another CVE leaking in, "New" when it should be auto-ignored.

Generic verdicts with no `file:line` evidence are rejected — be specific or stay silent.

## Phase 4 — Aggregate

1. Drop malformed JSON (note it in coverage).
2. Resolve `DUPLICATE` clusters — pick a canonical finding per cluster, list the rest under it.
3. Rank: `FALSE_POSITIVE` / `NOISE` / `MISCLASSIFIED_REACHABILITY` / `BAD_DATA` / `MISLEADING_PRESENTATION` first (these are the action items); `TRUE_POSITIVE` last (or omit in `--noise-only`).
4. Tally: `N findings → X true-positive, Y noise/FP, Z duplicate, W mis-scored, V bad-data/misleading`.
5. Group the action items by `recommended_action` so similar fixes batch (e.g. "3 findings → one Semgrep filter").

## Phase 5 — Report back + STOP

Print a tight chat summary: the tally, the top action items (verdict + one-line + recommended fix + `file:line`), and the de-dup clusters. Then **stop and ask Henry how he wants to proceed** — do not apply any fix. Optionally write the full per-finding table to `.claude/audits/evaluate-findings-<project>-<run>.md` for the record.

Report shape:

```markdown
# Findings Evaluation — <project> (run <short-run-id>)
Tally: <N> findings → <X> clean / <Y> noise-or-FP / <Z> duplicate / <W> mis-scored / <V> bad-data

## Action items (fail the bar)
### <verdict> — <finding_id>
- **User sees:** ...
- **Ground truth:** ... (file:line)
- **Why it fails:** ...
- **Recommended fix:** ...

## Duplicate clusters
- <canonical> ← also: <dupes> — recommend cluster/dedup

## Clean (true positives)
- <finding_id> — <one line> (omit in --noise-only)

## Recommended fixes, batched
- Semgrep filter: <rules>
- Reachability reclassify: <cves>
- Endpoint/scorer/fixture bugs: <list>
```

## Rules
- **Never auto-fix.** Report verdicts; Henry decides. (The fix conversation is the point.)
- **Always scope to the active extraction run.** Stale-run rows are themselves a BAD_DATA class, but never evaluate them as if live.
- **Evaluators must read the real source.** A verdict with no `file:line` evidence is rejected.
- **Minimal noise is the north star.** When unsure whether something is signal, weigh it as the *user* would: would a security engineer act on this line, or scroll past it? "Scroll past" = noise.
- Bias toward **clustering**: one bug shown once beats one bug shown four times, even when all four are technically true.
- Honor `--scanner` / `--noise-only` / `--deep`. Don't silently cap the finding set — if you sample or truncate, say so.
- Don't substitute generic "is this a CVE" checks for the real lens: reachability correctness + presentation honesty + dedup are where Deptex wins or loses.
```
