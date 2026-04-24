---
name: Reachability Phase 3 — Semgrep Reachability Rules Engine
status: in-progress
worktree: .claude/worktrees/reachability-phase3
branch: worktree-reachability-phase3
base_commit: 6bab970
---

# Reachability Phase 3 — Implementation Plan

## Overview

Phase 3 adds a hand-authored, per-CVE Semgrep taint-tracking layer on top of Phase 2's tree-sitter usage extractor. When a project depends on a known-CVE library AND its source code matches a CVE-specific source→sink taint pattern, we upgrade the vulnerability's `reachability_level` from heuristic (`module`/`function`) to `confirmed` — the highest-priority signal in the depscore pipeline.

Six design choices locked during the interview:

1. **Rule format**: native Semgrep YAML (`mode: taint`), no Deptex wrapper.
2. **Rule selection**: pre-filter rules by detected CVEs — only run rules whose `metadata.cve` matches a vuln found in this run.
3. **Semgrep invocation**: separate subprocess from the existing SAST `semgrep --config auto` pass.
4. **Validation**: golden per-rule fixtures (`vulnerable.<ext>` + `safe.<ext>` pairs) with Jest assertions.
5. **Level mapping**: any taint match → `confirmed` (we trust our own rules).
6. **CVE coverage**: 20 hand-picked rules across 5 npm, 5 Java, 4 Python, 3 Go, 3 Ruby/PHP.

Phase 3 does NOT re-enable EPD — that is Phase 4. Phase 3's job is to produce the high-confidence `confirmed` signal that Phase 4 will route through Claude for entry-point verification.

---

## Codebase Analysis

### Tables already in the DB (no new tables needed)

`project_reachable_flows` (Phase 6b) is reused. Phase 23 adds three new columns to make it polymorphic over its source:
- `reachability_source TEXT NOT NULL DEFAULT 'atom'` — 'atom' | 'semgrep_taint'
- `osv_id TEXT NULL` — CVE identifier for taint flows
- `rule_id TEXT NULL` — Semgrep rule.id for taint flows

Existing UNIQUE constraint on `(project_id, extraction_run_id, purl, entry_point_file, entry_point_line, sink_method)` is preserved — Semgrep flows that collide with atom flows on this tuple are silently dropped (atom wins). This is acceptable because the atom row already proves data flow.

### Existing reachability classification logic

`backend/extraction-worker/src/reachability.ts:384-556` (`updateReachabilityLevels`) currently does:

```
if matchingFlows.length > 0      → 'data_flow'
elif isDepUsed(depName)          → 'function'
elif transitive AND no imports   → 'unreachable'
else                             → 'module'
```

Phase 3 inserts a new highest-priority branch ahead of `data_flow`:

```
if matchingTaintFlows for this PDV's (dep, osv_id)  → 'confirmed'
elif matchingFlows.length > 0                        → 'data_flow'
elif isDepUsed(depName)                              → 'function'
... (unchanged)
```

### Existing Semgrep step

`backend/extraction-worker/src/pipeline.ts:1420-1540` is the SAST Semgrep call (`semgrep --config auto`). Phase 3's reachability_rules step copies this skeleton:
- `binaryAvailable('semgrep')` short-circuit + warn-with-install-hint
- `withTimeout(..., 15 * 60_000, 'reachability_rules')`
- Single subprocess for the filtered rule set (separate from SAST)
- `logStepError(severity: 'warn')` on failure — pipeline continues

### `commit_extraction` vs `finalize_extraction`

`finalize_extraction` is the active commit path; the pipeline streams writes during the run and finalize_extraction only does the pointer flip + reap. `commit_extraction` is documented as inert (kept for future JSONB-payload callers). Phase 23 extends `commit_extraction`'s `p_reachable_flows` typedef for hygiene only.

---

## Data Model — Phase 23 migration (LANDED, M1)

`backend/database/phase23_semgrep_reachability.sql`:

- `ALTER TABLE project_reachable_flows ADD reachability_source TEXT NOT NULL DEFAULT 'atom'`
- `ALTER TABLE project_reachable_flows ADD osv_id TEXT NULL`
- `ALTER TABLE project_reachable_flows ADD rule_id TEXT NULL`
- `CHECK (reachability_source IN ('atom', 'semgrep_taint'))`
- Two new indexes: `(extraction_run_id, reachability_source)` and `(project_id, extraction_run_id, osv_id) WHERE osv_id IS NOT NULL`
- `commit_extraction` RPC re-published with extended `p_reachable_flows` typedef + INSERT column list

Reapers untouched — they delete by `extraction_run_id` regardless of source.

Applied via Supabase MCP. `schema.sql` refreshed via `npm run schema:dump`.

---

## Rule Format Spec — Native Semgrep YAML

### Directory layout

```
backend/extraction-worker/reachability-rules/
├── README.md
├── CVE-2021-23337-lodash-template/
│   ├── rule.yml
│   └── __fixtures__/
│       ├── vulnerable.js
│       └── safe.js
└── ... 19 more
```

One folder per CVE; co-located fixtures.

### Required metadata fields

`cve` (required for selection), `package`, `ecosystem`, `affected_versions`, `confidence`, `cwe` (recommended), `references`.

The loader validates `cve`, `package`, `ecosystem` — missing → rule skipped with warn.

### Fixture conventions

`vulnerable.<ext>` must match the rule (≥1 finding). `safe.<ext>` must produce 0 findings. Differ in exactly one meaningful way (sanitizer present, fixed source, etc.). ~10-15 lines each.

---

## New Module: `backend/extraction-worker/src/reachability-rules.ts` (M2)

### Public API

```typescript
export interface RuleMetadata {
  cve: string;
  package: string;
  ecosystem: string;
  affectedVersions?: string;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  cwe?: string[];
}

export interface LoadedRule {
  rulePath: string;
  ruleId: string;
  metadata: RuleMetadata;
}

export interface TaintFinding {
  cve: string;
  ruleId: string;
  filePath: string;
  sourceLine: number;
  sourceContent: string | null;
  sinkLine: number;
  sinkMethod: string | null;
  sinkContent: string | null;
  flowSteps: Array<{ file: string; line: number; content: string }>;
  rawSemgrepResult: unknown;
}

export function loadAllRules(rulesDir: string): Promise<LoadedRule[]>;
export function selectRulesForCves(allRules: LoadedRule[], detectedCves: Set<string>): LoadedRule[];
export function runReachabilityRules(args: {
  workspaceRoot: string;
  rules: LoadedRule[];
  signal?: AbortSignal;
  timeoutMs: number;
}): Promise<TaintFinding[]>;
export function parseTaintOutput(semgrepJson: unknown, rulesById: Map<string, LoadedRule>): TaintFinding[];
```

### Internals

- YAML loading via `js-yaml` (already in extraction-worker deps from Phase 2).
- Temp rule dir per run: `os.tmpdir()/deptex-reach-rules-<runId>/` — cleaned up in `finally`.
- `--dataflow-traces` flag enables Semgrep's source/sink trace output.
- 15-min timeout via withTimeout, AbortSignal-cancellable.
- Per-rule failures logged at warn, don't fail the step.

---

## Pipeline Integration (M3)

New step in `pipeline.ts` after vuln_scan, before SAST Semgrep:

1. Fetch detected CVEs: `SELECT DISTINCT osv_id FROM project_dependency_vulnerabilities WHERE project_id=? AND extraction_run_id=? AND osv_id LIKE 'CVE-%'`
2. `loadAllRules() → selectRulesForCves(detectedSet)`
3. If no matches: log info "no matching reachability rules", skip
4. `runReachabilityRules()` with 15min timeout, AbortSignal
5. Map findings → `project_reachable_flows` row shape (reachability_source='semgrep_taint', osv_id, rule_id, etc.)
6. Batch upsert (chunks of 100) with `ignoreDuplicates: true` on existing UNIQUE
7. log.success with finding count

---

## `updateReachabilityLevels()` Changes (M4)

In `reachability.ts:384-556`:

1. Add fetch of taint flows alongside existing flows fetch:
```typescript
const { data: taintFlows } = await supabase
  .from('project_reachable_flows')
  .select('dependency_id, osv_id, rule_id, entry_point_file, entry_point_line, sink_method')
  .eq('project_id', projectId)
  .eq('extraction_run_id', runId)
  .eq('reachability_source', 'semgrep_taint');
```

2. Build `confirmedByPdv` map keyed `(dependency_id, osv_id)` → flows.

3. In per-PDV loop, check the new map FIRST:
```typescript
const taintMatches = confirmedByPdv.get(`${dependencyId}:${pdv.osv_id}`) ?? [];
if (taintMatches.length > 0) {
  level = 'confirmed';
  details = { rule_ids, flow_count, entry_points, sink_methods };
} else if (matchingFlows.length > 0) {
  level = 'data_flow';
  // existing logic unchanged
}
```

`is_reachable` derivation unchanged. Depscore weight for `confirmed` (1.0) already in `depscore.ts`.

---

## Implementation Tasks — Status

- **M1 (DONE)**: `phase23_semgrep_reachability.sql` migration applied via Supabase MCP, `schema.sql` refreshed, lodash CVE-2021-23337 rule + vulnerable/safe fixtures + reachability-rules/README.md.
- **M2**: `reachability-rules.ts` loader + invoker + parser, plus `reachability-rules.test.ts` covering all four functions.
- **M3**: Pipeline integration step.
- **M4**: Wire taint flows into `updateReachabilityLevels`.
- **M5**: Author 19 remaining CVE rule-packs + fixtures (4 npm, 5 Java, 4 Python, 3 Go, 3 Ruby/PHP).
- **M6**: End-to-end PGLite integration test + expanded README.

---

## Risks & Open Questions

- **Semgrep version pin**: Phase 2 pinned 1.160.0 in Dockerfile. Verify `mode: taint` + `--dataflow-traces` syntax stable on that version.
- **Rule ID collisions**: Semgrep requires unique rule IDs across one invocation. Use `deptex.<package>.<short>` namespacing.
- **CVE-to-package resolution**: When mapping a Semgrep finding back to a `project_dependencies` row, query by `name = metadata.package AND last_seen_extraction_run_id = runId`. Multiple matches → one flow row per match.
- **Cross-language sinks**: Some rules (Log4Shell) involve framework code outside the user repo. Match on user's call site only.
