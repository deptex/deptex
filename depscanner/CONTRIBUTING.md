# Contributing to depscanner

Welcome. This doc covers the contributor loop for the scanner worker: edit
code → prove your change didn't silently break anything → open a PR.

Most of the value here is the **snapshot regression suite**. It runs the
real CLI against ten-plus fixtures, captures every output file, and diffs
against committed golden snapshots. If your code change ripples into a
load-bearing field (a vulnerability's `reachability_level`, an entry
point's `classification`, a flow's source/sink, etc.), the suite tells
you — by file + leaf-path + before/after value, so you can decide
whether the change is intentional.

## TL;DR — the four-step contributor loop

```bash
cd depscanner

# 0. One-time setup (also re-run after Dockerfile changes).
npm run docker:build

# 1. Edit code (framework spec, pipeline step, scanner, etc).
$EDITOR src/taint-engine/framework-models/express.yaml

# 2. Run the snapshot suite.
npm run test:fixtures

# 3. Read the diff. Was it intentional?
#    - YES → regen + commit.
npm run test:fixtures:update
git add depscanner/fixtures/*/snapshots/
git commit

#    - NO → fix your code and go back to step 2.

# 4. Open the PR. CI re-runs the suite and rejects unintended diffs.
```

The whole loop runs without leaving your editor. No Supabase, no Fly.io,
no Aegis — just Docker + node.

## What the snapshot suite covers

Each fixture under `fixtures/<name>/` is a minimal codebase. The runner:

1. Spins up the `deptex-cli:local` Docker image (the same image you'd ship
   to a Fly.io machine).
2. Runs the full extraction pipeline against the fixture as a workspace:
   SBOM (cdxgen) → dep-scan (vuln catalogue) → tree-sitter usage + entry
   points → taint engine + CVE-targeted flows → Semgrep + TruffleHog →
   finalize.
3. Reads every row out of the embedded PGLite database and writes JSON
   files under `<output>/`:
   - `summary.json` — counts + reap deltas
   - `deps.json` — every dependency, transitive included
   - `vulns.json` — every vulnerability with depscore, reachability,
     EPD context
   - `reachable_flows.json` — every source→sink data flow with sanitizer
     chain + flow-signature hash
   - `entry_points.json` — every detected HTTP/CLI/scheduled handler
   - `semgrep.json` + `secrets.json` — SAST + secret findings
   - `generated_rules.json` + `rule_generation_telemetry.json` —
     AI-generated reachability rules (only when generation fires)
4. Diffs each file against the committed snapshot under
   `fixtures/<name>/snapshots/<file>.json`.
5. Strips volatile fields before diffing (EPSS / CVSS / KEV ticks daily,
   timestamps drift, UUIDs are random — these never produce diffs).

If your edit changes anything load-bearing, the runner prints exactly
what diverged.

## Example diff output

```
=== test-minimal-npm ===
  exit 0 as expected
  FAIL: snapshot mismatches:
  vulns.json: 1 difference(s)
    $[0].reachability_level: "module" ≠ "function"
```

If that change is what you meant — say you tightened a sanitizer rule so
a previously-flagged flow no longer hits a sink — regen:

```bash
npm run test:fixtures:update
```

…then `git diff depscanner/fixtures/test-minimal-npm/snapshots/vulns.json`
and stage the change. The PR review surface shows the exact load-bearing
flip, which is the whole point.

## Load-bearing fields (what gets pinned)

These are the fields a regression must NOT silently flip. The runner
strips every other field before diffing.

**`vulns.json`** — `osv_id`, `severity`, `summary`, `fixed_versions`,
`is_reachable`, `reachability_level`, `reachability_status`, `depscore`,
`base_depscore_no_reachability`, `contextual_depscore`, `epd_factor`,
`epd_depth`, `epd_status`, `epd_confidence_tier`,
`entry_point_classification`, `entry_point_weight`, `sink_precondition`,
`sanitization_postcondition`, `is_sanitized`, `status`, `suppressed`,
`risk_accepted`, `re_review_reasons`.

**`deps.json`** — `name`, `version`, `is_direct`, `source`,
`environment`, `is_outdated`, `versions_behind`, `policy_result`,
`namespace`, `files_importing_count`.

**`reachable_flows.json`** — `osv_id`, `flow_signature_hash`,
`source_class`, `source_method`, `source_file`, `source_line`,
`sink_class`, `sink_method`, `sink_file`, `sink_line`, `sanitizer_chain`,
`flow_length`, `reachability_source`, `entry_point_file`,
`entry_point_tag`, `framework`.

**`entry_points.json`** — `file_path`, `line_number`, `framework`,
`handler_name`, `http_method`, `route_pattern`, `entry_point_type`,
`classification`, `authenticated`, `auth_mechanism`, `middleware_chain`,
`metadata`.

**`summary.json`** — `schema_version`, `project_name`, `ecosystem`, all
`*_count`s, `finalize_summary.reap.*_deleted`, `finalize_summary.{vulns_new,
vulns_reopened, vulns_critical_new, vulns_carried_forward,
vulns_re_review_fired, deps_removed, sla_computed, rereview_enabled}`.

**`semgrep.json`** — `rule_id`, `severity`, `file_path`, `start_line`,
`code_snippet`, `message`, `metadata.cwe`, `metadata.owasp`,
`is_reachable`, `reachability_level`, `depscore`, `status`, `suppressed`.

**`secrets.json`** — `detector_type`, `file_path`, `start_line`,
`is_verified`, `is_current`, `redacted_value`, `code_snippet`, `depscore`,
`status`.

**`generated_rules.json`** — `vuln_class`, `osv_id`, `dependency_name`,
`rule_yaml`, `validation_status`, `validation_breakdown`, `confidence`,
`generation_source`.

The full list of stripped (volatile) fields lives in
`DEFAULT_IGNORE_FIELDS` at the top of `test/snapshot.ts`. Per-fixture
overrides live in `fixtures/<name>/snapshot-ignore.json`.

For a complete audit of every field across every fixture, see
`docs/snapshot-coverage-audit-2026-05-10.md`.

## Adding a new fixture

A fixture is a directory under `fixtures/` containing a real package
manifest plus a handful of source files. The runner figures out the
ecosystem from the manifest. Minimum layout:

```
depscanner/fixtures/test-myframework-myvuln/
  package.json            # or requirements.txt / pom.xml / go.mod
  src/handler.js          # framework entry point — the "source"
  src/sink.js             # the vulnerable callsite — the "sink"
  README.md               # one paragraph: what CVE this exercises and why
```

Register it in the `FIXTURES` array in `test/snapshot.ts`:

```ts
{ name: 'test-myframework-myvuln', expectClean: true, expectedExitCode: 0 },
```

…then run the suite. The first run auto-bootstraps the
`snapshots/` directory; commit those files in the same PR as the
fixture. Subsequent runs compare against your committed baseline.

If your fixture should NOT run in the default suite (slow ecosystems
like Java / Maven), set `slow: true`. The default suite then skips it;
contributors who want full coverage run `npm run test:fixtures --
--include-slow`.

## Useful flags

```bash
npm run test:fixtures -- --fixture=test-minimal-npm   # one fixture only
npm run test:fixtures -- --only=a,b,c                 # several by name
npm run test:fixtures -- --include-slow               # include slow fixtures
npm run test:fixtures -- --diff-only                  # dry-run: print what --update WOULD do
npm run test:fixtures -- --max-diff=500               # raise per-file diff cap (0 = unlimited)
npm run test:fixtures:update                          # regen all snapshots (destructive)
```

## Snapshot-runner regression tests

The runner itself has a meta-test that exercises the bootstrap path,
the mismatch path, the ignore-list path, and the argument parser. Run
it after touching `test/snapshot.ts`:

```bash
npm run test:snapshot-runner
```

It runs without Docker (operates on synthetic dirs) so it completes in
under one second.

## Other test commands

| Command | What it does |
|---------|--------------|
| `npm run test:taint-engine-all` | 15-stage taint-engine preflight (invariants, callgraph, propagator, per-language packs, CVE-targeted flows). Required for every taint-engine PR. |
| `npm run test:storage` | PGLite-backed storage round-trips. |
| `npm run test:finalize` | Finalize-extraction smoke (reap, vuln-state transitions, SLA). |
| `npm run type-check` | `tsc --noEmit`. |

## CI

The GitHub Actions workflow at `.github/workflows/test.yml` runs the
type-check + the taint-engine preflight on every PR. The fixture
snapshot suite is gated on Docker so it runs as a separate job
(`depscanner-fixtures`) that builds the image once and runs the suite
against the cached layers.

## Coordinating with the open-source corpus

Two layers above the fixtures are the **88-CVE corpus** and the **OSS
real-repo corpus**. Those run nightly, not on every PR, and they live in
`depscanner/scripts/oss-corpus*` + `depscanner/test/iterate/*`. You
don't need to touch them to land a normal change. Their job is to catch
regressions that synthetic fixtures don't reach — e.g. real
dependency-tree shapes, real cdxgen edge cases.

## Where to ask

- Snapshot infrastructure: open an issue tagged `snapshot-suite`.
- Framework spec changes: tag `framework-models`.
- Taint engine internals: tag `taint-engine`.
- General contributor experience: tag `contributor-onboarding`.

Thanks for reading. Now: edit, run, commit.
