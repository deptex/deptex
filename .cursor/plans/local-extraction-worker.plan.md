# Local Extraction Worker — Plan

## Vision

Make `extraction-worker` runnable as a standalone CLI on any local or remote repo, with a swappable storage backend (Supabase for prod, PGLite for local), so:

1. **Henry** can validate pipeline changes without touching prod or his dev Supabase
2. **Claude (sub-agent)** can run extraction against fixture or arbitrary repos in a chat turn and report results — no human in the loop
3. **OSS contributors** can clone the repo, run `npx extraction-worker run ./fixtures/test-npm`, see findings, and submit PRs without spinning up Supabase
4. **CI** can run snapshot tests against fixture repos on every PR — catches regressions for free
5. **Self-hosters** (future) can run the whole stack with PGLite or any Postgres, no Supabase dependency

This is also the foundation for everything in Phases 2–6 (tree-sitter, Semgrep rules, AI stitching, Joern, GuardDog, IaC scanning) — every new feature gets snapshot-tested against fixtures before merging.

## Non-Goals (v1)

- Replacing Supabase as the prod backend (storage abstraction enables it but no migration is forced)
- Multi-tenant local mode (single project per CLI invocation)
- Frontend in local mode (CLI is JSON-out only; no React UI shipped)
- Auth in local mode (CLI assumes you own the data; no JWT)
- QStash / Fly.io / Redis (all bypassed in local mode)

## User Scenarios

### Scenario A — Henry validates a Phase 19-style refactor before deploying
```bash
npx extraction-worker run ./fixtures/test-npm --output ./results/run-1
npx extraction-worker run ./fixtures/test-npm --output ./results/run-2  # second run
diff results/run-1/findings.json results/run-2/findings.json  # carry-forward correct?
```

### Scenario B — Claude tests a Semgrep rule on 10 OSS repos in chat
```bash
npx extraction-worker batch --config ./test-rules/CVE-2024-XXXX.yaml --output ./results
# Outputs per-repo JSON + aggregate report (FP rate, perf, etc.)
```
Claude reads the JSON, reports "fired correctly on 9/10, false positive on repo X line Y."

### Scenario C — OSS contributor adds Ruby ecosystem support
```bash
git clone deptex && cd deptex/backend/extraction-worker
npm install
# Add Ruby resolver
npx extraction-worker run ./fixtures/test-ruby --inspect-step deps_sync
# Iterates until output looks right
npm run test:fixtures  # snapshot tests pass
git push
```

### Scenario D — CI catches a regression
A PR adds tree-sitter; CI runs `npm run test:fixtures` on all 4 ecosystems; a snapshot mismatch on `test-java` shows the new code accidentally changed dep-scan output. PR blocked.

### Scenario E — Performance regression detection
```bash
npx extraction-worker run ./fixtures/test-npm --benchmark
# Outputs per-step timings; CI fails if any step regresses >20% vs baseline
```

## Architecture

### Storage abstraction

`backend/extraction-worker/src/storage/index.ts`:
```ts
export interface Storage {
  // Mirrors the subset of supabase-js the worker uses
  from(table: string): TableClient;
  rpc<T = unknown>(name: string, args?: object): Promise<{ data: T | null; error: Error | null }>;
  storage: { from(bucket: string): { upload(...): Promise<...> } };
}
```

Implementations:
- `SupabaseStorage` — wraps `createClient(...)`. Today's behavior. Default in prod.
- `PGLiteStorage` — wraps PGLite + an in-memory upload bucket (writes uploads to a `--output` dir). Default in local CLI.

`pipeline.ts` swaps `import { createClient } from '@supabase/supabase-js'` for `import { getStorage } from './storage'` — single line change, everything downstream untouched.

### PGLite bootstrap

On `extraction-worker run`, PGLiteStorage:
1. Spins up a fresh in-memory PGLite (or persisted to `--db-path file.db` for inspection)
2. Loads every migration from `backend/database/*.sql` in lex order (matches Supabase migration application order)
3. Hands the storage object to `runPipeline()`

Migrations need to apply cleanly without Supabase-specific extensions. We already use plain Postgres + `gen_random_uuid()` (need pgcrypto). PGLite ships with pgcrypto — verified during M1.

### CLI

`backend/extraction-worker/bin/extract.ts` (registered in package.json `bin` field):
```
extraction-worker run <repo-path-or-url> [options]
  --ecosystem <npm|python|java|go>     (auto-detected from manifest if omitted)
  --output <dir>                       (default: ./extraction-results)
  --format <table|json|sarif|html>     (default: table for tty, json otherwise)
  --severity <low,medium,high,critical> (filter findings by severity, default: all)
  --fail-on <severity>                 (exit non-zero if any finding >= severity; powers CI gating)
  --config <path>                      (default: .deptex.yaml in repo root)
  --ignore <path>                      (default: .deptexignore in repo root)
  --db-path <file>                     (persist PGLite to disk; default in-memory)
  --ai-provider <none|anthropic|openai|google> (default: none — stub all AI calls)
  --api-key <key>                      (required if --ai-provider != none)
  --skip <step,step>                   (e.g. --skip semgrep,trufflehog for fast iteration)
  --only <step>                        (run only one step — useful for debugging a regression)
  --benchmark                          (emit per-step timings to ./perf.json)
  --diff <previous-output-dir>         (run + diff against a previous output)
  --quiet / --verbose                  (logging volume; auto-detects tty for color)

Exit codes:
  0 = no findings (or none above --fail-on threshold)
  1 = findings present (or above threshold)
  2 = pipeline error (crash, missing binaries, etc.)

extraction-worker batch --config <yaml> [--output <dir>]
  Runs the worker against multiple repos defined in a YAML config:
    repos:
      - { url: github.com/expressjs/express, ecosystem: npm }
      - { path: ./local/repo, ecosystem: python }
  Aggregates per-repo results into a summary report.

extraction-worker fixtures
  Lists available built-in fixtures.

extraction-worker test:fixtures
  Runs the worker against every fixture, diffs output against committed snapshots,
  exits non-zero on mismatch. (Used by `npm run test:fixtures` and CI.)
```

### Config file (.deptex.yaml)

Optional repo-root config that callers can use instead of CLI flags:
```yaml
ecosystem: npm                    # default ecosystem if no manifest
severity: [high, critical]        # filter
fail_on: critical                 # CI gating threshold
ignore_paths:                     # globs excluded from extraction (also can live in .deptexignore)
  - vendor/**
  - third_party/**
ignore_findings:                  # per-CVE / per-rule suppressions
  - id: CVE-2021-23337            # by CVE id
    reason: "we don't use _.template"
  - rule: javascript.lang.security.audit.detect-eval
    paths: [test/**]              # only ignore in test code
```

CLI flags override config file values.

### .deptexignore

`.gitignore`-style path patterns excluded from scanning. Useful for monorepos that want one project at a time.

### Output shape

Per run, `--output <dir>/`:
- `summary.json` — top-level: project_id, extraction_run_id, deps_count, vulns_count, semgrep_count, secrets_count, duration_ms_total, finalize_summary, schema_version
- `deps.json` — full project_dependencies dump
- `vulns.json` — full PDV dump including depscore, reachability, EPD fields
- `semgrep.json`, `secrets.json`, `usage_slices.json`, `reachable_flows.json`
- `events.json` — project_vulnerability_events
- `step_errors.json` — anything written to extraction_step_errors
- `perf.json` (if --benchmark) — per-step duration_ms
- `pipeline.log` — full extraction_logs stream
- `report.html` (if `--format html`) — self-contained HTML report (no server, openable directly in a browser)
- `report.sarif` (if `--format sarif`) — SARIF 2.1.0 for GitHub Code Scanning auto-upload

JSON is sorted by stable keys for deterministic snapshot diffs. `schema_version` lets future tooling detect format changes.

### Output formats

- **table** (default for tty) — colored terminal output: severity badges, per-vuln rows with reachability, summary footer ("3 critical, 12 high reachable")
- **json** (default for non-tty) — machine-readable, same shape as `vulns.json` etc.
- **sarif** — SARIF 2.1.0; GitHub Action uploads this to the Security tab automatically (powers `github/codeql-action/upload-sarif`-style integration)
- **html** — single-file static report with tabs for Vulns / Deps / Semgrep / Secrets / Reachable Flows. Embeddable JS for expand/collapse, no external deps. Shareable artifact (PR comments, email, archived in CI artifacts)

### Fixtures

`backend/extraction-worker/fixtures/`:
- `test-npm/` — package.json + lockfile + src with vulnerable lodash/jsonwebtoken usage + planted secrets
- `test-python/` — requirements.txt + app.py with vulnerable pyyaml.load usage
- `test-java/` — pom.xml + Log4Shell-style vulnerable code
- `test-go/` — go.mod + main.go with vulnerable golang.org/x/* usage
- `test-empty/` — repo with no manifests (negative test)
- `snapshots/` — committed JSON outputs the snapshot test diffs against. Update via `extraction-worker test:fixtures --update`.

Same content as the original `deptex-test-*` GitHub repos (per `optimized-gliding-church.md` plan), but checked into the monorepo so contributors don't need GitHub access to test.

### Mocking external services

In local mode, default behavior:
- **AI calls (EPD, future AI rules / stitching):** stubbed to return deterministic fixture responses by default. Opt-in via `--ai-provider`.
- **OSV / GHSA fetches:** cached. v1 = bundle a snapshot of vulns for fixture deps in a `fixtures/vuln-cache.json`. Pipeline uses cached data when `STORAGE=pglite` to keep tests deterministic offline.
- **Watchtower / supply-chain enrichment:** skipped entirely.
- **dep-scan, semgrep, trufflehog binaries:** required on $PATH (same as prod). Document install in CONTRIBUTING.md. Future: detect missing binaries, log warn, skip the step.

### Snapshot test runner

`backend/extraction-worker/test/snapshot.test.ts`:
- Reads every fixture
- Runs the pipeline
- Diffs each `*.json` output against `fixtures/snapshots/<fixture-name>/`
- On mismatch: prints unified diff, fails the test
- `--update` flag rewrites snapshots (used after intentional behavior changes)

CI runs this on every PR via `npm run test:fixtures`.

## Milestones

### M1 — Storage abstraction + PGLite backend (~1.5 days)
- Define `Storage` interface
- Implement `SupabaseStorage` (today's behavior, refactored behind interface)
- Implement `PGLiteStorage` with migration loader
- Refactor `pipeline.ts` + `ast-storage.ts` + `reachability.ts` + `with-timeout.ts` to use `Storage` instead of `SupabaseClient`
- Verify all existing unit tests still pass

**Deliverable:** worker runs the full pipeline against PGLite in a unit test.

### M2 — CLI entry point + output formats + config (~1.5 days)
- `bin/extract.ts` with `run` subcommand
- Parses CLI args, sets up PGLiteStorage, calls `runPipeline()`, writes outputs
- Logger wires extraction_logs to stdout + file with quiet/verbose modes + tty color detection
- Auto-detects ecosystem from manifest files
- Output formats: table (tty default), JSON (non-tty default), SARIF, HTML stub (full HTML report lands in M7)
- Severity filter (`--severity`) and exit-code gating (`--fail-on`)
- `.deptex.yaml` config loader + `.deptexignore` parser

**Deliverable:** `npx extraction-worker run ./some-repo --severity critical --fail-on critical` works on at least one ecosystem and exits non-zero appropriately.

### M3 — Fixture repos for all 4 ecosystems (~0.5 day)
- Create `fixtures/test-{npm,python,java,go,empty}/`
- Each contains intentionally vulnerable code matching the spec in `optimized-gliding-church.md`
- Lockfiles committed (so dep resolution is deterministic)

**Deliverable:** all 4 fixtures extract end-to-end via the CLI.

### M4 — Snapshot test runner + ignore-fields + CI integration (~1 day)
- `test/snapshot.test.ts` runs fixtures and diffs against `fixtures/snapshots/`
- Default ignore list (in `test/snapshot-ignore.ts`): timestamps (`created_at`, `updated_at`, `extraction_run_id`, etc.), generated UUIDs (top-level row IDs), absolute file paths in stack traces
- Per-fixture `fixtures/<name>/snapshot-ignore.yaml` for case-specific overrides (e.g. test-npm might intentionally ignore EPSS scores since they update from upstream)
- `--update` regenerates snapshots after intentional changes
- Add `test:fixtures` to package.json
- Add to `.github/workflows/` (or equivalent CI) to run on every PR

**Deliverable:** `npm run test:fixtures` exits 0 on a clean tree, fails on a synthetic regression, doesn't churn on timestamp-only changes.

### M5 — Batch mode + diff mode + benchmark mode (~0.5 day)
- `extraction-worker batch --config <yaml>` runs N repos, aggregates results
- `--diff <previous-output-dir>` runs + diffs to validate carry-forward / re-review behavior
- `--benchmark` emits perf.json with per-step timings

**Deliverable:** Claude can be told "test this rule on 5 OSS repos" and run a batch in one command.

### M6 — Docs (~0.5 day)
- `backend/extraction-worker/README.md` — quickstart, CLI reference, how to write a fixture, how to debug a step
- `CONTRIBUTING.md` — section on local extraction testing
- Architecture doc covering the storage abstraction (1 page, explains why and how to add a new backend)

**Deliverable:** an OSS contributor can clone and run a fixture in <5 minutes following only the README.

### M7 — HTML report + GitHub Action wrapper (~2 days)
- `report.html` template: self-contained single file (CSS + JS inlined, no external deps), tabs for Vulns / Deps / Semgrep / Secrets / Reachable Flows
- Renders reachability call chains (entry point → vulnerable function) inline — this is Deptex's differentiator and should be visually obvious
- Severity badges, expand/collapse for stack traces, sortable tables
- GitHub Action wrapper at `.github/actions/scan/action.yml` (composite action) — wraps `npx extraction-worker run`, uploads SARIF to GitHub Security tab via `github/codeql-action/upload-sarif`
- Action README with `uses: deptex/scan-action@v1` example for downstream users (later: split into its own `deptex/scan-action` repo for `uses:` shorthand to work cleanly)
- `.gitlab-ci.yml` template + pre-commit hook config for parity

**Deliverable:** `--format html` produces a shareable report; PRs in the Deptex repo itself trigger the GitHub Action and SARIF appears in the Security tab.

**Total: ~6 days** (M2 grew, M4 grew, M7 added). One focused work-week with a half-week of slack.

## Decisions (locked 2026-04-19)

1. **CLI package location:** ships inside `deptex-extraction-worker` for v1 (simpler, faster). Long-term vision is a publishable `@deptex/cli` package like Trivy/OSV-Scanner — see memory `future_publishable_cli.md`. Extract later when v1 is mature.

2. **AI in local mode:** default to stubbed (returns null, same behavior as prod when no BYOK key set). If user passes `--api-key <key> --ai-provider <anthropic|openai|google>`, makes real AI calls.

3. **Snapshot tests:** include an ignore-fields config from day 1. Per-fixture YAML can specify fields to ignore in diffs (e.g. `created_at`, `id`, `extraction_run_id`, timestamps). Default ignore list applies to all fixtures (timestamps, UUIDs); per-fixture overrides for the specific cases. `npm run test:fixtures -- --update` regenerates snapshots; `git diff` for human review before commit.

4. **Worktree:** continue on `worktree-reachability-phase1`. Phase 19 + local-mode bundle into one merge. Acceptable since Henry is the only reviewer and the changes are non-overlapping in scope.

## v2+ Roadmap — work for after the local-mode foundation lands

These are features that fit cleanly on top of the v1 architecture but aren't worth building until the foundation is stable and the extraction pipeline is mature (post Phase 6 reachability work, ideally). When we eventually publish the CLI (`@deptex/cli`), most of these graduate from "nice-to-have" to "table stakes."

### Distribution & install ergonomics
- **Docker image** — `docker run deptex/cli scan ./repo` (Trivy parity)
- **Single-binary build** via `pkg` or `bun build --compile` — `brew install deptex`, `scoop install deptex`, `apt install deptex` work without Node
- **Auto-update** delegated to npm/brew/docker (don't roll our own)
- **Reproducible signed releases** + SLSA provenance attestations
- **Telemetry opt-in** (extraction count, ecosystems, anonymized) with explicit disclosure on first run — not Trivy-style implicit collection

### Output & integration
- **VS Code extension** — surface findings inline in the editor, hover tooltips for reachability
- **JetBrains plugin** — same for IntelliJ/WebStorm/PyCharm
- **TUI mode** — `deptex tui` opens an interactive findings browser like k9s
- **Custom output templates** — Go-template or Jinja for users who want bespoke reports
- **GraphQL API server** — `deptex serve --api` exposes a queryable layer over PGLite
- **Webhook hooks** — emit events on scan completion, severity threshold breach, new CVE detection

### Deptex differentiators (CLI surface)
- **AI-assisted triage** — `deptex explain <finding-id>` produces natural-language explanation of why a finding matters; auto-suppression suggestions for likely false positives
- **EPD-aware filtering surface** — `--entry-point public_unauth` flag to focus on internet-exposed risks (nobody else in OSS has this)
- **Per-CVE rule library shipping** — `deptex rules list/add/test`, ships the Phase 2-3 hand-written + AI-generated Semgrep rules; coverage report ("you're checking 73 / 100 CISA KEV CVEs")
- **Differential rule testing** — `deptex rules test ./my-rule.yaml ./fixtures/` runs one rule against N fixtures, reports FP rate vs baseline
- **Auto-remediation suggestions** — `deptex fix --dry-run` proposes lockfile updates that resolve N vulns without breakage; `deptex fix --pr` opens a PR
- **Reachability call-graph in CLI** — terminal rendering of "your `src/api.js:42` calls lodash.template() which is vulnerable to CVE-2021-23337"

### Scanning surface expansion
- **Container image scanning** — `deptex image nginx:latest` (Trivy parity, needed for Phase 6 IaC/container work)
- **Kubernetes manifest scanning** — `deptex k8s ./manifests/` (Checkov parity)
- **Cloud config scanning** — AWS / GCP / Azure misconfig detection (long tail)
- **License compliance report** — `deptex report licenses` separates license risk from vuln risk
- **VEX support** — accept `.vex.json` files declaring "we don't use this code path, ignore this CVE org-wide"

### Self-host & enterprise
- **Self-hostable Deptex stack** — once storage is abstracted (M1), the rest of the platform (backend API, frontend) can also be made PGLite-friendly. Major undertaking but local-mode is the prerequisite. Enables "run Deptex on your own infra" enterprise pitch.
- **Air-gapped offline mode** — bundled vuln DB for environments without internet access
- **Attestation signing** — sigstore/cosign integration for SBOM + scan results
- **VEX integration** — accept and emit Vulnerability Exploitability eXchange documents

### Dev / QA tooling (deeper than v1)
- **Replay from production** — given a `extraction_jobs.id` from prod, replay the same job locally with the same inputs. Useful for "this user's extraction failed, why?" debugging.
- **Persistent fixture cache** — share PGLite DB across runs to test multi-extraction scenarios (extraction 1 finds vuln, user suppresses, extraction 2 should preserve suppression — the carry-forward case)
- **Pre-canned fixture sequences** — testing carry-forward across version bumps (extraction 1 with lodash 4.17.20 → user suppresses CVE-X → extraction 2 with lodash 4.17.21 → suppression carries)
- **Property-based testing** for parser layer (fuzz inputs to oxc-parser, etc.)
- **Performance regression CI** — fail PR if any step regresses >20% vs baseline
- **Hot reload during development** — re-run pipeline on extraction-worker source change

### Things competitors have that we should NOT build
- Cloud history / trends / scheduled reports — that's the paid platform, don't put in CLI
- Team management in CLI — same
- Custom dashboards — paid platform
- Implicit telemetry without consent — Trivy gets flak for this, we won't repeat it

## When to revisit this list

After: (a) Phase 19 merged, (b) local-mode v1 (M1-M7) shipped, (c) at least one Phase 2 milestone landed (probably tree-sitter integration). At that point pick the highest-leverage v2+ items based on which OSS contributor friction points and user-facing differentiators have surfaced.

## Why this order

M1 is the big one — everything else falls out of it almost mechanically. Worth doing right (clean interface, no leaks of supabase-specific patterns into pipeline.ts). M2-M6 are each <1 day individually but only become valuable once M1 lands.

Doing M1 first also de-risks: if PGLite turns out to have a blocker (e.g. a Postgres feature we use that PGLite doesn't support), we discover it on day 1 not day 4. (Current usage: pgcrypto, RLS-disabled tables, JSONB, plpgsql functions — all PGLite-supported per their docs, but verify before building the rest.)

## Risks

- **PGLite Postgres parity gap.** Mitigated by M1 verification step (run all migrations + finalize_extraction in PGLite as the first thing).
- **Snapshot churn.** First few weeks of Phase 2-6 work will produce constant snapshot diffs as new analysis is added. Tolerable cost, but worth flagging.
- **Binary dependency drift.** dep-scan / semgrep / trufflehog versions on a contributor's machine vs CI vs prod. Mitigation: pin versions in CONTRIBUTING.md, document install steps, consider Docker-based CI for full reproducibility.
