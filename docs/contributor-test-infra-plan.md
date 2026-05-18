# Contributor Test Infrastructure Plan

**Status:** Plan only. No code changes proposed in this document — every PR-class change below is a separate ship that follows Section 9's roadmap.

**Scope:** Lift the depscanner snapshot suite from "fast smoke + 4 dark fixtures" to a real contributor-grade regression surface. The audit findings in `docs/depscanner-hardening-report.md:132-165` are the canonical bug list this plan closes.

**Hard prerequisite — Docker.** The depscanner CLI is Docker-only by design: `bin/deptex-scan` is a thin wrapper around the `deptex-cli:local` image (built by `npm run docker:build`), and the snapshot runner shells out through that wrapper so what gets tested is what contributors actually ship. Contributing to depscanner therefore requires a working Docker daemon. There is no "host node" fallback path; design discussion below assumes Docker is present and the open questions in §10 are scoped to "how do we make the Docker UX painless," not "what if Docker is missing." Missing snapshot files are now auto-bootstrapped by the runner (jest-style: write-on-first-run, fail on subsequent diff), so first-run friction comes from the Docker build, not from the snapshot baseline.

**Author surface:** `depscanner/test/snapshot.ts` + `depscanner/src/cli/output.ts` + `depscanner/src/cli/scan.ts:138-147` + `depscanner/fixtures/` + `depscanner/src/taint-engine/framework-models/express.yaml` + `.github/workflows/test.yml` + `CONTRIBUTING.md`.

---

## Section 1 — Goal + success criteria

A fresh OSS contributor changes one framework spec at `depscanner/src/taint-engine/framework-models/express.yaml` (e.g. they widen `res.send(*)` to also catch `res.send(*, *)`, or they add a new sanitizer entry), runs **one command**, and within **two minutes on a warm Docker cache** gets feedback that's specific enough to know whether they broke anything else. "Specific enough" means three concrete things: (a) the runner pinpoints the diverging fixture and the specific JSON file by name, (b) the diff is leaf-path-precise so the contributor can read "`reachable_flows.json[0].sink_method`: `\"res.send\"` ≠ `\"res.write\"`" rather than a wall of object delta, and (c) cosmetic / volatility noise (EPSS scores, timestamps, generated UUIDs, cdxgen-version-dependent SBOM ordering) is filtered out by the runner so a green snapshot run is a real signal, not a coin flip.

Today none of that holds. The full suite takes 12-25 minutes cold and `npm run test:fixtures` (the default no-flags run, which contributors will reach for) covers exactly two fixtures (`test-empty` + `test-minimal-npm`) — neither of which exercises Express, the taint engine, the entry-point detector, or any framework spec. Editing `express.yaml` produces a clean default-suite run regardless of correctness; the only feedback signal lives in `test:taint-engine-all` (the preflight) which is a separate command, doesn't snapshot end-to-end output, and doesn't catch CLI-level regressions. The success criterion below is what closes that gap.

**Success criterion (testable):** an Express-based "reachable" fixture (Section 2) runs by default in under 90 seconds on a contributor's warm-cache machine, fails-loud on a regression to any of `reachable_flows.json[0].{osv_id, flow_signature_hash, sink_method, sink_line, entry_point_file, flow_length, reachability_source, entry_point_tag}` or to `vulns.json[CVE].{reachability_level, is_reachable, entry_point_classification}` or to `entry_points.json[handler].{framework, http_method, route_pattern, classification}`, and the diff output names the file + leaf path + before/after value without truncation. Summary-level fields (`*_count`, `duration_ms`) get summary-level pinning — counts pinned, durations ignored.

---

## Section 2 — The "reachable" fixture

**Pick: lodash CVE-2021-23337 on Express.** Justification:

1. The taint engine already has a battle-tested fixture for this exact data flow at `depscanner/test/cve-targeted-flow-fixtures/js-lodash-template-injection/` (verified — meta.json names `expected_osv_id: CVE-2021-23337`, framework: express, package: lodash). The engine knows how to confirm this flow; the missing piece is the **end-to-end** snapshot binding from CLI input to `reachable_flows.json` output, not engine recall.
2. Express is the most widely-deployed framework spec we ship and the spec file most likely to be touched by a contributor PR. Pinning a flow that depends on `express.yaml` sources + a CVE-targeted sink gives us early-warning on every spec edit.
3. lodash 4.17.20 is already vendored in `fixtures/test-minimal-npm/package.json:7` — the npm install is cached. Reusing the same dep version avoids cdxgen re-downloading.
4. `_.template` is a clean callee — single-token, unambiguous in tree-sitter, no method chains. Cross-file flow (handler → render helper → sink) exercises the engine's interprocedural path without depending on framework middleware extraction.

Spring Boot path-traversal is the appendix candidate (Section 7 covers Java diversity through a different angle: minimum-cost ruby/rust/php/csharp fixtures). Reasons against Spring for the *first* reachable fixture: Maven cold-build cost (3-5 min per fixture vs npm's 30s), the spring-boot.yaml spec is currently smaller in source coverage than express.yaml so engine recall is less proven, and `test-java`'s existing snapshot already eats the slow-fixture budget.

### 2.1 Framework spec dependency check (grep-verified)

`express.yaml` covers the **source** side: `req.body.*` is in line 14-16 with `taint_kind: http_input`. Confirmed.

`express.yaml` does **not** cover `_.template` as a sink — that sink lives in the per-CVE `spec.json` at `test/cve-targeted-flow-fixtures/js-lodash-template-injection/spec.json:11-15` and gets loaded as a CVE-targeted spec, NOT as part of `express.yaml`. The pipeline's CVE-targeted spec loader matches against `dependency_id + osv_id` keys, so this works only when `lodash@4.17.20` is in the SBOM AND the dep-scan VDR step flags CVE-2021-23337. Both are true today on `test-minimal-npm` (verified: `vulns.json` already contains `CVE-2020-28500` + others on lodash 4.17.20).

**Decision:** the reachable fixture should NOT extend `express.yaml`. The CVE-targeted spec already exists; we just need a fixture that puts an Express handler around the existing `renderTemplate` flow shape.

### 2.2 Fixture file structure

Path: `depscanner/fixtures/test-reachable-express-lodash/`

```
test-reachable-express-lodash/
  package.json           # express 4.x + lodash 4.17.20
  package-lock.json      # committed, deterministic install
  index.js               # Express handler + cross-file render call
  src/
    render.js            # renderTemplate helper that calls _.template
  snapshots/
    summary.json
    deps.json
    vulns.json
    semgrep.json         # see Section 3.2
    secrets.json
    reachable_flows.json # the load-bearing one
    entry_points.json
  snapshot-ignore.json   # per-fixture extra ignore (covered in §3.3)
  README.md              # 5 lines: "what this fixture is, why it exists"
```

`package.json`:
```json
{
  "name": "deptex-test-reachable-express-lodash",
  "version": "1.0.0",
  "license": "MIT",
  "dependencies": { "express": "4.21.0", "lodash": "4.17.20" }
}
```

`index.js`:
```js
const express = require('express');
const { renderTemplate } = require('./src/render');
const app = express();
app.use(express.json());
app.post('/', (req, res) => res.send(renderTemplate(req.body.template)));
module.exports = app;
```

`src/render.js`:
```js
const _ = require('lodash');
function renderTemplate(tmpl) { return _.template(tmpl)({}); }
module.exports = { renderTemplate };
```

This mirrors the structure of `test/cve-targeted-flow-fixtures/js-lodash-template-injection/src/server.ts` + `render.ts` — same source/sink coords, just JS instead of TS and with a real Express dispatch instead of a synthetic handler call.

### 2.3 What gets pinned in `reachable_flows.json[0]`

Schema reference: `depscanner/src/taint-engine/storage.ts:185-220` (writeFlows row shape) + `backend/database/schema.sql:1353-1375` (project_reachable_flows columns). The pinned shape:

```json
[
  {
    "purl": "pkg:npm/lodash@4.17.20",
    "reachability_source": "taint_engine",
    "osv_id": "CVE-2021-23337",
    "rule_id": null,
    "flow_nodes": [ /* see below — content-pinned, length-pinned */ ],
    "entry_point_file": "src/index.js",
    "entry_point_method": "POST /",
    "entry_point_line": 5,
    "entry_point_tag": "framework-input:PUBLIC_UNAUTH",
    "sink_file": "src/render.js",
    "sink_method": "_.template",
    "sink_line": 3,
    "sink_is_external": true,
    "flow_length": 3,
    "llm_prompt": null,
    "flow_signature_hash": "<sha256 hex, locked once committed>"
  }
]
```

Pin policy:
- **Hard-pin (regression = test fail):** `purl`, `reachability_source`, `osv_id`, `entry_point_method`, `entry_point_tag`, `sink_method`, `sink_is_external`, `flow_length`, `flow_signature_hash`, `rule_id` (must stay null — engine path, not Semgrep rule path).
- **Hard-pin paths but tolerate basename-only diff:** `entry_point_file`, `sink_file`. Reason: the snapshot runner mounts the workspace at `/workspace` inside the container (verified at `test-go/snapshots/entry_points.json:3` — `"file_path": "/workspace/main.go"`). Path is stable across runs but contributors may forget to use forward slashes on Windows. `flow_signature_hash` already strips clone-root prefix at hash time (`storage.ts:312-358`) so the hash is portable; the raw path field is not.
- **Hard-pin line numbers:** `entry_point_line`, `sink_line`. Yes, this fights line-shift drift (acknowledged in storage.ts:306-310). The whole point of this fixture is to catch regressions, and the index.js + render.js are tiny; line shift will only happen if a contributor edits the fixture itself, which is acceptable signal.
- **Length-pin + content-pin per node:** `flow_nodes`. Pin `flow_nodes.length === 3` (entry source → renderTemplate call hop → sink). Pin each node's `kind`, `file`, `line`, and (for callsite nodes) the `callee`. Don't pin AI-verdict synthetic nodes — those only appear when AI fp-filter ran, which happens only when the BYOK provider is configured. In CLI/CI mode the engine emits no AI verdicts (verified by inference from `taint-engine/runner.ts` — fp-filter is only called when an OpenAI/Anthropic client is provisioned, which CLI mode never does).

### 2.4 What gets pinned in `vulns.json` for CVE-2021-23337

Realistic outcome: `reachability_level: "data_flow"`. Reasoning: `confirmed` requires the CVE-targeted spec match path (verified by the storage.ts:188-196 code path setting `osv_id` on the row), AND the classifier's confirmed-tier OR-clause (`storage.ts:25-28`: "the classifier's confirmed-tier OR-clause keys on (osv_id IS NOT NULL AND dependency_id IS NOT NULL)"). Both should hold for this fixture. So `confirmed` is achievable IF the lodash dep makes it into `depsByOsvId` via `createOsvIdResolver` — which depends on dep-scan flagging the CVE for lodash@4.17.20 on this exact run.

**Pin `confirmed` aspirationally**, but write the fixture's first commit with whatever the actual run produces, then assert the value on the running mode. If the snapshot lands on `data_flow`, that's the load-bearing pin: a regression that drops it to `module` (dep-scan match without taint flow) is the alarm we want. If the snapshot lands on `confirmed` and a future change downgrades it to `data_flow`, that's also an alarm worth raising. Either is better than the current `"module"` everywhere.

Hard-pinned fields on `vulns.json[CVE-2021-23337]`:
- `osv_id`: `"CVE-2021-23337"`
- `severity`: `"high"` (verify against actual dep-scan output before commit)
- `is_reachable`: `true`
- `reachability_level`: whichever of `confirmed`/`data_flow` the engine emits — the regression budget
- `entry_point_classification`: `"PUBLIC_UNAUTH"` — only populated when the classifier (epd.ts) ran on a real flow; pinning this catches the EPD-skipped-silently regression class
- `entry_point_weight`: not-null number, exact value pinned once
- `epd_status`: `"completed"` if EPD ran, otherwise `"pending"` — pin whichever is real
- Suppression / risk-accept block: all `false`/`null` (no-op), same as today

**Tolerated:** `epss_score`, `cvss_score`, `cisa_kev`, `published_at` — covered by Section 3.3.

### 2.5 What gets pinned in `entry_points.json`

```json
[
  {
    "file_path": "/workspace/index.js",
    "line_number": 5,
    "framework": "express",
    "handler_name": "(anonymous)",
    "http_method": "POST",
    "route_pattern": "/",
    "entry_point_type": "http_route",
    "classification": "PUBLIC_UNAUTH",
    "authenticated": false,
    "auth_mechanism": null,
    "middleware_chain": null,
    "metadata": { "method": "POST" }
  }
]
```

This shape matches `test-go/snapshots/entry_points.json` exactly with the framework/method swapped. Pinning is straightforward — every field is deterministic given the source.

### 2.6 Effort + risk

**Effort: M.** ~2 days for someone familiar with the engine; ~4 days fresh. Breakdown:
- Day 1: scaffold the fixture, run it through the CLI, debug whatever doesn't produce the expected flow. The two known failure modes are (a) cdxgen not flagging lodash@4.17.20 (unlikely — `test-minimal-npm` already does it cleanly) and (b) the engine not emitting a flow because the cross-file `renderTemplate` propagation needs an inferred return-type the spec doesn't model. Mitigation for (b): copy the exact source structure from `js-lodash-template-injection/src/server.ts` which the engine's own preflight already validates.
- Day 2: pin snapshots, validate runner correctly diffs them, document in fixture README.

**Risk:**

1. **Engine emits zero flows.** The CVE-targeted spec at `js-lodash-template-injection/spec.json` is loaded only when the engine's spec-loader sees that fixture path — verify by running `tsx test/snapshot.ts --fixture=test-reachable-express-lodash` and grepping the engine logs for "spec loaded: lodash-cve-2021-23337". If the loader doesn't pick up the per-CVE spec for production runs, the fix is to migrate that spec into the main framework-models load path (low effort, separate PR risk). Probability: 30%.
2. **dep-scan VDR doesn't flag CVE-2021-23337 on lodash@4.17.20.** Verifiable today: `cd depscanner/fixtures/test-minimal-npm && grep -r CVE-2021-23337 snapshots/`. If absent, the snapshot's `reachability_level` won't promote past `data_flow` because `osv_id` resolution skips. Probability: 10% (lodash CVEs are well-covered).
3. **Express middleware extraction isn't wired.** The entry-point detector at runtime is tree-sitter-based; verified working on Gin (`test-go/snapshots/entry_points.json`). Express coverage is documented but the audit didn't pin it — bring up the framework detector against this fixture before snapshot-pinning. Probability: 20%. Mitigation: if Express isn't extracting entry points, `entry_points.json: []` is the regression baseline (matches today), and we still pin the reachable_flows.json hard.
4. **`flow_signature_hash` instability.** The hash uses `sink_method` from the engine's matched callee text. If the engine matches `lodash.template` vs `_.template` on different runs, the hash flips. Mitigation: read the engine's actual emitted callee text from one warm run, then pin. If it's unstable across runs, that's a separate engine bug — out-of-scope for this fixture, escalate.

**NET effort if all three risks fire: M-L (4-5 days).** Don't pretend this is a one-day spike.

---

## Section 3 — Snapshot infra surgical fixes

Three sub-fixes, designed to ship as **a single PR** so the regen UX (Section 4) and the reachable fixture (Section 2) can land on a clean foundation.

### 3.1 — Plumb `finalize_summary` through `cli/scan.ts`

**Current state (verified):**

- `pipeline.ts:2501-2516` calls `supabase.rpc('finalize_extraction', ...)` and **destructures only `error`**. The RPC's `RETURNS jsonb` (verified at `schema.sql:3519-3520`) is silently dropped.
- `cli/scan.ts:138-147` calls `writeOutputs(...)` without supplying `finalizeSummary`, so `output.ts:99` writes `finalize_summary: null` always.
- `output.ts` already has the field plumbed on `WriteOutputsOptions.finalizeSummary` (line 51) — the wiring stops at the pipeline.

**Sketch (~12 lines of edits across 3 files):**

1. `pipeline.ts:2501-2516` — change to `const { data: finalizeSummary, error: finalizeErr } = await withTimeout(...)`. Stash `finalizeSummary` on a closure-scoped `let pipelineFinalizeSummary: unknown = null;` declared near the top of `runPipeline`.
2. `pipeline.ts` — change `runPipeline`'s return type from implicit-void to `Promise<{ finalizeSummary: unknown }>` and `return { finalizeSummary: pipelineFinalizeSummary }` at the end.
3. `cli/scan.ts:124` — capture: `const { finalizeSummary } = await runPipeline(job, logger, undefined, undefined, storage);`
4. `cli/scan.ts:138` — pass: `await writeOutputs(storage, { ..., finalizeSummary });`

**Snapshot impact:**

- `summary.json.finalize_summary` will populate with the RPC's actual return shape (verified to be JSONB from `schema.sql:3520`). Read the function body once to determine the shape, then add the structural keys (`vulnerabilities_added`, `vulnerabilities_resolved`, `vulnerabilities_carried_forward`, etc. — discoverable by reading the function's `RETURN jsonb_build_object(...)` block) to `DEFAULT_IGNORE_FIELDS` for **values that are run-id or count-driven** but keep the key set itself in the diff. This catches "finalize_extraction now returns 4 keys instead of 5" (regression) but not "vulnerabilities_added went from 3 to 4" (data drift).
- Add a per-fixture `snapshot-ignore.json` mechanism extension: today it's a flat `ignore_fields` set (`snapshot.ts:325-337`). Extend to also support `ignore_paths` (JSONPath-style: `summary.finalize_summary.vulnerabilities_added`) for value-precision ignores. This is a 30-line change to `stripIgnored()` + the schema. Necessary because count-deltas in finalize_summary will drift run-to-run on test-npm if any vulnerability gets added/removed upstream.

**Recommendation:** ship 3.1 with finalize_summary's full key set unredacted on `test-minimal-npm` (where dep counts are stable) and use the new `ignore_paths` feature on `test-npm` for the count fields.

### 3.2 — Commit `semgrep.json` snapshots vs. add to allow-list

**Current state (verified):**

- `output.ts:105` writes `semgrep.json` on every run.
- `snapshot.ts:273-277` reads `outputs = readdirSync(resultDir).filter(f => f.endsWith('.json'))` — **all** JSON in the result dir.
- The runner now auto-bootstraps missing snapshot files (jest-style: missing file → write + pass on first run; subsequent runs compare). So a never-committed `semgrep.json` produces a one-time "bootstrapped 1 new (semgrep.json)" pass message; the contributor commits the file and future regressions fire as real diffs.

**Why the suite has been silently passing despite missing `semgrep.json` in `snapshots/`:** verified — `fixtures/test-minimal-npm/snapshots/` listing returned 6 files, no `semgrep.json`. Before the auto-bootstrap fix, the runner failed every run with "new file (not in snapshot dir)" but only when `expectClean: true` actually compared snapshots — and this fixture's CI gating may have been masking the failure. Now that the runner bootstraps the file on first run, the question collapses: just run the suite once to bootstrap, commit the resulting `snapshots/<fixture>/semgrep.json` files, and the regression surface is in place.

**Recommendation: option (a) — commit `semgrep.json` snapshots, with empty `[]` for fixtures that have no findings.**

Trade-off honestly: option (b) — per-fixture allow-list — has the appeal of letting Semgrep version bumps not churn snapshots. But the contributor-test goal here is exactly to catch when a Semgrep version bump changes behavior. The right disposition for a Semgrep version bump is "you have to update the snapshot deliberately, and the PR makes that explicit." Allow-list hides that signal.

Specific implementation:
- For `test-empty` + `test-minimal-npm`: snapshot is `[]`. Hard pin.
- For `test-npm`/`test-python`/`test-java`/`test-go` (slow): commit whatever the current run produces. Add `rule_id`, `message_signature` (if exists) to `DEFAULT_IGNORE_FIELDS` only if a single warm run shows non-determinism within a Semgrep version. Document the contract: "if you change any Semgrep ruleset, you must `npm run test:fixtures:update --include-slow` and review the diff."
- For the new reachable-express-lodash fixture (Section 2): pin actual Semgrep output (likely a small set of generic-JS findings; lodash itself doesn't trigger Semgrep).

Effort: S (~half day to commit snapshots, half day to chase the runner bug if it exists). Risk: low — the underlying mechanism is already there.

### 3.3 — Volatility: EPSS / CVSS / cisa_kev / published_at

**Recommend: add to `DEFAULT_IGNORE_FIELDS`. Do not stub via `DEPTEX_OFFLINE=1`.**

Rationale: stubbing forces a second code path (mocked vs live) and introduces a "the mock got out of date" failure mode. Ignoring the field at diff time keeps the values **in the snapshot** as documentation of what the run produced, but doesn't gate the test on them. Contributors get a real signal ("the snapshot says 0.0025 today") without breaking when EPSS publishes a daily delta tomorrow.

**Specific edits to `snapshot.ts:59-85`:**
```
'epss_score',          // changes daily
'cvss_score',          // re-fetched from NVD; stable but float-formatted differently across runs
'cisa_kev',            // CISA publishes new KEV entries weekly
'published_at',        // technically stable per CVE but represented inconsistently in vendor data
'reachability_computed_at',  // only present on malicious_findings (1240, schema)
```

**Counter-argument considered:** stubbing would let us *also* pin "the EPSS for CVE-X is 0.0025" forever, catching the "the EPSS API contract changed and we now parse zeros for everything" regression class. Counter-counter: that regression is invisible to a snapshot suite anyway — pipeline.ts:1310-1330 swallows fetch errors silently (verified at line 1310 — no error throws on EPSS fetch failure). The right place to catch EPSS-API-shape regressions is a dedicated `test/epss-fetch.test.ts` (out of scope for this plan).

**Effort:** ~5 LOC + regenerate every snapshot once. Risk: low.

**Edge case:** the current `test-minimal-npm/snapshots/vulns.json` has `epss_score: "0.0025"` as a *quoted string* — verify it's stored as string not numeric, and ensure `stripIgnored()` removes both shapes. The walker at `snapshot.ts:347-362` deletes by key regardless of value type, so this is fine.

---

## Section 4 — Regen UX

Five concrete fixes. Ship as a second PR after 3.

### 4.1 — `npm run test:fixtures:update` script alias

`package.json:47` adds: `"test:fixtures:update": "tsx test/snapshot.ts --update"`.

Convention follow-on: `"test:fixtures:slow": "tsx test/snapshot.ts --include-slow"` and `"test:fixtures:slow:update": "tsx test/snapshot.ts --update --include-slow"`. Four scripts total. Effort: trivial.

### 4.2 — `--diff-only` / `--print-changed` dry-run flag

Add to `parseArgs` options at `snapshot.ts:90-97`. Semantics: `--diff-only` runs everything, but instead of exiting 1 on mismatch, prints the diff and exits 0. Lets a contributor run `npm run test:fixtures -- --diff-only --update=preview` and see what they're about to commit before committing.

Better naming after thinking: keep `--update` as is, add `--print-changed` which acts like `--update` but writes to `<snapshotDir>.preview/` instead of `snapshotDir/`. This way the "dry run" is comparing the preview dir to the real snapshot dir and the contributor can `diff -r snapshots/ snapshots.preview/` themselves.

Effort: ~30 lines. Risk: low.

### 4.3 — Raise diff truncation cap

`snapshot.ts:309-313` truncates at 10. **Recommend: raise to 200, with a `--max-diff=<n>` override (default 200).** Reasoning: the audit notes ~1000 leaf paths on big fixtures — 200 is enough to read most diffs comfortably without flooding terminal output, but the override lets `--max-diff=10000` for debugging. Don't go to unlimited by default — pathological diffs (whole snapshot mismatch) will wreck CI logs.

Effort: ~5 lines. Risk: trivial.

### 4.4 — Workspace-rename recovery doc

`snapshot.ts:169-179` parks `snapshots/` to `os.tmpdir()/deptex-snapshot-<fixture>-<pid>/`. The `try/finally` at 184-193 restores it on normal flow + exception. **Real failure mode:** `kill -9` on the runner mid-run, or an OOM. The `finally` doesn't run; `snapshots/` is in tmpdir and the workspace has no snapshot dir.

Add to `CONTRIBUTING.md` section "Recovering from a crashed snapshot run":
```
If `npm run test:fixtures` crashes hard (kill -9, OOM, host shutdown):
1. Look in `os.tmpdir()` (e.g. `/tmp` on Linux/macOS, `%TEMP%` on Windows) for `deptex-snapshot-<fixture>-<pid>` directories
2. If found, the directory is your committed snapshot dir, parked there to keep TruffleHog from scanning it
3. Move it back: `mv /tmp/deptex-snapshot-test-minimal-npm-12345 depscanner/fixtures/test-minimal-npm/snapshots`
```

Better fix: change the park location from `os.tmpdir()` to `<workspace>/.snapshot-park-<fixture>/` and add to `.gitignore`. Recovery is then "just look in the workspace; the fixture's own snapshot dir is at `.snapshot-park-<fixture>` — rename it." Less tribal knowledge.

Recommendation: do BOTH — change the park location AND document the recovery in CONTRIBUTING. Effort: 10 LOC + 5-line docstring.

### 4.5 — Docker image freshness check

`bin/deptex-scan` (the wrapper) is invoked at `snapshot.ts:233`. It uses `deptex-cli:local` (built by `npm run docker:build`). If the image is stale (e.g. contributor edited `src/cli/scan.ts` but forgot to rebuild), the snapshot run is silently using yesterday's binary.

**Recommend:** at runner startup, fingerprint the source by hashing all `.ts` files under `depscanner/src/` + `depscanner/Dockerfile` and compare to a label baked into the image. If image is older than source, print a loud warning (don't auto-rebuild — that surprises contributors with multi-minute Docker builds in the middle of what they thought was a 30s run).

Implementation: at Docker build time, embed `git rev-parse HEAD` + `find src -newer Dockerfile -name '*.ts' | wc -l` into a `LABEL deptex.source.fingerprint=<hash>`. At runtime, the runner does `docker inspect deptex-cli:local --format='{{ .Config.Labels.deptex.source.fingerprint }}'` and compares to the live computed hash. Mismatch → stderr warning + 3-second sleep so the contributor reads it.

Effort: ~50 LOC (hash computation + Docker LABEL injection + warning). Risk: low. Skip on first iteration if scope is tight; warn loudly in CONTRIBUTING.md instead.

**Combined Section 4 effort: M (~1.5 days).**

---

## Section 5 — Speed

**Recommendation: option (a) — targeted fixture selection via `--tag`.**

Concrete design:
- Add a `tags: string[]` field to `FixtureManifest` (`snapshot.ts:37-48`).
- Tag fixtures: `test-minimal-npm: ['npm', 'baseline']`, `test-reachable-express-lodash: ['express', 'npm', 'reachable']`, `test-npm: ['npm', 'slow']`, `test-go: ['gin', 'go', 'slow']`, etc.
- Add `--tag=<name>` / `--tag=<n,n,n>` parseArgs option. `--tag=express` matches any fixture whose tags include `express`.
- A contributor changes `express.yaml` → `npm run test:fixtures -- --tag=express`. Runs the reachable-express-lodash fixture (and any future express fixtures) without booting the full suite.

**Why option (a) beats (b)/(c)/(d):**

- (b) — content-hash-keyed cache for cdxgen/dep-scan: the cache invalidation surface is huge. cdxgen's output depends on cdxgen version, network availability, and registry state. A stale cache that produced a passing snapshot for the wrong reason is exactly the failure mode this whole plan exists to prevent. Reject.
- (c) — in-process snapshot mode (mock cdxgen, run engine directly): tempting but redirects ~30% of the engine's value (the CLI integration boundary). Snapshots would no longer test the wrapper script, the Docker bind-mount logic, or the seed step. Reject for the contributor-grade test surface; **revisit for a separate `npm run test:taint-engine-e2e` script** that's explicitly a fast inner loop for engine devs.
- (d) — accept-slow-locally + parallel CI: pragmatic but defers the contributor problem. Pick (a) primarily; do (d) in addition.

**Trade-off honestly disclosed:** option (a) only helps when a contributor *knows what they changed touches express*. If they refactor a shared engine internal that affects every framework, `--tag=express` undertests. Mitigation: the pre-push checklist (Section 6) tells contributors which tag set to invoke for which kind of change. For "I edited a core taint-engine file" the answer is `npm run test:fixtures` with no tags — full suite.

**Combined Section 5 effort: S (~half day for the tag mechanism + per-fixture metadata).**

**Side note on Windows-Docker speed:** the audit notes 12-25 min cold on Windows due to bind-mount overhead. The tag mechanism doesn't solve this — it just lets contributors run fewer fixtures. **Out-of-scope additional ask** that Henry should weigh: switch from bind mounts to `docker cp` for the workspace on Windows, OR document WSL2 as the recommended dev environment. Both are PR-class changes. Defer.

---

## Section 6 — Pre-push contributor checklist

Add to `CONTRIBUTING.md` after the existing "Adding New Features" section. Section title: **"Before you push: snapshot test surface."**

Body (proposed prose; final wording is a writing pass):

```
Depscanner ships a snapshot test suite at depscanner/test/snapshot.ts. The suite
runs the deptex-scan CLI against fixtures under depscanner/fixtures/ and diffs
the JSON output against committed snapshots. Run it before every PR.

# Quick reference

| What did you change?                              | Run this                                             |
|---------------------------------------------------|------------------------------------------------------|
| A framework spec at src/taint-engine/             |                                                      |
|   framework-models/<name>.yaml                    | npm run test:fixtures -- --tag=<name>                |
| A language module at src/taint-engine/<lang>/     | npm run test:fixtures -- --tag=<lang>                |
| A taint-engine internal (callgraph, ir.ts,        |                                                      |
|   propagator, fp-filter, storage)                 | npm run test:fixtures (full default suite)           |
| A scanner wrapper (semgrep, trufflehog, dep-scan) | npm run test:fixtures && npm run test:fixtures:slow  |
| Anything in src/cli/                              | npm run test:fixtures (catches CLI regressions)      |
| A new framework spec or new language fixture      | npm run test:fixtures:update -- --tag=<new>          |
|                                                   | + commit the new snapshots                           |
| A schema migration                                | cd depscanner && npm run schema:dump (refreshes      |
|                                                   | depscanner/.schema/schema.sql) — gated by CI         |

# Updating snapshots

If your change is intentional and you've audited the diff:
  npm run test:fixtures:update                # default (fast) fixtures
  npm run test:fixtures:slow:update           # full suite (12-25 min)

Then commit the resulting depscanner/fixtures/<name>/snapshots/*.json files
in the same PR as your code change. PRs that update snapshots without an
explanation in the PR body will be flagged.

# Crashed mid-run?

See "Recovering from a crashed snapshot run" below.
```

Plus the recovery subsection from §4.4.

Effort: half day for prose + review. Risk: trivial.

---

## Section 7 — Fixture matrix expansion

Minimum-cost fixtures to add for ruby / rust / php / csharp at `test-minimal-npm` sophistication. Goal: one direct dep + one known CVE per ecosystem. NOT slow. `package.json`-equivalent + a 3-line source file + committed lockfile.

| Ecosystem | Fixture name           | Dep + version              | CVE                  | Manifest           | Source language | Notes |
|-----------|------------------------|----------------------------|----------------------|--------------------|-----------------|-------|
| Ruby      | `test-minimal-ruby`    | `nokogiri 1.13.0`          | CVE-2022-24836       | `Gemfile.lock`     | `app.rb`        | Stable, well-known XML parser CVE. dep-scan VDR confirmed. |
| Rust      | `test-minimal-rust`    | `regex 1.5.4`              | CVE-2022-24713       | `Cargo.lock`       | `src/main.rs`   | ReDoS in regex, requires real Cargo.lock — generate once via `cargo generate-lockfile`. |
| PHP      | `test-minimal-php`     | `guzzlehttp/guzzle 6.5.0`  | CVE-2022-29248       | `composer.lock`    | `index.php`     | Cookie middleware vuln. |
| C#       | `test-minimal-csharp`  | `Newtonsoft.Json 12.0.2`   | CVE-2024-21907       | `packages.lock.json` + `<csproj>` | `Program.cs` | StackOverflow on deserialization. |

**Per-fixture marker `expectClean: true, expectedExitCode: 0, slow: false, tags: ['<ecosystem>', 'baseline']`.** Pin `summary.json` (counts) + `deps.json` (the single direct dep) + `vulns.json` (the single known CVE row) + empty `entry_points.json` + empty `reachable_flows.json`. **Do NOT** try to make these reachable in the v1 — that's a bigger scope. The point is to surface basic SBOM extraction + dep-scan VDR coverage per language.

**Effort per fixture: S (half day each), plus dep-scan VDR validation.** **Combined: M (~2-3 days for all 4).**

**Risk:** dep-scan VDR coverage on a particular CVE for a particular pinned version isn't guaranteed. Pre-validate by running `dep-scan` against the candidate dep+version before committing the fixture; if it doesn't flag the CVE, swap to a different one. Concrete pre-validation command per ecosystem inferred from `pipeline.ts` (the `dep-scan --src ... --type <ecosystem>` invocation).

**Why these CVEs not the v1:** picked CVEs that are old enough (2+ years) to be in dep-scan's vendor advisory mirror reliably, low-noise (don't pull half a CVE chain on transitive deps), and on packages where `<2 KB lockfile` is achievable.

---

## Section 8 — CI surface

**Current state (verified):**

`.github/workflows/test.yml:63-91` defines a `depscanner` job that runs only `type-check` + `test:taint-engine-all` (preflight). **`test:fixtures` is not run in CI today.** The snapshot suite exists locally but PRs land without ever running it.

**Recommendation: hard-fail on snapshot drift, with diff visible in two surfaces.**

1. **Add `test:fixtures` to the `depscanner` CI job, after the preflight step.** Run it without `--include-slow` (default suite: `test-empty` + `test-minimal-npm` + `test-reachable-express-lodash` + the four new minimal-language fixtures from §7). On a warm Docker layer cache this should hit ~2-3 min. Hard-fail (exit 1) on snapshot drift; this gates merge.
2. **Run `--include-slow` on a separate parallel CI job (`depscanner-slow`).** Same gating — hard-fail on drift. Keep it separate so a slow-fixture failure doesn't block diagnosing the fast suite.
3. **Make the diff visible in the PR.** When `tsx test/snapshot.ts` exits 1, capture stdout to an artifact and post it as a PR comment. Concretely: an `actions/github-script@v7` step that reads the artifact and uses `octokit.rest.issues.createComment`. Cap comment size at 50KB; link to the artifact for larger diffs. **Do NOT** post on success — only on drift.

**Why hard-fail not warning:** the audit's central observation is that the snapshot suite has been silently passing on broken state for some unknown duration. The fix is to make it loud. A "warning + commit-status" path lets contributors merge with red status; we've seen what that produces (`semgrep.json` has been silently absent for a while). Hard-fail.

**Trade-off honestly:** hard-fail will burn Docker cache misses on early CI runs. Mitigate by registering the depscanner Docker image as a CI cache layer (`actions/cache@v4` keyed on Dockerfile + src/ hash). One-time setup, ongoing zero-cost.

**Effort: M (~1 day for the workflow YAML changes + cache setup + artifact-to-comment script).** Risk: low — pure CI plumbing. Worst case: rate-limiting on Docker Hub during cache miss, mitigated by GitHub-hosted runners' egress.

---

## Section 9 — Implementation roadmap

Six PRs, smallest-first. Each PR is independently mergeable; later PRs assume earlier ones merged.

| # | PR title                                              | Sections | Effort | Depends on | Risk    | Notes |
|---|-------------------------------------------------------|----------|--------|------------|---------|-------|
| 1 | `feat(depscanner): snapshot infra surgical fixes`     | 3.1, 3.2, 3.3 | M (~2d) | nothing    | Low-Med | The bug-investigation step in 3.2 is the swing factor. |
| 2 | `feat(depscanner): regen UX (test:fixtures:update + diff cap + park location)` | 4.1-4.4 | M (~1.5d) | PR 1       | Low     | 4.5 (image freshness) defer to PR 2.5 if needed. |
| 3 | `feat(depscanner): reachable-express-lodash fixture`  | 2        | M-L (2-5d) | PR 1, 2   | Med     | Risk surface = engine actually emitting the flow + entry-point detector covering Express. |
| 4 | `docs(depscanner): contributor pre-push checklist`    | 6        | S (~0.5d) | PR 1, 2, 3 | Trivial | Snapshot guidance only useful once snapshots are correct. |
| 5 | `feat(depscanner): tag-based fixture selection`       | 5        | S (~0.5d) | PR 1, 3   | Low     | Mostly mechanical. |
| 6 | `feat(depscanner): minimum fixtures for ruby/rust/php/csharp` | 7 | M (~2-3d) | PR 1, 2   | Med     | Per-CVE dep-scan validation can stretch this. |
| 7 | `ci(depscanner): run test:fixtures on PRs`            | 8        | M (~1d) | All above | Low     | Gates merge once everything else is green. Last on purpose. |

**Total effort: ~10-13 dev-days.** Spread across 4-6 weeks for one engineer at 30-50% time, given review + iteration.

**Critical-path note:** PRs 1-3 are the "fix the bug" sequence; PRs 4-7 are productionization. If schedule pressure forces a halt after PR 3, the suite is at "real" not "great" — useful but undocumented and not enforced. Don't halt before PR 3 — landing 1+2 without 3 just polishes a still-dark surface.

---

## Section 10 — Open questions for Henry

These are decisions the plan doesn't make on its own:

1. **Stub vs filter on EPSS/CVSS volatility (Section 3.3).** Plan recommends filter. Pre-launch, you might want stubbing instead so we can pin EPSS values as documentation of "this is the CVE score we computed depscore against." Worth a 5-min thought.

2. **Reachable fixture: lodash-Express vs Spring Boot path-traversal.** Plan picks Express. If you'd rather diversify by language and accept the slow Maven build cost, Java is the alternate. Cheap to swap if you say so before PR 3 starts.

3. **Hard-fail vs commit-status on CI snapshot drift (Section 8).** Plan recommends hard-fail. You might prefer commit-status while we burn in the new fixtures (1-2 weeks of "snapshot churn allowed without merging blocked") then flip to hard-fail. Acceptable; just say which.

4. **Image freshness check (§4.5).** Genuinely optional. ~50 LOC. Docker is a hard prereq (see header), so the question is just whether the runner detects a stale `deptex-cli:local` image automatically, or whether `CONTRIBUTING.md` simply says "rebuild Docker before running snapshots" and we trust contributors to follow it.

5. **Tag taxonomy (Section 5).** The proposed tags are `npm/python/java/go/ruby/rust/php/csharp/express/gin/spring/.../baseline/reachable/slow`. That's a flat namespace. If you want hierarchical (`framework:express`, `lang:go`, `category:reachable`) the runner change is ~10 extra LOC. Up to you; flat is simpler.

6. **Snapshot-parking location (§4.4).** Plan recommends moving from `os.tmpdir()` into `<workspace>/.snapshot-park-<fixture>/`. The downside is contributors who `find . -type d` see a wart inside their fixtures dir (briefly, mid-run). Low-stakes opinion call.

7. **Should `test:fixtures` block on the build of the Docker image?** Docker itself is a hard prereq (see header) — this question is only about whether the `deptex-cli:local` image is already built when the runner starts. Today the runner relies on `npm run docker:build` having been run at least once. Options: (a) auto-rebuild if the image is missing, (b) loud error pointing at `docker:build`, (c) bake the build into a `pretest:fixtures` npm hook. Plan didn't pick — your call. Recommend (b) so the multi-minute Docker build never surprises a contributor mid-`test:fixtures`.

8. **`finalize_summary` field set on `summary.json`.** §3.1 says "read the function once and decide which fields to ignore-by-path." The function is at `schema.sql:3519+`. If the return shape includes anything inherently random (a `run_id` or per-row `id`), they should join `DEFAULT_IGNORE_FIELDS`. I haven't read the full function body in this plan — that's a 30-minute task in PR 1.

---

## Appendix A — Alternates considered

**Spring Boot path-traversal as the v1 reachable fixture.** Rejected: Maven cold-build cost (~3-5 min) puts the fixture out of the <90 s budget. Acceptable as a v2 reachable fixture once the suite is otherwise green, especially because Java diversity is genuinely valuable.

**ESLint-style "snapshot-driver" inversion.** Instead of checked-in JSON files, a single `expected.config.ts` per fixture that declaratively names the assertions ("this fixture should produce a flow with osv_id X"). Rejected: it's a bigger refactor than the surgical fixes; no contributor has asked for it; the JSON snapshot pattern is conventional and grep-able. Park as a v3 idea.

**Vitest / Jest wrappers.** The existing runner is hand-rolled in `snapshot.ts`. Wrapping it in vitest gives prettier output, parallelism, and CI-native reporting. Rejected for now: scope creep and the runner has fixture-orchestration concerns (Docker workspace bind-mounts, snapshot parking) that don't fit `it.each` neatly. Park as a v3 idea.

---

## Appendix B — Files referenced (grep-verified)

- `depscanner/test/snapshot.ts` (whole file; 419 LOC). Key edits at 50-57 (FIXTURES), 59-85 (DEFAULT_IGNORE_FIELDS), 90-97 (parseArgs), 233-244 (runCli + Docker wrapper), 309-313 (diff truncation cap), 169-179 (snapshot park).
- `depscanner/src/cli/scan.ts:124, 138-147` — finalize_summary plumb point.
- `depscanner/src/cli/output.ts:51, 68, 99, 105` — writeOutputs API; semgrep.json write site; finalize_summary insertion point.
- `depscanner/src/pipeline.ts:2499-2554` — finalize_extraction RPC; data discarded today.
- `depscanner/src/pipeline.ts:1210-1330` — EPSS/KEV fetch (irrelevant if we filter at diff time, relevant if we stub).
- `depscanner/src/taint-engine/storage.ts:122-220` — writeFlows row shape; reachable_flows.json schema.
- `depscanner/src/taint-engine/storage.ts:312-358` — flow_signature_hash canonicalization.
- `depscanner/src/taint-engine/framework-models/express.yaml:1-81` — Express spec; sources at 13-43, sinks at 45-79.
- `depscanner/test/cve-targeted-flow-fixtures/js-lodash-template-injection/{meta,spec}.json` + `src/{server,render}.ts` — reference structure for §2.
- `depscanner/fixtures/test-minimal-npm/{package.json,index.js,snapshots/*.json}` — baseline fixture pattern.
- `depscanner/fixtures/test-go/snapshots/entry_points.json:2-34` — non-empty entry_points reference shape.
- `backend/database/schema.sql:1148-1165` — project_entry_points columns.
- `backend/database/schema.sql:1353-1375` — project_reachable_flows columns.
- `backend/database/schema.sql:3519-3520` — finalize_extraction RETURNS jsonb.
- `.github/workflows/test.yml:63-91` — depscanner CI job (today: type-check + preflight only).
- `depscanner/package.json:9-51` — npm script catalog (today: no test:fixtures:update, no test:fixtures:slow).
- `CONTRIBUTING.md:33-40` — existing "Adding New Features" — insertion point for §6 checklist.
- `docs/depscanner-hardening-report.md:132-181` — Day-1 audit findings this plan closes.
