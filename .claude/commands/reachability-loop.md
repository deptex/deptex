# Reachability Self-Improvement Loop

You are running an **autonomous self-improvement loop** on the Deptex reachability engine. You scan real open-source application repos, evaluate the findings we produce, and then — for **every finding stuck at the `module` reachability level** — you dig in and answer one question: *why couldn't we give this a confident verdict (reachable or not-reachable), and can we fix the engine so we could?* When the answer is "yes, we could do better," you fix the engine, verify it, re-scan to confirm the finding moved, and loop. When (and only when) you're **provably certain** it's impossible to resolve without executing the app, you record why and move on.

This is `/evaluate-findings` pointed at the **reachability quality gap** and wired into a `/marathon`-style loop that **actually ships fixes** instead of just reporting them. The north star is Henry's: **minimal noise, maximal honesty.** Every finding should resolve to a *confident* verdict — confidently shown (reachable) or confidently hidden (not reachable). The `module` bucket is the "I'm not sure" middle, and "I'm not sure" is exactly where silence false-negatives hide. The loop's job is to drive that bucket toward zero — and to *prove* that whatever's left in it is genuinely undecidable, not a miss we never noticed.

## The reachability model (the thing this loop moves)

Tiers, lowest to highest: `unreachable`(0) → `module`(1) → `function`(2) → `data_flow`(3) → `confirmed`(4).

- **SILENCED** (phase48 auto-ignore, hidden from the user): `unreachable` and `module`.
- **VISIBLE** (shown as active findings): `function`, `data_flow`, `confirmed`.
- **`module` = "the dependency is present and used, but we could not prove the specific vulnerable function sits on a live, attacker-reachable path."** It's hidden, so from a noise standpoint it's fine — *unless* the path is genuinely exercised, in which case hiding it is a **silence false-negative** (the north-star failure).

**Two ways a finding climbs out of `module`:**
1. **Up to reachable** (`function`/`data_flow`/`confirmed`) — either the cross-file taint engine builds a request→sink flow (needs a mapped entry point + a source→sink path through `framework-models/*.yaml` specs), or symbol-verification confirms the vulnerable function is actually called (needs the dep's usage detected at the call site + a CVE-targeted sink pattern).
2. **Down to unreachable** — we prove the vulnerable code is genuinely not on any runtime path (dead code, dev-only scope, unused export).

**Why a finding gets *stuck* at `module` — the root-cause taxonomy** (this is what you diagnose and fix):
- `alias_blindness` — the app renames the dep at the call site (`var pr = require('path-to-regexp'); pr(...)`), so the name-based usage check misses it → `function`-tier never fires. **Fixable:** resolve aliases/re-exports in usage detection.
- `missing_sink_spec` — no CVE-targeted sink pattern authored for this CVE, so symbol-verify can't run. **Fixable:** author the sink spec (`framework-models/*.yaml` / cve-specs).
- `unmapped_entry_point` — on a real app we found **zero (or too few) entry points**, so the taint engine had no source to start a flow from. **Fixable:** add/repair the framework entry-point detector. (See the express caveat below — this is only a bug on a *real app*; on a framework-library repo, no entry point is *correct*.)
- `propagator_truncation` — a flow started but truncated before reaching the sink (non-convergence, depth cap, an unhandled IR shape). **Fixable:** extend the propagator / lowerer.
- `sca_instance_mismatch` — the CVE attached to the wrong copy of a package (e.g. a dev-transitive `cookie@0.4.1` instead of the prod `cookie@0.5.0`). **Fixable:** pin the instance in SCA matching.
- `genuinely_undecidable` — reachability truly depends on runtime config/input not present in source, and a careful human can't decide it from the code either. **`module` is the correct terminal answer. This is the ONLY acceptable "give up" verdict, and it requires a written justification.**

## The express caveat (do not manufacture phantom failures)

**Framework-library repos are the wrong measurement vehicle** and must never be triaged as under-reached. Scanning a framework *by itself* (express, fastify, the Django source tree) means there's no application driving it — so its own runtime deps can *only* ever reach `module`, and that's correct, not a miss. Such repos are marked measurement-only in the corpus (`ground_truth_cves: []`) and the loop **skips their module findings entirely**.

The valid vehicle is **real application repos**: an app declares a few deps, pulls a large transitive tree it doesn't fully exercise, and has real request entry points, so a genuinely-exercised path *can* form a `data_flow`/`confirmed` flow. Distinguish carefully:
- Module finding on a **framework-library repo** → correct-conservative, **skip**.
- Module finding on a **real app** where we found **zero entry points** → that's an `unmapped_entry_point` **bug**, not conservatism. Fix the detector.

## When to invoke

Good fits: "run the reachability self-improvement loop for a while", "keep scanning OSS apps and fixing why findings are stuck at module", "self-improve the engine against the corpus".

Bad fits: a single known engine bug (just fix it); building a new scanner category (that's `/plan-feature` → `/implement`); measuring the noise-reduction *score* without fixing anything (that's the corpus scorer alone — `reachability-corpus.ts`).

## Invocation

- `/reachability-loop` — set up (or adopt) the loop, scan the app corpus, and start looping: triage every `module` finding, fix the highest-leverage causes, re-scan, repeat until told to stop.
- `/reachability-loop --repos=<path>` — corpus source (default: the app entries in `depscanner/scripts/reachability-corpus.yaml`).
- `/reachability-loop --only=<repo>` — focus a single repo (fast iteration on one finding cluster).
- `/reachability-loop --triage-only` — diagnose + fill the ledger but make **no engine changes** (read-only survey; good for a first pass or when Henry wants to see the gap before authorizing fixes).
- `/reachability-loop --resume` — pick up from the ledger after a compaction/overnight pause (recovery is mechanical if end-of-tick state was synced).

## Phase 0 — Setup (one-time, at loop start; skip if adopting an existing loop)

1. **Worktree.** Run inside a dedicated worktree off `origin/main` (adopt the current one if already in it; else `/create-worktree reachability-loop`). Never edit the primary tree. Copy `.env` + `npm install` per the create-worktree skill.
2. **Corpus.** Confirm `reachability-corpus.yaml` holds real **app** repos with hand-labelled ground-truth CVEs, and that every framework-library repo (express, fastify, …) is marked `ground_truth_cves: []` (measurement-only). If a labelled repo is actually a framework library, demote it before scanning — a mislabel here manufactures fake silence-FNs.
3. **Images.** Ensure the CLI Docker image reflects the **current engine HEAD** (this is what makes fixes verifiable — an engine edit doesn't take effect in a scan until the image is rebuilt). Build it the same way `deptex-cli:corpus-final` was built (`npm run build` → `docker build -t deptex-cli:selfimprove depscanner/`). Fast-scan env: `DEPTEX_SKIP_OPTIONAL_SCANS=1` + `DEPTEX_OSV_FALLBACK=1`; VDB cache `~/.deptex/vdb`.
4. **Source-of-truth files** (in the worktree — compaction-safe, these ARE the loop's memory):
   - `.cursor/plans/reachability-loop-LEDGER.md` — the module-finding ledger + iteration journal. One row per module finding: `repo · dep · CVE · verdict · root_cause · ground_truth · fix (commit SHA or deferral reason) · before→after level`. Plus a per-iteration `## Iteration N` section.
   - `docs/reachability-loop-report.md` — the living quality report: current module-bucket size across the corpus, per-root-cause counts, silence-FN rate, and the ranked "fixes that would recover N findings" list. This is the artifact the loop ships.
5. **Memory.** Update `corpus_noise_reduction_state.md` (or a dedicated loop state file) with worktree path, branch, base SHA, ledger + report paths, and the on-resume protocol.

## Phase 1 — Scan the app corpus

Run the harness against the app repos with the current-engine image:
```bash
DEPTEX_CLI_IMAGE=deptex-cli:selfimprove DEPTEX_SKIP_OPTIONAL_SCANS=1 DEPTEX_OSV_FALLBACK=1 \
  npx tsx depscanner/scripts/oss-corpus.ts --repos=depscanner/scripts/reachability-corpus.yaml --output=<run-dir> [--only=<repo>]
```
Then score for context (module-bucket size, silence-FN rate, gates):
```bash
npx tsx depscanner/scripts/reachability-corpus.ts --report=<run-dir>/report.json
```
The scorer emits the gates + the silence score (`evaluateSilenceScore` → `silence-score.json`). Record the starting module-bucket size in the living report — that's the number the loop drives down.

## Phase 2 — Harvest the module work-queue

From the scan artifacts (per-repo `runs/<repo>/`: `vulns.json`, `reachable_flows.json`, `entry_points.json`, usage slices), extract **every finding at `module` level** on a **real app** repo. Skip framework-library repos. This list is the loop's work-queue; write it into the ledger with status `pending`.

## Phase 3 — Triage (parallel, READ-ONLY)

Fan out **read-only** subagents (`Explore` or `general-purpose`), clustered by dependency (co-located findings judged together catches shared root causes). Each agent gets the stable repo/run context first (cache-friendly), then its cluster, and MUST:
1. Read the **actual app source** at the call site — confirm whether the vulnerable function is genuinely reachable from a real entry point on a real request path.
2. Reconcile the scan artifacts: were entry points found? did any flow form and attach to this dep? did the usage slice see the dep (by name)? is there a CVE sink spec? is the matched package instance the one actually used at runtime?
3. Return strict JSON (no prose):
```json
{
  "finding": "<repo>:<dep>@<version>:<cve>",
  "verdict": "UNDER_REACHED | OVER_CAUTIOUS | CORRECT_MODULE",
  "ground_truth": "reachable | not_reachable | undecidable",
  "root_cause": "alias_blindness | missing_sink_spec | unmapped_entry_point | propagator_truncation | sca_instance_mismatch | genuinely_undecidable",
  "evidence": "<file:line proving the call path (or its absence)>",
  "fix_sketch": "<the concrete engine change that would resolve it — which file/spec>",
  "impossible_justification": "<REQUIRED iff root_cause=genuinely_undecidable: why no source-only analysis, human or engine, can decide this>"
}
```

**The 100%-impossible bar.** `CORRECT_MODULE` / `genuinely_undecidable` is the *only* acceptable "we can't do better" verdict, and it demands a written `impossible_justification` a skeptic would accept ("reachability depends on a runtime env var / operator-supplied route pattern / plugin loaded at deploy time, absent from source"). Anything short of that defaults to `UNDER_REACHED` (or `OVER_CAUTIOUS`) with a `fix_sketch` — i.e. **assume it's fixable and try, unless proven otherwise.**

Cluster the verdicts into the ledger and rank root causes by how many findings each fix would recover — that ranking drives Phase 4.

## Phase 4 — Improve (SERIAL, verified, one fix at a time)

Engine fixes are **serial, never parallel** — parallel agents editing the reachability engine / specs collide on hot files. Take the highest-leverage root cause and make **one generalizable engine change**:

- Prefer a **general** fix (alias resolution in usage detection, a reusable sink pattern, an entry-point detector, a propagator/lowerer extension) over per-repo special-casing. A change that recovers one finding via a hack that only works for one repo is **rejected** — it's not self-improvement, it's overfitting.
- **CVE sink specs** go in `framework-models/*.yaml` / cve-specs; **usage/alias** logic in the tree-sitter usage extractor; **entry points** in the framework detectors; **flow propagation** in the taint-engine propagator/lowerer.

Then run the **full verification gate** before accepting the change (all must be green):
1. `npx tsc --noEmit` (depscanner + backend if touched) — clean.
2. `npm run taint-engine:validate` — all spec/fixture pairs still pass.
3. `npm run test:taint-engine-*` (the languages you touched) — green.
4. Fixture **snapshot** suite — **byte-stable**. Never modify the byte-stable `depscanner/fixtures/test-*` inputs to make a fix pass.
5. `npm run dogfood:check` — the cross-batch regression gate stays green.
6. **Baseline-lock** (`checkBaselineLock`) — **no existing correct classification regressed.** Never relabel a corpus CVE or a fixture to flatter the metric; that's the cardinal sin (the scorer's baseline-lock exists to catch exactly this).
7. **Rebuild the CLI image** (`npm run build` → `docker build -t deptex-cli:selfimprove depscanner/`) and **re-scan the affected repo** (`--only=<repo>`). Confirm the target finding **moved** `module → function/data_flow/confirmed` (for UNDER_REACHED) or `module → unreachable` (for OVER_CAUTIOUS), **and nothing else regressed** (re-score, compare module-bucket + silence-FN before/after).

**If any gate fails → revert the change immediately** (`git checkout -- <files>`), record the failed attempt + why in the ledger, and either try a different fix or mark the finding deferred with the blocker. Never leave the engine in a red state to move on.

**On success:** checkpoint with a local commit (Conventional Commits, plain prose, no milestone labels, no Co-Authored-By, author as Henry) — one coherent commit per fix, for bisectability. **Do not push** — the loop accumulates commits on the worktree branch; Henry opens the single PR at the end. Update the ledger row with the SHA and before→after level, and refresh the living report's counts.

## Phase 5 — Loop

Move to the next finding / root cause. Re-scan the whole corpus periodically (not every fix — that's slow) to catch cross-repo regressions and refresh the module-bucket trend in the report. A tick is not done until the ledger + report on disk fully reflect reality (compaction discipline — see below).

**Stop conditions** (hard stops only — this is an open-ended loop, don't invent "natural pause points"):
- The user says stop / pause / wrap.
- Every remaining module finding is `CORRECT_MODULE` with an accepted `impossible_justification` — i.e. the bucket is genuinely irreducible from source. Report this and stand by.
- A gate fails in a way that needs a human decision (e.g. a fix would help one repo but regress another — surface the trade-off, don't unilaterally pick).

Per `/marathon`: an open-ended "keep self-improving" brief does **not** auto-close on a green test gate. "Diminishing returns", "clean stopping point", "treadmill" are self-justification traps. Keep scanning, keep finding stuck findings, keep fixing — until Henry says stop or the bucket is provably irreducible.

## Compaction safety (the loop must survive a compact / overnight)

Disk artifacts persist; conversation context does not. End every iteration with the ledger + report fully synced: every triaged finding recorded, every fix's commit SHA inlined the same turn it lands, every deferral's reason written, the current module-bucket trend updated. When self-pacing across pauses, use `ScheduleWakeup` with a `prompt` that restates: worktree path, branch, base SHA, recent fix commit SHAs, ledger + report paths, current module-bucket size, in-flight triage agents, and the next action. Recovery flow: read the ledger → check the worktree git log → resume at the latest `## Iteration N`.

## Rules (durable)

- **Fix, don't just report.** Unlike `/evaluate-findings`, this loop ships engine changes. But every change is verified and reverted-on-red.
- **Assume fixable; prove impossible.** The bar for "we can't do better" is a written justification a skeptic accepts. Default is to attempt a fix.
- **Generalizable fixes only.** No per-repo hacks to move a single number. A fix must be a real engine improvement.
- **Never relabel to flatter the metric.** Ground-truth CVE labels and byte-stable fixtures are frozen; `checkBaselineLock` guards them. Moving the number by softening a label is the cardinal sin.
- **Never modify `depscanner/fixtures/test-*`** — byte-stable snapshot inputs. The dogfood copies under `test-repos/` are the mutable ones.
- **Framework-library repos are measurement-only** — skip their module findings; they can't do better without an app.
- **Real app + zero entry points = a detection bug**, not correct conservatism. Fix the detector.
- **Triage parallel (read-only); fixes serial (verified).** Parallel engine edits collide.
- **Rebuild the image before re-scanning.** An engine edit is invisible to the scan until the Docker image is rebuilt.
- **Checkpoint-commit per verified fix; never push mid-loop.** Single final PR at the end; Henry opens it on github.com. Never use `gh`.
- **If a migration is unavoidable**, apply it via Supabase MCP and hand-patch `schema.sql` — do **not** run `npm run schema:dump` (it pulls prod drift). This loop should rarely touch migrations.
- **Don't gate on soft token caps.** Authorized, queued work gets dispatched; Henry signals explicitly to pause.
- **Compaction-safe every tick.** Ledger + report on disk fully reflect the loop's reality before standing down.

## Reference

- Harness: `depscanner/scripts/oss-corpus.ts` (scan/match/report), `depscanner/scripts/reachability-corpus.ts` (gates + baseline-lock + oracle + `evaluateSilenceScore`), `depscanner/scripts/reachability-corpus.yaml` (ground truth).
- Engine: `depscanner/src/taint-engine/` (propagator, lowerer, specs), `depscanner/framework-models/*.yaml` (sources/sinks/sanitizers), the tree-sitter usage extractor + framework detectors, and the reachability classifier (`updateReachabilityLevels`).
- Gates: `npm run taint-engine:validate`, `npm run test:taint-engine-*`, the snapshot suite, `npm run dogfood:check`.
- Sibling skills: `/evaluate-findings` (the findings-quality lens this specializes), `/marathon` (the loop/tick/compaction discipline this borrows), `/criticalreview` (persona lenses for the triage agents).
