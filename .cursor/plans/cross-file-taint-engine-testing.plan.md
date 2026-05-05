# Cross-File Taint Engine — Testing Roadmap

**Status:** draft. Branch `worktree-cross-file-taint-engine` @ `04d381b`, unmerged, gated on Phase 5.
**Scope:** validation/measurement only. No new features, no merge.
**Authoring stance:** Henry is solo dev; bias toward AI-driven crank work with short Henry sync windows.

---

## 0. Assumptions to confirm before starting

These cost <5 min each. Please confirm or correct.

1. **88-CVE corpus location.** Found Phase 5's evaluation corpus at `C:\Coding\Deptex\.claude\worktrees\reachability-phase5\backend\extraction-worker\test\iterate\candidates.ts` (88 entries × 5 ecosystems: 34 npm / 23 pypi / 16 maven / 9 golang / 6 rubygems). The cached patch metadata + diff outputs are at `...\test\iterate\cache\CVE-*.json`. **Assumption:** I'll author `test/taint-engine/benchmark/corpus.json` by adapting `candidates.ts` into the `BenchmarkCorpus` shape from `src/taint-engine/benchmark/corpus.ts`. CVEs without a clonable fixture project get `expectedFindings: []` (passthrough — they exercise loader/runner only). Confirm or point me at a richer source.
2. **Test repo locations.** Confirmed `C:\Coding\deptex-test-repos\deptex-test-{npm,python,java,go}\` exist and are minimal but real. **Assumption:** I'll use these for cross-ecosystem real-repo runs (Roadmap Unit 5) until something with actual vulns shows up. No equivalents for ruby/php/rust/csharp; I'll skip those for now.
3. **Shadow run target orgs.** **Assumption:** Henry's own dogfood org is the only "real customer" right now. The shadow run plan in Unit 8 will be "set `rollout_pct_override=100` on dogfood org, watch `taint_engine_runs` for a week before broadening." If there are external pilot orgs to canary on, name them.
4. **AI FP filter ground truth.** **Assumption:** For the signal/noise measurement (Unit 6), I'll use the existing 30 vuln/safe fixture pairs as ground truth (vuln=true-positive, safe=true-negative). 60 labeled flows is sufficient for first-pass threshold tuning. Real customer data later.
5. **Pre-launch latitude.** Per `feedback_solo_user_prelaunch.md`, I'll rewrite test scaffolding directly when needed and skip backwards-compat shims.

---

## 1. Roadmap units, prioritized by risk reduction

Each unit: independently runnable, clear pass/fail signal, AI-effort sized S/M/L/XL. **Unit ordering reflects risk-of-prod-bug-caught-first**; cosmetic coverage at the bottom.

### Unit 1 (M) — Engine-level invariant unit tests
**Why first:** these protect mid-flight fixes that are currently only fixture-validated. If propagate-core regresses, every language breaks silently.

**Deliverables:**
- New `test/taint-engine-invariants.test.ts` with explicit unit tests for:
  - `receiverRoot()` parsing across `q.name`, `q[0]`, `q->name`, `q::field`, `$q->name`, deeply chained `a.b.c.d`.
  - Receiver-as-args[0] convention: build a tiny `IrFunction` by hand with a method call, assert that `argument_indices: [1]` matches the first user-facing arg (not the receiver). One case per language IR (TS, Python, Java, Go, Ruby, PHP, Rust, C#).
  - Source-step receiver-fallback: synthesize a step where `target = q.name` and `q` is in `local`; assert `target` inherits `q`'s trace. Inverse: `q` not in `local` → target cleared.
  - Worklist termination: build a 4-function cycle with monotonic taint growth, assert convergence within iterations cap.
  - Worklist runaway: build a callgraph that would diverge if subsumption broke; assert `stoppedEarly=true` and `onWarn` fires once.
- Per-grammar IR workaround tests (exercise the actual parser, not a hand-built IR):
  - PHP `stripLeadingDollar`: assert `$q->input(*)` matches a spec pattern `q->input(*)`.
  - C# second-named-child fallback: parse `using (var x = req.Get())` and assert the IR has an assignment step for `x`.
  - Rust field_expression-as-function reroute: parse `Command::new("sh").arg(&p.cmd)` and assert the chained `.arg` lowers as a method call with the field-access receiver in `args[0]`.

**Henry sync:** review the invariants list before I start. I make assumptions about what "invariant" means here; he should sanity-check the list isn't missing something he's burned on before.
**Pass signal:** all new tests green; existing 196 tests still green.

### Unit 2 (L) — Per-language fixture matrix expansion (joint stdlib + framework)
**Why second:** the gaps Henry called out (#1, #3) are real recall holes. SQLi-only validation won't catch a Java path-traversal bug shipping on Monday.

**Approach.** For each non-JS language, validate one new vuln class per day in the order: XSS → path-traversal → SSRF → deserialization → log-injection → open-redirect → ReDoS. Each new class = one vuln/safe fixture pair per shipped framework, plus an explicit assertion per pair.

**Coverage matrix (target):**

| Language | Frameworks | Current pairs | Target pairs | Joint stdlib coverage? |
|---|---|---|---|---|
| Python | django, flask, fastapi | 6 (django SQLi, flask XSS+cmd) | 21 (3 fw × 7 new classes) | flask cmd already proves it; add 1 fastapi+stdlib SSRF pair to confirm |
| Java | spring-boot | 4 (SQLi, cmd) | 11 | spring-boot only models XSS/redir/SSRF → Java stdlib JDBC/Runtime carries SQLi/cmd; 4 existing pairs already prove it. Add path-traversal pair to lock it in. |
| Go | gin, echo | 4 (gin only) | 18 (2 fw × 7 new + 4 existing) | echo has 0 fixtures; add 2 echo pairs minimum to prove the loader works for echo. |
| Ruby | rails, sinatra | 4 (rails only) | 18 | sinatra has 0 fixtures; add 2 sinatra pairs minimum. |
| PHP | laravel, symfony | 4 (laravel only) | 18 | symfony has 0 fixtures; add 2 symfony pairs minimum. |
| Rust | actix-web, axum | 4 (actix only) | 18 | axum has 0 fixtures; add 2 axum pairs minimum. |
| C# | aspnet-core | 4 (SQLi, cmd) | 11 | aspnet-core only models XSS/redir → ASP.NET stdlib carries SQLi/cmd; 4 existing pairs prove it. Add 1 redirect pair on framework side to lock the framework-only path. |

**Per-pair workflow (AI-driven):**
1. Read existing same-class JS fixture as a recall reference (e.g. `express-vulns/path-traversal-vuln/`).
2. Author `<lang>-vulns/<framework>-<class>-vuln/` and `-safe/` directories — small (1-3 file) repos that idiomatically reproduce the vuln and the sanitized form.
3. Add a case to the language's existing `test/taint-engine-<lang>.test.ts` with `expectedVulnClass` set.
4. Run `npm run test:taint-engine-<lang>` and iterate the fixture/spec until the vuln pair fires and the safe pair stays clean.
5. If the spec is missing a sink/source/sanitizer needed by an idiomatic fixture, **expand the spec** (this is allowed — it's coverage closure, not new feature work). Note the spec change in the commit message.

**Joint validation callouts** (#3 from Henry's list):
- `aspnet-core.yaml` covers XSS+redirect only → existing 4 SQLi/cmd pairs already prove dotnet-stdlib fallthrough. **No extra work** beyond Unit 2 matrix; verify in commit message.
- `spring-boot.yaml` covers XSS+redirect+SSRF only → 4 SQLi/cmd pairs prove java-stdlib fallthrough. Path-traversal pair (filed under java-stdlib) closes it.
- `echo.yaml`, `gin.yaml` cover 3 classes each → echo fixtures (currently 0) prove the loader; the rest flow through go-stdlib.

**Henry sync:** spot-check 1 fixture per language to confirm idiomatic style. Per Henry's #1 footnote, joint framework+stdlib combos should be called out per-pair in commit messages so coverage intent is auditable.
**Pass signal:** all new pairs assert vuln-fires + safe-clean. Test count grows from 196 → ~290 (~94 new pairs).
**Effort estimate:** ~2 fixtures/hour, ~94 fixtures = L→XL. Split across days 2-3.

### Unit 3 (M) — Sinatra / Symfony / Axum loader proof
**Why third:** specs were written but never fixture-tested. Could be a YAML typo no one's noticed.

**Already covered by Unit 2** (sinatra/symfony/axum each get 2+ pairs in the matrix expansion). This is just a reminder to **commit those fixture pairs as a separate logical unit** so the loader-proof intent is in the commit log: `test(taint-engine): add sinatra fixture pairs validating spec loader`. Same for symfony and axum.

**Henry sync:** none beyond Unit 2.
**Pass signal:** loader-proof commits land independently.

### Unit 4 (M) — Atom A/B benchmark dry-run
**Why fourth:** harness exists but has never produced a real recall number. The retirement-gate evaluator can't say "GO" until this fires.

**Deliverables:**
- `test/taint-engine/benchmark/corpus.json` — handcrafted from Phase 5's `candidates.ts`. Initial scope: only entries where we have a clonable fixture project (Phase 5's iterate cache + `deptex-test-{npm,python,java,go}` fixtures cover ~22 of the 88 directly). Other 66 entries get `expectedFindings: []` (loader-only smoke). **OR** clone-on-demand via the `git` field — prefer this where feasible, but cache result so the run is reproducible.
- Run `npm run taint-engine:benchmark -- --corpus test/taint-engine/benchmark/corpus.json --output ./out/benchmark-2026-04-30 --workspace-root /tmp/dx-bench`.
- Capture `report.json` + `report.html`. Read the engine-vs-atom recall delta. Note any flow the engine misses that atom catches.
- Run `npm run taint-engine:retirement-gates -- --benchmark ./out/benchmark-2026-04-30/report.json --shadow-period-days 30 --failure-pct-ceiling 1.0 --recall-delta-floor-pp 0 --ai-cost-ceiling 0.10`. Verdict will be `EXTEND_SHADOW` (no shadow data yet) but **the run should not error**. That's the dry-run test.

**Henry needs to do:** sanity-check the corpus.json — particularly which 22 CVEs have local fixtures. He may want to point me at additional vuln-rich repos he has cached locally.

**Pass signal:** `report.html` opens, recall numbers aren't both zero. Retirement-gates CLI returns exit 0 with `EXTEND_SHADOW` due to missing shadow data (not due to failed parsing).
**Risk:** atom requires `depscan-reports/*-reachables.slices.json` to compare against. If those aren't pre-cached for the corpus projects, the harness will skip those rows. I'll document this gap in the run output.

### Unit 5 (M) — Cross-ecosystem real-repo smoke
**Why fifth:** test-npm was the only ecosystem ever exercised. Python/Java/Go runs could surface IR/lowering bugs the fixtures don't.

**Deliverables:**
- One-shot script `test/taint-engine/scripts/smoke-cross-ecosystem.ts` that:
  1. Runs `propagate(<lang>)` on each of `deptex-test-npm`, `deptex-test-python`, `deptex-test-java`, `deptex-test-go`.
  2. Asserts no thrown errors, propagation completes within 5 min, and prints flow counts + iteration counts per repo.
- Run it; note any crash, timeout, or pathological iteration count (>10× function count).
- For each crash: minimize to a fixture, file as a Unit 1 invariant test, fix in place.

**Henry sync:** 30 min if a crash needs his judgment on whether to fix vs ticket.
**Pass signal:** all 4 ecosystems complete, no crashes, flow output sensible (e.g. test-python has 0 framework code → 0 flows is fine; test-npm should match the 0-flow precedent already established).

### Unit 5.5 (S) — Upgrade existing test repos with multi-file flows
**Why:** the existing `deptex-test-{npm,python,java,go}` repos are mostly single-file. Phase 6 is about cross-file flows — Unit 5's smoke is more meaningful if the input repos actually exercise multi-file taint.

**Deliverables (per repo):**
- 1-2 realistic multi-file flow scenarios. Example for `deptex-test-npm`: Express app with `routes/users.js` → `services/user-service.js` → `db/queries.js`, user input from a route flows across 3 files into a SQL sink.
- Equivalent flows for python (Django/Flask), java (Spring), go (Gin).
- Each flow ends in a vulnerable dependency that's already in the repo's manifest, so the flow upgrades a real PDV.

**Henry sync:** spot-check one repo's multi-file flow for idiomatic style. He owns the GH push.
**Pass signal:** after upgrade, Unit 5's cross-ecosystem smoke produces ≥1 flow per repo.
**Slotted:** Day 4 (between fixture matrix completion and FP filter sweep).

### Unit 6 (M) — AI FP filter signal/noise + threshold sweep
**Why sixth:** filter has unit tests + one live call. We have no idea if it actually rejects FPs at the rate we want.

**Deliverables:**
- `test/taint-engine/scripts/fp-filter-eval.ts` that:
  1. Runs propagation on all 30 vuln fixtures + 30 safe fixtures.
  2. For each emitted flow, calls `filterFlow()` and records `verdict`, `confidence`, `costUsd`, plus ground truth (vuln-fixture flow → expected `kept`; safe-fixture flow that somehow fired → expected `rejected`).
  3. Emits `fp-filter-eval-2026-04-30.json` with per-flow rows.
- Threshold sweep: replay the json against confidence thresholds 0.5/0.6/0.7/0.8/0.9, compute recall/precision per threshold, recommend an optimum.
- Total spend cap: 100 calls × ~$0.0001 = ~$0.01. Negligible.

**Henry sync:** review the recommended threshold + decide whether to update `default_ai_fp_filter_confidence_threshold` migration value (currently in `phase26_3_fp_filter`). If he wants to change it, that's a follow-up commit (per `feedback_apply_migrations_via_mcp.md`, via Supabase MCP, then `npm run schema:dump`).
**Pass signal:** signal/noise table produced; exactly one threshold flagged optimal; recall doesn't drop more than 2pp at the recommended threshold vs no-filter baseline.

### Unit 7 (M) — AI spec inference end-to-end on a long-tail framework
**Why seventh:** one integration test exists, but we've never actually inferred a spec for a framework not already shipped and validated it works.

**Deliverable:**
- Pick **Koa** (JS, lightweight, idiomatic targets exist). Koa is not in the 23 bundled specs. Alternatives: Bottle (Python), Tornado (Python). Koa preferred — fewer moving parts.
- Build a 3-file Koa app with a SQLi vuln (handler → service → `db.query(rawSql)`) under `test/taint-engine/fixtures/koa-vulns/sql-injection-vuln/` plus its safe pair.
- Trigger spec inference end-to-end via the backend route `POST /api/orgs/:orgId/taint-engine/specs/infer` with framework='koa' and the fixture as the workspace.
- Persist the generated spec to `framework-models/koa.yaml`. Run the validate harness `npm run taint-engine:validate` against the new fixture. Assert the inferred spec catches the vuln pair.
- **Decision point:** if the inferred spec catches the vuln, commit it. If it misses, file as a known limitation in the plan output.

**Henry sync:** decide whether the inferred Koa spec ships in the bundle (probably yes) or stays in the test fixture only.
**Pass signal:** inference returns a non-empty YAML, validator passes, vuln pair fires.
**Cost:** one inference call, ~$0.005. Cheap.

### Unit 8 (S→M, mostly Henry) — 30-day shadow run kickoff
**Why eighth:** no shadow data → retirement gates can't fire → can't merge with confidence. This is **mostly Henry's call**; AI handles the prep but the kickoff is operational.

**Deliverables (AI):**
- Document a "shadow run kickoff" runbook section in this plan (below, in §3) listing the exact SQL/admin-route calls.
- Build a `test/taint-engine/scripts/shadow-monitor.ts` that queries `taint_engine_runs` for the past 7 days and prints failure rate, mean AI cost, mean propagation_ms, killswitch state. Henry runs this daily.

**Henry does:** flip the rollout pct on his dogfood org via the admin route or direct `taint_engine_settings.rollout_pct_override` update. Watch the monitor for a week. If failure rate < 1% and no crashes, broaden.

**Pass signal:** monitor works against Supabase live; one or more `taint_engine_runs` rows accumulate after kickoff.

### Unit 9 (M) — Synthetic failure-mode injection
**Why ninth:** circuit breaker + hard-fail policy are only validated on injected `throw new Error('test')`. Real failure shapes (OOM, malformed YAML, partial clone) are unobserved.

**Deliverables:** new `test/taint-engine-failure-modes.test.ts` covering:
- **Real OOM-shaped:** load a synthetic IR with 100k functions, run with `--max-old-space-size=128`. Assert the engine surfaces a recoverable error, not a node crash.
- **Malformed YAML:** drop a `framework-models/broken.yaml` with garbage; assert the loader logs a warning and skips it (doesn't poison the load).
- **Tsconfig parse failure:** point the TS callgraph builder at a tsconfig with a syntax error; assert it falls back to a sensible default (or fails loudly with a clear message).
- **Circular import:** a 2-file cycle (`a.ts` imports `b.ts` imports `a.ts`); assert the callgraph builds, no infinite loop, propagation terminates.
- **Partial workspace clone:** delete `package.json` from a fixture, run propagate; assert graceful degradation.

**Henry sync:** decide what "graceful" means for each (some should hard-fail with clear message, some should warn-and-skip — depends on the circuit-breaker policy).
**Pass signal:** all failure cases produce a documented behavior, no node-process crashes.

### Unit 10 (M) — Deep cross-procedural chain fixtures
**Why tenth:** worklist termination on real-world chain depth is unverified. This is more about catching false negatives than false positives.

**Deliverables:**
- One 4-hop fixture per language: `req → ctrl.handle() → svc.process() → repo.find() → db.query(tainted)`. Use the language's existing framework conventions.
- 8 new fixture pairs (vuln + safe) → 16 fixture cases.
- Add to the per-language test runners with assertion `flow.flow_nodes.length >= 4` to lock the chain depth.

**Henry sync:** confirm 4-hop is the right depth (vs 6-hop). 4 is the sweet spot for "interesting" without being slow.
**Pass signal:** all 8 chains fire end-to-end. Iteration count stays bounded.

### Unit 11 (S) — Sanitizer modeling audit
**Why eleventh:** ad-hoc adds. Could be over- or under-suppressing.

**Deliverables:** auto-generated audit report `test/taint-engine/scripts/sanitizer-audit.ts`:
1. For each loaded spec, list `sanitizers[]` patterns + `vuln_classes` they suppress.
2. Cross-check against the existing safe fixtures: each safe fixture's sanitizer pattern should appear in the spec.
3. Cross-check the inverse: each spec sanitizer should be exercised by at least one safe fixture (else it's untested).
4. Print warnings for: sanitizers in spec but no fixture; safe-fixture sanitizers not declared in spec; sanitizers claiming to suppress vuln classes the framework doesn't even sink.

**Henry sync:** review the warnings list; decide which are bugs vs intentional.
**Pass signal:** audit emits a clean report or a numbered punch list of action items (which become Unit 11.5 follow-ups).

### Unit 12 (S) — Untyped-JS quality signal validation
**Why twelfth:** `is_typed_js_project` + `typedFilesPct` are emitted but no one's defined "good." This is just a measurement.

**Deliverables:** SQL query report:
- For all `taint_engine_runs` with `ecosystem='npm'` (post-shadow-kickoff), bucket by `typed_files_pct` quartile. Compare flow recall/precision per bucket.
- Define what "good" looks like: e.g. `typed_files_pct < 25` should warn-but-still-run; `typed_files_pct < 5` could optionally skip the engine entirely.

**Henry needs to do:** ratify or reject the threshold proposal.
**Pass signal:** quartile table produced; one threshold proposal in the report.
**Blocker:** this needs Unit 8 shadow data first. Defer to after week-1 of shadow.

---

## 2. Day-by-day execution order (next 5 days)

Each day = ~6-10h AI autonomous work + ~30 min Henry sync at end of day. Henry sanity-checks before next day starts.

### Day 1 — Engine-level invariants + shadow prep
- AI: Unit 1 (engine invariants) — write 15-20 unit tests, all green. ~6h.
- AI: Unit 8 (shadow monitor script + runbook). ~2h.
- AI: Start Unit 4 (corpus.json hand-port from candidates.ts). ~2h.
- Henry sync (30 min): review invariant list, ratify shadow runbook, kickoff dogfood-org rollout if comfortable.
- Commits: `test(taint-engine): add propagate-core invariant unit tests`, `test(taint-engine): add shadow-run monitoring script`.

### Day 2 — Atom A/B benchmark dry-run + start fixture matrix
- AI: Finish Unit 4 — run benchmark, run retirement-gates, capture report.json, document recall delta. ~3h.
- AI: Unit 5 (cross-ecosystem real-repo smoke) — author smoke script, run against 4 test repos, fix any crashes. ~3h.
- AI: Begin Unit 2 — Python XSS + Python path-traversal fixture pairs (3 frameworks × 2 classes = 6 pairs). ~3h.
- Henry sync: review benchmark output, decide if any recall miss is blocking. Spot-check one Python fixture.
- Commits: `test(taint-engine): add atom A/B benchmark corpus`, `test(taint-engine): cross-ecosystem real-repo smoke`, `test(taint-engine): expand python xss + path-traversal fixtures`.

### Day 3 — Fixture matrix expansion (heaviest day)
- AI: Unit 2 continued — Python SSRF/deser/log-inj/redir/ReDoS (15 pairs). Java + C# fill-in (3 each). ~8h.
- AI: Unit 3 — sinatra/symfony/axum loader-proof pairs (6 pairs). Bundle into appropriate Day 3 commits. ~2h.
- Henry sync: spot-check one fixture per language he's least familiar with.
- Commits: `test(taint-engine): expand python fixture pairs across vuln classes`, `test(taint-engine): add sinatra fixture pairs`, `test(taint-engine): add symfony fixture pairs`, `test(taint-engine): add axum fixture pairs`.

### Day 4 — Finish fixture matrix + AI features
- AI: Unit 2 finish — Go (gin XSS+SSRF+path), Ruby (rails 5 classes), PHP (laravel 5 classes), Rust (actix 5 classes). ~6h. Fewer per-class than Python because frameworks model fewer sinks.
- AI: Unit 6 (FP filter signal/noise + threshold sweep). ~2h. Depends on Unit 2 fixture set being complete.
- AI: Unit 7 (Koa AI spec inference). ~2h.
- Henry sync: review FP filter recommendation, decide on threshold change. Decide whether Koa spec ships.
- Commits: `test(taint-engine): expand go|ruby|php|rust fixture pairs`, `test(taint-engine): measure ai fp filter signal/noise`, `feat(taint-engine): bundle koa framework spec from inference run` (only if Henry green-lights ship).

### Day 5 — Failure modes, deep chains, sanitizer audit
- AI: Unit 9 (synthetic failure-mode injection). ~3h.
- AI: Unit 10 (deep cross-procedural chain fixtures, 8 lang × 1 chain = 8 pairs). ~3h.
- AI: Unit 11 (sanitizer audit + fix any flagged gaps). ~2h.
- Henry sync: review failure-mode behavior decisions. Read the audit punch list, ratify or reject each item.
- Commits: `test(taint-engine): synthetic failure-mode injection`, `test(taint-engine): deep cross-procedural chain fixtures`, `test(taint-engine): sanitizer modeling audit`.

### Beyond day 5 (Henry-paced, AI assists on demand)
- Day 5+1 to 5+7: shadow data accumulates. Re-run `shadow-monitor.ts` daily. AI on standby for any unexpected failure modes.
- Day 5+8 to 5+30: continued shadow. Run `taint-engine:retirement-gates` weekly with current shadow data. Watch the recall delta and AI cost trend.
- **Unit 12 fires** once 7+ days of shadow data exist.
- Day 5+30: final retirement-gates evaluation. If GO → Henry merges and opens the atom-retirement follow-up. If EXTEND_SHADOW → another two weeks. If NO_GO → file the regression list, fix, re-shadow.

---

## 3. Shadow-run kickoff runbook (Unit 8 detail)

Henry runs these. AI doesn't touch prod.

### Pre-flight
1. Confirm Phase 5 has merged to main (Phase 6 migrations are gated on phase23/24/25 landing first to avoid number collisions per state memory line 14).
2. Phase 6 branch rebased on main, migrations re-numbered if needed.
3. `cd backend/extraction-worker && npm run schema:dump` after any migration touch (per `feedback_schema_dump_rebase.md`).
4. All Day 1-5 unit tests green: `npm run test:taint-engine-{callgraph,propagator,integration,fp-filter,benchmark,python,java,go,ruby,php,rust,csharp,invariants,failure-modes}`.

### Kickoff (dogfood org first)
1. Find Henry's dogfood org id in Supabase: `SELECT id FROM organizations WHERE owner_user_id = <henry user id>`.
2. Set per-org rollout to 100%: via admin route `POST /api/orgs/:orgId/taint-engine/settings` with `{rollout_pct_override: 100}`. (Not direct SQL — UI/API path to keep audit log clean.)
3. Trigger an extraction on a known-vuln repo (test-npm).
4. Verify: `SELECT * FROM taint_engine_runs WHERE org_id = <id> ORDER BY created_at DESC LIMIT 5;` — should show one new row with `status='succeeded'`, sensible `propagation_ms`, sensible `flows_count`, `failure_rate=0`.

### Daily monitor (Henry runs `shadow-monitor.ts`)
- Script prints: `failure_rate_7d`, `mean_ai_cost_usd_7d`, `mean_propagation_ms_7d`, `killswitch_engaged?`, `recent_failures[]`.
- **Action thresholds:**
  - `failure_rate_7d > 5%`: stop the rollout, investigate top failure reasons, file follow-up.
  - `killswitch_engaged=true`: investigate immediately (5%/60min/≥5-run trigger fired).
  - `mean_ai_cost_usd_7d > $0.10/run`: tighten FP filter threshold (Unit 6 result) or tighten cost cap.

### Broadening (after 7 days clean on dogfood)
- Pick 2-3 friendly external orgs (Henry names them). Set `rollout_pct_override=100` for those orgs only.
- Watch monitor for 14 more days.
- Final retirement-gate decision at day 30.

---

## 4. What Henry has to do himself (vs AI)

| Activity | AI | Henry |
|---|---|---|
| Write unit tests / fixtures / scripts | yes | spot-check |
| Run tests + iterate failures | yes | sync at EOD |
| Run benchmark CLI | yes | review report.html |
| Make recall/precision threshold decisions | propose | ratify |
| Run AI spec inference | yes | decide whether to bundle |
| Apply DB migrations | propose SQL | apply via Supabase MCP |
| `npm run schema:dump` after migration | run | confirm dump committed |
| Set `rollout_pct_override` in prod | — | yes (operational) |
| Daily shadow monitor read | — | yes |
| Final go/no-go on retirement gates | propose | yes |
| Push branch / open PR | — | yes (gated on Phase 5 merge) |
| Decide commits vs squash | — | yes |

---

## 5. Commit hygiene (per memory feedback)

Per `feedback_commit_format.md`, `feedback_commit_milestone_language.md`, `feedback_no_coauthor_trailer.md`:
- Conventional Commits per logical unit. One unit ≈ one commit (or one per language for the fixture matrix days).
- **No "M3" / "Phase 6 M2" / "milestone N" shorthand.**
- **No `Co-Authored-By: Claude` trailer.**
- Examples (good):
  - `test(taint-engine): add propagate-core invariant unit tests`
  - `test(taint-engine): expand python fixture pairs to xss, ssrf, path-traversal`
  - `test(taint-engine): synthetic failure-mode injection coverage`
  - `feat(taint-engine): bundle koa framework spec`
- Examples (bad — do not write):
  - `test: M9 fixture matrix expansion`
  - `chore: phase 6 testing milestone 2`

---

## 6. Out of scope (explicit non-goals)

- No new framework specs beyond Koa/Unit-7 unless an audit (Unit 11) flags one as missing-and-load-bearing.
- No new vuln classes (decision #3 locks 11).
- No engine algorithmic changes — only IR/spec fixes if a fixture surfaces a real bug.
- No PR open / no merge — that's Henry's call after retirement-gates says GO.
- No docs rewrites. The roadmap itself is OK as a plan; user-facing docs are not.

---

## 7. Success criteria for "ready to merge"

All of the following true:
1. Unit 1-11 deliverables landed on `worktree-cross-file-taint-engine`.
2. Test count grows from 196 → ~400 with no flaky greens.
3. Atom A/B benchmark report shows engine recall ≥ atom recall − 0pp (per locked decision #1 + retirement-gate floor).
4. AI FP filter threshold tuned with explicit signal/noise table.
5. ≥7 days of shadow data showing `failure_rate < 1%`.
6. `taint-engine:retirement-gates` returns `GO` (or `EXTEND_SHADOW` if Henry wants more confidence).
7. Phase 5 has merged. Phase 6 migrations re-numbered if needed. `schema.sql` dump current.

The merge itself, the `gh pr create`, and the atom-retirement follow-up are explicitly Henry-driven. Plan ends at "we have enough confidence to merge."

---

### Critical Files for Implementation
- `backend/extraction-worker/src/taint-engine/propagate-core.ts` (invariants live here; Unit 1 protects this module)
- `backend/extraction-worker/src/taint-engine/benchmark/corpus.ts` (corpus shape for Unit 4)
- `backend/extraction-worker/src/taint-engine/fp-filter.ts` (Unit 6 signal/noise harness)
- `backend/extraction-worker/src/taint-engine/runner.ts` (Unit 5 cross-ecosystem dispatch)
- Phase 5 88-CVE source: `.claude/worktrees/reachability-phase5/backend/extraction-worker/test/iterate/candidates.ts`
