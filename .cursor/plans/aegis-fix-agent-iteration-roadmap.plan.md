# Aegis Fix Agent — Iteration Roadmap

## Where we are (2026-04-29)

First end-to-end PR landed: https://github.com/deptex/deptex-test-npm/pull/3 — autonomous Semgrep fix (XSS via `res.write()` → EJS template with escaping), pushed by the Fix Agent on `worktree-aegis-ai-polish`. 25+ commits (M1-M9 + 12 dogfood-debug fixes) sit on the unpushed branch.

**Pipeline that works today:**
plan generation → user approval → token validation → worker claim → clone at base SHA → install deps → editor LLM produces udiff → patch applies (with fuzzy fallbacks) → tests run (or soft-pass for no-test-suite) → branch + commit + push + draft PR

**Validated surface area (one repo, one finding type, one language):**
- Finding type: Semgrep (XSS pattern)
- Language: JavaScript
- Repo shape: no test suite
- Provider: DeepInfra DeepSeek V3.1 (editor) + Qwen3-235B (planner)

**Everything else is unexercised.** Vulnerability finding type, secret finding type, Python/Go/Java/Ruby/PHP/Rust/C#, repos with real test suites, real test-failure repair cycles. That's the iteration backlog.

---

## Strategy

**Sequential iterations off merged main.** Each iteration gets its own worktree + branch + PR. Each iteration is small enough to ship in one sitting and gets dogfooded against real repos before merge. The dogfood loop is woven through, not a parallel fork — Henry validates the iteration's output on real repos before approving merge.

**Order chosen by leverage, not difficulty:**
1. Cheap visible polish first (every later iteration produces PRs, so PR craft is amortized).
2. Then expand finding-type and language coverage, because that's where the value-per-fix multiplier is.
3. Editor prompt quality + repair hardening last — they need accumulated dogfood data to be productive.
4. Streaming is its own track, not gated on any of the above.

---

## Iteration 1: PR craft polish

**Source:** `future_aegis_fix_pr_polish.md` items 2 + 3.

**Scope:**
- Thread `noTestSuite` flag through `executor.ts` → `commitAndPushFix` → `buildPRBody` in `backend/fix-worker/src/pr.ts`.
- When soft-passed, replace "Test command" section with "No test suite detected — review carefully" or omit entirely.
- Replace raw `git diff --cached --stat` output in "Diff summary" with a clean per-file list (`- modified src/index.js (+8 lines)\n- created views/page.ejs (3 lines)`) parsed from `git diff --cached --numstat` + `--name-status`.

**Files:** `backend/fix-worker/src/pr.ts`, `executor.ts` (return type), `test-runner.ts` (already has `noTestSuite`).

**Exit criteria:** Open one new fix PR; verify body reads cleanly when soft-passed and when tests actually run. Size: S (a few hours).

---

## Iteration 2: Vulnerability finding type — live exercise

**Source:** `aegis_fix_agent_state.md` "What's untested" line 1.

**Scope:**
- Pick a real CVE in deptex-test-npm or a fresh test repo (low-severity, well-known like a lodash CVE).
- Run the full pipeline. Planner now queries `dependency_vulnerabilities` correctly (post-`3139abc`) but the path is unproven.
- Likely surfaces: planner-prompt issues for upgrade-shaped fixes (different from code-patch fixes), npm version selection, lockfile updates.

**Files:** Probably `backend/src/lib/ai-fix-engine.ts` planner prompt, possibly `backend/fix-worker/src/executor.ts` for lockfile-aware install/test.

**Exit criteria:** One vuln-type PR landed. If it just works, this is the shortest iteration. If it needs prompt tuning, that work happens here. Size: S–M.

---

## Iteration 3: Multi-language coverage — Python + Go

**Source:** `aegis_fix_agent_state.md` "What's untested" lines 3-4. Phase 1 scope of the original Fix Agent plan claimed JS/TS/Python/Go; only JS/TS is live.

**Scope:**
- Test repo per language (Python: small Flask app with a Semgrep finding; Go: small HTTP service with a Semgrep finding).
- Surface and fix per-language quirks:
  - Install commands: `pip install -e .` vs `poetry install` vs `pip install -r requirements.txt` for Python; `go mod download` for Go.
  - Test runners: pytest exit codes, `go test ./...`.
  - File path conventions, import styles.
- Confirm `test-runner.ts` heuristics work (pytest exit 5 + go `[no test files]` are already in).

**Files:** `backend/fix-worker/src/executor.ts` (install logic), planner prompt if it needs language-specific guidance.

**Exit criteria:** One Python PR + one Go PR landed end-to-end. Size: M.

---

## Iteration 4: Editor prompt quality

**Source:** `future_aegis_fix_pr_polish.md` items 1 + 4.

**Scope:** This is the iteration that benefits most from dogfood data accumulated in iterations 1–3. By now there should be 5–10 example PRs to point at.

- Item 1: editor produces stark scaffolding for new files (the EJS template was 3 lines, no doctype/head/title). Tweak planner/editor prompts to produce production-quality scaffolding for creates, while keeping minimal-change behavior for modifies.
- Consider strategy bias: prefer in-place sanitization (e.g. add escape-html) over introducing new template files where both options exist.
- Broader prompt iteration: review actual PR outputs, identify patterns of weakness, tune.

**Files:** `backend/src/lib/ai-fix-engine.ts` (planner system prompt), `backend/fix-worker/src/executor.ts` (editor system prompt).

**Exit criteria:** Re-run 3–5 representative fixes; PR output quality visibly better. Size: M–L (real prompt work).

---

## Iteration 5: Repair loop hardening

**Source:** `aegis_fix_agent_state.md` "What's untested" line 6.

**Scope:**
- Find or build a test repo with a real test suite, run a fix that breaks tests, and validate the repair cycle works.
- Today the repair loop has been exercised only for diff-apply failures (synthetic stderr). Real test failures with stack traces / assertion mismatches are unproven.
- Likely surfaces: stderr tail length, repair prompt structure, retry budget tuning.

**Files:** `backend/fix-worker/src/repair.ts`, `executor.ts` (retry-loop wiring).

**Exit criteria:** One PR where iteration 1 of the editor breaks tests and iteration 2 (repair) fixes them. Size: M.

---

## Iteration 6: Chat streaming

**Source:** `future_aegis_streaming.md`.

**Scope:** Independent of the fix agent. Aegis chat replies arrive all at once instead of streaming. Switch from `generateText` + Realtime save-and-broadcast to `streamText` + SSE endpoint that the frontend consumes via `useChat`. Real refactor — its own worktree.

**Why it's last:** Fix agent isn't blocked on it; better UX overall but doesn't gate any backend feature. Comfortable to do whenever Henry has appetite for a frontend-heavy chunk of work.

**Exit criteria:** Aegis chat replies stream token-by-token. Size: L.

---

## Out of scope for this roadmap

- **Secret finding type** — third unexercised path; queue after iteration 5 if still needed.
- **Sprint / batch fix mode** — multi-fix orchestration. Belongs in a later phase, not this iteration cycle.
- **Self-hosted / open-core gating** — Phase 5 self-hosting work is separate.
- **Rule generation, reachability, EPD** — separate worktrees with their own roadmaps.
- **Aegis multi-year roadmap** — see `aegis_roadmap.md` for the broader 14-phase view; this doc is just the Fix Agent slice.

---

## Conventions for each iteration

- One worktree per iteration, off freshly-merged main: `worktree-aegis-fix-{iteration-name}`.
- Conventional Commits, no milestone language, no Co-Authored-By trailer (per memory).
- Dogfood the iteration on a real repo before opening the PR into main.
- Update `aegis_fix_agent_state.md` memory at end of each iteration with what landed and what's next-untested.
- If an iteration surfaces a bug that's out-of-scope, write a `future_*.md` memory and keep moving — don't expand the iteration.
