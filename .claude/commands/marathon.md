# Marathon — Autonomous Multi-Day Orchestration

Run a multi-day autonomous work session against a single bounded subsystem of Deptex. The marathon model: take an initial brief, set up source-of-truth artifacts, then drive a tick-based ScheduleWakeup loop that dispatches background subagents, harvests their output, integrates findings, and stands down — fully resumable across compactions, overnight pauses, and lost conversation context. Single final PR at marathon end.

This is for **scoped hardening / coverage / refactor / research sweeps on a subsystem** (e.g. depscanner hardening, taint engine recall push, Aegis dogfood polish). It is NOT for building a single feature — that is `/brainstorm` → `/plan-feature` → `/implement`.

## When to invoke

Good fits:
- "Spend a few days hardening depscanner — error logging, validation, refactor, test coverage, competitive eval, contributor docs, all of it."
- "Push reachability recall on the 88-CVE corpus — investigate gaps, dispatch fixes, ship per-framework spec extensions until the number moves."
- "Aegis chat dogfood polish marathon — rip through the backlog of small stale-state / fan-out / suppression bugs and ship them on one branch."

Bad fits (do not invoke `/marathon`):
- Single feature with a clear shape (use `/brainstorm` → `/plan-feature` → `/implement`).
- One-off bugfix or one-tick task (just do it).
- Cross-track sweep that touches 4 unrelated subsystems (split into separate marathons; scope discipline is the whole point).

## Inputs

The user describes the marathon brief in natural language: subsystem, soft target end date, what "done" looks like, and any tracks they want pursued. If they didn't, ask for it before doing anything else — `/marathon` requires a written brief, because every subsequent tick re-anchors against it.

Capture the brief verbatim into the daily log's `## Mission brief` section. **Re-read the brief at every major checkpoint** — scope drift is the dominant failure mode.

## Phase 0 — Setup (one-time, at marathon start)

1. **Sync local main to origin/main** — same as `/create-worktree` step 1. Never skip.
   ```bash
   git fetch origin
   git branch -f main origin/main
   ```
2. **Create the marathon worktree** off `origin/main`:
   ```bash
   git worktree add -b worktree-<name> .claude/worktrees/<name> origin/main
   cp backend/.env .claude/worktrees/<name>/backend/.env
   cp frontend/.env .claude/worktrees/<name>/frontend/.env
   cd .claude/worktrees/<name>/backend && npm install
   cd .claude/worktrees/<name>/frontend && npm install
   ```
   (Alternative: if `/create-worktree` was already run, just adopt that worktree.)
3. **Initialize the two source-of-truth files in the worktree:**
   - `.cursor/plans/<name>-DAILY-LOG.md` — tick-by-tick state of record. Header: mission start date, soft target end, worktree path, branch, base SHA, final delivery shape. First section: `## Mission brief` with verbatim user text. Then `## Operating model` (always-on tracks, cadence, comms cadence, PR shape). Then per-tick `## Tick N — DISPATCHED <date>` sections start landing.
   - `docs/<name>-report.md` — living findings + competitive analysis + refactor targets + doc plans. Treat this as the public artifact the marathon is shipping; the daily log is the orchestration journal.
4. **Update `active_sprint.md` memory** with: worktree path, branch, base SHA, first marathon commit (none yet), source-of-truth file paths, on-resume protocol. This is what the user (and post-compact me) will read to recover context.
5. **First ScheduleWakeup** — dispatch the first wave of background subagents simultaneously, then schedule the next tick. The wakeup `prompt` field MUST include: worktree path, branch, recent commit SHAs (none yet — restate base SHA), the user's Slack DM channel ID (if known), source-of-truth file paths. See "Wakeup prompt template" below.

Do NOT push the worktree branch at setup — pushing happens once, at marathon end.

## Phase 1 — Tick discipline (every wake)

Each tick follows the same shape. Drift from this is what causes lost context.

1. **Read the daily log first.** Scroll to the latest `## Tick N` section. Recover what's in flight, what's queued, what's blocked on user.
2. **Check Slack DM** for any user reply via `mcp__claude_ai_Slack__slack_read_channel` (limit ~5). Integrate any answers; close out questions in the daily log.
3. **Check git log for the worktree branch** — confirm any background fix-agent commits actually landed (they should report SHAs but verify).
4. **Harvest finished background agents.** For each agent that completed since last tick: read its output, summarize into the daily log under the tick where it was dispatched (back-fill), confirm the commit SHA inline (NEVER `see SHA below`), confirm gates green (tsc / jest / vitest baseline match), record token spend.
5. **Integrate findings into the living report.** P0/P1/P2/P3 findings, competitive deltas, refactor seams, follow-up work. Anything the marathon should know going forward. The living report is what survives the marathon; the daily log is what gets archived.
6. **Decide what to dispatch next.** Re-read the brief. Pick ≥0 background agents to launch (zero is a valid choice — see stand-down rules). Dispatch them with agent ID + estimated tokens + scope. Each dispatched agent gets a sub-bullet under the new `## Tick N — DISPATCHED <date>` section.
7. **Update the daily log fully BEFORE standing down** — see compact discipline rules below. Inline commit SHAs the same turn the commit lands. If a follow-up Edit is needed to fill in a SHA the agent reported in its tail output, do it before the wakeup.
8. **Schedule the next wake.** ScheduleWakeup with cadence per the rules below and a prompt that re-states load-bearing context.

A tick is NOT done until step 7 is done. "I'll update the log next tick" is the canonical bug — a compaction or computer-off between then and next tick loses the context.

## Compact-friendly discipline

Per `feedback_marathon_compact_discipline.md`. The user compacts conversations periodically through the day to save tokens, and may close his computer overnight. After a compact, conversation context is gone but disk artifacts persist.

End-of-tick state on disk MUST fully reflect the marathon's reality:

- Daily log has every commit SHA inlined under the right tick, every agent's harvest summarized, every Slack ping noted, every open question listed under the tick that surfaced it.
- Living report reflects current findings; obsolete framings (e.g. "queued for user approval" after approval lands) are rewritten in place, not appended.
- All commits land on the worktree branch. Do not leave fix-agent work sitting un-committed in worktree-modified state.
- The next ScheduleWakeup `prompt` re-states the load-bearing context. Treat the prompt as if the resuming agent has zero conversation history.

The recovery flow after a compact (or overnight pause): read daily log → check Slack DM → check git log for the worktree branch → resume tick cadence at the latest `## Tick N` section. If end-of-tick state is fully synced, recovery is mechanical.

## Wakeup prompt template

Every ScheduleWakeup `prompt` field should restate, at minimum:

```
Marathon: <name>
Worktree: .claude/worktrees/<name>
Branch: worktree-<name>
Base: origin/main @ <base-sha>
Recent marathon commits (newest first):
  <sha1> <subject>
  <sha2> <subject>
  ...
Source-of-truth files:
  - <worktree>/.cursor/plans/<name>-DAILY-LOG.md
  - <worktree>/docs/<name>-report.md
Slack DM channel for the user: <channel-id>

Latest tick: N — <one-line state>
Open questions for user: <count> (latest pinged at <timestamp>)
In-flight background agents: <count> (names if any)

Action this tick: <harvest-and-dispatch | stand-down | EOD-ping | marathon-close>
```

If the prompt does NOT include this, the post-compact resuming agent has to reverse-engineer it from disk, which is wasteful and error-prone.

## Cadence rules

- **Active work in flight:** 1500–1800s wake (25–30 min). Catches background-agent completion notifications fast.
- **Idle waiting on user:** 3600s wake (1 hr). 2 hr is acceptable after 3+ consecutive stand-downs.
- **Hard cap:** ScheduleWakeup runtime caps at 3600s anyway. Don't try to extend beyond that.
- **DO NOT gate on self-imposed token budgets.** Per `feedback_no_soft_token_caps.md`. If work is authorized and queued, dispatch. The user is paying for the work; cost framing is his to manage. He'll signal explicitly to pause.
- Soft caps are for *cadence shaping* (extending wake when nothing is happening), not for refusing dispatch.
- Hard stops: an agent reports a blocker, gates fail in a way that needs user input, the user explicitly says pause.

## Background subagent dispatch patterns

Every dispatch picks one of these patterns. Tag each agent's daily-log entry with which pattern it is.

### Critical-review-and-FIX agents
Multi-persona lens, scoped per subsystem (validation coverage, error-logging hygiene, multi-tenancy, etc.). Each agent: surveys → produces P0/P1/P2/P3 findings with file:line citations → ships fixes for the agreed scope in one commit. Use the Phase 2 persona library shape from `/criticalreview` for inspiration but tighten to the subsystem.

### Plan-writer agents (READ-ONLY)
Surveys the codebase + (optionally) competitor public surfaces, produces a markdown plan deliverable. Zero code changes, zero commits — output is the markdown file path. Used for "design before we touch this" sub-projects (e.g. contributor-test-infra plan, public benchmark scoreboard plan, DAST OpenAPI synthesis plan).

### Refactor agents
Pure refactor, **zero behavior delta**, full gate compliance (tsc / jest / vitest / pglite all baseline-match). Sequential, never parallel — refactor agents touching the same hot file collide. Daily-log entry MUST record the gate-baseline match explicitly so a regression introduced N ticks later is traceable.

### Test-authoring agents
Per-framework / per-fixture / per-suite. Each agent: scoped to ONE coherent test target (e.g. "rule-generation persistence test backfill", "30 framework reachable+unreachable fixture pairs", "snapshot bootstrap unit tests"). Reports tests-passing count delta in the daily-log harvest.

### Tournament patterns
Reserved for problems with a measurable ranking signal (88-CVE corpus, framework-spec recall matrix, competitor benchmark). Spawn 3–5 candidate strategies in parallel, score each, pick the winner. Cap: 2–3 tournaments over the marathon — they are token-expensive and most marathon work has no ranking signal.

## Slack discipline

Per `feedback_slack_notifications.md`. The user's DM channel is the marathon's async-comms channel.

- **Daily EOD ping** to the user's DM summarizing: commits shipped today, plan docs landed, open questions for him, token spend. ONE ping per real-world day, not per tick.
- **Don't ping more than once per day** unless substance accumulates (e.g. a completed multi-hour refactor lands mid-day worth surfacing).
- **Don't ping at all** if nothing material has shipped — silent ticks are fine. Pinging an unread channel is counterproductive.
- **Substance threshold for an extra ping:** ≥1 marathon commit landed AND something the user needs to know to make a decision (greenlight question, scope question, blocker). Just "things are progressing" doesn't clear the bar.
- The user is the logged-in Slack user; if `slack_search_users` doesn't find him by name, use the documented self-DM `D0A0VGZH23G` pattern (or the channel ID stored in `active_sprint.md`).

## Scope discipline (CRITICAL)

The dominant failure mode of an autonomous marathon is scope drift. Guard rails:

- **Re-read the original brief at every major checkpoint** — start of each day, before any "wave" decision, before any user-facing summary.
- **If the user adds scope mid-marathon, ADD it on top of the original** — don't replace. The original brief items still need to ship before "marathon done" gets declared.
- **Do not declare marathon done until the original brief items are actually done.** A marathon that solves three new things and leaves two original items unaddressed is a failure of scope, even if the new things are valuable.
- **Tracks parked at marathon start stay parked.** If the brief says "depscanner hardening", do not drift into Aegis polish, frontend ironing, IaC v2 implementation, or any other Track. Park them in `active_sprint.md` and resist.
- **Plan-doc deliverables are scope, not scope creep** — a plan doc that the brief asked for counts. A plan doc the brief did not ask for is creep, even if it's interesting.

When in doubt, surface a scope question to the user via Slack rather than unilaterally expanding.

## Commit hygiene

All marathon work follows existing Deptex conventions, plus marathon-specific rules:

- **Conventional Commits required.** `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`. Per `feedback_commit_format.md`.
- **No milestone labels** in commit messages ("M3", "Phase 2 M1", "Wave 4"). Describe the actual change in plain prose. Per `feedback_commit_milestone_language.md`.
- **No `Co-Authored-By: Claude` trailer.** Author as the user only. Per `feedback_no_coauthor_trailer.md`.
- **One coherent commit per concern.** Refactor commits stay refactor commits; never sneak a behavior-change into a refactor commit.
- **Don't push until marathon end.** All marathon commits accumulate on the worktree branch locally. The final PR has every commit visible. Pushing a partial branch invites the user to merge before the marathon's done.
- **Inline the commit SHA in the daily log THE SAME TURN** the commit lands. Don't write `see SHA below`. If the SHA only surfaces after the agent's tail output, do a follow-up Edit before standing down.

## Failure modes observed (DO NOT REPEAT)

These are real failure modes from a previous marathon. Re-read this section at every checkpoint.

### "Ship-ready test gate" ≠ "marathon done"

A green tsc/jest/vitest/preflight pass is **necessary, not sufficient**. The brief drives the stop, not the test gate.

If the brief said "test each section thoroughly + measure how well it works against real repos," then a marathon that ships green unit tests but never ran a single OSS corpus scan has NOT done the brief. Synthetic fixtures + jest counts are infrastructure proof, not capability proof.

For any "does X work properly" claim, the answer is the real-world measurement (OSS corpus recall/precision/noise/cost), not the unit-test pass rate.

### "Natural pause point" / "treadmill" / "diminishing returns" are self-justification

If the marathon's brief is open-ended ("keep working, harden everything, find what's missing"), there is NO natural pause point until the user says so. Concepts like:
- "Marathon at clean stopping point"
- "Continuing crosses into treadmill"
- "Diminishing returns past here"
- "Brief items twice over"

— are **traps**. They're the agent rationalizing closing the loop because no more work is queued, when in reality the open-ended brief means "find more work continuously." Re-open the loop. Find more gaps. Run more scans.

### Catalogued-but-deferred P2s are not "shipped"

If the brief says "fix all P2s" or "fix everything down to P3," then writing P2s into a daily-log catalogue and labeling them "architectural — defer" is **not shipping them**. Tournament-style or careful sequential agents can attack architectural P2s. They are work, not exemptions.

### Tournament budget of zero is wrong

"Sparingly" doesn't mean zero. If the marathon has hard problems with measurable ranking signals (recall benchmarks, fixture matrices) and the marathon scope explicitly calls out tournaments, use them. 2–3 tournaments over a multi-week marathon is the floor, not the ceiling.

### Documentation accumulates throughout, never on day-N

If the brief says "I want one long documentation here continuously updated," then writing the long doc once early and never touching it again is failing the brief. The living docs must be touched on most ticks — at minimum every time a section gets work.

### Real-money corpus runs are part of the brief

If the user gave you their DeepInfra/Anthropic key and explicitly said "you can run the code," then the brief expects you to spend real money on real corpus runs. Treating that as "expensive optional" is misreading the brief.

### OSS corpus > synthetic fixtures > jest

For ranking the "does it work properly" evidence quality:
1. **OSS corpus** (real popular repos, real CVE ground truth) — strongest
2. **Synthetic fixture pairs** (reachable/unreachable per framework) — useful, but limited
3. **Jest unit tests** (internal invariants) — necessary, not evidence of capability

A marathon that ships jest + synthetic and never touches OSS has weak evidence the system works.

### AI provider audit is a track, not a one-shot rip-out

"Make all AI go through user preference" is **not** the same as "rip out BYOK." It's:
- (a) Audit every AI call site, route through `getProviderForOrg()` (or platform-key fallback)
- (b) Record per-model `prompt_tokens` / `completion_tokens` / `cost_usd` into `scan_jobs`
- (c) Per-scan AI cost-cap input on top of monthly cap

These are three coordinated changes that need verification by reading every AI call site.

### Re-read the brief at every checkpoint (already in this skill, repeated here for emphasis)

If the marathon has been running 2+ days, the agent has accumulated drift from the original brief. Mid-marathon scope additions from the user **stack on top of the brief, never replace it.** Re-reading the verbatim brief at the start of every multi-hour decision is mandatory. The daily log's `## Mission brief` section is the source of truth.

## Marathon-end (the close)

Marathon ends when one of:
- Every original-brief item is done **AND** the brief is not open-ended (e.g. "ship feature X" rather than "harden Y continuously").
- The user explicitly says "wrap the marathon" / "ship it" / "we're done."
- Soft target end date passes AND the brief items are all done (extend if not, but check the brief items list against the failure-mode catalogue above — "shipped jest tests" is not "shipped corpus testing").

**Open-ended briefs (e.g. "harden this subsystem continuously while I'm gone") do NOT auto-close when test gates pass.** They close when the user explicitly says so or when there is genuinely no more work to find. Continuously scanning real OSS repos, fixing what's missed, and looping is the steady state — closing the loop on a green test gate is a failure mode.

To close:

1. **Final commit** — land any uncommitted daily log + living report updates. This is usually one `chore: marathon close` commit covering `<name>-DAILY-LOG.md` + `<name>-report.md` final-state snapshots.
2. **Push the branch:**
   ```bash
   git push -u origin worktree-<name>
   ```
3. **Surface the GitHub compare URL** to the user. They open the PR via github.com — never use `gh` CLI. Per `feedback_github_workflow.md`.
4. **PR body** should reference the living report as the canonical artifact and link the daily log for orchestration history. Suggest the user run `/criticalreview` against the branch before merging if the marathon touched security-sensitive code.
5. **Update `active_sprint.md`** to reflect the marathon's wrapped state (PR URL, final commit SHA, "marathon ended <date>"). The living report becomes the canonical reference for the subsystem going forward.
6. **Suggest `/cleanup` after the PR merges** — same as any other worktree.

## Rules (durable)

- **Original brief is sacred.** Re-read it, do not replace it, do not declare done without it.
- **Disk artifacts > conversation context.** End every tick with daily log + living report fully synced. Compaction-safe.
- **Inline commit SHAs the same turn.** Never "see SHA below" without filling it in.
- **One coherent commit per concern.** Don't mash refactor + behavior change into one commit.
- **Single final PR.** All marathon commits ship together; no partial-branch pushes.
- **Don't push during the marathon.** Pushing is the close-of-marathon ritual.
- **Don't gate on soft token caps.** Authorized work gets dispatched. The user signals explicitly to pause spend.
- **Slack: substance only.** One EOD ping per day, no spam, silent ticks are fine.
- **No `gh` CLI ever.** Plain `git push`; surface URLs and let the user act on github.com.
- **Subagents follow the dispatch patterns above** — critical-review-and-fix / plan-writer / refactor / test-authoring / tournament. Tag each in the daily log so the harvest pattern is consistent.
- **Refactor agents are sequential, never parallel.** Hot-file collisions are the canonical bug.
- **Tournament budget: 2–3 over the marathon, max.** Ranking-signal-only work.
- **Live-API probes before declaring an external integration done** — per `feedback_live_api_probe_value.md`. A marathon that ships an external integration without one real-world hit is incomplete.
- **Apply DB migrations via Supabase MCP** — never paste SQL for the user to run. Per `feedback_apply_migrations_via_mcp.md`. After any migration, run `cd depscanner && npm run schema:dump` in the same commit per CLAUDE.md.
- **No documentation files unless asked or unless the brief calls for them.** Per `feedback_docs_content.md`. The living report is the marathon's docs deliverable; ad-hoc `.md` files outside that are creep.
- **Frontend craft applies on the worktree.** If the marathon touches UI, the design / pixel / Vercel-typography rules from the standard memory set still hold.
- **Stand-down is a valid tick.** Idle ticks with no dispatch are fine. The cadence still ticks; the daily log still gets a `## Tick N — STAND-DOWN` entry recording the reason.

## Reference memory entries this skill leans on

Hard requirements:
- `feedback_marathon_compact_discipline.md` — end-of-tick disk-state sync.
- `feedback_no_soft_token_caps.md` — don't gate dispatch on self-imposed budget caps.
- `feedback_commit_format.md` — Conventional Commits required.
- `feedback_commit_milestone_language.md` — no milestone labels in commits.
- `feedback_no_coauthor_trailer.md` — no Claude attribution.
- `feedback_apply_migrations_via_mcp.md` — MCP apply, not manual SQL.
- `feedback_github_workflow.md` — never use `gh` CLI.
- `feedback_sync_main_often.md` / `feedback_sync_main_before_pr.md` — sync local main to origin/main at setup and before push.
- `feedback_worktree_setup.md` — copy `.env` + npm install in new worktrees.
- `feedback_brief_grep_verify.md` — when the marathon writes plan docs, grep-verify cited file:line claims.
- `feedback_dont_ask_henry_to_verify_grounding.md` — after surveying code, proceed; don't ask the user to verify what was found.

Cadence / comms heuristics:
- `feedback_slack_notifications.md` — Slack MCP for pings when connected.
- `feedback_ask_user_question_for_interviews.md` — for any interview-style sub-question, AskUserQuestion (not markdown lists).

Worktree / git safety:
- `feedback_commit_or_stash_before_destructive_git.md` — commit-or-stash before any destructive op.
- `feedback_cleanup_dirty_main_destroys_uncommitted.md` — never sweep the primary tree's main without checking status first.
- `feedback_no_uncommitted_work_in_main.md` — keep the primary tree clean during a marathon (the marathon's worktree is where work lands).
- `branching_strategy.md` — `main` is trunk, PRs target main, `prod` is Fly's deploy target.

## Reference: state files this skill creates

- `<worktree>/.cursor/plans/<name>-DAILY-LOG.md` — orchestration journal, archived after marathon close.
- `<worktree>/docs/<name>-report.md` — living findings, becomes the canonical subsystem reference.
- `active_sprint.md` (memory) — pointer to the marathon's source-of-truth files; updated at setup, mid-flight on major state changes, and at close.
