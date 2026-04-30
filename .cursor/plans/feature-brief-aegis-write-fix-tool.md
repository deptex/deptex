# Feature Brief — Aegis Autonomous Fix Agent (v1)

> Replace the current dialog-based `aider-worker` with a Jules/Devin-style plan-then-execute coding agent that fixes vulnerabilities and Semgrep findings, gets explicit human approval on the plan, executes in a sandboxed worker, and opens a GitHub PR. Multi-language from v1.

## North Star

The pitch: **you stop manually triaging dependency security because Aegis does it on your behalf.** A user opens a finding card, clicks "Fix with Aegis" (or asks in chat: "Aegis, patch CVE-2024-XXXX in payments-service"). Aegis pulls the context Deptex already has — vuln details, reachability paths, affected files, fix versions, test setup — produces a structured plan ("bump `lodash` from 4.17.20 → 4.17.21 in `package.json`, regen lockfile, no code changes needed"), shows the user the plan, the user clicks Approve, the agent runs in a sandbox, opens a PR, and reports back in the chat thread. Multi-language. Default-safe (no network during exec, allow-list).

Down the line: same pipeline handles Semgrep code patches ("sanitize this prompt-injection sink"), codemods for ecosystem migrations, and eventually autonomous sprints. v1 ships the foundation — narrowly scoped, HITL, observable.

## Locked v1 scope (from interview)

### Original scope (pre-interview)

- **Human-in-the-loop, plan approval gate**: Aegis presents a structured plan, user clicks Approve before the sandbox runs.
- **Trigger surfaces**: (a) Aegis chat — natural language ask; (b) finding cards — "Fix with Aegis" button on vuln + Semgrep finding cards.
- **Output**: GitHub PR through the existing GitHub App integration. Branch + commits + PR body summarizing the change and what was tested.
- **Tear out the current `aider-worker/` entirely**. Architectural mismatch (dialog vs plan-based) makes it cheaper to rebuild than retrofit.
- **Aider as a name retires.** New worker name: `fix-worker` (or similar — naming during /plan-feature).

### Locked during interview

| Decision | Locked answer |
|---|---|
| **Sandbox host** | Fly.io with new app `deptex-fix-worker`. Reuse extraction-worker base image + heartbeat / scale-to-zero patterns. microVM (E2B / Modal / Firecracker) deferred until self-host enterprise tier. |
| **PR author** | GitHub App bot (`deptex-bot[bot]`). PR description credits the requesting user. No user-OAuth impersonation. |
| **Legacy data** | Wipe all old `project_security_fixes` rows on cutover. Clean slate. |
| **Plan validation** | Trust the planner LLM; user is the gate. No second-pass critic LLM. (Schema validation only, to reject malformed plans.) |
| **Plan expiry** | **No hard expiry.** Plans live until approved or rejected. Surface a **staleness warning** when the repo has drifted since the plan was generated: "This plan is based on commit `<sha>`. The branch is now N commits ahead — consider regenerating." Trigger the warning by comparing `default_branch` HEAD vs the plan's recorded commit at view time. |
| **Approval surfaces** | All three: (a) Aegis chat — plan card with Approve / Reject inline. (b) Finding card — same buttons inline when triggered from there. (c) Aegis inbox — pending plans surface for batch review. Same backend endpoint, three trigger points. |
| **Failure UX** | Both: (a) diagnostics posted in the originating Aegis chat thread; (b) finding card status badge updated to "Fix failed." Surfaces stay consistent. |
| **Repair budget** | 2 test-fail-then-fix cycles. Plan → execute → test fail → repair → test fail → give up. Mirrors fail-fast convention. |
| **Job scope** | **One finding per job, one PR per job for v1.** Batch fixes are explicitly future work (post-v1). |
| **Planner model** | Whatever the org has selected in Settings → AI as the platform default (Anthropic Sonnet 4.6 / OpenAI GPT-4o / Gemini 2.5 Flash). No hard-coded planner model. |
| **v1 language scope** | **JS/TS + Python + Go must work end-to-end at v1 ship.** Java / Ruby / PHP / Rust / C# are stretch goals — can land incrementally before public launch. Code must keep all 8 supported (don't gate by language); the v1 acceptance bar is just stricter for those three. |
| **Planner inability to fix** | Surface **"no fix possible"** with the reason in chat. No risky/partial plan with warnings. Examples: vuln has no patched version, ambiguous code change, change too large to scope confidently. Aegis can still suggest manual steps in prose. |

## Why this shape works for Deptex

Three structural advantages over a generic Jules clone:

1. **The research phase is pre-solved.** Generic agents burn half their context exploring the repo to figure out where the bug lives. Aegis already has the vuln record, the affected file paths (from reachability + imports tracking), the depscore signal, and the fix versions in the DB. Hand the agent a tight context bundle — don't make it re-discover.
2. **Fix scope is tight.** Every task is "patch finding ID X to resolution Y." That's the variable that makes Devin score 67% PR-merge in 2025 vs. open-ended SWE-bench tasks where flagships sit at ~64% on SWE-Bench Pro ([labs.scale.com](https://labs.scale.com/leaderboard/swe_bench_pro_public)). Lean into the constraint.
3. **Existing infra carries 70% of the build.** Fly.io workers (sandbox + scale-to-zero), GitHub App (PRs), `project_security_fixes` table (job state + heartbeat), `ai-fix-engine.ts` (context gathering), Aegis v3 tool registry (RBAC + danger levels). The new build is mostly plan-UX + structured-edit tool + repair loop.

## Architecture recommendation

### Convergent pattern from competitive research

Across Jules, Devin, Codex, Copilot Workspace, and SWE-agent, the loop is:

`setup → explore/spec → APPROVE → edit → test → PR`

Plus a **repair sub-loop** between `edit` and `PR` (Copilot's "repair agent", Devin's iterate-on-error). Sources: [blog.google/jules](https://blog.google/technology/google-labs/jules/), [cognition.ai/introducing-devin](https://cognition.ai/blog/introducing-devin), [githubnext.com/copilot-workspace](https://githubnext.com/projects/copilot-workspace), [openai.com/introducing-codex](https://openai.com/index/introducing-codex/).

### Recommended for Deptex v1

| Decision | Choice | Rationale |
|---|---|---|
| Agent topology | **Single-threaded linear agent** | Cognition's hard-won published lesson: ["Don't Build Multi-Agents"](https://cognition.ai/blog/dont-build-multi-agents). Multi-agent collaboration produces fragile systems; share full context with one agent instead. Cursor 2.0's parallel agents work because they're independent worktrees, not a coordinated task. |
| Plan format | **Markdown with editable sections** | Token-efficient (34-38% fewer than JSON per [improvingagents.com](https://www.improvingagents.com/blog/best-nested-data-format/)), human-readable. Adopt Copilot Workspace's two-bullet "current state / desired state" framing — maps directly to "vulnerable: lodash@4.17.20 / patched: 4.17.21". |
| Edit format | **Aider's `udiff` or search/replace, architect-then-editor split** | Aider's [edit-formats research](https://aider.chat/docs/more/edit-formats.html) shows udiff prevents code elision in long-context generation; the architect-mode split (one model plans in prose, a separate editor model emits syntactically valid edits) gives the highest correctness across tested models. Skip whole-file edits for anything beyond manifest files. |
| Sandbox | **Containerized Fly.io worker, default-no-network** | Reuse extraction-worker's base image (already has tree-sitter, cdxgen, 8 ecosystems' parsers). Add a per-job setup-script step driven by existing framework detectors (Codex pattern from [OpenAI Codex docs](https://openai.com/index/introducing-codex/)). microVM (Firecracker/E2B) deferred — container is fine for "fix our own org's repo" trust model; upgrade only for self-host enterprise / untrusted forks. |
| Multi-language strategy | **One image, language-aware bootstrap** | Deptex's extraction-worker image already has the toolchain footprint. Per-job: detect language from `project_repositories.ecosystem`, run appropriate setup script (`npm ci`, `pip install -r requirements.txt`, `mvn install`, `go mod download`, etc.). Language-specific test runners discovered the same way. Fallback to LLM-driven Dockerfile synthesis ([Repo2Run pattern, arXiv 2502.13681](https://arxiv.org/html/2502.13681v1)) only if bootstrap fails. |
| Network during exec | **Default-off, allow-list per session** | Jules and Antigravity both shipped with prompt-injection→data-exfiltration paths in 2025 ([embracethered.com on Jules](https://embracethered.com/blog/posts/2025/google-jules-vulnerable-to-data-exfiltration-issues/), [cyberscoop.com on Antigravity](https://cyberscoop.com/google-antigravity-pillar-security-agent-sandbox-escape-remote-code-execution/)). Codex went default-off; we follow. Allow-list package registries (npm, pypi, maven central, etc.) for setup phase only. |
| Approval gate | **Per-plan, not per-step** | Per-step (Cursor) is too noisy for async work. Per-PR (Devin) lands first, asks questions later. Per-plan (Jules + Copilot Workspace) gives the user a real veto with one click. Plan persisted in DB; user approves via Aegis chat or finding card UI. |
| Test loop | **Structured runner per language, capped** | Replit Agent 3's lesson: specialized harness beats computer-use 3-10x on cost ([blog.replit.com](https://blog.replit.com/introducing-agent-3-our-most-autonomous-agent-yet)). Run language-appropriate test command (`npm test`, `pytest`, etc.); on failure → repair sub-loop with hard step+wall-clock cap. |
| Edit / repair budgets | **Wall-clock + step + diff-size caps with circuit breaker** | Devin's catastrophic failures are 200-minute autonomous runs ([theregister.com on Devin](https://www.theregister.com/2025/01/23/ai_developer_devin_poor_reviews/)). Cap v1 at single-digit-minutes wall-clock, ~30 tool calls, ~500 LOC diff. Mirror the Aegis monthly cost cap pattern. |
| Tooling philosophy | **Few thoughtful tools, high-signal errors** | SWE-agent's ACI insight ([arXiv 2405.15793](https://arxiv.org/abs/2405.15793)) and [Anthropic's tool-writing guidance](https://www.anthropic.com/engineering/writing-tools-for-agents) both converge on: tool descriptions + error messages outweigh tool count. Resist the urge to give the agent 50 tools — give it 6 great ones. |

### Pipeline mapped onto Deptex infra

```
USER TRIGGER
  - From Aegis chat: a write tool `request_fix(findingId, ...)`
  - From finding card: button hits POST /api/aegis/fix/request

REQUEST PHASE  (existing /api/aegis/fix/request route, redesigned)
  - Validate trigger_fix permission (existing RBAC)
  - Cost cap check (existing Redis)
  - Insert row into project_security_fixes with status='planning'
  - QStash dispatch -> planning job

PLANNING PHASE  (new: backend job, in-process or QStash)
  - Reuse gatherVulnerabilityContext() from ai-fix-engine.ts:200+
  - Build context bundle: vuln record + affected files + reachability paths
    + dep manifest paths + package.json/pyproject.toml + test command hints
  - LLM call with strict plan schema (Markdown, current/desired bullet lists,
    file-level changes)
  - Persist plan to project_security_fixes.plan (new JSONB column)
  - Update status='awaiting_approval'
  - Aegis chat thread surfaces the plan card with Approve / Reject buttons

APPROVAL GATE  (new)
  - User clicks Approve in Aegis chat or finding card
  - PATCH /api/aegis/fix/:id/approve -> status='approved' -> dispatch sandbox job

SANDBOX EXECUTION  (new: fix-worker on Fly.io, replaces aider-worker)
  - Claim job via existing claim_fix_job() RPC pattern
  - Heartbeat (existing pattern from extraction-worker)
  - Clone repo (existing github.ts helpers)
  - Run language-aware setup script
  - Apply plan via architect-then-editor edit tool
  - Run language-appropriate test command
  - Repair sub-loop on test failure (capped)
  - On success: branch + commit + push (existing github.ts) -> open PR

PR + REPORTING  (existing pieces)
  - Open PR via github.ts:480 (createPullRequest)
  - Update project_security_fixes with pr_url, pr_number, diff_summary
  - Aegis posts back to the originating chat thread: "Opened PR #N"
```

## Data model deltas

### `project_security_fixes` — extend existing table

Add columns:
- `plan` JSONB — the structured Markdown plan (current_state, desired_state, file_changes, test_plan)
- `plan_generated_at` TIMESTAMPTZ
- `approved_at` TIMESTAMPTZ, `approved_by_user_id` UUID
- `approval_token` TEXT (signed nonce so the approve link is unforgeable from the chat surface)
- Existing fields stay: status, heartbeat_at, attempts, pr_url, pr_number, diff_summary, tokens_used, estimated_cost

Status enum extended: `'planning' | 'awaiting_approval' | 'approved' | 'executing' | 'completed' | 'failed' | 'rejected'`.

### `aegis_chat_messages` — no schema change

The plan card renders as a custom message part (similar to how tool-calls are message parts). The existing message parts JSONB already supports arbitrary types.

## UX flow

### Chat trigger

```
User: "fix CVE-2024-XXXX in payments-service"

Aegis: [tool call: request_fix → status: planning]
       [plan card]
       PLAN — bump lodash 4.17.20 → 4.17.21
       Current state:
         • lodash@4.17.20 in package.json (CVE-2024-XXXX, prototype pollution)
         • imported by 3 files (utils.ts, models/user.ts, ...)
       Desired state:
         • lodash@4.17.21 (patched in 4.17.21)
         • lockfile regenerated
         • no code changes needed
       File changes:
         • package.json:  "lodash": "^4.17.20" → "^4.17.21"
         • package-lock.json: regenerated
       Tests to run: npm test
       Wall-clock cap: 10 min
       [Approve]  [Reject]

User: [clicks Approve]

Aegis: [tool call: execute_fix → status: executing]
       [running in sandbox...]
       ✓ Cloned payments-service
       ✓ Bumped lodash to 4.17.21
       ✓ Regenerated lockfile
       ✓ npm test (47 passing, 0 failing)
       ✓ Opened PR #142

       Done. PR: https://github.com/.../pull/142
```

### Finding card trigger

Same pipeline, just initiated from the finding detail panel. The "Fix with Aegis" button on a vuln/finding card kicks off the same `/api/aegis/fix/request` endpoint. The plan card surfaces back in the user's Aegis inbox or directly on the finding card. Approval flow identical.

## What we reuse vs replace

### Reuse without changes

- `backend/src/lib/github.ts` — clone, branch, file ops, PR creation. Zero changes.
- `backend/src/lib/ai-fix-engine.ts` — `gatherVulnerabilityContext()` for context bundling.
- `project_security_fixes` table + `claim_fix_job()` RPC (extend, don't replace).
- Worker pattern from `backend/extraction-worker/` (heartbeat, claim, scale-to-zero, structured logging).
- Aegis v3 tool registry (`backend/src/lib/aegis-v3/`) — register `request_fix`, `approve_fix`, `check_fix_status` as new tools.
- Cost cap (Redis) and rate-limiting infra.

### Replace entirely

- `backend/aider-worker/` — Aider CLI subprocess model. Gone.
- `executor.ts` — single-shot prompt → code subprocess.
- `strategies.ts` `buildFixPrompt()` — assumes linear, no plan step.
- `ai-fix-engine.ts` `requestFix()` orchestration — needs to dispatch to planning, not directly to executor.

### Net new

- `backend/fix-worker/` (or wherever) — plan-then-execute agent loop with edit tool and repair sub-loop.
- Plan generator service (could live in `backend/src/lib/aegis-v3/fix-planner.ts`).
- Plan card UI in Aegis chat (`frontend/src/components/aegis/PlanCard.tsx`).
- Approve/Reject endpoints + signed-nonce flow.
- Edit tool implementation — udiff parser + applier with validation.
- Language-aware sandbox bootstrap scripts.

## Risks + mitigations

| Risk | Mitigation |
|---|---|
| **Prompt injection → sandbox escape → exfil** (Jules, Antigravity, Claude Code all shipped with this in 2025) | Network default-OFF in sandbox. Allow-list package registries during setup phase only. No secrets mounted. Deny-list approach explicitly fails — use allow-list ([trailofbits.com on Claude Code escape](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/)). |
| **Bad PR lands** | HITL approval gate (locked in v1). Diff-size cap (e.g., 500 LOC) with hard reject. Test-must-pass gate before push. PR description includes "Generated by Aegis — review carefully." |
| **Devin-style infinite loop** ([theregister.com](https://www.theregister.com/2025/01/23/ai_developer_devin_poor_reviews/)) | Wall-clock cap (5-10 min). Tool-call count cap (~30). Circuit breaker: 3 consecutive test failures → fail the job with diagnostic dump. |
| **Multi-language without 8 worker images** | Single fat image based on extraction-worker. Language-aware setup-script per job. Repo2Run-style LLM-Dockerfile fallback for edge cases ([arXiv 2502.13681](https://arxiv.org/html/2502.13681v1)). |
| **Vague prompts → 2500-LOC bloat** ([Jules failure pattern](https://medium.com/@eristoddle/jules-ai-the-currently-free-coding-assistant-that-cant-follow-directions-but-gets-shit-done-c77093c03bd6)) | Tight scoping: every job is "patch finding X to resolution Y," not open-ended. Plan must reference the originating finding ID. Diff-size cap with a hard-fail. |
| **Sonnet 4.5 premature task termination** ([Cognition's published Sonnet 4.5 lessons](https://cognition.ai/blog/devin-sonnet-4-5-lessons-and-challenges)) | Cap context usage well below model window. Repeat key instructions at start *and end* of system prompt. Optional: enable 1M beta for the architect model. |
| **Multi-agent fragility** | Don't go there. Single-threaded agent, period. Sub-tasks happen as tool calls within the same context, not as forked agents. |
| **Test runner flakiness for unknown repos** | Detect test command from existing framework detection signals; cache last-known-good command per project. Failure on test discovery → fail fast with a "this repo's test setup isn't auto-detectable" error message rather than retry-loop. |

## v1 acceptance criteria

1. From a Deptex Aegis chat, the user types "Fix CVE-2024-XXXX in <project>" or clicks "Fix with Aegis" on a vuln card. Aegis produces a Markdown plan card within 30s.
2. User reviews and clicks Approve. Sandbox runs, tests pass, PR opens within 5-10 min.
3. End-to-end works for at least 3 of the 8 supported languages on day one (suggest JS/TS + Python + Go as v1 validation set; remaining 5 added incrementally before v1.0 ships).
4. The flow degrades safely on failure: bad plan → user rejects, no harm done. Test failure → no PR opened, error logged. Sandbox crash → job retried, max 3 attempts.
5. Diff-size cap, wall-clock cap, and test-must-pass gates all enforce before push.
6. PR description self-documents what was changed, why, and what was tested.
7. Sandbox network default-off; the only outbound traffic during execution is package-registry allow-list (during the setup phase only).
8. The whole flow is observable: every fix job has structured logs viewable in real-time via the existing extraction_logs subscription pattern.

## Residual open questions (for `/plan-feature`)

The interview resolved scope. These are operational tuning knobs that `/plan-feature` should pin down:

1. **Per-fix wall-clock cap** — suggested range 5–10 min. /plan-feature should pick a concrete number based on what's plausible for "clone + setup + plan + edit + test ×2 + push" on the average repo.
2. **Per-fix cost cap** — separate from the org monthly cap. Suggested range $0.50–$2.00 per job to bound runaway agents. Track in `project_security_fixes.estimated_cost`, hard-fail above the cap.
3. **Plan-card visual structure** — the markdown plan format is locked, but how it renders in chat / on a finding card / in the inbox is design work. Reference the current `ToolCallGroup` chat surface for visual language.
4. **Sandbox image build pipeline** — single fat image extending extraction-worker base. Concrete: Dockerfile diff, test-discovery scripts per language, registry caching strategy.
5. **What does "all 8 languages must work at the code level" mean concretely** — even though only JS/TS+Python+Go are v1 ship gates, the worker should refuse-with-message rather than crash on Ruby/PHP/Rust/C# until they're hardened. /plan-feature defines that fallback.
6. **Inbox UX for pending plans** — does the existing Aegis inbox already have a card pattern this slots into, or is this new component work?

## Recommended next step

Run `/plan-feature` on this brief. The interview is complete. /plan-feature will produce milestone breakdown with concrete schema migrations, route handlers, worker scaffolding, plan-card component, and acceptance tests. The 6 residual questions above should be closed during planning.

## Sources

Codebase audit findings inline in the "What we reuse vs replace" section. Competitive research sources cited inline throughout — full URL list:

- [blog.google/jules](https://blog.google/technology/google-labs/jules/)
- [cognition.ai/introducing-devin](https://cognition.ai/blog/introducing-devin)
- [cognition.ai/dont-build-multi-agents](https://cognition.ai/blog/dont-build-multi-agents)
- [cognition.ai/devin-sonnet-4-5](https://cognition.ai/blog/devin-sonnet-4-5-lessons-and-challenges)
- [cognition.ai/devin-annual-performance-review-2025](https://cognition.ai/blog/devin-annual-performance-review-2025)
- [arXiv 2405.15793 (SWE-agent)](https://arxiv.org/abs/2405.15793)
- [githubnext.com/copilot-workspace](https://githubnext.com/projects/copilot-workspace)
- [github.blog Copilot Agent Mode](https://github.blog/ai-and-ml/github-copilot/agent-mode-101-all-about-github-copilots-powerful-mode/)
- [cursor.com/blog/2-0](https://cursor.com/blog/2-0)
- [cursor.com/blog/composer](https://cursor.com/blog/composer)
- [blog.replit.com — Agent 3](https://blog.replit.com/introducing-agent-3-our-most-autonomous-agent-yet)
- [aider.chat — edit-formats](https://aider.chat/docs/more/edit-formats.html)
- [aider.chat — repomap](https://aider.chat/docs/repomap.html)
- [openai.com — Introducing Codex](https://openai.com/index/introducing-codex/)
- [improvingagents.com — best nested data format](https://www.improvingagents.com/blog/best-nested-data-format/)
- [northflank.com — Daytona vs E2B](https://northflank.com/blog/daytona-vs-e2b-ai-code-execution-sandboxes)
- [embracethered.com — Jules data exfil](https://embracethered.com/blog/posts/2025/google-jules-vulnerable-to-data-exfiltration-issues/)
- [cyberscoop.com — Antigravity sandbox escape](https://cyberscoop.com/google-antigravity-pillar-security-agent-sandbox-escape-remote-code-execution/)
- [trailofbits.com — Claude Code prompt injection RCE](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/)
- [theregister.com — Devin reviews](https://www.theregister.com/2025/01/23/ai_developer_devin_poor_reviews/)
- [labs.scale.com — SWE-Bench Pro](https://labs.scale.com/leaderboard/swe_bench_pro_public)
- [arXiv 2502.13681 — Repo2Run](https://arxiv.org/html/2502.13681v1)
- [anthropic.com — writing tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents)
