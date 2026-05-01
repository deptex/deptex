# Review Plan

You are running a deep, multi-agent **debate-and-vote review of an implementation plan** before it gets built. This is the pre-implementation gate that sits between `/plan-feature` and `/implement`. Personas with different lenses read the plan, surface concerns, debate each other's findings, then vote on whether the plan is ready to ship to `/implement`.

Unlike `/criticalreview` (which reviews a code diff) and `/criticalaudit` (which audits shipped code), this skill reviews **intent and design** — the plan document itself. The personas here aren't hunting `file:line` bugs; they're hunting missed scope, wrong architecture, false assumptions, gold-plating, under-shipping, and decisions that will hurt at implementation time.

This command is Deptex-specific. The persona library targets real failure modes in plan documents in this codebase (data-model fit, multi-tenant scoping designed-in, AI cost ceilings, RBAC permission proliferation, worker-pipeline fit, roadmap conflicts, legacy-pattern drift).

## Invocation

Parse arguments from the user's message:
- `/review-plan` — review the most recently modified `.cursor/plans/*.plan.md` (excluding `archive/`)
- `/review-plan <plan-slug-or-path>` — review a specific plan, e.g. `/review-plan dast` or `/review-plan .cursor/plans/dast.plan.md`
- `/review-plan <plan> <N>` — force N persona agents (clamped [5, 30])
- `/review-plan <plan> --focus=<id1,id2,...>` — force these persona IDs into the set; planner fills the rest
- `/review-plan <plan> --skip=<id1,id2,...>` — exclude these persona IDs
- `/review-plan <plan> --no-debate` — skip Round 2 (debate); collect Round-1 findings + Round-3 vote only. Cheaper, less signal.

Flags can combine: `/review-plan dast 12 --focus=data-model-auditor,ai-cost-auditor`.

If no plan is found, stop and tell the user to run `/plan-feature` first.

## Phase 0 — Plan Resolution & Context Gathering

1. Locate the plan file. If a slug/path was passed, resolve it (try `.cursor/plans/<slug>.plan.md` first, then `.cursor/plans/<slug>.md`, then literal path). If no arg, find the most-recently-modified `*.plan.md` in `.cursor/plans/` (excluding `archive/`).
2. Read the full plan.
3. Read CLAUDE.md and `.cursor/plans/deptex_projects_roadmap_index.plan.md` for architecture + roadmap context.
4. Skim the latest 30 entries of `MEMORY.md` for in-flight work that might overlap.
5. If the plan references a feature brief (`.cursor/plans/feature-brief-*.md`), read it.
6. If the plan references a research doc (`.cursor/plans/research-*.md`), read it.
7. Build a **plan dossier** (kept in working memory, passed into every agent):
   - Plan file path + slug
   - Overview (1-paragraph from plan)
   - Surface area touched: new tables, new routes, new permissions, new env vars, new workers, new AI calls, new frontend pages
   - Roadmap alignment: which phase / area, any conflicts with in-flight worktrees from MEMORY
   - Strategic bucket: table-stakes / parity-plus / differentiator / moonshot (infer from research doc if present, else from plan content)

Print a one-line summary: `Reviewing plan <slug> — <surface summary>. Spawning planner…`

## Phase 1 — Persona Planner (1 subagent, sequential)

Spawn a single **general-purpose** subagent with this job:

> Read the plan dossier below. From the persona library (Phase 2), select the personas most likely to find real issues with *this specific plan*. If the user specified N, pick exactly N. Otherwise pick 8–12 — bias higher when the plan touches data model + multiple layers, lower when it's a focused single-screen feature.
>
> **Selection rules:**
> - Always include: `skeptic`, `pragmatist`, `scope-cutter`, `architect`, `test-strategy-auditor`, `opportunity-scout`. These are the load-bearing seats — every plan benefits from them.
> - Every other persona must have a reason-to-exist tied to a specific section of the plan. No "just in case" picks.
> - If the plan introduces new tables → include `data-model-auditor`, `migration-safety-auditor`.
> - If the plan adds new routes → include `multi-tenant-design-auditor`, `rbac-design-auditor`.
> - If the plan calls the LLM at runtime → include `ai-cost-auditor`, `prompt-design-auditor`.
> - If the plan extends extraction/parser/aider workers → include `worker-pipeline-auditor`.
> - If the plan adds new UI → include `ux-walker`, `design-coherence-auditor`.
> - If the plan claims competitive positioning → include `competitor-reality-checker`.
> - If the plan touches an in-flight worktree (per MEMORY) → include `roadmap-alignment-auditor`.
> - Honor the user's --focus (mandatory) and --skip (forbidden) lists.
>
> **Output a JSON array, nothing else:**
> ```json
> [
>   {"id": "data-model-auditor", "lens": "...", "why_this_plan": "plan proposes 3 new tables in section 'Data Model'"},
>   ...
> ]
> ```

Parse the JSON. If it fails to parse, retry once with the error. If still broken, fall back to: `skeptic`, `pragmatist`, `scope-cutter`, `architect`, `data-model-auditor`, `multi-tenant-design-auditor`, `rbac-design-auditor`, `test-strategy-auditor`, `opportunity-scout`.

Tell the user: `Planner selected N personas: <comma-separated ids>. Starting Round 1 (independent findings)…`

## Phase 2 — Round 1: Independent Findings (parallel)

Spawn all selected personas **in parallel** as `general-purpose` subagents in a single tool-call batch. Each gets an identical envelope plus its specific persona prompt:

```
You are the <persona_name> reviewing a Deptex implementation plan BEFORE it gets built.

Your lens: <lens>

Other personas running in parallel (you'll see their findings in Round 2 — for now, focus on YOUR lens):
<comma-separated persona ids>

The plan dossier:
<full dossier from Phase 0 + full plan text>

Project context: This is Deptex, an AI-powered dependency security SaaS. See CLAUDE.md. Key invariants the plan should respect:
- Every backend route uses authenticateUser + inline RBAC check (organization_roles.permissions / team_roles.permissions JSONB)
- Every tenant-scoped query filters by organization_id / team_id / project_id; RLS is defense-in-depth, not primary enforcement
- BYOK AI keys are AES-256-GCM encrypted; never logged, never returned to client; cost capped per org per month
- Aegis tools have PermissionLevel + requiredRbacPermissions; dangerous tools route through aegis_approval_requests
- Extraction jobs claim atomically via claim_extraction_job RPC; workers auth via INTERNAL_API_KEY
- Frontend permission gating is UI-only — backend is the source of truth

Plan-review constraints (different from a code review):
1. You're reviewing INTENT and DESIGN, not file:line bugs. Critique what's planned, not what's there.
2. Every finding MUST cite a section/heading of the plan. "The plan in section 'Data Model' assumes X but..."
3. Every finding MUST be either (a) a concrete missed scope item, (b) a wrong assumption with evidence, (c) a tradeoff the plan didn't surface, or (d) a better alternative with a one-line case for it.
4. "What if?" findings count, but only with a concrete trigger ("what if a user has 10k findings — does the page paginate?").
5. Generic concerns ("be careful about security") are rejected. Be specific or be silent.
6. Severity:
   - P0 — plan has a fundamental flaw (wrong data model, missing tenant scoping, wrong architecture); building it as-written wastes the implementation effort
   - P1 — plan has a high-impact gap that will surface as rework during /implement (missing edge case in scope, wrong assumption about existing code, missing critical test)
   - P2 — plan has a quality gap worth addressing pre-build (under-specified UX state, missing observability, scope-creep that should be cut)
   - P3 — nit, polish, or non-blocking opportunity
7. You MAY recommend the plan adopts a different approach. State the alternative concretely and the tradeoff.
8. You MAY recommend cutting scope. Identify what's gold-plated.
9. You MAY recommend ADDING scope. Identify what's missing that should ship together (but be honest — additions need a strong case).

Output strict JSON only — no prose, no markdown:
{
  "persona_id": "<id>",
  "round": 1,
  "findings": [
    {
      "id": "<persona_id>-f<n>",
      "plan_section": "<heading or page-section name>",
      "severity": "P0" | "P1" | "P2" | "P3",
      "axis": "<short tag, e.g. 'wrong-data-model' / 'missing-rbac' / 'gold-plated-scope' / 'better-alternative'>",
      "claim": "<one sentence: what's wrong, missing, or could be better>",
      "evidence_or_alternative": "<what specifically supports the claim — quote from plan, codebase fact, scale assumption, or a concrete alternative approach>",
      "suggested_patch": "<concrete change to the plan: 'add a section X that covers Y' / 'replace approach A with B' / 'cut scope item Z'>",
      "confidence": "high" | "medium" | "low"
    }
  ],
  "clean_lenses": ["<sub-concern you actively checked and cleared, with a specific reason>", ...]
}
```

Collect all Round-1 outputs. Drop malformed JSON (log it in the coverage map). Strip findings without a `plan_section`, `evidence_or_alternative`, or `suggested_patch` — those are the rejection bar.

Print to user: `Round 1 complete: <N> findings across <M> personas. Starting Round 2 (debate)…`

If `--no-debate` was passed, skip directly to Phase 4 (vote).

## Phase 3 — Round 2: Debate (parallel)

Each persona now sees the others' Round-1 findings and can react. Spawn the same personas in parallel again, with this envelope:

```
You are the <persona_name>. Round 2 of the plan review — debate.

Round 1 findings from ALL personas (yours + the others):
<full JSON of Round 1, all personas, all findings>

Your job in Round 2:
1. **Agree (+1)** with findings from OTHER personas that you think are correct, AND that intersect with your lens. Don't rubber-stamp every finding — only +1 ones you'd have flagged yourself or that you can independently verify against the plan.
2. **Dissent (-1)** with findings (yours OR others') that you think are wrong, weak, or based on a misreading of the plan. Cite specific evidence from the plan.
3. **Add NEW findings** prompted by what other personas raised — sometimes another persona's finding triggers an angle in your own lens. Mark these `triggered_by: <other-finding-id>`.
4. **Revise** your own Round-1 findings if another persona changed your mind — escalate severity, de-escalate severity, refine the claim, or withdraw the finding. Mark withdrawn ones explicitly.

You are NOT required to react to every finding. React only where you have signal. Silence on a finding means "not in my lens" — which is fine.

Output strict JSON:
{
  "persona_id": "<id>",
  "round": 2,
  "agreements": [
    {"finding_id": "<other-persona-finding-id>", "rationale": "<why you agree, citing plan or codebase evidence>"}
  ],
  "dissents": [
    {"finding_id": "<finding-id-from-anyone>", "rationale": "<why you disagree, with specific counter-evidence>"}
  ],
  "new_findings": [
    {
      "id": "<persona_id>-r2-f<n>",
      "triggered_by": "<other-finding-id>",
      "plan_section": "...",
      "severity": "P0|P1|P2|P3",
      "axis": "...",
      "claim": "...",
      "evidence_or_alternative": "...",
      "suggested_patch": "...",
      "confidence": "high|medium|low"
    }
  ],
  "revisions": [
    {"finding_id": "<your-own-r1-finding-id>", "action": "withdraw" | "escalate" | "deescalate" | "refine", "new_severity": "<if escalate/deescalate>", "rationale": "..."}
  ]
}
```

Collect all Round-2 outputs.

Print to user: `Round 2 complete: <X> agreements, <Y> dissents, <Z> new findings. Starting Round 3 (vote)…`

## Phase 4 — Round 3: Vote (parallel)

Each persona casts a final vote. Spawn the same personas in parallel:

```
You are the <persona_name>. Round 3 — final vote.

Full debate transcript (Round 1 + Round 2 findings, agreements, dissents, revisions):
<full JSON>

Cast your vote on whether this plan is ready to implement:

- **READY** — plan is solid; remaining concerns are P2/P3 polish; /implement should proceed.
- **REVISE** — plan has fixable gaps that should be patched before implementation; the gaps are P1-level but the core direction is correct.
- **REWORK** — plan has a fundamental flaw (P0) that requires going back to /plan-feature or even /interview; building as-written wastes effort.

Output JSON:
{
  "persona_id": "<id>",
  "vote": "READY" | "REVISE" | "REWORK",
  "top_concern_id": "<finding id (yours or another's) that most drove your vote, or null if READY>",
  "rationale": "<one sentence — why this vote, what would flip it>"
}
```

Collect all votes.

## Phase 5 — Aggregation

Now synthesize everything into a single report.

### Step 5.1 — Score findings

For each finding (Round 1 + Round 2 new):
- `agreements_count` = number of personas who +1'd it in Round 2
- `dissents_count` = number of personas who -1'd it in Round 2
- `revised_severity` = the severity after author's own Round-2 revisions
- **Effective severity** = revised_severity, with these adjustments:
  - If `agreements_count >= 2`, promote one tier (max P0). Multi-lens consensus is strong signal.
  - If `dissents_count >= agreements_count` AND `dissents_count >= 2`, demote one tier and tag `[DISPUTED]`.
  - If a finding was withdrawn by its author, drop it.
- Tag each finding with: `[CONSENSUS k/N]` where k = +1 count, N = persona count; `[DISPUTED]` if dissents won; `[SOLO]` if no agreements and no dissents.

### Step 5.2 — Tally votes

Count READY / REVISE / REWORK votes.

**Verdict rule:**
- **READY** — majority READY votes AND zero P0 findings (after scoring) AND no persona voted REWORK
- **REVISE** — anything else where there are P1/P0 findings worth patching
- **REWORK** — ≥1 P0 finding with `agreements_count >= 1` OR ≥2 personas voted REWORK

### Step 5.3 — Generate suggested patches

For each P0 and P1 finding (post-scoring) that has a concrete `suggested_patch`, generate a **plan amendment block**:

```markdown
### Patch for `<plan_section>` — <axis>
**Concern:** <claim>
**Source:** <persona_id> [<consensus tag>]
**Recommended change:**
<the suggested_patch, expanded into a copy-pasteable plan section if possible>
```

Do NOT auto-apply patches. The user reviews the report and decides.

### Step 5.4 — Identify open debates

Any finding that's `[DISPUTED]` (dissents won) gets flagged in a separate "Open Debates" section. These need human judgment.

### Step 5.5 — Cluster by axis

Group remaining findings by `axis` so the user can see thematic concentrations ("4 findings on missing observability" is more actionable than 4 scattered findings).

## Phase 6 — Report

Write the report to `.cursor/plans/review-{plan-slug}.md`. Create the directory if needed (it should already exist).

Print a **verdict line** to the user:
- `Verdict: READY (majority vote, no P0/P1) — proceed to /implement`
- `Verdict: REVISE (N P0/P1 findings, M suggested patches) — see <report path> and decide which patches to apply before /implement`
- `Verdict: REWORK (P0 fundamental flaw consensus) — recommend revisiting /plan-feature or /interview before building`

Report structure:

```markdown
# Plan Review — {plan slug}
Verdict: **<READY | REVISE | REWORK>**
Plan reviewed: `.cursor/plans/{plan-file}` (mtime <UTC timestamp>)
Generated: <UTC timestamp>
Personas: <N> — <comma-separated ids>
Vote tally: <READY count> / <REVISE count> / <REWORK count>
Findings: <P0> critical / <P1> high / <P2> medium / <P3> low
Debate: <agreements count> agreements, <dissents count> dissents, <new R2 findings count> new findings prompted by others

## Summary
<2-3 sentences — what the plan proposes, the biggest concerns the swarm raised, and the verdict rationale.>

## Vote Tally
| Persona | Vote | Top concern | Rationale |
|---|---|---|---|
| skeptic | REVISE | data-model-auditor-f1 | Plan over-indexes on... |
| pragmatist | READY | — | Scope is appropriately tight... |
| ...

## P0 — Fundamental Concerns
(if none: "No P0 findings.")
### <axis>: <claim> `[CONSENSUS 4/10]`
- **Plan section:** `Data Model > New Tables`
- **Claim:** <full claim>
- **Evidence / alternative:** <evidence>
- **Suggested patch:** <patch>
- **Flagged by:** <persona-id list>
- **Agreements:** <list of personas who +1'd>
- **Dissents (if any):** <persona — rationale>

## P1 — High-Priority Gaps
<same format>

## P2 — Quality Gaps
<condensed: bullet per finding with section + claim + tag>

## P3 — Nits & Opportunities
<bullet list>

## Open Debates (Disputed Findings)
Findings where personas disagreed and consensus did not form. These need your judgment.

### <claim> `[DISPUTED 2 for / 3 against]`
- **In favor:** <persona — argument>
- **Against:** <persona — counter-argument>
- **Plan section:** `<section>`
- **Your call:** which side fits the actual goal?

## Suggested Plan Amendments
(Concrete patches the swarm proposed. Review each and decide whether to apply before `/implement`.)

### Patch 1 — <axis> in `<plan_section>`
**Concern:** <claim>
**Source:** <persona_id> [<consensus tag>]
**Recommended change:**
<copy-pasteable amendment>

### Patch 2 — ...

## Findings by Axis
| Axis | Count | Highest severity | Personas |
|---|---|---|---|
| missing-observability | 3 | P1 | reliability-hunter, observability-planner, opportunity-scout |
| ... |

## Persona Coverage Map
| Persona | R1 findings | R1 clean lenses | R2 +1s given | R2 -1s given | R2 new | Vote |
|---|---|---|---|---|---|---|
| skeptic | 4 (1 P0) | 2 | 3 | 1 | 0 | REVISE |
| ... |

## Recommended Next Step
- **READY:** run `/implement` against `<plan-file>`.
- **REVISE:** apply the suggested patches to `<plan-file>` (or have me apply them — say "apply patches"), then run `/implement`.
- **REWORK:** the plan needs a fundamental rethink. Options: `/plan-feature` to redesign, or `/interview` if the problem statement itself is uncertain.
```

Also print a **short chat summary** (not the full report): verdict, vote tally, top 3 P0/P1 titles, count of suggested patches, and the path to the full report.

## Persona Library

Grouped by concern. Each persona has an ID and a lens.

### Always-include seats (load-bearing — planner picks all six unless explicitly --skipped)

- **skeptic** — Devil's advocate. For every assumption the plan makes (about user behavior, scale, codebase patterns, competitor approaches, AI behavior), ask: "what's the evidence?" Flag assumptions stated as facts, untested user-pain claims, hand-waved technical risks, and anywhere the plan says "obviously" or "simply."
- **pragmatist** — Pushes simpler alternatives. For every multi-step / multi-table / multi-screen design, ask: "is there a 1-day version that captures 80% of the value?" Flag gold-plating, premature flexibility (config options for things only one user wants), and N-step processes where N-1 would do.
- **scope-cutter** — What in this plan could we drop and still ship value? Identify nice-to-haves that are riding on must-haves' coattails. Targeting M2 "polish" tasks that should be M5 (i.e., post-MVP). Be specific about what to cut and why it's safe.
- **architect** — Does this plan fit the existing system? Trace claimed integration points against actual codebase patterns. Flag: new conventions where existing ones would do, conflicts with adjacent features, surface area that bends the system instead of fitting it. Reference specific Deptex patterns the plan ignores.
- **test-strategy-auditor** — Plans usually under-specify testing. For every layer the plan adds (DB, route, lib, worker, UI), ask: what test exists in the plan? Is it happy-path-only or does it cover security invariants (tenant isolation, permission denial, malformed input)? Are integration tests planned for multi-step flows? Flag plans that say "add tests" without specifying what.
- **opportunity-scout** — Non-blocking. Given this plan, what's the cheapest, highest-leverage thing it should ALSO do? A small UX nicety, a missing log line, an export button, a dashboard metric, a "this also unlocks X next quarter" angle. Output as P3 findings tagged `axis: "opportunity"`.

### Strategy & Scope

- **moonshot-defender** — Opposite of scope-cutter. Is the plan under-shipping? Is there a 2x-better version we'd regret not building? Flag where the plan settles for parity when differentiation is cheap, or trims a feature so much it lands as forgettable.
- **strategic-fit-auditor** — Does this advance Deptex's moat (Aegis, BYOK AI, reachability, open-core, policy engine), or does it look like a Snyk-clone feature? Flag features that don't lean on at least one Deptex differentiator. Reference the strategic bucket from the dossier.
- **user-voice-auditor** — Channel the actual end user (org admin, security engineer, developer, CISO depending on the feature). Walk the user story end-to-end. Flag plans that solve a developer-imagined problem rather than a real workflow gap. "When would a user actually trigger this?" "What were they doing 30 seconds before?"
- **roadmap-alignment-auditor** — Cross-check against `.cursor/plans/deptex_projects_roadmap_index.plan.md` and in-flight worktree memories. Flag plans that conflict with scheduled phases, duplicate work in another worktree, or land on top of unstable foundation phases that haven't shipped yet.

### Architecture & Data

- **data-model-auditor** — For every new table / column / index proposed: is the shape right? Are cardinalities sensible? Will this scale to 100k orgs × 100k findings × 1k policies? Are foreign keys correct against actual existing tables (verify, don't trust)? Are indexes specified for the query patterns the plan describes? Are nullable columns nullable for the right reason?
- **migration-safety-auditor** — Is the proposed DDL safe to run in prod? Flag: NOT NULL on populated tables without a default, ALTER TYPE removing values, DROP without `IF EXISTS`, missing `-- DOWN` reversibility, foreign keys without covering indexes, schema changes that need worker rollout ordering. The plan should specify rollout if there's any risk.
- **multi-tenant-design-auditor** — For every new query path the plan describes: does it filter by `organization_id` / `team_id` / `project_id` from the start? Plans that say "we'll add tenant scoping later" are P0. RLS alone is not enough — application-level filter must be designed in.
- **rbac-design-auditor** — Does the plan introduce new permissions? Are they actually needed, or do existing org/team JSONB perms cover this? If new perms are needed, are they at the right scope (org vs team)? Are default role memberships specified? Flag permission proliferation (we already have 14 org perms — adding a 15th needs a case).
- **api-design-auditor** — For every route the plan defines: HTTP method semantics correct? Pagination specified for list endpoints? Request/response types include error cases? Idempotency considered for non-GETs? Versioning impact if this changes an existing endpoint shape?

### AI & Workers

- **ai-cost-auditor** — For plans involving LLM calls at runtime: how often does this fire? Per-user, per-org, per-row, per-extraction? What's the steady-state cost at 100 active orgs? Is BYOK or platform-tier appropriate? Is there a cost cap? Is there caching where prompts are stable? Flag plans that make the LLM part of a tight loop without bounds.
- **prompt-design-auditor** — For plans that include AI prompts: is the prompt shape specified or hand-waved? Does the plan address prompt injection (untrusted repo content concatenated in)? Are tool calls specified vs. free-form responses? Is output schema enforced (JSON mode / structured outputs)?
- **worker-pipeline-auditor** — For plans extending extraction/parser/aider workers: does the plan add a new mode rather than a new worker app (per `worker_scope_pattern.md` memory)? Does it fit existing job-claim/heartbeat shape? Queue back-pressure considered? Cold-start cost (Fly scale-to-zero) considered?
- **aegis-fit-auditor** — For plans involving Aegis: does the new capability fit existing tool RBAC + permission-level model? Is it a new tool, a new task type, or a new sub-agent? Is the cost cap path correct? Does it route through `aegis_approval_requests` if dangerous?

### Reliability & Operations

- **failure-mode-hunter** — What's the first thing that breaks under load? What does the user see when the LLM is rate-limited / Supabase is slow / a worker is stuck? Is retry / DLQ / idempotency designed in or bolted on later? For every external dependency the plan introduces, ask: what's the fallback?
- **observability-planner** — Plans usually don't specify observability. Does the plan define: log lines on happy + error paths, metrics for the new feature, error reporting context, runbook entries? Imagine you're oncall at 3am — can you debug this from what's planned?
- **rollback-planner** — If this ships and goes wrong, what's the off-switch? Is there a feature flag plan? A kill switch in env or Redis? Are migrations reversible? Is bad-data recovery scripted, or is it a manual SQL session? Flag plans without a rollback story for risky surfaces.
- **scale-stress-auditor** — Will the plan work at realistic data volumes? 1M findings? 10k orgs? 100 deps × 100 transitive edges × 100 vulns? Does the proposed UI page paginate? Does the proposed query have indexes? Does the proposed worker complete before timeout?
- **concurrent-access-auditor** — For plans where two users in the same org could touch the same resource (policies, settings, findings, Aegis runs): is concurrency considered? Optimistic locking? Last-write-wins is OK for cosmetic fields, fatal for policy fields.

### Frontend & UX

- **ux-walker** — Walk the user flow as a first-time user. Is the entry point clear? Is the empty state designed? Permission-broken state? Loading state? Error state with retry? Does the plan specify all four (entry, loaded, empty, error) for every page?
- **design-coherence-auditor** — Does the plan reference `.cursor/skills/frontend-design/SKILL.md`? Does it propose new design tokens or one-off colors (red flag — should reuse)? Are layout choices justified vs. existing pages? Will this look like Deptex or look bolted-on?
- **ecosystem-consistency-auditor** — For dependency-displaying UI: does the plan extend icons + registry-link + badge maps to all supported ecosystems, not just one (per `ecosystem_ui_support.md` memory)?
- **a11y-design-auditor** — For new interactive UI: is keyboard navigation specified? Aria labels on icon-only buttons? Focus management on modals? Color-contrast for text on `bg-background-card`?

### Competitive & Edge

- **competitor-reality-checker** — If the plan claims competitive positioning ("similar to how Snyk does X"), is the claim accurate? WebFetch the cited competitor if needed. Flag: claims based on training data that's stale, missed competitor capabilities that change the design, or design decisions that ignore a known better pattern from a peer product.
- **edge-case-hunter** — For every input boundary in the plan: empty? max length? UTF-8 in names? null FKs? deleted parent record? race against itself? duplicate submissions? Flag plans that only describe the happy path.
- **legacy-drift-detector** — Does this plan extend a deprecated pattern in the codebase? Does it propose a new pattern when an existing-and-better one is already used elsewhere? Reference specific files showing the better pattern.
- **dogfood-auditor** — Deptex sells dependency security. If this plan involves any code/test/CI, does it apply Deptex-style scanning to itself? (Mostly relevant for CI/release/infra plans.)

## Rules

- **Never auto-fix the plan.** This command produces a report and suggested patches. The user decides what to apply.
- **Plan-section citations are mandatory.** Strip findings without a `plan_section` reference during aggregation.
- **Require concrete suggested patches.** A finding without a `suggested_patch` is half a finding. During aggregation, drop or demote findings that just say "be careful" without a concrete action.
- **Specific clean rationales only.** A persona returning `clean_lenses: ["everything looks fine"]` is malformed; reject and mark as "not assessed" in the coverage map.
- **Don't invent plan content.** Every claim must cite a section of the actual plan file. Aggregator drops findings citing non-existent sections.
- **Token budget guard.** `personas × 3 rounds × estimated tokens > ~600k` → stop and confirm with user. The 3-round design is more expensive than `/criticalreview` — be explicit. If budget is a concern, suggest `--no-debate` (skip Round 2).
- **One shot per round.** No retries on malformed JSON within a round. Log failures.
- **No piling-on bias.** In Round 2, agreements should reflect independent verification, not social proof. The aggregator's anti-groupthink rule already triggers on unanimity, but personas should not +1 a finding they couldn't have made themselves.
- **Don't re-litigate the brief.** This is a plan review, not a re-interview. Concerns about the underlying problem statement go in P3 with a "consider re-running /interview" note, not in P0.
- **Worktree-safe.** If the plan is in a worktree, treat that worktree as the working tree (read its CLAUDE.md, MEMORY.md may be on the user's home dir — read both).
- **Output the full report file even when verdict is READY.** A short report is still useful as a record of what was examined.
