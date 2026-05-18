# Plan Review — aegis-chat-todos

> **Historical context (2026-05-09):** This plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. Where this plan references BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, or `AI_ENCRYPTION_KEY` for AI key envelopes, treat those as historical implementation details — current AI runs on platform keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from worker env). `AI_ENCRYPTION_KEY` itself is still in use, but only for `organization_registry_credentials` (IaC v2 Phase 1).

Verdict: **REWORK** (interpreted: substantial revision pass — see "What REWORK means here")
Plan reviewed: `.cursor/plans/aegis-chat-todos.plan.md`
Generated: 2026-05-06
Personas: 9 — `skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, prompt-design-auditor, aegis-fit-auditor, ux-walker`
Vote tally: **0 READY / 5 REVISE / 4 REWORK**
Findings (post-debate, deduped across personas): **6 P0** / **18 P1** / **15 P2** / **12 P3**
Debate: 9 personas all returned R2 reactions; ~60 cross-persona agreements, ~25 dissents, ~30 new R2-triggered findings.

## Summary

The plan is conceptually sound — Cursor-style AI-managed todos riding on existing `metadata.parts`, no new tables, no new routes. But independent verification by multiple personas hit **3 verified P0 falsifications of stated invariants**: (1) `deriveTodos` algorithm matches none of the three real AI SDK part shapes (live streaming `tool-<name>`/input, persisted `tool-call`/args, rehydrated `dynamic-tool`/input), so the strip will silently render nothing; (2) plan asserts "no changes to `aegis_tool_executions`" but `agent.ts:87-108` unconditionally writes every tool call, polluting telemetry; (3) plan claims framer-motion is "most likely a dependency" but it isn't in `package.json`. Plus a strong convergent simplification (collapse to a single `set_todos` full-replace tool resolves ~5 P0/P1s at once: id fabrication, naming asymmetry, step-budget cap, prompt complexity, half the tests). Plus the system-prompt rule itself contradicts the existing fan-out rule. The 4 REWORK voters didn't mean "the design is broken" — they meant "the patches we've identified are too numerous and structural for a quick edit; rewrite the plan with them folded in." The 5 REVISE voters agreed in spirit but counted the patches as an edit pass rather than a rewrite.

## What REWORK means here

The slash command spec defines REWORK as "fundamental flaw requiring `/plan-feature` redesign or `/interview` to revisit the problem statement." **Neither applies.** The user (Henry) wants Cursor-style todos and the design fits. What the four REWORK voters explicitly meant:

> *"Plan still ships two-tool design with dead `reason` field, `cancelled` status, framer-motion hedge, six-case derivation tests, and full Task 9 polish — collapsing to single set_todos full-replace plus dropping the polish removes ~30% of surface and most R1 P0/P1s in one stroke, but none of those cuts are in the plan yet."* — scope-cutter
>
> *"P0 plumbing changes (audit gate, agent.ts edits, parts-shape normalizer, message-history filter, empty-bubble guard) exceed REVISE-scope tweaks."* — aegis-fit-auditor
>
> *"Stalled-state UX hole, missing recovery affordance, missing scroll/collapse, undefined terminal-state visibility, and unspecified a11y haven't been folded in yet."* — ux-walker

In practice, the right next step is **apply the consensus patches inline** (rewrite the plan body to absorb them), then run `/implement`. Going back to `/plan-feature` would discard the converged design work.

## Vote Tally

| Persona | Vote | Top concern | Rationale |
|---|---|---|---|
| skeptic | REVISE | architect-f1 / shape-mismatch | Core direction sound; verified-broken derivation + 3 other P0s have concrete fixes — fold in before /implement. |
| pragmatist | REWORK | shape-mismatch + telemetry + single-tool decision | 5 P0 blockers remain; needs structural rewrites, not edits. |
| scope-cutter | REWORK | pragmatist-f1 / single-tool collapse | Plan still ships two-tool design with dead fields, polish, and over-scoped tests. |
| architect | REVISE | architect-f1 / three-shape mismatch | Five P0s with concrete patches; none require architectural rework, just an editing pass. |
| test-strategy-auditor | REVISE | shape-mismatch + test surface | Test matrix and shape-normalizer fixture need to land; one more revision warranted. |
| opportunity-scout | REVISE | telemetry log line missing | Plan converged on the right shape but ships zero discipline-metric instrumentation. |
| prompt-design-auditor | REVISE | rule-rewrite + threshold | Prompt-rule rewrite + simplification fixes are mechanical, well-scoped edits. |
| aegis-fit-auditor | REWORK | aegis-fit-f1 / agent.ts | Volume of P0/P1 plumbing edits exceeds REVISE-scope. |
| ux-walker | REWORK | ux-walker-f1 / stalled state | Multiple converged UX fixes haven't been folded in; shipping as-is produces a UI that lies. |

## P0 — Fundamental Concerns (post-debate)

### shape-mismatch in `Data Model > Derivation rule (frontend)` `[CONSENSUS 5/9]`
- **Plan section:** `Data Model > Derivation rule (frontend)`
- **Claim:** `deriveTodos` algorithm checks `parts[i]?.type === 'tool-call'` and reads `args` — but the three real shapes in this codebase are: (a) live streaming UIMessage parts = `{type: 'tool-<name>', input, output, state}`, (b) persisted DB rows in `aegis_chat_messages.metadata.parts` = `{type: 'tool-call', toolName, args}` (`backend/src/lib/aegis-v3/parts.ts:41-46`), (c) rehydrated UIMessages going to MessageBubble via `buildInitialMessages` = `{type: 'dynamic-tool', toolName, input, output}` (`frontend/src/components/aegis/ChatPane.tsx:88-130`). Plan's algorithm matches NONE of the three runtime shapes. Strip will silently render nothing both during streaming and on rehydration.
- **Suggested patch:** Single shared normalizer at `frontend/src/lib/aegis-parts.ts` mirroring `MessageBubble.tsx:34-47`'s `isToolPart` + `toolNameFor`: extract `toolName = part.toolName ?? (part.type?.startsWith('tool-') ? part.type.slice(5) : null)` and `args = part.args ?? part.input ?? {}`. `MessageBubble` switches to import from this same module in the same PR (kills a duplication risk). Add a round-trip test that drives all three shapes through it and asserts identical `Todo[]` output.
- **Flagged by:** architect, skeptic, test-strategy-auditor, aegis-fit-auditor, pragmatist
- **Agreements:** 5/9 personas

### telemetry-side-effects in `What we're explicitly NOT touching` `[CONSENSUS 4/9]`
- **Plan section:** `Codebase Analysis > What we're explicitly NOT touching`
- **Claim:** Plan asserts "no changes to `aegis_tool_executions`" but `backend/src/lib/aegis-v3/agent.ts:87-108` unconditionally writes every tool call via `saveToolExecution` with hardcoded `toolCategory: 'read_only'`, `permissionLevel: 'safe'`. A 12-item turn writes 25 telemetry rows for pure UI bookkeeping, polluting the same table the existing cost-cap, rate-limit, and AI-spend dashboards may aggregate against.
- **Suggested patch:** Add optional `audit?: boolean` (default `true`) to `AegisToolEntry` type. New chat-tool entries set `audit: false`. `agent.ts onStepFinish` checks `entry.audit !== false` before calling `saveToolExecution`. ~5 LOC. Plan must drop the "NOT touching aegis_tool_executions" bullet from §"What we're explicitly NOT touching" and add `agent.ts` to "Files this feature will touch."
- **Flagged by:** aegis-fit-auditor, architect, skeptic, pragmatist
- **Agreements:** 4/9

### single-tool-vs-two-tool-decision-blocker in `API Design > New tools` `[CONSENSUS 4/9]`
- **Plan section:** `API Design > New tools`
- **Claim:** Plan ships two tools (`set_todos` + `update_todo`). A single tool `set_todos({todos: [{title, status?}]})` with full-list-replace semantics resolves at the same time: id fabrication risk (no ids needed), naming asymmetry (`set_todos`/`update_todo` plural-vs-singular trips models), step-budget cap (12 todos × 25 calls = exact 25-step ceiling), most of derivation merge complexity, six of eight planned Jest cases, and the `cancelled` status's only purpose. Cursor's `todo_write` and Claude Code's `TodoWrite` are both single-tool full-replace.
- **Suggested patch:** Lock the design to one tool. `set_todos({todos: [{title: string, status?: 'pending'|'in_progress'|'done'}]})`. Status defaults to pending. Each call replaces. Drop `update_todo`, ids, `cancelled` state, `reason` field, server-side validation hook, six-of-eight derivation tests. *Open debate:* prompt-design-auditor and opportunity-scout argue for batch `update_todos({updates:[{id, status, note?}]})` instead — preserves stable ids and cuts re-emit token cost. Resolution recommendation: single-tool full-replace per pragmatist-r2-f1, with `maxItems: 6` to bound re-emit cost.
- **Flagged by:** pragmatist, scope-cutter, aegis-fit-auditor, architect (implicit)
- **Agreements:** 4/9
- **Dissents:** prompt-design-auditor (output-token cost, lifecycle clarity) and opportunity-scout (per-item progress prose) prefer the batch variant.

### prompt-rule-rewrite in `Risks > Model discipline (sample copy)` `[CONSENSUS 5/9]`
- **Plan section:** `Risks > Model discipline (sample copy)`
- **Claim:** The proposed system-prompt rule has multiple defects: (1) "≥2 discrete actions" threshold is undefined and contradicts itself ("user-visible workstreams" vs "tool calls" — the canonical Fix flow is 4 tool calls for ONE deliverable); (2) "Don't return prose to the user until the list is fully done" is UX-hostile (60+ second silence on 5-item lists), conflicts with the existing "Be concise" tone rule, and contradicts `announce` operating mode's narration promise; (3) directly conflicts with the just-added "Plan revisions / fan out" rule (parallel vs sequential); (4) no concrete YES/NO examples, no negative-example injection ("WRONG because..."); (5) rule placement under Fix flow (rule 9) mis-files generic orchestration as fix-specific.
- **Suggested patch:** Rewrite as a new rule 10 under a new "Plan" tool category bullet, structured with When/Do-NOT/Lifecycle scaffold mirroring rule 9. Replace silence clause with "Treat the strip as canonical progress indicator — do NOT narrate 'now I'll do step 1' in prose; the strip already shows that. Per item, may emit a short prose result." Replace ambiguous threshold with "≥2 user-visible workstreams ≥30s each." Add 2 positive + 2 negative examples inline. Cross-reference the parallel-revise rule explicitly. Token budget: ≤200 tokens, snapshot-tested.
- **Flagged by:** prompt-design-auditor, ux-walker, skeptic, aegis-fit-auditor, architect
- **Agreements:** 5/9

### step-budget-collision in `Risks (missing section)` `[CONSENSUS 4/9]`
- **Plan section:** `Risks` (concern absent)
- **Claim:** `agent.ts:77` has `stopWhen: stepCountIs(25)`. Plan's `maxItems: 12` × 2 tools (1 set + 12 in_progress + 12 done) = 25 steps exactly — the budget is exhausted by orchestration before any real work fires. Even at maxItems:6 it's 13 telemetry calls vs 12 real-work steps.
- **Suggested patch:** Solved as a side-effect of the single-tool collapse (12 todos × 1 step each = 12 of 25 calls, leaving 13 for actual work). If the two-tool design survives, lower `maxItems` to 6 AND raise `stopWhen` to 40 as belt-and-suspenders. Add to plan §Risks: "Cost & latency" subsection naming the constraint and the chosen mitigation.
- **Flagged by:** aegis-fit-auditor, skeptic, pragmatist, architect
- **Agreements:** 4/9

### MessageBubble-empty-bubble-guard in `Implementation Tasks Task 7` `[CONSENSUS 4/9]`
- **Plan section:** `Implementation Tasks > Task 7 (Suppress in-scroll rendering)`
- **Claim:** Plan says "early-return on `set_todos`/`update_todo` so they don't appear in `ToolCallGroup`." But `MessageBubble.tsx:99-153` always wraps `elements` in a `<div className="px-4 py-2"><div className="mx-auto max-w-3xl space-y-2">{elements}</div></div>` regardless of length. A turn whose parts are ONLY `set_todos`+`update_todo`+`update_todo` (no text, no other tool calls) renders as an empty assistant bubble with padding alone — looks like the agent crashed.
- **Suggested patch:** After `parts.forEach` + `flushTools()`, add `if (!isUser && !error && elements.length === 0) return null;`. Specify suppression order in Task 7: place `if (CHAT_ONLY_TOOLS.has(toolName)) return;` IMMEDIATELY after `toolName` is computed, BEFORE the `request_fix`/`revise_fix` branch (line 116). Add unit fixture in `message-bubble.test.tsx` with parts=`[set_todos, update_todo, update_todo]` asserting no DOM emitted.
- **Flagged by:** aegis-fit-auditor, architect, ux-walker, skeptic
- **Agreements:** 4/9

## P1 — High-Priority Gaps

(Listed by axis; these need to land before `/implement` but don't block design.)

- **framer-motion-not-a-dep** `[CONSENSUS 5/9]` — Verified by architect: zero `framer-motion` imports anywhere; only `tailwindcss-animate` is in `frontend/package.json`. Plan's `motion.div initial/animate/exit` won't compile. Patch: drop framer-motion entirely; use Tailwind `transition-opacity` + `transition-colors`. Lock in plan, don't defer to /implement.
- **latest-message-vs-latest-assistant-message** `[CONSENSUS 4/9]` — `messages[messages.length - 1]` returns the user's reply most often; strip flickers out on every send. Patch: walk backward to most recent `role === 'assistant'` message.
- **stalled-state UI lies** `[CONSENSUS 3/9]` — When `useChat.status !== 'streaming'` and any todo is non-terminal (user hit Stop, model errored, BYOK rate-limited), Loader2 keeps spinning forever. Patch: render those rows muted with Pause icon + caption ('Stopped' / 'Error' / 'Stream ended'). Add header X dismiss affordance (client-only, doesn't mutate parts).
- **tool-result-pairing-on-rehydration** `[CONSENSUS 2/9]` — `parts.ts:48` only emits a UIMessage `dynamic-tool` part when there's a paired `tool-result`. Bare tool-call parts (mid-stream, abort, server crash) silently dropped. Plan's "page refresh restores state" success criterion fails for refresh-during-streaming. Patch: special-case `set_todos` in `buildInitialMessages` to emit even without paired result, OR document the limitation explicitly.
- **message-history-feedback-loop** `[CONSENSUS 3/9]` — Tool-call parts replay into LLM context on subsequent turns. With multi-step turns, that's 25+ tool-call parts of pure UI bookkeeping in context per turn. Patch: filter `set_todos` parts in the stream route's ModelMessage rebuild path. Add backend test asserting prior-turn `set_todos` parts do not appear in `convertToModelMessages` output.
- **suppression-ordering edge case** `[CONSENSUS 2/9]` — If a turn has `[set_todos, update_todo, request_fix(error)]`, the request_fix error path falls through to `toolBuffer.push`. Suppression must happen BEFORE that branch, AFTER `toolName` is computed. Add explicit unit fixture.
- **system-prompt regression test** `[CONSENSUS 2/9]` — `aegis-v3-helpers.test.ts:131` already snapshots prompt content. Plan's "manual streaming inspection" hedge is below the existing test bar. Patch: add `it('includes the multi-step todos rule')` asserting prompt contains `set_todos` and the rule's governing phrase.
- **MessageBubble regression test missing** `[CONSENSUS 2/9]` — Task 7 modifies a high-touch dispatch with no existing `message-bubble.test.tsx`. Patch: add cases per existing branch (request_fix in-flight/resolved/error fallthrough, approve_fix, set_todos suppressed, empty-elements null-return).
- **page-refresh integration test missing** `[CONSENSUS 2/9]` — Headline success criterion is verify-only. Patch: seed an `aegis_chat_messages` row with realistic parts, run through `buildInitialMessages` + `deriveTodos`, assert `Todo[]` matches expected.
- **turn-boundary semantics undefined** `[CONSENSUS 2/9]` — When next turn happens with no own `set_todos`, are old todos retired? Patch: define explicit rule: sticky-across-turns ONLY between user-send and assistant-first-action. Once new assistant turn produces tool calls or text without own `set_todos`, retire prior-turn todos.
- **first-render scroll displacement** `[SOLO 1/9]` — Strip pops in mid-stream and shifts ChatInput downward by ~280px in one frame; user reading message loses their place. Patch: reserve placeholder space on stream-start OR programmatic `scrollIntoView` on first strip-render.
- **id-fabrication silent skip** `[CONSENSUS 2/9]` — Plan acknowledges risk; mitigation is "frontend ignores update_todo with unknown id" (silent skip) AND a prompt rule that gives no instruction on stable id generation. Resolved by single-tool collapse (no ids needed). If two-tool form survives, schema description must say "COPY THE ID VERBATIM from the most recent set_todos" and execute should return `{error}` on unknown id so the model self-corrects.
- **negative-example injection** `[SOLO 1/9]` — Cursor / Claude Code prompts use `<wrong>...</wrong>` blocks with explicit "WRONG because..." rationale; plan's prompt copy is positive-only. Patch: append 2 wrong-usage examples to rule 10.
- **announce-mode contradiction** `[CONSENSUS 2/9]` — `announce` operating mode promises pre-action narration; "don't return prose until done" silently revokes that. Resolved if the silence clause is dropped per prompt-rule-rewrite P0.
- **rule-conflict assertable** `[SOLO 1/9]` — Existing fan-out rule (parallel revise_fix) vs new sequential todos rule. Patch: add `it('multi-step todos rule does not contradict parallel revise_fix rule')` asserting both phrases coexist near each other.
- **dogfood scenarios are happy-path-only** `[CONSENSUS 2/9]` — 5 scenarios all positive paths. None tests model invents id, calls `set_todos` twice, calls `update_todo` without prior `set_todos`, BYOK rate-limit mid-list. Patch: add 4-cell × 4-cell matrix per `test-strategy-r2-f8`. *Disputed* — scope-cutter argues 16-cell matrix is research-project bloat.
- **ChatTodos component test bar too low** `[SOLO 1/9]` — Plan says "optional smoke render" against a project that already has 13 component test files. Patch: required component test covering icon mapping per status, `doneCount/total` header, visibility rule. *Disputed* — scope-cutter dissents (declarative component, no logic to test).
- **performance claim untested** `[SOLO 1/9]` — "<1ms for typical (≤8 todos, ≤30 parts)" asserted not measured. Patch: drop the claim OR add a microbenchmark.

## P2 — Quality Gaps

- **4 unresolved open questions** — Resolve before /implement (framer-motion: drop; tasks-reuse: no reuse; terminal-state visibility: pick one; operating-mode gate: ungated).
- **FixPanel surface-boundary** — Visual recipe match between chat strip and FixPanel's To-dos card creates duplicate-list confusion in the canonical "revise both plans" flow. Patch: define explicit surface boundary copy ('strip = orchestration; panel = inside the open plan'), or visually distinguish the strip's chrome from FixPanel's.
- **false-start noise** — Single-step requests trigger flicker (1-item strip pops in for 200ms then vanishes). Patch: schema `minItems: 2` + minimum-visible-duration 800ms before strip can unmount.
- **a11y not specified** — Strip needs `aria-live='polite'` on header counter only (per-row updates DON'T announce), `role='status'`, `aria-label`.
- **danger:'safe' missing** — Plan omits explicit `danger: 'safe'` per existing convention (`fix.ts:482-488`). Add.
- **Aegis Plan Panel split-screen coexistence** — Recently shipped split-screen mode + new chat strip + identical `FixListBody` recipe = three near-identical lists. Patch: distinct visual treatment OR auto-collapse strip when PlanPanel open.
- **user-visible id leak risk** — Hard rule: ids never user-visible; future tooltip work cannot expose them.
- **token-budget snapshot test** — Plan asserts ~120 tokens; sample copy alone reads ~180. Patch: snapshot test asserting `buildAegisSystemPrompt` output stays under a measured budget.
- **set_todos naming collision with fix-worker tasks** — `aegis_fix_agent` already has durable "tasks/todos" vocabulary. Consider rename to `set_chat_plan` / `set_turn_todos` to disambiguate.
- **maxItems too high** — `maxItems: 12` drives multiple downstream complications (mobile collapse, viewport-eat, step budget). Lower to 6.
- **title injection vector** — Schema has no charset constraint. Mitigated: model produces title (no untrusted input), but strip control chars on render to avoid future surprises.
- **discreteness threshold ambiguity** — Subsumed by prompt-rule rewrite P0 + minItems:2 + minimum-visible-duration.
- **operating-mode prompt conditional** — Subsumed by prompt-rule rewrite P0 (drops silence clause).
- **registry test extension** — Existing `aegis-v3-tools.test.ts:60` has explicit name-list assertions; must include `set_todos` (and `update_todo` if kept).
- **stop-button visual divergence** — Loader2 keeps spinning after user-initiated stop. Subsumed by stalled-state P1.

## P3 — Nits & Opportunities

- **`makeChatTool` helper-factory pattern** — DRYs the two-or-one chat-tool entries.
- **extract MessageBubble's helpers to `aegis-parts.ts`** — Naturally combines with the shape-mismatch fix.
- **history-readability summary chip** — On all-terminal, persist a compact "Plan complete — N/N done" summary into message body so chat history shows what happened.
- **link payload (`link?: {kind, handle}`)** — Optional navigation handle on each todo for jumping to the corresponding fix/finding. *Disputed* — scope-cutter and pragmatist argue v1.1.
- **fix-worker → chat-todo bridge** — Future v1.1 unlock for fix-worker emitting `update_todo` to the chat thread.
- **broaden-prompt-examples** — Add audit/triage/list examples to expand discipline-measurement sample size in dogfood.

## Open Debates (Disputed Findings)

### Single-tool-full-replace vs two-tool-batch-update `[DISPUTED 4 for / 2 against]`
- **For collapse:** pragmatist, scope-cutter, aegis-fit-auditor, architect (implicit) — resolves id fabrication, naming, step budget, prompt complexity, half the tests in one cut.
- **Against collapse:** prompt-design-auditor (full-replace each tick costs more output tokens; lifecycle clarity worse for prompt design), opportunity-scout (full-replace breaks per-item progress prose).
- **Recommendation:** Adopt collapse with `maxItems: 6`. Output-token concern is bounded. Per-item progress prose can be added in v1.1 via an optional `note` field if dogfood demands it.

### Drop Task 9 polish vs keep `Done — N/N` hold `[DISPUTED 2 for / 2 against]`
- **Drop entirely:** scope-cutter, pragmatist — speculative tuning before any user has seen the strip.
- **Keep just the 1.5s hold:** ux-walker, opportunity-scout — completion is the highest-value comprehension event; vanishing instantly destroys the feedback loop.
- **Recommendation:** Keep just the 1.5s `Done — N/N` hold + fade. Drop tooltip-on-hover and explicit truncation (already covered by `truncate min-w-0`).

### Drop `cancelled` status vs keep for redirect `[DISPUTED 2 for / 2 against]`
- **Drop:** pragmatist, scope-cutter — no producer in v1.
- **Keep:** ux-walker, prompt-design-auditor — only honest UX path on mid-flight redirect.
- **Recommendation:** Drop in v1 if single-tool collapse adopted (redirect = re-emit set_todos with shorter list). Keep if two-tool form survives.

### Test bloat vs test coverage `[DISPUTED]`
- **Cut tests:** scope-cutter, pragmatist — most R1 test additions are testing the json-schema library or test-debt-the-touching-PR-pays.
- **Add tests:** test-strategy-auditor — converged regression holes are real (shape-mismatch, MessageBubble dispatch, page-refresh, prompt-snapshot).
- **Recommendation:** Cut json-schema-library schema-acceptance tests and component-render-only tests. KEEP: prompt-snapshot test, MessageBubble regression for empty-bubble + suppression order, derivation 3-shape round-trip, page-refresh integration, registry name-list extension.

### User recovery affordance vs no-user-editing-in-v1 `[DISPUTED 2 for / 4 against]`
- **Yes, dismiss-X header + per-row mark:** ux-walker, skeptic.
- **No user editing:** architect, aegis-fit-auditor, pragmatist, scope-cutter.
- **Recommendation:** Header Dismiss-X (client-only, doesn't mutate `metadata.parts`) is acceptable v1 — purely visibility. Per-row manual edit deferred to v1.1.

## Suggested Plan Amendments

**Apply these inline to `.cursor/plans/aegis-chat-todos.plan.md` before `/implement`.**

### Patch 1 — Lock the design to a single tool with full-replace semantics
**Replaces:** `API Design > New tools` (currently two tools)
**Concern:** Convergent simplification; resolves 4-5 P0/P1s at once.

> ### Single tool: `set_todos`
>
> ```ts
> // jsonSchema
> {
>   type: 'object',
>   required: ['todos'],
>   additionalProperties: false,
>   properties: {
>     todos: {
>       type: 'array',
>       minItems: 2,        // prevents single-step false-start flicker
>       maxItems: 6,        // bounds re-emit cost + step budget
>       items: {
>         type: 'object',
>         required: ['title'],
>         additionalProperties: false,
>         properties: {
>           title: { type: 'string', minLength: 4, maxLength: 120 },
>           status: { type: 'string', enum: ['pending', 'in_progress', 'done'], default: 'pending' },
>         },
>       },
>     },
>   },
> }
> ```
>
> Each call **replaces** the active list. To declare progress, the agent re-calls `set_todos` with the same titles + updated `status` values. No ids — array order = identity within a turn. No `update_todo`, no `cancelled` state, no `reason` field.
>
> ```ts
> // execute
> execute: async () => ({ ok: true })
> ```
>
> Marked `danger: 'safe'`, `audit: false` (see Patch 2).

### Patch 2 — Add `audit?: boolean` to `AegisToolEntry`; respect in `agent.ts`
**Replaces:** "Codebase Analysis > What we're explicitly NOT touching" bullet that claims `aegis_tool_executions` is untouched.

> Add optional `audit?: boolean` (default `true`) to `AegisToolEntry` in `backend/src/lib/aegis-v3/tool-types.ts`. New chat-tool entries set `audit: false`. Update `backend/src/lib/aegis-v3/agent.ts onStepFinish` (around line 93) to skip `saveToolExecution` when `entry.audit === false`.
>
> **Files this feature will touch** must include:
> - `backend/src/lib/aegis-v3/tool-types.ts` — add `audit?: boolean` to interface
> - `backend/src/lib/aegis-v3/agent.ts` — gate `saveToolExecution` call on `entry.audit !== false`
>
> Add to plan §Risks: "`set_todos` does not write to `aegis_tool_executions` (audit:false). Cost-cap and rate-limit counters are unaffected (those track per-turn, not per-tool-call)."

### Patch 3 — Rewrite the Data Model derivation rule against the real shape
**Replaces:** `Data Model > Derivation rule (frontend)`

> The frontend derivation must mirror MessageBubble's existing part adapter. Extract a shared helper module:
>
> ```ts
> // frontend/src/lib/aegis-parts.ts
> export function isToolPart(part: any): boolean {
>   return (
>     part?.type === 'dynamic-tool' ||
>     (typeof part?.type === 'string' && part.type.startsWith('tool-'))
>   );
> }
>
> export function toolNameFor(part: any): string {
>   if (part.toolName) return part.toolName as string;
>   if (typeof part.type === 'string' && part.type.startsWith('tool-')) {
>     return part.type.replace(/^tool-/, '');
>   }
>   return 'tool';
> }
>
> export function toolArgs(part: any): any {
>   return part.args ?? part.input ?? {};
> }
> ```
>
> `MessageBubble.tsx` switches to import from this module in the same PR (kills duplication risk).
>
> ```ts
> // frontend/src/lib/aegis-todos.ts (or inline in ChatTodos.tsx)
> export function deriveTodos(message: UIMessage): Todo[] {
>   const parts = (message as any).parts ?? [];
>   for (let i = parts.length - 1; i >= 0; i--) {
>     if (isToolPart(parts[i]) && toolNameFor(parts[i]) === 'set_todos') {
>       const args = toolArgs(parts[i]);
>       return (args?.todos ?? []).map((t: any) => ({
>         title: t.title,
>         status: t.status ?? 'pending',
>       }));
>     }
>   }
>   return [];
> }
> ```
>
> ChatTodos must read `messages[i]` walking backward from `messages.length - 1` until it finds the most recent message with `role === 'assistant'`. Single-tool full-replace means no merge logic.

### Patch 4 — Rewrite the system-prompt rule
**Replaces:** `Risks > Model discipline (sample copy)`

Add a new bullet to `system-prompt.ts` line 43 list: `- **Plan**: \`set_todos\``. Add a new rule 10 (NOT folded into rule 9):

> **10. Multi-step plans.** When the user requests **≥2 user-visible workstreams** in one turn that take ≥30 seconds each (e.g. "revise both plans", "fix all 3 secrets", "do X then Y"), declare the plan upfront: call `set_todos({todos: [{title}]})` BEFORE your first content-producing tool call. To mark progress, re-call `set_todos` with the same titles plus updated `status` values (`pending` → `in_progress` → `done`). The strip is your progress UI — do NOT narrate "now I'll do step 1" in prose; the strip already shows that. After completing each item, you MAY emit a brief one-line result note (e.g. "Opened PR #42"). For multi-plan revisions, set_todos comes BEFORE the parallel `revise_fix` fan-out, not instead of it.
>
> **YES**: "revise both plans" (2 items). **YES**: "fix CVE-X, CVE-Y, CVE-Z" (3 items).
>
> **NO**: "what's my biggest risk?" (single chained query — rule 7 covers it).
> **NO**: "fix CVE-X" (single deliverable — rule 9 covers it).
>
> **WRONG**: User: "fix this issue". Assistant calls `set_todos(["read file", "draft patch", "open PR"])`. WRONG — these are tool-call subroutines for ONE deliverable.

Token budget: cap at 200 tokens for rule 10 + the tool-list bullet. Snapshot-tested via extension to `aegis-v3-helpers.test.ts:131`.

### Patch 5 — MessageBubble suppression + empty-bubble guard
**Replaces:** `Implementation Tasks Task 7`

> Inside `parts.forEach` in `MessageBubble.tsx`, AFTER `const toolName = toolNameFor(part);` and BEFORE the `request_fix`/`revise_fix` branch (line 116), add:
>
> ```ts
> if (toolName === 'set_todos') return;  // skip iteration; suppression
> ```
>
> AFTER `parts.forEach` + `flushTools()`, add:
>
> ```ts
> if (!isUser && !error && elements.length === 0) return null;
> ```
>
> Add `frontend/src/__tests__/message-bubble.test.tsx` covering: (1) `request_fix` in-flight → `PlanCardSkeleton`; (2) `request_fix` resolved → `PlanCard`; (3) `request_fix` with `output.error` → falls through to `ToolCallGroup`; (4) `approve_fix` resolved → `FixStatusCard`; (5) parts = `[set_todos, set_todos]` only → `null`; (6) parts = `[text, set_todos, request_fix(error)]` → renders text + error pill, no extra chrome.

### Patch 6 — ChatTodos stalled-state + dismiss
**Replaces:** `Frontend Design > <ChatTodos /> spec`

> `<ChatTodos />` accepts `messages: UIMessage[]` and `streaming: boolean` props (latter from `useChat.status === 'streaming'`).
>
> Visibility rule:
> - Walk backward through `messages` to find the most recent `role === 'assistant'` entry. If none, render `null`.
> - Run `deriveTodos` on that message. If `[]`, render `null`.
> - If `streaming` and any todo non-terminal: normal display (Loader2 spinner on in_progress rows).
> - If `!streaming` and any todo non-terminal: render rows muted (Pause icon, `text-foreground/40`, no spin) with header caption "Stream ended" + a header `<X />` Dismiss button (client-only, sets a session-scoped `dismissed` flag for that message id).
> - If all todos terminal: hold strip for 1.5s with `<CheckCircle2 className="text-success"/> Done — N/N`, then fade out.
>
> Layout: sticky above `<SendQueuePanel />` in `ChatPane`'s bottom dock. `max-h-[40vh] overflow-y-auto` on the row list. Use Tailwind `transition-opacity` + `transition-colors` only — no framer-motion (verified not a dependency). a11y: `role="status"` `aria-label="Agent task progress"` on the strip; `aria-live="polite"` on the `Plan N/M` header counter only (per-row updates do not announce).

### Patch 7 — Resolve the four open questions inline
**Replaces:** `Risks & Open Questions > Open questions`

> All four resolved before /implement:
>
> - **framer-motion**: NOT a dependency (verified). Drop entirely; use Tailwind transitions.
> - **terminal-state visibility**: hold 1.5s with `Done — N/N`, then fade.
> - **operating-mode gate**: ungated. Rule 10 applies in all three operating modes; the dropped "no prose" clause removes the announce-mode conflict.
> - **reuse aegis tasks schema**: no reuse. Chat todos do NOT reference fix-worker task ids. If a chat todo represents fix-worker work, the title is human prose only and clicking does nothing in v1.

### Patch 8 — Trim Task 9 to just the Done hold
**Replaces:** `Implementation Tasks Task 9`

> Task 9 (Polish): hold strip 1.5s with `Done — N/N` row before fading on terminal state. Truncate already covered by `truncate min-w-0`. No tooltip, no `reason` field. Defer all other polish to post-dogfood.

### Patch 9 — Cost & latency subsection in Risks
**Adds new bullet to** `Risks & Open Questions > Risks`

> **Cost & latency.** Each `set_todos` call costs one step against `stopWhen: stepCountIs(25)` (`backend/src/lib/aegis-v3/agent.ts:77`). With `maxItems: 6` and full-list-replace semantics, a 6-item plan with 6 progressions = 7 calls, leaving 18 steps for actual work. Per-call output token cost ≈ `set_todos({todos: [...]})` × full list ≈ 200 tokens × 7 calls ≈ 1.4k output tokens of UI bookkeeping per multi-step turn. Acceptable; far cheaper than per-item update_todo round-tripping.

### Patch 10 — Filter set_todos parts from prior-turn ModelMessages
**Adds task to** `Implementation Tasks`

> Task 10 (Backend message-history filter): in the stream route's `convertToModelMessages` path (likely `backend/src/routes/aegis-v3-stream.ts` — grep to confirm), filter out tool-call/tool-result parts whose `toolName` is in `CHAT_ONLY_TOOLS = new Set(['set_todos'])` before sending history to the model. Add backend test asserting prior-turn `set_todos` parts do not appear in the constructed `ModelMessages` array.

### Patch 11 — Test surface
**Replaces:** `Testing & Validation Strategy`

> **Backend tests** (added to existing files, not new files):
> - `backend/src/__tests__/aegis-v3-tools.test.ts` — extend the registry name-list assertion to include `set_todos`. Assert `set_todos` is `safe`, has no `permission` key, has `audit: false`. Schema-validation tests are NOT required (testing the json-schema library, not our code).
> - `backend/src/__tests__/aegis-v3-helpers.test.ts` — add `it('includes the multi-step todos rule')` asserting `buildAegisSystemPrompt` output contains `set_todos`, the rule heading, and at least one of the YES/NO/WRONG examples. Also add token-budget snapshot: prompt output ≤ 4500 chars.
> - New: `backend/src/__tests__/aegis-v3-audit-skip.test.ts` (or extend `agent.ts` test if exists) — assert that a streamed turn with only set_todos calls produces zero `saveToolExecution` calls.
>
> **Frontend tests**:
> - New: `frontend/src/lib/aegis-todos.test.ts` (or `aegis-parts.test.ts`) — 4 cases: empty parts → []; one set_todos → expected list; two consecutive set_todos → last wins; malformed args → [].
> - New: `frontend/src/__tests__/message-bubble.test.tsx` — 6 cases per Patch 5.
> - **Required (not optional)**: `frontend/src/__tests__/aegis-chat-todos.test.tsx` — 4 cases: streaming + non-terminal → Loader2; streaming + terminal → Done pill; ended + non-terminal → stalled muted with Dismiss; ended + terminal + auto-fade after 1.5s.
> - New: `frontend/src/__tests__/aegis-todos-roundtrip.test.ts` — load a real assistant message JSON (one with persisted set_todos parts) into deriveTodos and assert correct Todo[]. The fixture should be captured from a real stream OR hand-crafted to match all three real shapes (live `tool-<name>`/input, persisted `tool-call`/args, rehydrated `dynamic-tool`/input).
>
> **Manual dogfood (kept tight per scope-cutter dissent):**
> 1. Single-step: "fix this CVE" → no strip (negative test).
> 2. Multi-revise: "revise both plans" → 2-item strip → both flip done → 1.5s Done pill → fade.
> 3. Page refresh mid-stream: refresh while `set_todos` is in flight → strip rehydrates correctly OR (if rehydration limitation accepted) appears empty until next assistant message lands.
> 4. Stop mid-list: hit Stop while item 2 is in_progress → strip flips to muted "Stream ended" with Dismiss-X.
> 5. Mid-flight redirect: agent emits 3-item strip; user types "actually skip step 2" → agent re-emits set_todos with shorter list (no `cancelled` ceremony).

### Patch 12 — Optional rename
**Adds (low priority)**

> Consider renaming `set_todos` to `set_chat_plan` to disambiguate from the durable Aegis fix-worker task system (which CLAUDE.md describes as "plan-then-execute with QStash"). The current `set_todos` reads ambiguous in code review. Final call left to user; defer to /implement if unresolved.

## Findings by Axis

| Axis | Count | Highest severity | Personas |
|---|---|---|---|
| shape-mismatch / part-encoding | 6 | P0 | architect, skeptic, test-strategy-auditor, aegis-fit-auditor, pragmatist |
| telemetry / persistence side-effects | 4 | P0 | aegis-fit-auditor, architect, skeptic, pragmatist |
| simplification / scope-cut | 11 | P0 | pragmatist, scope-cutter, aegis-fit-auditor |
| prompt-rule design | 8 | P0 | prompt-design-auditor, ux-walker, skeptic, aegis-fit-auditor |
| step-budget / cost / context | 5 | P0 | aegis-fit-auditor, skeptic, pragmatist, architect |
| MessageBubble dispatch | 4 | P1 | aegis-fit-auditor, architect, skeptic |
| stalled / error UX | 4 | P1 | ux-walker, skeptic, aegis-fit-auditor |
| test surface | 8 | P1 | test-strategy-auditor, scope-cutter (dissents) |
| dependency / package | 2 | P1 | architect, scope-cutter |
| viewport / layout / a11y | 5 | P2 | ux-walker, opportunity-scout |
| open questions / docs hygiene | 3 | P2 | scope-cutter, skeptic |
| polish (cancelled, reason, animation) | 6 | P3 | scope-cutter, pragmatist (dissents from ux-walker) |
| opportunity / observability / nav | 8 | P3 | opportunity-scout |

## Persona Coverage Map

| Persona | R1 findings | R1 clean lenses | R2 +1s given | R2 -1s given | R2 new findings | Vote |
|---|---|---|---|---|---|---|
| skeptic | 10 (1 P0) | 3 | 16 | 5 | 5 (1 P0) | REVISE |
| pragmatist | 8 (0 P0) | 4 | 16 | 17 | 7 (1 P0) | REWORK |
| scope-cutter | 8 (0 P0) | 4 | 14 | 19 | 3 (1 P0) | REWORK |
| architect | 8 (1 P0) | 5 | 4 | 2 | 3 (0 P0) | REVISE |
| test-strategy-auditor | 11 (2 P0) | 4 | 5 | 4 | 6 (0 P0) | REVISE |
| opportunity-scout | 8 (0 P0) | 3 | 5 | 0 | 5 (0 P0) | REVISE |
| prompt-design-auditor | 9 (2 P0) | 6 | 6 | 2 | 5 (1 P0) | REVISE |
| aegis-fit-auditor | 11 (1 P0) | 6 | 5 | 3 | 4 (0 P0) | REWORK |
| ux-walker | 5 (1 P0) | 5 | 8 | 4 | 8 (1 P0) | REWORK |

## Recommended Next Step

**Verdict is REWORK by the strict slash-command rule (≥2 REWORK votes), but the REWORK voters all said the same thing: "rewrite the plan to absorb the converged patches before /implement," not "the design is fundamentally broken." The 5 REVISE voters agreed in spirit but called it an edit pass.**

Concrete next step:

1. **Apply the 12 plan amendments above to `.cursor/plans/aegis-chat-todos.plan.md`** — this absorbs all the P0 patches (shape-normalizer, audit-skip, single-tool collapse, prompt rewrite, MessageBubble guards, dogfood + test surface, four open-question resolutions). Either:
   - **(a)** I can do this — say "apply patches" and I'll edit the plan in-place.
   - **(b)** You apply them manually if you want fine-grained control over the prose.
2. **Re-run `/review-plan aegis-chat-todos --no-debate`** for a quick sanity sweep on the rewrite, OR skip straight to `/implement` if confident the patches landed cleanly.
3. **Do NOT run `/plan-feature` again** — that would discard the converged design work. The problem statement is sound; the plan body just needs the patches inline.

The single-tool-vs-batch debate has a clear majority recommendation (single-tool full-replace) but is the one real design call that's still slightly contested. If you have a strong preference either way, lock it in the rewrite to short-circuit further debate.
