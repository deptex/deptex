# Plan Review — flow-code-editor

**Verdict: REWORK** → **RESOLVED via REVISE inline (2026-04-30)**

> **Update 2026-04-30:** Henry chose REVISE inline. All P0 clusters have been resolved in `.cursor/plans/flow-code-editor.plan.md`:
> - **Sandbox engine:** option (B) — install isolated-vm seriously as M0; migrate `executePolicyFunction` to share the engine. The "same engine as legacy" claim is now true after M0 lands.
> - **Fork vs reuse:** M1 sandbox is now a thin wrapper over `executePolicyFunction` (which itself moves to isolated-vm in M0). One sandbox engine.
> - **Helpers/fetch:** preserved per parent-plan parity. Inherited from `executePolicyFunction`.
> - **Save-gate failure mode:** fail-CLOSED with 503; owner-role escape hatch via env flag, logged to activities.
> - **AI token caps + return-value bomb:** AI helper (M5) deferred to v2 entirely; return-value 256KB cap enforced inside isolate via JSON.stringify-then-slice; `result.copy()` wrapped in 200ms post-cap timeout to defeat Proxy-getter host hangs.
>
> P1 patches also applied: codegen replaced with runtime `addExtraLib`; save-validation moved server-side (no N round-trips); RBAC via `canManageFlow`; body extract/wrap helpers hoisted to shared `frontend/src/lib/code-body-helpers.ts` using AST (acorn) not regex; sample-contexts audit step explicit; visual→code auto-converter cut; filter/switch/transform contract stubs removed (YAGNI); per-call in-flight lock replaces 60/min counter; OCC concurrency check added.
>
> The original review below is preserved for the record.

---

Plan reviewed: `.cursor/plans/flow-code-editor.plan.md`
Generated: 2026-04-29
Personas: 9 — skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, failure-mode-hunter, ai-cost-auditor, legacy-drift-detector
Vote tally: **0 READY / 2 REVISE / 7 REWORK**
Findings: **5 P0 clusters / 10 P1 clusters / 6 P2 clusters / 12 P3 opportunities**
Round 2 (debate) skipped to stay within token budget; Round 1 cross-lens consensus + Round 3 vote drove the verdict.

---

## Summary

The plan describes a sandbox + validator + codegen + AI helper for code-mode flow nodes. **Five personas independently caught the same load-bearing factual error**: the plan asserts that `isolated-vm` is "the same engine the legacy policy engine already uses on Fly," but `backend/src/lib/policy-engine.ts` actually uses `new Function()` exclusively — there is no `isolated-vm` import in `backend/`, no entry in `package.json`, no Dockerfile changes wired up. M1's threat-model promises (1s CPU cap, 32MB mem cap, escape-attempt fixtures against `process` / `require` / prototype pollution) are not enforceable on the path that exists today.

Compounding this, the plan **forks** the sandbox abstraction (creates `runFlowCode` as a peer of `executePolicyFunction`) — directly contradicting the parent `unified-flow-builder.plan.md`, which explicitly locks "Reuse the existing executePolicyFunction() sandbox — same SSRF protections, same fetch limits." The new sandbox also drops `fetch` and helpers (`semverGt`, `daysSince`, `isLicenseAllowed`), which is a **silent runtime regression** for any existing flow currently using them, never acknowledged in the plan.

Two more P0s independently flagged: (a) save-gate failure-mode is unspecified — fail-open vs fail-closed on validate-code 5xx; (b) AI generate has no per-call token caps and the sandbox has no return-value cap before `result.copy()`, both of which are unbounded cost / DoS surfaces.

The two REVISE voters (pragmatist, scope-cutter) argued the P0s are patchable in-place by reusing the legacy engine + trimming scope. The seven REWORK voters argued the sandbox engine, fork-vs-reuse, and fetch-helper decisions are foundational enough that the plan needs to be re-grounded against actual codebase reality before milestones are implementable.

**Recommended next step:** revisit the sandbox-reuse story with `/plan-feature` (or directly amend this plan's locked decisions #5, #8 + M1) before `/implement`. The REVISE camp's view is supported here too — once the sandbox decision is grounded, the rest of the plan is mostly editable rather than rewritable.

---

## Vote Tally

| Persona | Vote | Top concern | Rationale |
|---|---|---|---|
| skeptic | REWORK | skeptic-f1 | Foundation-level errors invalidate security posture, scope, and migration story. |
| pragmatist | REVISE | pragmatist-f1 | P0s patchable by reusing legacy engine and trimming M3/M5/M6/M7. |
| scope-cutter | REVISE | scope-cutter-f1 | Multiple P0s fixable with targeted edits; also ~5 deferrable scope items. |
| architect | REWORK | architect-2 | Plan forks sandbox against parent's reuse directive; engine and threat model must be re-grounded. |
| test-strategy-auditor | REWORK | tsa-1 | M1 test strategy built on false premise; needs structural rewrite. |
| opportunity-scout | REWORK | (cluster) | Five personas flagged factual error + four other P0s; architectural premises, not patches. |
| failure-mode-hunter | REWORK | FMH-001 | Three independently-confirmed P0s mean the sandbox design must be redrawn before M1. |
| ai-cost-auditor | REWORK | ai-cost-3 | Unbounded per-call token spend compounds with the isolated-vm error; M1 cost controls unimplementable. |
| legacy-drift-detector | REWORK | drift-2 | Plan silently drops shipped helpers and forks the sandbox — contradicts parent plan. |

---

## P0 — Fundamental Concerns

### Sandbox engine claim is factually wrong `[CONSENSUS 5/9]`

- **Plan section:** Locked decisions #5; M1 (`sandbox.ts`); Open questions ("`isolated-vm` install on Fly"); M8 threat model
- **Claim:** Plan asserts "isolated-vm — same engine the legacy policy engine already uses on Fly." Reality: `backend/src/lib/policy-engine.ts` only uses `new Function()`. No `import 'isolated-vm'` anywhere in `backend/`. No `isolated-vm` in `backend/package.json`. No backend `Dockerfile` exists at all (only extraction-worker has one).
- **Evidence:** policy-engine.ts:1-10 docstring admits "Falls back to a simple Function()-based sandbox when isolated-vm is unavailable." The fallback is the only path that exists. M1's listed escape-attempt fixtures (`process`, `require`, `Object.constructor.constructor("return process")()`, prototype pollution) all SUCCEED against `new Function()` — they are not escape attempts, they are legal reads. The `setTimeout`-based timeout in the legacy code does not preempt synchronous `while(true){}`. The 32MB heap cap is unimplementable inside a host-realm Function.
- **Suggested patch:** Pick one and lock it explicitly:
  - **(A) Actually install isolated-vm:** add `isolated-vm@^5` to `backend/package.json`, write a `backend/Dockerfile` with `apt-get install -y python3 build-essential`, ensure Fly base image supports node-gyp, add a CI smoke test that imports isolated-vm and creates an Isolate, and route `executePolicyFunction` through the same engine (don't have two sandbox tiers in the same backend with different threat models). This is a real M0 milestone, ~2-4 days of platform work.
  - **(B) Drop the isolated-vm framing:** rewrite locked-decision #5 honestly as "Function()-based sandbox via existing `executePolicyFunction`." Replace M8's "Defense: isolated-vm with no globals injected" with the actual posture (`new Function` with shadowed-global gating). Remove the 1s-CPU and 32MB-mem caps from M1; document the realistic posture (best-effort timeout via `setTimeout`, no real heap cap, escape-vector blocking via wrapped scope). This is a plan-edit, half a day.
- **Flagged by:** skeptic, architect, test-strategy-auditor, failure-mode-hunter, legacy-drift-detector
- **Independent confirmations:** skeptic-f1, architect-1, tsa-1, tsa-2, FMH-001 (all citing the same evidence: grep on backend, package.json absence, policy-engine.ts:274-283 the only execution path)

### Plan FORKS the sandbox abstraction against parent plan's explicit reuse directive `[CONSENSUS 3/9]`

- **Plan section:** Locked decision #5; M1 (`backend/src/lib/flow-code/sandbox.ts` as new module); M2 (new validate-code endpoint)
- **Claim:** `unified-flow-builder.plan.md:39` and `:95` explicitly: "Reuse the existing executePolicyFunction() sandbox for the code escape-hatch node — same SSRF protections, same fetch limits. The code escape-hatch node will call executePolicyFunction directly with a synthetic function name." This plan instead creates a parallel `runFlowCode` with its own `FlowCodeError`, its own contracts, its own sample contexts, its own helper policy (none vs SSRF-protected fetch), its own timeout/mem caps. Two sandbox primitives, different threat models, different fetch policies — neither file forces the other to update when one changes.
- **Suggested patch:** M1 `sandbox.ts` becomes a thin wrapper: `runFlowCode({ contract, code, context }) → executePolicyFunction(wrappedCode, contract.functionName, context, opts) → run contract.returnTypeCheck on result → wrap errors as FlowCodeError`. If `executePolicyFunction` doesn't accept `helpers` map or `returnTypeCheck` callback, EXTEND the existing function — don't fork. Sandbox-test surface area drops by half (escape-attempt and cap tests already live with the policy engine).
- **Flagged by:** architect (architect-2), legacy-drift-detector (drift-1), pragmatist (pragmatist-f6)

### `fetch()` and helpers silent runtime regression `[CONSENSUS 2/9]`

- **Plan section:** Locked decision #8 ("Helpers: raw payload only. No `helpers.fetch`."); M8 threat model section "Not exposed: ... `fetch`"; Out-of-scope: "Sandboxed fetch / DB reads — no async, no I/O"
- **Claim:** `policy-engine.ts:285-308` injects `fetch`, `isLicenseAllowed`, `isLicenseBanned`, `semverGt`, `semverLt`, `daysSince` into the sandbox first arg AND as named parameters. `notification-validator.ts:131-136` injects `fetch`. The `PolicyCodeEditor` `.d.ts` (PolicyCodeEditor.tsx:227-235) declares all five helpers as globals + `fetch` on every context. Existing flows on the worktree (per `flow_builder_project.md` memory) and live legacy package-policy / pr-check users may reference these.
- **Evidence:** Parent `unified-flow-builder.plan.md:39, 1620, 1657` repeatedly locks "same SSRF protections, same fetch limits." This plan's "no fetch, no helpers" decision contradicts that without acknowledgment.
- **Suggested patch:** Either:
  - **(A) Preserve helper surface:** inject `fetch` (controlledFetch from `policy-engine.ts:125-170`), `daysSince`, `isLicenseAllowed`, `isLicenseBanned`, `semverGt`, `semverLt`. This is the contract the parent plan locked; ~0 net new code if the sandbox is reused per the previous P0.
  - **(B) Acknowledge the regression explicitly:** add to "Open questions / known risks": "Existing flows / legacy package-policy code using `fetch()`, `daysSince`, `semverGt`, etc. will fail at runtime after M15 cutover. Audit `flows.config.code` and legacy `package_policy_code`/`pr_check_code` rows in DB before merge; manually rewrite the affected rows. Solo pre-launch makes this acceptable, but it must be explicit." The parent plan's `same SSRF, same fetch limits` lock should be amended in the same PR.
- **Flagged by:** legacy-drift-detector (drift-2), skeptic (skeptic-f8)

### Save-gate failure mode unspecified `[SOLO]`

- **Plan section:** M7 — Save-time validation
- **Claim:** Plan says "Before calling api.updateFlow ... call /api/flows/validate-code. If any fail, block save." Silent on what happens when validate-code itself fails (5xx, network timeout, isolated-vm pool exhausted, Redis rate-limit Redis itself unreachable). Two bad outcomes: fail-open (malicious code saved unchecked, breaks "Save = passes Test = runs at runtime" promise) or fail-closed (single Fly machine restart blocks all editing for 30s with no override).
- **Suggested patch:** M7 explicit clause: "On validate-code 4xx → block save with the error. On validate-code 5xx or network timeout → block save (fail-CLOSED) with toast: 'Validation service unavailable; try again. If persists, contact support.' Never save unvalidated code. Add monitoring: P95 validate-code latency, error rate, surfaced in internal status. Owner-role escape hatch via env var, logged to activities as a security event." Add an integration test asserting save blocks on 500.
- **Flagged by:** failure-mode-hunter (FMH-006)

### No AI input/output token caps + return-value memory bomb `[CONSENSUS 2/9]`

- **Plan section:** M5 (AI generate-code) + M1 (sandbox.ts return-value handling) + Open questions ("Return-value size cap: not in spec yet; propose 1MB")
- **Claim — AI side:** M5's `prompt` field has no length cap. Gemini Flash call has no `maxOutputTokens` specified. With the system prompt assembling full event schema descriptions (~1-4k tokens), a malicious or accidental 100k-token user prompt costs ~$0.05-$0.10/call vs the documented ~$0.0001 — daily cap of 30 calls becomes ~$0.30-$3 per malicious org per day. CLAUDE.md cost projection breaks.
- **Claim — sandbox side:** `result.copy()` materializes the isolate's return value in HOST process memory, OUTSIDE the 32MB cap. `return new Array(1e7).fill(0)` builds inside the cap then OOMs the API process on copy. M1 mentions a 1MB cap as a "propose" but doesn't enforce it; M1 fixtures don't include "return-value bomb."
- **Suggested patch:**
  - M5: cap `prompt.length <= 2000` chars at route handler. Pass `maxOutputTokens: 1024` to Gemini. Truncate event schema descriptions if assembled system prompt exceeds 3k tokens.
  - M1: enforce return-value cap BEFORE `result.copy()`. Inside the isolate, run `JSON.stringify(result).slice(0, 256_000)` first; copy only the bounded string. Reject if exceeds 256KB (flow-code returns are booleans/small objects; legitimate use needs no more). Add fixture: `return new Array(1e7).fill(0)` must fail-fast with FlowCodeError stage `returnSize`.
- **Flagged by:** ai-cost-auditor (ai-cost-3), failure-mode-hunter (FMH-003)

---

## P1 — High-Priority Gaps

### Codegen reinvents existing `POLICY_TYPEDEFS` + `addExtraLib` pattern `[CONSENSUS 2/9]`

- **Plan section:** M3
- **Claim:** `frontend/src/components/PolicyCodeEditor.tsx:10-236, :378` already declares `POLICY_TYPEDEFS` as a hand-maintained TS string and registers via `monaco.languages.typescript.javascriptDefaults.addExtraLib(POLICY_TYPEDEFS, 'policy-context.d.ts')`. `NotificationRulesSection.tsx:366` does the same. The plan adds: a tsx prebuild script, checked-in generated artifact, predev/prebuild hooks, dedicated CI workflow, contracts mirror file, frontend-vs-backend equality test — for what the codebase already does with a runtime string constant.
- **Suggested patch:** Replace M3 with `frontend/src/components/flow/flow-code-typedefs.ts` exporting `buildEventDts(eventType): string` (and a contract→signature builder). Call from `<FlowCodeEditor>`'s `useEffect` and pass to `addExtraLib`. Source of truth = `flow-event-schemas.ts` literal directly, no codegen, no checked-in artifact, no equality test, no CI workflow. Drift impossible by construction. If this becomes painful in 6 months, codegen later.
- **Flagged by:** pragmatist (pragmatist-f1), architect (architect-3)

### N round-trips per save `[CONSENSUS 4/9]`

- **Plan section:** M7
- **Claim:** Save runs sequential `/api/flows/validate-code` per code-mode node. 10-node graph = 10 round-trips at p95 ~1.5s each = 15s save latency. With 60/min/user rate limit, save cadence is capped. Server-side validation is the established Deptex pattern (`policy-engine.ts:470-574 validatePolicyCode` runs in-process at write time).
- **Suggested patch:** Move authoritative validation server-side: `PUT /api/flows/:id` walks `graph.nodes`, for each `mode === 'code'` node looks up the contract and calls `runFlowCode` against its sample context inline. Returns `400 { errors: [{nodeId, stage, message}] }` on first failure. Test button keeps the round-trip endpoint for interactive UX, but save is one round trip and authoritatively gated. Side-benefit: client-side validate-code rate limit becomes irrelevant for save.
- **Flagged by:** skeptic (skeptic-f4), pragmatist (pragmatist-f5), architect (architect-7), failure-mode-hunter (FMH-013)

### Adversarial sandbox fixtures under-enumerated `[CONSENSUS 3/9]`

- **Plan section:** M1 testing list
- **Claim:** Listed escape attempts cover only `process`, `require`, `Object.constructor.constructor("return process")()`, prototype pollution. Missing high-impact vectors:
  - Proxy traps run on `result.copy()` AFTER 1s timer cleared (`return new Proxy({}, { get: () => { while(true){} } })` infinite-loops the host outside the timer)
  - `Symbol.toPrimitive` / `Symbol.iterator` throwing during serialization
  - `eval()`, `(()=>{}).constructor('return process')()`, dynamic `import()`, `AsyncFunction`/`GeneratorFunction`
  - ReDoS (`/(a+)+$/.test('a'.repeat(50)+'b')`)
  - Huge-string OOM (`'a'.repeat(2**30)`)
  - `Promise.resolve().then(() => while(true){})` microtask bypass
  - `Error.prepareStackTrace` host-code execution
  - Return-shape adversarial: `new Boolean(true)` (object wrapper, not primitive — does check use `typeof` or instanceof?), `new Proxy({}, {ownKeys: () => { throw }})` breaks JSON.stringify on host
- **Suggested patch:** M1 fixture file `__tests__/fixtures/escape-attempts/*.js` with one file per vector. Each fixture asserts (a) sandbox throws or aborts AND (b) host process is unaffected (post-test `process.memoryUsage` and elapsed wall-clock under thresholds). Wrap `result.copy()` in `Promise.race` against 200ms; on race-loss reject and dispose isolate.
- **Flagged by:** test-strategy-auditor (tsa-3, tsa-4), failure-mode-hunter (FMH-008)

### AI-generated code may break the editor / inject malicious patterns `[CONSENSUS 3/9]`

- **Plan section:** M5
- **Claim:** Plan says "Insert into editor" with no parse step. Gemini emits markdown fences, leading explanations, full function declarations, prototype-mutation code, and references to fields not in `EVENT_SCHEMAS` regularly. No validate-then-retry, no fence-stripping, no AST guard against `Object.prototype`/`Array.prototype` mutation. First time output has fences, editor breaks. First time output mutates a global, the next isolate (if reused) runs corrupted.
- **Suggested patch:** M5 backend: after Gemini returns, (1) strip markdown fences, (2) re-extract via `extractFunctionBody` if a full function is returned, (3) call validate-code against sample context internally before returning to client; on failure retry once with the parse error in the prompt; on second failure return `{ error: 'ai_output_invalid', last_attempt: code }`. AST scan reject `MemberExpression` referencing `prototype`. Log all generated code to activities for audit.
- **Flagged by:** skeptic (skeptic-f7), test-strategy-auditor (tsa-9), failure-mode-hunter (FMH-011)

### `SAMPLE_CONTEXTS` scope undercount + parallel registry drift `[CONSENSUS 4/9]`

- **Plan section:** M1 sample-contexts.ts
- **Claim:** `notification-validator.ts#SAMPLE_CONTEXTS` covers only 6 of 21 event types declared in `EVENT_SCHEMAS`. Filling the gap is 15 hand-authored payloads. The plan says "audit and fill gaps" without acknowledging the scope. Additionally: the new file is created as a parallel registry, not the consolidated home.
- **Suggested patch:** (a) Add explicit M0/M1 audit step: enumerate 21 event types, for each find `emitEvent('<eventType>', ...)` call site, capture actual payload shape. (b) Hoist `SAMPLE_CONTEXTS` to `backend/src/lib/flow-code/sample-contexts.ts` (or shared location); have `notification-validator.ts` import from there during M15 cutover. Single source of sample data. (c) Conformance test asserting every event type in `EVENT_SCHEMAS` has a matching entry whose fields satisfy the schema. Alternative scope-cut: only fill samples for events with shipped triggers; mark others as `NOT_YET_SUPPORTED` sentinel.
- **Flagged by:** skeptic (skeptic-f2), legacy-drift-detector (drift-3), architect (architect-9), scope-cutter (scope-cutter-f3)

### RBAC inconsistency on validate/generate routes `[SOLO]`

- **Plan section:** M2 + M5 ("Auth: authenticateUser + org-membership check (any org member can validate; no special perm).")
- **Claim:** `backend/src/routes/flows.ts:44-68` already wires `canManageFlow(orgId, userId, flowType)` keyed off `permissionsForFlowType(flowType)`. Routes that mutate flows gate on it. The new `validate-code` and `generate-code` routes allow ANY org member to (a) burn the org's daily Gemini quota by hitting /generate-code 30 times, and (b) DoS the sandbox up to 60 reqs/min/user. Aegis enforces `interact_with_aegis`; PR-check editing enforces `manage_policies`. This is an inconsistent posture.
- **Suggested patch:** Reuse `canManageFlow()`. If a user can't manage a flow type, they can't validate or generate code for that type. Read-only members aren't writing code.
- **Flagged by:** architect (architect-8)

### Per-user sub-cap missing on AI quota `[CONSENSUS 2/9]`

- **Plan section:** M5
- **Claim:** Daily cap is org-keyed only. 10-member org → one user can drain 30 calls in <5 min, blocking everyone else. Daily reset (not rolling) → 60-in-2-min around midnight UTC.
- **Suggested patch:** Two-tier cap with atomic Lua INCR+EXPIRE: `flow-code-gen:user:{userId}:{date}` at 10/day AND `flow-code-gen:org:{orgId}:{date}` at 30/day. Distinct error codes (`user_cap_exceeded` vs `org_cap_exceeded`). Optionally use rolling-window Redis sorted set instead of per-day to prevent midnight abuse. Atomic increment fixes the cap-counter race separately flagged.
- **Flagged by:** ai-cost-auditor (ai-cost-1, ai-cost-2), failure-mode-hunter (FMH-005)

### Sandbox isolate fresh vs reused not specified `[SOLO]`

- **Plan section:** M1 (assuming the isolated-vm migration happens)
- **Claim:** Fresh per call → cold-start cost (~30-80ms × 60 calls/min = sandbox-creation-bound). Reused → state leak across tenants (`Object.prototype.toJSON = () => 'pwned'` from user A poisons user B's run).
- **Suggested patch:** M1 explicit: "Fresh `new ivm.Isolate({ memoryLimit: 32 })` and `await isolate.createContext()` per call. Dispose in finally. No pooling." Sandbox unit test: run `Object.prototype.x = 1` in call N and assert call N+1 does NOT see it. If cold-start regresses, document and consider snapshot-based reset.
- **Flagged by:** failure-mode-hunter (FMH-002) — only meaningful if isolated-vm path is chosen

### Native isolated-vm install fragility on Fly `[SOLO]`

- **Plan section:** Open questions
- **Claim:** isolated-vm needs node-gyp; Fly slim images may lack python3 + build-essential. arm64 vs x86_64 prebuilt mismatch risk. Single failed Docker build breaks all flow-related routes, not just flow-code. memory `local_extraction_worker_state.md` flags native modules as a known deploy concern.
- **Suggested patch:** Explicit Dockerfile changes pre-M1 (or as M0). Post-deploy smoke test against `/api/flows/validate-code`. Pin Node version to isolated-vm's prebuilt-binary support matrix. Decide explicitly: keep `Function()` fallback as an env-flagged degraded mode (`ALLOW_FUNCTION_FALLBACK=false` in prod, `=true` in local dev), or fail-closed on missing isolated-vm.
- **Flagged by:** failure-mode-hunter (FMH-017)

### Body extract/wrap helpers reinvented `[CONSENSUS 2/9]`

- **Plan section:** M4 helpers file
- **Claim:** `frontend/src/app/pages/PoliciesPage.tsx` already exports `extractFunctionBody(code, fnName)`, `wrapPackagePolicyBody(body)`, `wrapPrCheckBody(body)`. Plan creates `FlowCodeEditor.helpers.ts` with the same logic.
- **Suggested patch:** Promote `extractFunctionBody` to `frontend/src/lib/code-body-helpers.ts`, parameterize wrap by signature string from contract, call from both PoliciesPage and FlowCodeEditor. Migration is mechanical. Use a real JS parser (acorn) instead of regex to handle adversarial inputs (regex literal containing `function`, comment containing it, nested braces) — both call sites benefit.
- **Flagged by:** architect (architect-6), legacy-drift-detector (drift-5)

---

## P2 — Quality Gaps

- **Visual-to-code converter complexity + injection risk** `[CONSENSUS 2/9]` — naive interpolation enables JS injection via field names/values; nested dot-paths, AND/OR, enum-set membership, regex/semver operators are non-trivial. Use AST construction (acorn) or strict allowlist + JSON.stringify on values + operator allowlist. (skeptic-f6, FMH-012)
- **Filter/Switch/Transform contract stubs YAGNI** `[CONSENSUS 2/9]` — only `condition` ships today; YAGNI applies. (pragmatist-f3, scope-cutter-f4)
- **Visual→code auto-converter cut** `[CONSENSUS 2/9]` — workflow nobody asked for; show `defaultBody` on first switch instead. (pragmatist-f4, scope-cutter-f2)
- **Defer M5 (AI generate)** `[CONSENSUS 2/9]` — solo user pre-launch; autocomplete + non-trivial `defaultBody` per contract covers v1 friction. Reclaim: route, RBAC, Redis quota, popover, tests, Tier 1 spend line. (pragmatist-f2, scope-cutter-f1)
- **Concurrent edit race** `[SOLO]` — two tabs save simultaneously, last-write wins overwrites validated code with unvalidated. Add OCC: `flow.updated_at` in validate + update body, 409 on mismatch. (FMH-007)
- **Code length cap missing** `[SOLO]` — legacy capped at 50KB; new endpoint accepts arbitrary string. Add `code.length <= 50_000` check + Express body-parser limit `64kb` on the route. (FMH-014)
- **Schema-drift integration test missing** `[SOLO]` — plan claims drift "caught here automatically" but no test asserts the cross-layer behavior. Add: add field, write code, remove field, verify save-gate blocks. (tsa-7)
- **Codegen conflict-detection fixtures unspecified** `[SOLO]` — Open questions mentions codegen conflicts; testing strategy doesn't enumerate fixtures. Add: leaf-vs-object collision, array-index path collision, reserved-word leaf. (tsa-8)
- **AI route SSE divergence** `[SOLO]` — existing `/policies/ai-assist` and `/notifications/ai-assist` stream via SSE; this plan returns blob JSON. Mirror the SSE pattern; reuse PolicyAIAssistant shell. (architect-4)
- **Cap counter not atomic** `[SOLO]` — naive GET+INCR is racy. Use `INCR` first then check. (ai-cost-2)
- **No CSRF/origin enforcement on validate/generate** `[SOLO]` — XSS-stolen JWT pivots to AI quota theft + sandbox abuse under legitimate user identity. Origin header check + audit log per call. (FMH-016)
- **Save validation N-roundtrip blocks UI for 30s on large flows** — covered in P1 above. (FMH-013)

---

## P3 — Nits & Opportunities

- **Naming for reuse** — rename `flow-code/` to `code-sandbox/`; `runFlowCode` to `runUserCode`; primitive becomes reusable for Aegis user-defined tools, future Policy v2. (OPP-1)
- **Sandbox audit trail** — emit structured log line `{event:'flow_code_run', orgId, contract, source, durationMs, ok, errorStage?}` from sandbox. Future Flow Diagnostics panel for free. (OPP-2)
- **Codegen `.d.ts` as authenticated download** — `GET /api/flows/code-types.d.ts` for future CLI / VS Code. (OPP-3)
- **"Run with my own sample" affordance** — ephemeral custom context in Test panel; canonical sample stays the contract. (OPP-4)
- **AI generation provenance** — `config.code_meta = { generated_by, prompt, model, ts }` on AI-saved code. (OPP-5)
- **Validate-code result caching** — Redis hash(nodeType+eventType+code) with 5min TTL; save and Test become cheap on no-change. (OPP-7)
- **Result panel as structured table** — for transform contracts; `<RecordTable>` reusable in execution-history later. (OPP-8)
- **Validate-code latency metric** — histogram + counter for cost-shape visibility; structured log line minimum. (OPP-10)
- **AI generation count in `view_ai_spending` dashboard** — close the spend-visibility loop. (OPP-11)
- **Sample-contexts as canonical-events module** — name/structure for future flow E2E test harness. (OPP-12)
- **AA: documentation scope** — pragmatist-f7 + scope-cutter-f7 — reduce M8 to JSDoc + 1 paragraph header comment, defer full docs file to OSS launch prep. `[CONSENSUS 2/9]`
- **BB: rate-limit values picked from thin air** — `[CONSENSUS 3/9]` — replace 60/min counter with per-user in-flight lock OR raise to 300/min OR document the rationale.
- **CC: directory naming** — plan uses `components/flow/` but parent uses `components/flow-editor/`. (architect-11)
- **DD: drop "Untested" status state** — two states is enough for a solo user. (scope-cutter-f9)
- **FF: AI route co-location** — handler should sit alongside other platform-AI routes, not under `routes/flows.ts`. (drift-6)
- **EE: helper-exposure-list invariant test** — assert empty set stays empty so future helper additions can't silently break the doc. (tsa-14)
- **Skeptic-f5 — `addExtraLib` cost not measured** — measure time-to-interactive on slow CPU; if regresses, lazy-load `.d.ts` per active event.

---

## Open Debates (Disputed Findings)

R2 was skipped, so explicit dissents weren't captured. Two votes (pragmatist, scope-cutter) implicitly dissent from the REWORK verdict — they argue the P0s are patchable in revision rather than requiring re-plan. Their position is supported by the patches in this report being concrete and bounded:

- **REWORK camp (7):** the sandbox-engine claim being false invalidates the threat model, the test plan, and the cost story. The fork-vs-reuse decision contradicts the parent plan. These are foundation-level and need to be re-grounded.
- **REVISE camp (2):** patching locked-decision #5 (engine), #8 (helpers), and re-pointing M1 at `executePolicyFunction` is editable. Same for trimming M3/M5/M6/M7. No need to re-interview or re-plan.

**Henry's call:** if you're willing to apply the suggested patches inline and call that a revision, REVISE works. If the sandbox decision needs a real conversation about (A) install isolated-vm seriously vs (B) accept Function-based posture honestly, REWORK is the right framing.

---

## Suggested Plan Amendments (concrete, copy-pasteable)

### Patch 1 — Re-ground locked decision #5 against actual codebase

```markdown
5. **Sandbox engine: REUSE the existing `executePolicyFunction` from `backend/src/lib/policy-engine.ts`.**
   It currently runs via `new Function()` (the legacy "isolated-vm fallback" — there is no isolated-vm dep in backend today; see policy-engine.ts:1-10 docstring + package.json).
   Threat model is therefore: best-effort timeout via `setTimeout`, no real heap cap, escape-vector blocking via shadowed scope. M1 sandbox is a thin wrapper on `executePolicyFunction` adding (a) per-contract `returnTypeCheck`, (b) `FlowCodeError` shape with `stage: 'parse'|'run'|'returnShape'|'returnSize'`.
   *Future work*: migrate `executePolicyFunction` itself to true isolated-vm in a separate `sandbox-hardening` plan — when that lands, flow-code inherits.
```

### Patch 2 — Replace M1 sandbox milestone with reuse-wrapper

```markdown
### M1 — Foundation: contracts + sandbox wrapper + sample contexts (backend)

**Files:**
- `backend/src/lib/flow-code/contracts.ts` — `NODE_CODE_CONTRACTS` registry. Today: ONLY `condition`. Filter/switch/transform contracts added when those nodes get UI (YAGNI).
- `backend/src/lib/flow-code/sandbox.ts` — `runFlowCode({ contract, code, context })` wraps `executePolicyFunction` with: contract-driven `functionName`, returnTypeCheck on result, JSON.stringify-then-slice return-size cap (256KB), error shape normalization to `FlowCodeError`. NOT a fresh isolate harness.
- `backend/src/lib/flow-code/sample-contexts.ts` — consolidated home of event sample payloads. Notification-validator.ts SAMPLE_CONTEXTS imports from here during M15 cutover. Audit step: enumerate the 21 event types in EVENT_SCHEMAS, walk each `emitEvent(...)` call site to capture realistic payloads. Conformance test: every event type has a sample whose fields satisfy the schema.

**Tests** — only the DELTA from policy-engine's existing tests:
- contract.returnTypeCheck pass/fail per contract
- FlowCodeError stage normalization (parse/run/returnShape/returnSize)
- return-size cap (returns Array(1e7) → fail-fast at returnSize stage)
- Helper exposure test: assert only `context` + the inherited helper set is exposed (locked to whatever executePolicyFunction injects today — see Patch 3)
```

### Patch 3 — Acknowledge fetch/helpers, decide explicitly

```markdown
### Locked design decision #8 (REVISED)

8. **Helpers: SAME AS LEGACY** — flow-code inherits whatever `executePolicyFunction` injects today: `fetch` (controlledFetch with SSRF / 10-call cap / 10s timeout), `daysSince`, `isLicenseAllowed`, `isLicenseBanned`, `semverGt`, `semverLt`. This matches the parent plan's "same SSRF protections, same fetch limits" lock.
   *No new helpers added in this plan*; reduction would silently break legacy users mid-cutover.
```

### Patch 4 — Replace M3 codegen with runtime addExtraLib

```markdown
### M3 — Type definitions for Monaco autocomplete (replaces codegen)

**File:** `frontend/src/components/flow/flow-code-typedefs.ts` exports `buildEventDts(eventType: string): string` and `buildContractSignature(nodeType: string): string`. Both read directly from `EVENT_SCHEMAS` and `NODE_CODE_CONTRACTS` (frontend mirror or imported from backend lib).

**Wiring:** `<FlowCodeEditor>`'s `useEffect` calls them on mount + when eventType/nodeType changes; passes string to `monaco.languages.typescript.typescriptDefaults.addExtraLib(dts, 'flow-code-types.d.ts')`. Same pattern as `PolicyCodeEditor.tsx:378`.

**Tests:** unit test that `buildEventDts('vulnerability_discovered')` produces a string parseable as TS that contains `vulnerability.severity: 'critical' | 'high' | …`.

**Removed vs original M3:** no checked-in generated artifact, no prebuild/predev script, no dedicated CI workflow, no contracts mirror file, no equality test, no codegen conflict-detection fixtures. Drift impossible by construction.
```

### Patch 5 — Save-time validation moves server-side

```markdown
### M7 — Save-time validation (REVISED)

**Server-side enforcement.** `PUT /api/flows/:id` walks `graph.nodes`; for each `mode === 'code'` node, calls `runFlowCode` against the contract's sample context inline (in-process, no HTTP). On any failure, returns `400 { errors: [{nodeId, stage, message, line?}] }`. No extra round-trips on save.

**Frontend Test button** keeps using `/api/flows/validate-code` for interactive UX (M2, unchanged surface).

**Failure mode (was unspecified):** if the inline sandbox throws or times out unexpectedly, save fails-CLOSED with `503 { error: 'sandbox_unavailable' }`. Frontend toast: 'Validation service unavailable; try again.' Owner-role escape hatch via env flag, logged to activities.

**Tests:** integration test for partial-fail (some valid, some invalid → first error returned, no DB write), sandbox-timeout (mocked to throw → 503, no DB write).
```

### Patch 6 — AI helper: cap tokens, validate output, defer or harden

Two sub-options; pick one before /implement:

**6a (DEFER M5 to a follow-up):**
```markdown
### M5 — REMOVED in v1
Tracked as a follow-up in `flow_builder_project.md` memory. Re-enter when (a) Henry has written 5+ code conditions and felt the friction, or (b) a second user lands.
Replace the "✨ Generate" button slot in M4 UI with: per-contract `defaultBody` + 2 commented example bodies in a collapsed "Examples" section.
```

**6b (HARDEN M5 in place):**
```markdown
### M5 — AI helper: generate-from-prompt (HARDENED)

Add to backend `POST /api/flows/generate-code`:
- Cap `prompt.length <= 2000` chars (400 if exceeded)
- Pass `maxOutputTokens: 1024` to Gemini Flash
- Truncate event-schema portion of the system prompt at 3KB; warn-log if assembled prompt > 4KB
- Two-tier rate limit: per-user 10/day AND per-org 30/day (atomic Lua INCR+EXPIRE; rolling window via Redis ZSET to defeat midnight reset)
- Increment counter AFTER successful Gemini call, not before (so outages don't burn quota)
- Post-Gemini parse: strip ```js fences, re-extract via `extractFunctionBody` if a full function returned, AST-scan reject `MemberExpression` ending in `prototype`
- Internal validate-code call against sample context before returning to client; on failure retry once with parse error in prompt; on second failure return `{ error: 'ai_output_invalid', last_attempt }`
- Log all generated code (orgId, userId, prompt, output, model, ts) to activities for audit
- RBAC: gate on `canManageFlow(orgId, userId, flowType)` not org-membership

UI: only show button if user has manage perm.
```

### Patch 7 — RBAC fix on validate route

```markdown
### M2 — `/api/flows/validate-code` (RBAC FIX)
Auth: `authenticateUser` + `canManageFlow(orgId, userId, flowType)` (per `routes/flows.ts:44`).
Rationale: validate-code burns sandbox CPU; should match the same RBAC posture as flow save.
(Same applies to M5 generate-code per Patch 6.)
```

---

## Findings by Axis

| Axis | Count | Highest severity | Personas |
|---|---|---|---|
| sandbox-engine-factual-error | 5 | P0 | skeptic, architect, test-strategy, failure-mode, legacy-drift |
| fork-vs-reuse-existing-primitive | 4 | P0 | architect, legacy-drift, pragmatist, scope-cutter |
| silent-regression-helpers/fetch | 2 | P0 | legacy-drift, skeptic |
| failure-mode-unspecified | 1 | P0 | failure-mode |
| ai-cost-uncapped / mem-bomb | 2 | P0 | ai-cost, failure-mode |
| codegen-overengineering | 2 | P1 | pragmatist, architect |
| n-roundtrip-save-gate | 4 | P1 | skeptic, pragmatist, architect, failure-mode |
| under-specified-test-fixtures | 5 | P1 | test-strategy, failure-mode |
| ai-output-not-validated | 3 | P1 | skeptic, test-strategy, failure-mode |
| sample-contexts-undercount | 4 | P1 | skeptic, legacy-drift, architect, scope-cutter |
| rbac-inconsistency | 1 | P1 | architect |
| per-user-subcap-missing | 2 | P1 | ai-cost, failure-mode |
| visual-to-code-injection | 2 | P2 | skeptic, failure-mode |
| premature-flexibility-stubs | 2 | P2 | pragmatist, scope-cutter |
| auto-converter-gold-plate | 2 | P2 | pragmatist, scope-cutter |
| defer-m5-ai-helper | 2 | P2 | pragmatist, scope-cutter |
| platform-leverage-opportunity | 12 | P3 | opportunity-scout |

---

## Persona Coverage Map

| Persona | R1 findings | Clean lenses | R2 | Vote |
|---|---|---|---|---|
| skeptic | 9 (1 P0) | 5 | skipped | REWORK |
| pragmatist | 8 (0 P0) | 6 | skipped | REVISE |
| scope-cutter | 9 (0 P0) | 3 | skipped | REVISE |
| architect | 12 (2 P0) | 6 | skipped | REWORK |
| test-strategy-auditor | 15 (2 P0) | 4 | skipped | REWORK |
| opportunity-scout | 12 (0 P0) | 3 | skipped | REWORK |
| failure-mode-hunter | 17 (2 P0) | 3 | skipped | REWORK |
| ai-cost-auditor | 7 (1 P0) | 6 | skipped | REWORK |
| legacy-drift-detector | 6 (1 P0) | 4 | skipped | REWORK |

Total findings: 95. Round 2 skipped to honor token budget — Round 1 cross-lens consensus on P0 cluster (5 personas independently identifying the same factual error) made the verdict clear without explicit agree/dissent.

---

## Recommended Next Step

**REWORK path** (matches majority verdict):
1. Make the sandbox-engine call explicitly: option (A) install isolated-vm seriously (M0 milestone, Dockerfile + native deps + CI smoke + migrating `executePolicyFunction` itself); or option (B) drop the isolated-vm framing and reuse `executePolicyFunction` honestly. Patch 1+2 in this report cover (B).
2. Reconcile with parent `unified-flow-builder.plan.md`: fork vs reuse must be ONE answer. If reusing, apply Patch 2 (sandbox.ts as wrapper, not peer).
3. Address the helpers/fetch regression: apply Patch 3 (preserve helpers) or document the regression explicitly.
4. Specify save-gate failure mode: apply Patch 5 (server-side, fail-closed).
5. Cap AI inputs/outputs and the return-value bomb: apply Patch 6 (defer or harden).

Once (1)-(5) are decided, the remaining P1s (codegen overengineering, RBAC, sample-contexts scope, missing fixtures) are inline edits to the plan, not re-architecture.

**Alternative REVISE path** (if you trust the patches enough to commit them inline without re-planning): apply Patches 1-7 directly to `flow-code-editor.plan.md` and proceed to `/implement`. The two REVISE voters (pragmatist, scope-cutter) believe this works.

Either way, do NOT proceed to `/implement` against the plan as currently written.
