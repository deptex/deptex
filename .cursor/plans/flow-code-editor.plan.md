# Flow Code Editor — Implementation Plan

Worktree: `worktree-flow-builder` (off `origin/main` + cherry-pick `7680b0c` for M1 backend tables).
Parent feature: see `flow_builder_project.md` memory + `.cursor/plans/unified-flow-builder.plan.md`.

> **Revised 2026-04-30** after `/review-plan` (REVISE verdict, see `.cursor/plans/review-flow-code-editor.md`). Key changes from v1: M0 added (install isolated-vm seriously and migrate `executePolicyFunction`); helpers/fetch preserved (parent-plan parity); M5 AI helper deferred to v2; M3 codegen replaced with runtime `addExtraLib`; save-time validation moved server-side; RBAC tightened; visual→code auto-converter cut; per-node-type contract stubs (filter/switch/transform) removed.

## Goal

Build a single, validated, sandboxed code primitive that **every code-capable flow node** uses. The load-bearing promise: **"Save = passes Test = runs at runtime."** The same wrap/parse/sandbox/contract pipeline drives the editor, the Test button, save-time validation, and the eventual runtime engine — one source of truth.

This replaces the legacy per-feature policy editors (`packagePolicy`, `pullRequestCheck`, `projectStatus`) inline with the broader unified flow builder cleanup (M15: drop `package_policy_code`, `project_status_code`, `pr_check_code` tables).

## Locked design decisions (post-review)

1. **Shared primitive now**, not Condition-specific. One `<FlowCodeEditor>` + one `runFlowCode()` wrapper, parameterized per node type. Today's contract registry has **only `condition`** populated (filter/switch/transform contracts added when those nodes get UI; YAGNI).
2. **TS types & autocomplete via Monaco's TS worker**, fed `.d.ts` strings built **at runtime** from `EVENT_SCHEMAS` + contracts (same pattern as existing `PolicyCodeEditor.tsx`). No build-time codegen, no checked-in generated artifact, no CI drift workflow.
3. **AI helper deferred to v2.** This plan ships defaultBody + commented examples in the editor. Generate-from-prompt re-enters when (a) Henry has felt real authoring friction, or (b) a second user lands.
4. **Contributor doc only** (`docs/flow-code-sandbox.md` — threat model + how to add a node type / event). No end-user `/help` doc.
5. **Sandbox engine: real `isolated-vm`** — installed in M0 along with a backend Dockerfile + Fly verification. **`executePolicyFunction` migrates to isolated-vm in the same milestone**, so flow-code and legacy policy-engine share one hardened sandbox. No two-tier threat model.
6. **Type source: runtime build from `flow-event-schemas.ts`** + `NODE_CODE_CONTRACTS`. Frontend imports `EVENT_SCHEMAS` and the contracts mirror, builds a `.d.ts` string per `(nodeType, eventType)` on editor mount, hands to `monaco.languages.typescript.typescriptDefaults.addExtraLib`. Drift impossible by construction.
7. **Test execution: backend round-trip** via `/api/flows/validate-code` (same engine the runtime uses). No browser-side eval.
8. **Helpers: same as legacy** — flow-code inherits whatever `executePolicyFunction` injects: `fetch` (controlledFetch with SSRF / 10-call cap / 10s timeout), `daysSince`, `isLicenseAllowed`, `isLicenseBanned`, `semverGt`, `semverLt`. Matches parent plan's "same SSRF protections, same fetch limits."
9. **Per-node return contracts: only `condition → boolean` today.** No filter/switch/transform stubs (added when those nodes get UI). Contract structure designed to be extensible.
10. **Schema drift: re-validate on save only.** Server-side; runtime is permissive (missing field = `undefined`, code handles or throws).
11. **Visual ↔ Code: independent storage.** `config.mode` decides what runs. Mode switches: Code→Visual shows confirmation dialog ("code will be cleared"); Visual→Code with empty `config.code` seeds with `contract.defaultBody`; with non-empty code, shows "Replace?" prompt. **No automatic visual-to-code converter** (cut per review — operator-mapping table + escape-handling was meaningful new surface area for a workflow nobody asked for).

## Milestones

### M0 — Install isolated-vm + migrate executePolicyFunction (NEW)

**This is foundational platform work, not flow-specific.** Lands the real sandbox the codebase has been claiming.

**Pre-audit results (2026-04-30):** policy-eval frequency audit completed. Verdict: **VERY HOT.**
- `runPackagePolicy` fires **per-dependency** in `evaluateProjectPolicies` at `policy-engine.ts:736` (loop over `projectDeps`). Typical project: 100–500 deps; large monorepos: 1500–3000.
- At 1500 deps × 50ms cold-isolate cost = **~75s added per extraction**, against a current baseline of 2–5 min total. Roughly triples extraction time at the high end. Unacceptable as written.
- `runProjectStatus` (1×/extraction) and `runPRCheck` (1×/PR) are benign — single-call sites, no loop.

**M0 must therefore include snapshot-based isolate reuse** (option 1 from the audit; chosen because batch evaluation requires `Object.prototype`-integrity checks between calls and changes the per-dep call shape, while lazy/async approaches change policy semantics or UX).

**Files / changes:**
- `backend/package.json` — add `isolated-vm@^5.0.x`. Pin in lockfile.
- `backend/Dockerfile` (new) — Node base, `apt-get install -y python3 build-essential` for node-gyp, `npm rebuild isolated-vm` step. Match the Fly app config used by the API.
- `fly.toml` (or equivalent) — verify the API uses the new Dockerfile path; check arm64 vs x86_64 prebuilt support.
- `backend/src/lib/policy-engine.ts` — replace the `new Function()` path with isolated-vm.
  - **Snapshot-warm-restore architecture:** at process startup, build a shared `ivm.Isolate.createSnapshot([{ code: bootstrapScript }])` containing the helper bindings (`fetch`, `daysSince`, `isLicenseAllowed`, `isLicenseBanned`, `semverGt`, `semverLt`) and any frozen prototype seals. Per call: `new ivm.Isolate({ memoryLimit: 32, snapshot: BOOTSTRAP_SNAPSHOT })` → `createContext()` → run user code → dispose in `finally`. Snapshot restore on a 1500-call sweep should land at ~1–2ms per call (vs 30–80ms cold), restoring the extraction-pipeline budget.
  - Helpers re-exposed via `Reference.copy()` / `Reference.applySync()` callbacks defined in the bootstrap script. Helpers themselves are host-side closures; the snapshot only seeds the references.
  - No state-leak concern: each call gets a fresh isolate hydrated from the snapshot. `Object.prototype` mutations from a malicious call die when its isolate disposes.
- Wrap `result.copy()` in `Promise.race` against 200ms; on race-loss, reject and dispose. Inside-isolate `JSON.stringify`-then-slice return cap of 256KB.

**Deploy plan:**
- CI smoke test: import isolated-vm, create an Isolate, run `1 + 1`, assert result. Fail PR if isolated-vm is missing.
- Post-deploy smoke: hit `/api/flows/validate-code` with a known-good payload before declaring deploy healthy.
- Fail-closed at startup: if isolated-vm import throws, refuse to boot. **No `Function()` fallback at any tier — local, dev, or prod.** Windows developers who can't build node-gyp natively run the backend via WSL or the existing `docker compose` dev path. The legacy fallback existed because nobody ever installed isolated-vm; once we install it for real, the fallback has no justification.

**Tests:** `backend/src/lib/__tests__/policy-engine.test.ts` updated to verify:
- Fresh isolate (snapshot-restored) per call — no state leak: `Object.prototype.x = 1` in call N, assert call N+1 doesn't see it
- 1s CPU cap actually preempts `while(true){}` (ms-precision wall-clock assertion)
- 32MB heap cap actually fails on `new Array(1e7).fill(0)`
- Return-value cap (`return new Array(1e7).fill(0)` → fail at `returnSize` stage, host process unaffected)
- Proxy with hostile getters during `result.copy()` doesn't infinite-loop the host (the 200ms post-cap copy timeout)
- Helpers (`fetch`, `daysSince`, etc.) still work end-to-end via snapshot-restored references
- **Snapshot bench:** per-call p50 with snapshot-restore < 5ms; 1500-call sweep total < 10s (matching extraction-pipeline budget). If the snapshot warm-up doesn't deliver this, M0 isn't done — fall back to batch-evaluation (audit option 2) before declaring complete.

**Risk:** native module install on Fly. Mitigated by CI smoke + post-deploy smoke. If it fails, M0 is the right place to find out — better than discovering at M1.

### M1 — Foundation: contracts + sandbox wrapper + sample contexts (backend)

**Files:**
- `backend/src/lib/flow-code/contracts.ts` — `NODE_CODE_CONTRACTS` registry. Today: `condition` only. Per node type: `{ functionName, paramName, returnTypeTs, returnTypeCheck: (val) => true|string, defaultBody, exampleBodies?: string[] }`.
- `backend/src/lib/flow-code/sandbox.ts` — `runFlowCode({ contract, code, context })` wraps the now-isolated-vm `executePolicyFunction(wrappedCode, contract.functionName, context, opts)`. Adds: `contract.returnTypeCheck` on result; error normalization to `FlowCodeError({ stage: 'parse'|'run'|'returnShape'|'returnSize', message, line? })`; structured log line `{ event: 'flow_code_run', orgId?, contract, source, durationMs, ok, errorStage? }` for future diagnostics. **NOT a fresh isolate harness** — thin wrapper.
- `backend/src/lib/flow-code/sample-contexts.ts` — **consolidated** home of canonical event payloads. `notification-validator.ts#SAMPLE_CONTEXTS` re-exports from here during transition.
  - **Audit step (real work, not glossed):** enumerate the 21 event types in `EVENT_SCHEMAS`. For each, find the `emitEvent('<eventType>', ...)` call site(s) and capture the actual payload shape into a sample. Today's `notification-validator.ts` covers 6; the other 15 must be hand-authored. Plan-level acceptance: every event type has a sample whose fields satisfy its schema (conformance test below).

**Tests:** `backend/src/lib/flow-code/__tests__/`
- `sandbox.test.ts` — only the *delta* from policy-engine tests:
  - `condition` contract happy path
  - `returnTypeCheck` adversarial fixtures: `new Boolean(true)` (object wrapper), `Object.create(null, {valueOf:{value:()=>true}})` (coerces but isn't), `Promise.resolve(true)` (async leak), `new Proxy({}, {get:()=>{throw 'x'}})` (breaks JSON.stringify)
  - FlowCodeError stage normalization
  - Helper exposure invariant: argument list contains exactly `context` + the inherited helper set; no surprises.
- `sample-contexts.conformance.test.ts` — for each event type in `EVENT_SCHEMAS`, assert `SAMPLE_CONTEXTS[eventType]` exists and every `field.path` resolves to a non-undefined value matching the declared type.

### M2 — Backend API: `/api/flows/validate-code`

**File:** extend `backend/src/routes/flows.ts`.

**Endpoint:** `POST /api/flows/validate-code`
- Body: `{ flowId, nodeType, eventType, code }`. `flowId` is REQUIRED (RBAC scope).
- Auth: `authenticateUser` + `canManageFlow(orgId, userId, flowType)` (per `routes/flows.ts:44-68`). Anyone who can save a flow can validate code for it; nobody else. **Not org-membership-only.**
- Code length cap: `code.length <= 50_000` (mirrors legacy `validatePolicyCode`). Express body-parser `limit: '64kb'` on this route.
- Rate limit: per-user **in-flight lock** via Redis (max 1 concurrent validate-code per user). Sandbox CPU cap already bounds throughput; an explicit per-minute counter is unnecessary churn. Future ops can revisit.
- Calls `runFlowCode(...)` against `SAMPLE_CONTEXTS[eventType]`.
- **Optional `customContext?: unknown`** in the body — if present, validates against contract type, runs against user-supplied JSON. Ephemeral; not persisted. Powers M4's "Run with my own sample" affordance (small win flagged by opportunity-scout, ~30 LOC).
- **Result caching** (Redis, 5min TTL): key `flow-code-validate:sha256(nodeType|eventType|code)`. On hit, skip sandbox, return cached result with `cached: true`. Doesn't apply to `customContext` path. Cuts save-time validation cost on no-edit nodes to near-zero.
- Response: `{ syntaxOk, runOk, returnValue?, error?: { stage, message, line? }, durationMs, cached?: boolean }`.

**Tests:** `backend/src/routes/__tests__/flows-validate-code.test.ts`
- Happy path per error stage (parse, run, returnShape, returnSize)
- Auth missing → 401; non-flow-manager → 403
- In-flight lock — second concurrent call from same user 429s
- Code length > 50KB → 400
- customContext path
- Cache hit returns `cached: true` and doesn't re-run sandbox
- Cross-org user (in org A, validates against flow in org A — succeeds; against flow in org B — 403 via canManageFlow)

### M3 — Type definitions for Monaco autocomplete (replaces codegen)

**Files:**
- `frontend/src/components/flow/flow-code-typedefs.ts` — exports:
  - `buildEventDts(eventType: string): string` — reads `EVENT_SCHEMAS[eventType].fields`, reassembles dot-paths into nested `interface XContext { ... }` declarations. Detects collisions (leaf vs object at same path; reserved-word leaves) and throws.
  - `buildContractSignature(nodeType: string): string` — reads `NODE_CODE_CONTRACTS[nodeType]`, emits the `function evaluate(context: XContext): boolean` line.

**Wiring:** `<FlowCodeEditor>`'s `useEffect` calls both on mount + when `(nodeType, eventType)` changes; passes the combined string to `monaco.languages.typescript.typescriptDefaults.addExtraLib(dts, 'flow-code-types.d.ts')` (matches `PolicyCodeEditor.tsx:378`'s pattern). Stale extraLib is removed on change to avoid registry bloat.

**Tests:**
- `flow-code-typedefs.test.ts` — `buildEventDts('vulnerability_discovered')` produces a string parseable as TS containing `vulnerability.severity: 'critical' | 'high' | 'medium' | 'low'`; collision fixtures (`foo` leaf vs `foo.bar` object) throw; reserved-word leaves throw.

**Removed vs original M3:** no checked-in generated artifact, no prebuild/predev hook, no dedicated CI workflow, no contracts mirror file, no equality test. Drift impossible by construction.

### M4 — `<FlowCodeEditor>` primitive (frontend)

**Files:**
- `frontend/src/components/flow/FlowCodeEditor.tsx` — the new primitive.
- `frontend/src/lib/code-body-helpers.ts` (new, hoisted) — `extractFunctionBody(code, fnName)`, `wrapBody(body, signature)`. Migrated from `frontend/src/app/pages/PoliciesPage.tsx` so both call sites share one implementation. **Uses `acorn` for AST-based extraction** (regex was vulnerable to misextraction on bodies containing `function` markers in strings/regex literals/comments).
- `frontend/src/components/flow/FlowCodeEditor.test.tsx` — extract/wrap round-trip on adversarial bodies (regex literals, string-literal markers, comment markers); signature pin renders correctly per contract; status-line states; stale-Test (result clears on edit); unmount-during-fetch (no setState warning).

**Component shape:**
```tsx
<FlowCodeEditor
  flowId={flow.id}
  nodeType="condition"
  eventType="vulnerability_discovered"
  value={body}
  onChange={setBody}
  onValidationChange={(v) => …}   // parent stores last { ok, codeHash } per node for save-gate informational use
/>
```

**UI:**
- Pinned signature header (read-only): `function evaluate(context: VulnerabilityDiscoveredContext): boolean {`. Footer: `}`.
- Monaco `language: 'typescript'`. On mount, register `flow-code-typedefs` strings via `addExtraLib`. Cleanup on unmount.
- "Test" button (top-right). Calls `/api/flows/validate-code`. Result panel below editor — return value pretty-printed (or `<RecordTable>` for object returns), or error with line marker.
- Optional "Run with my own sample" collapsible — paste JSON, validates against the contract's input shape, runs ephemerally.
- "Examples" collapsible (replaces the deferred "✨ Generate" button) — shows `contract.exampleBodies` as one-click templates.
- Status line: `✓ Valid (last test passed)` / `✗ Error: <message>` (red). **Two states only**, no "Untested" — staleness is caught at save-gate (M7).
- `CodeEditorSkeleton` while Monaco loads (already shipped).

**Migrate ConditionSidebar:** replace current `<PolicyCodeEditor>` usage. On load, parse stored value with shared `extractFunctionBody` — if already body-only (no `function X(` prefix), use as-is; else extract. Re-save in body-only form going forward. No DB migration.

### ~~M5 — AI helper~~ DEFERRED to v2

Pulled per `/review-plan` 2026-04-30. Track in `flow_builder_project.md` memory. Re-enter when:
- Henry has written 5+ code conditions and felt the friction, OR
- A second user lands.

When re-introduced, the plan should follow Patch 6b in `review-flow-code-editor.md`: cap `prompt.length <= 2000`, `maxOutputTokens: 1024`, two-tier rate limit (10/user/day + 30/org/day, atomic Lua INCR with rolling-window ZSET), increment counter only on success, post-Gemini parse with fence-strip + AST guard against prototype mutation, internal validate-code retry-once loop, RBAC via `canManageFlow`, log all generated code to activities for audit, mirror existing `/policies/ai-assist` SSE pattern.

### M5 — Visual ↔ Code UX (was M6)

**Lives in:** `frontend/src/app/pages/FlowEditorPage.tsx` ConditionSidebar.

- `config.mode: 'visual' | 'code'` (already in place).
- Switch UI stays as the existing Tabs.
- **Visual → Code**: if `config.code` is empty, seed with `contract.defaultBody`. If non-empty, show prompt "Replace existing code?" before overwriting.
- **Code → Visual**: confirmation dialog "Switching to Visual will discard your code. Continue?" before clearing.
- Runtime evaluator reads `config.mode` to pick path.

**Removed vs original M6:** the visual-to-code auto-converter. Operator-mapping table, AST-construction-or-strict-allowlist for value escaping, fuzz tests for injection — all meaningful surface for a workflow Henry isn't actively asking for. If/when needed, it's additive.

### M6 — Save-time validation (was M7, now SERVER-SIDE)

**Lives in:** `backend/src/routes/flows.ts` `PUT /:id`.

- Walk `graph.nodes`. For each `mode === 'code'` node: look up the contract, call `runFlowCode(...)` against the contract's sample context **inline in-process** (no HTTP). On any failure, return `400 { errors: [{ nodeId, stage, message, line? }] }`. No partial saves.
- **Optimistic concurrency:** include `flow.updated_at` (or version int) in the request body; backend returns `409 { error: 'flow_modified_elsewhere' }` if mismatch. Frontend prompts "Flow modified elsewhere; reload?"
- **Failure mode (now specified): fail-CLOSED.** If the inline sandbox throws or times out unexpectedly → `503 { error: 'sandbox_unavailable' }`. Frontend toast: "Validation service unavailable; try again." No save-without-validation path. Owner-role escape hatch via env flag (`ALLOW_UNVALIDATED_SAVE=true`), logged to activities as a security-sensitive event.
- Schema-drift surface: TS types in editor are built from current schema (M3), so referencing a removed field is a TS error → shown in editor → backend re-validation catches it on save.

**Frontend Test button** keeps using `/api/flows/validate-code` for interactive UX (M2). Save and Test now share authoritative server-side logic. No N round-trips on save.

**Tests:** integration test in `backend/src/routes/__tests__/flows-save-validation.test.ts`:
- Multi-node graph, one invalid → 400 with the failing nodeId
- Sandbox throw mocked → 503, no DB write
- Stale `updated_at` → 409
- All-valid → 200, graph persisted
- Schema-drift integration test (`frontend/src/__tests__/flow-code-drift.integration.test.tsx`): add field X to `EVENT_SCHEMAS` → write code referencing X → remove field X → verify save returns 400 with editor TS-error visible.

### M7 — Contributor doc (was M8)

**File:** `docs/flow-code-sandbox.md`

**Sections:**
1. **Threat model** — who we trust (org members per RBAC), what we don't trust (the code they write), what's at risk (other tenants' data, Fly machine resources, outbound network).
2. **Sandbox engine** — `isolated-vm` v5+; fresh isolate per call (no pooling); 1s CPU cap, 32MB heap cap, 256KB return-value cap (enforced inside isolate via JSON.stringify-then-slice); `result.copy()` wrapped in 200ms post-cap timeout. **Co-located with `policy-engine.ts` since both share the engine.**
3. **What's exposed at runtime** — `context` (typed) + helpers (`fetch` SSRF-protected, `daysSince`, `isLicenseAllowed`, `isLicenseBanned`, `semverGt`, `semverLt`) inherited from `executePolicyFunction`. **Not exposed:** `process`, `require`, `import`, `setTimeout` (the wall-clock helper is host-side), `XMLHttpRequest`, `WebSocket`, `Function` constructor, fs, net, child_process.
4. **Adding a new code-capable node type** — append to `NODE_CODE_CONTRACTS`, write `returnTypeCheck`, ship a `defaultBody` and 1-2 `exampleBodies`, add a sandbox test.
5. **Adding a new event schema** — update `flow-event-schemas.ts` AND `flow-code/sample-contexts.ts`. The conformance test will fail otherwise. The runtime `addExtraLib` picks up the change automatically (no codegen step).
6. **What NOT to change without a security review** — sandbox bootstrap (`policy-engine.ts` isolate setup), `isolated-vm` version pin, helper exposure list, return-value cap, the `result.copy()` post-timeout. Any change here is a security-sensitive PR.
7. **Operations** — failure modes (sandbox unavailable → fail-closed save), monitoring (P95 validate-code latency, 503 rate), CI checks (isolated-vm import smoke, sample-contexts conformance, codegen-typedef tests).

Linked from `CLAUDE.md`.

## Build order

Spine first, polish second.

```
M0 (real isolated-vm) → M1 (contracts + wrapper + samples)
                            ↓
                          M2 (validate-code endpoint)
                            ↓
                          M3 (typedef builders)
                            ↓
                          M4 (FlowCodeEditor)
                            ↓
                      ┌─────┴─────┐
                      │ M5  │ M6  │ M7
                      │ UX  │save │doc
                      └─────┴─────┘
                       (parallel)
```

**M0 unblocks everything** — until isolated-vm actually installs on Fly, the rest is theatre. Land M0 first as its own PR; the remaining milestones build on a known-good sandbox.

## Out of scope (don't re-litigate)

- Helpers beyond what `executePolicyFunction` already injects (no new ones in this plan).
- Multi-sample test runner / user-defined assertions.
- Inline AI assistant (explain/fix/completions/ghost-text). Generate-from-prompt is also deferred to v2 (above).
- Two-way visual↔code sync. Visual→code auto-converter cut entirely.
- End-user `/help` doc.
- Code-as-node (a separate "Code" node type with full freedom). Code-MODE inside other nodes only.
- Custom return shapes per flow.
- Pooled isolates / context reuse (state-leak risk).
- AI-generation cost tracking / dashboards (deferred with M5).

## Open questions / known risks

- **isolated-vm install on Fly arm64 vs x86_64 prebuilt support** — verify pre-merge in M0 deploy smoke. If arm64 prebuilts don't ship, fall back to x86_64 machines.
- **Performance regression for legacy policy-engine callers** — *audit confirmed VERY HOT* (`runPackagePolicy` runs per-dep, 100–1500×/extraction). Mitigation now baked into M0: snapshot-warm-restore architecture targeting <5ms p50 per call. Bench gate in M0 tests. If snapshot doesn't hit budget, fall back to batch evaluation before merging.
- **`isolated-vm` CVE history** — pin a minor version, subscribe to GitHub Security Advisories for `laverdet/isolated-vm`, add `npm audit` to CI gate. Document upgrades as security reviews in M7.
- **Return-value size cap** — 256KB inside isolate (JSON.stringify-then-slice). Boolean/small-object contracts never need this much; if a future contract does, lift the cap deliberately.
- **Migration of existing flows** — the few flows already saved with `config.code` containing the full `function evaluate() { ... }` form get parse-tolerantly normalized on load (M4). No DB migration.
- **Migration of legacy policy_code rows** — when M0 lands, existing `package_policy_code` / `pr_check_code` / `project_status_code` rows continue to run via `executePolicyFunction` against isolated-vm. Helpers preserved. Should be a transparent upgrade. Verify with the legacy policy-engine tests.

## Testing strategy

| Layer | What | File |
|---|---|---|
| M0 isolate | Fresh-per-call, CPU cap preempts, heap cap fails, return cap, Proxy hostile-getter post-copy timeout, helpers still work | `backend/src/lib/__tests__/policy-engine.test.ts` |
| M0 deploy | isolated-vm import smoke; post-deploy `/api/flows/validate-code` smoke | CI workflow + Fly deploy step |
| M1 sandbox | Contract returnTypeCheck adversarial (Boolean wrapper, Proxy throw, Promise leak); FlowCodeError stage normalization; helper-exposure invariant | `backend/src/lib/flow-code/__tests__/sandbox.test.ts` |
| M1 samples | Conformance: every event type in EVENT_SCHEMAS has matching SAMPLE_CONTEXTS entry satisfying schema | `backend/src/lib/flow-code/__tests__/sample-contexts.conformance.test.ts` |
| M2 route | Auth, RBAC via canManageFlow, code-length cap, in-flight lock, customContext path, cache hit | `backend/src/routes/__tests__/flows-validate-code.test.ts` |
| M3 typedefs | buildEventDts schema → TS shape; collision detection; reserved-word leaves | `frontend/src/components/flow/__tests__/flow-code-typedefs.test.ts` |
| M4 editor | extract/wrap on adversarial bodies (regex literals, string markers, comment markers); signature pin; status states; stale-test; unmount-during-fetch | `frontend/src/components/flow/__tests__/FlowCodeEditor.test.tsx` |
| M6 save-gate | Multi-node partial-fail; sandbox 503; OCC 409; schema-drift integration | `backend/src/routes/__tests__/flows-save-validation.test.ts` + `frontend/src/__tests__/flow-code-drift.integration.test.tsx` |

Per memory `backend_test_mock_patterns.md`: M2 / save-gate tests use existing `setTableResponse` / `pushTableResponse` helpers (`backend/src/__tests__/helpers/supabase-mock.ts`).

## Out-of-band touchpoints

- `CLAUDE.md` — link `docs/flow-code-sandbox.md`.
- `flow_builder_project.md` memory — add "Flow code editor shipped" entry once M0–M7 land. Track AI helper as deferred follow-up.
- `.cursor/plans/unified-flow-builder.plan.md` — cross-reference this plan as the code-mode chunk; locked decision around `executePolicyFunction` reuse is honored (this plan reuses + hardens it).
- Memory `local_extraction_worker_state.md` (native module deploy concern) — verify M0's isolated-vm install pattern doesn't conflict with extraction-worker's existing native deps.
