# Flow Code Sandbox

The flow code sandbox runs user-supplied JavaScript inside flow-builder
condition nodes (and, in the future, filter / switch / transform nodes). It's
the same engine that runs legacy `package_policy_code`, `project_status_code`,
and `pr_check_code`, so anything in this doc applies equally to those callers.

The load-bearing promise: **"Save = passes Test = runs at runtime."** The
editor's Test button, the save-time validator, and the runtime evaluator all
go through the same code path against the same sample contexts.

## Threat model

We trust **organization members per RBAC** to write code that's intentionally
benign within the rules below. We do **not** trust the code itself — assume it
will eventually be hostile (typo'd, copied from the internet, or written by a
former employee). At risk:

- Other tenants' data on the same backend process
- Fly machine resources (CPU, memory, file descriptors)
- Outbound network: SSRF to private metadata endpoints (cloud-IMDS, internal services)

The sandbox is the only thing standing between user code and that surface.

## Sandbox engine

[`isolated-vm`](https://github.com/laverdet/isolated-vm) v5+. Each call gets a
fresh `Isolate` hydrated from a process-wide V8 startup snapshot, runs the
user's code, and disposes the isolate in `finally`. **No pooling** — that would
let prototype mutations leak between calls.

Caps:

| Cap | Value | Enforcement |
|---|---|---|
| Heap | 32 MB | `new Isolate({ memoryLimit: 32 })` |
| CPU | 30 s (5 s for validation) | `script.run({ timeout })` |
| Return value size | 256 KB | `JSON.stringify(...).length` check inside the isolate |
| Result copy | 200 ms post-execution | `Promise.race` on `refResult.copy()` |
| `fetch()` calls | 10 per execution | host-side counter |
| `fetch()` per-request timeout | 10 s | `AbortController` |

Co-located in `backend/src/lib/policy-engine.ts` since flow-code and the legacy
policy engine share the engine. The `flow-code/sandbox.ts` wrapper adds
contract validation, error normalization, and structured logging on top —
nothing about isolation lives there.

The snapshot is rebuilt on every process start. Per-call cost stays around
1–3 ms p50 (bench: `1500 calls < 10 s`), so the per-dependency hot path in
extraction is healthy. **Don't pool isolates** to chase more speed — the
state-leak risk dominates.

## What's exposed at runtime

User code can reference:

- **`context`** — the typed event payload. Shape comes from
  `EVENT_SCHEMAS` (in `backend/src/lib/flow-code/event-schemas.ts` and
  `frontend/src/lib/flow-event-schemas.ts`). Sample fixtures for each event
  type live in `backend/src/lib/flow-code/sample-contexts.ts`.
- **Helpers** — top-level identifiers `fetch`, `daysSince`, `isLicenseAllowed`,
  `isLicenseBanned`, `semverGt`, `semverLt`. Inherited from
  `executePolicyFunction`. `fetch` is SSRF-protected (private-IP DNS resolution
  is blocked) and returns `{ ok, status, json(), text() }` synthesized inside
  the isolate from the cached body string.

Explicitly **NOT** exposed:

- `process`, `require`, `import`
- `setTimeout` / `setInterval` (the `daysSince` helper does the wall-clock work host-side)
- `XMLHttpRequest`, `WebSocket`
- `Function` constructor
- `fs`, `net`, `child_process`

If a user references something not in that list, it's `ReferenceError` at
runtime — which the sandbox surfaces as a normal `run`-stage error.

## Adding a new code-capable node type

1. Append to `NODE_CODE_CONTRACTS` in `backend/src/lib/flow-code/contracts.ts`:
   ```ts
   filter: {
     functionName: 'filter',
     paramName: 'context',
     returnTypeTs: 'boolean | null',
     returnTypeCheck: (v) => typeof v === 'boolean' || v === null
       ? true
       : `Filter must return boolean | null, got ${typeof v}`,
     defaultBody: '  return true;',
     exampleBodies: [/* ... */],
   },
   ```
2. Mirror the metadata in `frontend/src/components/flow/flow-code-typedefs.ts`'s
   `NODE_CODE_CONTRACTS` (only `functionName` / `paramName` / `returnTypeTs` —
   the editor doesn't need the runtime-side check).
3. Add a sandbox test in `backend/src/lib/flow-code/__tests__/sandbox.test.ts`
   covering at minimum the happy path + one returnTypeCheck rejection.
4. Wire `mapNodeTypeToContract` in `backend/src/routes/flows.ts` so the
   save-time validator picks up the new node type.

## Adding a new event schema

1. Append to `EVENT_SCHEMAS` in **both**:
   - `frontend/src/lib/flow-event-schemas.ts` (used by the field picker + Monaco autocomplete)
   - `backend/src/lib/flow-code/event-schemas.ts` (used by save-time validation)
2. Author a sample payload in `backend/src/lib/flow-code/sample-contexts.ts`.
   Capture the actual shape — find the `emitEvent('your_type', ...)` call
   site(s) and use real-looking values. The conformance test
   (`sample-contexts.conformance.test.ts`) will fail until every field path
   the schema declares is non-undefined in the sample.
3. The runtime `addExtraLib` in `<FlowCodeEditor>` picks up the change
   automatically; no codegen step.

## What NOT to change without a security review

Touching any of the following is a security-sensitive PR. CC the maintainer
when you open it:

- `executePolicyFunction` in `backend/src/lib/policy-engine.ts` — the per-call
  isolate setup, the snapshot, the helper-Reference wiring, the result-copy
  race
- `isolated-vm` version pin in `backend/package.json`
- The exposed-helpers list (anything new must be SSRF-safe and idempotent —
  not, e.g., a method that writes to disk)
- The 256 KB return-value cap and 200 ms copy timeout
- The fail-closed startup behaviour

## Operations

- **Logs**: every sandbox call emits one JSON line (`flow_code_run`) with
  `contract`, `durationMs`, `ok`, `errorStage`, `source`. Pickable up by Vercel
  logs; query for per-org P95 by joining `organizationId`.
- **Failure modes**:
  - User-code error (parse/run/returnShape/returnSize) → `200` with
    `runOk: false` from the validate-code endpoint, `400` with `errors[]` from
    the save endpoint
  - Sandbox itself crashing → `503` from both endpoints (fail-closed). Operator
    escape hatch: `ALLOW_UNVALIDATED_SAVE=true` env var, logged to activities
- **Monitoring**: P95 latency on `/api/flows/validate-code`; 503 rate; CPU-cap
  hits. The bench in `policy-engine.test.ts` is the canary — if it goes red,
  the extraction pipeline is in trouble.
- **CI checks**:
  - `policy-engine.test.ts` (bench, isolation, caps)
  - `flow-code/__tests__/sandbox.test.ts` (contract + error normalization)
  - `flow-code/__tests__/sample-contexts.conformance.test.ts` (every event
    type has a sample satisfying its schema)

## Why no AI helper

Generate-from-prompt was deferred to v2 (see `flow-code-editor.plan.md` and
`review-flow-code-editor.md` Patch 6b). When it's reintroduced, it must:

- cap `prompt.length <= 2000`
- set `maxOutputTokens: 1024`
- two-tier rate limit (10/user/day + 30/org/day)
- fence-strip + AST guard against prototype mutation in the AI output
- internal validate-code retry-once loop
- log every generated body to activities for audit
