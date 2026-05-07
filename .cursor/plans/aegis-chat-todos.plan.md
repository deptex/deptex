# Aegis Chat Todos — Implementation Plan

## Overview

Add a Cursor-style AI-managed todo list to the Aegis chat surface. When the user issues a multi-step request ("revise both plans", "fix these 5 issues", "do X then Y"), Aegis declares an explicit todo list at the start of the turn, marks each item in_progress / done as it works, and a sticky strip above the chat input shows the user what's pending. Persistence rides on the existing assistant message metadata (`metadata.parts`) — no new DB table — so the list survives page refresh and is scoped per-thread.

This replaces today's behavior where the agent improvises structure with chatty self-narration ("let me try with a general instruction first…"). The todos surface gives the agent *and* the user a shared, visible plan.

## Competitive Research & Design Rationale

The pattern is well-established. Reference points:

- **Cursor (AI agent panel)** — explicit `todo_write` tool produces a checkbox list that updates live. The agent is instructed to keep the list current and not stop until items are checked. This is the closest analogue to what we're building.
- **Manus / Devin** — similar pattern: a "thinking" / "plan" panel separate from the message stream that the agent drives via tool calls.
- **Claude Code itself** — exposes `TaskCreate` / `TaskUpdate` / `TaskList` to subagents. Same shape: agent owns the list; user observes.
- **GitHub Copilot Workspace** — structured "spec → plan → implementation" steps. More heavyweight; not the right fit for a chat turn.
- **Linear / Notion AI** — task creation is *output*, not orchestration. Different problem.

**What we adopt:**
- Single-tool full-replace: agent calls `set_todos` to declare the plan AND to update statuses (re-emit with same titles + new `status` values). Cursor's `todo_write` and Claude Code's `TodoWrite` both ship this exact pattern.
- Sticky placement above the composer (Cursor's location).
- Per-turn replacement semantics: latest `set_todos` wins.
- AI-managed only — header Dismiss-X is the only user affordance in v1 (Cursor v1 was the same).

**Where we differ:**
- Persistence by riding on AI SDK `metadata.parts` rather than a separate `todos` array on the message. This means zero new schema, and the same store/realtime path the rest of the chat already uses.
- Scoped strictly to one assistant turn. We don't roll up across turns; each new user message implicitly retires the old list (the agent's next turn either calls `set_todos` again or doesn't show the strip).

**Why not the heavier `aegis_tool_executions` / QStash plan-then-execute path:** that's for durable, recoverable, possibly-cross-thread work (the existing fix-worker queue). Chat todos are ephemeral progress chrome, not durable workflows. Mixing concerns adds DB pressure and migration churn for no user-visible benefit.

## Codebase Analysis

### Existing patterns to follow

- **Aegis tool registration** — every tool is an `AegisToolEntry` exported as part of a category bundle in `backend/src/lib/aegis-v3/tools/<category>.ts`, then aggregated in `backend/src/lib/aegis-v3/tools/index.ts`. We add a new `chat.ts` and import the bundle.
- **Tool shape** — `{ name, description, inputSchema (jsonSchema), permission?, danger?, audit?, execute }`. See `backend/src/lib/aegis-v3/tools/fix.ts` lines 72+ (`requestFix`, `reviseFix`) and `fix.ts:482-488` (the `danger: 'safe'` precedent) for canonical examples. The new `set_todos` tool is `safe` / no permission gate / `audit: false` (it doesn't mutate user data and shouldn't pollute telemetry).
- **`AegisToolEntry` extension** — the `audit?: boolean` field is **new**; gated in `agent.ts onStepFinish` so chat-only tools opt out of `aegis_tool_executions` rows.
- **Tool context** — `execute({input}, ctx)` receives `{ orgId, userId, threadId, operatingMode, supabase }`. The new tool uses none of these (parts persist via the AI SDK message store automatically).
- **System prompt** — `backend/src/lib/aegis-v3/system-prompt.ts`. Add a new rule **10** (NOT folded into rule 9, which is fix-flow-specific) governing when to call `set_todos`.
- **Tool list line in prompt** — line 43 lists tools per category. Add a new "Plan" category bullet for `set_todos`.

### Frontend patterns

- **Message rendering** — `frontend/src/components/aegis/MessageBubble.tsx` walks `parts`, dispatches each part type to a renderer. Tool calls fall through to `ToolCallGroup` unless they have a special-case (request_fix → PlanCard, approve_fix → FixStatusCard). `set_todos` should NOT render a tool-call bubble in the message scroll — it only affects the sticky strip. We add a suppression early-return in MessageBubble (placement matters — see Task 8 — must be AFTER `toolName` is computed, BEFORE the `request_fix` branch). We also add an empty-bubble guard since a turn whose parts are only `set_todos` would otherwise render as an empty padded bubble.
- **Part-shape helpers** — `MessageBubble.tsx:34-47` already has inline `isToolPart` + `toolNameFor` helpers that handle the three real part shapes (live `tool-<name>` / persisted `tool-call` / rehydrated `dynamic-tool`). We extract these to `frontend/src/lib/aegis-parts.ts` so the new `deriveTodos` helper consumes the same abstraction (preventing the silent-render-nothing bug class).
- **Composer placement** — `frontend/src/components/aegis/ChatPane.tsx` lines 617–633 wraps the composer in `<div className="px-4 pb-4"><div className="mx-auto max-w-3xl">…<SendQueuePanel/>…<ChatInput/>…</div></div>`. The new `<ChatTodos />` slots in the same `mx-auto max-w-3xl` column, just above `<SendQueuePanel />`.
- **Existing sibling — `SendQueuePanel`** — same shape we're building (sticky strip above composer that conditionally renders). Use it as the visual / structural template.
- **Message store** — Vercel AI SDK `useChat` provides `messages`. We derive todos from the *last* assistant message's `parts` array. No new fetch path, no new realtime subscription.
- **Lucide icons** — already used heavily; `Circle` (pending), `Loader2` (in_progress, animate-spin), `CheckCircle2` (done), `Pause` (stalled), `X` (header dismiss).

### Files this feature will touch

**Backend (new):**
- `backend/src/lib/aegis-v3/tools/chat.ts` — new file containing the single `setTodos` entry.

**Backend (modified):**
- `backend/src/lib/aegis-v3/tools/index.ts` — add `chatTools` import + spread.
- `backend/src/lib/aegis-v3/system-prompt.ts` — add the todos rule, list new tool.
- `backend/src/lib/aegis-v3/tool-types.ts` — add `audit?: boolean` to `AegisToolEntry` interface.
- `backend/src/lib/aegis-v3/agent.ts` — gate the `saveToolExecution` call in `onStepFinish` (around line 93) on `entry.audit !== false` so chat-only tools opt out of telemetry rows.
- `backend/src/routes/aegis-v3-stream.ts` (path TBD; grep for the route that calls `convertToModelMessages`) — filter `set_todos` parts from prior-turn ModelMessages before they replay into LLM context. See Task 10.

**Frontend (new):**
- `frontend/src/components/aegis/ChatTodos.tsx` — sticky strip component.
- `frontend/src/lib/aegis-parts.ts` — shared part-shape helper (`isToolPart`, `toolNameFor`, `toolArgs`) consumed by ChatTodos derivation **and** MessageBubble. Eliminates duplication risk between the new derivation and the existing tool-call dispatcher.
- `frontend/src/lib/aegis-todos.ts` — pure `deriveTodos` helper that walks message parts via `aegis-parts.ts` and returns the current todos state.

**Frontend (modified):**
- `frontend/src/components/aegis/ChatPane.tsx` — render `<ChatTodos messages={messages} streaming={status === 'streaming'} />` above `<SendQueuePanel />`.
- `frontend/src/components/aegis/MessageBubble.tsx` — switch part-shape inspection to `aegis-parts.ts` helpers; suppress `set_todos` from in-scroll rendering; add empty-bubble guard.

### What we're explicitly NOT touching

- No new DB migration (parts are stored in `aegis_chat_messages.metadata` already).
- No new HTTP endpoint (tools ride the existing `/api/aegis/v2/stream` path).
- No realtime subscription change (AI SDK message store already updates).
- No changes to the durable task system in `lib/aegis/` (the QStash plan-then-execute path).

**Note on `aegis_tool_executions`:** the `set_todos` tool deliberately opts out of the telemetry write performed in `agent.ts onStepFinish` (via the new `audit: false` flag — see Patch 2 / Task 1). Cost-cap and rate-limit counters are unaffected since those track per-turn, not per-tool-call.

## Data Model

**No new tables.** State lives in the existing `aegis_chat_messages.metadata.parts` JSONB array.

### Part shapes the agent emits

The single tool produces parts in three real runtime shapes — the derivation must handle all three. Verified file:line references:

| Where | Shape | Source |
|---|---|---|
| Live AI SDK `useChat` stream (in flight) | `{ type: 'tool-set_todos', input, output, state }` | Vercel AI SDK v5 UIMessage convention |
| Persisted in `aegis_chat_messages.metadata.parts` | `{ type: 'tool-call', toolName: 'set_todos', args, toolCallId }` | `backend/src/lib/aegis-v3/parts.ts:41-46` |
| Rehydrated UIMessage going into MessageBubble | `{ type: 'dynamic-tool', toolName: 'set_todos', input, output }` | `frontend/src/components/aegis/ChatPane.tsx:88-130` |

`MessageBubble.tsx:34-47` already abstracts these via `isToolPart` / `toolNameFor`. The derivation **must** read through the same abstraction to avoid silent render-nothing bugs (which is what the previous plan's algorithm did — it only matched the persisted shape).

### Shared part-shape helper

Extract a single shared helper module that both ChatTodos derivation and MessageBubble use. This kills the duplication risk between the new code path and the existing dispatcher.

```ts
// frontend/src/lib/aegis-parts.ts
export function isToolPart(part: any): boolean {
  return (
    part?.type === 'dynamic-tool' ||
    (typeof part?.type === 'string' && part.type.startsWith('tool-'))
  );
}

export function toolNameFor(part: any): string {
  if (part?.toolName) return part.toolName as string;
  if (typeof part?.type === 'string' && part.type.startsWith('tool-')) {
    return part.type.replace(/^tool-/, '');
  }
  return 'tool';
}

export function toolArgs(part: any): any {
  return part?.args ?? part?.input ?? {};
}
```

`MessageBubble.tsx` switches to import these from `aegis-parts.ts` in the same PR (replacing its current inline copies at lines 34-47).

### Derivation rule (frontend)

Single-tool full-replace semantics make the derivation trivial: walk backward, take the most recent `set_todos`, return its todos.

```ts
// frontend/src/lib/aegis-todos.ts
import { isToolPart, toolNameFor, toolArgs } from './aegis-parts';

export type TodoStatus = 'pending' | 'in_progress' | 'done';
export type Todo = { title: string; status: TodoStatus };

export function deriveTodos(message: UIMessage): Todo[] {
  const parts = (message as any).parts ?? [];
  for (let i = parts.length - 1; i >= 0; i--) {
    if (isToolPart(parts[i]) && toolNameFor(parts[i]) === 'set_todos') {
      const args = toolArgs(parts[i]);
      return (args?.todos ?? []).map((t: any) => ({
        title: t.title,
        status: t.status ?? 'pending',
      }));
    }
  }
  return [];
}
```

**Latest-assistant-message rule:** ChatTodos must walk `messages` backward from `messages.length - 1` until it finds the most recent entry with `role === 'assistant'`. Reading `messages[messages.length - 1]` directly returns the user's reply most often during streaming and would flicker the strip out on every send.

**Turn-boundary semantics:** todos are sticky-across-turns ONLY between user-send and assistant-first-action. Once a new assistant turn produces tool calls or text without its own `set_todos`, prior-turn todos are retired (the derivation walks back to the most recent assistant message, which won't contain them).

**Visibility rule:** strip renders when the latest assistant message has ≥1 todo. Visual treatment for terminal/stalled states is in the `<ChatTodos />` spec under Frontend Design.

**Rehydration limitation (documented):** `parts.ts:48` only emits a UIMessage `dynamic-tool` part when there's a paired `tool-result`. If the user refreshes the page mid-stream while `set_todos` is in flight, the bare tool-call has no paired result and is silently dropped on rehydration — the strip will appear empty until the next assistant message lands. This is acceptable for v1; documenting it explicitly so dogfood scenario 3 verifies behavior, not regression.

## API Design

**No new HTTP endpoints.** A single tool is registered into the existing Vercel AI SDK toolset and served via `POST /api/aegis/v2/stream` (already auth'd via `authenticateUser`).

### Single tool: `set_todos`

| Tool | Inputs | Output | Permission | Danger | Audit |
|---|---|---|---|---|---|
| `set_todos` | `{ todos: [{ title, status? }] }` | `{ ok: true }` | none | `safe` | `false` (opts out of `aegis_tool_executions` row) |

**Full-replace semantics.** Each call replaces the active list entirely. To declare progress, the agent re-calls `set_todos` with the same titles plus updated `status` values (`pending` → `in_progress` → `done`). No ids — array order is identity within a turn. This collapses what the previous draft modeled as two tools (`set_todos` + `update_todo`) into one, which:

- Eliminates the id-fabrication risk (model can't invent ids when there are no ids).
- Prevents the naming-asymmetry confusion (plural `set_todos` vs singular `update_todo`).
- Resolves the step-budget collision against `agent.ts:77`'s `stepCountIs(25)` cap (see Risks > Cost & latency).
- Cuts ~6 of 8 originally-planned derivation tests.
- Removes the `cancelled` state (mid-flight redirect = re-emit `set_todos` with shorter list).
- Removes the `reason` field (not a v1 surface).

This is the same pattern Cursor's `todo_write` and Claude Code's `TodoWrite` both ship.

### Input schema (jsonSchema)

```ts
{
  type: 'object',
  required: ['todos'],
  additionalProperties: false,
  properties: {
    todos: {
      type: 'array',
      minItems: 2,        // prevents single-step false-start flicker
      maxItems: 6,        // bounds re-emit cost + step budget
      items: {
        type: 'object',
        required: ['title'],
        additionalProperties: false,
        properties: {
          title: {
            type: 'string',
            minLength: 4,
            maxLength: 120,
            description: 'One-line user-visible title for this workstream.',
          },
          status: {
            type: 'string',
            enum: ['pending', 'in_progress', 'done'],
            default: 'pending',
            description: 'Current state. Omit on initial call (defaults to pending). Re-call set_todos with updated status values to declare progress.',
          },
        },
      },
    },
  },
}
```

### Server-side execute

```ts
execute: async () => ({ ok: true })
```

The *args* carry the state; persistence is automatic via the AI SDK message store. No cross-call validation needed (no ids to validate). The frontend's derivation always reads the most-recent `set_todos` part — earlier ones are naturally superseded.

The `AegisToolEntry` is marked `danger: 'safe'`, no `permission` key, and `audit: false` (see Patch 2 — this requires a new optional `audit` flag on the `AegisToolEntry` type, gated in `agent.ts onStepFinish` so chat-only tools don't pollute `aegis_tool_executions`).

## Frontend Design

### Component tree

```
ChatPane (existing)
└── streaming view
    ├── messages scroll (existing)
    └── bottom dock (existing px-4 pb-4 mx-auto max-w-3xl)
        ├── ChatTodos          ← NEW
        ├── SendQueuePanel     (existing)
        └── ChatInput          (existing)
```

### `<ChatTodos />` spec

**Props:** `{ messages: UIMessage[]; streaming: boolean }` — `streaming` plumbed in from `useChat.status === 'streaming'` in `ChatPane`.

**Visibility / state machine:**

1. Walk `messages` backward to find the most recent `role === 'assistant'` entry. If none, render `null`.
2. Run `deriveTodos` on that message. If `[]`, render `null`.
3. If component-internal `dismissed[messageId] === true`, render `null` (header X-button toggles this in session-scoped state; doesn't mutate `metadata.parts`).
4. Otherwise render a panel above `<SendQueuePanel />`. Row treatment depends on `(streaming, anyNonTerminal)`:

| `streaming` | any non-terminal | Treatment |
|---|---|---|
| true | true | Active: rows render with status icon below; `Loader2` spins on `in_progress` rows |
| true | false | Holding: all `done` rows + `<CheckCircle2 className="text-success"/> Done — N/N` header pill, hold for 1.5s, then fade out |
| false | true | Stalled: rows muted (`text-foreground/40`), `Pause` icon replaces Loader2 on non-terminal rows, header caption "Stream ended" + a header `<X />` Dismiss button (client-only) |
| false | false | Same as (true, false): hold 1.5s with Done pill, then fade |

**Markup skeleton:**

```tsx
<div
  role="status"
  aria-label="Agent task progress"
  className="mb-2 rounded-md border border-border bg-background-subtle/30 px-4 py-3 transition-opacity"
>
  <div className="flex items-center gap-1.5 mb-2 text-xs font-medium text-foreground-secondary">
    <ListChecks className="h-3.5 w-3.5" />
    <span aria-live="polite">Plan {doneCount}/{total}</span>
    {showDismiss && (
      <button onClick={onDismiss} className="ml-auto" aria-label="Dismiss plan">
        <X className="h-3.5 w-3.5" />
      </button>
    )}
  </div>
  <ul className="space-y-1.5 max-h-[40vh] overflow-y-auto">
    {todos.map((t, idx) => <TodoRow key={idx} todo={t} muted={isStalled} />)}
  </ul>
</div>
```

**`<TodoRow />` per-status:**

| Status | Icon (active) | Icon (stalled) | Title style |
|---|---|---|---|
| pending | `Circle` h-3.5 w-3.5 text-foreground/40 | `Pause` h-3.5 w-3.5 text-foreground/40 | text-foreground-secondary |
| in_progress | `Loader2` h-3.5 w-3.5 animate-spin text-foreground | `Pause` h-3.5 w-3.5 text-foreground/40 | text-foreground (or muted in stalled) |
| done | `CheckCircle2` h-3.5 w-3.5 text-success | `CheckCircle2` h-3.5 w-3.5 text-success/60 | text-foreground-secondary |

Visual recipe matches `FixListBody`'s "To-dos" / "Verification" cards in `FixPanel.tsx` lines 372–432. To prevent duplicate-list confusion when both surfaces are visible (chat strip + open Plan Panel), the strip's chrome stays distinct enough — strip lives in the bottom dock, panel cards live in the right rail. If dogfood reveals confusion, the polish pass can auto-collapse the strip when PlanPanel is open (deferred to v1.1).

**Animation:** Tailwind `transition-opacity` + `transition-colors` only. **No `framer-motion`** — verified not in `frontend/package.json` (only `tailwindcss-animate` is present).

**Layout:** inherits `mx-auto max-w-3xl` from the bottom dock. `max-h-[40vh] overflow-y-auto` on the row list to bound viewport eat. Long titles `truncate min-w-0`.

**a11y:** strip wrapper has `role="status"` and `aria-label="Agent task progress"`. Only the header counter has `aria-live="polite"` — per-row updates do NOT announce (would otherwise spam SR users with N updates per turn).

### Routing / state management

- No new routes.
- No new context. `messages` already flow through `ChatPane` via `useChat`.
- `<ChatTodos />` is a pure derived component — no internal state.

### Loading / empty / error states

- No loading state — todos appear/disappear with the message stream.
- Empty state — render `null`. The strip is purely additive.
- Error state — if a malformed `set_todos` slips through, `deriveTodos` returns `[]`, no crash.

### Layout, responsive

- Inherits `mx-auto max-w-3xl` from the bottom dock.
- On mobile, same layout; rows truncate with `truncate min-w-0 flex-1`.

### Performance

- Derivation is O(parts) once per render. Parts arrays are bounded (< ~50 items per turn). Negligible.
- No memoization needed in v1; if profiling shows churn during streaming, wrap in `useMemo` keyed on the last message's parts length.

## Implementation Tasks

Each task is independently testable. Complexity in parens.

1. **(S) Backend — `audit?: boolean` on `AegisToolEntry` + gate in `agent.ts`.**
   - Modify: `backend/src/lib/aegis-v3/tool-types.ts` — add optional `audit?: boolean` (default `true` semantically) to the `AegisToolEntry` interface.
   - Modify: `backend/src/lib/aegis-v3/agent.ts onStepFinish` (around line 93) — look up the entry by tool name and skip the `saveToolExecution` call when `entry.audit === false`.
   - Acceptance: types compile; existing tools still write telemetry rows; backend test asserts `set_todos` produces zero `aegis_tool_executions` rows for a streamed turn.

2. **(S) Backend — define the `set_todos` tool.**
   - New file: `backend/src/lib/aegis-v3/tools/chat.ts` exporting `chatTools: AegisToolEntry[]`. Single entry: `set_todos` with `danger: 'safe'`, no `permission`, `audit: false`, `execute: async () => ({ ok: true })`.
   - Acceptance: types compile; entry passes registry shape checks.

3. **(S) Backend — register the tool.**
   - Modify: `backend/src/lib/aegis-v3/tools/index.ts` — import `chatTools`, spread into `ALL_AEGIS_TOOLS`.
   - Acceptance: existing tool-registry tests still pass; the registry name-list assertion in `aegis-v3-tools.test.ts:60` is extended to include `set_todos`.

4. **(S) Backend — system prompt rule.**
   - Modify: `backend/src/lib/aegis-v3/system-prompt.ts`.
   - Add a new "Plan" tool category bullet to the tool list around line 43: `- **Plan**: \`set_todos\``.
   - Add a new rule **10** (NOT folded into rule 9) governing when to call `set_todos`, the lifecycle, and the strip-is-progress contract. Full copy in Risks section below.
   - Acceptance: token-budget snapshot test asserts prompt output stays under measured budget; new test asserts prompt contains `set_todos`, the rule heading, and at least one of the YES/NO/WRONG examples.

5. **(S) Frontend — shared part-shape helper + derivation helper.**
   - New file: `frontend/src/lib/aegis-parts.ts` — exports `isToolPart`, `toolNameFor`, `toolArgs` per Data Model section. `MessageBubble.tsx` switches its inline copies (lines 34-47) to import from this module in the same PR.
   - New file: `frontend/src/lib/aegis-todos.ts` — exports `deriveTodos(message: UIMessage): Todo[]` per Data Model section.
   - New file: `frontend/src/lib/aegis-todos.test.ts` — 4 cases: empty parts → `[]`; one `set_todos` part → expected list; two consecutive `set_todos` parts → last wins; malformed args (`todos: undefined`, missing `title`) → `[]` or filtered.
   - New file: `frontend/src/__tests__/aegis-todos-roundtrip.test.ts` — drives all three real part shapes (live `tool-set_todos`/`input`, persisted `tool-call`/`args`, rehydrated `dynamic-tool`/`input`) through `deriveTodos` and asserts identical `Todo[]` output.
   - Acceptance: tests pass.

6. **(M) Frontend — `<ChatTodos />` component.**
   - New file: `frontend/src/components/aegis/ChatTodos.tsx`.
   - Visual + state machine per spec above. Tailwind transitions only — no framer-motion.
   - Required component test: `frontend/src/__tests__/aegis-chat-todos.test.tsx` covering 4 states from the visibility matrix (streaming + non-terminal → Loader2; streaming + terminal → Done pill; ended + non-terminal → stalled muted with Dismiss-X; ended + terminal → auto-fade after 1.5s).
   - Acceptance: tests pass; renders correctly with synthetic message data.

7. **(S) Frontend — wire into ChatPane.**
   - Modify: `frontend/src/components/aegis/ChatPane.tsx` — add `<ChatTodos messages={messages} streaming={status === 'streaming'} />` immediately above `<SendQueuePanel />` inside the bottom dock.
   - Acceptance: visible in browser when assistant emits `set_todos` part; latest-assistant-message rule prevents flicker on user-send.

8. **(S) Frontend — suppress in-scroll rendering of `set_todos` + empty-bubble guard.**
   - Modify: `frontend/src/components/aegis/MessageBubble.tsx`.
   - **Suppression placement (load-bearing):** inside `parts.forEach`, AFTER `const toolName = toolNameFor(part);` is computed, BEFORE the `request_fix` / `revise_fix` branch (currently around line 116), add:
     ```ts
     if (toolName === 'set_todos') return;
     ```
     Placement matters — putting it later means a turn ending with `[set_todos, request_fix(error)]` falls through to the request_fix error path before suppression hits.
   - **Empty-bubble guard:** AFTER `parts.forEach` + `flushTools()`, before the wrapping return, add:
     ```ts
     if (!isUser && !error && elements.length === 0) return null;
     ```
     This prevents a turn whose parts are only `[set_todos, set_todos, …]` from rendering as an empty padded bubble.
   - New file: `frontend/src/__tests__/message-bubble.test.tsx` — 6 cases:
     1. `request_fix` in-flight → `PlanCardSkeleton`
     2. `request_fix` resolved → `PlanCard`
     3. `request_fix` with `output.error` → falls through to `ToolCallGroup`
     4. `approve_fix` resolved → `FixStatusCard`
     5. parts = `[set_todos, set_todos]` only → `null` (empty-bubble guard)
     6. parts = `[text, set_todos, request_fix(error)]` → renders text + error pill, no extra chrome from `set_todos`
   - Acceptance: chat scroll does not show "1 tool call" pills for `set_todos`; empty-bubble case returns `null`.

9. **(S) Polish — Done hold only.**
   - When all todos terminal, hold the strip 1.5s with `<CheckCircle2 className="text-success"/> Done — N/N` row before fading. (Already covered in the visibility matrix; this task captures the timer wiring.)
   - Truncation already handled by `truncate min-w-0` on row title.
   - **Drop:** tooltip-on-hover (no `reason` field anymore), explicit truncation polish, manual long-title work. Defer all other polish to post-dogfood.

10. **(S) Backend — filter `set_todos` parts from prior-turn ModelMessages.**
    - Modify the stream route's `convertToModelMessages` path (grep for the route file in `backend/src/routes/` that wires the `useChat` SSE stream — likely `aegis-v3-stream.ts` or similar). Filter out tool-call/tool-result parts whose `toolName` is in `CHAT_ONLY_TOOLS = new Set(['set_todos'])` BEFORE sending history to the model. Chat todos are UI bookkeeping; replaying them into LLM context bloats input cost and confuses the model on subsequent turns.
    - Add backend test asserting prior-turn `set_todos` parts do not appear in the constructed `ModelMessages` array.
    - Acceptance: test passes; manual dogfood multi-turn shows no token growth from prior strips.

11. **(M) Dogfood — 5-scenario discipline pass.**
    - Manual scenarios (kept tight per scope-cutter dissent — full matrix in Testing section):
      1. Single-step ("fix this CVE") → no strip (negative test, `minItems: 2` enforces).
      2. Multi-revise ("revise both plans") → 2-item strip → both flip done → 1.5s Done pill → fade.
      3. Page refresh mid-stream → strip rehydrates correctly OR (if rehydration limitation accepted) appears empty until next assistant message lands.
      4. Stop mid-list → strip flips to muted "Stream ended" with Dismiss-X.
      5. Mid-flight redirect ("actually skip step 2") → agent re-emits `set_todos` with shorter list (no `cancelled` ceremony).
    - Iterate the system prompt rule until the agent reliably declares the plan upfront on multi-step requests AND treats the strip as canonical (no "now I'll do step 1" prose narration).

## Testing & Validation Strategy

The test surface is deliberately bounded — converged regression holes covered, json-schema-library tests and component-render-only smokes cut.

### Backend tests (added to existing files where possible)

- **`backend/src/__tests__/aegis-v3-tools.test.ts`** — extend the registry name-list assertion (line 60) to include `set_todos`. Assert the entry has `danger: 'safe'`, no `permission` key, and `audit: false`. **No** schema-validation tests (those test the json-schema library, not our code).
- **`backend/src/__tests__/aegis-v3-helpers.test.ts`** — add `it('includes the multi-step todos rule')` asserting `buildAegisSystemPrompt` output contains `set_todos`, the rule heading, and at least one of the YES / NO / WRONG examples. Add `it('does not contradict parallel revise_fix rule')` asserting both phrases coexist near each other. Add token-budget snapshot assertion: prompt output ≤ 4500 chars (or whatever the current measured budget is — capture once, fail on regression).
- **New: `backend/src/__tests__/aegis-v3-audit-skip.test.ts`** (or extend an existing `agent.ts` test if one exists) — assert that a streamed turn invoking only `set_todos` produces zero `saveToolExecution` calls.
- **Backend message-history filter** (Task 10) — assert prior-turn `set_todos` parts do not appear in the constructed `ModelMessages` array after `convertToModelMessages` runs.

### Frontend tests

- **`frontend/src/lib/aegis-todos.test.ts`** — 4 cases: empty parts → `[]`; one `set_todos` → expected list; two consecutive `set_todos` → last wins; malformed args → `[]`.
- **`frontend/src/__tests__/aegis-todos-roundtrip.test.ts`** — drives all three real part shapes (live `tool-set_todos`/`input`, persisted `tool-call`/`args`, rehydrated `dynamic-tool`/`input`) through `deriveTodos` and asserts identical `Todo[]` output. This is the test that would have caught the original-plan derivation's silent-render-nothing bug.
- **`frontend/src/__tests__/message-bubble.test.tsx`** — 6 cases per Task 8 (request_fix in-flight / resolved / error fallthrough; approve_fix; set_todos suppressed → null; mixed parts).
- **Required: `frontend/src/__tests__/aegis-chat-todos.test.tsx`** — 4 cases per Task 6's visibility matrix (streaming + non-terminal; streaming + terminal; ended + non-terminal stalled; ended + terminal → fade after 1.5s). Required, not optional — visibility logic is the load-bearing UX of the feature.

### Manual dogfood (5 scenarios)

Per Task 11. Tracks: (1) single-step → no strip, (2) multi-revise full lifecycle, (3) page refresh mid-stream, (4) Stop mid-list → stalled, (5) mid-flight redirect.

### Performance

- Render budget: `deriveTodos` runs on every `messages` change. Parts arrays are bounded (< ~50 items per turn). No measured target — drop the previous "<1ms" claim. If profiling reveals churn, wrap in `useMemo` keyed on `messages.length` + last-message parts length.
- Network: zero new requests (tool calls ride existing SSE).

### Regression

- Existing `request_fix` / `revise_fix` / `approve_fix` / `reject_fix` flows still render `PlanCard` / `FixStatusCard` correctly (covered by `message-bubble.test.tsx` cases 1-4).
- `SendQueuePanel`, `ChatInput`, model picker, send queue, stop button still work (manual smoke during dogfood).
- MessageBubble's existing `isToolPart` / `toolNameFor` callers continue to work after the helper is moved to `aegis-parts.ts` (the same module is imported back).

## Risks & Open Questions

### Risks

- **Model discipline (highest risk).** The agent might forget to call `set_todos`, or call it once and never re-call to update statuses. Mitigations:
  - Strict, structured system-prompt rule (full copy below).
  - During dogfood iteration, count "set_todos was called when expected" / "all todos reached done". If discipline lags, escalate by injecting a "you have N pending todos" reminder into context (heavier; v1.1).

- **System-prompt rule (full copy).** Add a new "Plan" tool category bullet to `system-prompt.ts` line 43 list (e.g. `- **Plan**: \`set_todos\``) and a new rule **10** under it (NOT folded into rule 9, which is fix-flow-specific):

    > **10. Multi-step plans.** When the user requests **≥2 user-visible workstreams** in one turn that take ≥30 seconds each (e.g. "revise both plans", "fix all 3 secrets", "do X then Y"), declare the plan upfront: call `set_todos({todos: [{title}]})` BEFORE your first content-producing tool call. To mark progress, re-call `set_todos` with the same titles plus updated `status` values (`pending` → `in_progress` → `done`). The strip is your progress UI — do NOT narrate "now I'll do step 1" in prose; the strip already shows that. After completing each item, you MAY emit a brief one-line result note (e.g. "Opened PR #42"). For multi-plan revisions, `set_todos` comes BEFORE the parallel `revise_fix` fan-out, not instead of it.
    >
    > **YES**: "revise both plans" (2 items). **YES**: "fix CVE-X, CVE-Y, CVE-Z" (3 items).
    >
    > **NO**: "what's my biggest risk?" (single chained query — rule 7 covers it).
    > **NO**: "fix CVE-X" (single deliverable — rule 9 covers it).
    >
    > **WRONG**: User: "fix this issue". Assistant calls `set_todos(["read file", "draft patch", "open PR"])`. WRONG because these are tool-call subroutines for ONE deliverable, not user-visible workstreams.
    >
    > **WRONG**: Assistant declares 3 todos, then narrates "Now starting step 1..." in prose before each one. WRONG because the strip already shows progress; prose narration duplicates and contradicts the strip's role as canonical UI.

  Token budget: cap rule 10 + tool-list bullet at ≤200 tokens. Snapshot-tested via extension to `aegis-v3-helpers.test.ts:131`. Cross-references rule 9 (single-fix flow) and the parallel-revise fan-out rule explicitly so the model sees them as complementary, not contradictory.

- **List churn during fast streams.** Rapid `set_todos` re-emissions could cause flicker. Mitigation: Tailwind `transition-opacity` + `transition-colors` on icon changes; minimum-visible-duration of ~800ms before strip can unmount on terminal cascade.

- **Conflict with existing FixPanel side panel.** Both surfaces show progress; visual recipe match (rounded card + bg-background-subtle/30) creates duplicate-list risk in the canonical "revise both plans" flow. v1 mitigation: distinct location (strip is bottom-dock; panel is right rail) and distinct copy intent (strip = orchestration across plans; panel = inside one open plan). If dogfood shows confusion, auto-collapse strip when PlanPanel is open (deferred).

- **Cost & latency.** Each `set_todos` call costs one step against `stopWhen: stepCountIs(25)` (`backend/src/lib/aegis-v3/agent.ts:77`). With `maxItems: 6` and full-list-replace semantics, a 6-item plan with 6 progressions = 7 calls, leaving 18 steps for actual work. Per-call output token cost ≈ `set_todos({todos: […]})` × full list ≈ ~200 tokens × 7 calls ≈ ~1.4k output tokens of UI bookkeeping per multi-step turn. Acceptable; far cheaper than per-item update-call round-tripping. Without this collapse the previous two-tool design hit the step cap exactly (12 todos × 2 = 25), leaving zero budget for real work. The audit-skip flag (Patch 2 / Task 1) keeps these calls out of `aegis_tool_executions`, so cost-cap counters are unaffected.

- **Title injection vector.** `title` schema has no charset constraint. Mitigated: model produces title (no untrusted user input flows in), but the renderer should strip control chars defensively (`title.replace(/[ -]/g, '')`) to avoid future surprises.

- **Prompt budget.** Adding rule 10 grows the system prompt by ~150-200 tokens. Snapshot test guards against further drift.

### Open questions (all resolved before `/implement`)

- **`framer-motion` dependency?** Resolved: NOT a dependency (verified — `frontend/package.json` has only `tailwindcss-animate`). Drop entirely; use Tailwind transitions.
- **Terminal-state visibility?** Resolved: hold strip 1.5s with `<CheckCircle2 className="text-success"/> Done — N/N` row, then fade.
- **Operating-mode gate (`propose` / `announce` / `autopilot`)?** Resolved: ungated. Rule 10 applies in all three modes; the dropped "no prose" silence clause removes the announce-mode contradiction.
- **Reuse the existing Aegis `tasks` schema (the durable QStash plan-then-execute path)?** Resolved: no reuse. Chat todos are ephemeral UI chrome; durable tasks are heavyweight cross-thread workflows. Chat todos do NOT reference fix-worker task ids. If a chat todo represents fix-worker work, the title is human prose only and clicking it does nothing in v1.
- **User editing affordance (cancel/dismiss)?** Resolved: **header Dismiss-X only**, client-only (toggles a session-scoped `dismissed[messageId]` flag; does NOT mutate `metadata.parts`). No per-row manual edit; deferred to v1.1.

## Dependencies

- **Vercel AI SDK message-parts persistence** — already wired via `aegis_chat_messages.metadata.parts`. No change needed.
- **Existing tool registration pipeline** in `backend/src/lib/aegis-v3/tools/index.ts`.
- **Existing system-prompt builder** in `backend/src/lib/aegis-v3/system-prompt.ts`.
- **Existing `useChat` hook + `<ChatPane>` composer dock layout.**
- **Existing `MessageBubble.tsx` part-shape helpers** (`isToolPart` / `toolNameFor`) at lines 34-47 — being extracted to `aegis-parts.ts` and re-imported.
- **Lucide icons** (already a dependency) — `Circle`, `Loader2`, `CheckCircle2`, `Pause`, `X`, `ListChecks`.
- **Tailwind transitions** — `transition-opacity` and `transition-colors` only. **No `framer-motion`** (verified not in `frontend/package.json`).

## Success Criteria

- Asking Aegis "revise both plans" produces a 2-item todo strip above the composer; both items flip pending → in_progress → done as the model works; strip holds for 1.5s with a Done pill, then fades.
- Stop mid-list flips the strip to muted "Stream ended" state with a Dismiss-X.
- Mid-flight redirect ("actually skip step 2") causes the agent to re-emit `set_todos` with a shorter list; the strip updates without a `cancelled` ceremony.
- The earlier chatty self-narration ("let me try a general instruction first") no longer appears on multi-step requests — Aegis declares the plan via `set_todos` instead, and the strip is canonical.
- Single-step requests do NOT produce a strip (negative test, enforced by `minItems: 2`).
- Page refresh mid-stream rehydrates the strip with the correct state OR appears empty until next assistant message lands (the documented rehydration limitation — verified, not a regression).
- `set_todos` calls do NOT appear in `aegis_tool_executions` (audit-skip working).
- Prior-turn `set_todos` parts do NOT replay into the next-turn LLM context (history filter working).
- All new tests pass; no regression on existing `request_fix` / `revise_fix` / `approve_fix` flows.
- TypeScript compiles cleanly; no new warnings introduced.
