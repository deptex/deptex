# Aegis Chat Streaming — Implementation Plan

## Overview

Aegis chat replies appear all at once after generation completes — typically 10–40s of dead air, then the full response paints in one event. The Vercel AI SDK already gives us first-class token streaming; we just aren't using it. This plan migrates the chat UI from the current "POST /chat → fire-and-forget generateText → save to DB → Supabase Realtime broadcasts the row" pipeline to "POST /api/aegis/v3/stream → SSE → useChat renders tokens as they arrive → persist final message in onFinish".

Result: first token within ~1–3s, full response visible as it generates, tool calls flicker into "running" then "done" state inline.

## Competitive Research & Design Rationale

The Vercel AI SDK's `streamText` + `useChat` pattern is the canonical agentic-chat shape. Every direct competitor we benchmark against ships streamed responses today:

- **Cursor / Continue / Aider** — token-streamed assistant turns with live tool-call cards
- **Claude.ai / ChatGPT / Gemini** — same; users notice within 2s when streaming is broken
- **Linear's Asks (LLM feature) / GitHub Copilot Chat** — both stream, both render tool calls inline as they execute

There's no controversial design decision here — we're catching up to table stakes. The only real choice is **where to persist the assistant message**:

- **Option A (chosen): `onFinish` hook on the stream**. Persist the full `{ text, parts }` blob once the stream completes. Single DB write per turn. Standard Vercel SDK pattern.
- **Option B**: persist incremental chunks during streaming (every N tokens / M ms). Multi-write, more DB load, lets a refresh mid-stream resume. Overkill for a chat UX where users wait out the full turn anyway.

Option A is what `future_aegis_streaming.md` recommends and what the half-built v3 route already targets.

## Codebase Analysis

**Already built:**
- `backend/src/routes/aegis-v3.ts:32` — `POST /api/aegis/v3/stream` route exists, calls `agent.stream({ messages })` → `result.pipeUIMessageStreamToResponse(res)`. Mounted at `app.use('/api/aegis/v3', aegisV3Router)` (`backend/src/index.ts:136`).
- `backend/src/lib/aegis-v3/agent.ts` — `createAegisAgent()` returns a `ToolLoopAgent` with system prompt + 50+ tools + tool-execution persistence in `onStepFinish`.
- `backend/src/lib/aegis-v3/thread.ts` — `getOrCreateThread`, `loadThreadHistory` (loads last 50 messages as `ModelMessage[]`).
- `backend/src/lib/aegis-v3/memory.ts` — `queryRelevantMemories` (pgvector context).
- `frontend/src/components/aegis/MessageBubble.tsx` — already renders `dynamic-tool` parts with state `running` / `done` / `error`, plus `tool-call` / `tool-result` parts on replay. Both shapes work.
- `frontend/src/components/aegis/ChatPane.tsx:63` — `buildInitialMessages` converts persisted `{ tool-call, tool-result }` parts into `dynamic-tool` UIMessage parts on history seed.

**Half-built or wrong:**
- `aegis-v3/persistence.ts:29` — `saveAssistantMessage` only stores `metadata: { steps, tokens }`. **No `parts` array** — so reload after streaming would lose all PlanCard / ToolCallGroup rendering. Must change.
- `aegis-v3/thread.ts:25` — `getOrCreateThread` derives titles from `message.substring(0, 50) + '...'`. The slick auto-title flow lives only in the `/chat` path. Needs migration.
- `aegis-v3.ts` route — no cost-cap pre-flight, no error-message persistence on stream failure (errors `res.end()` silently), no regenerate sibling, no auto-title.

**Missing entirely:**
- Frontend integration. `ChatPane.tsx` POSTs to `/api/aegis/chat` and listens via Supabase Realtime. None of the streaming infra is wired into the UI yet.

**Reusable code to lift from the existing `/chat` flow:**
- `routes/aegis.ts` `cleanGeneratedTitle()` + auto-title prompt
- `routes/aegis.ts` `classifyChatError()`, `chatErrorUserText()`, `writeAegisChatError()` — extract these into a shared helper module so both routes can call them
- `routes/aegis.ts` cost-cap pre-flight block (lines ~494–511)
- `lib/aegis-v3/chat-generation.ts:154` `stepsToMessageParts()` — already converts `result.steps` into the persisted `{ tool-call, tool-result }` shape; we can call this in `onFinish`

**Memories that constrain this:**
- `feedback_solo_user_prelaunch.md` — direct rewrite is fine; no compat shims; OK to delete `/api/aegis/chat` once `/v3/stream` reaches parity
- `aegis_group_chat_deferred.md` — group chat is parked, so the Supabase Realtime subscription on `aegis_chat_messages` becomes optional. Drop it for the streaming path; document that re-introducing group chat means layering Realtime back **only for "another participant posted"** events, not for your own assistant turn

## Data Model

**No schema changes.** `aegis_chat_messages.metadata` is already JSONB and stores `{ parts: MessagePart[], error?: AegisChatError }` from the `/chat` path. Streaming writes the same shape.

## API Design

### Routes

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/aegis/v3/stream` | authenticateUser | Existing route, enhanced. Body `{ organizationId, threadId?, message, context? }`. Returns SSE per Vercel AI SDK protocol. `X-Thread-Id` header for new threads. |
| POST | `/api/aegis/v3/regenerate` | authenticateUser | New route. Body `{ threadId }`. Wipes everything after last user message, streams a fresh response. Same SSE shape. |
| ~~POST `/api/aegis/chat`~~ | ~~deleted~~ | — | Removed once frontend migrates. The non-streaming path becomes dead code. |
| ~~POST `/api/aegis/chat/regenerate`~~ | ~~deleted~~ | — | Replaced by v3 sibling. |

### Stream lifecycle (server side)

1. Permission + rate-limit + cost-cap pre-flight checks. Cost-cap exceeded → write `cost_cap` assistant message, return 200 with `X-Thread-Id`, no stream.
2. `getOrCreateThread` → `threadId`.
3. **Insert user message immediately** (so refresh during stream doesn't lose it). The current v3 route batches user+assistant inserts in `saveAssistantMessage`; split that.
4. Build agent, call `agent.stream({ messages })`.
5. Wire `onFinish({ text, steps, totalUsage })` to:
   - Convert steps → MessagePart[] via `stepsToMessageParts()`
   - Insert assistant row with `metadata: { parts }`
   - Update `aegis_chat_threads.updated_at`
   - On first exchange (≤3 messages total): generate auto-title via existing helper
   - Call `recordActualCost` so the cost-cap counter is accurate
6. Wire `onError(err)` to `writeAegisChatError(threadId, classifyChatError(err))`.
7. `pipeUIMessageStreamToResponse(res)` carries tokens + tool parts to client.

### Stream lifecycle (client side via `useChat`)

```ts
const { messages, append, reload, status, error } = useChat({
  api: `${API_BASE_URL}/api/aegis/v3/stream`,
  initialMessages: seededFromAegisApi,
  body: { organizationId, threadId },
  onFinish: () => onThreadUpdated?.(),
});
```

- `status === 'streaming'` drives the typing indicator
- `error` from `useChat` triggers an inline error bubble (separate from server-persisted error messages)
- `append({ role: 'user', content })` replaces the manual fetch + tempId pattern
- Regenerate calls a custom function (NOT `useChat.reload`, because we need to also delete the trailing assistant error server-side first):

```ts
async function regenerate() {
  await aegisApi.regenerate(threadId);  // server deletes trailing assistant + ack
  reload();                              // useChat re-streams against same history
}
```

## Frontend Design

### Component changes

- **`frontend/src/components/aegis/ChatPane.tsx`** — primary surgery
  - Replace `handleSubmit` fetch path with `useChat.append`
  - Replace manual `setIsGenerating` with `status === 'streaming'`
  - Drop the Supabase Realtime subscription on `aegis_chat_messages` (deferred-group-chat note)
  - Keep `buildInitialMessages` for history seed
  - `useChat`'s `onFinish` triggers `onThreadUpdated` (sidebar refresh)
  - Regenerate handler: call `aegisApi.regenerate` then `useChat.reload`
  - Map `useChat.error` → existing `ErrorBubble` for transient client-side errors
  - Server-persisted error messages (`metadata.error` set in DB) still render as ErrorBubble after seed

- **`frontend/src/lib/aegis-api.ts`** — minor
  - `regenerate()` route changes to `/api/aegis/v3/regenerate`
  - No other shape changes (uses same `AegisMessage` type)

- **`frontend/src/components/aegis/MessageBubble.tsx`** — no functional change; already handles both persisted and live tool-part shapes

### Streaming-specific UX details

- **First-token latency** target: <3s for cached models, <8s with 50-tool system prompt
- **Tool-call rendering**: ToolCallGroup already shows `running` state; verify the SDK emits `state: 'input-streaming'` → `'output-available'` transitions correctly (it does — the existing replay shape matches)
- **Streaming cancellation**: `useChat` exposes `stop()`. Wire a Cancel button on the typing indicator. Cancelled streams write a `transient` error message server-side via `onError` (since `onFinish` won't fire)
- **Reload mid-stream**: user message is already persisted in step 3, so refreshing during a live stream loses only the in-flight assistant tokens. They re-trigger nothing — the user has to retry manually. Acceptable for v1
- **Long tool loops**: SSE keep-alive frames every ~25s, browser tolerates 5-min idle. ToolLoopAgent caps at 25 steps so worst case ~60s

## Implementation Tasks

### Backend (S–M tasks)

1. **[S] Extract shared chat-error helpers** — pull `classifyChatError`, `chatErrorUserText`, `writeAegisChatError`, `cleanGeneratedTitle` from `routes/aegis.ts` into `lib/aegis-v3/errors.ts` and `lib/aegis-v3/title.ts`. Update `/chat` to import from there.
2. **[S] Cost-cap pre-flight in `/v3/stream`** — call `getProviderInfoForOrg` + `checkMonthlyCostCap` at top of route. On exceeded, write cost-cap error, return 200 with `X-Thread-Id`, skip stream.
3. **[M] Persist user message before streaming** — split `saveAssistantMessage` into `saveUserMessage` + `saveAssistantMessage`. Insert user row right after `getOrCreateThread`.
4. **[M] Wire `onFinish` to persist parts** — refactor `agent.ts` to expose the agent's stream call site, OR shift the `onFinish` handling into the route so it can call `stepsToMessageParts` + insert with `metadata: { parts }`.
5. **[S] Auto-title on first exchange** — call the title helper from `onFinish` when `loadThreadHistory` returned ≤2 messages.
6. **[S] Wire `onError` to `writeAegisChatError`** — also handle the case where stream is cancelled (`AbortError`) → write transient error.
7. **[S] Record actual cost in `onFinish`** — call `recordActualCost(orgId, model, inputTokens, outputTokens, estimatedCents)`. Confirms the cost-cap counter stays accurate.
8. **[M] New `POST /api/aegis/v3/regenerate`** — mirror existing `chat/regenerate` shape. Permission check, find last user message, delete everything after, return `{ threadId }`. Client then calls `useChat.reload()` which streams against the trimmed history.
9. **[S] Remove `/api/aegis/chat` and `/api/aegis/chat/regenerate`** — once frontend migration is verified locally.

### Frontend (S–L tasks)

10. **[L] ChatPane migration to `useChat`** — primary work item:
    - Install/verify `@ai-sdk/react` is already in deps (it is — used elsewhere)
    - Replace `handleSubmit` + manual state with `useChat` hook
    - Replace `isGenerating` with `status === 'streaming' || status === 'submitted'`
    - Drop Realtime subscription block (~50 lines)
    - Adjust `onThreadCreated` wiring — read new `threadId` from `X-Thread-Id` response header
    - Verify message-id collision handling on history-seed + new-stream merge
11. **[S] aegisApi.regenerate route swap** — change `/api/aegis/chat/regenerate` → `/api/aegis/v3/regenerate`.
12. **[S] Cancel button** — wire `useChat.stop()` to the typing indicator dot, replacing it with a stoppable button while `status === 'streaming'`.
13. **[S] useChat error mapping** — render `useChat.error` (network drops, 4xx/5xx that come back before stream starts) as ErrorBubble with regenerate. Existing server-persisted ErrorBubbles still work via `metadata.error`.

### Cleanup (S)

14. **[S] Memory note update** — mark `future_aegis_streaming.md` as SHIPPED with PR link.
15. **[S] Update `aegis_group_chat_deferred.md`** — explicitly call out that streaming dropped the Realtime subscription and re-adding group chat means re-layering it for `role !== 'assistant'` events only.

## Testing & Validation Strategy

### Backend
- **Unit**: error classifier (429 → rate_limit, AbortError → transient, anything else → transient with statusCode), `stepsToMessageParts` round-trip
- **Integration**: hit `/v3/stream` with a stub model, assert SSE frames + final DB row contains `metadata.parts` matching sent stream
- **Cost-cap**: integration test where pre-flight check returns `allowed: false` → assert no model call made + cost_cap error message persisted
- **Regenerate**: insert thread with [user, assistant_error], hit regenerate, assert assistant_error deleted before stream starts
- **Performance target**: first SSE frame <2s after request (excluding model TTFT — that's provider-bound)

### Frontend
- **Manual**: typing indicator → first token visible within 3s on Sonnet 4.6 / 8s on Qwen
- **Manual**: tool calls render `running` → `done` inline as they execute
- **Manual**: refresh mid-stream → user message still in history, no orphaned skeleton
- **Manual**: kill backend mid-stream → ErrorBubble appears with Regenerate
- **Manual**: cost-cap path → switch org cap to $0.01, send any message → cost_cap error inline, no model call

### Regression
- **Existing chat history reload**: messages saved via the new `/v3/stream` path render identically to ones saved via `/chat`. Specifically: ToolCallGroup, PlanCard, FixStatusCard
- **Auto-title**: first-exchange titles still get the `cleanGeneratedTitle` treatment (no "Title:" prefix)
- **Aegis Fix Agent integration**: `request_fix` and `approve_fix` tool calls still resolve into PlanCard / FixStatusCard

## Risks & Open Questions

1. **ToolLoopAgent stream API surface** — verify `agent.stream({ messages })` returns a result with `pipeUIMessageStreamToResponse` AND lets us hook `onFinish` for the full result. If onFinish isn't exposed at that layer, we may need to drop down to `streamText` directly (skip ToolLoopAgent wrapper). Day-1 spike to confirm.
2. **Tool part schema drift between SDK versions** — `dynamic-tool` shape changed between AI SDK 4.x and 5.x. Lock the SDK version + add a smoke test that round-trips a tool-call message through SSE → DB → reload.
3. **First-token latency on cold DeepInfra** — even with streaming, Qwen3-235B has 10–20s cold-start latency. Streaming makes this *more* visible (typing dot pulses for 15s). Mitigation: keep the typing indicator subtle; consider switching org default to Anthropic for dogfood (already discussed).
4. **`useChat` and persisted-message id collision** — after stream completes, server-saved row has DB id; useChat's local message has client-generated id. On the next thread mount, both don't conflict (server is source of truth on reload), but the same-mount transition must not duplicate. Verify with a refresh-after-stream test.
5. **Aborted streams** — if user closes the tab mid-stream, `onFinish` won't fire and `onError` may not either. Need a server-side "stream interrupted, no message persisted" path so the user-message-only thread doesn't look broken on reload. Punt: just leave it; user can resend.

## Dependencies

- `ai@^5` and `@ai-sdk/react@^1` already in deps (verify versions in `frontend/package.json`)
- All chat-error helpers from the recently-shipped `feat: persist Aegis chat errors with regenerate flow` (commit `92f145b`) — extract & reuse
- AegisFixAgent regenerate UI (commit `92f145b`) — reuse pattern for new `/v3/regenerate`
- `aegis-v3.ts` permission-check function — keep as-is

## Success Criteria

- "Hey how are you" produces a first visible token within 3s on Anthropic Sonnet 4.6 (warm path)
- A tool-using turn (e.g. "show me critical CVEs") renders ToolCallGroup `running` → `done` transitions live, not all-at-once at the end
- Refreshing the page after a streamed response shows the assistant message + all tool parts unchanged (replay parity)
- Provoking a 429 from the provider mid-stream produces an inline ErrorBubble with Regenerate, no silent failure
- Cost-cap exceeded produces an inline cost_cap ErrorBubble with the "Manage AI budget" link, no model call billed
- `/api/aegis/chat` and `/api/aegis/chat/regenerate` are deleted from the codebase; grep returns no callers
