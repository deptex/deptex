# Aegis v3 — Phase 0 (Foundations) Implementation Plan

> **Historical context (2026-05-09):** This plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. Where this plan references BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, or `AI_ENCRYPTION_KEY` for AI key envelopes, treat those as historical implementation details — current AI runs on platform keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from worker env). `AI_ENCRYPTION_KEY` itself is still in use, but only for `organization_registry_credentials` (IaC v2 Phase 1).

## Overview

Phase 0 of the multi-year aegis roadmap (`.cursor/plans/research-aegis-multiyear.md`). The goal is a **structural refactor of the Aegis chat backend** from the current `executor-v2.ts` (which calls `streamText` directly with hand-rolled config) to AI SDK v6's `ToolLoopAgent` abstraction, behind a clean per-category tool registry. No new user-visible features — but it unlocks every later phase (Agent Core, Write Tools, PR Review, Aegis Fix, Skills, Compliance, etc.) by giving us:

- A typed tool registry with consistent `permission`/`danger`/`needsApproval` metadata
- SDK-native loop control via `stopWhen: stepCountIs(...)`
- A single source of truth for the system prompt (currently 3 files, 2 of which are confused or dead)
- Cleanup of v1 chat code (`executor.ts`, `executor-v2.ts`, 3 system-prompt files, `chat.ts`) which has accumulated ~700 lines of architectural debt

Built in parallel under `backend/src/lib/aegis-v3/` with a new `/api/aegis/v3/stream` endpoint. The v1 chat path stays mounted and functional throughout. The final PR flips the frontend to `/v3/stream` and deletes v1 in one atomic commit. **No feature flag** (solo pre-launch — see `feedback_solo_user_prelaunch.md` memory).

**Not in scope** (deferred to later phases): write tools, skills, subagents, MCP, sprint-orchestrator, automations-engine, pr-review, slack-bot, group chats, typed UIMessage data parts, `Output.object`, `needsApproval`-via-SDK migration. Phase 0 ships read-only chat parity with the current backend.

---

## Locked Decisions (from /interview substitute)

| Question | Choice |
|---|---|
| Endpoint | New `POST /api/aegis/v3/stream` next to v2 |
| Tool registry | Explicit per-category arrays in `lib/aegis-v3/tools/<category>.ts` |
| Feature flag | None — frontend stays on v2 until v3 is verified, then single PR swaps + deletes v1 |
| Retirement scope | **Chat path only** — `executor.ts`, `executor-v2.ts`, `chat.ts`, three `system-prompt*.ts` files. `sprint-orchestrator`, `automations-engine`, `pr-review`, `slack-bot` retire in their own respective later phases |

---

## Codebase Analysis (current state, verified)

### v1 chat path end-to-end

```
Frontend AegisPage.tsx:249  DefaultChatTransport(api: '/api/aegis/v2/stream')
                            body: { organizationId, threadId, message, context }
                            ↓
Backend  routes/aegis.ts:1051  POST /v2/stream
   - hasAegisPermission() — RBAC: organization_roles.permissions.interact_with_aegis
   - checkRateLimit() — 200 messages/day per user
   - dynamic import → executor-v2.createAegisStream(...)
   - res.setHeader('X-Thread-Id', resolvedThreadId)
   - result.toDataStreamResponse() forwarded to client
                            ↓
Backend  lib/aegis/executor-v2.ts  createAegisStream()
   - getLanguageModelForOrg() — BYOK, decrypts API key, returns LanguageModel
   - getOrCreateThread() — creates aegis_chat_threads row if threadId missing
   - loadThreadHistory() — selects from aegis_chat_messages
   - queryRelevantMemories() — pgvector lookup in aegis_memory
   - buildAgentSystemPrompt() — from system-prompt-v2.ts (the live one)
   - buildToolSet() — registry self-registers ~50 tools across 10 categories
   - streamText({ model, system, messages, tools, maxSteps: 25, onStepFinish, onFinish })
   - onFinish → save user+assistant messages to aegis_chat_messages, log usage
```

### Tool API style — verified all-zod

Every tool in `backend/src/lib/aegis/tools/` (26 files, ~50 tools) uses `tool({ description, parameters: z.object({...}), execute })`. **None** use `dynamicTool({ inputSchema: jsonSchema({...}) })` despite the gotcha note in memory `aegis_v2_state.md`. This means `zod` is a hard dependency and pinning it explicitly in `package.json` (currently transitive through `ai`) is required to avoid version drift triggering the documented TS2589 error.

### Three system-prompt files — only one live

| File | Lines | Status |
|---|---|---|
| `system-prompt-v2.ts` | 83 | **LIVE** — imported by `executor-v2.ts:6`. 68-line agentic system prompt. This is the keeper. |
| `systemPrompt.ts` | 168 | Used by v1 `executor.ts` (legacy non-streaming `/api/aegis/handle`). Retire with v1. |
| `system-prompt.ts` | 44 | **DEAD** — not imported anywhere. Delete. |

### Existing tool registry

`lib/aegis/tools/registry.ts` exposes `registerAegisTool()` (self-registration pattern) + `buildToolSet(toolContext, message)` returning `Record<name, CoreTool>` for `streamText`. It also wraps tools with permission checks (`checkToolPermission`) and approval middleware that writes to `aegis_approval_requests` and returns a JSON sentinel `{approval_required: true}` to signal the LLM to back off.

The registry already has a notion of:
- `TOOL_PROFILES` (10 profiles: default, security, policy, intelligence, external, admin, compliance, +3 more)
- `permission_level: 'safe' | 'moderate' | 'dangerous'`
- per-category tool files (`org-management.ts`, `project-ops.ts`, `security-ops.ts`, `policy.ts`, `compliance.ts`, `intelligence.ts`, `external.ts`, `memory.ts`, `automation.ts`, `learning.ts`, `incidents.ts`) plus 13 single-tool specialized files (`get-*`, `check-*`, `list-*`, `analyze-*`).

v3 inherits the spirit (categories + permission/danger metadata) but replaces the self-registration pattern with **explicit imports** so the dependency graph is statically inspectable.

### Database tables (already exist — no new migrations for Phase 0)

Verified via recon:

| Table | Migration | Used by v3? |
|---|---|---|
| `aegis_chat_threads` | `aegis_chat_threads_schema.sql` | ✅ Yes — same shape |
| `aegis_chat_messages` | `aegis_chat_messages_schema.sql` | ✅ Yes — same shape (`role`, `content`, `metadata` JSONB) |
| `aegis_tool_executions` | `phase7b_aegis_platform.sql:40` | ✅ Yes — write tool audits via `onStepFinish` |
| `aegis_approval_requests` | `phase7b_aegis_platform.sql:62` | Phase 3+ (no write tools in Phase 0) |
| `aegis_memory` (pgvector) | `phase7b_aegis_platform.sql` | ✅ Yes — same `queryRelevantMemories()` |
| `aegis_org_settings` | `phase7b_aegis_platform.sql` | ✅ Yes — `operating_mode` column drives default tool profile |

### BYOK provider loader

`lib/aegis/llm-provider.ts:28` — `getLanguageModelForOrg(organizationId)`:
1. Selects `is_default = true` row from `organization_ai_providers`
2. Decrypts `encrypted_api_key` via `lib/ai/encryption` (AES-256-GCM, `AI_ENCRYPTION_KEY` env)
3. Calls `getLanguageModel({ providerType, apiKey, model })` which adapts to `createOpenAI() | createAnthropic() | createGoogleGenerativeAI()`
4. Returns `LanguageModel` ready for `streamText` / `ToolLoopAgent`

This works as-is for v3. **Port via thin re-export, don't duplicate.**

### Frontend transport

`frontend/src/app/pages/AegisPage.tsx:249-279` uses `DefaultChatTransport` from `@ai-sdk/react@3.0.170`. Custom `prepareSendMessagesRequest` extracts the last user message text and sends `{ organizationId, threadId, message, context }` — **NOT** a standard AI SDK `messages: UIMessage[]` array. The server reconstructs history from DB.

This is the convention v3 must keep: server-side history reconstruction (so the frontend transport doesn't change in Phase 0; only the URL changes in PR 0e).

---

## SDK v6 ToolLoopAgent API (verified from official docs)

Sources: [tool-loop-agent reference](https://ai-sdk.dev/docs/reference/ai-sdk-core/tool-loop-agent), [createAgentUIStreamResponse](https://ai-sdk.dev/docs/reference/ai-sdk-core/create-agent-ui-stream-response), [Loop Control](https://ai-sdk.dev/docs/agents/loop-control).

```typescript
import { ToolLoopAgent, stepCountIs, createAgentUIStreamResponse, tool } from 'ai';

const agent = new ToolLoopAgent({
  model,                                  // LanguageModel from BYOK loader
  instructions: systemPrompt,             // string
  tools: { name: toolDef, ... },          // Record<string, Tool>
  stopWhen: stepCountIs(25),              // matches current maxSteps
  onStepFinish: ({ toolCalls, toolResults, usage }) => { /* persist tool audit */ },
  onFinish: ({ usage, steps, text }) => { /* persist final assistant message */ },
});

const stream = agent.stream({
  messages,                               // ModelMessage[] reconstructed from DB
  options: callOptions,                   // typed per-request context (orgId, userId, etc.)
});

// Express bridge:
const response = await createAgentUIStreamResponse({ agent, uiMessages: messages });
response.body.pipeTo(new WritableStream({ write(c) { res.write(c); }, close() { res.end(); } }));
```

Key API points the plan relies on:
- `stopWhen` accepts `StopCondition | StopCondition[]` — we'll start with `stepCountIs(25)`
- `callOptionsSchema` lets us declare a typed context (`orgId`, `userId`, `threadId`, `operatingMode`) the agent loop can pass to tool `execute` functions
- `onStepFinish` and `onFinish` callbacks fire per step + at end — same hooks `streamText` had
- `output.schema` (Output.object) is available but unused in Phase 0
- Approval flow exists conceptually ("A tool call needs approval" is a documented stop reason) but the exact `needsApproval` typing isn't on the public docs page. We'll discover it in Phase 3 when write tools land. **Phase 0 has zero write tools, so this is not a blocker.**

---

## New Architecture

### Directory layout

```
backend/src/lib/aegis-v3/
├── agent.ts                  createAegisAgent({ orgId, userId, threadId }) → ToolLoopAgent
├── streaming.ts              wraps createAgentUIStreamResponse for Express
├── system-prompt.ts          single-file system prompt (replaces 3 files)
├── thread.ts                 getOrCreateThread, loadThreadHistory (ported from executor-v2)
├── memory.ts                 queryRelevantMemories (ported from executor-v2)
├── persistence.ts            saveAssistantMessage, saveToolExecution
├── provider.ts               re-exports getLanguageModelForOrg (no duplication)
├── tool-types.ts             AegisToolEntry, AegisToolContext, ToolDanger, ToolPermission
└── tools/
    ├── index.ts              flat tools map: { name: Tool } for ToolLoopAgent
    ├── projects.ts           list_projects, get_project_summary, list_project_dependencies
    ├── security.ts           get_project_vulnerabilities, get_security_posture, get_vulnerability_detail, get_reachability_flows
    ├── intelligence.ts       check_cisa_kev, get_epss_score, get_package_reputation, analyze_upgrade_path
    └── policy.ts             list_policies

backend/src/routes/aegis-v3.ts    new router, mounted at /api/aegis/v3
```

### Tool registry shape

```typescript
// lib/aegis-v3/tool-types.ts
export type ToolDanger = 'safe' | 'low' | 'medium' | 'high';
export type ToolPermissionKey =
  | 'interact_with_aegis' | 'manage_aegis' | 'trigger_fix'
  | 'view_ai_spending'    | 'manage_incidents';

export interface AegisToolContext {
  orgId: string;
  userId: string;
  threadId: string;
  operatingMode: 'propose' | 'announce' | 'autopilot';
  supabase: SupabaseClient;
}

export interface AegisToolEntry<I = any, O = any> {
  name: string;
  description: string;
  inputSchema: z.ZodType<I>;
  permission?: ToolPermissionKey;       // RBAC pre-check
  danger?: ToolDanger;                  // metadata only in Phase 0; drives needsApproval in Phase 3
  execute: (input: I, ctx: AegisToolContext) => Promise<O>;
}

export function buildSDKTool(entry: AegisToolEntry, ctx: AegisToolContext) {
  return tool({
    description: entry.description,
    parameters: entry.inputSchema,
    execute: async (input) => {
      if (entry.permission && !(await hasPermission(ctx.orgId, ctx.userId, entry.permission))) {
        return { error: `Missing permission: ${entry.permission}` };
      }
      return entry.execute(input, ctx);
    },
  });
}
```

Each per-category file exports a typed `Array<AegisToolEntry>` (compile-time guarantees). `tools/index.ts` aggregates them and converts to the `Record<name, Tool>` shape `ToolLoopAgent` expects:

```typescript
// lib/aegis-v3/tools/index.ts
import { projectsTools } from './projects';
import { securityTools } from './security';
import { intelligenceTools } from './intelligence';
import { policyTools } from './policy';
import type { AegisToolContext, AegisToolEntry } from '../tool-types';

export const ALL_AEGIS_TOOLS: AegisToolEntry[] = [
  ...projectsTools,
  ...securityTools,
  ...intelligenceTools,
  ...policyTools,
];

export function buildToolSet(ctx: AegisToolContext) {
  return Object.fromEntries(
    ALL_AEGIS_TOOLS.map((entry) => [entry.name, buildSDKTool(entry, ctx)])
  );
}
```

### The 12 read-only tools migrated in Phase 0

Picked for: (a) currently used by chat, (b) zero side effects, (c) mechanically portable from existing `lib/aegis/tools/` files. Mapping to source:

| # | v3 name | v3 file | v1 source |
|---|---|---|---|
| 1 | `list_projects` | tools/projects.ts | `tools/project-ops.ts` |
| 2 | `get_project_summary` | tools/projects.ts | `tools/project-ops.ts` |
| 3 | `list_project_dependencies` | tools/projects.ts | `tools/list-project-dependencies.ts` |
| 4 | `get_project_vulnerabilities` | tools/security.ts | `tools/get-project-vulnerabilities.ts` |
| 5 | `get_security_posture` | tools/security.ts | `tools/get-security-posture.ts` |
| 6 | `get_vulnerability_detail` | tools/security.ts | `tools/get-vulnerability-detail.ts` |
| 7 | `get_reachability_flows` | tools/security.ts | `tools/get-reachability-flows.ts` |
| 8 | `check_cisa_kev` | tools/intelligence.ts | `tools/check-cisa-kev.ts` |
| 9 | `get_epss_score` | tools/intelligence.ts | `tools/get-epss-score.ts` |
| 10 | `get_package_reputation` | tools/intelligence.ts | `tools/get-package-reputation.ts` |
| 11 | `analyze_upgrade_path` | tools/intelligence.ts | `tools/analyze-upgrade-path.ts` |
| 12 | `list_policies` | tools/policy.ts | `tools/list-policies.ts` |

This matches the master plan's "12 read-only tools passing through" exit criterion.

### `/api/aegis/v3/stream` route handler shape

```typescript
// routes/aegis-v3.ts
const router = Router();

router.post('/stream', authenticateUser, async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { organizationId, threadId, message, context } = req.body;

  // RBAC + rate limit (same as v2)
  if (!(await hasAegisPermission(organizationId, userId))) return res.status(403).json(...);
  const dailyLimit = await checkRateLimit(`ai:aegis:user:${userId}`, 200, 86400);
  if (!dailyLimit.allowed) return res.status(429).json(...);

  // Resolve thread + history
  const resolvedThreadId = await getOrCreateThread(organizationId, userId, threadId, message, context);
  const history = await loadThreadHistory(resolvedThreadId);
  const memoryContext = await queryRelevantMemories(organizationId, message);

  // Build agent
  const agent = await createAegisAgent({
    orgId: organizationId,
    userId,
    threadId: resolvedThreadId,
    operatingMode: (await getOrgSettings(organizationId)).operating_mode,
    memoryContext,
  });

  res.setHeader('X-Thread-Id', resolvedThreadId);

  const messages = [...history, { role: 'user' as const, content: message }];
  const response = await createAgentUIStreamResponse({ agent, uiMessages: messages });

  // Pipe to Express
  response.body!.pipeTo(new WritableStream({
    write(chunk) { res.write(chunk); },
    close()       { res.end(); },
  }));
});

export default router;
```

Mounted in `backend/src/index.ts` as `app.use('/api/aegis/v3', aegisV3Router)`.

---

## Implementation Tasks (PR-by-PR)

Each PR is mergeable on its own. Each rebases on fresh `main` before opening. Per-PR commits use Conventional Commits and avoid milestone language ("M3", "Phase 0").

### PR 0a — Scaffold + zod pin (S, ~half day)

**Goal:** structural setup, no behavior change. Mergeable risk-free.

Files created:
- `backend/src/lib/aegis-v3/tool-types.ts` — `AegisToolEntry`, `AegisToolContext`, `ToolDanger`, `ToolPermissionKey`, `buildSDKTool` helper
- `backend/src/lib/aegis-v3/tools/index.ts` — empty aggregator stub returning `[]`

Files modified:
- `backend/package.json` — add `"zod": "^4.1.8"` explicit dep (currently transitive)
- `backend/package-lock.json` — regenerated by `npm install`

**Acceptance:**
- `cd backend && tsc --noEmit` clean
- `cd backend && npm test` passes (no behavior change)
- `cd frontend && tsc --noEmit` clean
- New `lib/aegis-v3/` directory exists with stub files

**Commit message:**
```
chore(aegis): scaffold lib/aegis-v3/ and pin zod
```

---

### PR 0b — Provider, system prompt, thread + memory utilities (S-M, ~1 day)

**Goal:** port the helper functions v3 needs, no chat path change yet.

Files created:
- `backend/src/lib/aegis-v3/provider.ts` — re-exports `getLanguageModelForOrg` from `lib/aegis/llm-provider.ts` (single line, no duplication)
- `backend/src/lib/aegis-v3/system-prompt.ts` — consolidated 68-line system prompt copied from `system-prompt-v2.ts` with naming cleanup (function name `buildAegisSystemPrompt` for clarity)
- `backend/src/lib/aegis-v3/thread.ts` — `getOrCreateThread`, `loadThreadHistory` (ported from `executor-v2.ts`, kept identical)
- `backend/src/lib/aegis-v3/memory.ts` — `queryRelevantMemories` (ported from `executor-v2.ts`, kept identical)
- `backend/src/lib/aegis-v3/persistence.ts` — `saveAssistantMessage(threadId, content, metadata)`, `saveToolExecution(orgId, userId, threadId, toolName, params, result, durationMs, tokensUsed)` (extracted from v2 `onFinish`/`onStepFinish` for cleaner reuse)

Files modified: none (purely additive)

**Acceptance:**
- `tsc --noEmit` clean on backend
- Existing `aegis-platform.test.ts` tests still pass (untouched code paths)
- New unit tests in `backend/src/__tests__/aegis-v3-provider.test.ts` cover `getLanguageModelForOrg` re-export and stub tool builder

**Commit message:**
```
feat(aegis): port chat helpers to lib/aegis-v3/
```

---

### PR 0c — 12 read-only tools migrated (M, 1-2 days)

**Goal:** all 12 tools registered in v3, type-safe, with unit tests.

Files created:
- `backend/src/lib/aegis-v3/tools/projects.ts` — exports `projectsTools: AegisToolEntry[]` with 3 tools
- `backend/src/lib/aegis-v3/tools/security.ts` — 4 tools
- `backend/src/lib/aegis-v3/tools/intelligence.ts` — 4 tools
- `backend/src/lib/aegis-v3/tools/policy.ts` — 1 tool
- `backend/src/__tests__/aegis-v3-tools.test.ts` — per-tool unit tests covering happy path + RBAC denial + invalid input

Files modified:
- `backend/src/lib/aegis-v3/tools/index.ts` — `ALL_AEGIS_TOOLS` array imports + `buildToolSet(ctx)` exported

**Migration recipe (per tool):**
1. Read source from `lib/aegis/tools/<source>.ts`
2. Copy `description` text verbatim (LLM behavior must not change)
3. Copy `parameters` zod schema verbatim
4. Wrap `execute` body to take `(input, ctx: AegisToolContext)` instead of accessing module-scoped state
5. Replace any `supabase` access with `ctx.supabase` to allow test injection
6. Remove the `tool({...})` wrapper — register as plain `AegisToolEntry`

**Acceptance:**
- `tsc --noEmit` clean
- `npm test` passes including new `aegis-v3-tools.test.ts`
- Per-tool test demonstrates: returns same JSON shape as v1 source given the same input
- ESLint clean

**Commit message:**
```
feat(aegis): port 12 read-only tools to v3 registry
```

---

### PR 0d — ToolLoopAgent + /v3/stream endpoint (M, 1-2 days)

**Goal:** new endpoint live and verified end-to-end via curl. Frontend NOT switched.

Files created:
- `backend/src/lib/aegis-v3/agent.ts` — `createAegisAgent({ orgId, userId, threadId, operatingMode, memoryContext })` returns `ToolLoopAgent`
- `backend/src/lib/aegis-v3/streaming.ts` — Express bridge wrapping `createAgentUIStreamResponse` (extracted for testability + future reuse by other endpoints)
- `backend/src/routes/aegis-v3.ts` — `POST /stream` handler as shown above
- `backend/src/__tests__/aegis-v3-stream.test.ts` — supertest-based test that mounts the router with a mocked `LanguageModel` (returns canned tool-call + text), asserts response includes streamed chunks + correct `X-Thread-Id` header

Files modified:
- `backend/src/index.ts` — add `import aegisV3Router from './routes/aegis-v3'` and `app.use('/api/aegis/v3', aegisV3Router)` next to existing aegis mount

**`createAegisAgent` reference shape:**
```typescript
export async function createAegisAgent(opts: AegisAgentOpts): Promise<ToolLoopAgent> {
  const model = await getLanguageModelForOrg(opts.orgId);
  const orgRow = await supabase.from('organizations').select('name').eq('id', opts.orgId).single();
  const systemPrompt = buildAegisSystemPrompt({
    orgName: orgRow.data!.name,
    orgId: opts.orgId,
    operatingMode: opts.operatingMode,
  }) + opts.memoryContext;

  const ctx: AegisToolContext = { orgId: opts.orgId, userId: opts.userId, threadId: opts.threadId, operatingMode: opts.operatingMode, supabase };
  const tools = buildToolSet(ctx);

  return new ToolLoopAgent({
    model,
    instructions: systemPrompt,
    tools,
    stopWhen: stepCountIs(25),
    onStepFinish: async ({ toolCalls, toolResults, usage }) => {
      for (let i = 0; i < (toolCalls?.length ?? 0); i++) {
        await saveToolExecution(opts.orgId, opts.userId, opts.threadId, toolCalls[i].toolName, toolCalls[i].args, toolResults?.[i]?.result, /* duration */ 0, usage?.totalTokens ?? 0);
      }
    },
    onFinish: async ({ usage, text }) => {
      await saveAssistantMessage(opts.threadId, text, { tokens: usage?.totalTokens });
    },
  });
}
```

**Manual verification before PR opens:**
```bash
# Start backend in worktree
cd backend && npm run dev

# In another terminal, with a real BYOK org configured:
curl -N -X POST http://localhost:3001/api/aegis/v3/stream \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"organizationId": "<uuid>", "message": "list my projects"}'

# Expected: SSE stream with text + tool-call for list_projects + text + finish
# Expected: aegis_chat_messages row created for user + assistant
# Expected: aegis_tool_executions row for the list_projects call
# Expected: X-Thread-Id header on response
```

**Acceptance:**
- `tsc --noEmit` clean
- `npm test` includes new stream test passing
- Manual curl produces a streaming response with at least one tool call
- DB rows verified in `aegis_chat_messages` and `aegis_tool_executions`
- v2 endpoint still works unchanged (regression check)

**Commit message:**
```
feat(aegis): add /api/aegis/v3/stream backed by ToolLoopAgent
```

---

### PR 0e — Frontend swap + v1 chat retirement (M, ~1 day)

**Goal:** flip frontend to v3, delete v1 chat code in the same PR so main is never broken between commits.

Files modified:
- `frontend/src/app/pages/AegisPage.tsx` — change `DefaultChatTransport({ api: ... })` from `/api/aegis/v2/stream` to `/api/aegis/v3/stream`. No other changes (request body, headers, X-Thread-Id handling stay identical).
- `backend/src/routes/aegis.ts` — remove `POST /v2/stream` handler (and the v1 `POST /handle` handler). Keep the rest of the file (read endpoints for thread list, messages, etc. stay until later phases retire them).
- `backend/src/index.ts` — no change (the aegis router is still mounted; only its internal routes thinned out)

Files deleted:
- `backend/src/lib/aegis/executor.ts`
- `backend/src/lib/aegis/executor-v2.ts`
- `backend/src/lib/aegis/chat.ts`
- `backend/src/lib/aegis/system-prompt-v2.ts`
- `backend/src/lib/aegis/system-prompt.ts`
- `backend/src/lib/aegis/systemPrompt.ts`

**Browser smoke test before opening PR:**
1. `cd backend && npm run dev` (port 3001)
2. `cd frontend && npm run dev` (port 3000)
3. Open AegisPage in browser
4. Ask "list my projects" — verify streaming text response with the `list_projects` tool firing
5. Ask "what vulnerabilities does project X have" — verify `get_project_vulnerabilities`
6. Click an existing thread in sidebar — verify history loads and continues correctly
7. Verify `X-Thread-Id` is read from response (new threads create a sidebar entry)
8. Verify markdown rendering works (the v2 UI is unchanged)
9. Verify thread title auto-generates after first user message

**Acceptance:**
- All 9 browser checks pass
- `tsc --noEmit` clean on backend AND frontend (no broken imports from deleted v1 files)
- `npm test` passes both projects (some v1 tests may need pruning if they reference deleted files — delete them, don't keep dangling test files)
- No grep hits for `executor-v2|executor.ts|system-prompt-v2|systemPrompt|chat.ts` outside `lib/aegis-v3/` and historical plan docs

**Commit message:**
```
feat(aegis): cut chat over to v3 ToolLoopAgent and remove v1 executor
```

---

## Testing & Validation Strategy

### Unit tests
- **PR 0b:** provider re-export, helper utilities (thread, memory, persistence)
- **PR 0c:** per-tool tests with `(input, ctx) → output` shape assertion + RBAC denial
- **PR 0d:** `createAegisAgent` with mocked `LanguageModel` returning a canned trace; `routes/aegis-v3.ts` `POST /stream` via supertest
- **PR 0e:** delete tests for retired files; verify no test references the deleted modules

### Integration / manual
- **PR 0d:** curl test (specified above) before opening PR
- **PR 0e:** the 9 browser checks above before opening PR

### Regression
- After every PR: `cd backend && tsc --noEmit && npm test`, `cd frontend && tsc --noEmit && npm test`
- Existing `aegis-platform.test.ts`, `aegis-learning-ui.test.ts` should keep passing through PR 0d. They may need pruning in PR 0e for tests that exercise the deleted v1 code.
- Smoke test of `/api/aegis/handle`, `/api/aegis/threads`, etc. — non-chat aegis endpoints stay live throughout.

### Performance
- v3 should match v2 in stream latency (same model, same tools, same DB queries). If a regression is observed, profile `createAegisAgent` first — most likely cause is duplicate `getOrCreateThread` calls.
- Target: TTFB ≤ 1s, full response ≤ 30s for typical 3-tool agentic flow.

---

## Risks & Open Questions

### Risks
1. **`ToolLoopAgent` API gap vs `streamText` config.** The current `executor-v2.ts` uses options like `experimental_telemetry` (probably none, but worth verifying). Mitigation: PR 0d's test catches this.
2. **`createAgentUIStreamResponse` may emit a different chunk format than `result.toDataStreamResponse()`.** The frontend's `DefaultChatTransport` may need to be reconfigured if data parts differ. Mitigation: browser smoke test in PR 0e is the gate. If the format differs incompatibly, we either keep `result.toDataStreamResponse()` style by calling `agent.stream(...).toDataStreamResponse()` (likely available — verify in PR 0d) or update the frontend transport in PR 0e.
3. **BYOK provider returning a model that `ToolLoopAgent` rejects.** Unlikely (same `LanguageModel` type) but verify in PR 0d's curl test.
4. **Hidden v1 dependencies.** The `executor.ts` may be referenced from non-chat code paths (e.g. `aegis-task-step.ts` for async task execution). Mitigation: PR 0e grep + tsc must show clean before merge. If found, those callers move to v3 too OR keep their v1 dependency and we narrow the deletion scope.

### Open questions
1. **`needsApproval` exact API in SDK v6.** Public docs reference the concept ("A tool call needs approval" is a stop reason) but not the typed shape. Phase 0 has zero write tools so this is **not blocking**. Discover during Phase 3 (Write Tools).
2. **Custom UIMessage data parts shape.** Same status — Phase 0 streams text only. Defer to Phase 12 (UX Polish) or whichever phase first wants typed structured streaming (e.g. live "fix plan" object).
3. **Per-org `operating_mode` semantics in v3.** Currently drives v1's tool profile selection. v3 has only safe read-only tools so this is metadata-only in Phase 0. Real wiring waits for Phase 3.
4. **`pgvector` query behavior in tests.** The recon agent confirmed `aegis_memory` exists. Memory-loading tests in PR 0b may need to mock the pgvector RPC, since CI doesn't run pgvector. Use existing mock pattern from `aegis-platform.test.ts` if one exists.

---

## Dependencies

- AI SDK v6: `ai@^6.0.106` ✅ already installed
- `@ai-sdk/react@^3.0.170` ✅ already installed (frontend)
- BYOK provider loader (`lib/aegis/llm-provider.ts`) — kept alive (re-exported)
- Existing Supabase tables (no migration in Phase 0)
- `lib/ai/encryption.ts` ✅ (used by BYOK loader)
- `lib/rate-limit.ts` ✅ (used by `/v3/stream` route)
- `middleware/auth.ts` (`authenticateUser`, `AuthRequest`) ✅

No new external services. No new env vars. No DB migration.

---

## Success Criteria

Phase 0 is done when:

1. ✅ `POST /api/aegis/v3/stream` accepts `{ organizationId, threadId, message, context }` and streams a chat response using `ToolLoopAgent`
2. ✅ All 12 read-only tools fire correctly through the new registry with RBAC checks intact
3. ✅ `aegis_chat_messages` and `aegis_tool_executions` rows are written by `onFinish`/`onStepFinish`
4. ✅ Frontend `AegisPage` chats against `/v3/stream` with no UX regression vs the current v2 experience
5. ✅ v1 chat code (`executor.ts`, `executor-v2.ts`, `chat.ts`, three system-prompt files) deleted; no broken imports
6. ✅ `tsc --noEmit` and `npm test` clean on backend and frontend
7. ✅ Master-plan exit criterion met: "v3 chat on fresh branch with v6 SDK agent loop, 12 read-only tools passing through, all v2 UX parity"

What unlocks: Phase 2 (Agent Core), Phase 3 (Write Tools + Triage), Phase 4 (PR Review), Phase 12 (UX Polish), and downstream (Phase 5 Aegis Fix).

---

## Per-PR commit cadence summary

| PR | Title | Size | Days | Dependency |
|---|---|---|---|---|
| 0a | scaffold lib/aegis-v3/ and pin zod | S | 0.5 | none |
| 0b | port chat helpers to lib/aegis-v3/ | S-M | 1 | 0a |
| 0c | port 12 read-only tools to v3 registry | M | 1-2 | 0b |
| 0d | add /api/aegis/v3/stream backed by ToolLoopAgent | M | 1-2 | 0c |
| 0e | cut chat over to v3 and remove v1 executor | M | 1 | 0d (verified live) |

Total: ~5-7 working days. Worst case (open questions surface, manual debugging): ~10 days. Either way still within the master plan's "1-2 weeks" Phase 0 budget.
