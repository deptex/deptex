# Aegis v2 — Implementation Plan

## Overview

Nuke the existing Aegis implementation (33 backend lib files, 5 frontend components, 10+ aegis DB tables, Aider worker, Slack bot, automations, incidents, learning, memory, sprint orchestrator) and rebuild a tight MVP: a dedicated `/organizations/:id/aegis` page with per-user chat threads, streaming Vercel AI SDK responses, ~12 read-only tools, collapsed tool-call cards with expand, and full GFM markdown. Authed via Gemini Flash platform key. Gated behind `interact_with_aegis`. No writes, no memory, no Aider, no Slack — those come in later milestones.

Reference: feature brief at `.cursor/plans/feature-brief-aegis-v2.md`.

---

## Competitive Research & Design Rationale

**Snyk Agent Fix / DeepCode:** Inline-only (IDE zap icon + PR comment). No dashboard, no chat. We differentiate by being conversational.

**Devin / Windsurf / Copilot Workspace:** All converged on the *agent dashboard* pattern — left list (threads/sessions) + streaming chat + collapsed tool cards inline + optional right panel. We adopt this pattern wholesale.

**Claude.ai / ChatGPT:** Threads metaphor (vs "sessions"). Honest for MVP since nothing runs autonomously yet — we call them "threads" and upgrade to "sessions with status" when Aider + background work lands.

**Key differentiation points:**
- Domain-specific tools (reachability, SBOM, policy, blast radius) that generic agents don't have.
- Tight scope: no admin console, no management UI — just chat. Polish one surface before expanding.
- "Regenerate + Edit/truncate-and-rerun" baseline (skip Claude-style branch tree to save ~3x UI effort).

---

## Codebase Analysis

### What already exists and we're reusing

| Piece | Location | Notes |
|---|---|---|
| Route `/organizations/:id/aegis` + `/:threadId` | `frontend/src/app/routes.tsx:127-133` | **Keep routes, rewrite page** |
| Router mount `app.use('/api/aegis', aegisRouter)` | `backend/src/index.ts:134` | **Keep mount, rewrite route file** |
| Gemini Flash provider factory | `backend/src/lib/ai/provider.ts:79` (`getPlatformProvider()`) | Returns Google provider; we need Vercel AI SDK `@ai-sdk/google` model instead — wrap it |
| Vercel AI SDK backend pattern | `backend/src/lib/aegis/executor-v2.ts`, `routes/aegis.ts:1050-1114` | `streamText({ model, system, messages, tools, maxSteps, onFinish })` + `result.toDataStreamResponse()` + `X-Thread-Id` header |
| Vercel AI SDK frontend pattern | `frontend/src/app/pages/AegisPage.tsx` | `useChat({ id, transport: new DefaultChatTransport({ api, headers, body, fetch: intercept X-Thread-Id })})` |
| Tool definition pattern | `backend/src/lib/aegis/tools/*.ts` | `tool({ description, parameters: z.object({...}), execute: async (...) => {...} })` — we'll keep this shape |
| Sidebar nav | `frontend/src/components/OrganizationSidebar.tsx:54-66` | Push `NavItemDef` into `allNavItems`, add id to `SIDEBAR_SECTIONS` |
| Auth middleware | `backend/src/middleware/auth.ts` | `authenticateUser` + `req.user = { id, email }` — standard |
| Permission helper | `backend/src/routes/aegis.ts:22-64` (`hasAegisPermission`) | Inline helper — we'll extract to `backend/src/lib/permissions.ts` for reuse |
| Supabase client | `backend/src/lib/supabase.ts` | Service-role key, `supabase.from(...)` |
| Frontend API helper | `frontend/src/lib/api.ts` | `fetchWithAuth()` auto-injects JWT |
| Auth context | `frontend/src/contexts/AuthContext.tsx` | `useAuth()` returns `{session, user}`; JWT at `session.access_token` |
| Markdown | `react-markdown` + `remark-gfm` already in package.json | Add syntax highlighter (see M5) |
| shadcn UI | `frontend/src/components/ui/` | button, input, dialog, dropdown-menu, tabs, card, badge, tooltip, popover, sheet, toast — all available |

### What's being deleted (full list)

**Backend:**
- `backend/src/routes/aegis.ts` (1682 lines)
- `backend/src/routes/aegis-task-step.ts`
- `backend/src/lib/aegis/` (entire directory — 33 files)
- `backend/src/lib/learning/` (entire directory — 4 files)
- `backend/aider-worker/` (entire directory — archive to branch `aider-worker-archive` before deleting)
- Un-register `aegisTaskStepRouter` if mounted in `backend/src/index.ts`

**Frontend:**
- `frontend/src/app/pages/AegisPage.tsx` (complete rewrite)
- `frontend/src/components/AegisPanel.tsx`
- `frontend/src/components/AegisManagementConsole.tsx`
- `frontend/src/app/pages/docs/AegisContent.tsx` (if purely the settings-console content — confirm during M4)
- `frontend/src/lib/aegis-stream.ts`
- Tests: `aegis-phase7b.test.tsx`, `aegis-learning-ui.test.ts`, `ai-aegis.test.ts`

**Database (via new migration):**
- Legacy Aegis tables: `aegis_activity_logs`, `aegis_automations`, `aegis_automation_jobs`, `aegis_config`, `aegis_inbox`
- Phase7b tables: `aegis_org_settings`, `aegis_tool_executions`, `aegis_approval_requests`, `aegis_tasks`, `aegis_task_steps`, `aegis_memory`, `aegis_memory_embeddings`, `aegis_incidents`, `aegis_incident_timeline`, `aegis_incident_notes`, `incident_playbooks`
- Phase7 tables: any from `phase7_ai_fix.sql` (aider jobs)
- Phase16 tables: `fix_outcomes`, `strategy_patterns`
- Phase17 tables: `security_incidents`, `incident_timeline`, `incident_notes`, `incident_playbooks` (overlaps with phase7b — verify before dropping)
- Phase6c BYOK tables: `organization_ai_providers`, `ai_usage_logs`

**Keep intact:** `aegis_chat_threads`, `aegis_chat_messages`.

### What's being created

**Backend:**
- `backend/src/routes/aegis.ts` — fresh ~300-line route file (threads CRUD + chat stream + auto-title + truncate)
- `backend/src/lib/aegis/chat.ts` — streamText wrapper
- `backend/src/lib/aegis/system-prompt.ts` — tight prompt
- `backend/src/lib/aegis/provider.ts` — Vercel AI SDK Gemini Flash model factory
- `backend/src/lib/aegis/tools/index.ts` — registry
- `backend/src/lib/aegis/tools/{list-projects,get-project-summary,list-project-dependencies,get-project-vulnerabilities,get-reachability-flows,get-security-posture,get-vulnerability-detail,get-package-reputation,get-epss-score,check-cisa-kev,list-policies,analyze-upgrade-path}.ts` — 12 tool files
- `backend/src/lib/aegis/types.ts` — shared types
- `backend/src/lib/permissions.ts` — extract `requireOrgPermission()` helper
- `backend/database/phase20_aegis_v2_cleanup.sql` — drop migration

**Frontend:**
- `frontend/src/app/pages/AegisPage.tsx` — fresh 2-column page
- `frontend/src/components/aegis/ThreadList.tsx`
- `frontend/src/components/aegis/ChatPane.tsx`
- `frontend/src/components/aegis/MessageBubble.tsx`
- `frontend/src/components/aegis/ToolCallCard.tsx`
- `frontend/src/components/aegis/MarkdownRenderer.tsx`
- `frontend/src/components/aegis/PromptChips.tsx`
- `frontend/src/components/aegis/ChatInput.tsx`
- `frontend/src/components/aegis/EmptyState.tsx`
- `frontend/src/lib/aegis-api.ts` — typed API client (threads + messages)

---

## Data Model

### Tables kept as-is

**`aegis_chat_threads`** (existing — no changes):
```sql
CREATE TABLE aegis_chat_threads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
-- RLS: per-user (already in place)
-- Indexes: organization_id, user_id, updated_at DESC (already in place)
```

**`aegis_chat_messages`** (existing — no changes):
```sql
CREATE TABLE aegis_chat_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  thread_id UUID NOT NULL REFERENCES aegis_chat_threads(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
  content TEXT NOT NULL,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

**Tool-call storage:** `metadata` JSONB stores `{ parts: [{type:'text', text}, {type:'tool-call', toolCallId, toolName, args}, {type:'tool-result', toolCallId, result}, ...] }`. Matches Vercel AI SDK's `ChatMessage.parts` shape so the frontend can round-trip without transformation.

### New migration

**File:** `backend/database/phase20_aegis_v2_cleanup.sql`

```sql
-- Aegis v2 cleanup: drop everything except aegis_chat_threads + aegis_chat_messages.
-- Safe to run multiple times (IF EXISTS on every drop).

-- Legacy Aegis platform tables
DROP TABLE IF EXISTS aegis_activity_logs CASCADE;
DROP TABLE IF EXISTS aegis_automation_jobs CASCADE;
DROP TABLE IF EXISTS aegis_automations CASCADE;
DROP TABLE IF EXISTS aegis_config CASCADE;
DROP TABLE IF EXISTS aegis_inbox CASCADE;

-- Phase 7b platform tables
DROP TABLE IF EXISTS aegis_org_settings CASCADE;
DROP TABLE IF EXISTS aegis_tool_executions CASCADE;
DROP TABLE IF EXISTS aegis_approval_requests CASCADE;
DROP TABLE IF EXISTS aegis_task_steps CASCADE;
DROP TABLE IF EXISTS aegis_tasks CASCADE;
DROP TABLE IF EXISTS aegis_memory_embeddings CASCADE;
DROP TABLE IF EXISTS aegis_memory CASCADE;
DROP TABLE IF EXISTS aegis_incident_notes CASCADE;
DROP TABLE IF EXISTS aegis_incident_timeline CASCADE;
DROP TABLE IF EXISTS aegis_incidents CASCADE;

-- Phase 7 Aider
DROP TABLE IF EXISTS ai_fix_jobs CASCADE;
DROP TABLE IF EXISTS ai_fix_artifacts CASCADE;

-- Phase 16 learning
DROP TABLE IF EXISTS strategy_patterns CASCADE;
DROP TABLE IF EXISTS fix_outcomes CASCADE;

-- Phase 17 incidents (overlap with phase7b — idempotent)
DROP TABLE IF EXISTS security_incidents CASCADE;
DROP TABLE IF EXISTS incident_timeline CASCADE;
DROP TABLE IF EXISTS incident_notes CASCADE;
DROP TABLE IF EXISTS incident_playbooks CASCADE;

-- Phase 6c BYOK + usage
DROP TABLE IF EXISTS ai_usage_logs CASCADE;
DROP TABLE IF EXISTS organization_ai_providers CASCADE;

-- Drop any leftover functions / RPCs referenced by deleted tables
DROP FUNCTION IF EXISTS compute_strategy_patterns() CASCADE;
DROP FUNCTION IF EXISTS query_aegis_memory(uuid, text, int) CASCADE;
```

**Verification before running:** Grep for every table name in `backend/src/` — confirm no non-Aegis code references them. If anything still reads from e.g. `ai_usage_logs`, fix those references as part of M1.

### No new tables needed.

---

## API Design

All endpoints mounted under `/api/aegis` in `backend/src/routes/aegis.ts`. All require `authenticateUser` + `requireOrgPermission('interact_with_aegis')` (extracted helper).

| Method | Route | Description |
|---|---|---|
| `GET` | `/threads?organizationId=:id` | List current user's threads for the active org, ordered by `updated_at DESC`. |
| `POST` | `/threads` | Create thread. Body: `{ organizationId, title? }`. Returns `{ id, title, createdAt }`. |
| `PATCH` | `/threads/:id` | Rename thread. Body: `{ title }`. |
| `DELETE` | `/threads/:id` | Delete thread (cascade deletes messages). |
| `GET` | `/threads/:id/messages` | Load full message history for a thread. |
| `POST` | `/chat` | **Main streaming endpoint.** Body: `{ organizationId, threadId?, messages }`. Returns AI SDK data stream; sets `X-Thread-Id` header (new or existing). |
| `POST` | `/threads/:id/auto-title` | Generate short title from first message. Called by frontend after first assistant response. Body: `{ firstUserMessage, firstAssistantMessage }`. |
| `DELETE` | `/messages/:id/below` | Truncate: delete this message + all later messages in the same thread. Used for regenerate and edit-rebranch. |

### Types (shared with frontend via `backend/src/lib/aegis/types.ts`)

```ts
export interface AegisThread {
  id: string;
  organizationId: string;
  userId: string;
  title: string;
  createdAt: string;
  updatedAt: string;
}

export type ToolCallPart = {
  type: 'tool-call';
  toolCallId: string;
  toolName: string;
  args: Record<string, unknown>;
};

export type ToolResultPart = {
  type: 'tool-result';
  toolCallId: string;
  toolName: string;
  result: unknown;
  isError?: boolean;
};

export type TextPart = { type: 'text'; text: string };

export type MessagePart = TextPart | ToolCallPart | ToolResultPart;

export interface AegisMessage {
  id: string;
  threadId: string;
  role: 'user' | 'assistant';
  content: string;        // plain text fallback; full structure lives in metadata.parts
  metadata: { parts: MessagePart[] };
  createdAt: string;
}

export interface ChatRequestBody {
  organizationId: string;
  threadId?: string;
  messages: Array<{ role: 'user' | 'assistant'; content: string; parts?: MessagePart[] }>;
}
```

### Chat endpoint behavior (`POST /chat`)

1. Auth check → permission check → fail with `403` on deny.
2. If no `threadId`, create a thread with placeholder title `"New chat"`.
3. Persist the incoming user message (last message in `messages`).
4. Load last N assistant/user messages (already in body from useChat) + system prompt.
5. Call `streamText({ model: geminiFlash, system, messages, tools, maxSteps: 15, temperature: 0.2, onFinish: persistAssistantMessage })`.
6. Persist the full assistant message (text + tool calls + tool results as `metadata.parts`) in `onFinish`.
7. Set `X-Thread-Id` header so frontend captures the ID for new threads.
8. Return `result.toDataStreamResponse()`.

**`maxSteps: 15`** cap prevents runaway tool loops. Individual tool calls time out at 10s via `AbortController` (pass to each tool's `execute`).

### Auto-title endpoint

- Takes the first user message + assistant response.
- Calls `generateText({ model: geminiFlash, prompt: "Generate a 3-5 word title..." })`.
- Updates `aegis_chat_threads.title`.
- Returns `{ title }`. Frontend updates state.

### Performance

- `/threads` list: indexed on `(user_id, organization_id, updated_at DESC)` — sub-50ms for <500 threads.
- `/threads/:id/messages`: indexed on `thread_id, created_at` — sub-100ms for <500 messages per thread.
- `/chat`: first-token latency depends on Gemini Flash (typically <800ms). Tool calls add per-tool latency (see Tool Catalog below).

---

## Tool Catalog (12 read-only tools)

All tools live in `backend/src/lib/aegis/tools/`. Each exports a `tool({...})` definition. The registry assembles them into the `tools` param for `streamText`.

Each tool receives an injected context object: `{ organizationId, userId, supabase }` via closure in `tools/index.ts`:

```ts
export function getAegisTools({ organizationId, userId }: Ctx) {
  return {
    list_projects: listProjectsTool({ organizationId, userId }),
    get_project_summary: getProjectSummaryTool({ organizationId, userId }),
    // ...etc
  };
}
```

| Tool name | Parameters (zod) | Queries | Target latency |
|---|---|---|---|
| `list_projects` | `{}` | `projects` JOIN `project_health_scores` | <200ms |
| `get_project_summary` | `{ projectId: z.string().uuid() }` | `projects` + `project_dependencies` count + `project_vulnerabilities` count + `semgrep_findings` count | <300ms |
| `list_project_dependencies` | `{ projectId, directOnly?: z.boolean(), limit?: z.number().default(50) }` | `project_dependencies` JOIN `dependencies` | <300ms |
| `get_project_vulnerabilities` | `{ projectId, severity?: enum, reachableOnly?: boolean }` | `project_vulnerabilities` JOIN `vulnerabilities` + reachability join | <400ms |
| `get_reachability_flows` | `{ vulnerabilityId }` | `vulnerability_reachability` + flow data | <300ms |
| `get_security_posture` | `{}` | Aggregate across all org projects | <600ms |
| `get_vulnerability_detail` | `{ cveId: z.string() }` or `{ vulnerabilityId }` | `vulnerabilities` + EPSS + KEV joins | <200ms |
| `get_package_reputation` | `{ ecosystem, packageName }` | `packages` (OpenSSF cached data) | <200ms |
| `get_epss_score` | `{ cveId }` | `epss_scores` cache | <100ms |
| `check_cisa_kev` | `{ cveId }` | `cisa_kev` table | <100ms |
| `list_policies` | `{}` | `package_policy_code` + `project_status_code` + `pr_check_code` | <200ms |
| `analyze_upgrade_path` | `{ ecosystem, packageName, currentVersion }` | Calls existing upgrade-path logic in `backend/src/lib/dependencies/upgrade.ts` (or wherever it lives — confirm in M3) | <800ms |

All tools return structured JSON (never prose) so the model can reason over it. Errors are returned as `{ error: string }` in the tool result, **not** thrown — throwing breaks the stream.

### System prompt (shape)

```txt
You are Aegis, an AI security engineer embedded in Deptex.

Your job: help the user understand and reason about their org's software supply chain
security. You have tools to query projects, dependencies, vulnerabilities, reachability,
policies, and package intelligence. You answer questions with grounded data — never
fabricate CVE IDs, package names, or counts.

Style: direct, technical, short. Markdown for structure. Tables for lists with multiple
columns. Code blocks for package names and code snippets.

Current org: ${orgName} (id: ${organizationId})

When the user asks about their org broadly, start by calling `get_security_posture` and
`list_projects`. Then go deeper as needed.

When you don't know something, say so. Don't guess.
```

Tone: casual-teammate (decided in brief open-question #3).

---

## Frontend Design

### Routes

Already in `routes.tsx` — no changes needed:
- `/organizations/:id/aegis` → `<AegisPage />`
- `/organizations/:id/aegis/:threadId` → `<AegisPage />` (for deep-linking to a specific thread)

### Component Tree

```
AegisPage
├─ ThreadList (left, ~260px)
│  ├─ NewChatButton
│  └─ ThreadListItem × N
│     └─ DropdownMenu (rename / delete)
└─ ChatPane (main, flex-1)
   ├─ (empty state) EmptyState
   │  └─ PromptChips (3 chips)
   ├─ (active) MessageList
   │  └─ MessageBubble × N
   │     ├─ MarkdownRenderer (assistant text parts)
   │     ├─ ToolCallCard × N (collapsed, expandable)
   │     └─ MessageActions (copy / regenerate / edit — hover)
   └─ ChatInput (sticky bottom)
```

### Page layout (AegisPage.tsx)

Follow `.cursor/skills/frontend-design/SKILL.md`:

```tsx
<div className="flex h-[calc(100vh-3rem)] bg-background">
  {/* Left thread list */}
  <aside className="w-[260px] flex-shrink-0 border-r border-border bg-background-card flex flex-col">
    <ThreadList ... />
  </aside>

  {/* Main chat */}
  <main className="flex-1 flex flex-col min-w-0">
    <ChatPane ... />
  </main>
</div>
```

- Page height: `h-[calc(100vh-3rem)]` accounts for the `h-12` top header.
- No top app header inside the page — OrganizationLayout already provides the outer chrome.
- No right panel in MVP.

### Design specs

| Element | Spec |
|---|---|
| Thread list container | `w-[260px] border-r border-border bg-background-card` |
| New chat button | Full-width at top, `h-9`, primary variant, `Plus` icon + "New chat" |
| Thread item | `px-3 py-2 text-sm rounded-md hover:bg-background-subtle cursor-pointer` — truncate long titles — active state `bg-background-subtle text-foreground` |
| Thread hover actions | `DropdownMenu` triggered by `MoreHorizontal` icon, appears on hover, items: Rename / Delete |
| Chat pane | `flex flex-col min-w-0`, messages scroll in `flex-1 overflow-y-auto custom-scrollbar`, input sticks at bottom |
| Empty state | Centered flex, `max-w-xl mx-auto`, welcome heading + 3 chip buttons in grid `grid-cols-1 sm:grid-cols-3 gap-2` |
| Prompt chip | `px-4 py-3 rounded-lg border border-border bg-background-card hover:bg-background-subtle text-sm text-left` |
| User message bubble | Right-aligned, `max-w-[80%]`, `rounded-lg bg-background-card border border-border px-4 py-3` |
| Assistant message | Full-width left-aligned, no bubble — just markdown + tool cards |
| Tool call card (collapsed) | `rounded-md border border-border bg-background-card px-3 py-2 text-xs`, monospace tool name with 🔧 icon, one-line result summary, chevron right |
| Tool call card (expanded) | Same card, expands to show `<pre>` with input + output JSON in `bg-background-subtle rounded-md p-3 text-xs font-mono` |
| Chat input | Textarea `min-h-[44px] max-h-[240px] resize-none`, bg `bg-background-card`, border `border border-border rounded-lg`, Send button inline-right |
| Message action buttons | `h-7 w-7 p-0` icon buttons, ghost variant, shown on hover |

### Streaming UX

- Frontend uses `useChat({ id: threadId, transport: DefaultChatTransport })` with `prepareSendMessagesRequest` to shape the POST body.
- Token streaming rendered via AI SDK default behavior.
- Tool call start → card renders with `Loader2` spinner and label `Running: tool_name`.
- Tool call end (stream emits `tool-result`) → card swaps to static collapsed state with a one-line summary (computed client-side from the result shape).
- Stream error → inline error bubble with "Retry" button that calls `reload()`.

### Empty state wording

Title: `"Aegis, your AI security agent"`
Body: `"Ask me anything about your org's security posture. I have access to your projects, dependencies, vulnerabilities, and policies."`
Chips:
- `"What's my security posture?"`
- `"Which vulnerabilities are reachable?"`
- `"Summarize my riskiest projects"`

### Sidebar nav integration

In `frontend/src/components/OrganizationSidebar.tsx`:

```ts
// Add import
import { Sparkles } from 'lucide-react';

// Push to allNavItems
const allNavItems: NavItemDef[] = [
  { id: 'overview', label: 'Overview', path: 'overview', icon: LayoutDashboard, requiredPermission: null },
  { id: 'aegis', label: 'Aegis', path: 'aegis', icon: Sparkles, requiredPermission: 'interact_with_aegis' as keyof RolePermissions },
  { id: 'vulnerabilities', label: 'Vulnerabilities', path: 'vulnerabilities', icon: ShieldAlert, requiredPermission: null },
  { id: 'compliance', label: 'Compliance', path: 'compliance', icon: Scale, requiredPermission: null },
  { id: 'settings', label: 'Settings', path: 'settings', icon: Settings, requiredPermission: null },
];

// Add to a section
const SIDEBAR_SECTIONS: { label: string; itemIds: string[] }[] = [
  { label: 'Workspace', itemIds: ['overview', 'aegis', 'vulnerabilities', 'compliance'] },
  { label: 'Organization', itemIds: ['settings'] },
];
```

**Confirm** `interact_with_aegis` is in the `RolePermissions` TypeScript type in `frontend/src/lib/api.ts`. If not, add it.

### Markdown rendering

`MarkdownRenderer.tsx`:
- `react-markdown` + `remark-gfm` (already in deps)
- Add `react-syntax-highlighter` (or `shiki`) for code blocks — decide in M5. Lean `react-syntax-highlighter` for smaller bundle.
- Override `<table>`, `<code>`, `<a>` (open external in new tab), `<pre>` for styling.
- Wrap in `prose prose-invert prose-sm max-w-none` (Tailwind typography) or roll custom classes — match SKILL.md tokens.

---

## User Flows

### First-time user
1. Click Aegis in org sidebar → `/organizations/:id/aegis`
2. Page loads → fetch threads → empty → show `EmptyState` with 3 prompt chips
3. User clicks `"What's my security posture?"` chip → prompt inserted into input, auto-submits
4. Frontend calls `POST /api/aegis/chat` with `{ organizationId, messages: [userMsg] }` (no threadId)
5. Backend creates thread, captures `X-Thread-Id` in header, streams response
6. Frontend `fetch` interceptor pulls `X-Thread-Id`, updates URL to `/aegis/:threadId`, adds thread to list
7. After assistant finishes, frontend calls `POST /threads/:id/auto-title` → thread title updates from "New chat" to e.g. `"Security posture review"`

### Returning user
1. Click Aegis → lands on `/aegis`
2. Fetch threads → if any, redirect to `/aegis/:mostRecentThreadId`
3. That thread's messages load, rendered in chat pane
4. User can click another thread to switch, or "+ New chat" for fresh thread

### Regenerate
1. User hovers assistant message → `RotateCcw` icon
2. Click → `DELETE /messages/:assistantMessageId/below` (truncates just that message)
3. Re-submit the preceding user message (via useChat's `reload()`)

### Edit + truncate-rerun
1. User hovers own message → `Pencil` icon
2. Click → message becomes textarea with Submit/Cancel
3. Submit → `DELETE /messages/:userMessageId/below` (truncates user msg + everything after)
4. Frontend updates message list (optimistic) and calls `sendMessage()` with new content

### Rename thread
1. Hover thread → dropdown → "Rename" → title becomes inline input
2. Enter → `PATCH /threads/:id` → list updates

### Delete thread
1. Hover → dropdown → "Delete" → AlertDialog confirm
2. `DELETE /threads/:id` → list updates; if active, redirect to `/aegis`

---

## Implementation Milestones

Each milestone is independently shippable and testable. Ordered so each builds on the previous.

### M1 — DB cleanup & code deletion (S, backend-heavy)

**Goal:** Leave codebase in a clean state with only `aegis_chat_threads` + `aegis_chat_messages` intact.

1. Archive `backend/aider-worker/` to a dedicated branch `aider-worker-archive` (before deletion, so it's recoverable).
2. Write `backend/database/phase20_aegis_v2_cleanup.sql` (from Data Model section).
3. Grep for every to-be-dropped table name across `backend/src/` to ensure nothing else reads them. Note any non-Aegis consumers (e.g., if `organization_ai_providers` is used by a Tier-2-AI feature unrelated to Aegis — unlikely but verify). Patch or delete offending code.
4. Apply migration via Supabase MCP (`mcp__claude_ai_Supabase__apply_migration`).
5. Delete files:
   - `backend/src/routes/aegis.ts`
   - `backend/src/routes/aegis-task-step.ts`
   - `backend/src/lib/aegis/` (entire)
   - `backend/src/lib/learning/` (entire)
   - `backend/aider-worker/` (entire — already archived)
   - Frontend: `AegisPage.tsx`, `AegisPanel.tsx`, `AegisManagementConsole.tsx`, `AegisContent.tsx` (if purely aegis console — verify), `aegis-stream.ts`
   - Tests: `aegis-phase7b.test.tsx`, `aegis-learning-ui.test.ts`, `ai-aegis.test.ts`
6. In `backend/src/index.ts`: comment out `import aegisRouter` and `app.use('/api/aegis', aegisRouter)` TEMPORARILY — we'll re-add in M2.
7. In `frontend/src/app/routes.tsx`: temporarily set `aegis` route to a placeholder `<div>Aegis v2 coming…</div>` so TypeScript compiles.
8. Remove dangling imports (use TypeScript compiler to find): `AegisPage` in routes.tsx, `AegisPanel` in project pages (if imported), `AegisManagementConsole` references.
9. Run `npm run build` in both backend + frontend — both must pass.
10. Commit: `refactor: nuke aegis v1 in preparation for v2 rebuild`.

**Acceptance:** Both apps build cleanly. No references to deleted files. DB is cleaned. `aegis_chat_threads` + `aegis_chat_messages` tables still exist and contain 0 rows (or any existing rows — fine either way).

**Complexity: S** — mostly deletion, but careful about dangling references.

---

### M2 — Backend: threads CRUD + provider + types (M)

**Goal:** All non-streaming endpoints work end-to-end with curl / Postman.

1. Create `backend/src/lib/permissions.ts`:
   ```ts
   export async function userHasOrgPermission(
     userId: string, orgId: string, permission: string
   ): Promise<boolean> { /* membership → role → permissions[permission] */ }

   export function requireOrgPermission(permission: string) {
     return async (req: AuthRequest, res: Response, next: NextFunction) => { /* ... */ };
   }
   ```
   Reuse in other routes later.
2. Create `backend/src/lib/aegis/provider.ts`:
   ```ts
   import { google } from '@ai-sdk/google';
   export function getAegisModel() {
     return google('gemini-2.5-flash');  // reads GOOGLE_AI_API_KEY env
   }
   ```
3. Create `backend/src/lib/aegis/types.ts` (from API Design section).
4. Create `backend/src/routes/aegis.ts` with threads CRUD:
   - `GET /threads` (list)
   - `POST /threads` (create)
   - `PATCH /threads/:id` (rename)
   - `DELETE /threads/:id`
   - `GET /threads/:id/messages`
   - `DELETE /messages/:id/below` (truncate)
   - All apply `authenticateUser` + `requireOrgPermission('interact_with_aegis')`.
   - Enforce ownership: `user_id = req.user.id` AND `organization_id` matches.
5. Register router in `backend/src/index.ts`: `app.use('/api/aegis', aegisRouter)`.
6. Test each endpoint with curl:
   - Create a thread, list, rename, delete, list messages (empty), truncate-below.
7. Commit: `feat(aegis): add v2 thread + message routes`.

**Acceptance:** All 6 endpoints return correct status codes + JSON. 403 if permission missing. 404 for nonexistent resources. No unauthorized access (try cross-user fetch — should 403 or empty).

**Complexity: M** — straightforward CRUD, but permission helper + ownership checks need care.

---

### M3 — Backend: chat stream + 12 tools + auto-title (L)

**Goal:** Can POST a message to `/chat` and get a streaming response back that includes tool calls.

1. Create `backend/src/lib/aegis/system-prompt.ts` with the system prompt template (takes `orgName`, `organizationId`).
2. Create `backend/src/lib/aegis/chat.ts`:
   ```ts
   export async function streamChat({ organizationId, userId, threadId, messages }) {
     // Load org name
     // Build system prompt
     // Get tools via getAegisTools({ organizationId, userId })
     // Call streamText({ model, system, messages, tools, maxSteps: 15, temperature: 0.2,
     //   onFinish: (result) => persistMessage(...) })
     // Return { result, threadId }
   }
   ```
3. Implement each of the 12 tools in `backend/src/lib/aegis/tools/`:
   - For each: read the existing Deptex table columns, write a typed query, return structured JSON.
   - Keep each tool <80 lines. Parameters via zod.
   - Handle errors by returning `{ error: 'message' }`, not throwing.
4. Create `backend/src/lib/aegis/tools/index.ts` that imports all 12 and exports `getAegisTools({ organizationId, userId })`.
5. Add `POST /chat` endpoint to `routes/aegis.ts`:
   - Validate body.
   - If no `threadId`, create thread with title "New chat".
   - Persist last user message.
   - Call `streamChat(...)`.
   - Set `X-Thread-Id` header.
   - `onFinish` persists assistant message with `metadata.parts` populated.
   - Return `result.toDataStreamResponse()`.
6. Add `POST /threads/:id/auto-title` endpoint:
   - Fetch first 2 messages.
   - Call `generateText({ model, prompt })` to get 3-5 word title.
   - Update thread title.
7. Test chat end-to-end with curl:
   ```
   curl -N -X POST http://localhost:3001/api/aegis/chat \
     -H "Authorization: Bearer $JWT" \
     -H "Content-Type: application/json" \
     -d '{"organizationId":"...","messages":[{"role":"user","content":"what is my security posture?"}]}'
   ```
   Expect streamed SSE response with tool calls.
8. Verify DB: after the stream ends, assistant message row exists with `metadata.parts` containing tool-call and tool-result parts.
9. Commit: `feat(aegis): streaming chat with 12 read-only tools`.

**Acceptance:** 
- Chat streams token-by-token for at least the 3 suggested prompts.
- Tool calls execute against real DB data, return grounded results.
- Assistant message persisted with full `parts[]`.
- Auto-title produces reasonable titles.
- No hallucinated CVEs/package names when spot-checked against real data.

**Complexity: L** — streaming + 12 tools is the biggest chunk. Parallelize per-tool implementation if needed.

---

### M4 — Frontend: page shell + thread list + empty state (M)

**Goal:** The page loads, user can see threads, create threads, rename/delete, and see the empty state.

1. Create `frontend/src/lib/aegis-api.ts`:
   ```ts
   export const aegisApi = {
     listThreads: (orgId) => fetchWithAuth(`/api/aegis/threads?organizationId=${orgId}`),
     createThread: (orgId, title?) => ...,
     renameThread: (id, title) => ...,
     deleteThread: (id) => ...,
     getMessages: (threadId) => ...,
     truncateBelow: (messageId) => ...,
     autoTitle: (threadId) => ...,
   };
   ```
2. Confirm / add `interact_with_aegis: boolean` to `RolePermissions` type in `frontend/src/lib/api.ts`.
3. Create `frontend/src/components/aegis/ThreadList.tsx`:
   - Props: `threads`, `activeThreadId`, `onSelect`, `onCreate`, `onRename`, `onDelete`.
   - Layout per design specs above.
   - Dropdown with rename (inline edit) + delete (AlertDialog confirm).
4. Create `frontend/src/components/aegis/EmptyState.tsx` + `PromptChips.tsx`.
5. Create `frontend/src/app/pages/AegisPage.tsx`:
   - Use `useParams()` for `id` and optional `threadId`.
   - Fetch threads on mount.
   - If `threadId` param, set active; else if any threads exist, redirect to most recent.
   - Render `ThreadList` + placeholder main area.
   - Re-wire route in `routes.tsx` to new AegisPage.
6. Test: create 3 threads, rename one, delete one, click between them.
7. Commit: `feat(aegis): thread list + empty state`.

**Acceptance:** 
- Page renders without errors.
- Can create / rename / delete threads.
- Active thread highlights.
- Empty state shows when no threads.

**Complexity: M** — mostly plumbing + shadcn components.

---

### M5 — Frontend: chat pane + streaming + tool cards + markdown (L)

**Goal:** Can send messages and see streamed responses with tool cards and polished markdown.

1. Install `react-syntax-highlighter` (or `shiki`) — pick one (lean `react-syntax-highlighter` for smaller bundle), add to `frontend/package.json`.
2. Create `frontend/src/components/aegis/MarkdownRenderer.tsx`:
   - `react-markdown` + `remark-gfm` + syntax highlighting for code blocks.
   - Custom `<a>` (open new tab + underline), `<table>` (styled), `<code>` (inline styled).
3. Create `frontend/src/components/aegis/ToolCallCard.tsx`:
   - Collapsed: icon + tool name + one-line summary (auto-generated from result shape — e.g., `Found 12 vulns (3 reachable)`).
   - Expanded: `<pre>` with input JSON + output JSON, copy buttons.
   - Running state (while `tool-result` hasn't arrived): spinner + "Running {toolName}…".
4. Create `frontend/src/components/aegis/MessageBubble.tsx`:
   - Renders all parts from `message.parts[]`: text parts via `MarkdownRenderer`, tool-call/tool-result pairs via `ToolCallCard`.
   - User messages: right-aligned bubble. Assistant: full-width.
5. Create `frontend/src/components/aegis/ChatInput.tsx`:
   - Textarea, auto-grow, Shift+Enter newline, Enter submits.
   - Send button (disabled while streaming or empty).
   - Expose `value` + `onSubmit` via ref.
6. Create `frontend/src/components/aegis/ChatPane.tsx`:
   - Uses `useChat({ id: threadId, transport })`.
   - `transport: new DefaultChatTransport({ api: '/api/aegis/chat', headers: Authorization, body: { organizationId, threadId }, fetch: intercept X-Thread-Id })`.
   - Renders `MessageList` (mapping `messages` to `MessageBubble`) + `ChatInput`.
   - On first assistant finish for a new thread: call `aegisApi.autoTitle(threadId)`.
   - Auto-scroll to bottom on new messages.
7. Wire `ChatPane` into `AegisPage` — replace placeholder.
8. Clicking a prompt chip should insert into input and auto-submit (via ref).
9. Commit: `feat(aegis): streaming chat pane with tool cards + markdown`.

**Acceptance:**
- Submitting "What's my security posture?" streams a response.
- Tool cards appear with spinner while running, collapse with summary when done.
- Clicking a tool card expands it to show JSON.
- Markdown renders properly (tables, code, links).
- URL updates to `/aegis/:threadId` after first message on a new thread.

**Complexity: L** — this is the hero feature. Expect iteration.

---

### M6 — Frontend: message actions (copy / regenerate / edit) (S)

**Goal:** User can copy any message, regenerate an assistant response, or edit and rerun a user message.

1. Add `MessageActions.tsx` component:
   - Props: `message`, `onCopy`, `onRegenerate`, `onEdit`.
   - Hover-revealed icon buttons: `Copy`, `RotateCcw` (assistant only), `Pencil` (user only).
2. Wire actions in `ChatPane`:
   - **Copy**: `navigator.clipboard.writeText(message.content)` + toast.
   - **Regenerate**: `aegisApi.truncateBelow(message.id)` → `useChat.reload()`.
   - **Edit**: swap the user bubble for inline textarea + Submit/Cancel → on submit: `truncateBelow(messageId)` → `useChat.sendMessage(editedContent)`.
3. Commit: `feat(aegis): message copy/regenerate/edit`.

**Acceptance:** All three actions work correctly. Truncate removes everything from that message onward.

**Complexity: S** — small, mostly wiring.

---

### M7 — Nav integration (S)

**Goal:** Aegis shows up in the org sidebar nav and is gated by permission.

1. Add `interact_with_aegis` to `RolePermissions` type if not present (confirmed in M4 but double-check).
2. Update `frontend/src/components/OrganizationSidebar.tsx` per "Sidebar nav integration" spec above.
3. Verify: as an owner, Aegis shows; with a role missing the permission, it doesn't.
4. Commit: `feat(aegis): add Aegis to org sidebar nav`.

**Acceptance:** Nav item appears under Workspace section with Sparkles icon. Clicking navigates to `/organizations/:id/aegis`. Hidden for roles without the permission.

**Complexity: S.**

---

### M8 — Polish, QA, and success check (M)

**Goal:** MVP is demo-grade and you can dogfood it for a week.

1. **Loading states:**
   - Thread list skeleton shimmer while loading.
   - Message list skeleton (3-4 shimmer rows) while fetching historical messages.
   - Input disabled during stream with "Aegis is thinking..." indicator.
2. **Error states:**
   - Stream error → inline error bubble + retry button.
   - Thread fetch error → toast + retry.
   - 403 (no permission) → full-page message "You don't have permission to use Aegis."
3. **Edge cases:**
   - Very long threads (test with 50+ messages) — verify scroll performance.
   - Very long tool results — `ToolCallCard` expanded view handles overflow with `max-h-[400px] overflow-auto`.
   - Stream interrupted mid-response → partial message is persisted gracefully; retry reload works.
4. **Visual QA:**
   - Compare against design-skills tokens. Spot-check border radius, padding, hover states.
   - Tool card icon — pick one (`Wrench`? `Zap`? Match AegisPage's existing aesthetic).
   - Empty state wording + CTA feel right.
5. **Dogfood for a week:** Use Aegis daily instead of clicking through vuln page. Log issues, fix them.
6. **Accuracy check:** Spot-check 20 responses — grep the raw tool output against what Aegis says, flag any hallucinations. If any, tighten the system prompt with a "NEVER fabricate CVE IDs or counts; if unsure, call the right tool or say you don't know" rule.
7. Commit: `polish(aegis): loading + error states + visual QA`.

**Acceptance:** All 4 success criteria from the brief are met.

**Complexity: M** — depends on how much polish friction surfaces during dogfood.

---

## Testing & Validation Strategy

### Backend
- **Manual curl tests** for each of the 8 endpoints (threads CRUD, messages, chat stream, auto-title, truncate).
- **Permission tests:** create a member role with `interact_with_aegis: false` → verify 403.
- **Cross-user isolation:** create thread as user A → user B cannot list/read/update/delete it.
- **Tool accuracy:** unit-test each tool with a seeded org — each returns expected structured data. Target: all 12 tools tested in `backend/src/lib/aegis/tools/*.test.ts` (deferred to M8 if time-boxed).

### Frontend
- **Golden path:** empty state → click chip → streamed response with tool cards → auto-title updates → URL updates to `/aegis/:threadId`.
- **Thread management:** create, rename, delete, switch between.
- **Message actions:** copy, regenerate, edit-rerun.
- **Stream edge cases:** refresh mid-stream, hit regenerate, network interruption.

### Integration
- **E2E sanity:** real org with real projects → ask all 3 suggested prompts → responses reference actual project names, vuln counts that match the vulnerabilities page.

### Performance
- `/threads` list: <100ms server time.
- `/chat` first-token: <1.5s (Gemini Flash latency dominant).
- Tool calls: each <800ms (targets in Tool Catalog table).
- Page TTI: <2s after auth.

### Regression
- `/organizations/:id/overview` + vulnerabilities + compliance pages still load (sanity check — we're not touching them but the DB migration drops tables they might reference if I missed something).

---

## Risks & Open Questions

| Risk / Question | Mitigation |
|---|---|
| **Some dropped table still used elsewhere.** M1 step 3 grep is critical. If we miss one, prod breaks. | Grep every table name before running migration. Apply migration on a branch DB (Supabase branch) first; run backend build + integration tests. |
| **Gemini Flash rate limits.** Platform key shared across Aegis + docs assistant + policy AI + notification AI. A chat loop burst could trigger throttling. | No rate limiting in MVP (user request). Monitor. Add Redis rate limiter in a later milestone if it becomes an issue. |
| **Vercel AI SDK version drift.** Existing code uses `parameters:` (pre-v5). If `@ai-sdk/*` packages get upgraded, `parameters` might become `inputSchema`. | Check `package.json` for pinned AI SDK version. Match existing code's style (the old `aegis/tools/*` still compiles, so it's fine). Note any drift as a side task. |
| **Tool hallucinations.** Gemini Flash is smaller; may fabricate tool results or skip tools. | System prompt emphasizes grounding. M8 accuracy spot-check. If false rate >10%, upgrade prompt or switch default to Gemini Pro. |
| **Scroll performance on long threads.** 200+ messages might chug. | MVP expects <50 msgs/thread. If this becomes real, add react-virtual in a later pass. |
| **Icon choice for sidebar.** `Sparkles` is the AegisPage convention. Alternatives: `Bot`, `Shield`, `Wand2`. | Default `Sparkles`. Revisit in M8 if it feels wrong. |
| **Auto-title quality.** Gemini might produce verbose titles. | Prompt engineering: "3-5 words, Title Case, no quotes". Truncate >40 chars client-side. |
| **Aider worker deletion.** If we need Aider's strategy logic in future, re-reading from archive branch is annoying. | Archive before delete (step 1 of M1). Document the branch name in a memory. |
| **Tool max-step cap (15).** Some multi-step queries (e.g., "summarize riskiest projects" with 50 projects) might hit the cap. | Start at 15. Bump if it trips. Show a "hit step cap" notice in the UI if Aegis stops early. |

### Open questions (flagged for you during implementation)

1. **Route filename:** `routes/aegis.ts` (replaces old) or `routes/aegis-v2.ts` (new, old nuked)? → **Recommend `routes/aegis.ts`** — old is deleted, no reason to namespace. Cleaner.
2. **System prompt tone:** casual teammate or formal SecEng? → **Recommend casual** (per brief). Revisit in M8 dogfood.
3. **Syntax highlighter:** `react-syntax-highlighter` or `shiki`? → `react-syntax-highlighter` (smaller bundle, simpler integration).
4. **Aider worker archive strategy:** dedicated branch + delete, or move to `archive/aider-worker/` path? → **Branch + delete.** Keeps repo tidy.

---

## Dependencies

- **Backend:** Express, Supabase service role client, Vercel AI SDK (`ai`, `@ai-sdk/google`), zod — all already in `package.json`.
- **Frontend:** React 18, Vite, `@ai-sdk/react`, `ai` (for `DefaultChatTransport`), `react-markdown`, `remark-gfm`, Tailwind, shadcn — all already present. **New:** `react-syntax-highlighter` (~80kb gzipped).
- **External:** Gemini Flash via `GOOGLE_AI_API_KEY` — already configured (`backend/src/lib/ai/provider.ts:82`).
- **Infra:** No new Fly apps, no new Upstash usage, no new Supabase tables.

---

## Success Criteria

1. **Chat loop works end-to-end.** All 3 suggested prompts return accurate, grounded responses. No stream errors on the golden path.
2. **Daily dogfood for 7 days.** You (Henry) use Aegis instead of manually clicking through the vulnerability page. If you stop using it, we haven't shipped MVP — iterate.
3. **Tool result accuracy.** Spot-check 20 random responses — no hallucinated CVE IDs, package names, or counts. Cross-reference against raw DB queries.
4. **UI is demo-grade.** Threads, chat, tool cards, empty state all feel production-quality. Nothing placeholder-looking.

---

## Out of Scope — Reserved for Future Milestones

(Full list in the feature brief; summary here.)

- **Next up:** Aider fix worker + write tools (triggerAiFix, suppressVulnerability) + approval flow.
- **After that:** Contextual floating panel on vuln/project pages, Memory system ("teach Aegis"), Usage/spend tracking.
- **Later:** Slack bot, Automations/scheduled jobs, Incident response, Learning system, Sprint orchestrator, BYOK.
- **Much later:** Full autonomy mode, branch-tree message editing, multi-user collaboration on threads.
