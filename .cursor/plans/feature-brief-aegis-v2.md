# Feature Brief: Aegis v2 (MVP Rebuild)

> **Historical context (2026-05-09):** This plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. Where this plan references BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, or `AI_ENCRYPTION_KEY` for AI key envelopes, treat those as historical implementation details — current AI runs on platform keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from worker env). `AI_ENCRYPTION_KEY` itself is still in use, but only for `organization_registry_credentials` (IaC v2 Phase 1).

## One-liner
A conversational AI security agent at `/organizations/:id/aegis` that lets any permitted org member chat about their org's security posture, with tool calls rendered inline and per-user thread history.

## Problem Statement
The existing Aegis implementation is a scope-creep casualty: 33 backend lib files, 50+ tools, Aider worker, Slack bot, automations, incident response, learning system, memory, sprint orchestrator — all built, none polished, none used. The feature is orphaned (not linked from nav) and the surface area is too wide to iterate on.

The refactor: rip out everything peripheral, rebuild a small, polished chat MVP that actually gets used daily, and iterate outward from there — Aider/fix actions next, then Slack, then autonomy features.

## Competitive Landscape

**What security competitors do:**
- **Snyk Agent Fix / DeepCode:** No dashboard. Inline "zap" icon in IDE + PR comments, up to 5 fix suggestions per issue. Pure action-oriented, no chat.
- **Dependabot / GitHub Advanced Security:** Auto-PRs, no conversational surface.

**What agent platforms do:**
- **Devin, Windsurf, Copilot Workspace:** Dedicated dashboards. Converged UI pattern: sessions/threads list on left, streaming chat with tool cards inline, optional artifact panel on right. "Agent command center" framing.
- **Claude.ai / ChatGPT:** Threads list + streaming chat. Baseline pattern.

**Where Aegis differentiates:**
- Unlike Snyk (inline-only, no chat), Aegis is a *colleague you talk to* backed by deep contextual data (reachability, SBOM, policies, blast radius).
- Unlike generic agents (Devin, Claude), Aegis has built-in security domain knowledge via tools.
- MVP chooses the agent-dashboard pattern (familiar, demo-able) over inline-assistant (deferred to v2).

## User Stories

1. **As an org admin**, I want to open `/organizations/:id/aegis` and ask "what's our security posture?" so I can get a high-level read without clicking through pages.
2. **As a developer**, I want to ask "which vulnerabilities are reachable?" so I can triage real risk without parsing tables.
3. **As a team lead**, I want to ask "summarize my riskiest projects" so I can prioritize the week.
4. **As a returning user**, I want to see my past threads so I can pick up where I left off or reference prior answers.
5. **As a user who made a typo**, I want to edit a message and re-run from that point instead of starting a new thread.

## Data Model

**Keep (existing tables, already have clean schemas):**
- `aegis_chat_threads` — id, organization_id, user_id, title, timestamps. RLS per-user.
- `aegis_chat_messages` — id, thread_id, role ('user' | 'assistant'), content TEXT, metadata JSONB, created_at. Store tool calls in `metadata.parts[]` (Vercel AI SDK format).

**Drop (via new migration):**
- `phase7_ai_fix.sql` — aider job tables
- `phase7b_aegis_platform.sql` — tasks, task_steps, approval_requests, tool_executions, automations, automation_jobs, org_settings, memory, memory_embeddings, incidents
- `phase16_aegis_learning.sql` — fix_outcomes, strategy_patterns
- `phase17_incident_response.sql` — incident tables
- `aegis_activity_logs_schema.sql`
- `aegis_automations_schema.sql`
- `aegis_automation_jobs_schema.sql`
- `aegis_config_schema.sql`
- `aegis_inbox_schema.sql`
- `organization_ai_providers` (phase6c BYOK table)
- `ai_usage_logs` (phase6c — skipped for MVP)

New migration: `phase20_aegis_v2_cleanup.sql` — DROP all above, idempotent with `IF EXISTS`.

## API Endpoints

All under `/api/aegis/v2/` (new route file, replaces old `aegis.ts`):

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/threads` | List current user's threads for active org. Order by `updated_at DESC`. |
| `POST` | `/threads` | Create a thread. Returns `{id, title}`. |
| `PATCH` | `/threads/:id` | Rename thread. |
| `DELETE` | `/threads/:id` | Delete thread (cascade deletes messages). |
| `GET` | `/threads/:id/messages` | Load full message history. |
| `POST` | `/chat` | Main streaming endpoint. Accepts `{threadId, messages}`. Uses Vercel AI SDK `streamText` + tools. Returns SSE data stream. |
| `POST` | `/threads/:id/auto-title` | Generate a short title from first user message (called once after first turn). |
| `DELETE` | `/messages/:id/truncate` | For edit+rebranch: delete this message and all messages after it in the same thread. |

All require `authenticateUser` + permission check `interact_with_aegis`.

## Frontend Views

**Route:** `/organizations/:id/aegis` (add to `frontend/src/app/routes.tsx`)

**Nav:** Top-level org sidebar item with sparkle/AI-accent icon, same level as Projects / Teams / Security.

**Page layout (2-column):**
- **Left sidebar (~260px):** Thread list, "+ New chat" button at top, each thread shows title + relative timestamp. Hover reveals rename/delete. Truncate long titles.
- **Main pane:** Streaming chat.
  - **Empty state:** Centered welcome — "Hi, I'm Aegis. Ask me about your security posture." + 3 prompt chips:
    - "What's my security posture?"
    - "Which vulnerabilities are reachable?"
    - "Summarize my riskiest projects"
  - **Active chat:** Messages stream. Assistant messages render markdown (GFM: code blocks, tables, lists, links, syntax highlighting). Tool calls render as collapsed cards showing `🔧 toolName` + one-line summary; click to expand full input/output JSON.
  - **Input:** Textarea at bottom, Enter to send, Shift+Enter for newline. Disabled while streaming.
  - **Message actions (on hover):** Copy (both roles), Regenerate (assistant only), Edit (user only).

**Design references:** Claude.ai for layout/threads, Devin for tool-call card expand pattern, v0 for streaming feel.

## User Flows

**First-time user:**
1. Click "Aegis" in org sidebar → arrives at `/aegis`
2. Empty state welcome + 3 prompt chips
3. Click a chip → auto-populates input and submits
4. Thread created, auto-titled after response, streaming begins
5. Tool cards appear with spinner, fill in when done
6. Response streams token-by-token

**Returning user:**
1. Click Aegis → lands on most recent thread (or empty state if none)
2. Scrollable thread list on left, click to switch
3. "+ New chat" creates a fresh thread

**Edit + rebranch:**
1. User hovers their own message → edit icon
2. Click → message becomes editable, Submit button appears
3. On submit: truncate all messages after that point (soft delete via DELETE `/messages/:id/truncate`), re-run from new edited content

**Regenerate:**
1. User hovers assistant message → regenerate icon
2. Click → delete that assistant message, re-run from preceding user message

## Tool Catalog (MVP)

~12 read-only tools in `backend/src/lib/aegis-v2/tools/`. All implemented against existing Deptex tables:

| Tool | Returns |
|---|---|
| `listProjects` | Projects in org with health score, status, framework |
| `getProjectSummary` | Dependency count, vuln count, semgrep/secret counts |
| `listProjectDependencies` | Deps with version, license, direct/transitive |
| `getProjectVulnerabilities` | Vulns filtered by severity/reachability |
| `getReachabilityFlows` | Data flow paths for a vuln |
| `getSecurityPosture` | Org-wide aggregate score + counts |
| `getVulnerabilityDetail` | CVE detail with EPSS/CVSS/KEV |
| `getPackageReputation` | OpenSSF score + downloads + license for a package |
| `getEPSSScore` | Exploit probability |
| `checkCISAKEV` | Is CVE in active exploitation catalog |
| `listPolicies` | Org's package/status/PR-check policies |
| `analyzeUpgradePath` | Safe upgrade target for a vulnerable dep |

All tools tagged `safe`. No approval flow needed in MVP.

## Backend Structure

```
backend/src/
  routes/
    aegis-v2.ts                 # All endpoints above. Replaces old aegis.ts + aegis-task-step.ts.
  lib/
    aegis-v2/
      chat.ts                   # streamText wrapper, system prompt, tool registry invocation
      system-prompt.ts          # Tight system prompt: role, tool usage rules, org context
      provider.ts               # Always returns Gemini Flash via getPlatformProvider()
      tools/
        index.ts                # Tool registry export
        list-projects.ts
        get-project-summary.ts
        ...                     # 12 tool files
      types.ts                  # Thread, Message, ToolPart types shared with frontend
```

**Delete entirely:**
- `backend/src/routes/aegis.ts` (1682 lines)
- `backend/src/routes/aegis-task-step.ts`
- `backend/src/lib/aegis/` (33 files)
- `backend/src/lib/learning/` (4 files)
- `backend/aider-worker/` (6 files — archive to a branch first for later reference)

## Frontend Structure

```
frontend/src/
  app/pages/
    AegisPage.tsx               # NEW — 2-column dashboard. Replaces existing AegisPage.
  components/aegis/
    ThreadList.tsx              # Left sidebar
    ChatPane.tsx                # Main area with streaming
    MessageBubble.tsx           # User/assistant message rendering
    ToolCallCard.tsx            # Collapsed tool-call UI with expand
    MarkdownRenderer.tsx        # react-markdown + remark-gfm + syntax highlighting
    PromptChips.tsx             # Welcome-state suggestions
    ChatInput.tsx               # Textarea + send button
```

**Delete entirely:**
- Existing `AegisPage.tsx`, `AegisPanel.tsx`, `AegisManagementConsole.tsx`, `AegisContent.tsx`, `aegis-stream.ts`
- Tests: `aegis-phase7b.test.tsx`, `aegis-learning-ui.test.ts`, `ai-aegis.test.ts`

## Non-Functional Requirements

- **Performance:** First-token latency < 1s. Tool calls complete < 3s for simple reads, < 8s for aggregations (e.g., `listProjects` across large orgs).
- **Data volume:** Thread list expected < 100/user. Messages per thread < 200 typical. No pagination needed for MVP.
- **Streaming reliability:** Use Vercel AI SDK's built-in reconnect/error handling. Show error bubble if stream breaks; user can regenerate.
- **Real-time:** No Supabase Realtime in MVP (all chat state is per-user and owned by the active browser session).

## RBAC Requirements

- Gate behind `interact_with_aegis` organization permission (already defined in `organization_roles.permissions` JSONB).
- All endpoints check permission via middleware.
- Thread RLS already restricts to `user_id = auth.uid()`.

## Dependencies / Integrations

- **Vercel AI SDK** (`ai`, `@ai-sdk/google` for Gemini, `@ai-sdk/react` useChat) — already in package.json
- **`getPlatformProvider()`** in `backend/src/lib/ai/provider.ts` — already returns Gemini Flash when `GOOGLE_AI_API_KEY` set
- **Supabase Auth + service role client** — standard
- **Existing tables** for tool queries: `projects`, `project_dependencies`, `project_vulnerabilities`, `vulnerability_reachability`, `semgrep_findings`, `package_policy_code`, `project_status_code`, `pr_check_code`, plus the `dependencies`, `packages`, OpenSSF/GHSA cached data

## Success Criteria

1. **End-to-end chat loop works:** All 3 suggested prompts produce correct, grounded answers using the right tools.
2. **Daily usage for a week:** Henry uses Aegis instead of manually clicking through the vuln page for 7 consecutive days.
3. **Tool accuracy:** Spot-check ~20 responses — no hallucinated CVEs, package names, or counts.
4. **UI polish:** Threads, chat, tool cards, empty state, streaming all feel production-grade.

## Explicitly Out of Scope (Next Milestones)

- Aider fix worker / write actions (triggerAiFix, suppress, accept risk, create policy)
- Contextual floating panel on vuln/project pages (v2 UI)
- Memory / "teach Aegis" / pgvector recall
- Slack bot, automations, scheduled jobs
- Incidents, tasks/sprints, learning system
- BYOK provider config
- Usage / spend dashboards
- Approval flow for dangerous tools
- Rate limiting
- Message branch tree (we'll do truncate-and-rerun only)
- Unit tests (add once loop is proven)

## Open Questions

- **Sparkle icon for nav:** which exact icon? Lucide `sparkles`, `shield`, or custom?
- **Aider worker archive strategy:** delete outright or move to `archive/aider-worker/` branch for later?
- **System prompt tone:** formal "security engineer" voice or casual "teammate" voice? Suggest we start casual and adjust.

## Scope Summary

**MVP (this milestone):** Chat page, 12 read-only tools, threads per-user, streaming with tool cards, edit/regenerate, permission gate. Nuke everything else.

**Next milestone (post-MVP):** Re-introduce Aider worker + 1–2 write tools (e.g., `triggerAiFix`, `suppressVulnerability`) with approval flow.

**Later milestones:** Memory recall, contextual panel on vuln pages, Slack integration, automations, incidents, autonomy.
