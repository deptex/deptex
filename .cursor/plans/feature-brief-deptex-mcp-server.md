# Feature Brief: Deptex MCP Server

## 1. Feature Name & One-liner

**Deptex MCP Server** (`mcp.deptex.io`) — a remote, standards-compliant Model Context Protocol server that exposes Aegis's tool surface (findings, reachability, depscore, policies, and approval-gated write actions) to any MCP client (Claude Code, Cursor, Windsurf, Codex, VS Code, OpenAI ChatGPT Desktop, etc.), so a developer in an existing Deptex org can drop Aegis into their IDE with one OAuth flow and operate on their org's real security state using their IDE's own LLM.

## 2. Problem Statement

Aegis today lives only in the Deptex web UI. Developers who already use Claude Code / Cursor / Windsurf in their IDE have to leave their flow to ask Aegis anything — losing the benefit of in-context, mid-refactor, pre-commit security answers. Meanwhile every ASPM competitor (Snyk Studio, Endor MCP, Semgrep MCP, Wiz MCP, Checkmarx Developer Assist) has staked this ground in late 2025 / early 2026; first-mover time on "the security MCP server your IDE knows" is a real strategic window.

A legal side-benefit: Anthropic's Feb 2026 terms banned subscription passthrough for third-party products but explicitly preserved **MCP-tool-calls-originated-from-Claude-Code as subscription-covered**. This is the one narrow path where Deptex can put Aegis in front of Claude Max users at zero token cost to Deptex, without violating Anthropic's commercial terms.

Not solved today: developers can't use Aegis from their IDE at all; Deptex has no footprint in the agentic-IDE distribution channel; org admins have no way to govern what tools their devs are running against Deptex data from external clients.

## 3. Competitive Landscape

(Full research in `.cursor/plans/research-aegis-multiyear.md` §2.10. Condensed here.)

- **MCP standard**: Linux Foundation / AAIF since Dec 2025. OAuth 2.1 + PKCE + Dynamic Client Registration + RFC 8707 Resource Indicators + `/.well-known/oauth-protected-resource` is the mandatory auth shape. Streamable HTTP is the canonical remote transport.
- **Snyk MCP Server** (GA March 2026): CLI-packaged (`snyk mcp`). Auth bridges Snyk CLI login. Tool surface heavy on "scan this path" rather than "query my org."
- **Semgrep MCP** (open source at `github.com/semgrep/mcp`): closest to our shape. Tools: `security_check`, `semgrep_scan`, `semgrep_findings` (platform-authed), `get_abstract_syntax_tree`, `semgrep_rule_schema`. Works stdio + Streamable HTTP + SSE. Runs for auth'd platform use, supports in-IDE "vibe-coding guardrail."
- **GitHub Remote MCP Server** (GA Sep 2025): spec-compliant OAuth 2.1 reference implementation. Secret-scanning on tool-call inputs added March 2026. This is our auth reference.
- **Wiz MCP Server**: slash-command UX (`#wiz remediate`). Translates NL queries into workflows. Workflow-oriented.
- **Endor Labs MCP**: integrates with Copilot/Cursor/Claude Code/Windsurf for in-IDE dep vuln checks. Real-time AT-type.

**What we're borrowing:**
- Auth stack from GitHub Remote MCP (OAuth 2.1 + PKCE + DCR + `/.well-known/oauth-protected-resource`).
- Tool-surface shape from Semgrep (findings platform, RBAC-enforced, tenant-data-aware — unlike Snyk Assist).
- Registry listings (MCP official + Smithery + Glama) from all three big players' playbook.

**Where we differentiate:**
- **Reachability + depscore + policy-as-code first-class in tool outputs** — no competitor surfaces these as structured MCP responses.
- **Policy-as-code write tools** (`propose_policy_change`, `simulate_policy_change`) — no one lets an IDE-based agent mutate a sandboxed, version-controlled JS policy.
- **Approval-flow bridge to existing `aegis_approval_requests`** — we have HITL infrastructure competitors don't.
- **Open-core** — Semgrep is the only fully-OSS MCP we compete with; ours ships as part of the broader Deptex open-core distribution.

## 4. User Stories

**Primary persona:** a developer who is already a user of a Deptex-using organization and uses Claude Code, Cursor, Windsurf, or Codex as their daily driver.

- **As a developer**, I want to install the Deptex MCP server in my IDE in under a minute with a single OAuth flow, so that I can ask my agent about our org's security state without leaving my editor.
- **As a developer**, I want to ask my agent "what are the critical vulns in the payments service?" and get reachability-weighted results, so that I don't have to context-switch to the Deptex web UI to understand priority.
- **As a developer**, I want my agent to propose a fix and have the fix kicked off as a Deptex-managed job (not a half-applied patch in my working tree), so that the fix goes through our existing review/approval/CI pipeline.
- **As a developer**, I want the agent to tell me when an action needs human approval, so that I don't accidentally autonomously change a policy or trigger a fix on prod.
- **As an org admin**, I want to enable/disable MCP access for my org, see which users have active MCP sessions, revoke any session, and review an audit log of every MCP tool call, so that I retain RBAC control over what agents do with my data.
- **As an org admin**, I want the MCP permissions tied to our existing `interact_with_aegis` / `trigger_fix` / `manage_aegis` RBAC, so that there's one governance surface for agent access.
- **As an auditor**, I want every MCP tool call written to the same audit ledger as web Aegis calls (`aegis_tool_executions`), so that compliance reviews cover both surfaces with no extra integration work.

## 5. Competitive Research Summary (for this specific feature)

Tool-surface patterns across the five competitors:

| Competitor | Read tools | Write tools | Approval pattern |
|---|---|---|---|
| Snyk | `snyk_scan`, `snyk_findings` | None (scan-only) | N/A |
| Semgrep | `security_check`, `semgrep_findings`, `get_abstract_syntax_tree` | `semgrep_scan_with_custom_rule` | No HITL; client-side approve |
| GitHub | Issues, PRs, code search, workflows | PR comment, issue create, branch push | GitHub token scope |
| Wiz | Issue discovery, impact | In-PR `#wiz remediate` slash | Chat-confirmation pattern |
| Endor | Dep vulns, package risk | None (read-only today) | N/A |

**No competitor has solved structured HITL approval for write tools via MCP.** This is Deptex's wedge: surface `{status: 'pending_approval', approval_url}` and route through the existing `aegis_approval_requests` infrastructure for a formal audit trail.

## 6. Data Model

### New tables

**`mcp_oauth_clients`** — Dynamically-registered client applications.
```
id                    uuid PK
client_id             text UNIQUE NOT NULL           -- returned to client on DCR
client_secret_hash    text                           -- bcrypt; nullable for public clients (PKCE-only)
client_name           text NOT NULL                  -- from DCR request
redirect_uris         text[] NOT NULL
grant_types           text[] NOT NULL                -- e.g. ['authorization_code', 'refresh_token']
token_endpoint_auth_method text                      -- 'none' (public/PKCE) or 'client_secret_post'
scope                 text                           -- requested scopes, space-separated
software_id           text                           -- optional client self-identification
software_version      text
registered_by_user_id uuid                           -- who triggered the DCR (nullable for open DCR)
created_at            timestamptz DEFAULT now()
revoked_at            timestamptz
```

**`mcp_oauth_authorization_codes`** — Short-lived codes for PKCE exchange.
```
id                    uuid PK
code_hash             text NOT NULL                  -- sha256
client_id             text NOT NULL REFERENCES mcp_oauth_clients(client_id)
user_id               uuid NOT NULL REFERENCES auth.users(id)
default_organization_id uuid REFERENCES organizations(id)  -- picked during consent
redirect_uri          text NOT NULL
code_challenge        text NOT NULL                  -- PKCE S256 challenge
code_challenge_method text NOT NULL DEFAULT 'S256'
scope                 text NOT NULL
resource              text NOT NULL                  -- RFC 8707; must equal our canonical URI
created_at            timestamptz DEFAULT now()
expires_at            timestamptz NOT NULL           -- 5 min TTL
consumed_at           timestamptz
```

**`mcp_oauth_access_tokens`** — Active and historical access/refresh tokens.
```
id                    uuid PK
token_hash            text UNIQUE NOT NULL           -- sha256 of bearer token
token_type            text NOT NULL                  -- 'access' | 'refresh'
client_id             text NOT NULL REFERENCES mcp_oauth_clients(client_id)
user_id               uuid NOT NULL REFERENCES auth.users(id)
default_organization_id uuid REFERENCES organizations(id)
scope                 text NOT NULL
resource              text NOT NULL                  -- RFC 8707 bound URI
expires_at            timestamptz NOT NULL
created_at            timestamptz DEFAULT now()
revoked_at            timestamptz
last_used_at          timestamptz
last_user_agent       text
last_ip_hash          text                           -- hashed; privacy-preserving
```

**`mcp_tool_executions`** — Extension of `aegis_tool_executions` behavior; may be a `source='mcp'` addition to the existing table rather than a new table. Decision: **extend `aegis_tool_executions`** with `source TEXT NOT NULL DEFAULT 'web'` + new columns `mcp_client_id TEXT`, `mcp_token_id UUID`. Reuses the audit ledger we already have.

### Reused tables

- **`aegis_approval_requests`** — dangerous MCP tool calls write rows here with `source='mcp'` and return `approval_id` + `approval_url` to the MCP client.
- **`aegis_tool_executions`** — extended per above for unified audit across web + MCP.
- **`organization_roles.permissions`** — RBAC check on every MCP tool call (`interact_with_aegis` required to call any tool; per-tool additional checks below).
- **`organization_ai_providers`** — not used by MCP itself (MCP users bring their own LLM via their IDE); but write tools that internally call Deptex-hosted models (rare) still route through this.

### Realtime

- Approval UI in Deptex web subscribes to `aegis_approval_requests` inserts (already uses Supabase Realtime). No new subscription needed.
- MCP sessions list in Org Settings subscribes to `mcp_oauth_access_tokens` inserts/updates for live "X users connected" indicator.

### Background jobs

- **QStash: `mcp_token_reaper`** (hourly) — revoke access tokens past `expires_at` and DCR'd clients older than 90 days with no active tokens.
- **QStash: `mcp_approval_timeout`** (every 5 min) — expire `aegis_approval_requests` where MCP-originated and `expires_at < now()`, return to the agent as `{status: 'approval_expired'}` next poll.

## 7. API Endpoints

### OAuth / discovery endpoints (public, unauthenticated)

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/oauth-protected-resource` | RFC 9728 metadata. Points to auth server. |
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 metadata. Lists authorization/token/registration/revocation endpoints. |
| POST | `/oauth/register` | RFC 7591 Dynamic Client Registration. Returns `client_id`. |
| GET | `/oauth/authorize` | RFC 6749 authorization endpoint. Renders consent UI. Requires existing Supabase session (redirects to Deptex login if not). |
| POST | `/oauth/token` | Token endpoint. Accepts `authorization_code` + PKCE verifier, issues access/refresh token. Enforces RFC 8707 `resource` param. |
| POST | `/oauth/revoke` | RFC 7009 token revocation. |
| POST | `/oauth/introspect` | RFC 7662 token introspection (internal use; for MCP resource server validating its own tokens). |

### MCP protocol endpoint (token-authenticated)

| Method | Path | Purpose |
|---|---|---|
| POST | `/mcp` | Streamable HTTP endpoint. JSON-RPC 2.0 MCP messages. Validates bearer token → resolves to user + default_org → dispatches tool calls. |
| GET | `/mcp` | SSE endpoint for server-initiated notifications (approval-resolved push, etc.). Optional for clients that support it. |

### Deptex web-UI endpoints (session-authenticated)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/mcp/status/:organizationId` | Is MCP enabled for org? Active session count. |
| POST | `/api/mcp/enable/:organizationId` | Toggle MCP on/off for org. Requires `manage_integrations`. |
| GET | `/api/mcp/sessions/:organizationId` | List active tokens for users in this org. Admin view. |
| DELETE | `/api/mcp/sessions/:organizationId/:tokenId` | Revoke a specific token. |
| GET | `/api/mcp/my-sessions` | User's own active MCP sessions. |
| DELETE | `/api/mcp/my-sessions/:tokenId` | Revoke own token. |
| GET | `/api/mcp/audit/:organizationId` | Audit log of MCP tool calls (filter view on `aegis_tool_executions`). |
| GET | `/api/mcp/install-config/:organizationId` | Generate ready-to-paste config JSON for the requesting user (pre-filled with OAuth URL for this server). |

## 8. MCP Tool Surface

All tools prefixed with `deptex_`. RBAC required on every call; multi-tenant org routing via hybrid default + per-call override.

### Meta tools (no org required)

| Tool | Purpose | Perm |
|---|---|---|
| `deptex_list_my_organizations` | Enumerate orgs the authenticated user belongs to. Returns id + name + default flag. | authenticated |
| `deptex_set_default_organization` | Change session default. Persists on `mcp_oauth_access_tokens.default_organization_id`. | authenticated |
| `deptex_whoami` | User info + default org + scopes. | authenticated |

### Read tools (all require `interact_with_aegis` in target org)

| Tool | Purpose |
|---|---|
| `deptex_list_projects` | Paginated project list. Filters: `team_id`, `asset_tier_id`, `status_id`, `name_contains`. |
| `deptex_get_project_summary` | Aggregate: dep count, vuln counts by severity, depscore trend, last extraction. |
| `deptex_list_findings` | Paginated unified findings across vulns + secrets + Semgrep. Filters: `project_id`, `severity`, `reachability_level`, `depscore_min`, `kev_only`, `assigned_to`, `status`. |
| `deptex_get_finding_detail` | CVSS, references, reachability detail, fix options, policy evaluation, history. |
| `deptex_get_reachability_flows` | Atom flows for a finding: entry points, sinks, code snippets, flow length. |
| `deptex_get_depscore_breakdown` | Composite score breakdown: severity × EPSS × reachability × asset-tier × EPD. Lets agent explain prioritization. |
| `deptex_list_dependencies` | Project deps with versions, transitive flag, malicious indicator, is_outdated. |
| `deptex_get_package_reputation` | OpenSSF Scorecard + downloads + malicious signals composite. |
| `deptex_list_policies` | Org policies (package/status/pr_check) metadata + version history pointer. |
| `deptex_check_policy` | Dry-run: evaluate current policies against a hypothetical dep or PR context. |
| `deptex_search_dependencies` | Semantic search across all org deps. |
| `deptex_get_extraction_status` | Latest `extraction_job` per project. |
| `deptex_read_extraction_logs` | Paginated logs for a run_id (diagnostic tool). |

### Write tools — low danger (require `interact_with_aegis`; no approval)

| Tool | Purpose |
|---|---|
| `deptex_add_finding_note` | Append a markdown note to a finding. Immutable history. |
| `deptex_acknowledge_finding` | Mark as acknowledged (soft state, per-user). |

### Write tools — medium danger (require `interact_with_aegis`; approval required)

| Tool | Purpose | Additional perm |
|---|---|---|
| `deptex_suppress_finding` | Suppress a finding with reason + expiry. | `manage_aegis` recommended |
| `deptex_assign_finding` | Set owner (team member id). | `manage_aegis` |

### Write tools — high danger (require explicit per-tool perm; approval required)

| Tool | Purpose | Perm |
|---|---|---|
| `deptex_propose_policy_change` | Create a `project_policy_changes` or `organization_package_policies` change with proposed code; returns preview + approval_url. | `manage_policies` |
| `deptex_simulate_policy_change` | Dry-run proposed policy code against current org state; returns diff impact without writing. (Not approval-gated; doesn't mutate.) | `manage_policies` |
| `deptex_trigger_fix` | Kick off Aider-based fix for a finding. Returns approval_url → approved → queues Fly.io job → returns fix_job_id. | `trigger_fix` |
| `deptex_post_pr_comment` | Post an Aegis-attributed comment on a GitHub/GitLab/Bitbucket PR tied to a project. | `trigger_fix` (as proxy) |

**Day 1 ships all of the above (per Henry's "full write surface Day 1 with approval flow baked in" decision).**

### Approval flow shape

Dangerous tool call returns:
```json
{
  "status": "pending_approval",
  "approval_id": "aa_01J...",
  "approval_url": "https://deptex.io/aegis/approvals/aa_01J...",
  "preview": { /* tool-specific preview payload */ },
  "expires_at": "2026-04-24T12:00:00Z"
}
```

Agent presents this to user. User clicks the URL, lands on Deptex web UI approval screen (reuses existing `aegis_approval_requests` pattern with a small MCP-source badge). Approves or rejects.

Agent polls `deptex_get_approval_status(approval_id)` (or receives server-push via `GET /mcp` SSE). Returns:
- `{status: 'approved', result: {...}}` — tool executes and result returns
- `{status: 'rejected', reason: '...'}`
- `{status: 'pending'}` — keep polling
- `{status: 'expired'}` — re-invoke the original tool if you still want the action

### Tool output shape

All tools return structured JSON. Paginated tools include `next_cursor`. Large payloads (e.g. `get_project_summary` on 50-project org) use `limit`/`cursor`/`filter` server-side to stay under 50KB responses. For truly huge reads (org-wide finding export), return a job handle via the existing extraction-job pattern.

## 9. Multi-Tenant Org Routing (the elegant UX)

Henry chose "whatever's the elegant UX solution." Here's the design:

1. **Install flow sets a default.** During OAuth consent (§10), user picks a default organization. Stored on `mcp_oauth_access_tokens.default_organization_id`. Single-org users never think about this.
2. **Every org-scoped tool accepts optional `organizationId`.** Not passed → uses default. Passed → overrides for that call only.
3. **`deptex_list_my_organizations`** is always available so agents can discover alternatives.
4. **`deptex_set_default_organization`** mutates the session default (for the current token) for the rest of the session.
5. **Tool descriptions reference the default.** `"List findings. Uses your default organization unless organizationId is set."` This makes agents behave predictably.

Result: single-org users see `deptex_list_findings(severity='critical')` work with no org param. Multi-org users can say "Aegis, check all my orgs" and the agent fans out. Nobody has to learn MCP-session-state concepts.

## 10. OAuth Consent Flow (Deptex-hosted)

User in Claude Code runs `claude mcp add deptex` (or clicks the "Connect to Claude Code" deep-link from our web UI).

1. Claude Code hits `GET /.well-known/oauth-protected-resource` → learns auth endpoints.
2. Claude Code POSTs `/oauth/register` with its metadata → receives `client_id`.
3. Claude Code opens browser to `/oauth/authorize?client_id=...&code_challenge=...&redirect_uri=...&scope=...&resource=https://mcp.deptex.io`.
4. Deptex validates existing Supabase session cookie (redirects to login if absent).
5. **Consent screen** renders:
   - "Claude Code wants to connect to Deptex"
   - List of scopes being requested (readable descriptions)
   - **Default organization picker** (dropdown of orgs user belongs to, auto-selected if only one)
   - "Authorize" / "Deny" buttons
6. User authorizes → Deptex issues auth code → redirects back to Claude Code's localhost callback.
7. Claude Code POSTs `/oauth/token` with code + PKCE verifier → receives access + refresh token.
8. Claude Code stores tokens, begins sending MCP requests to `/mcp` with `Authorization: Bearer <token>`.

Refresh: automatic via refresh token, no user interaction.

## 11. Frontend Views

All live in the **Org Settings → new "Integrations" tab** (Henry's choice).

### A. Integrations tab redesign
Group the existing integration cards (GitHub, GitLab, Bitbucket, Slack) under a section header; add a new **"AI Agents & IDE"** section with the MCP card as the first entry.

### B. Deptex MCP card
- Status pill: "Disabled" / "Enabled" / "X active sessions"
- Admin toggle (requires `manage_integrations`): enable/disable MCP for the org
- "Connect to your IDE" primary button (available to any user with `interact_with_aegis` once org is enabled)
- Link: "View audit log" / "Manage sessions"

### C. "Connect to your IDE" modal
Four tabs:
1. **Claude Code** — "Run this command in your terminal:" + `claude mcp add deptex https://mcp.deptex.io` + "Or click this link to auto-install:" deep-link button
2. **Cursor** — Copy-paste JSON blob into `.cursor/mcp.json` + visual showing path + docs link
3. **Windsurf** — Analogous
4. **Other / Generic** — JSON config with annotations for other MCP clients

All four tabs: "Once installed, the first tool call will prompt you to authorize in your browser."

### D. OAuth consent screen
- Clean full-screen layout, Deptex branding
- "`<Client Name>` wants to connect to Deptex on behalf of `<User Email>`"
- Scopes (human-readable):
  - Read your organizations' findings, dependencies, and policies
  - Propose policy changes and fix actions (with per-action approval)
- **Default organization picker** (searchable dropdown of user's orgs)
- "Authorize" (primary) + "Deny" (secondary) buttons

### E. MCP Sessions page (Org Settings → Integrations → "MCP Sessions" link)
Admin-only view. Table:
- User | Client Name | Created | Last Used | Scopes | Default Org | Revoke
- Empty state: "No active MCP sessions. When a member connects their IDE, sessions will appear here."
- Bulk "Revoke all" with confirmation modal.

### F. MCP Audit Log page
Re-uses the existing `aegis_tool_executions` viewer with a filter preset `source = 'mcp'`. Adds a column: Client Name. No new component — configure existing table.

### G. "My IDE Connections" (user personal settings)
Small per-user view: "You have X active MCP sessions across Y organizations. [Manage]." Clicking opens their token list with revoke buttons. Prevents the "admin revokes me; I can't see why" problem.

### H. Approval inbox
Zero new UI. Existing `aegis_approval_requests` detail page gains:
- A small "from MCP" badge when `source='mcp'`
- Client name shown alongside user name ("triggered from Claude Code")
- The structured preview (diff for fix, policy change preview, etc.) renders as it already does

## 12. User Flows

### Flow 1: First-time install (Claude Code user, has Deptex account)

1. User opens Aegis in Deptex web UI → sees "Use Aegis in your IDE" banner → clicks
2. Redirected to **Org Settings → Integrations → Deptex MCP card**
3. Clicks "Connect to your IDE" → modal opens, Claude Code tab selected
4. Clicks the deep-link button → Claude Code opens with install prompt
5. Claude Code posts `/oauth/register`, opens browser to `/oauth/authorize`
6. User is already logged into Deptex → consent screen appears immediately
7. User picks default org (pre-filled if single-org), clicks "Authorize"
8. Redirected back to Claude Code → install confirmed
9. In Claude Code: user asks "what critical vulns are in our payments service?" → agent calls `deptex_list_findings(severity='critical', project_name_contains='payments')` → results stream in

### Flow 2: First-time install (Cursor user)

Same as Flow 1 except step 4 is "Copy JSON" + paste into `.cursor/mcp.json`. Next invocation of an MCP tool in Cursor triggers browser-based OAuth, user lands on consent screen from step 6 onward.

### Flow 3: Triggering a fix from the IDE

1. User in Claude Code: "Aegis, there's a critical CVE in lodash here. Fix it."
2. Agent calls `deptex_get_finding_detail(finding_id='...')` → returns context
3. Agent calls `deptex_trigger_fix(finding_id='...', fix_strategy='minimum_upgrade')`
4. Server returns `{status: 'pending_approval', approval_url: '...', preview: {...}}`
5. Agent renders preview inline and shows the approval URL
6. User clicks URL → Deptex web UI approval screen with full preview
7. User approves → server writes to `aegis_approval_requests` (existing), enqueues Fly.io Aider job
8. Agent polls `deptex_get_approval_status(approval_id)` → returns `{status: 'approved', result: {fix_job_id: '...'}}`
9. Agent can call `deptex_get_fix_status(fix_job_id)` to watch progress
10. Fix job opens a PR in the user's repo when done

### Flow 4: Org admin enables/governs MCP

1. Admin visits Org Settings → Integrations → Deptex MCP card
2. Toggles "Enabled for organization"
3. Invites team members via existing flows; members with `interact_with_aegis` can install
4. Admin occasionally views MCP Sessions page to see who's connected, from what client
5. Admin views Audit Log filtered to `source='mcp'` after an incident
6. Admin revokes a specific token if a teammate leaves or a laptop is lost

### Flow 5: Non-admin user without `interact_with_aegis` tries to use MCP

1. User installs MCP, completes OAuth successfully (they have a Deptex account)
2. First tool call returns `{error: 'forbidden', message: 'You do not have Aegis access in <org_name>. Ask an admin to grant interact_with_aegis.'}`
3. No degraded read-only mode (Henry's choice). Clean failure.

## 13. Edge Cases & Error Handling

- **User is in zero Deptex orgs** — consent screen shows "You must belong to at least one Deptex organization." No token issued.
- **User's default org gets deleted** — next tool call returns `{error: 'default_organization_unavailable', remediation: 'set_default_organization'}`.
- **User removed from the org their token was issued against** — token continues to authenticate but every tool call returns `{error: 'forbidden'}`. Admin-initiated revocation recommended via audit tooling.
- **Token expired mid-call** — standard 401 + `WWW-Authenticate: Bearer` header. Client refreshes via refresh token automatically.
- **Approval expires before user approves** — `aegis_approval_requests.expires_at` passes; poll returns `{status: 'expired'}`. Agent re-invokes the tool if needed.
- **Approval already approved but agent disconnected** — next poll returns `{status: 'approved', result: {...}}`. Result is still produced because approval triggers the side-effect server-side, not the poll.
- **Rate limit hit** — `429` with `Retry-After` header. Client backs off.
- **Large finding list (10k+ findings)** — default `limit: 100`; require cursor; hard-cap at 500 per page.
- **MCP org disabled by admin while user's session is live** — next tool call returns `{error: 'mcp_disabled_for_org'}`. Existing tokens not revoked (admin can do that separately) but functionally locked out.
- **`organizationId` param refers to an org the user doesn't belong to** — `{error: 'not_a_member', organization_id: '...'}`.
- **Policy simulation errors (invalid JS in proposed code)** — return the sandbox error clearly; don't consume an approval slot.
- **Tool result too large for MCP response** — stored to `aegis_tool_executions.result_overflow_blob`; tool returns `{partial: true, result_url: 'https://deptex.io/.../results/<id>'}`.
- **OAuth DCR abuse (someone registering millions of clients)** — rate-limit `/oauth/register` by IP + require captcha above threshold. Auto-prune clients with no token activity in 90 days.
- **Claude Code / Cursor client bug sending malformed JSON-RPC** — return standard JSON-RPC 2.0 error responses; log to telemetry.
- **Secrets in tool-call inputs** — adopt GitHub's March 2026 pattern: scan incoming tool params for obvious credentials (private keys, GitHub tokens) and reject with `{error: 'credential_detected_in_input'}`.

## 14. Non-Functional Requirements

### Performance
- **Tool-call latency**: p50 < 400ms, p99 < 2s for read tools on normal-sized orgs (10 projects, 1000 findings).
- **Pagination**: default limit 50, max 500. Every paginated tool returns `next_cursor` when more results exist.
- **Large org scaling**: a 100-project org with 50k findings must still return `list_findings` page 1 in < 2s. Requires DB indexes on `findings(organization_id, severity, depscore DESC)` and similar.
- **OAuth token exchange**: p99 < 500ms (pure DB lookup + JWT sign).
- **MCP endpoint throughput**: 500 RPS sustained across the fleet (initial target).

### Reliability
- Eventual consistency OK for audit log writes (can batch/async). Everything else (tool results, approval state) must be strongly consistent.
- If `/mcp` endpoint is down, MCP clients retry; users see error in IDE. No silent data loss.
- Background jobs (token reaper, approval expiry) are idempotent.

### Rate limits (defaults; configurable per-org)
- **Per-token read tools**: 60 req/min (1/sec sustained)
- **Per-token write tools**: 10 req/min
- **Per-token dangerous tools (approval-gated)**: 30 req/hour
- **Per-org aggregate**: 10× single-token limits
- **Per-org-per-day budget**: 10,000 total MCP tool calls (alerts at 80%)
- Enforced via Redis sliding-window counters (existing pattern in `backend/src/lib/rate-limit`).

### Security
- Bearer tokens SHA-256 hashed in DB (never stored plain).
- Refresh tokens single-use (rotating).
- Audit every tool call with user+client+token+tool+params+result shape (params sanitized for secrets; full result hashed, stored-on-demand).
- PKCE required for all client types (public and confidential).
- RFC 8707 Resource Indicators required — reject tokens not bound to `mcp.deptex.io`.
- No cross-origin access from browser (MCP is server-to-server; no CORS allow for MCP endpoint).
- Every dangerous tool call produces an `aegis_approval_requests` row; never execute without approval.
- Secret scanning on tool-call inputs (GitHub March 2026 pattern).
- Claude-subscription-passthrough: **not implemented.** Per Anthropic terms. Explicitly documented as out-of-scope.

### Scalability
- MCP protocol endpoint is stateless; scales horizontally behind LB.
- Token validation is DB-lookup cached in Redis (60s TTL).
- Approval polling should eventually move to SSE push (optional client support); poll is fallback.

## 15. RBAC Requirements

### Org-level enablement
- **`manage_integrations`** — required to enable/disable MCP for an org (existing permission in `organization_roles.permissions`).

### Per-user tool access
- **`interact_with_aegis`** — required for any MCP tool call. Base gate.
- Tool-specific additional permissions layered on top:
  - `manage_aegis` — for memory, approval-override, sessions-revoke tools
  - `manage_policies` — for `deptex_propose_policy_change`
  - `trigger_fix` — for `deptex_trigger_fix`, `deptex_post_pr_comment`
  - `view_activities` — for audit-log-reading tools

### Org-level governance
- Admins can revoke any member's MCP session via Org Settings → MCP Sessions page.
- Admins see all MCP activity in the audit log.
- Admin disabling MCP for an org immediately rejects all new tool calls; existing tokens are not revoked but become non-functional.

## 16. Dependencies

### External
- MCP spec `2025-06-18` (authorization) and `2025-xx` (streamable HTTP) compliance
- OAuth 2.1 / PKCE / DCR / RFC 7009 / RFC 7662 / RFC 8707 / RFC 9728 implementations
- Potentially use `@modelcontextprotocol/sdk` for protocol plumbing (npm)
- JWT / token signing — use existing infrastructure (no new libs beyond `jose` if not already present)
- Fly.io — MCP server deploys alongside existing backend or as a separate app

### Internal Deptex primitives
- **Supabase auth** (`backend/src/middleware/auth.ts`) — bridging user sessions to MCP OAuth
- **RBAC** (`organization_roles.permissions` JSONB, existing checker)
- **Aegis approval flow** (`aegis_approval_requests`, existing routes `/api/aegis/approvals/*`)
- **Aegis tool registry** (`backend/src/lib/aegis/tools/`) — MCP tool handlers call into these
- **Rate-limit library** (`backend/src/lib/rate-limit/`) — existing Redis-backed sliding window
- **Cost-cap library** (`backend/src/lib/ai/cost-cap.ts`) — not used directly (MCP uses user's LLM, not ours) but audit log plumbing is shared
- **Supabase Realtime** — approval notifications
- **QStash cron-dispatcher** — token reaper, approval expiry

### Blocks nothing
- The fix-execution engine (Anchor 1 / Phase 5) is called by `deptex_trigger_fix` but doesn't have to exist yet — tool can return "fix job queued, not yet started" until Anchor 1 ships. Write tools that require Anchor 1 will function but the actual fix execution is a separate milestone.
- Flow-builder write tools (`deptex_propose_flow_change`) are NOT in this phase; they arrive alongside flow-builder GA.

### Blocked by nothing
- Can ship without Phase 0 agent-core refactor. MCP is a new surface; it can ship on its own before Aegis web UI migrates to AI SDK v6 `ToolLoopAgent`.

## 17. Success Criteria

### Shipping success (acceptance criteria)
- A user with an existing Deptex account can install the MCP server in Claude Code via the "Connect to Claude Code" button in under 60 seconds from click to first tool call.
- All 20+ Day-1 tools (meta + read + write + dangerous) work and return well-shaped results.
- Dangerous tools route through `aegis_approval_requests` and the existing approval UI in Deptex web.
- Org admins can enable/disable MCP per-org, see active sessions, and revoke any session.
- Every MCP tool call produces a row in `aegis_tool_executions` with `source='mcp'`.
- Published on the official MCP Registry (registry.modelcontextprotocol.io) and Smithery.
- Deptex MCP audits pass: OAuth 2.1 compliance (checked with a public MCP client conformance tool), PKCE required, DCR works, RFC 8707 bound tokens.
- Documentation page on `deptex.io/docs/mcp` describing install, tool surface, permissions.

### Product success (measure over the first 90 days post-GA)
- **Installs**: 50+ orgs with at least one active MCP session in the first month.
- **Usage**: median org with MCP enabled makes 200+ tool calls/week by month 3.
- **Write tool usage**: ≥10% of MCP tool calls are write tools (signals trust, not just read-browsing).
- **Approval completion rate**: ≥75% of approval requests raised from MCP are approved (rejections are fine; expiries are bad — means UX broken).
- **MTTR delta**: for orgs with MCP enabled, critical-vuln MTTR drops by 20% vs orgs without (correlates IDE-in-flow benefit).
- **First-day activation**: 40% of installers make ≥5 tool calls in their first session.
- **Support load**: < 5 support tickets/week related to MCP install or auth flow by month 3.

### Strategic success
- Deptex appears in Claude Code's default MCP discovery suggestion list (requires MCP Registry listing + adoption signal).
- Semgrep-style brand presence: when a dev searches "MCP server security findings," Deptex is in the top 3 results.
- Two or more competitor deals lost in Q3 2026 cite "Deptex's IDE integration was the tiebreaker."

## 18. Open Questions (to resolve during `/plan-feature`)

1. **Separate Fly.io app or same backend?** Should MCP endpoint (`/mcp`, `/.well-known/*`, `/oauth/*`) run in the existing backend or in a new `deptex-mcp` Fly app on a dedicated subdomain (`mcp.deptex.io`)? Arguments both ways; likely same backend initially with subdomain routing, split later if load demands.
2. **MCP SDK choice.** Use `@modelcontextprotocol/sdk` (official TypeScript SDK) or hand-roll? Official SDK handles protocol framing; hand-roll gives more control over streaming and error shapes. Default: use the SDK, wrap where needed.
3. **OAuth server — build vs buy.** Is there an existing OSS component that handles RFC 9728 + RFC 8707 + DCR out of the box (e.g., `node-oidc-provider`, Supabase's auth gateway)? Worth a 1-day research spike during the planning phase.
4. **Is there any scenario where we'd want Claude-subscription passthrough to this server?** Per research: no, it's prohibited. But worth flagging as a hard "do not build" boundary.
5. **Consent scope granularity.** Should the OAuth consent screen offer fine-grained scope selection (e.g., "read-only, no fixes") or is it all-or-nothing per org? Default recommendation: all-or-nothing, since per-tool RBAC is already enforced server-side; adding scope granularity is Phase 2 polish.
6. **Refresh token rotation strategy** — standard rotating single-use, or sliding-window long-lived? Default: rotating.
7. **Client name surfacing in audit log** — is the `software_id` / `client_name` from DCR trustworthy enough to display verbatim, or do we need a curated list of "verified clients" (Claude Code, Cursor, Windsurf) with unverified clients labeled "Unverified third-party"? Likely need the curated list for the audit-log UX to be trustworthy.
8. **Marketing/launch coordination** — when Henry decides to publicly launch, what does that look like? Not required for building; flagged for later.
9. **Tool-level approval override by org policy** — should an admin be able to force approval on tools we've marked low-danger (e.g., "no `deptex_add_finding_note` without approval in our org")? Defer to Phase 1.5.
10. **Tool result redaction policies** — what if an org classifies certain findings as "do not expose to IDE" (e.g., internal-only security incidents)? Needs an `organization_mcp_settings.excluded_finding_ids` or tag-based filter. Defer to Phase 1.5.

## 19. Scope & Rollout

Henry's directive: build the complete plan, don't artificially time-box. So: one complete feature spec, split into reviewable PR-sized milestones for clean rollout.

### Milestone A — Foundation: OAuth + read tools + install UX
- OAuth 2.1 server endpoints (authorize/token/revoke/introspect/DCR)
- `/.well-known/oauth-protected-resource` + `/.well-known/oauth-authorization-server`
- MCP `/mcp` endpoint with JSON-RPC plumbing (via `@modelcontextprotocol/sdk`)
- All 3 meta tools + 13 read tools
- Backend tables (`mcp_oauth_*`, extend `aegis_tool_executions.source`)
- Org Settings → Integrations tab redesign with MCP card
- "Connect to your IDE" modal with all 4 client tabs
- OAuth consent screen with default-org picker
- MCP Sessions admin page
- Docs page on `deptex.io/docs/mcp`
- Publish on MCP Registry + Smithery
- End-to-end test: Claude Code + Cursor + Windsurf install and first tool call
- Feature-flagged on a per-org opt-in

### Milestone B — Write tools + approval flow
- Low-danger writes (`deptex_add_finding_note`, `deptex_acknowledge_finding`)
- Medium-danger writes (`deptex_suppress_finding`, `deptex_assign_finding`) with approval
- High-danger writes (`deptex_propose_policy_change`, `deptex_simulate_policy_change`, `deptex_trigger_fix`, `deptex_post_pr_comment`)
- Full approval flow: `{status: 'pending_approval'}` + web UI badge + polling + optional SSE push
- Approval inbox gets `source='mcp'` filter + "from `<client name>`" label
- Secret scanning on tool-call inputs
- Per-tool additional RBAC enforcement

### Milestone C — Governance, polish, launch-ready
- User "My IDE Connections" view in personal settings
- Audit log filtered view with client-name column
- Per-org rate-limit + budget settings admin UI (edit defaults)
- Token reaper + approval expiry crons
- Registry listings complete (Registry + Smithery + Glama + `.well-known` server card)
- Public docs with tool reference, install guide per client, troubleshooting
- Analytics dashboard for MCP usage (admin view: tool-call volume, top tools, approval rate)
- Conformance with public MCP client testers
- Remove feature flag; GA

### Follow-up (Phase 1.5 — not in this brief)
- Anonymous / sign-up-from-IDE funnel for OSS acquisition (deferred per Henry's Round 1 choice)
- Tool-level org-override on approval requirements (Open Question 9)
- MCP-visible finding redaction policies (Open Question 10)
- Fine-grained scope selection in OAuth consent (Open Question 5)
- Additional write tools (flow-builder mutation, org-management tools) as those primitives mature
- Server-sent events for approval-resolved push
- Deep integration with Phase 5 Aegis Fix pipeline

---

**Recommended next step**: Run `/plan-feature` on this brief to produce the implementation plan (milestone A specifically, since B and C depend on A).
