# Research: Aegis — Multi-Year Roadmap to a Billion-Dollar Autonomous Security Engineer

> **Historical context (2026-05-09):** This plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. Where this plan references BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, or `AI_ENCRYPTION_KEY` for AI key envelopes, treat those as historical implementation details — current AI runs on platform keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from worker env). `AI_ENCRYPTION_KEY` itself is still in use, but only for `organization_registry_credentials` (IaC v2 Phase 1).

> **Status:** Research brief. Not a plan. Output of a 15-agent parallel research spike April 2026. Drives the next `/interview` → `/plan-feature` cycle.
> **Horizon:** 2–3 years, ~14 phases, designed to be parallelizable across multiple concurrent worktrees.
> **Frame:** Aegis today is a chat. This doc is the argument for what Aegis must become to anchor an open-core ASPM platform that credibly competes with Snyk/Endor/GitHub Advanced Security/Cycode/Jit, while building moat that none of them can copy.

---

## 0. Pre-flight: The Paused Worktree

Before any roadmap work: **`worktree-aegis-v2` is sitting on an orphan history** with no common ancestor against `main`. A cherry-pick of the 27 aegis-v2-specific commits onto `aegis-v2-rebased` was started; the nuke-v1 commit's 105 conflicts are partially resolved (5 content conflicts still unresolved in `DocsPage.tsx`, `HelpCenterPage.tsx`, `docsConfig.ts`, `routes.tsx`, `api.ts`). A safety tag `backup/worktree-aegis-v2-pre-rebase` is in place.

Three decision paths, with strong lean:

1. **Abandon the rebase. Start `aegis-v3` fresh off `main` using this research doc as the spec.** The v2 UI work (thread list, pin/archive, search, markdown renderer, streaming chat) is ~2 days of reimplementation against the new backend architecture proposed below. The conflict surface is so high and Phase 7B re-architects so much that preserving v2 commits buys little. Recommended.
2. Squash all v2 work into a single commit on a fresh branch off `main`. Preserves net state, loses history.
3. Push through the cherry-pick. 27 commits × ~20–100 conflicts each = a day or two of mechanical merging for a result that gets discarded by Phase 1 of this roadmap anyway.

Path 1 is the right move *if you agree with the roadmap below*. If you'd rather incrementally evolve v2 into v3, path 2 is the fallback. Path 3 is strictly dominated.

---

## 1. Current State in Deptex

Aegis today is a thread-based chat UI with streaming against Gemini Flash (platform-paid Tier 1). The backend surface exposes 12 read-only tools for discovery/assessment (`list_projects`, `get_project_summary`, `list_project_dependencies`, `get_project_vulnerabilities`, `get_reachability_flows`, `get_security_posture`, `get_vulnerability_detail`, `get_package_reputation`, `get_epss_score`, `check_cisa_kev`, `list_policies`, `analyze_upgrade_path`) wired from `backend/src/lib/aegis/tools/index.ts`. No fix execution. No write-side actions. No plans. No automations. No PR comments. Threads support pin/archive (per-user in v2), streaming, markdown, auto-title, participants/invite-codes, and a deferred group-chat UI. The `AegisPanel` frontend component is project-scoped via `context_type/context_id`. Row-level tables in `aegis_*` schema are already built out for a much larger vision: `aegis_tasks`, `aegis_task_steps`, `aegis_tool_executions`, `aegis_approval_requests`, `aegis_memory` (vector 1536), `aegis_automations` (cron + QStash schedule IDs), `aegis_event_triggers`, `aegis_org_settings` (operating_mode, budgets, tool_permissions, pr_review_mode), `aegis_slack_config`, `aegis_activity_logs`, `aegis_inbox`, `security_debt_snapshots`. This is the skeleton of the Phase 7B plan already in the roadmap — the tables exist, the logic to use them largely doesn't yet.

Critically, Deptex has **adjacent primitives no competitor combines**:
- **Reachability** (Phase 1–3 shipped): tree-sitter usage extraction across 8 languages + 34 framework entry-point detectors + EPD/data-flow scoring + atom reachable flows (`project_reachable_flows`, `project_usage_slices`, `project_code_snippets`).
- **Policy-as-code** with `isolated-vm` sandbox, user-written in Monaco, three separated tables (`organization_package_policies`, `organization_status_codes`, `organization_pr_checks`), git-like change history, SSRF-protected fetch.
- **Flow builder** (in flight on `worktree-flow-builder`): visual policy/notification/status composition, `flows` + `flow_runs`.
- **Extraction pipeline** (cdxgen + dep-scan + semgrep + trufflehog + tree-sitter in one worker on Fly.io), job queue (`extraction_jobs`), real-time logs (`extraction_logs`), recovery RPCs.
- **BYOK AI**: `organization_ai_providers` AES-256-GCM-encrypted keys across OpenAI/Anthropic/Google, rate limits, `monthly_cost_cap`, `ai_usage_logs`.
- **Aider worker**: Python fix-worker on Fly.io with poll-based job claim, git-ops, strategies.
- **Depscore**: composite scoring with `asset_tier_id` multipliers, tiered reachability weights (confirmed=1.0, data_flow=0.9, function=0.7, module=0.5), EPD factor.
- **Audit trail**: `activities`, `aegis_tool_executions`, `aegis_activity_logs`.

The Phase 7B plan in the roadmap sketches the agentic loop, 50+ tools, memory, automations, Slack bot, PR review, compliance autopilot, and proactive intelligence. This research refines and re-sequences that plan against 2026 competitive reality.

---

## 2. Competitive Landscape

### 2.1 Snyk — the incumbent
Snyk shipped **Evo** (Oct 2025 preview → Mar 2026 GA as AI-SPM), a multi-agent OODA-loop platform for securing AI-native apps; launched **Snyk Studio** (Mar 2026, 300+ enterprise Studio customers) positioning as "Secure at Inception" via MCP; **Agent Fix** (formerly DeepCode AI Fix) ships hybrid LLM+symbolic verifier with 80% accuracy claim over 8 languages. **Snyk Assist** has zero tenant-data access — it's a docs bot, not an agent over your findings. **Reachability** GA in Python (Dec 2025–Jan 2026) and Java. **Fix PRs / Upgrade PRs / Backlog PRs** with 21-day cooldown. **Snyk MCP Server + Snyk API/Web MCP Server** GA Mar 2026. Pricing moved to **Platform Credit Consumption** Jan 2026. Team $25/contributing-dev/mo. Strategic direction: Snyk is pivoting from AppSec to **AppSec + AI-SPM**, and they're treating MCP as the primary integration surface.

### 2.2 Endor Labs — the reachability pioneer
Rebuilt around **AURI** (Mar 2026) — multi-agent platform on a **Code Context Graph** (500M code embeddings). Four pillars: code generation, code review, backlog reduction, full-stack reachability. **AI SAST** (Nov 2025) claims 95% auto-suppressed FPs, 4.5% TP, 0.5% unknown. **Endor Magic Patches / Patch Factory** is unique: AI-assisted backported security fixes served via Artifactory/Nexus proxy with 14-day SLO. **Full-Stack Reachability** (post-Autonomous Plane acquisition Feb 2026) extends reachability into container OS packages. **Agentic Code Security Benchmark** (2026) is their thought-leadership asset. No open-core. No BYOK. Quote-only pricing (ACV ~$34.7k median).

### 2.3 Socket + Aikido — developer-first SCA/ASPM
**Socket**: Coana acquisition (Apr 2025) brought function-level reachability; **Socket Fix 2.0** auto-remediates with autopilot mode and smart multi-step upgrade planning; **Supply Chain Attack Campaigns** tracks campaigns (Shai-Hulud, Nx) as entities; typosquat + homoglyph + AI-slopsquat detection. Free tier for OSS forever; Team $25/dev/mo. **Aikido**: 16-scanner ASPM, **Aikido Infinite** (Feb 2026) continuous autonomous AI pentest, **Aikido Attack** sub-hour pentest, 95% FP reduction via **reachability + LLM contextual analysis**, AutoFix across 13 languages, strong privacy posture (no code leaves customer env). Series B $60M at $1B valuation Jan 2026.

### 2.4 Semgrep — the pattern everyone else imitates
**Semgrep Assistant**: Analyze + Auto-triage + Remediation guidance + Autofix. **Memories** (2025) — natural-language snippets of org-specific context, auto-suggested from triage activity, admin-editable. Fortune-500 beta: 5 memories → 2.8× FP reduction, one rule dropped 580 FPs after one memory. ~60% of new findings auto-triaged across 1000+ deployments; 95% user agreement; 96% agreement with internal researchers on a 2000-finding `promptfoo` eval set. **Autofix verifies itself** by re-running Semgrep on the patched file. **Multimodal** (Mar 2026): rule-engine + LLM-reasoning hybrid, 8× more TP at 50% fewer FPs, 61% IDOR precision vs 22% for Claude Code alone. AI is **not enterprise-gated** — this is the price-pressure threat. MCP server is open source.

### 2.5 GitHub Advanced Security + Copilot — the 800-lb incumbent
**Copilot Autofix** (GA Aug 2024, free for public repos, ~50% of alert types in JS/TS/Java/Python; expansion to Shell/Dockerfile/Terraform/PHP Q2 2026). **Coding Agent** (GA 2025, assign an issue to `@copilot` → draft PR streamed with commits on a GitHub Actions runner). **Security Campaigns** (GA Apr 2025) batch-remediates 1000+ historical findings. GHAS unbundled Apr 2025: **Secret Protection** $19/committer + **Code Security** $30/committer; both now on Team plan. **Remote GitHub MCP Server** GA Sep 2025; MCP secret-scanning Mar 2026. GitHub owns the PR chrome; this is a moat. What we can't break: native placement in the PR, identity + audit trail already paid for, compatibility scores from millions of CI runs, default-on for public repos. What we can beat: cross-repo organizational context (GitHub's unit of analysis is the repo; our unit is the org).

### 2.6 GitLab + Checkmarx + Veracode — enterprise tier
**GitLab Duo**: `/vulnerability_explain`, `/vulnerability_resolve`, **Agentic SAST Vulnerability Resolution** (Beta), **Security Analyst Agent** (Apr 2026) for batch triage, **Root Cause Analysis** for CI failures. Duo Enterprise add-on $19/user over Duo Pro. **Checkmarx One Assist** (GA Aug 2025): AI Query Builder, Policy Assist, Insights Assist, Developer Assist for AI-native IDEs. **Veracode Fix** (trained on Veracode's proprietary vetted dataset) + **Veracode Fix for SCA** (Mar 2026).

### 2.7 Emerging ASPM agent-native vendors
- **Cycode** — most aggressive agent narrative. **AI Exploitability Agent** (Black Hat 2025) + **AI Fix & Remediation Agent** + **Cycode Maestro** orchestrator + **ACSA** for AI-generated code. Claims 99% MTTR reduction, 17× close rate, 46% auto-remediation on high-risk violations. Closest to true multi-step autonomous fix execution in ASPM.
- **Jit** — architecturally most agent-native. Explicit **Plan → Execute → Reflect → Respond** loop. Core/Pre-Built/Custom agent layers. Public per-dev pricing with free tier. Owns its scanning engines. Wiz partnership bridges ASPM/CNAPP.
- **Apiiro** — **Deep Code Analysis Risk Graph**, **AI-SAST** (Dec 2025), **Guardian Agent** (pre-create prevention), **AI Threat Modeling** (Apr 2025). Fortune-10 ACV $5M, F100 $4M. Median ACV $55k, 50-seat min.
- **Legit Security** — 4 named AI agents + **Ask Legit** + **AI Security Command Center** + **AI-BOM** + **Remediation Campaigns** (industry-first framing, Oct 2025).
- **ArmorCode (Anya)** — 40B findings corpus is their moat. MCP Server. AI Code Insights. Named Leader IDC MarketScape ASPM 2025.
- **Wiz Code** — Dazz acquisition ($450M Nov 2024) + Wiz SAST (public preview). In-PR workflow: `#wiz remediate` slash command. **Wiz MCP Server** for natural-language queries.
- **OX Security** — VibeSec Active ASPM, OX AI Security Agent.
- **Arnica** — pipelineless architecture (no CI/CD dependency). **Arnie AI** (Nov 2025). Developer Feedback Loop auto-generates SAST rules from historical dismissals.
- **Mend** — AI Red Teaming. Legacy SCA brand.
- **Orca** — SAST/AI bolt-on to CNAPP core.

### 2.8 AI coding platforms — UX reference designs
- **Claude Code** — Skills (SKILL.md), Subagents, Hooks, MCP, permission model with `Tool(specifier)` syntax, CLAUDE.md + auto-memory, Plan mode, `ultrareview` / `ultraplan`. Cloud in Anthropic-managed VMs with branch isolation + GitHub proxy. Pricing Pro $20 / Max 5x $100 / Max 20x $200. **Commercial reality: subscription passthrough is banned as of Feb 2026, enforced Apr 2026. MCP-as-tool is allowed and subscription-covered.**
- **Cursor** — Plan Mode, Clarifying Questions tool, Background Agents in cloud VMs, **Bugbot** ($40/user/mo including 200 PR-reviews, with **Learned Rules** from signals), parallel agents up to 8 via worktrees (2.0), Subagents + Skills (2.4), Agents Window (3.0), Self-hosted cloud agents (2026).
- **Google Jules** — plan-preview + reasoning + diff before execution; Scheduled Tasks (Dec 2025); environment snapshots; memory; audio changelog. Free $0 / Pro $19.99 / Ultra $124.99. Data-exfil CVE in planner with network egress → lesson: don't give the planner exfil-capable tools.
- **Devin (Cognition)** — ACU pricing ($2.25/ACU), Devin 2.0 agent-native IDE, Devin 2.2 self-verification loop + desktop access. Devin Wiki auto-indexed repo docs. Devin Annual Review 2025: security vuln fixes in 1.5 min (20× speedup).
- **OpenAI Codex** — async cloud agent, bundled into ChatGPT Plus through Pro tiers; 5-hour rolling rate windows; in-app browser; automatic approval review agent; **Code Review skill as first-class task type** (separate budget).
- **GitHub Copilot Coding Agent** — GA Sep 2025. Assign issue → `@copilot` → draft PR streamed from GitHub Actions runner. 1 session = 1 premium request. Business/Enterprise admin-enabled.
- **Windsurf (Codeium)** — Cascade single-agent two-mode (Write/Chat), click-to-edit Previews, SWE-1/1.5 in-house models, Flow awareness (session state stream), Workflows (reusable rulebooks).
- **OpenHands** — MIT + source-available enterprise Helm chart. **AgentDelegateAction** inside one event stream. Docker runtime + browser + VNC + VS Code. **OpenHands Vulnerability Fixer** (Mar 2026): Trivy scan → parallel per-CVE fix agents → auto-PR. This is conceptually Aegis-fix-sprint shipped as OSS.
- **Sourcegraph Batch Changes + Cody/Amp** — declarative multi-repo refactor with 10k-changeset UI, repo-scoped tokens, signed commits, bulk rebase. **Amp** agent spun out as standalone company 2025.
- **Replit Agent 3** — checkpoints as the universal unit (snapshot + undo + pricing + audit), REPL-based self-testing (browser simulation), up to 200-min unsupervised runs, effort-based pricing.
- **Aider** — tree-sitter repo map + PageRank, architect/editor split, 18+ providers via LiteLLM, auto-commits, conventional commit messages via weak model, scripted headless, watch mode. **Already our fix worker foundation.**

### 2.9 AI SDK v6 + workflow frameworks
Vercel AI SDK v6 is the runtime. Key primitives Aegis is not yet using: **`ToolLoopAgent`** (replaces hand-rolled loops), **`needsApproval: true`** per-tool (replaces our custom approval-request rows), **typed `UIMessage` data parts** (replaces ad-hoc JSON-in-text), **`Output.object` inside `streamText`** (replaces `generateObject`), **`experimental_telemetry` + `TelemetryIntegration`** hooks (replaces wrapping the stream for cost-cap), **`consumeStream` + `resumeStream`** (for disconnect-resilient Aegis sessions), **`dynamicTool` + `jsonSchema()`** (for MCP and user-defined tools). Pin `zod@^4.1.8` to kill TS2589. Mastra adds `createWorkflow` + `stateSchema` + suspend/resume but couples memory/logger — adopt the shapes, not the runtime. LangGraph's `interrupt()` + checkpointer is the right mental model for our QStash task-step system; implement the shape, not the dep.

### 2.10 MCP + Anthropic commercial terms
MCP is now a Linux Foundation (AAIF) standard as of Dec 2025. 10k+ active public servers Mar 2026. OAuth 2.1 + PKCE + Resource Indicators (RFC 8707) + Dynamic Client Registration + `/.well-known/oauth-protected-resource` metadata is the mandatory auth pattern. Claude Code and Cursor both first-class MCP clients. **Legal/technical verdict on Claude subscription passthrough**: prohibited for any third-party product; Anthropic Feb 2026 terms + Apr 2026 enforcement. BUT — **MCP tool calls originated from Claude Code itself are subscription-covered**. The legal BYO-Claude path is: ship `mcp.deptex.io`, user installs in Claude Code, Aegis tools show up in their IDE, user's Max quota pays for the model, Deptex never bills tokens.

### 2.11 Vuln feeds + compliance
**Phase 1 feeds (free, high-signal):** OSV.dev (primary, aggregates 40+ ecosystems), EPSS (daily, prioritization), CISA KEV (hourly poll for ransomware-tag flips), OpenSSF Scorecard (supply-chain health), GHSA (ecosystem-timely advisories). **Phase 2 (when justified):** NVD 2.0 API (CVSS/CPE), Grype/Trivy DB (container images), Sonatype OSS Index (paid post-Apr 2026). Skip Snyk Intel (proprietary). **Compliance**: SOC2 CC4.1/7.1, ISO 27001 A.8.28 (new 2022), PCI DSS 4.0 6.3.2 SBOM-required fully enforced Mar 2025. Every `extraction_jobs` row + `vulnerability_findings.resolved_at` + `pr_check` run + SBOM export is already a 1:1 evidence artifact — tagging them to control IDs and publishing a signed append-only ledger is a $3–8k/yr add-on SKU per org.

---

## 3. Landscape Synthesis

### Table-stakes (every serious competitor ships these — we must match or die)
- AI fix suggestions rendered inline in PR with one-click commit
- AI vulnerability explanation + exploitability reasoning in plain English
- AI-powered false-positive suppression (60–95% FP reduction) driven by reachability
- Auto-remediation PRs with configurable auto-merge policies
- SARIF-native finding ingestion + export
- In-IDE agent extension (Cursor/VS Code/Windsurf/Copilot host targets, not our product)
- MCP server as an integration surface
- SBOM import/export (CycloneDX + SPDX)
- Compliance dashboard for SOC 2 / ISO 27001
- GitHub App installation with short-lived tokens
- Slack/webhook alerting on supply-chain events
- Malicious package + typosquat detection
- Real-time PR commenting with warn vs block gating
- Root-cause analysis for failing CI (GitLab Duo bar)

### Frontier (2–3 vendors have it, still emerging — advance here to feel modern)
- Multi-step autonomous fix agents with plan preview (Cycode Maestro, Jit, GitHub Coding Agent)
- Agent-specific memory systems that auto-suggest from triage actions (Semgrep Memories)
- Self-verification loops (Semgrep re-runs engine on patched file; Devin 2.2; Replit REPL-testing)
- Autonomous AI pentesting (Aikido Infinite; uncommon but rising)
- AI-SPM (securing the customer's AI systems, not just their dep code) — Snyk Evo, Apiiro AI-BOM
- AI-native Risk Graphs (Endor's Code Context Graph with 500M embeddings)
- Batch-fix orchestration ("Security Campaigns" — Legit, GHAS)
- Function-level reachability as the triage gate (Socket via Coana, Endor, Aikido)
- ACU / premium-request / credit-consumption pricing (Devin, Codex, GHAS, Snyk Jan 2026)
- Agentic SAST rule authoring (Checkmarx AI Query Builder, Arnica's learned rules)
- MCP server advertised as primary integration surface (Snyk Studio stance)

### Whitespace (no one does well — Deptex's wedge)
- **Open-core autonomous security agent.** Every agent-native ASPM is closed. OpenHands is the only OSS generalist agent with a serious security demo; nobody has a full open-core autonomous security agent product.
- **Aegis-inside-Claude-Code via MCP (the legal BYO-Claude path).** Snyk Studio and Endor MCP are constrained read-mostly tools. No vendor has shipped a full-write-capable security agent as an MCP server that runs on the user's Claude subscription. This is a massive free-tier acquisition funnel.
- **Policy-as-code as a first-class tool the agent uses.** Vendors have policy OR agents. Deptex has `package_policy_code` / `project_status_code` / `pr_check_code` in `isolated-vm`. Expose these as Aegis tools and you get agent-evaluated, customer-authored, sandboxed, version-controlled security logic that can't be replicated without re-architecting an entire policy engine.
- **Reachability + EPD + asset-tier composite scoring** as the prioritization substrate. No vendor publicly surfaces depscore-style per-org configurable scoring with tiered reachability weights and asset-tier multipliers. Snyk's Priority Score is opaque. Endor's is proprietary. We can publish ours and let customers tune it.
- **Self-hosted Aegis runtime with BYOK (or local-LLM via baseURL).** Enterprise privacy wedge. Cursor shipped "self-hosted cloud agents" 2026; we match + extend with the whole stack.
- **Declarative multi-repo Security Campaigns.** Sourcegraph Batch Changes as applied to CVE remediation — nobody has shipped this in security specifically. 10k-changeset dashboards with conflict/rebase handling is enterprise table stakes nobody in AppSec has.
- **Fix verification via the same extraction pipeline.** Semgrep re-runs the engine on the patched file; nobody in SCA does this with dep-scan + tree-sitter + depscore as the oracle. Deptex already owns both sides.
- **Flow-builder + AI agent integration.** Visual composition of policy/notification/status workflows plus Aegis as an agent that reads AND mutates flows. No vendor has this UI at all.
- **Scheduled agent pods.** Jules has Scheduled Tasks for coding work. Nobody has scheduled security agent pods ("every Monday 7am Aegis triages the backlog, emails a digest, opens fix PRs for anything above depscore 800") as a productized feature.
- **Compliance evidence ledger derived from scan history.** Drata/Vanta have ledgers but no AppSec scan depth. We have the scans, they have the auditor relationships — we build the control-mapping layer ourselves.
- **Org graph multiplayer + Aegis.** The org-graph multiplayer canvas shipping on `worktree-org-graph-multiplayer` is already a novel UX for security teams; plugging Aegis into the canvas (spawn from a node, reason about policy across teams, etc.) is completely unmatched.

### Deptex's standing today
- **Ahead on reachability depth** (tree-sitter + 34 framework detectors across 8 langs, Phase 1–3 shipped, matches/beats Socket/Endor).
- **Ahead on policy-as-code** (customer-authored JS in `isolated-vm` with SSRF protection and git-like versioning beats every vendor's templated policy DSL).
- **At parity on depscore** (we've built the composite, but no competitor has shipped anything equivalent publicly — we can move to "ahead" by making it configurable and published).
- **Ahead on open-core positioning** (no agent-native competitor is open-source).
- **Behind on agent execution** (no fix execution, no plans, no memory in use, no PR review, no MCP server).
- **Behind on enterprise distribution** (GitHub Apps depth, enterprise auth, audit log integration all need work).
- **Behind on compliance** (Phase 15 SLAs + PCI/ISO/SOC2 evidence ledger not yet built).
- **Behind on IDE presence** (no VS Code / Cursor / Claude Code extension; MCP server is the cheapest path).

---

## 4. Deptex's Moat (what the reachability + flow builder + extraction + policy engine let us do that competitors can't)

Five specific combinations are uniquely possible in Deptex:

1. **Reachability-weighted AI triage with customer-auditable weights.** Agent reads `reachability_level` + `reachability_details` from `project_dependency_vulnerabilities`, applies `organization_asset_tiers.environmental_multiplier`, and proposes "dismiss" only when confidence clears a threshold the customer can inspect and edit. Competitors either don't expose the weights (Snyk, Endor) or don't have the reachability depth (Aikido's reachability is rougher per public docs).
2. **Policy-as-code agent tools.** Expose `evaluate_package_policy`, `evaluate_project_status`, `evaluate_pr_check`, `propose_policy_change`, `simulate_policy_change` as Aegis tools. The agent can dry-run a new policy against real data before proposing a version-controlled change with git-like diff in `project_policy_changes`. No vendor has both a policy sandbox and an agent that writes to it.
3. **Flow-builder as Aegis's action surface.** Aegis doesn't just send notifications — it composes flow nodes in the flow-builder (on `worktree-flow-builder`), configures branching, and deploys. The agent is editing the workflow graph itself. OX Security's "policies-as-code during authoring" is the closest analogue; none ship a visual flow-builder.
4. **Extraction worker as verification oracle.** Every fix attempt re-runs the specific sub-stage that surfaced the finding (dep-scan/Semgrep/TruffleHog/tree-sitter-usage) on the patched tree. Pass required before PR opens. Semgrep does this single-engine; Deptex can do it across all five detectors in one worker. Replit's REPL-based self-testing and OpenHands's Trivy re-scan pattern is the reference.
5. **Open-core deployment topology.** Aegis + BYOK + local-LLM-via-baseURL + self-hosted extraction worker + self-hosted Aegis runtime → enterprise-privacy deployment where code never leaves the customer network. OpenHands Cloud Self-hosted (Nov 2025) is the reference point; no ASPM vendor has done this.

These aren't "features we could build." They're structural consequences of primitives we already have that competitors do not and cannot easily clone.

---

## 5. Feature Catalog (exhaustive, tagged)

Tags: **TS** = table-stakes, **P+** = parity-plus (we match + UX edge), **D** = differentiator (our moat), **M** = moonshot. Sizes: S (1–2 wk), M (3–6 wk), L (8–16 wk), XL (multi-phase). Dependencies cited.

### Layer A — Agent Core Platform (prerequisite for everything else)
| # | Feature | Tag | Size | Depends on |
|---|---|---|---|---|
| A1 | AI SDK v6 `ToolLoopAgent` migration + `needsApproval` + `UIMessage` data parts | TS | M | — |
| A2 | Skills (`.aegis/skills/<name>/SKILL.md`) — user-editable playbooks with YAML frontmatter, progressive disclosure, `/skill-name` slash commands | D | L | A1 |
| A3 | Subagents (Explore/Plan/Fix/Review archetypes) with isolated context windows + shared event stream | P+ | L | A1 |
| A4 | Hooks on tool-use / session / prompt events (PreToolUse / SessionStart / PostToolUse / UserPromptSubmit) | P+ | M | A1 |
| A5 | Plan mode as default for write-side operations; editable Markdown plan; Clarifying-Questions tool that doesn't block | P+ | M | A1 |
| A6 | Permission rules with `Tool(specifier)` syntax; managed enterprise rules > org > user > session | P+ | M | A1 |
| A7 | Checkpoints — unify snapshot/undo/pricing/audit per task step; preview diff; pricing unit | D | L | A1, existing QStash task-steps |
| A8 | pgvector memory scoped per-project/per-rule/per-vuln-class; auto-suggest from triage; admin review queue (Semgrep Memories pattern) | P+ | M | existing `aegis_memory` |
| A9 | Asymmetric confidence gating: separate chains for "close finding" vs "annotate finding" with calibrated thresholds | P+ | M | A8 |
| A10 | Telemetry + cost-cap via `TelemetryIntegration`; per-tool latency, error taxonomy | TS | S | A1 |
| A11 | Disconnect-resilient streams (`consumeStream` + `resumeStream` via Redis registry) | TS | S | A1 |
| A12 | Background agents on Fly.io ephemeral VMs with session URL; `/teleport` session back to local | D | L | A3, A7 |

### Layer B — Write-side Tools (the engine for fix/org-mgmt)
| # | Feature | Tag | Size | Depends on |
|---|---|---|---|---|
| B1 | Tool registry refactor: typed schemas, danger levels (read / write / dangerous), per-tool cost budget | TS | M | A1, A6 |
| B2 | Aider-integrated `trigger_fix` tool: clean file-set from reachability, BYOK routing, test/lint hooks, Conventional Commits, sandboxed Fly machine | D | L | existing aider-worker, Phase 7 |
| B3 | Fix verification loop: re-run dep-scan/Semgrep/TruffleHog/tree-sitter on patched tree before PR opens | D | M | extraction-worker, B2 |
| B4 | Policy engine as Aegis tools: `evaluate_policy`, `propose_policy_change`, `simulate_policy_change`, `merge_policy_change` | D | L | existing policy-engine, `project_policy_changes` |
| B5 | Flow-builder as Aegis tools: `read_flow`, `propose_flow_node`, `simulate_flow`, `deploy_flow` | D | L | flow-builder |
| B6 | Org management tools: `invite_user`, `assign_to_team`, `configure_integration`, `set_notification_rule`, `adjust_asset_tier` (all with approval gates) | D | M | existing routes |
| B7 | PR tools: `comment_on_pr`, `request_review`, `push_branch`, `open_pr`, `merge_pr` (via GitHub App installation tokens) | TS | M | GitHub App |
| B8 | Slack/Discord/Teams tools: `post_message`, `open_thread`, `set_status` | P+ | S | existing Slack config |
| B9 | Ticketing tools: `create_jira_issue`, `create_linear_issue`, `create_github_issue` (MCP-wrapped) | TS | S | B13 |
| B10 | Extraction control: `queue_extraction`, `read_extraction_logs`, `diagnose_extraction_failure`, `retry_extraction` | D | M | existing extraction |
| B11 | SBOM tools: `generate_sbom`, `import_sbom`, `diff_sbom`, `export_vex` | TS | M | cdxgen |
| B12 | Internet tools: `fetch_changelog`, `fetch_cve_detail`, `fetch_release_notes`, `fetch_advisory`, `web_search` (with planner-egress ban) | TS | S | B13, Jules lesson |
| B13 | MCP client layer: wrap GitHub/Slack/Jira/Linear/Semgrep/Supabase as MCP rather than hand-coded | P+ | M | A1 |

### Layer C — Plan / Campaign / Batch Orchestration
| # | Feature | Tag | Size | Depends on |
|---|---|---|---|---|
| C1 | Plan-then-execute task system with durable checkpoints (LangGraph `interrupt()` pattern on QStash) | P+ | L | A7, existing `aegis_tasks` |
| C2 | Security Campaigns — declarative multi-repo batch-fix spec (target set + transform + gate) with 1000+-changeset dashboard | D | XL | B2, B7, C1 |
| C3 | Security Sprints — AI-planned per-org remediation sprints (pick top-N by depscore × reachability × asset tier, estimate cost, one-click commit) | D | L | B2, C1 |
| C4 | Scheduled agent pods (cron-bound agent routines) — weekly triage, daily digest, monthly compliance report | D | M | QStash, existing `aegis_automations` |
| C5 | Event-driven agent triggers — Aegis initiates chat/task on `critical_cve_found`, `extraction_failure`, `policy_violation`, `pr_opened` | D | M | existing `aegis_event_triggers` |
| C6 | Parallel fix agents — fan-out sprint to N per-finding agents each in its own Fly machine + worktree, coordinator merges | P+ | L | C3, A12 |
| C7 | Sprint progress viewer — streaming logs + screenshots + diff previews + conflict resolution UI | TS | M | C3 |
| C8 | Self-verification before PR — agent runs tests + extraction re-scan + policy eval; only PRs on pass | D | M | B3 |
| C9 | Per-step rollback; if step N fails and we don't auto-fix, rewind to N-1 checkpoint | P+ | S | A7, C1 |

### Layer D — PR Review & Inline Comments
| # | Feature | Tag | Size | Depends on |
|---|---|---|---|---|
| D1 | GitHub App (not PAT) — short-lived install tokens, check-runs + PR comments attributed to Aegis | TS | M | octokit.js |
| D2 | Reachability-aware PR review — comment per affected finding with depscore diff, EPD factor, proposed fix preview | D | M | D1, reachability |
| D3 | One-click "fix this finding" from PR comment → spawns background fix agent → updates PR | D | M | D2, C6 |
| D4 | Bulk PR reviewer for `ultrareview`-style multi-agent deep review (dep-review + secret-scan + semgrep-triage + depscore-diff in parallel subagents) | D | L | A3, D2 |
| D5 | GitLab MR + Bitbucket PR parity | TS | M | D1, existing webhooks |
| D6 | "Assign to Aegis" via issue/PR assignee or label — matches Copilot UX | P+ | S | D1 |
| D7 | Conversational PR refinement — `@aegis also sanitize X` in PR comment drives next commit | P+ | M | D1, C1 |

### Layer E — Agent-of-Agents + Multiplayer
| # | Feature | Tag | Size | Depends on |
|---|---|---|---|---|
| E1 | Aegis group chats — multiple humans + Aegis on one thread; typing/presence; @-mentioning humans or specialist subagents | D | L | deferred v2 work, A3 |
| E2 | Agent Swarm management pane — active runs, queue, cost, owners, intervention buttons (OpenHands AgentHub-style) | P+ | M | A3, C1 |
| E3 | Agent handoff — Aegis writes a ticket, another agent picks up; owner changes tracked in `aegis_task_steps` | D | M | A3, B9 |
| E4 | Human-in-team delegation — Aegis tags the right human (by owner, RBAC, SLA) via team graph | D | M | A3, org-graph |
| E5 | Org-graph canvas integration — spawn Aegis from a node; reason across teams/projects | D | L | org-graph-multiplayer |

### Layer F — Intelligence & Research
| # | Feature | Tag | Size | Depends on |
|---|---|---|---|---|
| F1 | Vuln feed integration — OSV.dev primary + EPSS + CISA KEV + OpenSSF Scorecard + GHSA fallback; hourly polling with diff alerting | TS | M | — |
| F2 | Patch researcher — given CVE, find fix commit; assess backport risk (Snyk breakability-style + Pixee-style usage-diff via our tree-sitter AST) | D | L | F1, reachability |
| F3 | Changelog/release-notes summarizer with breaking-change detection (Conventional Commits + `MIGRATION.md` heuristics + LLM fallback) | P+ | M | F1 |
| F4 | Typosquat + homoglyph detector (Levenshtein + download ratio + Cyrillic/Greek Unicode confusables) | TS | M | — |
| F5 | Supply-chain campaign tracker — model active campaigns (Shai-Hulud, Nx) as entities; "are we affected right now?" dashboard | P+ | M | F1 |
| F6 | AI-slopsquat detector — cross-reference LLM-hallucinated package names against real deps | D | S | F4 |
| F7 | Malicious package agent — real-time LLM+signature on new dep adds (Socket/Checkmarx pattern) | TS | M | F1 |
| F8 | Threat model agent — STRIDE/PASTA drafts from repo context + framework detection + route enumeration | P+ | L | Apiiro reference |
| F9 | AI-BOM — inventory of models, datasets, MCPs, agent skills in customer code | D | M | AURI reference, F1 |
| F10 | Agent Red Teaming — autonomous adversarial testing of deployed AI agents (Snyk Agent Red Teaming, Aikido Infinite) | M | XL | moonshot |

### Layer G — Compliance & Governance
| # | Feature | Tag | Size | Depends on |
|---|---|---|---|---|
| G1 | Control-mapping layer — tag `extraction_jobs`, `vulnerability_findings.resolved_at`, `pr_check` runs, SBOM exports to SOC2/ISO/PCI control IDs | D | M | — |
| G2 | Immutable evidence ledger — append-only `compliance_evidence` table with SHA-256 chain + signed daily Merkle root | D | M | G1 |
| G3 | Auditor read-only portal — filterable evidence by control, date, repo; PDF/CSV export with chain-of-custody manifest | D | L | G2 |
| G4 | SLA tracker + breach cron + exception flow with approver + business justification (Phase 15) | TS | M | existing SLA foundation |
| G5 | Aegis compliance agent — natural-language queries over evidence ledger; draft-evidence-for-control workflow | D | M | G2, A1 |
| G6 | Drata/Vanta bi-directional integration — push Deptex evidence into customer's existing compliance program | P+ | M | G2 |
| G7 | Policy-as-code → control-satisfaction mapping — write a policy once, auto-generate evidence across controls | D | M | B4, G1 |
| G8 | Audit log for every agent action (exists partially in `aegis_tool_executions` — formalize, harden, retention-policy) | TS | S | existing |
| G9 | Configurable autonomy level per org — observe / propose / execute-with-approval / fully autonomous | TS | S | A6 |
| G10 | Aegis management hub — personality, guardrails, default tools, budget caps, autonomy levels (already partially scaffolded in `aegis_org_settings`) | TS | M | existing |

### Layer H — Distribution & IDE
| # | Feature | Tag | Size | Depends on |
|---|---|---|---|---|
| H1 | Deptex MCP Server at `mcp.deptex.io` — Streamable HTTP + OAuth 2.1 + PKCE + Dynamic Client Registration + `/.well-known/oauth-protected-resource` | D | L | — |
| H2 | Publish on registry.modelcontextprotocol.io + Smithery + Glama | TS | S | H1 |
| H3 | `@deptex/cli` npm package — Trivy/OSV-Scanner-style CLI, local scan + remote sync (already planned, see memory) | TS | L | existing extraction-worker |
| H4 | VS Code extension — inline vuln warnings, hover cards, CodeLens, gutter icons | TS | L | H3 |
| H5 | GitHub Action + GitLab CI recipe | TS | S | H3 |
| H6 | Pre-commit hook — run Deptex check before commit | TS | S | H3 |
| H7 | Slack bot (already partially built) — `/deptex`, `@aegis` mentions, block-kit findings UI | TS | M | existing Slack config |
| H8 | Email integration — "reply to this vuln email to triage"; outbound digest emails; inbound IMAP webhook | P+ | M | H1 |
| H9 | Mobile PWA / iOS app for inbox + approvals | P+ | L | existing Aegis UI |
| H10 | Voice interface for on-call (Whisper + TTS) | M | L | moonshot |
| H11 | Browser extension — inline findings on GitHub.com PR view without installing the App | P+ | M | D1 |

### Layer I — Enterprise & Self-Host
| # | Feature | Tag | Size | Depends on |
|---|---|---|---|---|
| I1 | Self-hostable Aegis runtime (Helm chart + Docker compose, source-available with trial) | D | L | Phase 5 self-hosting |
| I2 | Local LLM via baseURL config (Ollama, LM Studio, vLLM) | D | M | BYOK provider layer |
| I3 | Self-hosted extraction-worker already shipped; now wire to self-hosted Aegis | D | M | extraction-worker |
| I4 | SSO (SAML/OIDC) for Aegis surface (Phase 14) | TS | M | existing SSO foundation |
| I5 | MFA enforcement toggle | TS | S | existing |
| I6 | Fine-grained audit log export (SIEM / Splunk / Datadog via webhook) | TS | M | G8 |
| I7 | Data residency — EU/US machine pools, per-org choice | TS | L | Fly.io regions |
| I8 | Private AI model / Azure OpenAI / Bedrock / Vertex routing | TS | M | BYOK |
| I9 | Per-tenant encryption keys for `organization_ai_providers.encrypted_api_key` | TS | S | existing AES-256-GCM |
| I10 | Zero-data-retention pre-signed agreements — per provider, per tenant opt-in | TS | M | I8 |

### Layer J — Monetization & Pricing
| # | Feature | Tag | Size | Depends on |
|---|---|---|---|---|
| J1 | Credit-consumption pricing model — "AegisCU ≈ 15 min agent work" metered across all write tools | P+ | M | A10, Devin reference |
| J2 | Free tier including Aegis-via-MCP-in-Claude-Code (subscription-covered, $0 AI cost to us) | D | S | H1 |
| J3 | Paid tiers — $25 Team, $X Scale, Enterprise custom; BYOK included in all paid tiers | TS | S | existing Stripe |
| J4 | Compliance Evidence add-on SKU — $3–8k/yr; gates G2/G3/G6 | D | S | G2 |
| J5 | Enterprise Self-Host add-on SKU | D | S | I1 |
| J6 | Overage credits — pay-as-you-go past AegisCU cap | TS | S | J1 |
| J7 | Marketplace listings — GitHub Marketplace, Azure DevOps, Atlassian Marketplace | TS | M | H5 |
| J8 | Migration tooling from Snyk/Endor/Wiz — "bring your SARIF, bring your ignore rules" | P+ | M | F1 |

### Layer K — Moonshots (ambitious, distinct, not table-stakes)
| # | Feature | Tag | Size |
|---|---|---|---|
| K1 | "Patch Factory" — AI-backported security fixes served via proxy registry (Artifactory/Nexus replacement for our users' private deps) — Endor's best moat re-done open-core | M | XL |
| K2 | Continuous autonomous pentesting (Aikido Infinite) — Aegis agents generate exploits, validate exploitability, then auto-remediate, with responsible-disclosure workflow | M | XL |
| K3 | Runtime agent guard — enforce runtime restrictions on customer's deployed AI agents (Snyk Agent Guard) | M | XL |
| K4 | Voice interface with on-call dispatch — "Aegis, what's the blast radius of CVE-2026-12345?" while commuting | M | L |
| K5 | Proactive predictive agent — anticipate zero-days and pre-queue mitigations (predictive risk signals) | M | XL |
| K6 | Browser-based LLM Preview — click-to-edit UI in Deptex that lets Aegis patch a finding with live preview (Windsurf Previews applied to security) | M | L |
| K7 | Deptex Benchmark — public security-agent benchmark à la Endor Agentic Code Security Benchmark, run by Deptex as thought leadership | M | L |
| K8 | Deptex Academy — Aegis as a security-training agent; explains a vuln in the context of dev's actual code, tracks learning progress per dev | M | L |
| K9 | Cross-org federated learning — privacy-preserving signal sharing across tenants (k-anonymous aggregate patterns; strict opt-in) | M | XL |
| K10 | Org graph + Aegis — Aegis lives as a node in the multiplayer canvas; reasoning across teams visualized as moves on the canvas | D | L |

---

## 6. Billion-Dollar Anchor Features (the non-negotiable killer bets)

Scored on Value (impact on product/market fit) × Leverage (how much it rides on Deptex's existing moats).

### Anchor 1 — **Aegis Fix**: autonomous end-to-end vuln remediation with self-verification
**Value 5 / Leverage 5.** Ties reachability + extraction + aider-worker + policy-engine + BYOK into one loop: Aegis plans → aider patches → extraction re-runs detector on patched file → policy engine evaluates → PR opens with proof artifact attached. Self-verification is the Semgrep Multimodal / Replit REPL-testing / OpenHands Vulnerability Fixer pattern — nobody in ASPM publicly demonstrates this end-to-end. **Size:** XL (Phases 2, 3, 5). Dependencies: B2, B3, C1, C3, C6, C7, D1.

### Anchor 2 — **Deptex MCP Server**: legal BYO-Claude distribution
**Value 5 / Leverage 5.** Ship `mcp.deptex.io` exposing Aegis's tool surface via OAuth 2.1 + Streamable HTTP, listed on the official MCP registry and Smithery. Deptex lives inside every Claude Code / Cursor / Windsurf / Codex user's IDE, on the user's Claude Max quota, at $0 token cost to us and $0 marginal cost to users who already pay Anthropic. This is the only legal BYO-Claude path post-Feb 2026 ToS, and it's a massive free-tier acquisition funnel. **Size:** L (Phase 1). Dependencies: H1, B1.

### Anchor 3 — **Security Campaigns**: declarative multi-repo batch-fix orchestration
**Value 5 / Leverage 4.** Sourcegraph Batch Changes + GitHub Security Campaigns, applied to CVE remediation with reachability-aware targeting. Declarative spec: *target set = "all repos where lodash@<4.17.21 is reachable," transform = "bump + regenerate lockfile + Aegis-verify + open PR," gate = "depscore drops ≥100."* 10k-changeset UI with conflict/rebase handling. No ASPM vendor has this. It's the enterprise hero feature. **Size:** XL (Phase 5). Dependencies: C2, B2, D1, F1.

### Anchor 4 — **Aegis-as-Skills** user-extensible playbooks
**Value 4 / Leverage 5.** Ship SKILL.md-style user-editable playbooks with YAML frontmatter, progressive disclosure, per-path auto-activation, `/skill-name` slash invocation. User-extensibility without backend redeploys is the reason Claude Code + Cursor compound fast; shipping it for a security agent turns Aegis into a platform. **Size:** L (Phase 2). Dependencies: A2, A5, A6.

### Anchor 5 — **Compliance Evidence Ledger + Agent**
**Value 4 / Leverage 5.** Every extraction run, vuln resolution, PR check, SBOM export is already an evidence artifact. Add: control-mapping (SOC2/ISO/PCI), immutable signed ledger, auditor portal, Drata/Vanta bi-directional integration. Aegis compliance agent does "draft SOC2 CC7.1 evidence for Q2" natural-language queries. Move-upmarket wedge. **Size:** L (Phase 7). Dependencies: G1–G7.

### Anchor 6 — **Reachability-Weighted AI Triage + Memories**
**Value 5 / Leverage 5.** Semgrep's Memories pattern (per-project/per-rule/per-vuln-class org-specific context auto-suggested from triage activity) + our reachability + EPD + asset-tier weights drive auto-suppression. 95% FP reduction is industry-achievable; adding reachability as the primary gate beats pure LLM triage for accuracy. Ship asymmetric confidence: *close* only when confident, else *annotate*. Expose all weights as configurable depscore inputs. **Size:** L (Phase 3). Dependencies: A8, A9, reachability.

### Anchor 7 — **Security Sprints**: AI-planned remediation at org scope
**Value 5 / Leverage 4.** Aegis plans a sprint: pick top-N findings by `depscore × reachability_tier × asset_tier_multiplier`, estimate AegisCU cost, present plan for approval, execute in parallel across per-finding subagent fix workers, verify each, open PRs with rollup dashboard. This is Devin's "here's my plan" × Cycode's "fix at scale" × Sourcegraph's multi-repo with Deptex-specific prioritization that no competitor can match. **Size:** XL (Phase 6). Dependencies: C3, C6, B2, B3, Anchor 1.

### Anchor 8 — **Self-Host Aegis Runtime**: enterprise-privacy deployment
**Value 4 / Leverage 5.** Helm chart + BYO-LLM via baseURL (Ollama/vLLM/Azure OpenAI/Bedrock) + self-hosted extraction-worker + self-hosted Aegis runtime. Code never leaves customer network. Unlocks regulated industries. Builds on Phase 5 self-hosting work already shipped (per memory). **Size:** L (Phase 8). Dependencies: I1, I2, I3.

### Anchor 9 — **PR Security Review with One-Click Fix Spawn**
**Value 4 / Leverage 4.** GitHub App installation → reachability-aware inline PR comments → "open as background agent" button on each → Aegis opens a branch, fixes, pushes, updates the PR. Matches Bugbot's flow and beats it on security specificity. **Size:** L (Phase 4). Dependencies: D1, D2, D3.

### Anchor 10 — **Scheduled Agent Pods + Proactive Intelligence**
**Value 4 / Leverage 4.** "Every Monday 7am Aegis triages the backlog, emails a digest, opens fix PRs for depscore > 800." Event-driven triggers on `critical_cve_found`, `extraction_failure`, `policy_violation`, `pr_opened`. Proactive — Aegis starts conversations, not only responds. The retention driver. **Size:** L (Phase 4). Dependencies: C4, C5.

---

## 7. Multi-Year Phased Roadmap

Each phase is designed to ship parallelizable worktrees. The critical path is **Phase 0 → 1 → 2 → 3 → 5 → 6**; all other phases can run concurrently with sufficient hands. Phase numbers below are Aegis-roadmap-internal and orthogonal to the existing Deptex Phase index (Phases 1–18) in the roadmap file — think of these as "Aegis roadmap phases" that map into the Phase 7B work already in the master roadmap.

### Phase 0 — Decision + foundations (1–2 weeks, critical path)
- Abandon `worktree-aegis-v2`; create `worktree-aegis-v3` off `main`
- Re-apply essential v2 UI elements (thread list, pin/archive, search, markdown, streaming) on fresh Phase-7B-aligned backend
- Migrate to AI SDK v6 `ToolLoopAgent` (A1)
- Pin `zod@^4.1.8`, kill TS2589
- Ship typed `UIMessage` data parts, `needsApproval`, `Output.object`
- Feature-flag all new Aegis work
**Exit criteria:** v3 chat on fresh branch with v6 SDK agent loop, 12 read-only tools passing through, all v2 UX parity.

### Phase 1 — MCP + distribution wedge (3–4 weeks, parallelizable)
- Deptex MCP Server at `mcp.deptex.io` — OAuth 2.1 + PKCE + DCR + `/.well-known/oauth-protected-resource` (H1)
- Listed on registry.modelcontextprotocol.io + Smithery + Glama (H2)
- Migrate GitHub/Slack/Jira/Linear/Semgrep/Supabase integrations to MCP-client (B13)
- Ship `@deptex/cli` stub with `deptex mcp` command for self-install (H3)
**Exit criteria:** a user with Claude Max can run `claude mcp add deptex` and use Aegis tools in their IDE on their subscription quota. Anchor 2 shipped.

### Phase 2 — Agent Core Platform (6–8 weeks, critical path)
- Skills (SKILL.md + slash commands + progressive disclosure) (A2)
- Subagents (Explore/Plan/Fix/Review archetypes) (A3)
- Hooks on tool-use + session + prompt events (A4)
- Plan mode default + Clarifying-Questions tool (A5)
- `Tool(specifier)` permission rules + managed enterprise overrides (A6)
- Checkpoints as universal task-step unit (A7)
- pgvector memory scoping (per-project/per-rule/per-vuln-class) + auto-suggest (A8)
- Asymmetric confidence gating (A9)
- `consumeStream` + `resumeStream` (A11)
**Exit criteria:** user can write `.aegis/skills/my-playbook/SKILL.md` and invoke via `/my-playbook`; Aegis runs plan mode by default for any write tool; checkpoint rewind works. Anchor 4 shipped.

### Phase 3 — Write Tool Registry + Reachability-Triage (6–8 weeks, parallelizable with Phase 2)
- Tool registry refactor with typed schemas + danger levels (B1)
- Policy-engine tools (B4): `evaluate_policy`, `propose_policy_change`, `simulate_policy_change`
- Flow-builder tools (B5)
- Org-management tools (B6) with approval gates
- Extraction-control tools (B10)
- Reachability-weighted AI triage + Memories + asymmetric confidence (A8, A9 applied)
- Vuln feed integration: OSV + EPSS + KEV + Scorecard + GHSA (F1)
- Changelog summarizer + breaking-change detection (F3)
- Typosquat + slopsquat detection (F4, F6)
- Supply-chain campaign tracker (F5)
**Exit criteria:** Aegis can propose policy changes, triage findings with ≥90% user-agreement, surface active supply-chain campaigns. Anchor 6 shipped.

### Phase 4 — PR Review + Proactive Agents (6–8 weeks, parallelizable with Phase 5)
- GitHub App installation + short-lived tokens + octokit.js (D1)
- Reachability-aware PR review (D2)
- One-click "fix this finding" from PR comment (D3)
- `ultrareview`-style multi-agent deep PR review (D4)
- GitLab MR + Bitbucket PR parity (D5)
- "Assign to Aegis" via label/assignee (D6)
- Conversational PR refinement via `@aegis` (D7)
- Scheduled agent pods (C4)
- Event-driven triggers (C5)
- Inbox + notification UI (existing `aegis_inbox`)
**Exit criteria:** Aegis posts security review on every PR; scheduled pods deliver weekly digest; event triggers fire. Anchors 9 + 10 shipped.

### Phase 5 — Aegis Fix + Self-Verification (8–12 weeks, critical path)
- Aider-integrated `trigger_fix` tool (B2)
- Fix verification loop: re-run dep-scan/Semgrep/TruffleHog/tree-sitter on patched tree (B3)
- Plan-then-execute task system with durable checkpoints + `interrupt()` pattern (C1)
- Background agents on Fly.io with session URL + `/teleport` (A12)
- Per-step rollback (C9)
- Sprint progress viewer (C7)
- Internet research tools (B12) with planner-egress ban
**Exit criteria:** Aegis fixes a medium-complexity vuln end-to-end with self-verification and opens PR. Anchor 1 shipped.

### Phase 6 — Security Sprints + Campaigns (10–14 weeks, critical path)
- Security Sprints (C3)
- Security Campaigns (C2) — 1000+-changeset UI
- Parallel per-finding fix agents with worktree isolation (C6)
- Self-verification before PR (C8)
- Migration tooling from Snyk/Endor/Wiz SARIF (J8)
- AegisCU credit-consumption pricing (J1, J6)
**Exit criteria:** a customer can run "Fix all critical vulns in repos tagged asset-tier-1" as a declarative campaign and watch 50 PRs open with progress dashboard. Anchors 3 + 7 shipped.

### Phase 7 — Compliance Evidence Ledger (8–10 weeks, parallelizable with Phase 6)
- Control-mapping layer (G1)
- Immutable signed evidence ledger (G2)
- Auditor read-only portal (G3)
- SLA tracker + breach cron + exception flow (G4, Phase 15 work)
- Aegis compliance agent (G5)
- Drata/Vanta bi-directional integration (G6)
- Policy → control-satisfaction mapping (G7)
- Audit log hardening (G8)
- Compliance Evidence add-on SKU launch (J4)
**Exit criteria:** customer can export "SOC2 CC7.1 evidence for Q2 2026" as a signed PDF; push to Vanta. Anchor 5 shipped.

### Phase 8 — Self-Host + Enterprise (8–12 weeks, parallelizable)
- Self-hostable Aegis runtime Helm chart (I1)
- Local LLM via baseURL (Ollama/vLLM/Azure/Bedrock) (I2)
- Self-hosted extraction-worker → self-hosted Aegis wiring (I3)
- SSO SAML/OIDC (I4)
- Data residency (I7)
- Zero-data-retention agreements (I10)
- SIEM/Splunk/Datadog audit-log export (I6)
- Enterprise Self-Host SKU launch (J5)
**Exit criteria:** a regulated customer runs Aegis entirely inside their VPC with local LLM. Anchor 8 shipped.

### Phase 9 — Agent-of-Agents + Multiplayer (10–14 weeks)
- Aegis group chats (revive deferred v2 work) (E1)
- Agent Swarm management pane (E2)
- Agent handoff (E3)
- Human-in-team delegation via org-graph (E4)
- Org-graph canvas + Aegis integration (E5)
- Ticketing tools (B9)
**Exit criteria:** customer can @-mention Aegis in a group chat during an incident and hand off to a human or specialist subagent. Partial Anchor 10 + novel UX shipped.

### Phase 10 — Intelligence Layer (8–10 weeks, parallelizable)
- Patch researcher with backport-risk assessment (F2)
- Malicious-package agent (F7)
- Threat model agent (F8)
- AI-BOM inventory (F9)
- SBOM tools (B11)
- Deptex Benchmark release (K7)

### Phase 11 — IDE + Distribution Depth (8–10 weeks, parallelizable)
- VS Code extension (H4)
- JetBrains extension (via same MCP-client pattern)
- GitHub Action + GitLab CI (H5)
- Pre-commit hook (H6)
- Browser extension for GitHub.com (H11)
- Slack bot depth (H7)
- Marketplace listings (J7)

### Phase 12 — Cursor / Devin Parity UX Polish (6–8 weeks)
- Checkpoints UI (A7 frontend polish)
- Clarifying-questions non-blocking pattern
- Windsurf-style click-to-edit on finding cards
- Background-agent spawn from Slack/Linear/Jira
- Agents Window unified inbox UI
- `/ultrareview` + `/ultraplan` skill bundles

### Phase 13 — Compliance Deep Dive + Pentest (10–14 weeks)
- Continuous autonomous pentesting (K2 moonshot → productized)
- Agent Red Teaming (F10, Snyk parity)
- PCI DSS 4.0 evidence generation
- HIPAA evidence pack

### Phase 14 — Patch Factory (XL moonshot, 6+ months)
- Patch Factory: AI-backported security fixes served via proxy registry (K1)
- Artifactory/Nexus proxy deployment
- 14-day patch SLO
- Signed reproducible builds
**Exit criteria:** customer points their private registry proxy at Deptex Patches; `npm install lodash` returns a backported-fixed artifact. Endor's best moat, open-core.

---

## 8. Parallelism Plan

Worktrees recommended, in priority order:
1. **`worktree-aegis-v3`** — Phases 0 + 2 (critical path)
2. **`worktree-aegis-mcp`** — Phase 1
3. **`worktree-aegis-write-tools`** — Phase 3
4. **`worktree-aegis-pr-review`** — Phase 4
5. **`worktree-aegis-fix`** — Phase 5 (critical path after 0+2)
6. **`worktree-aegis-campaigns`** — Phase 6 (critical path after 5)
7. **`worktree-aegis-compliance`** — Phase 7
8. **`worktree-aegis-selfhost`** — Phase 8 (builds on existing `self-hosting` work)
9. **`worktree-aegis-multiplayer`** — Phase 9 (builds on `worktree-org-graph-multiplayer`)
10. **`worktree-aegis-intel`** — Phase 10
11. **`worktree-aegis-ide`** — Phase 11
12. **`worktree-aegis-ux`** — Phase 12

Phase 0 blocks everything. Phases 2+3+4 can run concurrently after 0+1. Phase 5 requires 2+3 merged. Phase 6 requires 5 merged. Phases 7–12 are independent and can parallelize freely.

---

## 9. Positioning Against Specific Competitors

| Competitor | Where we beat them | Where we match them | Where they beat us today (close this) |
|---|---|---|---|
| Snyk | Open-core, BYOK, self-host, policy-as-code, flow-builder | MCP server (Phase 1), reachability (already) | Studio distribution, AI-BOM, Evo AI-SPM |
| Endor Labs | Open-core, BYOK, public pricing, user-extensible skills | Reachability depth, AI triage, AI-SAST-style multi-agent | Patch Factory (Phase 14), Code Context Graph scale |
| GitHub Advanced Security | Cross-repo / cross-org analysis, policy engine, flow-builder | Coding Agent parity (Phase 4), Security Campaigns (Phase 6) | Native PR chrome, compatibility scores from CI corpus, bundle with seats |
| Cycode / Jit | Open-core, policy-as-code, self-host | Maestro-style orchestration (Phase 2 + 6), agent swarm | Enterprise proof / deployments |
| Semgrep | Open-core + reachability (not just rules), BYOK | AI Memories (Phase 3), Multimodal-style tool-using triage | Deep rule library + Multimodal eval rigor |
| Apiiro | Open-core, policy-as-code | DCA-equivalent via reachability + framework detection | Risk graph brand + enterprise motion |
| Aikido | Open-core, BYOK, policy-as-code | Continuous pentesting (Phase 13) | 16-scanner breadth (DAST, CSPM, IaC, RASP) |
| Cursor / Claude Code | Security-specialized; reachability-aware | Agent UX patterns (Phases 2 + 12) | General-purpose IDE traction — we don't try to match, we plug in via MCP |
| Devin / Jules | Open-core, security-specialized, self-host | Checkpoints, plan preview, scheduled tasks (Phases 2 + 4) | General SWE-bench scores — not our competition |
| Snyk Evo / AI-SPM | Open-core + user-auditable | AI-BOM (Phase 10) | AI-SPM brand + Fortune-500 deployments |

**One-line positioning**: *"Deptex Aegis is the open-core autonomous security engineer for teams who want their AI to act on their repo, not just describe it — with reachability-driven triage, customer-authored policy-as-code, and a self-hostable agent runtime."*

---

## 10. Architectural Sketches for the Top 3 Anchors

### Anchor 1 — Aegis Fix data flow
```
User: "fix CVE-2025-12345 in checkout-service"
  ↓
Aegis Planner Subagent (Haiku, read-only tools, plan-mode)
  • Tools called: get_vulnerability_detail, get_reachability_flows, list_project_dependencies, analyze_upgrade_path, get_epss_score
  • Emits: editable plan (Markdown) — which files, which deps, which test cmd, estimated AegisCU cost
  ↓ user approves via needsApproval UI
Aegis Fix Subagent (BYOK Sonnet/Opus, write tools, sandbox Fly machine)
  • Tools: clone_repo, read_files, write_files, run_tests, run_extraction_step
  • Uses Aider with --model from organization_ai_providers BYOK
  • Pre-scoped file list from reachability (not repo-map)
  • Commits on its own branch
  ↓
Verification Subagent (same Fly machine, read-only)
  • Re-runs: dep-scan (finding must be gone), Semgrep (no new findings), tree-sitter usage (reachability path broken), policy engine (evaluate_package_policy passes)
  • Depscore comparison: old vs new; MUST drop
  • Blocked if any fail
  ↓ if all pass
PR Opens (via GitHub App installation token)
  • PR body includes: plan, changes summary, verification results, policy diff, depscore delta
  • Check-run attributed to Aegis app
  ↓
If human comments "@aegis also sanitize X", reopens Fix Subagent
```

Durability: every step is a checkpoint in `aegis_task_steps`. Rollback = rewind to N-1. Resumable after disconnect via `resumeStream`.

### Anchor 2 — Deptex MCP Server surface
```
mcp.deptex.io (Streamable HTTP, OAuth 2.1 + PKCE)

Tools exposed (initial set, mirrors Aegis read-side + some write):
  READ: list_projects, get_project_summary, list_findings, get_finding_detail,
        get_reachability_flows, get_depscore_breakdown, check_policy,
        search_dependencies, list_sprints, get_sprint_status
  WRITE (approval-gated per-org): trigger_fix, propose_policy_change,
        suppress_finding, assign_finding, open_incident

Auth flow:
  1. Claude Code detects mcp.deptex.io in .mcp.json
  2. Client hits /.well-known/oauth-protected-resource — gets auth server URL
  3. Dynamic Client Registration (RFC 7591) — Claude Code registers itself
  4. OAuth 2.1 + PKCE + Resource Indicators (RFC 8707)
  5. Tokens scoped: resource = "https://mcp.deptex.io", scopes = [read, write]
  6. Deptex validates token against its own Supabase user-session table (bridge)
  7. Per-org RBAC enforced on every tool call — same system as Aegis web UI
```

Commercial posture: using Deptex-MCP-in-Claude-Code is subscription-covered; no Deptex AI cost. Free tier.

### Anchor 3 — Security Campaign spec
```yaml
# .deptex/campaigns/lodash-rollout.yaml
campaign:
  name: "Lodash 4.17.21 rollout — reachable uses only"
  target:
    reachability_tier: [confirmed, data_flow]
    package: lodash
    version: "<4.17.21"
    asset_tier_ids: [tier-1, tier-2]
  transform:
    kind: dependency_upgrade
    target_version: ">=4.17.21"
    bump_strategy: minimum_safe
  gate:
    depscore_must_drop_by: 100
    tests_must_pass: true
    policy_check: default
  execution:
    parallelism: 10
    max_agent_minutes: 30
    approval_per_pr: optional
  output:
    dashboard: /campaigns/lodash-rollout
    slack_channel: "#security-fixes"
```

Execution: Deptex queries for matching `project_dependencies` rows → creates 1 `aegis_task` per repo → fans out Fix subagents → Anchor 1 flow per task → coordinator tracks in `campaign_changesets` table with state (pending/running/pr_open/merged/failed/conflict) → dashboard renders 10k-changeset UI with filter/sort/bulk-rebase.

---

## 11. Monetization Implications

**Free (no cost to us):**
- Aegis-as-MCP-in-Claude-Code (Anchor 2) — subscription-covered
- `@deptex/cli` local scans (no cloud LLM)
- Public-repo scanning with read-only Aegis web chat on Gemini Flash Tier 1

**Team ($25/dev/mo, BYOK included):**
- All read tools, all write tools with approval
- Scheduled pods, event triggers
- PR review + one-click fix spawn
- 100 AegisCU/mo, pay-as-you-go overage at $2/AegisCU

**Scale (~$100/dev/mo or per-AegisCU pool):**
- Security Campaigns unlimited
- Parallel fix agents up to 10 concurrent
- Compliance Evidence add-on gate
- Custom skills deployed org-wide
- 500 AegisCU/mo included

**Enterprise (custom):**
- Self-Host Aegis runtime
- SSO SAML/OIDC
- Data residency (EU/US pools)
- SIEM export
- Private LLM / Azure OpenAI / Bedrock routing
- Zero-data-retention pre-signed
- Compliance Evidence Locker + auditor portal

**Add-ons:**
- **Compliance Evidence Locker: $3k–$8k/yr** — gates G2/G3/G6
- **Enterprise Self-Host: starting $15k/yr** — gates I1/I2/I7

Migration incentive: trade-in for Snyk/Endor/Wiz — bring SARIF, ignore rules, dep inventory, and get first 6 months at 50%.

---

## 12. Where Deptex's Existing Roadmap Slots In

The existing `.cursor/plans/deptex_projects_roadmap_index.plan.md` already contains Phase 6C (AI Infrastructure & Aegis Copilot), Phase 7 (Aider), Phase 7B (Aegis Autonomous Security Platform), Phase 15 (Security SLAs), Phase 16 (Outcome-Based Learning), Phase 17 (Incident Response — already shipped), Phase 18 (Developer Touchpoints). This Aegis-roadmap maps into that index roughly as:

| This roadmap | Existing roadmap |
|---|---|
| Phase 0 + 2 | Phase 6C (refactor) + Phase 7B (agent core) |
| Phase 1 (MCP) | **New** — not in existing roadmap |
| Phase 3 (write tools + triage) | Phase 7B (tools) + Phase 16 (learning) |
| Phase 4 (PR review) | Phase 7B (PR review pipeline) + Phase 8 (PR management) |
| Phase 5 (Aegis Fix) | Phase 7 (Aider) + Phase 7B (fix orchestration) |
| Phase 6 (Sprints + Campaigns) | Phase 7B (sprint orchestrator) + **new** Campaigns |
| Phase 7 (Compliance) | Phase 5 (Compliance) + Phase 15 (SLAs) + **new** evidence ledger |
| Phase 8 (Self-Host) | **New** — builds on Phase 5 self-hosting work |
| Phase 9 (Multiplayer) | Phase 7B (Slack bot) + **new** group chats + org-graph |
| Phase 10 (Intelligence) | Phase 7B (proactive intelligence) + **new** AI-BOM |
| Phase 11 (IDE) | Phase 18 (developer tools) |
| Phase 12 (UX polish) | **New** — Cursor/Devin-pattern parity |
| Phase 13 (Pentest) | **New** — moonshot |
| Phase 14 (Patch Factory) | **New** — moonshot |

Net: we're adding MCP/Campaigns/Self-Host/Multiplayer/Pentest/Patch-Factory as net-new phases, rewriting Phase 7B against 2026 competitive reality, and reordering the critical path to put MCP distribution first (cheapest + earliest acquisition funnel).

---

## 13. Metrics to Drive the Program

Output (what we ship):
- Aegis tool count (target 80+ by Phase 6)
- Skills library size
- MCP tool coverage (% of write tools)
- Subagent archetype count

Input (how much work the agent does):
- AegisCU consumed per org per week
- Fix PR open rate / merge rate / revert rate
- Campaign changesets completed
- Scheduled pod runs

Outcome (did it work):
- MTTR for critical vulns (target: <2 days, vs industry ~30 days)
- FP suppression rate (target: ≥95%, Semgrep parity)
- Depscore delta per sprint (target: 30% monthly reduction org-wide)
- Auto-merged fix PR rate (target: 40% of Aegis Fix PRs merge without edits)
- Compliance evidence coverage % (target: 100% of in-scope SOC2 CC7.1/CC4.1 controls)

Adoption (network-effect leading indicators):
- MCP server monthly installs across Claude Code + Cursor + Windsurf
- Skills shared/forked across orgs
- % of open-source repos running Deptex CLI in CI

Eval (do we know we're not regressing):
- CVE-Bench repair rate (target: >21%, beat SWE-agent baseline)
- Internal golden-set pass rate (build from N=500 real extraction jobs)
- SWE-bench Pro for general-coding regression protection
- CyberSecEval 4 / AutoPatchBench for C/C++ story
- Red-team adversarial set including prompt injection via issue bodies (Embrace-The-Red-style Jules findings)

---

## 14. Recommended Next Steps (decide before touching code)

1. **Confirm Phase 0 decision on `worktree-aegis-v2`**: abandon + restart (recommended) vs squash vs push-through. This unblocks the whole program.
2. **Run `/interview` on Anchor 2 (Deptex MCP Server)** — it's the cheapest, most-leverage, distribution-defining phase and should ship first. Scope it tight; don't try to expose all tools Day 1 (start with read tools + `trigger_fix` + `propose_policy_change`).
3. **Run `/interview` on Anchor 1 (Aegis Fix)** — parallelizable with MCP phase since it depends on Phase 2 (agent core) not Phase 1.
4. **Tag the existing Phase 7B plan as *superseded by this research doc*** so future-Henry doesn't get confused by two parallel visions.
5. **Kill the push to incrementally evolve v2 into v3** — the architecture needs enough surgery (AI SDK v6 migration, tool registry refactor, skills system, subagent archetypes) that fresh start beats evolution.
6. **Pick which moonshot to promote to real phase** based on customer-signal + thematic fit: Patch Factory (K1) is the biggest enterprise wedge; Continuous Pentest (K2) is the biggest brand moment; Agent Red Teaming (F10) is the Snyk Evo parity play. One is enough for the next 12 months.

---

## Appendix A — Sources

All competitor citations are inline in Section 2 and in the underlying research agent reports. The 15-agent research spike of April 2026 covered: Deptex code inventory, Snyk, Endor Labs, Socket + Aikido, Semgrep, GitHub Advanced Security, GitLab Duo + Checkmarx + Veracode, 10-vendor ASPM survey (Apiiro/Legit/ArmorCode/OX/Cycode/Jit/Arnica/Mend/Wiz/Orca), Claude Code + Cloud, Cursor, Google Jules + Devin, OpenHands + Replit + Sourcegraph, MCP + Anthropic ToS, Vuln feeds + compliance, Aider + fix-agent landscape, AI SDK v6 + Mastra + LangGraph, Codex + Copilot Workspace + Windsurf.

## Appendix B — Unresolved Questions for Future Interviews

- Do we want a separate Deptex-managed API key tier (we pay, mark up BYOK costs 1.5×) vs strict BYOK-only in paid plans?
- Is continuous autonomous pentesting (Aikido Infinite parity) a Phase 13 investment or a moonshot we skip in favor of Patch Factory?
- How aggressive do we want MCP server write capability on Day 1 — read-only only, or include `trigger_fix`?
- Patch Factory as productized OSS (customers host their own proxy) vs Deptex-hosted Patch Factory as a paid add-on?
- Do we try to match Snyk's AI-BOM / AI-SPM narrative, or bet that it's a fad and stay focused on classic AppSec?
- How do we handle the Phase 7B plan file already in `.cursor/plans/` — archive as superseded, or incrementally edit into alignment with this research?

---

## Recommended Next Step
Run `/interview` on concept #2 ("Deptex MCP Server") to refine scope before planning. This is the cheapest, highest-leverage, distribution-defining phase and needs to ship first.
