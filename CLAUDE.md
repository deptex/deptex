# Deptex System Reference

Deptex is an AI-powered open-core dependency security platform. It combines dependency intelligence, continuous supply-chain monitoring, policy-as-code, and an autonomous AI security agent (Aegis) to automate software security for organizations.

**Open-core model:** CE (open-source core) in `backend/` + `frontend/`, EE (commercial) in `ee/`. Toggle: `DEPTEX_EDITION=ce|ee` (default: ee). CE must never import from `ee/`; EE can import from `backend/src/`.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend API | Express + TypeScript (ES2020, CommonJS) |
| Database | PostgreSQL via Supabase (`@supabase/supabase-js`, service role key) |
| Auth | Supabase Auth (JWT Bearer tokens, Google/GitHub OAuth) |
| Realtime | Supabase Realtime (subscription to DB changes) |
| Frontend | React 18 + Vite 5 + Tailwind CSS 3 + Radix UI primitives (shadcn pattern) |
| Routing | React Router v6 (`createBrowserRouter`) |
| Graphs | @xyflow/react (dependency + vulnerability graphs) |
| Tables | @tanstack/react-table |
| Code editor | Monaco Editor (policy code) |
| Forms | react-hook-form + zod validation |
| Workers | 4 Node.js workers (extraction, parser, watchtower-worker, watchtower-poller) |
| SBOM | cdxgen (CycloneDX generation) |
| Vuln scanning | dep-scan (VDR analysis), Semgrep, TruffleHog |
| AST parsing | oxc-parser (JS/TS import extraction) |
| Queues | Upstash QStash (async jobs, cron schedules) |
| Cache | Upstash Redis (caching, ast-parsing-jobs, watchtower-jobs). Extraction jobs use Supabase `extraction_jobs` table. |
| AI - Tier 1 | Google Gemini Flash (platform features -- we pay, ~$0.0001/call) |
| AI - Tier 2 | BYOK OpenAI/Anthropic/Google (Aegis + Aider -- org pays via their own API keys) |
| Deployment | Fly.io (workers, scale-to-zero), Supabase (DB + auth), Vercel-style frontend |
| Billing | Stripe (Phase 13, not yet built) |

---

## Codebase Map

```
backend/
  src/
    index.ts                    Express entry. CE routes always mounted, EE routes via load-ee-routes.js
    routes/
      userProfile.ts            GET/PUT /api/user-profile (avatar, full_name)
      docs-assistant.ts         POST /api/docs-assistant (Gemini-powered docs Q&A, no auth, IP rate limited)
      recovery.ts               POST /api/internal/recovery/extraction-jobs (CE, X-Internal-Api-Key: requeue stuck jobs, fail exhausted, start machines for orphans)
    lib/
      supabase.ts               Lazy-init Supabase client (service role). createUserClient(jwt) for user-scoped
      features.ts               getEdition(), isEeEdition() -- CE vs EE toggle
      ecosystems.ts             MANIFEST_FILES map, FRAMEWORK_RULES, 11 ecosystems (npm, pypi, maven, golang, cargo, gem, composer, pub, hex, swift, nuget)
      ghsa.ts                   GitHub Advisory GraphQL batch fetch (up to 100 pkgs), severity mapping, version filtering
      semver-affected.ts        OSV-style affected range matching (introduced/fixed)
      vuln-counts.ts            Vuln counts per (dependency, version) from DB + GHSA fallback, threshold checks
      transitive-edges.ts       npm transitive dep resolution via pacote, upserts dependency_version_edges
      registry-fetchers.ts      Registry metadata for non-npm ecosystems (pypi, maven, nuget, go, cargo, gem, composer, pub, hex, swift)
      detect-monorepo.ts        Monorepo detection (pnpm-workspace, package.json workspaces, tree scan). Provider-agnostic via MonorepoGitProvider interface
    middleware/
      auth.ts                   authenticateUser (required JWT), optionalAuth. Sets req.user = { id, email }
  extraction-worker/            Clone + cdxgen SBOM + dep-scan + AST + Semgrep + TruffleHog. Polls Supabase extraction_jobs (atomic claim). Deployed to Fly.io scale-to-zero. See fly.md.
  parser-worker/                Standalone AST import analysis (oxc-parser)
  watchtower-worker/            Supply-chain forensic analysis (registry integrity, scripts, entropy, commits, contributors, anomalies)
  watchtower-poller/            Daily cron: dependency refresh (npm latest, GHSA batch), new commit detection for watched packages
  database/                     ~140 SQL migration files (CE + EE tables). data/spdx-obligations.json for license seed reference.
  load-ee-routes.js             Plain JS loader so tsc doesn't compile ee/

ee/backend/
  routes/
    organizations.ts            Org CRUD, members, invitations, roles, policies, notification rules, deprecations, join link. Phase 4: statuses CRUD, asset tiers CRUD, split policy code (package_policy, project_status, pr_check) PUT/GET, policy-changes (GET org history), revert (POST). Seed statuses and tiers on org creation.
    teams.ts                    Team CRUD, roles, members, transfer ownership
    projects.ts                 Project CRUD, repos, dependencies (list/overview/versions/supply-chain/safe-version), vulnerabilities, policies, exceptions, PR guardrails, Watchtower actions (bump/decrease/remove PRs), notes, contributing teams, AST import status. Extraction: POST extraction/cancel, GET extraction/logs, GET extraction/runs. Phase 5 compliance: GET sbom (real cdxgen from storage), GET legal-notice (grouped by license, Redis-cached), GET registry-search (proxy to npm/Maven/Cargo/RubyGems/PyPI/Go), POST apply-exception (Gemini AI policy exception), GET license-obligations. Policy engine: POST evaluate-policy, POST preflight-check (ecosystem param), POST validate-policy, policy-changes CRUD, revert-policy.
    activities.ts               GET activities with date/type/team filters
    integrations.ts             OAuth flows + webhooks for GitHub App, GitLab, Bitbucket, Slack, Discord, Jira, Linear, Stripe, Asana. Org connections CRUD, custom integrations, email notifications
    aegis.ts                    Aegis AI: enable/status, chat (handle message with tool execution), threads, automations CRUD + run, inbox, activity logs
    workers.ts                  Extraction pipeline: queue-populate, populate-dependencies (QStash), backfill-dependency-trees, extract-deps. Houses extractDependencies() for lockfile parsing
    watchtower.ts               Supply-chain endpoints: full analysis, commits (with anomaly sort + touches_imported filter), contributors, anomalies, summary, AI commit analysis (GPT-4)
    internal.ts                 Internal API (X-Internal-Api-Key): create-bump-pr
    invitations.ts              GET pending invitations for current user
  lib/
    aegis/
      executor.ts               Main Aegis entry: executeMessage() runs OpenAI with tool definitions, handles tool calls, logs to aegis_activity_logs
      systemPrompt.ts           Aegis system prompt (role, capabilities, guidelines)
      actions/
        index.ts                Action registry: registerAction(), getActionHandler(), getActionDefinitionsForOpenAI()
        init.ts                 Imports teams, members, policies to register actions
        teams.ts                listTeams, addMemberToTeam, moveAllMembers
        members.ts              listMembers (with team info)
        policies.ts             listPolicies, getPolicy
      queue.ts                  Automation processor: parseScheduleToNextRun, processAutomationJobs, scheduleAutomations, startQueueProcessor
    github.ts                   GitHub App: JWT, installation tokens, repo file/tree access, branch/PR operations, commit diffs
    gitlab-api.ts               GitLab OAuth: repo listing, file content, tree access
    bitbucket-api.ts            Bitbucket OAuth: repo listing, file content
    git-provider.ts             GitHubProvider, GitLabProvider, BitbucketProvider implementing GitProvider interface. createProvider(integration) factory
    qstash.ts                   QStash helpers: signature verification, queuePopulateDependencyBatch, queueBackfillDependencyTrees, queueDependencyAnalysis
    redis.ts                    Redis: queueASTParsingJob. Supabase: queueExtractionJob (inserts extraction_jobs, calls startExtractionMachine), cancelExtractionJob
    fly-machines.ts             Fly Machines API: startExtractionMachine() — start from pool or create burst machine
    rate-limit.ts               checkRateLimit(key, maxRequests, windowSeconds) — Redis-backed, fail-open. Used by evaluate-policy, preflight-check, validate-policy, legal-notice, apply-exception
    cache.ts                    Redis cache: getCached/setCached/invalidateCache, TTL constants, cache key helpers for projects/deps/versions/safe-versions/watchtower/legal-notice
    openai.ts                   Lazy-init OpenAI client
    email.ts                    sendEmail, sendInvitationEmail (nodemailer/Gmail)
    activities.ts               createActivity() -- insert activity log
    create-bump-pr.ts           Create version bump PR via GitHub/GitLab/Bitbucket
    create-remove-pr.ts         Create package removal PR
    latest-safe-version.ts      Calculate latest safe version (vuln checks + cache)
    project-policies.ts         isLicenseAllowed(), getEffectivePolicies() (org policy_code for a project)
    policy-engine.ts            Sandboxed policy execution (isolated-vm or Function fallback). evaluateProjectPolicies(), validatePolicyCode(), preflightCheck(). Runs packagePolicy() per dep, projectStatus(), pullRequestCheck().
    policy-defaults.ts          DEFAULT_PACKAGE_POLICY_CODE, DEFAULT_PROJECT_STATUS_CODE, DEFAULT_PR_CHECK_CODE
    policy-seed.ts              Seeds statuses and asset tiers on org creation
    watchtower-queue.ts         queueWatchtowerJob() to Redis watchtower-jobs queue

frontend/src/
  main.tsx                      RouterProvider + TooltipProvider entry
  contexts/
    AuthContext.tsx              AuthProvider: Supabase session, signInWithGoogle/GitHub, signOut, avatar sync to user_profiles
  app/
    routes.tsx                  All route definitions (see Frontend Routing below)
    DocsApp.tsx                 Docs layout shell: DocsHeader + Outlet + DocsAIAssistant
    pages/                      All page components (see Frontend Pages below)
  components/                   Shared components (see Frontend Components below)
```

---

## Frontend Routing

### Protected Routes (require auth)
| Path | Page |
|------|------|
| `/organizations` | OrganizationsPage (list + create) |
| `/organizations/:id` | OrganizationLayout with tabs |
| `/organizations/:id/teams` | TeamsPage |
| `/organizations/:id/vulnerabilities` | OrganizationVulnerabilitiesPage |
| `/organizations/:id/projects` | ProjectsPage |
| `/organizations/:id/settings` | OrganizationSettingsPage (general, members, roles, integrations, notifications, statuses, policies, audit_logs, etc.) |
| `/organizations/:id/policies` | PoliciesPage (Package Policy, PR Check Monaco editors; Change History sub-tab) |
| `/organizations/:id/compliance` | CompliancePage |
| `/organizations/:orgId/projects/:projectId/overview` | ProjectOverviewPage |
| `/organizations/:orgId/projects/:projectId/vulnerabilities` | ProjectVulnerabilitiesPage |
| `/organizations/:orgId/projects/:projectId/dependencies` | ProjectDependenciesPage |
| `/organizations/:orgId/projects/:projectId/dependencies/:dependencyId/overview` | DependencyOverviewPage |
| `/organizations/:orgId/projects/:projectId/dependencies/:dependencyId/watchtower` | DependencyWatchtowerPage |
| `/organizations/:orgId/projects/:projectId/dependencies/:dependencyId/supply-chain` | DependencySupplyChainPage |
| `/organizations/:orgId/projects/:projectId/compliance` | ProjectCompliancePage. Sub-routes: /compliance/project (status overview), /compliance/policy-results, /compliance/updates |
| `/organizations/:orgId/projects/:projectId/settings` | ProjectSettingsPage (asset tier dropdown uses dynamic tiers from organization_asset_tiers) |
| `/organizations/:orgId/teams/:teamId/overview` | TeamOverviewPage |
| `/organizations/:orgId/teams/:teamId/projects` | TeamProjectsPage |
| `/organizations/:orgId/teams/:teamId/members` | TeamMembersPage |
| `/organizations/:orgId/teams/:teamId/alerts` | TeamAlertsPage |
| `/organizations/:orgId/teams/:teamId/settings` | TeamSettingsPage |
| `/invite/:invitationId` | InvitePage |
| `/join/:organizationId` | JoinPage |
| `/settings` | SettingsPage (general, connected accounts) |

### Public Routes
| Path | Page |
|------|------|
| `/` | HomePage (hero, features, framework support, product showcase, CTA) |
| `/login` | LoginPage (Google/GitHub OAuth) |
| `/autonomous-agent` | Aegis AI marketing page |
| `/repository-tracking` | Repository tracking marketing |
| `/anomaly-detection` | Anomaly detection marketing |
| `/vulnerability-intelligence` | Vuln intelligence marketing |
| `/sbom-compliance` | SBOM compliance marketing |
| `/project-health` | Project health marketing |
| `/integrations` | Integrations marketing |
| `/open-source` | Open source marketing |
| `/solutions/*` | 6 persona pages (engineering, security, devops, OSS maintainers, CTO, startups) |

### Docs Routes (no auth, separate DocsApp layout)
| Path | Page |
|------|------|
| `/docs` | Redirects to /docs/introduction |
| `/docs/learn` | LearnPage (tutorial hub) |
| `/docs/learn/:tutorial` | LearnTutorialPage |
| `/docs/help` | HelpCenterPage |
| `/docs/:section` | DocsPage rendering section content |

Docs sections: introduction, quick-start, projects, dependencies, vulnerabilities, compliance, sbom-compliance, organizations, teams, integrations, policies, notification-rules, terms, privacy, security.

---

## Frontend Key Components

### Layout
- **AppHeader / DocsHeader / OrganizationHeader / ProjectHeader / TeamHeader** -- context-specific headers
- **NavBar** -- main marketing nav with Product/Resources dropdowns
- **OrganizationSidebar / ProjectSidebar / TeamSidebar / SettingsSidebar / DependencySidebar** -- navigation sidebars
- **OrganizationSwitcher / ProjectSwitcher / TeamSwitcher** -- entity switchers
- **ProtectedRoute / PublicRoute** -- auth guards via AuthContext

### Dependency & Supply Chain
- **PackageOverview** -- package metadata, score, downloads, versions
- **supply-chain/** -- CenterNode, DependencyNode, BanVersionSidebar, RemoveBanSidebar, SafeVersionCard, UnusedInProjectCard, useGraphLayout (xyflow graph)
- **vulnerabilities-graph/** -- ProjectCenterNode, VulnProjectNode, useTeamVulnerabilitiesGraphLayout, useOrganizationVulnerabilitiesGraphLayout, VulnerabilitiesSimulationCard

### Sidebars & Panels
- **VersionSidebar** -- version details with vuln counts
- **DeprecateSidebar** -- mark package as deprecated
- **CommitSidebar** -- watchtower commit details
- **SyncDetailSidebar** -- live extraction logs (Supabase Realtime), terminal-style UI, cancel button, historical run selector
- **DependencyNotesSidebar** -- dependency notes (collaborative)
- **PolicyExceptionSidebar / PolicyExceptionSidepanel** -- policy exception management
- **ComplianceSidepanel** -- compliance nav (legacy; ProjectCompliancePage uses top tabs)
- **PreflightSidebar** -- Phase 5: check hypothetical package against policy before adding (ProjectCompliancePage, inline)
- **ExceptionDiffDialog** -- Phase 5: review AI-generated policy exception before applying
- **PRGuardrailsSidepanel** -- PR merge blocking config
- **ScoreBreakdownSidebar** -- reputation score breakdown
- **CreateProjectSidebar** -- project creation flow

### Org Settings (Phase 4 Policy Engine)
- **StatusesSection** -- Org Settings > Statuses tab. Sub-tabs: Statuses (CRUD), Asset Tiers (CRUD), Status Code (Monaco editor), Change History (org-level status code version list)
- **PoliciesPage** -- Org Policies tab. Sub-tabs: Package Policy (Monaco), Pull Request Check (Monaco), Change History (org-level package_policy + pr_check version list). API: revertOrganizationPolicyCode exists; UI shows list only (no revert buttons or diff viewer yet)

### AI & Policy
- **PolicyAIAssistant** -- AI-powered policy code helper (Gemini)
- **NotificationAIAssistant** -- AI-powered notification rule helper
- **PolicyDiffViewer** -- diff view for policy changes
- **DocsAIAssistant** -- floating docs Q&A panel

### UI Primitives (shadcn/Radix)
button, input, label, checkbox, switch, slider, progress, badge, avatar, card, dialog, sheet, dropdown-menu, popover, tooltip, toast, toaster, calendar, accordion, select, separator, tabs

---

## Worker Pipelines

### Extraction Worker (extraction-worker/)
**Trigger:** `queueExtractionJob()` inserts into Supabase `extraction_jobs` table and calls `startExtractionMachine()` to start a Fly.io machine. Worker polls Supabase via atomic `claim_extraction_job` RPC (FOR UPDATE SKIP LOCKED). Machines scale-to-zero: 60s idle shutdown.

**Fault tolerance:** Heartbeat every 60s; stuck detection after 5 min no heartbeat; recovery cron (`POST /api/internal/recovery/extraction-jobs`) requeues stuck jobs, fails exhausted (max 3 attempts), starts machines for orphaned queued jobs. 4-hour machine watchdog.

**Pipeline:**
1. **Clone** -- clone repo via GitHub App / GitLab OAuth / Bitbucket OAuth token
2. **SBOM** -- run `cdxgen` to generate CycloneDX SBOM
3. **Parse SBOM** -- extract dependencies, relationships, licenses from SBOM
4. **Upsert** -- insert/update `dependencies`, `dependency_versions`, `project_dependencies`, `dependency_version_edges`
5. **Queue populate** -- call `POST /api/workers/queue-populate` for new direct deps
6. **AST import analysis** -- oxc-parser on JS/TS files, extract ESM imports -> `project_dependency_functions`, `project_dependency_files`, `files_importing_count`
7. **dep-scan** -- run dep-scan VDR analysis for vulnerabilities, fetch EPSS scores, CISA KEV status, compute depscore
8. **Semgrep** -- `semgrep scan --config auto` for code security findings (optional)
9. **TruffleHog** -- secret scanning (optional)
10. **Upload** -- store sbom.json, dep-scan.json, semgrep.json, trufflehog.json to Supabase storage `project-imports/{projectId}/{runId}/`
11. **Status** -- set `project_repositories.status = 'ready'`, `extraction_step = 'completed'`

**Live logs:** `ExtractionLogger` writes to `extraction_logs` (Supabase Realtime). Frontend SyncDetailSidebar subscribes for live streaming.

**Populate callback** (`POST /api/workers/populate-dependencies` via QStash):
- Fetch npm registry (versions, downloads, GitHub URL)
- Fetch GHSA vulnerabilities (batch GraphQL)
- Fetch OpenSSF scorecard
- Compute reputation score (OpenSSF + popularity + maintenance penalties)
- **Policy evaluation** (Phase 4): After batch populated, run `evaluateProjectPolicies()` — packagePolicy() per dep (stores `policy_result`), projectStatus() (sets `projects.status_id`, `status_violations`), then `status = 'ready'`
- Queue `backfill-dependency-trees` for transitive edge resolution

**Depscore**: Uses `tierMultiplier` from `organization_asset_tiers` (project's `asset_tier_id`); pipeline fetches from DB and passes to `calculateDepscore()`.

### Parser Worker (parser-worker/)
**Trigger:** `queueASTParsingJob()` pushes to Redis `ast-parsing-jobs` (standalone re-parse without full extraction).

1. Clone repo via GitHub App
2. oxc-parser on .js/.jsx/.ts/.tsx/.mjs/.cjs files, extract ESM imports
3. Update `project_dependencies.files_importing_count`, upsert `project_dependency_functions`, `project_dependency_files`
4. Set `project_repositories.ast_parsed_at`, `status: 'ready'`
5. Invalidate Redis caches

### Watchtower Worker (watchtower-worker/)
**Trigger:** `queueWatchtowerJob()` pushes to Redis `watchtower-jobs` when a package is added to org watchlist, or `watchtower-new-version-jobs` when poller finds new version, or `watchtower-batch-version-jobs` for historical analysis.

**Full analysis pipeline:**
1. Fetch npm metadata
2. Registry integrity: compare npm tarball SHA vs git tag
3. Script capabilities: detect preinstall/postinstall/install hooks
4. Entropy analysis: obfuscation detection
5. Clone repo with history, extract commits
6. Build contributor profiles
7. Anomaly detection (new contributor, unusual patterns, etc.)
8. Store to `watched_packages`, `dependency_versions`, `package_commits`, `package_contributors`, `package_anomalies`
9. Queue batch job for previous 20 versions

**New-version job:** analyze new version, check vuln status, apply quarantine rules, create bump PRs for candidate projects.

### Watchtower Poller (watchtower-poller/)
**Trigger:** Daily cron via Redis sorted set `watchtower-daily-poll` (checks every 60s, runs every 24h).

**Job 1 - Dependency refresh:**
- For each unique direct dependency: fetch npm latest version
- If version changed: update `dependencies.latest_version`, enqueue `watchtower-new-version-jobs`
- GHSA batch fetch (up to 100 names) -> upsert `dependency_vulnerabilities`

**Job 2 - Poll sweep:**
- For each `watched_packages` with `status = 'ready'`: check for new commits via remote git
- If new commits: incremental analysis (commits, anomaly detection, contributor updates)

---

## Aegis AI Agent

**Architecture:** OpenAI function-calling agent with registered tool actions.

**Flow:**
1. User sends message via `POST /api/aegis/handle`
2. `executor.ts` builds conversation history + system prompt + tool definitions
3. OpenAI processes message, may call tools (listTeams, addMemberToTeam, moveAllMembers, listMembers, listPolicies, getPolicy)
4. Tool results fed back to OpenAI for natural language response
5. All tool executions logged to `aegis_activity_logs`

**Features:**
- Chat threads with message history (`aegis_chat_threads`, `aegis_chat_messages`)
- Scheduled automations (`aegis_automations`) with cron-based job queue (`aegis_automation_jobs`)
- Inbox for alerts/tasks/approvals (`aegis_inbox`)
- Activity logs for audit trail (`aegis_activity_logs`)
- Per-org enable/disable (`aegis_config`)

---

## Database Schema

### Core Tables
| Table | Purpose | Key Relations |
|-------|---------|---------------|
| `extraction_jobs` | Job queue for extraction worker (Supabase-based, survives crashes). status: queued/processing/completed/failed/cancelled. RPC: claim_extraction_job, recover_stuck_extraction_jobs, fail_exhausted_extraction_jobs | FK project_id, organization_id |
| `extraction_logs` | Live extraction log stream. Supabase Realtime enabled. | FK project_id (via run_id) |
| `projects` | Projects with health_score, status_id, asset_tier_id, framework, auto_bump, policy_evaluated_at, status_violations, effective_package_policy_code, effective_project_status_code, effective_pr_check_code (Phase 4 overrides) | FK organization_id, team_id, status_id (organization_statuses), asset_tier_id (organization_asset_tiers) |
| `project_repositories` | One repo per project: provider, repo_full_name, status, extraction_progress | FK project_id (1:1) |
| `dependencies` | Global package registry: name, license, score, openssf, downloads, latest_version, ecosystem, is_malicious (Phase 3) | UNIQUE(name) |
| `dependency_versions` | Versions per dependency: vuln counts, watchtower analysis statuses, slsa_level (0-4, Phase 3) | FK dependency_id, UNIQUE(dependency_id, version) |
| `project_dependencies` | Project-level deps: version, is_direct, source, environment, files_importing_count, ai_usage_summary, policy_result (JSONB: { allowed, reasons } from packagePolicy), is_outdated, versions_behind (Phase 3) | FK project_id, dependency_id, dependency_version_id |
| `dependency_vulnerabilities` | Global vuln data from OSV/GHSA: osv_id, severity, affected_versions, fixed_versions | FK dependency_id, UNIQUE(dependency_id, osv_id) |
| `project_dependency_vulnerabilities` | Project-specific vulns: is_reachable, epss_score, cvss_score, cisa_kev, depscore | FK project_id, project_dependency_id |
| `dependency_version_edges` | Global dependency graph (parent -> child version) | FK parent_version_id, child_version_id |
| `project_dependency_functions` | AST: imported functions per project dependency | FK project_dependency_id |
| `project_dependency_files` | AST: files importing each dependency | FK project_dependency_id |
| `user_profiles` | User avatar_url, full_name | FK auth.users |
| `license_obligations` | SPDX license reference: requires_attribution, requires_notice_file, requires_source_disclosure, requires_license_text, is_copyleft, is_weak_copyleft, summary, full_text. Seeded with ~50 common licenses (phase5_license_obligations.sql, seed_license_obligations.sql). Used by legal-notice export and License Obligations UI. | UNIQUE(license_spdx_id) |

### EE Organization Tables
| Table | Purpose | Key Relations |
|-------|---------|---------------|
| `organizations` | Orgs: name, plan, avatar, github_installation_id | -- |
| `organization_members` | Membership: role (owner/admin/member) | FK organization_id, user_id |
| `organization_roles` | Custom roles with JSONB permissions, color, display_order | FK organization_id |
| `organization_integrations` | Connected providers: access_token, refresh_token, webhook_secret, metadata | FK organization_id, UNIQUE(org, provider) |
| `organization_statuses` | Org-defined project statuses (Compliant, Non-Compliant, Under Review, etc.). name, color, rank, is_system, is_passing. Seeded on org creation. | FK organization_id |
| `organization_asset_tiers` | Org-defined tiers (Crown Jewels, External, Internal, Non-Production). environmental_multiplier for depscore. Seeded on org creation. | FK organization_id |
| `organization_package_policies` | package_policy_code (packagePolicy function). Runs per-dep. | FK organization_id (1:1) |
| `organization_status_codes` | project_status_code (projectStatus function). Assigns status to projects. | FK organization_id (1:1) |
| `organization_pr_checks` | pr_check_code (pullRequestCheck function). PR blocking. | FK organization_id (1:1) |
| `organization_policy_changes` | Org-level version history. previous_code, new_code, message, code_type (package_policy \| project_status \| pr_check). Revert API available. | FK organization_id, parent_id (self) |
| `organization_policies` | Legacy: policy_code (JavaScript). Deprecated; split into package/status/pr tables above. | FK organization_id (1:1) |
| `organization_notification_rules` | Notification rules: trigger_type, min_depscore, custom_code, destinations | FK organization_id |
| `organization_watchlist` | Watched packages: quarantine_until, latest_allowed_version | FK organization_id, dependency_id |
| `organization_watchlist_cleared_commits` | Cleared commits per org per package | FK organization_id |
| `organization_deprecations` | Org-level deprecated packages | FK organization_id, dependency_id |
| `banned_versions` | Org-level banned versions with bump_to_version | FK organization_id |
| `activities` | Activity log: type, description, metadata | FK organization_id, user_id |

### EE Team Tables
| Table | Purpose |
|-------|---------|
| `teams` | Teams within orgs |
| `team_members` | Team membership with role_id |
| `team_roles` | Custom team roles with permissions |
| `project_teams` | Many-to-many projects <-> teams, is_owner flag |
| `team_banned_versions` | Team-level banned versions |
| `team_deprecations` | Team-level deprecations |
| `team_integrations` | Team-scoped integrations |
| `team_notification_rules` | Team notification rules |

### EE Project Extension Tables
| Table | Purpose |
|-------|---------|
| `project_integrations` | Project-scoped integrations |
| `project_notification_rules` | Project notification rules |
| `project_pr_guardrails` | PR merge blocking (vuln thresholds, score minimums) |
| `project_policy_exceptions` | License/SLSA policy exceptions (legacy) |
| `project_policy_changes` | Git-like project-level policy overrides. code_type, base_code, proposed_code, status (pending/accepted/rejected), has_conflict, ai_merged_code. API: create, review (accept/reject), get, revert. UI for Policy Source Card not yet built. |
| `dependency_notes` | Collaborative notes on dependencies |
| `dependency_note_reactions` | Reactions on notes |
| `dependency_prs` | Tracked PRs: type (bump/decrease/remove), target_version, pr_url |

### Aegis Tables
| Table | Purpose |
|-------|---------|
| `aegis_config` | Per-org Aegis enabled flag |
| `aegis_chat_threads` | Chat conversation threads |
| `aegis_chat_messages` | Messages within threads (role, content) |
| `aegis_automations` | Scheduled automations (name, prompt, schedule, enabled) |
| `aegis_automation_jobs` | Job queue for automations (status, scheduled_for, result) |
| `aegis_inbox` | Inbox items (type: alert/message/task/approval/report) |
| `aegis_activity_logs` | Audit log of all Aegis requests and tool executions |

### Watchtower Tables
| Table | Purpose |
|-------|---------|
| `watched_packages` | Global analysis results: status, analysis_data |
| `package_commits` | Commits per watched package |
| `package_commit_touched_functions` | Functions modified per commit |
| `package_contributors` | Contributor profiles for anomaly detection |
| `package_anomalies` | Anomaly scores per commit |

### Entity Relationships
```
organizations
  |-- organization_members (-> auth.users)
  |-- organization_roles
  |-- organization_integrations
  |-- organization_statuses, organization_asset_tiers
  |-- organization_package_policies, organization_status_codes, organization_pr_checks (1:1 each)
  |-- organization_policy_changes (version history)
  |-- organization_policies (1:1, legacy)
  |-- organization_notification_rules
  |-- organization_watchlist (-> dependencies)
  |-- banned_versions
  |-- organization_deprecations (-> dependencies)
  |-- activities
  |-- aegis_config, aegis_chat_threads, aegis_automations, aegis_inbox, aegis_activity_logs
  |-- teams
       |-- team_members (-> auth.users, team_roles)
       |-- team_roles
       |-- team_banned_versions, team_deprecations, team_integrations, team_notification_rules
       |-- project_teams (-> projects)
  |-- projects
       |-- extraction_jobs (job queue, RPC claim)
       |-- extraction_logs (live logs, Realtime)
       |-- project_repositories (1:1)
       |-- project_dependencies (-> dependencies, dependency_versions)
       |     |-- project_dependency_functions
       |     |-- project_dependency_files
       |     |-- project_dependency_vulnerabilities
       |-- project_integrations, project_notification_rules
       |-- project_pr_guardrails, project_policy_exceptions, project_policy_changes
       |-- dependency_notes, dependency_prs

dependencies (global)
  |-- dependency_versions
  |     |-- dependency_version_edges (parent -> child)
  |-- dependency_vulnerabilities (OSV/GHSA)
  |-- watched_packages -> package_commits, package_contributors, package_anomalies
```

---

## Auth Flow

1. Frontend: Google/GitHub OAuth via Supabase Auth -> session with JWT
2. Frontend stores session, sends `Authorization: Bearer <jwt>` on API calls
3. Backend: `authenticateUser` middleware calls `supabase.auth.getUser(token)` -> sets `req.user = { id, email }`
4. `optionalAuth` variant: same flow but doesn't fail on missing/invalid token
5. Frontend `ProtectedRoute` redirects to `/` if no session; `PublicRoute` redirects to `/organizations` if session exists
6. Avatar sync: `checkAndRestoreAvatar` in AuthContext syncs OAuth profile picture to `user_profiles`

---

## Key Data Flows

### Repo Connect -> Extraction
```
User connects repo (ProjectSettingsPage)
  -> POST /api/organizations/:id/projects/:pid/repositories/connect
  -> queueExtractionJob() inserts into extraction_jobs, calls startExtractionMachine() (Fly Machines API)
  -> Fly machine boots, worker claims job via claim_extraction_job RPC (atomic)
  -> Clone -> cdxgen SBOM -> parse -> upsert deps -> AST analysis -> dep-scan vulns -> Semgrep -> TruffleHog
  -> Logs stream to extraction_logs (Realtime) -> SyncDetailSidebar
  -> POST /api/workers/queue-populate (QStash async)
  -> QStash calls POST /api/workers/populate-dependencies
  -> npm registry + GHSA vulns + OpenSSF scorecard -> upsert
  -> evaluateProjectPolicies(): packagePolicy() per dep -> policy_result, projectStatus() -> status_id
  -> Set status = 'ready'
  -> QStash calls POST /api/workers/backfill-dependency-trees
  -> Transitive edge resolution via pacote
```

### Watchtower Monitoring
```
User adds package to watchlist (DependencyWatchtowerPage)
  -> PATCH /api/.../dependencies/:id/watching
  -> queueWatchtowerJob() to Redis watchtower-jobs
  -> Watchtower worker: full analysis (registry, scripts, entropy, commits, contributors, anomalies)
  -> Stored in watched_packages, package_commits, package_contributors, package_anomalies

Daily (watchtower-poller):
  -> Check all direct deps for new npm versions -> enqueue watchtower-new-version-jobs
  -> Check watched packages for new commits -> incremental analysis
  -> GHSA batch vulnerability refresh
```

### Aegis Chat
```
User sends message (SecurityAgentPage or Aegis panel)
  -> POST /api/aegis/handle { organizationId, threadId, message }
  -> executor.ts: build history + system prompt + OpenAI tools
  -> OpenAI processes, may call tools (listTeams, listMembers, listPolicies, etc.)
  -> Tool results fed back to OpenAI -> natural language response
  -> Logged to aegis_activity_logs
  -> Response returned to frontend
```

### Supply Chain Graph
```
User views dependency supply chain (DependencySupplyChainPage)
  -> GET /api/.../dependencies/:id/supply-chain
  -> Reads dependency_version_edges (parent -> child)
  -> Frontend renders @xyflow/react graph with CenterNode + DependencyNodes
  -> BanVersionSidebar / RemoveBanSidebar / SafeVersionCard overlays
```

### Policy-as-Code (Phase 4)
```
Org-level: Policies tab (Package Policy, PR Check) + Statuses tab (Status Code). Each save -> organization_policy_changes. Revert API: POST /policy-code/:codeType/revert.
Project-level: projects.effective_*_code overrides. project_policy_changes for request/review flow. API exists; Policy Source Card UI in Compliance tab not yet built.
Change History: Policies + Statuses tabs show org-level change list. Revert buttons and diff viewer not yet in UI.
```

### Compliance (Phase 5)
```
SBOM Export: GET /api/.../sbom -> fetches sbom.json from Supabase Storage (project-imports/{projectId}/{runId}/)
Legal Notice: GET /api/.../legal-notice -> generates from project_dependencies + license_obligations, Redis-cached 1h, rate-limited 5/min
Registry Search: GET /api/.../registry-search?ecosystem=&query= -> proxies to npm/Maven/Cargo/RubyGems/PyPI/Go
Preflight Check: POST /api/.../preflight-check { packageName, packageVersion?, ecosystem? } -> runs packagePolicy() on hypothetical dep
Apply for Exception: POST /api/.../apply-exception { packageName, version?, reason? } -> Gemini generates modified policy, validates, creates project_policy_change (accepted if manage_policies, pending otherwise)
```

---

## External Services & Integrations

| Service | How It's Used | Config |
|---------|--------------|--------|
| **Supabase** | Postgres DB (all tables), Auth (JWT, OAuth), Realtime (extraction_logs), Storage (SBOM/scan artifacts, avatars, icons). Extraction jobs in `extraction_jobs` table. | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_ANON_KEY` |
| **Fly.io** | Extraction worker (scale-to-zero via Machines API), parser worker, watchtower workers | `fly.toml` per worker. Backend: `FLY_API_TOKEN`, `FLY_EXTRACTION_APP`, `FLY_MAX_BURST_MACHINES` |
| **Upstash QStash** | Async job dispatch: populate-dependencies, backfill-trees. Cron for automations and extraction recovery (optional) | `QSTASH_TOKEN`, `QSTASH_CURRENT_SIGNING_KEY`, `QSTASH_NEXT_SIGNING_KEY` |
| **Upstash Redis** | ast-parsing-jobs, watchtower-jobs, caching. Extraction jobs use Supabase. | `UPSTASH_REDIS_URL`, `UPSTASH_REDIS_TOKEN` |
| **GitHub App** | Repo access, file content, tree, branch/PR ops, commit diffs, webhook | `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET` |
| **GitLab** | OAuth repo access, file content, tree | `GITLAB_CLIENT_ID`, `GITLAB_CLIENT_SECRET` |
| **Bitbucket** | OAuth repo access, file content | `BITBUCKET_CLIENT_ID`, `BITBUCKET_CLIENT_SECRET` |
| **Slack** | OAuth for user + org, notification delivery | `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET` |
| **Discord** | OAuth for user + org, notification delivery | `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET` |
| **Jira** | OAuth + PAT, ticket creation for notifications | `JIRA_CLIENT_ID`, `JIRA_CLIENT_SECRET` |
| **Linear** | API key connect, issue creation | -- |
| **Asana** | OAuth for org, task creation | `ASANA_CLIENT_ID`, `ASANA_CLIENT_SECRET` |
| **Stripe** | OAuth (current: user integration). Full billing in Phase 13 | `STRIPE_CLIENT_ID`, `STRIPE_SECRET_KEY` |
| **OSV.dev** | Vulnerability data (free, no key needed) | -- |
| **Socket.dev** | Malicious package detection (free tier 250/mo) | `SOCKET_API_KEY` |
| **GHSA (GitHub Advisory)** | Batch vulnerability fetch via GraphQL (up to 100 packages) | `GITHUB_TOKEN` / `GH_TOKEN` / `GITHUB_PAT` |
| **OpenSSF Scorecard** | Supply chain security scoring | API (free, no key) |
| **Google AI (Gemini)** | Docs assistant, policy AI, notification AI, usage analysis, Apply for Exception (Phase 5) (Tier 1) | `GOOGLE_AI_API_KEY` |
| **OpenAI** | Aegis chat, Watchtower commit analysis (Tier 2 BYOK) | `OPENAI_API_KEY` |
| **Nodemailer/Gmail** | Email notifications and invitations | `GMAIL_USER`, `GMAIL_APP_PASSWORD` |

**Internal API:** `INTERNAL_API_KEY` — protects recovery endpoint (`/api/internal/recovery/extraction-jobs`), create-bump-pr.

---

## RBAC & Permissions

**Organization roles** (`organization_roles.permissions` JSONB):
- `manage_teams_and_projects`, `view_all_teams_and_projects`, `manage_organization_settings`, `manage_integrations`, `manage_members`, `manage_policies`, `manage_notifications`, `manage_statuses`, `view_activities`

**Team roles** (`team_roles.permissions` JSONB):
- `manage_projects`, `manage_members`, `manage_settings`, `manage_integrations`, `manage_notifications`

**Default org roles:** Owner (all), Admin (all except transfer), Member (view only)
**Default team roles:** Owner (all), Member (view only)

**Permission checks:** Backend routes check membership + role permissions before allowing actions. Frontend hides/disables UI elements based on permissions from API responses.

---

## Roadmap

18-phase roadmap in `.cursor/plans/deptex_projects_roadmap_index.plan.md`.

| Phase | Name | Status |
|-------|------|--------|
| 1 | Multi-Provider Testing | Refined |
| 2 | Fly.io Deployment (scale-to-zero extraction) | Refined |
| 3 | Extraction Enhancements (malicious detection, SLSA, container scanning) | Refined |
| 4 | Policy-as-Code Engine + Custom Statuses | Refined |
| 5 | Compliance Tab Overhaul | Refined |
| 6 | Security Tab Overhaul (Depscore graphs, Semgrep/TruffleHog, Aegis Copilot) | Refined |
| 6B | Code-Level Reachability Engine (atom, call graphs, data-flow) | Refined |
| 7 | AI-Powered Fixing (Aider on Fly.io, 7 fix strategies) | Refined |
| 7B | Aegis Autonomous Security Platform (50+ tools, memory, automations, Slack bot, PR review) | Refined |
| 8 | PR Management & Webhooks (manifest registry, smart extraction, check runs) | Refined |
| 9 | Notifications & Integrations (event bus, 8 destinations, batching, rate limiting) | Refined |
| 10 | UI Polish & Project Overview | Refined |
| 10B | Organization Watchtower Page (per-project activation, org-level view) | Refined |
| 11 | CANCELLED -- merged into 7B | -- |
| 12 | Documentation Overhaul | Refined |
| 13 | Plans, Billing & Stripe (4 tiers, usage metering, plan limits) | Outline |
| 14 | Enterprise Security (MFA, SSO/SAML, session management) | Outline |
| 15 | Security SLA Management (per-severity deadlines, breach detection, compliance reports) | Outline |
| 16 | Aegis Outcome-Based Learning (fix outcome tracking, strategy recommendations) | Outline |
| 17 | Incident Response Orchestration (6-phase IR, playbooks, post-mortem) | Outline |
| 18 | Developer Touchpoints (VS Code extension, CLI, GitHub Action, git hooks) | Outline |

---

## Conventions

- Use git bash, not PowerShell
- Backend: `cd backend && npm run dev` (port 3001). Frontend: `cd frontend && npm run dev` (port 3000)
- CE route: add to `backend/src/routes/`, register in `backend/src/index.ts` OUTSIDE `isEeEdition()` block
- EE route: add to `ee/backend/routes/`, register INSIDE `isEeEdition()` block
- CE must never import from `ee/`. EE imports from `backend/src/` via relative paths
- DB migrations: `backend/database/` for both CE and EE. Document EE-only tables in `ee/database/README.md`
- UI components: Radix primitives + Tailwind (shadcn pattern). Add new components via `npx shadcn@latest`
- See `DEVELOPERS.md` for full setup, `CONTRIBUTING.md` for PR flow. See `fly.md` for extraction worker Fly.io deployment.
- See `.cursor/skills/add-new-features/SKILL.md` for CE vs EE placement decisions
- See `.cursor/skills/frontend-design/SKILL.md` and `.cursor/skills/ui-principles/SKILL.md` for UI standards
