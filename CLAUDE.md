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
| Realtime | Supabase Realtime (subscription to DB changes). Phase 10: useRealtimeStatus subscribes to project_repositories for extraction status. |
| Frontend | React 18 + Vite 5 + Tailwind CSS 3 + Radix UI primitives (shadcn pattern) |
| Routing | React Router v6 (`createBrowserRouter`) |
| Graphs | @xyflow/react (dependency + vulnerability graphs) |
| Tables | @tanstack/react-table |
| Code editor | Monaco Editor (policy code) |
| Forms | react-hook-form + zod validation |
| Workers | 4 Node.js workers (extraction, parser, watchtower-worker, watchtower-poller) |
| SBOM | cdxgen (CycloneDX generation) |
| Vuln scanning | dep-scan (VDR analysis). Phase 6B: `--profile research` for atom engine (call graphs, data-flow). Semgrep, TruffleHog |
| AST parsing | oxc-parser (JS/TS import extraction) |
| Queues | Upstash QStash (async jobs, cron schedules). Phase 8: scheduled-extraction (every 6h), watchtower-daily-poll (daily 4AM UTC). Phase 9: dispatch-notification, dispatch-notification-batch, reconcile-stuck-notifications (every 15min), digest-check (hourly), notification-cleanup (daily 3AM UTC). |
| Cache | Upstash Redis (caching, ast-parsing-jobs, watchtower-jobs, webhook-delivery dedup, notification rate limiting). Extraction jobs use Supabase `extraction_jobs` table. |
| AI - Tier 1 | Google Gemini Flash (platform features — we pay, ~$0.0001/call). getPlatformProvider() in ee/backend/lib/ai/provider.ts |
| AI - Tier 2 | BYOK OpenAI/Anthropic/Google (Aegis Security Copilot, Aider — org pays). organization_ai_providers, AES-256-GCM key encryption |
| AI - Agent engine | Phase 7B: Vercel AI SDK (`ai`, `@ai-sdk/openai`, `@ai-sdk/anthropic`, `@ai-sdk/google`) for multi-turn tool calling, SSE streaming. Frontend: `@ai-sdk/react` useChat. |
| Memory (Aegis) | Phase 7B: pgvector in Supabase for semantic memory; Google text-embedding-004 for embeddings. |
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
      fix-recovery.ts           POST /api/internal/recovery/fix-jobs (CE, X-Internal-Api-Key: Phase 7 AI fix job recovery, requeue stuck, fail exhausted, start machines for orphans)
      aegis-task-step.ts        Phase 7B: POST /api/internal/aegis/execute-task-step, check-due-automations, run-automation/:id, snapshot-debt (QStash or X-Internal-Api-Key)
      vuln-check.ts             POST /api/internal/vuln-check (CE, X-Internal-Api-Key: Phase 6C background vuln monitoring, OSV batch, hourly QStash cron)
      scheduled-extraction.ts   POST /api/workers/scheduled-extraction (CE, QStash or X-Internal-Api-Key: daily/weekly extraction for sync_frequency projects)
      watchtower-daily-poll.ts  POST /api/workers/watchtower-daily-poll (CE, QStash or X-Internal-Api-Key: dependency refresh, poll sweep, webhook health)
      notification-unsubscribe.ts  GET/POST /api/notifications/unsubscribe (CE, token-based email unsubscribe, no auth)
      user-notifications.ts       GET /api/user-notifications (paginated inbox, unread-count, mark-read, mark-all-read), GET/PUT /api/user-notifications/preferences/:orgId (user notification prefs)
      sso.ts                      SSO SAML login/callback/metadata/bypass CE routes (unauthenticated)
      user-sessions.ts            GET/DELETE /api/user/sessions (authenticated)
      user-api-tokens.ts          CRUD /api/user/api-tokens (authenticated)
      scim.ts                     SCIM 2.0 /api/scim/v2/* (SCIM bearer token auth)
      learning-cron.ts            Phase 16: POST /api/internal/learning/recompute-patterns (daily QStash), POST /api/internal/learning/check-feedback-prompts (hourly QStash)
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
      watchtower-poll.ts        Phase 8: Extracted logic from watchtower-poller. runDependencyRefresh(), runPollSweep(), runWebhookHealthCheck(), cleanupOldWebhookDeliveries()
    middleware/
      auth.ts                   authenticateUser (required JWT), optionalAuth. Sets req.user = { id, email }
      ip-allowlist.ts          IP allowlist middleware, CIDR matching via ipaddr.js, in-memory 5min cache
  extraction-worker/            Clone + cdxgen SBOM + dep-scan + AST + Semgrep + TruffleHog. Polls Supabase extraction_jobs (atomic claim). Deployed to Fly.io scale-to-zero. Phase 6B: cdxgen `--profile research --deep`, dep-scan `--profile research --explain --explanation-mode LLMPrompts` (async spawn with heartbeat), parseReachableFlows/parseUsageSlices/updateReachabilityLevels, purl.ts (PURL parser), reachability.ts (atom slice parsing), stream-json for large reachables files. See fly.md.
  parser-worker/                Standalone AST import analysis (oxc-parser)
  watchtower-worker/            Supply-chain forensic analysis (registry integrity, scripts, entropy, commits, contributors, anomalies)
  watchtower-poller/            (Phase 8: deprecated for prod; use QStash cron -> POST /api/workers/watchtower-daily-poll instead)
  aider-worker/                 Phase 7: AI-powered fix worker. Polls project_security_fixes (Supabase). Runs Aider (Python) to apply fix strategies, validates, creates PRs. Deployed to Fly.io scale-to-zero.
   src/
   index.ts                    Poll loop, orchestrates fix pipeline (claim -> clone -> execute -> validate -> PR -> complete)
   job-db.ts                   Supabase RPC wrappers: claimJob, sendHeartbeat, updateJobStatus, isJobCancelled
   logger.ts                   FixLogger: writes to extraction_logs, secret sanitization
   strategies.ts               Ecosystem detection, getStrategyFiles, buildFixPrompt (7 strategies), getSafeInstallCommand, getAuditCommand
   executor.ts                 Aider subprocess management, streaming output, watchdog timeout, env key handling
   validation.ts               Post-fix validation: install, audit, test. Clears LLM keys from env.
   git-ops.ts                  Clone, branch naming (collision handling), commit, push, diff summary, PR creation via Git provider API
   Dockerfile                  node:20-slim + Python venv + aider-chat + git
   fly.toml                    shared-cpu-4x, 8GB RAM, 15m auto-stop
  database/                     ~140 SQL migration files (CE + EE tables). data/spdx-obligations.json for license seed reference.
  load-ee-routes.js             Plain JS loader so tsc doesn't compile ee/

ee/backend/
  routes/
    organizations.ts            Org CRUD, members, invitations, roles, policies, notification rules, deprecations, join link. Phase 4: statuses CRUD, asset tiers CRUD, split policy code. Phase 6C: AI provider CRUD. Phase 9: validate-notification-rule, test-notification-rule, notification-history (paginated, retry), notification-stats, notification-rules/:id/history, revert, pagerduty/connect, snooze, notification-rule-templates. PATCH notifications_paused_until for org pause. Phase 10: GET /:id/stats (org-level aggregated stats, 60s cache).
    teams.ts                    Team CRUD, roles, members, transfer ownership. Phase 6: GET teams/:teamId/security-summary (aggregate security counts). Phase 10: GET teams/:teamId/stats (team-level aggregated stats, 60s cache).
    projects.ts                 Project CRUD, repos, dependencies (list/overview/versions/supply-chain/safe-version), vulnerabilities, policies, exceptions, PR guardrails, Watchtower actions (bump/decrease/remove PRs), notes, contributing teams, AST import status. Extraction: POST extraction/cancel, GET extraction/logs, GET extraction/runs. Phase 5 compliance: GET sbom (real cdxgen from storage), GET legal-notice (grouped by license, Redis-cached), GET registry-search (proxy to npm/Maven/Cargo/RubyGems/PyPI/Go), POST apply-exception (Gemini AI policy exception), GET license-obligations. Policy engine: POST evaluate-policy, POST preflight-check (ecosystem param), POST validate-policy, policy-changes CRUD, revert-policy. Phase 6 Security: GET semgrep-findings, GET secret-findings (permission-gated), GET vulnerabilities/:osvId/detail, PATCH suppress/unsuppress, PATCH accept-risk/unaccept-risk, GET dependencies/:depId/security-summary, GET version-candidates, GET security-summary (org aggregate). Phase 6B: GET reachable-flows (paginated), GET usage-slices (paginated), GET reachable-flows/:flowId/code-context (lazy git provider fetch, rate-limited 30/min). Phase 10: GET projects/:projectId/stats (aggregated dashboard, 60s cache), GET projects/:projectId/recent-activity (union: activities, vuln events, extraction jobs), POST projects/:projectId/sync (retrigger extraction, 60s cooldown).
    activities.ts               GET activities with date/type/team filters
    integrations.ts             OAuth flows + webhooks. Phase 8: GitHub push/PR webhooks (smart extraction, per-project check runs, smart comments, PR tracking, repo lifecycle events). See gitlab-webhooks.ts, bitbucket-webhooks.ts for GitLab/Bitbucket.
    gitlab-webhooks.ts          Phase 8: GitLab Push Hook, Merge Request Hook. Token verification, commit statuses, MR notes.
    bitbucket-webhooks.ts       Phase 8: Bitbucket repo:push, pullrequest:*. HMAC verification, build statuses, PR comments.
    aegis.ts                    Aegis AI: enable/status, chat (handle, stream), threads, automations CRUD + run, inbox, activity logs. Phase 6C: POST /stream (SSE). Phase 7B: POST /v2/stream (AI SDK SSE), GET/PUT settings/:orgId, GET tasks/:orgId, GET tasks/:orgId/:taskId, POST tasks/:taskId/approve|cancel|pause, GET approvals/:orgId, POST approvals/:id/approve|reject, GET/POST/PUT/DELETE memory/:orgId|:id, GET tool-executions/:orgId, GET spending/:orgId, GET usage-stats/:orgId, GET debt/:orgId, POST/GET sprints/:orgId (create, confirm, summary), POST slack/events, POST slack/interactions. Permissions: hasAegisPermission (interact_with_aegis), hasPermission (trigger_fix, etc.).
    workers.ts                  Extraction pipeline: queue-populate, populate-dependencies (QStash), backfill-dependency-trees, extract-deps. Phase 9: POST dispatch-notification, dispatch-notification-batch, reconcile-stuck-notifications, digest-check, notification-cleanup. Houses extractDependencies(), assembleAndSendDigest(). Phase 10: after policy eval, calls computeHealthScore(), invalidates project-stats and org-stats caches.
    watchtower.ts               Supply-chain endpoints: full analysis, commits (with anomaly sort + touches_imported filter), contributors, anomalies, summary, AI commit analysis (GPT-4)
    internal.ts                 Internal API (X-Internal-Api-Key): create-bump-pr
    invitations.ts              GET pending invitations for current user
    learning.ts                 Phase 16: GET /:id/learning/recommendations, GET /:id/learning/dashboard, GET /:id/learning/outcomes, POST /:id/learning/feedback
  lib/
    ai/                         Phase 6C: Two-tier AI infrastructure
      encryption.ts             AES-256-GCM encrypt/decrypt API keys, multi-version key rotation (AI_ENCRYPTION_KEY, AI_ENCRYPTION_KEY_PREV)
      provider.ts               getProviderForOrg(), getPlatformProvider(), createProviderFromKey(). Factory for OpenAI/Anthropic/Google.
      types.ts                  AIProvider interface, Message, ChatResult, StreamChunk, AIProviderError
      models.ts                 Model context windows, PROVIDER_MODELS, getContextWindow()
      pricing.ts                TOKEN_PRICING table, estimateCost(), getTokenPricing()
      logging.ts                logAIUsage() fire-and-forget, getAIUsageSummary(), getAIUsageLogs()
      cost-cap.ts               checkMonthlyCostCap(), checkSSEConcurrency(), recordActualCost() — Redis atomic counters
      providers/
        openai-provider.ts      OpenAI SDK wrapper
        anthropic-provider.ts   @anthropic-ai/sdk wrapper
        google-provider.ts      @google/generative-ai wrapper
    aegis/
      executor.ts               Legacy single-shot Aegis; logs to aegis_activity_logs
      executor-v2.ts            Phase 7B: Multi-turn ReAct loop via Vercel AI SDK streamText(maxSteps), createAegisStream(), BYOK via llm-provider
      llm-provider.ts           Phase 7B: Bridges getProviderForOrg() to AI SDK LanguageModel; getEmbeddingModel() for memory (text-embedding-004)
      systemPrompt.ts           Legacy system prompt. Phase 6C: getSecuritySystemPrompt()
      system-prompt-v2.ts       Phase 7B: buildAgentSystemPrompt() — role, tool categories, anti-hallucination, plan mode, dynamic context
      tasks.ts                  Phase 7B: createTask, approveTask, cancelTask, pauseTask, executeTaskStep, getNextPendingStep; circuit breaker >50% failures
      sprint-orchestrator.ts    Phase 7B: createSecuritySprint(), confirmInteractiveSprint(), getSprintSummary(); batch fix as aegis_task with fix steps
      slack-bot.ts              Phase 7B: handleSlackEvent (app_mention), handleSlackInteraction (approval buttons), processSlackMessage, sendSlackResponse
      automations-engine.ts     Phase 7B: checkDueAutomations (QStash cron), runAutomation(), matchEventTrigger(), cronMatchesNow, AUTOMATION_TEMPLATES
      security-debt.ts          Phase 7B: computeDebtScore(), snapshotDebt(), getDebtHistory(), getDebtVelocity()
      pr-review.ts              Phase 7B: reviewPR(), generatePRComment(); risk assessment, policy checks, structured markdown comment
      tools/
        types.ts                ToolCategory, PermissionLevel, AegisToolMeta, ToolContext, TOOL_PROFILES
        registry.ts             registerAegisTool(), getAllToolMetas(), resolveActiveProfiles(), checkToolPermission(), logToolExecution(), buildToolSet()
        index.ts                Imports all category modules to register tools
        org-management.ts       listOrganizations, listTeams, addMemberToTeam, moveAllMembers, listMembers, getOrgSummary, listProjects, getProjectSummary (8)
        project-ops.ts          listDependencies, getDependencyVersions, getSafeVersion, listVulnerabilities, getVulnerabilityDetail, triggerAiFix, getExtractionStatus, listProjectRepos (8)
        security-ops.ts         getProjectVulnerabilities, getSecuritySummary, getVersionCandidates, getSemgrepFindings, getSecretFindings, analyzeReachability, generateSecurityReport, suggestFixPriority, explainVulnerability, emergencyLockdownPackage (10)
        policy.ts               listPolicies, getPolicy, testPolicyDryRun, generatePolicyFromDescription, getComplianceStatus, generateSBOM, generateVEX (7)
        compliance.ts           generateLicenseNotice, generateAuditPackage, getComplianceStatus, listPolicyExceptions, evaluatePolicy (5)
        intelligence.ts         getPackageReputation, getBlastRadius, getEPSSScores, getZeroDayAlerts, getWatchtowerSummary, analyzeNewDependency (6)
        reporting.ts            getSecurityMetrics, generateExecutiveReport, getROIMetrics, getActivityFeed (4)
        external.ts             createJiraTicket, createLinearIssue, createSlackMessage, sendEmail, triggerWebhook, createAsanaTask (6)
        memory.ts               storeMemory, queryMemory, deleteMemory (3)
        automation.ts           listAutomations, createAutomation, runAutomation (3)
        learning.ts             Phase 16: getStrategyRecommendation (1)
    learning/
      strategy-constants.ts     Phase 16: CANONICAL_STRATEGIES, normalizeStrategy(), LEGACY_TO_CANONICAL map
      outcome-recorder.ts       Phase 16: recordOutcomeFromFixJob(), updateOutcomeOnMerge(), markOutcomeReverted(), backfillMissingOutcomes()
      pattern-engine.ts         Phase 16: recomputePatterns() (calls compute_strategy_patterns RPC), recomputeAllStaleOrgs(), queryPatterns()
      recommendation-engine.ts  Phase 16: recommendStrategies() (ranked with confidence/cost/revert penalties), getDashboardData()
      actions/
        index.ts                Legacy action registry (Phase 6C)
        init.ts                 Imports teams, members, policies, security to register actions
        teams.ts                listTeams, addMemberToTeam, moveAllMembers
        members.ts              listMembers (with team info)
        policies.ts             listPolicies, getPolicy
        security.ts             Phase 6C: getProjectVulnerabilities, getVulnerabilityDetail, triggerAiFix (stub), etc.
      queue.ts                  Legacy automation processor: parseScheduleToNextRun, processAutomationJobs, scheduleAutomations
    github.ts                   GitHub App: JWT, installation tokens, repo file/tree access, branch/PR operations, commit diffs. Phase 8: listIssueComments, updateIssueComment for smart PR comments.
    manifest-registry.ts        Phase 8: MANIFEST_PATTERNS, matchManifestFile(), detectAffectedWorkspaces() for multi-ecosystem change detection.
    gitlab-api.ts               GitLab OAuth: repo listing, file content, tree access
    bitbucket-api.ts            Bitbucket OAuth: repo listing, file content
    git-provider.ts             GitHubProvider, GitLabProvider, BitbucketProvider implementing GitProvider interface. createProvider(integration) factory
    qstash.ts                   QStash helpers: signature verification, queuePopulateDependencyBatch, queueBackfillDependencyTrees, queueDependencyAnalysis
    redis.ts                    Redis: queueASTParsingJob. Supabase: queueExtractionJob (inserts extraction_jobs, calls startExtractionMachine), cancelExtractionJob
    fly-machines.ts             Fly Machines API: startFlyMachine(config) generic launcher. EXTRACTION_CONFIG + AIDER_CONFIG. startExtractionMachine(), startAiderMachine(), stopFlyMachine(). Phase 7: generalized from extraction-only.
    ai-fix-engine.ts            Phase 7: Fix orchestrator. requestFix() (validate, BYOK check, budget, context, queue_fix_job RPC, start machine), cancelFixJob(), checkExistingFix(), checkAndReserveBudget(). 7 strategies, 3 fix types.
    rate-limit.ts               checkRateLimit(key, maxRequests, windowSeconds) — Redis-backed, fail-open. Phase 6C: Tier 1 limits (analyze usage 5/day, policy assistant 20/conv 50/day, report 3/day), Tier 2 (Aegis 200 msg/day).
    cache.ts                    Redis cache: getCached/setCached/invalidateCache, TTL constants, cache key helpers for projects/deps/versions/safe-versions/watchtower/legal-notice. Phase 10: project-stats:{id}, org-stats:{id}, team-stats:{id}, sync-cooldown:{projectId}
    openai.ts                   Lazy-init OpenAI client
    email.ts                    sendEmail, sendInvitationEmail (nodemailer/Gmail)
    activities.ts               createActivity() -- insert activity log
    create-bump-pr.ts           Create version bump PR via GitHub/GitLab/Bitbucket
    create-remove-pr.ts         Create package removal PR
    latest-safe-version.ts      Calculate latest safe version (vuln checks + cache)
    project-policies.ts         isLicenseAllowed(), getEffectivePolicies() (org policy_code for a project)
    policy-engine.ts            Sandboxed policy execution (isolated-vm or Function fallback). evaluateProjectPolicies(), validatePolicyCode(), preflightCheck(). Runs packagePolicy() per dep, projectStatus(), pullRequestCheck().
    health-score.ts             Phase 10: computeHealthScore(projectId) — weighted 0–100 (40% compliance, 30% vulns, 20% freshness, 10% code findings). Called after populate + policy eval.
    event-bus.ts                Phase 9: emitEvent(), emitEventBatch(), QStash dispatch queuing, resolveTeamId(). Persists to notification_events.
    notification-dispatcher.ts  Phase 9: dispatchNotification(), dispatchNotificationBatch(), rule cascade (org+team+project), sandbox trigger execution, dedup, OAuth refresh mutex, in-app notification creation.
    notification-validator.ts   Phase 9: validateNotificationTriggerCode() (syntax, shape, fetch resilience), executeNotificationTrigger() with SSRF-protected sandbox.
    destination-dispatchers.ts  Phase 9: Slack Block Kit, Discord embeds, Jira, Linear, Asana, Email (with CAN-SPAM unsubscribe), Custom HMAC webhooks, PagerDuty Events API. buildDefaultMessage(), enforceMessageLimits().
    notification-rate-limiter.ts Phase 9: checkOrgRateLimit (200/hr), checkDestinationRateLimit (30/hr, 10/hr ticketing), Redis sliding window.
    notification-health.ts      Phase 9: updateConnectionHealth(), auto-disable integration after 3 consecutive failures.
    policy-defaults.ts          DEFAULT_PACKAGE_POLICY_CODE, DEFAULT_PROJECT_STATUS_CODE, DEFAULT_PR_CHECK_CODE
    policy-seed.ts              Seeds statuses and asset tiers on org creation
    health-score.ts             Phase 10: computeHealthScore(projectId) — weighted 0–100 (40% compliance, 30% vulns, 20% freshness, 10% code findings). Called after populate + policy eval.
    watchtower-queue.ts         queueWatchtowerJob() to Redis watchtower-jobs queue
    security-audit.ts           logSecurityEvent() fire-and-forget to security_audit_logs, getClientIp()
    saml.ts                     createSAMLInstance(), generateAuthRequest(), validateResponse(), verifyDomain() DNS TXT, generateBypassToken(), generateSCIMToken()
    plan-limits.ts              getFeatureAccess(plan), checkFeatureAccess(), getTierLevel() -- plan tier gating

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
| `/organizations/:id` | OrganizationLayout with tabs (Phase 10: Org Overview shows stats, mini graph, security posture, status distribution, activity feed) |
| `/organizations/:id/teams` | TeamsPage |
| `/organizations/:id/security` | OrganizationVulnerabilitiesPage (Security tab). Redirect: `/vulnerabilities` → `/security` |
| `/organizations/:id/projects` | ProjectsPage |
| `/organizations/:id/settings` | OrganizationSettingsPage (general, members, roles, integrations, webhooks, notifications, ai_configuration, statuses, policies, audit_logs, aegis_management, etc.) |
| `/organizations/:id/aegis` | AegisPage (Phase 7B: dedicated three-panel Aegis screen; useChat with /api/aegis/v2/stream). Optional :threadId for deep-link. |
| `/organizations/:id/policies` | PoliciesPage (Package Policy, PR Check Monaco editors; Change History sub-tab) |
| `/organizations/:id/compliance` | CompliancePage |
| `/organizations/:orgId/projects/:projectId/overview` | ProjectOverviewPage (Phase 10: real stats, status/tier badges, sync button, real-time extraction, mini graph, action items, activity feed) |
| `/organizations/:orgId/projects/:projectId/security` | ProjectVulnerabilitiesPage (Security tab). Redirect: `/vulnerabilities` → `/security` |
| `/organizations/:orgId/projects/:projectId/dependencies` | ProjectDependenciesPage |
| `/organizations/:orgId/projects/:projectId/dependencies/:dependencyId/overview` | DependencyOverviewPage |
| `/organizations/:orgId/projects/:projectId/dependencies/:dependencyId/watchtower` | DependencyWatchtowerPage |
| `/organizations/:orgId/projects/:projectId/dependencies/:dependencyId/supply-chain` | DependencySupplyChainPage |
| `/organizations/:orgId/projects/:projectId/compliance` | ProjectCompliancePage. Sub-routes: /compliance/project, /compliance/policy-results, /compliance/updates (Phase 8: Pull Requests + Commits sub-tabs with real API data) |
| `/organizations/:orgId/projects/:projectId/settings` | ProjectSettingsPage (asset tier dropdown, Phase 8: sync frequency dropdown, webhook health, disconnected repo banner) |
| `/organizations/:orgId/teams/:teamId/overview` | TeamOverviewPage |
| `/organizations/:orgId/teams/:teamId/projects` | TeamProjectsPage |
| `/organizations/:orgId/teams/:teamId/members` | TeamMembersPage |
| `/organizations/:orgId/teams/:teamId/alerts` | TeamAlertsPage |
| `/organizations/:orgId/teams/:teamId/settings` | TeamSettingsPage |
| `/invite/:invitationId` | InvitePage |
| `/join/:organizationId` | JoinPage |
| `/settings` | SettingsPage (general, connected accounts, notifications) |
| `/settings/notifications` | SettingsPage (Notifications tab — user prefs: email opt-out, event muting, DND, digest preference per org) |

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
- **NotificationBell** -- Phase 9: In-app notification center in AppHeader. Unread badge, Supabase Realtime subscription, popover dropdown with mark-read, mark-all-read.
- **NavBar** -- main marketing nav with Product/Resources dropdowns
- **OrganizationSidebar / ProjectSidebar / TeamSidebar / SettingsSidebar / DependencySidebar** -- navigation sidebars
- **OrganizationSwitcher / ProjectSwitcher / TeamSwitcher** -- entity switchers
- **ProtectedRoute / PublicRoute** -- auth guards via AuthContext

### Overview Screens (Phase 10)
- **StatsStrip** -- reusable horizontal stat cards (4–5 per row), skeleton loading
- **ActionableItems** -- prioritized action list (critical vulns, compliance, code findings); green shield empty state
- **ActivityFeed** -- timeline of recent events with slide-out sidebar for details (sync, vuln, policy)
- **OverviewGraph** -- ReactFlow mini-graph (project/team/org modes), lazy load via IntersectionObserver, node limits, empty states
- **useRealtimeStatus** -- Supabase subscription on `project_repositories` for extraction status; 5s polling fallback

### Dependency & Supply Chain
- **PackageOverview** -- package metadata, score, downloads, versions
- **supply-chain/** -- CenterNode, DependencyNode, BanVersionSidebar, RemoveBanSidebar, SafeVersionCard, UnusedInProjectCard, useGraphLayout (xyflow graph)
- **vulnerabilities-graph/** -- ProjectCenterNode (Phase 6: security counts, clickable), VulnProjectNode, VulnerabilityNode (Phase 6: EPSS, KEV, reachability, fix indicators, Depscore coloring. Phase 6B: tiered reachability icons — data_flow=orange, function=yellow, module=gray, unreachable=dimmed), useTeamVulnerabilitiesGraphLayout, useOrganizationVulnerabilitiesGraphLayout, VulnerabilitiesSimulationCard

### Security (Phase 6)
- **SecuritySidebar** -- shared slide-in sidebar wrapper for Security tab context (project, dependency, vulnerability)
- **VulnerabilityDetailContent** -- full vulnerability detail with suppress/accept-risk actions. Phase 6B: tiered reachability badge. Phase 6C: "Explain with Aegis", "Fix with AI" buttons (require BYOK + interact_with_security_agent).
- **CodeImpactView** -- Phase 6B: data-flow visualization with atom code snippets, call chain arrows, collapsible steps, lazy code context via git provider API, "Explain with Aegis" hook
- **DependencySecurityContent** -- dependency-level security summary (Semgrep, secrets, vulns, version candidates). Phase 6B: usage slices (specific functions used)
- **ProjectSecurityContent** -- project-level Security tab content (graph, filters). Phase 6C: "Ask Aegis" buttons on Semgrep, secrets, priority actions (require BYOK + interact_with_security_agent).
- **SecurityFilterBar** -- filters with URL persistence (severity, KEV, suppressed, etc.). Phase 6B: reachability level filter (All, Data flow, Function, Module, Unreachable)

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
- **PolicyAIAssistant** -- AI-powered policy code helper (Gemini, Tier 1)
- **NotificationAIAssistant** -- AI-powered notification rule helper (Tier 1)
- **NotificationRulesSection** -- Phase 9: Org/team/project notification rules. Template picker, Test Rule button, validation display, dry-run toggle, snooze, PagerDuty destination, IntelliSense for context. Sub-tabs: Rules, History, Health.
- **NotificationHistorySection** -- Phase 9: Delivery history table with filters (event type, destination, status, timeframe), expandable rows, retry failed.
- **PolicyDiffViewer** -- diff view for policy changes
- **DocsAIAssistant** -- floating docs Q&A panel (Tier 1)
- **AegisPanel** -- Phase 6C: collapsible right panel, streaming chat (legacy /api/aegis/stream), context switching (project/vuln/dependency/semgrep/secret), quick actions, markdown rendering. Requires BYOK + interact_with_aegis.
- **AegisPage** -- Phase 7B: Full-page Aegis at /organizations/:id/aegis. Three-panel layout (threads + tasks/automations, main chat with useChat + /api/aegis/v2/stream, optional right context panel). Org sidebar "Aegis" nav item gated by interact_with_aegis.
- **AegisManagementConsole** -- Phase 7B: Org Settings > AI & Automation > Aegis AI. 9 tabs: Configuration (operating mode, tool permissions, budgets), Active Work (tasks, approvals), Automations, Memory, Usage Analytics, Audit Log; Phase 16: Learning tab replaced with real LearningDashboard; Incidents placeholder. Requires manage_aegis.
- **AIConfigurationSection** -- Phase 6C: Org Settings > AI & Automation > AI Configuration. Provider cards (OpenAI, Anthropic, Google), connect modal, usage dashboard (monthly summary, cost by feature/user, recent logs).
- **StrategyPicker** -- Phase 16: Dialog for selecting AI fix strategy with ranked recommendations, success rates, confidence badges, cost/duration, warnings, expandable reasoning. Cold-start fallback when no org data.
- **LearningDashboard** -- Phase 16: 5-section dashboard in AegisManagementConsole Learning tab: Strategy Performance Matrix, Learning Curve (recharts line/area), Failure Analysis (horizontal bars), Follow-up Chains, Quality Insights (star ratings). Uses recharts.

### UI Primitives (shadcn/Radix)
button, input, label, checkbox, switch, slider, progress, badge, avatar, card, dialog, sheet, dropdown-menu, popover, tooltip, toast, toaster, calendar, accordion, select, separator, tabs

---

## Worker Pipelines

### Extraction Worker (extraction-worker/)
**Trigger:** `queueExtractionJob()` inserts into Supabase `extraction_jobs` table and calls `startExtractionMachine()` to start a Fly.io machine. Worker polls Supabase via atomic `claim_extraction_job` RPC (FOR UPDATE SKIP LOCKED). Machines scale-to-zero: 60s idle shutdown.

**Fault tolerance:** Heartbeat every 60s; stuck detection after 5 min no heartbeat; recovery cron (`POST /api/internal/recovery/extraction-jobs`) requeues stuck jobs, fails exhausted (max 3 attempts), starts machines for orphaned queued jobs. 4-hour machine watchdog.

**Pipeline:**
1. **Clone** -- clone repo via GitHub App / GitLab OAuth / Bitbucket OAuth token
2. **SBOM** -- run `cdxgen --profile research --deep` (15-min timeout). Phase 6B: research profile for atom-compatible metadata.
3. **Parse SBOM** -- extract dependencies, relationships, licenses from SBOM
4. **Upsert** -- insert/update `dependencies`, `dependency_versions`, `project_dependencies`, `dependency_version_edges`
5. **Queue populate** -- call `POST /api/workers/queue-populate` for new direct deps
6. **AST import analysis** -- oxc-parser on JS/TS files, extract ESM imports -> `project_dependency_functions`, `project_dependency_files`, `files_importing_count`
7. **dep-scan** -- Phase 6B: async `spawn()` with heartbeat (not spawnSync). `--profile research --vulnerability-analyzer VDRAnalyzer --explain --explanation-mode LLMPrompts`. Produces `*-reachables.slices.json`, `*-usages.slices.json`, LLM prompts. VDR analysis for vulnerabilities, EPSS, CISA KEV, depscore.
8. **Reachability (Phase 6B)** -- parse reachable flows (stream-json for >50MB), usage slices, LLM prompts; update `reachability_level` on `project_dependency_vulnerabilities`; upsert `project_reachable_flows`, `project_usage_slices`. Fallback: atom failure preserves prior data.
9. **Semgrep** -- `semgrep scan --config auto` for code security findings (optional). Phase 6: parse JSON → upsert `project_semgrep_findings` (metadata sanitized: no source/fix in DB).
10. **TruffleHog** -- secret scanning (optional). Phase 6: parse output → upsert `project_secret_findings` (redacted, Raw stripped before storage).
11. **Upload** -- store sbom.json, dep-scan.json, semgrep.json, trufflehog.json to Supabase storage `project-imports/{projectId}/{runId}/`
12. **Status** -- set `project_repositories.status = 'ready'`, `extraction_step = 'completed'`
13. **Finalization (Phase 6)** -- after successful run, delete findings from prior runs (stale Semgrep/secret records). Phase 6B: also delete stale `project_reachable_flows`, `project_usage_slices` from other `extraction_run_id`.

**Live logs:** `ExtractionLogger` writes to `extraction_logs` (Supabase Realtime). Frontend SyncDetailSidebar subscribes for live streaming.

**Populate callback** (`POST /api/workers/populate-dependencies` via QStash):
- Fetch npm registry (versions, downloads, GitHub URL)
- Fetch GHSA vulnerabilities (batch GraphQL)
- Fetch OpenSSF scorecard
- Compute reputation score (OpenSSF + popularity + maintenance penalties)
- **Policy evaluation** (Phase 4): After batch populated, run `evaluateProjectPolicies()` — packagePolicy() per dep (stores `policy_result`), projectStatus() (sets `projects.status_id`, `status_violations`), then `status = 'ready'`
- Queue `backfill-dependency-trees` for transitive edge resolution

**Depscore**: Uses `tierMultiplier` from `organization_asset_tiers` (project's `asset_tier_id`); pipeline fetches from DB and passes to `calculateDepscore()`. Phase 6B: tiered `reachabilityLevel` weights (confirmed=1.0, data_flow=0.9, function=0.7, module=0.5). Falls back to `isReachable` boolean when `reachabilityLevel` is null.

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

**Phase 7B architecture:** Multi-turn ReAct agent powered by Vercel AI SDK. Two entry points: legacy single-shot `POST /api/aegis/handle` and `POST /api/aegis/stream` (Phase 6C), and Phase 7B `POST /api/aegis/v2/stream` (AI SDK SSE, useChat on frontend).

**Phase 7B flow (v2/stream):**
1. Frontend (AegisPage or AegisPanel) sends message to `POST /api/aegis/v2/stream` with organizationId, threadId, message, optional context.
2. `executor-v2.ts` loads BYOK model via `llm-provider.ts`, gets/creates thread, loads history, queries `aegis_memory` (pgvector) for relevant context, builds system prompt (`system-prompt-v2.ts`), builds tool set from `tools/registry.ts` (50+ tools across 10 categories) with permission checks and logging.
3. AI SDK `streamText()` runs with `maxSteps` (multi-turn tool loop). Each tool call: `checkToolPermission()` (RBAC + danger level + org overrides), optional approval flow for dangerous tools, `execute`, `logToolExecution()` to `aegis_tool_executions`.
4. Streamed response returned as SSE; messages and token counts persisted on finish.

**Features:**
- Chat threads with message history (`aegis_chat_threads`, `aegis_chat_messages`); Phase 7B: metadata for tool refs.
- **Task system (Phase 7B):** Plan-then-execute. User approves plan → `aegis_tasks` + `aegis_task_steps`; QStash triggers `POST /api/internal/aegis/execute-task-step` for each step; circuit breaker on >50% failures.
- **Sprint orchestration (Phase 7B):** `createSecuritySprint()` discovers vuln/semgrep/secret candidates, builds task with triggerAiFix steps; `POST /api/aegis/sprints/:orgId`, confirm, summary.
- **Memory (Phase 7B):** pgvector `aegis_memory` with embeddings; queryMemory() injects relevant snippets into system prompt.
- **Automations (Phase 7B):** QStash cron `POST /api/internal/aegis/check-due-automations`; `runAutomation()`, event triggers (`aegis_event_triggers`), templates, auto-disable after 3 failures.
- **Slack bot (Phase 7B):** `POST /api/aegis/slack/events` (app_mention), `POST /api/aegis/slack/interactions` (approval buttons); `aegis_slack_config` per org.
- **PR security review (Phase 7B):** `pr-review.ts` reviewPR(), generatePRComment(); risk assessment, policy checks.
- **Security debt (Phase 7B):** `security-debt.ts` computeDebtScore(), snapshotDebt(); daily QStash `POST /api/internal/aegis/snapshot-debt`; `security_debt_snapshots` table.
- **Management console (Phase 7B):** Org Settings > AI & Automation > Aegis AI; settings, tasks, approvals, memory, automations, usage, audit log. Permissions: `interact_with_aegis`, `manage_aegis`, `trigger_fix`, `view_ai_spending`, `manage_incidents`.
- Per-org enable/disable (`aegis_config`); Phase 7B per-org config in `aegis_org_settings`.

---

## Database Schema

### Core Tables
| Table | Purpose | Key Relations |
|-------|---------|---------------|
| `extraction_jobs` | Job queue for extraction worker (Supabase-based, survives crashes). status: queued/processing/completed/failed/cancelled. RPC: claim_extraction_job, recover_stuck_extraction_jobs, fail_exhausted_extraction_jobs | FK project_id, organization_id |
| `extraction_logs` | Live extraction log stream. Supabase Realtime enabled. | FK project_id (via run_id) |
| `projects` | Projects with health_score (Phase 10: computed by computeHealthScore after populate+policy), status_id, asset_tier_id, framework, auto_bump, policy_evaluated_at, status_violations. Phase 6C: last_vuln_check_at, vuln_check_frequency (12h/24h/48h/weekly). | FK organization_id, team_id, status_id (organization_statuses), asset_tier_id (organization_asset_tiers) |
| `project_repositories` | One repo per project: provider, repo_full_name, status, extraction_progress. Phase 8: sync_frequency, webhook_id, webhook_secret, last_webhook_at, last_webhook_event, webhook_status, last_extracted_at | FK project_id (1:1) |
| `dependencies` | Global package registry: name, license, score, openssf, downloads, latest_version, ecosystem, is_malicious (Phase 3) | UNIQUE(name) |
| `dependency_versions` | Versions per dependency: vuln counts, watchtower analysis statuses, slsa_level (0-4, Phase 3) | FK dependency_id, UNIQUE(dependency_id, version) |
| `project_dependencies` | Project-level deps: version, is_direct, source, environment, files_importing_count, ai_usage_summary, policy_result (JSONB: { allowed, reasons } from packagePolicy), is_outdated, versions_behind (Phase 3) | FK project_id, dependency_id, dependency_version_id |
| `dependency_vulnerabilities` | Global vuln data from OSV/GHSA: osv_id, severity, affected_versions, fixed_versions, cwe_ids (Phase 16: TEXT[] from GHSA cwes) | FK dependency_id, UNIQUE(dependency_id, osv_id) |
| `project_dependency_vulnerabilities` | Project-specific vulns: is_reachable, epss_score, cvss_score, cisa_kev, depscore. Phase 6: suppressed, suppressed_by, suppressed_at, risk_accepted, risk_accepted_by, risk_accepted_at, risk_accepted_reason. Phase 6B: reachability_level (unreachable/module/function/data_flow/confirmed), reachability_details JSONB | FK project_id, project_dependency_id |
| `dependency_version_edges` | Global dependency graph (parent -> child version) | FK parent_version_id, child_version_id |
| `project_dependency_functions` | AST: imported functions per project dependency | FK project_dependency_id |
| `project_dependency_files` | AST: files importing each dependency | FK project_dependency_id |
| `user_profiles` | User avatar_url, full_name | FK auth.users |
| `license_obligations` | SPDX license reference: requires_attribution, requires_notice_file, requires_source_disclosure, requires_license_text, is_copyleft, is_weak_copyleft, summary, full_text. Seeded with ~50 common licenses (phase5_license_obligations.sql, seed_license_obligations.sql). Used by legal-notice export and License Obligations UI. | UNIQUE(license_spdx_id) |

### EE Organization Tables
| Table | Purpose | Key Relations |
|-------|---------|---------------|
| `organization_ai_providers` | Phase 6C: BYOK provider config per org. provider (openai/anthropic/google), encrypted_api_key, model_preference, is_default, monthly_cost_cap. AES-256-GCM encryption. | FK organization_id, UNIQUE(organization_id, provider) |
| `ai_usage_logs` | Phase 6C: AI usage audit. feature, tier (platform/byok), provider, model, input/output tokens, estimated_cost, duration_ms, success, context_type, context_id. | FK organization_id, user_id |
| `organizations` | Orgs: name, plan, avatar, github_installation_id. Phase 9: timezone, notifications_paused_until | -- |
| `organization_members` | Membership: role (owner/admin/member) | FK organization_id, user_id |
| `organization_roles` | Custom roles with JSONB permissions, color, display_order | FK organization_id |
| `organization_integrations` | Connected providers: access_token, refresh_token, webhook_secret, metadata. Phase 9: token_expires_at, consecutive_failures, last_failure_at | FK organization_id, UNIQUE(org, provider) |
| `organization_statuses` | Org-defined project statuses (Compliant, Non-Compliant, Under Review, etc.). name, color, rank, is_system, is_passing. Seeded on org creation. | FK organization_id |
| `organization_asset_tiers` | Org-defined tiers (Crown Jewels, External, Internal, Non-Production). environmental_multiplier for depscore. Seeded on org creation. | FK organization_id |
| `organization_package_policies` | package_policy_code (packagePolicy function). Runs per-dep. | FK organization_id (1:1) |
| `organization_status_codes` | project_status_code (projectStatus function). Assigns status to projects. | FK organization_id (1:1) |
| `organization_pr_checks` | pr_check_code (pullRequestCheck function). PR blocking. | FK organization_id (1:1) |
| `organization_policy_changes` | Org-level version history. previous_code, new_code, message, code_type (package_policy \| project_status \| pr_check). Revert API available. | FK organization_id, parent_id (self) |
| `organization_policies` | Legacy: policy_code (JavaScript). Deprecated; split into package/status/pr tables above. | FK organization_id (1:1) |
| `organization_notification_rules` | Notification rules: trigger_type (weekly_digest \| custom_code_pipeline), min_depscore, custom_code, destinations. Phase 9: schedule_config, snoozed_until, dry_run | FK organization_id |
| `organization_watchlist` | Watched packages: quarantine_until, latest_allowed_version | FK organization_id, dependency_id |
| `organization_watchlist_cleared_commits` | Cleared commits per org per package | FK organization_id |
| `organization_deprecations` | Org-level deprecated packages | FK organization_id, dependency_id |
| `banned_versions` | Org-level banned versions with bump_to_version | FK organization_id |
| `activities` | Activity log: type, description, metadata. Phase 10: GIN index on metadata for project-scoped queries (metadata->>'project_id') | FK organization_id, user_id |

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
| `project_semgrep_findings` | Phase 6: Semgrep code findings (rule_id, severity, path, message; metadata sanitized). FK project_id. | FK project_id |
| `project_secret_findings` | Phase 6: TruffleHog secret findings (redacted, no Raw in DB). Permission-gated in API. | FK project_id |
| `project_reachable_flows` | Phase 6B: atom data-flow paths. purl, dependency_id, flow_nodes JSONB, entry_point_*, sink_*, llm_prompt. extraction_run_id for stale cleanup. | FK project_id, dependency_id |
| `project_usage_slices` | Phase 6B: atom usage slices (file_path, line_number, target_name, resolved_method, target_type). extraction_run_id for stale cleanup. | FK project_id |
| `project_vulnerability_events` | Phase 6: vuln lifecycle (event_type: detected/resolved, osv_id, project_dependency_id). For timeline/MTTR. | FK project_id |
| `project_version_candidates` | Phase 6: upgrade suggestions (same_major_safe, fully_safe, latest). OSV-verified, respects banned_versions. | FK project_id, dependency_id |
| `project_commits` | Phase 8: commits hitting default branch. sha, message, author, manifest_changed, extraction_triggered, compliance_status, provider_url. Powers Compliance tab Commits sub-tab. | FK project_id |
| `project_pull_requests` | Phase 8: PR lifecycle tracking. pr_number, status (open/merged/closed), check_result, check_summary, deps_added/updated/removed, blocked_by. Powers Compliance tab Pull Requests sub-tab. | FK project_id |
| `project_security_fixes` | Phase 7: AI fix jobs. fix_type (vulnerability/semgrep/secret), strategy (7 types), status (queued/running/completed/failed/cancelled/pr_closed/merged/superseded), target IDs, payload JSONB, machine_id, heartbeat_at, attempts/max_attempts, pr_url/pr_number/pr_branch, diff_summary, tokens_used, estimated_cost, validation_result, error_message/error_category. RPC: claim_fix_job, queue_fix_job, recover_stuck_fix_jobs, fail_exhausted_fix_jobs. | FK project_id, organization_id |
| `webhook_deliveries` | Phase 8: audit trail of all webhook receipts. delivery_id, provider, event_type, processing_status, error_message. 30-day retention. | -- |

### Phase 9 Notification Tables
| Table | Purpose | Key Relations |
|-------|---------|---------------|
| `notification_events` | Event persistence. event_type, organization_id, project_id, team_id, payload, source, priority, batch_id, deduplication_key, dispatch_attempts, status (pending/dispatching/dispatched/failed) | FK organization_id, project_id, team_id |
| `notification_deliveries` | Delivery tracking. event_id, rule_id, rule_scope, destination_type, destination_id, status, message_title/body, response, external_id, error_message, attempts, is_test | FK event_id, organization_id |
| `user_notification_preferences` | Per-user, per-org: email_opted_out, muted_event_types, muted_project_ids, dnd_start/end_hour, digest_preference | FK user_id, organization_id, UNIQUE(user_id, organization_id) |
| `user_notifications` | In-app inbox. title, body, severity, event_type, project_id, deptex_url, read_at. 30-day retention. | FK user_id, organization_id, event_id |
| `notification_rule_changes` | Rule version history. previous_code, new_code, previous_destinations, new_destinations, changed_by_user_id | FK organization_id |

### Enterprise Security Tables (Phase 14)
| Table | Purpose | Key Relations |
|-------|---------|---------------|
| `security_audit_logs` | Security event audit trail. action, actor_id, target_type/id, ip_address, user_agent, metadata, severity (info/warning/critical) | FK organization_id |
| `organization_mfa_exemptions` | Temp MFA exemptions per user. reason, expires_at, exempted_by | FK organization_id, user_id |
| `user_sessions` | Session tracking. session_id, ip_address, user_agent, device_info, last_active_at. Upserted on each request. | FK user_id |
| `organization_sso_providers` | SSO SAML config. provider_type, entity_id, sso_url, certificate, domain, domain_verified, enforce_sso, group_role_mapping, jit_provisioning. UNIQUE(organization_id), UNIQUE(domain) | FK organization_id |
| `organization_sso_bypass_tokens` | Single-use emergency SSO bypass. token_hash, expires_at 24h, used_at | FK organization_id |
| `organization_ip_allowlist` | CIDR entries for IP allowlisting. cidr, label, created_by | FK organization_id |
| `api_tokens` | User API tokens. token_prefix (dptx_), token_hash (SHA-256), scopes, last_used_at/ip, expires_at, revoked_at | FK user_id, organization_id |
| `organization_scim_configs` | SCIM 2.0 config per org. scim_token_hash, is_active, last_sync_at | FK organization_id |
| `scim_user_mappings` | SCIM user provisioning tracking. scim_external_id, user_id, email, is_active, deprovisioned_at | FK organization_id |

### Aegis Tables
| Table | Purpose |
|-------|---------|
| `aegis_config` | Per-org Aegis enabled flag |
| `aegis_chat_threads` | Chat conversation threads. Phase 6C: project_id, context_type, context_id, total_tokens_used |
| `aegis_chat_messages` | Messages within threads (role, content). Phase 7B: metadata JSONB for tool execution refs |
| `aegis_automations` | Scheduled automations (name, prompt, schedule, enabled). Phase 7B: cron_expression, timezone, automation_type, delivery_config, template_config, qstash_schedule_id, last_run_*, run_count, consecutive_failures |
| `aegis_automation_jobs` | Job queue for automations (status, scheduled_for, result) |
| `aegis_inbox` | Inbox items (type: alert/message/task/approval/report) |
| `aegis_activity_logs` | Audit log of all Aegis requests and tool executions |
| `aegis_org_settings` | Phase 7B: Per-org operating_mode, role_mode_overrides, monthly/daily/per_task_budget, alert_thresholds, tool_permissions, default_delivery_channel, preferred_provider/model, pr_review_mode |
| `aegis_tool_executions` | Phase 7B: Audit trail for every tool call (org, user, thread_id, task_id, tool_name, parameters, result, success, permission_level, approval_status, duration_ms, tokens_used, estimated_cost) |
| `aegis_approval_requests` | Phase 7B: Pending/approved/rejected requests for dangerous tools (requested_by, thread_id, task_id, tool_name, parameters, justification, status, reviewed_by, expires_at) |
| `aegis_tasks` | Phase 7B: Long-running tasks (title, description, mode plan|sprint, status, plan_json, total_steps, completed_steps, failed_steps, total_cost, summary, started_at, completed_at). Linked to aegis_task_steps |
| `aegis_task_steps` | Phase 7B: Individual steps (task_id, step_number, title, tool_name, tool_params, status, result_json, error_message) |
| `aegis_memory` | Phase 7B: pgvector memory (organization_id, key, content, embedding vector(768), category, source_thread_id, expires_at) |
| `aegis_event_triggers` | Phase 7B: Event-driven automation triggers (automation_id, event_type, filter_criteria, enabled) |
| `aegis_slack_config` | Phase 7B: Per-org Slack bot (slack_team_id, slack_bot_token, slack_signing_secret, encryption_key_version, default_channel_id, enabled) |
| `security_debt_snapshots` | Phase 7B: Daily debt score snapshots (organization_id, project_id nullable, score, breakdown JSONB, snapshot_date) |
| `package_reputation_scores` | Phase 7B: Composite package reputation (dependency_id, score, breakdown, signals_available, calculated_at) |

### Learning Tables (Phase 16)
| Table | Purpose |
|-------|---------|
| `fix_outcomes` | Structured outcome record per fix job. fix_type, strategy, ecosystem, framework, vulnerability_type, cwe_id, severity, success, failure_reason, duration/tokens/cost, pr_merged, human_quality_rating (1-5), fix_reverted, previous_attempt_id. 7 indexes. |
| `strategy_patterns` | Aggregated strategy success rates per org. Multi-level: ecosystem+vulnType+strategy (specific) down to strategy-only (broad). success_rate, confidence (low/medium/high), common_failure_reasons JSONB, best_followup_strategy. Computed by `compute_strategy_patterns` RPC. |

### Incident Response Tables (Phase 17)
| Table | Purpose |
|-------|---------|
| `incident_playbooks` | Per-org playbook templates. trigger_type (zero_day/supply_chain/secret_exposure/compliance_breach/custom), trigger_criteria JSONB, phases JSONB (6-phase steps), severity_default, auto_execute, is_template. | FK organization_id |
| `security_incidents` | Active/resolved incidents. playbook_id, severity, status (declared/containing/assessing/communicating/remediating/verifying/resolved/closed/aborted), current_phase, phase_started_at, affected_projects/dependencies/vulnerabilities (TEXT[]), dedup_key (unique partial on active), escalation_level, post_mortem_md, declared_by, resolved_by/at, closed_by/at. | FK organization_id, playbook_id, task_id (aegis_tasks) |
| `incident_timeline` | Chronological event log per incident. event_type (phase_started/step_completed/step_failed/escalation/note/approval_requested/approval_granted/scope_expanded/containment_action/communication_sent), phase, actor (system/aegis/user), actor_id, details JSONB. | FK incident_id |
| `incident_notes` | User/AI notes on incidents. author_id, content TEXT, is_ai_generated. | FK incident_id |

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
  |-- organization_notification_rules (Phase 9: schedule_config, snoozed_until, dry_run)
  |-- notification_events, notification_deliveries (Phase 9)
  |-- user_notification_preferences (Phase 9, via user_id)
  |-- notification_rule_changes (Phase 9)
  |-- organization_watchlist (-> dependencies)
  |-- banned_versions
  |-- organization_deprecations (-> dependencies)
  |-- activities
  |-- organization_ai_providers (Phase 6C), ai_usage_logs (Phase 6C)
  |-- aegis_config, aegis_chat_threads, aegis_chat_messages, aegis_automations, aegis_automation_jobs, aegis_inbox, aegis_activity_logs
  |-- aegis_org_settings, aegis_tool_executions, aegis_approval_requests, aegis_tasks, aegis_task_steps, aegis_memory, aegis_event_triggers, aegis_slack_config (Phase 7B)
  |-- security_debt_snapshots, package_reputation_scores (Phase 7B)
 |-- fix_outcomes, strategy_patterns (Phase 16)
 |-- incident_playbooks, security_incidents (-> aegis_tasks), incident_timeline, incident_notes (Phase 17)
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
       |-- project_semgrep_findings, project_secret_findings (Phase 6)
       |-- project_vulnerability_events, project_version_candidates (Phase 6)
       |-- project_reachable_flows, project_usage_slices (Phase 6B)
       |-- project_security_fixes (Phase 7: AI fix jobs, RPC claim/queue/recovery)
       |-- project_commits, project_pull_requests (Phase 8)

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
  -> computeHealthScore() (Phase 10) -> projects.health_score, invalidate project-stats/org-stats caches
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

Daily (Phase 8: QStash cron -> POST /api/workers/watchtower-daily-poll):
  -> runDependencyRefresh(): npm latest for direct deps, GHSA batch -> watchtower-new-version-jobs
  -> runPollSweep(): check watched_packages for new commits
  -> runWebhookHealthCheck(): mark repos inactive if no webhook in 7 days
  -> cleanupOldWebhookDeliveries(): 30-day retention
```

### Aegis Chat
```
User sends message (AegisPage full screen or AegisPanel sidebar)
  -> POST /api/aegis/v2/stream { organizationId, threadId, message, context } — Phase 7B AI SDK SSE (useChat on frontend)
  -> Or legacy: POST /api/aegis/handle (non-streaming), POST /api/aegis/stream (Phase 6C SSE)
  -> Permission: interact_with_aegis required (legacy: interact_with_security_agent)
  -> Provider: getProviderForOrg() — BYOK (OpenAI/Anthropic/Google). llm-provider.ts wraps for AI SDK.
  -> Rate limits: 200 msg/day per user, 5 concurrent streams per org, monthly cost cap (Redis)
  -> executor-v2: streamText(maxSteps), tool set from registry (50+ tools), checkToolPermission, logToolExecution
  -> Multi-turn tool loop; dangerous tools may create aegis_approval_requests
  -> Logged to aegis_activity_logs, aegis_tool_executions, ai_usage_logs
  -> Response streamed via SSE (v2) or returned (handle)
```

### Overview Screens (Phase 10)
```
Project Overview:
  -> GET /api/.../projects/:projectId/stats (60s cached) — health_score, status/tier, compliance, vulns, code findings, deps, sync, action_items, graph_deps
  -> GET /api/.../projects/:projectId/recent-activity — union of activities, vuln events, extraction jobs
  -> useRealtimeStatus subscribes to project_repositories for live extraction status
  -> POST /api/.../projects/:projectId/sync — retrigger extraction (manage_teams_and_projects, 60s cooldown)

Team Overview:
  -> GET /api/.../teams/:teamId/stats (60s cached) — projects by health band, vulns, compliance, status_distribution, top_vulnerabilities
  -> getActivities(orgId, { team_id }) for activity feed

Org Overview:
  -> GET /api/.../stats (60s cached) — projects, vulns, compliance, status_distribution, top_vulnerabilities, syncing_count
  -> OrgGetStartedCard policy step checks Phase 4 tables (organization_package_policies, organization_status_codes, organization_pr_checks)
```

### Supply Chain Graph
```
User views dependency supply chain (DependencySupplyChainPage)
  -> GET /api/.../dependencies/:id/supply-chain
  -> Reads dependency_version_edges (parent -> child)
  -> Frontend renders @xyflow/react graph with CenterNode + DependencyNodes
  -> BanVersionSidebar / RemoveBanSidebar / SafeVersionCard overlays
```

### Security Tab (Phase 6)
```
Project/Org/Team Security tab (renamed from Vulnerabilities; routes /security, redirects /vulnerabilities)
  -> GET /api/.../security-summary (project, org, team)
  -> GET /api/.../semgrep-findings, /secret-findings (permission-gated)
  -> GET /api/.../vulnerabilities/:osvId/detail, PATCH suppress/unsuppress, accept-risk/unaccept-risk
  -> GET /api/.../dependencies/:depId/security-summary, /version-candidates
  -> Frontend: SecuritySidebar (VulnerabilityDetailContent, DependencySecurityContent, ProjectSecurityContent)
  -> Graph: Depscore coloring, EPSS/KEV/reachability/fix indicators, SecurityFilterBar with URL persistence
  -> Org graph: No Team fix — ungrouped projects rendered on org ring, linked from center

Phase 6B (Code-Level Reachability):
  -> dep-scan research profile: atom engine produces *-reachables.slices.json, *-usages.slices.json
  -> project_reachable_flows, project_usage_slices; reachability_level on project_dependency_vulnerabilities
  -> GET /api/.../reachable-flows, /usage-slices, /reachable-flows/:flowId/code-context (lazy git provider, 30/min rate limit)
  -> VulnerabilityDetailContent: CodeImpactView (data-flow path, atom snippets, expandable context), tiered reachability badge
  -> DependencySecurityContent: usage_slices (functions used from package)
  -> VulnerabilityNode: tiered reachability icons (data_flow=orange, function=yellow, module=gray, unreachable=dimmed)
  -> SecurityFilterBar: reachability level filter (All, Data flow, Function, Module, Unreachable)
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

### Notification System (Phase 9)
```
Event sources (extraction, policy eval, PR handler, membership, integrations, project CRUD) call emitEvent() or emitEventBatch()
  -> Persist to notification_events
  -> Queue QStash dispatch (priority-based delay: critical=0s, high=0s, normal=30s, low=5min)
  -> POST /api/workers/dispatch-notification (single) or dispatch-notification-batch
  -> notification-dispatcher: resolve rules (org+team+project cascade), evaluate trigger code in sandbox
  -> Check rate limits (200/hr org, 30/hr destination), user prefs (email opt-out, muted events/projects)
  -> Dispatch to 9 destinations: Slack, Discord, Jira, Linear, Asana, Email, Custom webhook, PagerDuty
  -> Record to notification_deliveries, create user_notifications for in-app inbox
  -> updateConnectionHealth() — auto-disable after 3 consecutive failures

QStash cron:
  - reconcile-stuck-notifications (*/15 * * * *): re-queue pending events >10min old
  - digest-check (0 * * * *): hourly, dispatch weekly/daily digest to orgs with active digest rules
  - notification-cleanup (0 3 * * *): 90-day retention for events/deliveries, 30-day for user_notifications
```

### PR Management & Webhooks (Phase 8)
```
Webhook endpoints: POST /api/webhook/github, POST /api/integrations/webhooks/gitlab, POST /api/integrations/webhooks/bitbucket

Push event (GitHub/GitLab/Bitbucket):
  -> detectAffectedWorkspaces(changedFiles) via manifest-registry (multi-ecosystem)
  -> sync_frequency check: manual=skip, on_commit=extract if affected, daily/weekly=skip (handled by scheduler)
  -> queueExtractionJob() for full Fly.io pipeline (NOT extractDependencies)
  -> Per-org cap: max 10 extraction jobs per push
  -> Record commits to project_commits
  -> Update last_webhook_at, webhook_status

PR event (opened/synchronize/reopened):
  -> Per-project check runs: "Deptex - {project_name}", in_progress -> completed
  -> Smart comment: find existing <!-- deptex-pr-check -->, edit; else create
  -> PR tracking: upsert project_pull_requests
  -> Policy engine: effective_pr_check_code or organization_pr_checks, fallback to project_pr_guardrails

QStash cron (CE routes):
  POST /api/workers/scheduled-extraction (every 6h): queue extraction for sync_frequency=daily|weekly projects
  POST /api/workers/watchtower-daily-poll (daily 4AM UTC): dependency refresh, poll sweep, webhook health

Repo lifecycle (GitHub): repository.deleted/renamed/transferred/edited, installation_repositories.removed, installation.deleted
  -> Update project_repositories.status (repo_deleted, access_revoked, installation_removed)
```

---

## External Services & Integrations

| Service | How It's Used | Config |
|---------|--------------|--------|
| **Supabase** | Postgres DB (all tables), Auth (JWT, OAuth), Realtime (extraction_logs), Storage (SBOM/scan artifacts, avatars, icons). Extraction jobs in `extraction_jobs` table. | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_ANON_KEY` |
| **Fly.io** | Extraction worker (scale-to-zero via Machines API), parser worker, watchtower workers | `fly.toml` per worker. Backend: `FLY_API_TOKEN`, `FLY_EXTRACTION_APP`, `FLY_MAX_BURST_MACHINES` |
| **Upstash QStash** | Async job dispatch: populate-dependencies, backfill-trees. Phase 8: Cron for scheduled-extraction (every 6h), watchtower-daily-poll (daily 4AM UTC). Cron for automations and extraction recovery (optional). | `QSTASH_TOKEN`, `QSTASH_CURRENT_SIGNING_KEY`, `QSTASH_NEXT_SIGNING_KEY` |
| **Upstash Redis** | ast-parsing-jobs, watchtower-jobs, caching, webhook-delivery dedup (1h TTL). Extraction jobs use Supabase. | `UPSTASH_REDIS_URL`, `UPSTASH_REDIS_TOKEN` |
| **GitHub App** | Repo access, file content, tree, branch/PR ops, commit diffs, webhook. Phase 8: GITHUB_WEBHOOK_SECRET required in production (rejects if missing). | `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET` |
| **GitLab** | OAuth repo access, file content, tree. Phase 8: webhook support (Push Hook, MR Hook). Per-repo webhook_secret in project_repositories. | `GITLAB_CLIENT_ID`, `GITLAB_CLIENT_SECRET` |
| **Bitbucket** | OAuth repo access, file content. Phase 8: webhook support (repo:push, pullrequest:*). Per-repo HMAC webhook_secret. | `BITBUCKET_CLIENT_ID`, `BITBUCKET_CLIENT_SECRET` |
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
| **Google AI (Gemini)** | Docs assistant, policy AI, notification AI, usage analysis, Apply for Exception (Phase 5) (Tier 1). getPlatformProvider() when GOOGLE_AI_API_KEY set. | `GOOGLE_AI_API_KEY` |
| **OpenAI / Anthropic / Google** | Aegis Security Copilot (Tier 2 BYOK). Org configures in Organization Settings > AI Configuration. Keys stored encrypted. | Org BYOK via organization_ai_providers. Requires `AI_ENCRYPTION_KEY` (32-byte hex). |
| **Nodemailer/Gmail** | Email notifications and invitations | `GMAIL_USER`, `GMAIL_APP_PASSWORD` |
| **PagerDuty** | Phase 9: Incident alerts via Events API v2. Routing key stored in organization_integrations. PagerDuty costs $21/user/month on their side. | User provides routing key (no OAuth) |

**Internal API:** `INTERNAL_API_KEY` — protects recovery endpoint (`/api/internal/recovery/extraction-jobs`), fix-recovery (`/api/internal/recovery/fix-jobs`), create-bump-pr, vuln-check (`/api/internal/vuln-check`), Phase 8 QStash cron endpoints (scheduled-extraction, watchtower-daily-poll), Phase 9 notification worker endpoints (dispatch-notification, digest-check, reconcile-stuck-notifications, notification-cleanup), **Phase 7B:** `POST /api/internal/aegis/execute-task-step`, `check-due-automations`, `run-automation/:id`, `snapshot-debt`. **Phase 16:** `POST /api/internal/learning/recompute-patterns`, `check-feedback-prompts`.

---

## RBAC & Permissions

**Organization roles** (`organization_roles.permissions` JSONB):
- `manage_teams_and_projects`, `view_all_teams_and_projects`, `manage_organization_settings`, `manage_integrations`, `manage_members`, `manage_policies`, `manage_notifications`, `manage_statuses`, `view_activities`
- **Phase 7B (AI & Aegis):** `interact_with_aegis` (chat, copilot, "Fix with AI"/"Explain with Aegis" buttons; gates Aegis nav item), `manage_aegis` (Aegis Management Console, AI Configuration, operating mode, budgets, tool overrides, memory, automations), `trigger_fix` (create security sprints, approve fix tasks), `view_ai_spending` (read-only spending/usage/audit in console), `manage_incidents` (declare/resolve incidents)

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
| 6C | AI Infrastructure & Aegis Security Copilot (BYOK, SSE streaming, security actions, usage dashboard) | Completed |
| 6B | Code-Level Reachability Engine (atom, call graphs, data-flow) | Completed |
| 7 | AI-Powered Fixing (Aider on Fly.io, 7 fix strategies) | Completed |
| 7B | Aegis Autonomous Security Platform (50+ tools, ReAct loop, memory, tasks, sprints, automations, Slack bot, PR review, security debt, management console) | Refined (implementation complete; test suite 7B-Q pending) |
| 8 | PR Management & Webhooks (manifest registry, smart extraction, check runs) | Refined |
| 9 | Notifications & Integrations (event bus, 9 destinations, batching, rate limiting, delivery tracking, digest, in-app center) | Completed |
| 10 | UI Polish & Project Overview (stats endpoints, real-time extraction, mini graphs, activity feeds) | Completed |
| 10B | Organization Watchtower Page (per-project activation, org-level view) | Refined |
| 11 | CANCELLED -- merged into 7B | -- |
| 12 | Documentation Overhaul | Refined |
| 13 | Plans, Billing & Stripe (4 tiers, usage metering, plan limits) | Outline |
| 14 | Enterprise Security (MFA, SSO/SAML, IP allowlist, API tokens, audit log, SCIM) | Completed |
| 15 | Security SLA Management (per-severity deadlines, breach detection, compliance reports) | Outline |
| 16 | Aegis Outcome-Based Learning (fix outcome tracking, strategy recommendations, learning dashboard) | Completed |
| 17 | Incident Response Orchestration (6-phase IR, playbooks, post-mortem) | Completed |
| 18 | Developer Touchpoints (VS Code extension, CLI, GitHub Action, git hooks) | Outline |

---

## Phase 6B Setup Checklist

After deploying Phase 6B (Code-Level Reachability):

1. **Run database migration:** `phase6b_reachability_tables.sql` (creates `project_reachable_flows`, `project_usage_slices`; adds `reachability_level`, `reachability_details` to `project_dependency_vulnerabilities`).

2. **Extraction worker:** Requires `stream-json` npm package. cdxgen and dep-scan must support `--profile research`. dep-scan runs async (3h timeout) with heartbeat—no spawnSync.

3. **Machine sizing:** Fly.io `performance-8x` 64GB recommended for atom (32–64GB typical). Extraction time ~10–25 min with research mode.

4. **No backfill:** Existing projects get `reachability_level = NULL` until next extraction. UI shows "Pending analysis" badge. Trigger re-extraction from Project Settings to populate.

---

## Phase 8 Setup Checklist

After deploying Phase 8 (PR Management & Webhooks), complete these steps:

1. **Run database migrations** (in order):
   - `phase8_migrations.sql` (sync_frequency, webhook columns, last_extracted_at)
   - `phase8_project_commits.sql`
   - `phase8_webhook_deliveries.sql`
   - `phase8_project_pull_requests.sql`

2. **Configure QStash cron schedules** (Upstash dashboard):
   - **Scheduled extraction:** `0 */6 * * *` → `POST https://<your-backend>/api/workers/scheduled-extraction`
   - **Watchtower daily poll:** `0 4 * * *` → `POST https://<your-backend>/api/workers/watchtower-daily-poll`
   - Auth: QStash signs requests; or use `X-Internal-Api-Key: $INTERNAL_API_KEY` header.

3. **Production env:** Set `GITHUB_WEBHOOK_SECRET` (required; webhooks are rejected if missing in production).

4. **GitLab/Bitbucket webhooks:** When connecting a GitLab or Bitbucket repo, the connect flow must register the webhook with the provider (POST /projects/:id/hooks for GitLab, POST /repositories/:workspace/:repo/hooks for Bitbucket). The handlers expect `webhook_secret` and `webhook_id` on `project_repositories`. If the connect flow does not yet register webhooks, add that logic or register manually.

5. **Optional:** Deprecate the standalone `watchtower-poller` process in production; QStash cron replaces it.

---

## Phase 6C Setup Checklist

After deploying Phase 6C (AI Infrastructure & Aegis Security Copilot):

1. **Run database migrations** (in order):
   - `aegis_chat_threads_schema.sql` (if not already applied — creates base Aegis tables)
   - `phase6c_ai_infrastructure.sql` (organization_ai_providers, ai_usage_logs, aegis_chat_threads columns, projects columns, permission migration)

2. **Set AI_ENCRYPTION_KEY** (required for BYOK): 32-byte hex key. Generate with `openssl rand -hex 32`. Without it, BYOK endpoints return 503. Server logs a warning on startup if missing.

3. **ee/backend dependencies:** `npm install` in ee/backend adds `@anthropic-ai/sdk` and `@google/generative-ai`.

4. **Optional QStash cron for vuln-check:** `0 * * * *` (hourly) → `POST https://<your-backend>/api/internal/vuln-check` with `X-Internal-Api-Key`. Checks projects due for vuln scan (last_vuln_check_at + vuln_check_frequency), OSV batch query, logs to project_vulnerability_events.

5. **Frontend:** AegisPanel must receive `hasByokProvider`, `hasAegisPermission`, and `onOpenAegis` from parent. VulnerabilityDetailContent and ProjectSecurityContent accept these props to enable "Explain with Aegis", "Ask Aegis", "Fix with AI" buttons. Wire AegisPanel into Security tab layout where the graph is rendered.

---

## Phase 9 Setup Checklist

After deploying Phase 9 (Notifications & Integrations):

1. **Run database migration:** `phase9_notifications.sql` (creates `notification_events`, `notification_deliveries`, `user_notification_preferences`, `user_notifications`, `notification_rule_changes`; adds token_expires_at, timezone, schedule_config, snoozed_until, dry_run, consecutive_failures to existing tables; migrates vulnerability_discovered rules to custom_code_pipeline; RLS policies).

2. **Configure QStash cron schedules** (Upstash dashboard):
   - **Stuck reconciliation:** `*/15 * * * *` → `POST https://<your-backend>/api/workers/reconcile-stuck-notifications`
   - **Digest check:** `0 * * * *` → `POST https://<your-backend>/api/workers/digest-check`
   - **Retention cleanup:** `0 3 * * *` → `POST https://<your-backend>/api/workers/notification-cleanup`
   - Auth: QStash signs requests; or use `X-Internal-Api-Key: $INTERNAL_API_KEY` header.

3. **PagerDuty:** User-provided routing key (no OAuth). Document that PagerDuty costs $21/user/month on their side.

4. **CE routes:** `notification-unsubscribe` and `user-notifications` are mounted in backend/src/index.ts (always available).

---

## Phase 10 Setup Checklist

After deploying Phase 10 (UI Overhaul / Overview Screens):

1. **Run database migration:** `phase10_gin_index.sql` (GIN index on `activities.metadata` for project-scoped activity queries).

2. **Backend:** New stats endpoints in projects.ts, organizations.ts, teams.ts. Cache keys: `project-stats:{projectId}`, `org-stats:{orgId}`, `team-stats:{teamId}` (60s TTL). Sync endpoint sets `sync-cooldown:{projectId}` (60s).

3. **Health score:** `computeHealthScore()` in `ee/backend/lib/health-score.ts` runs after populate-dependencies + policy evaluation. Existing projects get `health_score` updated on next extraction; no backfill.

4. **Frontend:** New components — StatsStrip, ActionableItems, ActivityFeed, OverviewGraph. useRealtimeStatus hook subscribes to `project_repositories`; requires Supabase Realtime enabled for that table.

5. **OrgGetStartedCard:** Policy step now checks Phase 4 split tables (`organization_package_policies`, `organization_status_codes`, `organization_pr_checks`) in addition to legacy `organization_policies.policy_code`.

---

## Phase 7 Setup Checklist

After deploying Phase 7 (AI-Powered Fixing with Aider):

1. **Run database migration:** `phase7_ai_fix.sql` (creates `project_security_fixes` table, `claim_fix_job` RPC, `queue_fix_job` RPC, `recover_stuck_fix_jobs` RPC, `fail_exhausted_fix_jobs` RPC).

2. **Deploy Aider worker:** `cd backend/aider-worker && npm install && npm run build`, then `flyctl deploy` from `backend/aider-worker/`. Requires `FLY_AIDER_APP` env var on backend.

3. **Aider worker env vars:** `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `AI_ENCRYPTION_KEY` (for BYOK key decryption on machine). Machine sizing: `shared-cpu-4x`, 8GB RAM, 15m auto-stop.

4. **Optional QStash cron for fix recovery:** `*/5 * * * *` → `POST https://<your-backend>/api/internal/recovery/fix-jobs` with `X-Internal-Api-Key`. Requeues stuck jobs (5min heartbeat stale), fails exhausted (3 attempts max).

5. **Frontend:** `FixStatusProvider` wraps the app for global fix status tracking. `useFixStatus` hooks provide real-time status via Supabase Realtime on `project_security_fixes`. `FixProgressCard` and `FixWithAIButton` integrate into `VulnerabilityDetailContent`.

6. **BYOK required:** Fixes use the org's configured AI provider (organization_ai_providers). No BYOK = no fixes. Keys are decrypted at runtime on the worker, never stored in job payloads.

7. **Phase 8 integration:** GitHub webhook handler recognizes AI fix PRs (`dependency_prs.source = 'ai_fix'`) and updates `project_security_fixes` status to `merged` or `pr_closed`.

---

## Phase 7B Setup Checklist

After deploying Phase 7B (Aegis Autonomous Security Platform):

1. **Run database migrations in order** (see `backend/database/phase7b_aegis_platform.sql` header):
   - `aegis_chat_threads_schema.sql`
   - `aegis_chat_messages_schema.sql`
   - `aegis_automations_schema.sql`
   - `phase6c_ai_infrastructure.sql`
   - `phase7b_aegis_platform.sql` (pgvector, 10 new tables, ALTERs; permission migration interact_with_security_agent → interact_with_aegis, adds trigger_fix, view_ai_spending, manage_incidents)

2. **Dependencies:** `ee/backend`: `ai`, `@ai-sdk/openai`, `@ai-sdk/anthropic`, `@ai-sdk/google`. `frontend`: `@ai-sdk/react`.

3. **Configure QStash cron schedules** (Upstash dashboard):
   - **Aegis due automations:** `*/5 * * * *` → `POST https://<your-backend>/api/internal/aegis/check-due-automations`
   - **Aegis debt snapshot:** `0 2 * * *` → `POST https://<your-backend>/api/internal/aegis/snapshot-debt`
   - Auth: QStash signature or `X-Internal-Api-Key: $INTERNAL_API_KEY`

4. **Slack bot (optional):** Configure app in Slack; set Events API and Interactivity URLs to `POST /api/aegis/slack/events` and `POST /api/aegis/slack/interactions`. Store bot token and signing secret in `aegis_slack_config` (encrypted).

5. **Frontend:** Aegis nav item in OrganizationSidebar (gated by `interact_with_aegis`). Org Settings > AI & Automation: Aegis AI (manage_aegis), AI Configuration. Route `/organizations/:id/aegis` and optional `:threadId`.

6. **Permissions:** PermissionEditor includes AI & Automation group: interact_with_aegis, trigger_fix, manage_aegis, view_ai_spending, manage_incidents. Default owner/admin have these; member does not have manage_aegis/trigger_fix/view_ai_spending/manage_incidents.

---

## Phase 14 Setup Checklist

After deploying Phase 14 (Enterprise Security):

1. **Run database migration:** `phase14_enterprise_security.sql` (creates security_audit_logs, organization_mfa_exemptions, user_sessions, organization_sso_providers, organization_sso_bypass_tokens, organization_ip_allowlist, api_tokens, organization_scim_configs, scim_user_mappings; adds mfa_enforced/mfa_grace_period_days/mfa_enforcement_started_at/max_session_duration_hours/require_reauth_for_sensitive/ip_allowlist_enabled to organizations; fixes manage_security on member role).

2. **Install npm packages:** `cd backend && npm install @node-saml/node-saml ipaddr.js` (SSO SAML processing + IP CIDR matching).

3. **Trust proxy:** `app.set('trust proxy', true)` is now set in `backend/src/index.ts`. Required for correct `req.ip` resolution behind load balancers.

4. **CE routes mounted:** SSO (`/api/sso/*`), user sessions (`/api/user/sessions`), user API tokens (`/api/user/api-tokens`), SCIM (`/api/scim/v2/*`) in `backend/src/index.ts`.

5. **Frontend routes:** `/sso-callback` (public, handles SAML token verification), `/settings/security` (user MFA + sessions + API tokens). Org Settings sidebar adds Session Policy, IP Allowlist, API Tokens, SCIM Provisioning under Security.

6. **MFA:** Supabase Auth TOTP via AAL system. Users enroll from Settings > Security. Org enforcement toggle in Org Settings > Security > MFA (manage_security). MFAGate component wraps ProtectedRoute.

7. **SSO:** `@node-saml/node-saml` (free, MIT). Admin configures in Org Settings > Security > SSO. Domain verification via DNS TXT record. Emergency bypass tokens (24h, single-use).

8. **API tokens:** `dptx_` prefix, SHA-256 hashed, scopes (read/write/admin). Auth middleware auto-detects token type. User manages in Settings > Security, admin view in Org Settings > Security > API Tokens.

---

## Phase 16 Setup Checklist

After deploying Phase 16 (Aegis Outcome-Based Learning):

1. **Run database migration:** `phase16_aegis_learning.sql` (adds `cwe_ids` to `dependency_vulnerabilities`; creates `match_aegis_memories` RPC; creates `fix_outcomes` and `strategy_patterns` tables with RLS; creates `compute_strategy_patterns` RPC for multi-level aggregation).

2. **Install npm package (frontend):** `cd frontend && npm install recharts` (charting library for Learning Dashboard).

3. **Configure QStash cron schedules** (Upstash dashboard):
   - **Pattern recomputation:** `0 3 * * *` (daily 3AM UTC) → `POST https://<your-backend>/api/internal/learning/recompute-patterns`
   - **Feedback prompts:** `0 * * * *` (hourly) → `POST https://<your-backend>/api/internal/learning/check-feedback-prompts`
   - Auth: QStash signs requests; or use `X-Internal-Api-Key: $INTERNAL_API_KEY` header.

4. **No new env vars required.** Phase 16 uses existing infrastructure (Supabase, Redis, QStash).

5. **Backfill:** On first pattern recomputation cron run, `backfillMissingOutcomes()` automatically creates `fix_outcomes` records for any `project_security_fixes` jobs that completed before Phase 16 deployment. No manual action needed.

6. **Frontend:** Learning tab in AegisManagementConsole (Org Settings > AI & Automation > Aegis AI) now shows real dashboard instead of placeholder. StrategyPicker dialog integrates into fix trigger flow.

---

## Phase 17 Setup Checklist

After deploying Phase 17 (Incident Response Orchestration):

1. **Fix Phase 7B gap:** Already applied — `approveTask()` now queues first step via QStash.

2. **Run database migration:** `backend/database/phase17_incident_response.sql` (creates `incident_playbooks`, `security_incidents`, `incident_timeline`, `incident_notes`; adds `allow_autonomous_containment` to organizations; RLS policies).

3. **Enable Supabase Realtime** on `security_incidents` and `incident_timeline` tables (Supabase dashboard > Database > Replication).

4. **No new QStash cron schedules.** Trigger checking is inline with notification dispatch. Escalation uses on-demand QStash delayed publish.

5. **No new env vars.** Uses existing `INTERNAL_API_KEY`, `QSTASH_TOKEN`, etc.

6. **No new npm dependencies.** Frontend PDF export uses `window.print()` (zero deps).

7. **Seed playbook templates:** Call `seedPlaybookTemplates(orgId)` from `ee/backend/lib/incident-templates.ts` when an org first enables incident response, or add to Aegis onboarding flow.

8. **Frontend:** AegisPage now shows Active Incidents in the left sidebar with Realtime subscription. Clicking opens incident detail view with 6-phase progress bar, timeline, and affected scope panel. AegisManagementConsole Incidents tab shows stats, playbooks, and incident history.

9. **CE routes:** `POST /api/internal/incidents/escalate` registered in `backend/src/index.ts`.

10. **EE routes:** `ee/backend/routes/incidents.ts` registered in `load-ee-routes.js` under `/api/organizations`.

---

## Phase 7B Testing (7B-Q)

The plan (`.cursor/plans/phase_07b_aegis.plan.md` § 7B-Q) specifies a full test suite:

- **Backend (66 tests):** Core agentic loop (1–8), tool system (9–16), task system (17–24), memory (25–30), automations (31–36), Slack bot (37–42), PR review (43–48), compliance (49–54), management console (55–60), permissions (61–66).
- **Frontend (50 tests):** Aegis screen layout & navigation (67–76), chat interface (77–84), right panel & context (85–90), management console (91–106), security debt (107–112), cross-platform touchpoints (113–116).

**Current state:** Phase 6C tests exist: `ee/backend/routes/__tests__/ai-infrastructure.test.ts` (AI providers, usage logging, thread helpers). Frontend `frontend/src/__tests__/ai-aegis.test.ts` covers AegisPanel with legacy stream. **Phase 7B-specific tests** (executor-v2, tool registry, tasks, sprint orchestrator, slack-bot, automations-engine, security-debt, pr-review, v2/stream endpoint, permissions, AegisPage, AegisManagementConsole) are **not yet implemented**. Add tests per 7B-Q in `ee/backend/routes/__tests__/` and `frontend/src/__tests__/`; see plan for full list. A minimal scaffold exists at `ee/backend/routes/__tests__/aegis-phase7b.test.ts` (placeholder specs and 1–2 real tests) to document coverage goals.

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
- Phase 6B migrations: phase6b_reachability_tables.sql (project_reachable_flows, project_usage_slices, reachability_level/reachability_details on project_dependency_vulnerabilities).
- Phase 6C migrations: aegis_chat_threads_schema.sql (prerequisite), phase6c_ai_infrastructure.sql (organization_ai_providers, ai_usage_logs, aegis_chat_threads columns, projects columns).
- Phase 7 migration: phase7_ai_fix.sql (project_security_fixes, claim_fix_job, queue_fix_job, recover_stuck_fix_jobs, fail_exhausted_fix_jobs).
- Phase 8 migrations: phase8_migrations.sql, phase8_project_commits.sql, phase8_webhook_deliveries.sql, phase8_project_pull_requests.sql.
- Phase 10 migration: phase10_gin_index.sql (idx_activities_metadata).
- Phase 9 migrations: phase9_notifications.sql (notification_events, notification_deliveries, user_notification_preferences, user_notifications, notification_rule_changes, prerequisite columns).
- Phase 7B migrations: run in order — aegis_chat_threads_schema.sql, aegis_chat_messages_schema.sql, aegis_automations_schema.sql, phase6c_ai_infrastructure.sql, then phase7b_aegis_platform.sql (see file header).
- Phase 14 migrations: phase14_enterprise_security.sql (security_audit_logs, organization_mfa_exemptions, user_sessions, organization_sso_providers, organization_sso_bypass_tokens, organization_ip_allowlist, api_tokens, organization_scim_configs, scim_user_mappings, org columns for mfa/session/ip).
- Phase 16 migration: phase16_aegis_learning.sql (fix_outcomes, strategy_patterns, cwe_ids on dependency_vulnerabilities, compute_strategy_patterns RPC, match_aegis_memories RPC).
- Phase 17 migration: phase17_incident_response.sql (incident_playbooks, security_incidents, incident_timeline, incident_notes, allow_autonomous_containment on organizations).
- See `.cursor/skills/add-new-features/SKILL.md` for CE vs EE placement decisions
- See `.cursor/skills/frontend-design/SKILL.md` and `.cursor/skills/ui-principles/SKILL.md` for UI standards
