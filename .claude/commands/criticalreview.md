# Critical Review

You are running a deep, multi-agent critical review of the changes on the current branch. The goal is to hold the diff to a **billion-dollar-SaaS quality bar**: production-grade security, airtight multi-tenancy, RBAC correctness, regression safety, code quality, and an honest scan for opportunities we missed.

This command is Deptex-specific. The persona library below targets real failure modes in this codebase (RLS, BYOK encryption, Aegis tool RBAC, extraction-job atomicity, policy-engine sandbox, QStash signatures, React stale state). Do not substitute generic "code reviewer" personas for the specific ones.

## Invocation

Parse arguments from the user's message:
- `/criticalreview` — planner picks agent count based on diff scope (typically 8–15)
- `/criticalreview <N>` — spawn exactly N persona agents, clamped to [5, 50]
- `/criticalreview auto` — same as no arg
- `/criticalreview --focus=<id1,id2,...>` — force these persona IDs into the set; planner fills the rest
- `/criticalreview --skip=<id1,id2,...>` — exclude these persona IDs; planner picks from the remainder
- Flags can combine with N: `/criticalreview 15 --focus=multi-tenancy-auditor,audit-log-completeness-auditor --skip=a11y-auditor`

If N is outside [5, 50], coerce and tell the user. If the user wrote `/criticalreview deep` or similar English, treat as auto. Pass the parsed `--focus` / `--skip` lists to the planner — focused IDs are mandatory, skipped IDs are forbidden.

## Phase 0 — Branch & Diff Scoping

Before spawning anything:

1. Run `git rev-parse --abbrev-ref HEAD`. If on `main`, stop and report: "Nothing to review — you're on main. Switch to a feature branch or worktree."
2. Run `git fetch origin main` (best effort — ignore failure on self-host).
3. Compute the diff: `git diff origin/main...HEAD` (fall back to `git diff main...HEAD` if no `origin/main`).
4. If the diff is empty, stop and report: "Nothing to review — no changes vs main."
5. Build a **scope summary** — not for the user yet, for the planner:
   - Files changed (count, paths, grouped by domain)
   - Lines added / removed
   - Touched domains: routes, middleware, database migrations, lib (ai/aegis/learning/policy-engine/etc.), workers (extraction/parser/watchtower/aider), frontend pages, frontend components, tests, config
   - Any schema changes (CREATE TABLE, ALTER TABLE, DROP, new RLS policies)
   - Any new/modified permission strings (grep the diff for org/team permission constants)
   - Any new network calls, new external integrations, new AI tool registrations
6. Print a one-line summary to the user: `Reviewing <branch> — <N> files, <+X/-Y> lines across <domains>. Spawning planner…`

## Phase 1 — Persona Planner (1 subagent, sequential)

Spawn a single **general-purpose** subagent with this job:

> Read the diff summary below. From the persona library (see Phase 2), select the set of personas most likely to find real issues in *this* diff. If the user specified N, pick exactly N. Otherwise pick 8–15 — bias toward more when the diff touches auth/RBAC/migrations/workers/AI tools, fewer when the diff is frontend-only polish.
>
> **Selection rules:**
> - Every persona must have a reason-to-exist tied to a specific file or pattern in the diff. No "just in case" picks.
> - Prefer narrow, specific personas (e.g., "BYOK secrets auditor") over broad ones ("OWASP Top 10") when the diff has a specific hit.
> - Always include at least one "Regression Hunter" if the diff modifies shared lib/ code or shared components.
> - Always include "Opportunity Scout" — this is the non-blocking "what else could we add" seat.
> - If the diff is migrations-only, include "Migration Safety" and skip most frontend personas.
> - If the diff is frontend-only, skip Aegis/worker/policy personas.
>
> **Output a JSON array**, nothing else:
> ```json
> [
>   {"id": "multi-tenancy-auditor", "lens": "...", "why_this_diff": "touches backend/src/routes/new-route.ts line 42"},
>   ...
> ]
> ```

Parse the JSON. If it fails to parse, retry once with the error. If still broken, fall back to a hand-picked default set (multi-tenancy + RBAC-org + RBAC-team + secrets + regression-hunter + type-safety + opportunity-scout).

Tell the user: `Planner selected N personas: <comma-separated ids>. Spawning review swarm…`

## Phase 2 — Parallel Review Swarm

Spawn all selected personas **in parallel** as `general-purpose` subagents, in a single tool-call batch. Each gets an identical envelope plus its specific persona prompt:

```
You are the <persona_name> for this critical review. Your lens: <lens>.

Other personas running in parallel (DO NOT duplicate their work — if you see an issue outside your lens, tag it OUT_OF_SCOPE and skip):
<comma-separated persona ids from planner output>

The diff:
<full git diff output>

Project context: This is Deptex, an AI-powered dependency security SaaS. See CLAUDE.md for architecture. Key invariants:
- Every backend route uses authenticateUser middleware + inline permission check via organization_roles.permissions or team_roles.permissions JSONB
- Every tenant-scoped query must filter by organization_id / team_id / project_id — RLS is defense in depth, not primary enforcement
- BYOK AI keys are AES-256-GCM encrypted with AI_ENCRYPTION_KEY; NEVER log or expose plaintext
- Aegis tools have PermissionLevel = 'safe' | 'moderate' | 'dangerous'; dangerous tools require aegis_approval_requests flow
- Extraction jobs are claimed atomically; workers authenticate via INTERNAL_API_KEY
- Frontend permission gating is UI-only — the source of truth is backend enforcement

Constraints:
1. Every finding MUST cite file:line from the diff. Findings without citations are rejected.
2. Every finding MUST include a reproduction — either a concrete input, a call path, or a test case that would fail.
3. You MUST either return at least one real finding OR return `{"status": "clean", "rationale": "..."}` with a rationale specific to YOUR lens explaining why the diff is safe for that concern (no generic "looks good"). "LGTM" is not an acceptable rationale.
4. Severity: P0 (breaks prod / exfiltrates data / escalates privs), P1 (high — correctness bug or likely prod incident), P2 (medium — code smell or latent risk), P3 (low — nit, style, minor).
5. Do NOT suggest rewrites, refactors, or style changes unless your persona is specifically about that.

Output strict JSON only — no prose, no markdown. Schema:
{
  "persona_id": "<id>",
  "findings": [
    {
      "file": "<path>",
      "line": <number or range "X-Y">,
      "severity": "P0" | "P1" | "P2" | "P3",
      "axis": "<short bug-class tag, e.g. 'missing-tenant-filter'>",
      "claim": "<one sentence: what is wrong>",
      "reproduction": "<how to trigger it or confirm it — concrete input, call path, or failing test>",
      "confidence": "high" | "medium" | "low"
    }
  ],
  "clean_lenses": []  // list of sub-concerns you actively checked and cleared, to make the null result auditable
}
```

Collect all agent outputs. Parse JSON; log malformed responses but do not retry them (one shot per persona keeps cost bounded).

## Persona Library

Grouped by concern axis. Each persona has an ID (used in planner JSON) and a lens prompt.

### Security — Multi-Tenancy & Access

- **multi-tenancy-auditor** — For every new/modified Supabase query in the diff, verify it filters by `organization_id`, `team_id`, or `project_id` appropriate to the route's scope. Flag any query that relies solely on RLS. Trace foreign-key joins to confirm tenant scope propagates.
- **rls-auditor** — For every new table or schema change in `backend/database/`, verify `ENABLE ROW LEVEL SECURITY` and at least one `CREATE POLICY`. For modified queries, confirm the relevant table already has RLS and the policy still covers the new access pattern.
- **horizontal-escalation-hunter** — For every new route that takes an `:id` path param (projectId, teamId, orgId, dependencyId, findingId), construct a call where user A passes user B's ID. Verify the route rejects it before any data leak.
- **org-permission-auditor** — For every new/modified backend route, verify the required organization permission constant (`manage_teams_and_projects`, `manage_policies`, `interact_with_aegis`, `manage_aegis`, `trigger_fix`, `view_ai_spending`, `manage_incidents`, etc.) is checked against `organization_roles.permissions` JSONB before any write or sensitive read.
- **team-permission-auditor** — Same as above for team-scoped routes and team permissions (`manage_projects`, `manage_members`, `manage_settings`, `manage_integrations`, `manage_notifications`).
- **frontend-only-gating-detector** — For every UI permission check in the diff (`hasPermission(...)` gating a button/route), verify a **matching backend enforcement** exists on the route the UI calls. UI-only hiding is a bug.
- **service-role-leakage-auditor** — Supabase service role bypasses RLS entirely. For any new/modified query built with the service-role client (the default backend client), verify the code itself filters by `organization_id` / `team_id` / `project_id` BEFORE returning data to the user. Flag any route that returns service-role-scoped data without explicit tenant filtering — RLS will not save you. Particularly dangerous on `.rpc()` calls, `.select('*')`, joins across tables, and any helper that wraps queries (the wrapper may not propagate the filter).

### Security — Secrets, Signatures, Sandboxes

- **byok-secrets-auditor** — For any code touching `organization_ai_providers`, `AI_ENCRYPTION_KEY`, `encryptApiKey`, `decryptApiKey`: verify plaintext keys are never logged, never sent to client, never persisted in plaintext. Check error paths — exceptions during decrypt should not leak ciphertext or partial plaintext.
- **webhook-signature-auditor** — For every webhook handler in the diff (GitHub, GitLab, Bitbucket, QStash): verify HMAC/token verification runs BEFORE any side-effecting logic. Check that `GITHUB_WEBHOOK_SECRET` / GitLab webhook token / Bitbucket secret / QStash `verifyQStashSignature` is enforced in production (no `if (process.env.NODE_ENV === 'development')` bypass that ships).
- **webhook-idempotency-auditor** — Separate from signature verification. GitHub and GitLab redeliver webhooks (timeouts, provider retries). For every side-effecting webhook handler in the diff: verify the handler de-dupes via delivery-ID header (`X-GitHub-Delivery`, `X-Gitlab-Event-UUID`), event-ID field, or content-hash stored in a `webhook_deliveries`-style table. Handlers that inject extraction jobs, create PRs, send notifications, or write audit logs without an idempotency key are P0 — retries cause duplicate jobs, duplicate PRs, and duplicate notifications. Also verify the store is checked BEFORE processing, not after.
- **oauth-redirect-auditor** — For any change to OAuth callback handling (Google, GitHub, GitLab, Bitbucket sign-in) or post-login redirect logic: verify the `redirect_uri` / `state.redirect_to` / `next` parameter is validated against an allowlist before redirecting. Any path that accepts a user-controlled URL and issues a 302 without allowlisting is an open-redirect → phishing surface. Same check applies to Supabase Auth flow overrides.
- **payload-dos-auditor** — For any new/modified Express route that accepts a body: verify `express.json({ limit: '...' })` applies an explicit limit and it's appropriate for the route (1MB default is fine for JSON; 10MB for file uploads; do NOT accept unbounded). Flag any route that parses untrusted JSON into memory (`JSON.parse(rawBody)` without size check), any route that accepts user-controlled arrays and iterates without a length guard, and any file-upload endpoint without a size/type check. Target: no single request should be able to consume >50MB of server memory.
- **internal-api-key-auditor** — For any new endpoint under `/api/internal/*` or gated on `x-internal-api-key` / `INTERNAL_API_KEY`: verify the header check uses a constant-time comparison, rate-limits aren't bypassed for internal calls, and the endpoint doesn't accept user-controlled `organization_id` without re-validation.
- **ssrf-hunter** — For any URL fetched where the URL value originates from the database or a user payload (policy engine `fetch`, OG image preview, remote config, etc.): verify DNS resolution + private-IP block list (`10.x`, `172.16-31.x`, `192.168.x`, `127.x`, `::1`, `fc00:`, `fd00:`). Flag any `fetch(userSuppliedUrl)` without guards.
- **prompt-injection-hunter** — For any new/modified Aegis tool, agent, or AI prompt that concatenates repo-derived content (vulnerability descriptions, commit messages, PR bodies, dependency READMEs, file contents) into the prompt: flag the injection surface. Confirm tool outputs are labeled as untrusted and the system prompt tells the model not to treat them as instructions.
- **policy-sandbox-escape** — For any change to `backend/src/lib/policy-engine.ts` or policy-code execution paths: verify `isolated-vm` is preferred and the `Function()` fallback is gated behind a clear dev/Windows guard. Flag any new capability exposed to the sandbox (globals, fetch, require, process).
- **jwt-parser-auditor** — For any change to `backend/src/middleware/auth.ts` or manual JWT handling: check for missing signature verification, timing attacks in token comparison, aal2/MFA bypass via API tokens or grace periods.
- **owasp-injection-pass** — SQL injection (any string interpolation into raw SQL, `.rpc(name, params)` with user input in `name`), command injection in worker scripts, XSS in frontend (any `dangerouslySetInnerHTML` with server data), open redirect, and CSRF (state-changing GET, missing SameSite).

### Security — Aegis-Specific

- **aegis-tool-permission-auditor** — For any new Aegis tool in `backend/src/lib/aegis/tools/`: verify it declares a `PermissionLevel`, has a `requiredRbacPermissions` array, and dangerous tools route through `aegis_approval_requests`. Check the tool profile (default / security / policy / intelligence / external / admin / compliance) matches what the tool actually does — a "read-only" tool in the `default` profile must not mutate.
- **aegis-cost-cap-race** — For any change touching `checkMonthlyCostCap`, `recordActualCost`, `ai:cost:{orgId}:*` Redis keys: check for race conditions where N concurrent requests each pass the pre-flight check before any of them increments the counter. Flag if estimate-then-actual drift can overshoot the cap.

### Reliability & Data Correctness

- **extraction-race-condition-auditor** — For any change to extraction job lifecycle (`queueExtractionJob`, `claim_extraction_job` RPC, heartbeat, `recover_stuck_extraction_jobs`, `startExtractionMachine`): verify atomic claim, max-3-attempts, stuck-detection still fires, and no path lets two workers process the same job.
- **rate-limit-fail-open-detector** — For any new `rate-limit.ts` usage: flag if Redis outage causes fail-open on a security-sensitive path (auth, MFA, invites, cost cap). Fail-open is acceptable for cosmetic rate limits, unacceptable for abuse prevention.
- **migration-safety-auditor** — For every new `.sql` file in `backend/database/`: verify (a) no `NOT NULL` column added to populated tables without a default, (b) destructive operations (`DROP TABLE`, `DROP COLUMN`, `ALTER TYPE` removing a value) are either idempotent or guarded, (c) foreign keys have covering indexes, (d) RPC changes are backwards-compatible with deployed backend (or the rollout order is specified).
- **realtime-subscription-auditor** — For any new Supabase Realtime subscription on the frontend: verify the subscription filter (`eq('organization_id', orgId)`) scopes to the current tenant. Unscoped subscriptions leak across orgs.
- **n-plus-one-hunter** — For any new backend handler that loops (`for (const x of ...)` + `.from(...).select()` inside): flag. Prefer `.in()` / joins / RPC. Include the expected row count at scale (check related table sizes).
- **index-usage-auditor** — For any new WHERE/ORDER BY column in the diff, verify an index exists in `backend/database/` for that pattern. Flag missing indexes on likely-hot paths.
- **worker-claim-atomicity** — Specifically for worker code (extraction-worker, parser-worker, watchtower-worker): verify `FOR UPDATE SKIP LOCKED` or equivalent, heartbeat cadence, max-attempt bail-out.
- **concurrent-edit-auditor** — For any mutating route where two users in the same org could edit the same resource (policies, status codes, PR checks, project settings, team settings, Aegis automations): check for optimistic-locking via a `version` / `updated_at` column in the update's WHERE clause. Without it, last-write-wins silently clobbers a concurrent edit. Flag as P1 when the resource is a policy/code field (losing an admin's policy edit is a real incident), P2 on cosmetic fields.
- **cache-invalidation-auditor** — Redis is hot-path for rate-limits, cost caps, AI responses, dependency metadata, and session state. For every mutation in the diff: identify every cache key shape that could be stale after the mutation, and verify there's a matching invalidation (DEL, SETEX overwrite, or a TTL short enough that staleness doesn't matter). Flag any new cache write without a matching invalidation path. Particular hot spots: `ai:cost:*` (cost-cap staleness → budget overrun), package/dependency cache (post-registry-update staleness → wrong depscore), org/team membership cache (stale permissions → ghost access after revoke).

### Compliance & Business Logic

- **audit-log-completeness-auditor** — For every sensitive mutation in the diff — member invites, permission/role changes, policy code edits, status/PR-check edits, Aegis dangerous-tool executions, suppressions, organization settings changes, integration token changes, API token issuance — verify the mutation writes to an audit log (`organization_activities`, `aegis_approval_requests`, `organization_policy_changes`, or equivalent) with `{actor_user_id, organization_id, action, target_id, diff_or_reason, timestamp, ip_address}`. Missing audit log on a sensitive mutation = P1 (P0 if the mutation involves revoking access or changing billing). Also flag audit-log writes that skip `actor_user_id` when one exists in the request context.
- **business-logic-invariant-auditor** — For any change touching depscore math, tier multiplier application, EPD scoring, reachability weighting, or any other composite score: verify the calculation is applied consistently across ALL surfaces that display or act on the score (API response, frontend display, policy engine evaluation, worker computation, notification body). Flag any place the score is computed or filtered with different inputs than the canonical path. Also applies to: permission composition (org role + team role resolution), billing/usage calculations, rate-limit bucket keys, and any other derived value that MUST match across services.

### Code Quality

- **type-safety-auditor** — Flag every `any`, `as unknown as`, `@ts-ignore`, `@ts-expect-error`, and `// eslint-disable` introduced in the diff. Each needs a justification comment or it's a finding.
- **error-handling-auditor** — Flag swallowed errors (`catch {}`, `catch (e) { /* ignore */ }`), missing try/catch around async handlers, and error responses that leak stack traces or internal paths. Verify error status codes are semantically correct (401 vs 403 vs 404 for horizontal-escalation cases — returning 404 for "not authorized to see this" prevents enumeration).
- **test-thoroughness-auditor** — Go beyond "was a test added." For every new/modified backend route, lib function, RPC, worker path, or frontend component in the diff:
  - Is there ANY test? If no, P2 at minimum.
  - Does the test exercise **real edge cases** (empty input, max input, concurrent writes, tenant isolation, permission denial), or only the happy path? Happy-path-only = P2.
  - Are **security invariants** tested — can user A access user B's data? Does the route reject expired/malformed JWTs? Do dangerous Aegis tools require approval? Missing security test on a security-relevant change = P1.
  - Does the test **mock the database where it shouldn't**? Project invariant: *"don't mock the database in these tests — mocked tests that pass have masked broken migrations in the past"*. Integration tests on migration-sensitive code must hit a real Supabase instance or a transactional test DB — in-memory chain mocks of `.from().select()` are P0 on migration-touching code.
  - Do mocks follow the project's `setTableResponse` / `pushTableResponse` conventions, or do they drift into one-off brittle stubs? Drift = P3.
  - For multi-step flows in the diff (extraction lifecycle, Aegis plan-then-execute, policy + notification dispatch): are there **integration tests**, or only isolated units? Missing integration coverage on multi-step changes = P1.
  - Per changed function: "If I introduced a bug on this line, which test would catch it?" If the answer is "none," that's a finding.
- **dead-code-detector** — Flag imports added but not used, exports added but not referenced, helpers introduced that have only one caller (should be inlined), and any `// TODO` / `// FIXME` added without a tracking reference.
- **observability-auditor** — For new backend code: are there log lines for the happy path and error path? Do log lines include `organization_id` for tenant correlation? Is any log line logging a secret (JWT, API key, BYOK key, webhook secret)?

### Frontend-Specific

- **react-stale-state-auditor** — For any new frontend state that persists across navigation (sidebar selection, detail-panel ID, filter state): check for the `panelOverviewDepId`-style bug where effect fires after selection change with stale data. Verify state is reset on the triggering dependency change, not just inside the effect.
- **pixel-alignment-auditor** — For CSS/Tailwind diffs: flag class combinations that look like they came from a restructure when a 1-2px tweak would have worked. Reference `.claude/skills/frontend-design/SKILL.md` design tokens.
- **empty-loading-error-state-auditor** — For every new page/list/detail component: verify all three states are handled (skeleton on load, empty-state with CTA, error-state with retry).
- **ecosystem-ui-consistency** — For any dependency-display UI: verify icon + registry-link + badge maps are extended to all supported ecosystems, not just the one being worked on (see `ProjectDependenciesContent` + `PackageOverview` icon maps).
- **a11y-auditor** — For new interactive UI: keyboard navigation (Tab order, Esc to close, Enter to submit), aria labels on icon-only buttons, focus management on modals, color contrast for text on `bg-background-card`.

### Regressions & Blast Radius

- **regression-hunter** — For every modified file in `backend/src/lib/`, `backend/src/middleware/`, or shared frontend component: grep the codebase for every importer. List features that import the modified code and could silently break. Produce a manual-verify checklist. *Always include this persona when shared code is touched.*
- **breaking-api-detector** — For every modified route response shape, query-parameter contract, or error code: find frontend callers (`fetch('/api/...')` or typed clients) and verify they still parse the response correctly. Flag every unannounced shape change.
- **schema-vs-extraction-detector** — For every migration that renames/drops a column used by the extraction pipeline or worker code: verify the worker Docker image / Fly deployment rollout ordering is specified. Mismatched deploys = extraction job failures.

### Opportunity Seats (non-blocking)

- **opportunity-scout** — Answer the question: "Given this diff, what's the cheapest, highest-leverage thing we're NOT adding that we should?" Observability, a follow-up test, an a11y nit, a small UX polish, a missing error toast, a log line for future debugging, a dashboard metric. Output as P3 findings tagged `axis: "opportunity"`. *Always include this persona.*
- **competitive-delta-scout** — Compare the diff's feature direction to what Snyk / Socket / Endor Labs / Dependabot / Semgrep do in the same area. Identify small extensions (1-2 days of work) that would move Deptex notably ahead. Output as P3 findings tagged `axis: "competitive"`. Include when the diff is a user-facing feature.
- **docs-drift-detector** — For any change to public behavior (new route, changed response shape, new permission, new env var): check whether `CLAUDE.md`, `DEVELOPERS.md`, `CONTRIBUTING.md`, `fly.md`, or the roadmap plans need updating. Include when backend/infra changes.

## Phase 3 — Verification Pass

For every P0 and P1 finding across all personas, spawn a **verifier subagent** (general-purpose, in parallel, one per finding) with:

```
A persona reviewer flagged this finding. Verify it against the current codebase.

Finding:
<json finding>

Your job:
1. Read the cited file at the cited line.
2. Trace the claim — call path, data flow, or the repro steps given.
3. Decide: VERIFIED (the bug really exists and the repro is correct), UNVERIFIED (you could not confirm — the cited code doesn't exhibit the claimed behavior), DISPUTED (you found evidence the claim is wrong, e.g., a guard earlier in the call chain that the reviewer missed).

Output JSON: {"verdict": "VERIFIED" | "UNVERIFIED" | "DISPUTED", "evidence": "<what you found — cite file:line>", "demote_to": null | "P1" | "P2" | "P3"}
```

Rules for the aggregator:
- `VERIFIED` keeps severity.
- `UNVERIFIED` demotes one tier (P0→P1, P1→P2) and adds `[UNVERIFIED]` tag.
- `DISPUTED` demotes to P3 and adds `[DISPUTED — needs human]`.
- P2/P3 findings are not verified individually (cost control); they get `[UNVERIFIED]` by default.

## Phase 4 — Aggregation

Cluster findings across all personas:

1. **Dedup:** Group findings where `normalized_file` matches AND `line` is within ±5 AND `axis` matches. The cluster inherits the highest severity among its members.
2. **Consensus tags:** Each cluster gets `[k/N agents]` where N is the persona count.
3. **Promotion rule:** If `k >= 2` within the same axis, promote one tier (max P0). If `k >= 3`, promote again. This is the adversarial-reviewer rule — agreement is signal.
4. **Anti-groupthink guard:** If `k == N` (unanimous agreement from every persona), add `[POSSIBLE CONSENSUS BIAS — human verify]` — unanimity across personas with different lenses is a known failure mode worth flagging.
5. **Epistemic tag:** `[VERIFIED]`, `[CONSENSUS k/N]`, `[SINGLE-SOURCE]`, `[UNVERIFIED]`, `[DISPUTED]`. A finding can carry multiple tags.
6. **Out-of-scope merging:** If persona A reports something and persona B tags the same thing `OUT_OF_SCOPE`, credit both toward consensus.

Separate the output:
- **Blocking findings** (P0, P1) — gate merge
- **Quality findings** (P2) — should fix before merge if cheap
- **Nits** (P3) — take or leave
- **Opportunities** (axis = `opportunity` or `competitive`) — always non-blocking, presented separately
- **Regression watch-list** — output of regression-hunter persona, formatted as a manual-verify checklist with file + what-to-check

## Phase 5 — Report

Write the report to `.claude/reviews/critical-review-{branch-slug}-{YYYY-MM-DD-HHMM}.md`. Create the directory if it doesn't exist.

Also print a **verdict line** to the user:

- **Ready to Merge** — 0 P0, ≤2 P1 (all UNVERIFIED), no regression-hunter findings
- **Needs Attention** — 0 P0, any P1 VERIFIED, or P2s worth fixing
- **Needs Work** — ≥1 P0 OR ≥3 P1 VERIFIED OR regression-hunter surfaced concrete breakage

Report structure:

```markdown
# Critical Review — <branch>
Verdict: **<Ready to Merge | Needs Attention | Needs Work>**
Generated: <UTC timestamp>
Diff scope: <N files, +X/-Y lines, domains>
Personas run: <N> — <comma-separated ids>
Findings: <P0> critical / <P1> high / <P2> medium / <P3> low / <K> opportunities

## Summary
<2-3 sentences — what the diff does, what the biggest concerns are, and the go/no-go recommendation>

## P0 — Blocking
(if none: "No P0 findings.")
### <axis>: <one-line claim> `[VERIFIED] [CONSENSUS 3/12]`
- **File:** `backend/src/routes/foo.ts:42`
- **Claim:** <full claim>
- **Reproduction:** <steps>
- **Flagged by:** <persona-id, persona-id, ...>
- **Evidence:** <verifier's finding>

## P1 — High Priority
<same format>

## P2 — Medium
<condensed: one bullet per finding with file:line + claim + personas>

## P3 — Nits
<bullet list, no expansion>

## Regression Watch-list
Features to manually verify after shipping:
- `backend/src/lib/shared-helper.ts` modified — verify: <affected feature 1>, <affected feature 2>
- ...

## Opportunities (non-blocking)
### <title>
- **Persona:** opportunity-scout
- **Suggestion:** <what to add and why it's high-leverage>
- **Estimated effort:** <rough>

## Persona Coverage Map
| Persona | Findings | Clean lenses cleared |
|---|---|---|
| multi-tenancy-auditor | 2 (1 P0, 1 P2) | org-id filter on new routes; team-id scoping |
| ... |
```

Also print a **short summary to the user in chat** (not the full report) — verdict, counts, top 3 P0/P1 titles, and the path to the full report.

## Rules

- **Never auto-fix.** This command is read-only. Report findings, let the user decide what to act on.
- **File:line citations are mandatory.** Strip any finding that doesn't have one during aggregation.
- **Require specific rationales on clean returns.** A persona that returns `{status: clean, rationale: "the diff looks safe"}` is malformed; reject and mark that lens as "not assessed" in the coverage map rather than assuming it passed.
- **Do not invent code paths.** Every claim must cite real files. During aggregation, drop findings that cite non-existent paths.
- **Token budget guard:** if `personas × estimated_tokens_per_agent > ~500k`, stop before spawning and ask the user to confirm. Hint: diffs over 2000 lines or 50 files are expensive.
- **No retries on malformed JSON from review agents.** One shot per persona. Log failures in the coverage map as "response malformed".
- **Worktree-safe.** If run in a worktree, diff is still vs `origin/main` — don't try to compare against the worktree's parent branch.
- **Small-diff escape:** if the diff is under 50 lines and touches zero backend routes/middleware/migrations/workers, let the planner pick just 3–5 personas. Don't spawn 15 agents to review a CSS tweak.
- **Do not commit the review file.** It goes in `.claude/reviews/` which should be gitignored. If it isn't, note that in the final output but don't modify `.gitignore` unprompted.
