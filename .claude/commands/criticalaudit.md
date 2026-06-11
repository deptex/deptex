# Critical Audit

You are running a deep, multi-agent **retrospective audit** of an existing feature, screen, or code area in Deptex. This is the counterpart to `/criticalreview` (which gates PRs) — `/criticalaudit` evaluates shipped code for security, correctness, RBAC, tenant isolation, test thoroughness, performance at scale, observability, pattern drift, and accumulated debt.

The quality bar is the same: billion-dollar SaaS. The lens is retrospective — you're not asking "is this diff safe to merge," you're asking "is this feature actually production-grade right now, or did we miss things when we built it?"

Reuse the persona library and aggregation logic from `/criticalreview`. Key differences are called out below.

## Invocation

Parse arguments from the user's message:
- `/criticalaudit <scope>` — audit the named feature / screen / directory / file. Examples:
  - `/criticalaudit aegis` — the full Aegis surface
  - `/criticalaudit compliance screen` — the compliance UI + the routes + the data it displays
  - `/criticalaudit backend/src/routes/projects.ts` — one specific file and its callers/callees
  - `/criticalaudit extraction pipeline` — the full cross-worker flow
- `/criticalaudit <scope> <N>` — force N persona agents (clamped [5, 50])
- `/criticalaudit <scope> --focus=<id1,id2>` — force these persona IDs; planner fills the rest
- `/criticalaudit <scope> --skip=<id1,id2>` — exclude these persona IDs
- `/criticalaudit <scope> --delta` — delta mode: find the most recent prior report for this scope in `.cursor/audits/` and compare. Don't re-flag findings that are still open with the same severity — focus on what's new, what's resolved, and what changed severity. Useful for re-auditing after acting on P0s.
- `/criticalaudit` with no args — ask the user what to audit, don't guess

Flags can combine: `/criticalaudit aegis 20 --focus=audit-log-completeness-auditor --delta`. `--focus` IDs are mandatory for the planner; `--skip` IDs are forbidden.

If the scope argument is ambiguous (e.g., bare "org stuff"), ask one clarifying question before proceeding. Do not burn token budget on an ambiguous target.

## Phase 0 — Scope Resolution

Spawn a single **Explore** subagent with thoroughness "very thorough":

> Resolve the scope `<user's argument>` to a concrete file set for audit. Trace the feature across every layer:
>
> 1. **Frontend** — pages (`frontend/src/app/pages/`), components used exclusively by those pages, hooks, routes in `frontend/src/app/routes.tsx`
> 2. **Backend routes** — every route handler the frontend calls (grep for `fetch('/api/<prefix>/...')` in the frontend files)
> 3. **Lib code** — every module under `backend/src/lib/` that the routes import (follow imports transitively, but stop at shared infra like `supabase`, `logger`)
> 4. **Database** — every table the routes query, every migration that touches those tables (grep `backend/database/` for CREATE/ALTER on matched table names)
> 5. **Workers** — any worker (`depscanner/`, `parser-worker/`, `watchtower-worker/`, `watchtower-poller/`, `aider-worker/`) that reads/writes the same tables
> 6. **Cron / QStash** — any cron or QStash dispatch that triggers code paths in scope
> 7. **Tests** — every test file that covers any of the above (`__tests__/`, `.test.ts`, `.spec.ts`)
> 8. **Docs** — sections of `CLAUDE.md`, `DEVELOPERS.md`, `.cursor/plans/`, or inline comments that describe this feature
> 9. **Config / env** — environment variables and settings gates relevant to this feature
>
> Return a **feature dossier** as JSON:
> ```json
> {
>   "scope_summary": "one paragraph on what this feature does",
>   "layers": {
>     "frontend": ["path", "path"],
>     "backend_routes": ["path"],
>     "lib": ["path"],
>     "database_tables": ["table_name"],
>     "migrations": ["path"],
>     "workers": ["path"],
>     "cron_qstash": ["path or endpoint"],
>     "tests": ["path"],
>     "docs": ["path or 'CLAUDE.md:line-X-Y'"],
>     "env_vars": ["VAR_NAME"]
>   },
>   "entry_points": ["how users trigger this — UI route, webhook, cron, Aegis tool"],
>   "critical_invariants": ["list of 3-5 things that MUST hold for this feature to be correct — e.g., 'every vulnerability suppression writes an audit log', 'org_id always flows from JWT, never from request body'"]
> }
> ```
>
> If the scope is too broad (>80 files), bucket it and ask the caller which bucket to prioritize.

Parse the dossier. Print a **scope confirmation** to the user:

```
Scope resolved for "<user's argument>":
- Frontend: N pages, M components
- Backend: N routes, M lib modules
- Database: N tables across M migrations
- Workers: <list>
- Tests: N files (estimated X% coverage — see Phase 3)
Proceed? (y/skip confirmation if scope was explicit like a file path)
```

If the user gave an explicit file path or narrow directory, skip the confirmation — proceed directly.

## Phase 0.5 — Delta Mode (only if `--delta` flag)

If `--delta` was passed:

1. `ls .cursor/audits/audit-<scope-slug>-*.md` and pick the most recent. If none, print "No prior audit found for this scope — running fresh" and skip this phase.
2. Read the prior report. Extract:
   - Every finding with its `{file, line, axis, severity, persona_id}`
   - The verdict and axis-health table
   - The report's timestamp (for the "as-of" reference)
3. Attach the prior-findings list to every persona's envelope in Phase 2 with the instruction:
   > You are running a **delta audit**. The following findings were flagged in the prior audit on `<timestamp>`. For each:
   > - If the same issue still exists at the same severity → tag as `STILL_OPEN` with brief confirmation; do NOT re-explain the bug, just confirm it's unchanged.
   > - If the issue is resolved → tag as `RESOLVED` with evidence of the fix (file:line showing the new code).
   > - If the severity changed (code changed but bug persists differently) → tag as `CHANGED` with the new details.
   > - New issues you find that aren't in the prior list → report normally.
4. In Phase 5, the report leads with a **Delta Summary** block showing resolved / still-open / changed / new findings, then the normal audit structure below.
5. Verdict logic changes: `Strong` requires `RESOLVED >= STILL_OPEN` among P0/P1 and zero new P0s. `Significant Debt` if any prior P0 is still open or any new P0 appeared.

## Phase 1 — Persona Planner (1 subagent)

Spawn a general-purpose subagent with the dossier and:

> Select personas from the library (full list in Phase 2). Audit mode — different from PR review:
>
> - **Always include** (not optional): test-thoroughness-auditor, pattern-drift-detector, doc-truth-auditor, observability-audit, opportunity-scout, regression-blast-radius (for shared code)
> - **Security baseline** (always include at least 3): multi-tenancy-auditor, rls-auditor, org-permission-auditor, horizontal-escalation-hunter — plus any feature-specific security personas (byok-secrets for AI features, webhook-signature for integrations, aegis-tool-permission for Aegis code, policy-sandbox-escape for policy engine, etc.)
> - **Scale if dossier is large** — up to 20 personas for full-feature audits, 8-12 for single-screen audits, 5-8 for a single file
> - **Respect user's N if specified**
>
> Output JSON array of `{id, lens, why_this_feature}` — each pick must cite a specific file or invariant from the dossier.

Fallback set if planner JSON fails: multi-tenancy-auditor, rls-auditor, org-permission-auditor, test-thoroughness-auditor, pattern-drift-detector, doc-truth-auditor, observability-audit, performance-at-scale-auditor, opportunity-scout.

## Phase 2 — Parallel Audit Swarm

Spawn all selected personas in parallel as **Explore** subagents (they need to read files, not just a diff). Envelope for each:

```
You are the <persona_name> running a RETROSPECTIVE audit on an existing Deptex feature.

Your lens: <lens>
Other personas running in parallel (don't duplicate — tag out-of-scope findings and skip):
<persona-id list>

Feature dossier:
<full JSON dossier from Phase 0>

You may read any file in the dossier, follow imports, grep the codebase for callers, and read related tests. You are NOT editing — read only.

Project context: This is Deptex, an AI-powered dependency security SaaS. See CLAUDE.md. Core invariants:
- Every backend route enforces auth + permission inline (authenticateUser + organization_roles.permissions / team_roles.permissions JSONB)
- Every tenant-scoped query filters by organization_id/team_id/project_id; RLS is defense-in-depth
- BYOK AI keys are AES-256-GCM encrypted; NEVER logged, NEVER returned to client
- Aegis tools have PermissionLevel and requiredRbacPermissions; dangerous tools route through aegis_approval_requests
- Extraction jobs claim atomically; workers auth via INTERNAL_API_KEY
- Frontend permission gating is UI-only — source of truth is backend

Retrospective-mode rules (different from a PR review):
1. Focus on what's actually there NOW, not what was added recently. Bugs that have shipped for months are P0 if they're real.
2. Compare this feature's conventions to the rest of the codebase — if Aegis uses an older auth pattern than projects.ts, that's drift worth flagging.
3. Evaluate REAL-WORLD behavior, not hypothetical. If a query has no index but touches a 100-row table, that's fine; same query on a 1M-row table is P0.
4. Check what an oncall engineer would have in a prod incident: logs, metrics, error reporting, runbooks.
5. Accumulated debt is a finding — stale feature flags, dead code paths, commented-out blocks, TODO from >3 months ago.

Constraints (same as /criticalreview):
1. Every finding cites file:line with a real path — rejected otherwise.
2. Every finding has a reproduction — a concrete input, a call path, a test that would fail, or a scale condition that triggers it.
3. Either return ≥1 real finding OR `{"status": "clean", "rationale": "<specific to your lens>"}` — no generic LGTM.
4. Severity P0/P1/P2/P3 as in /criticalreview. For retrospective: P0 = active prod risk right now, P1 = bug waiting to trigger under normal usage, P2 = debt worth paying down, P3 = nit.

Output strict JSON (no prose):
{
  "persona_id": "<id>",
  "findings": [
    {
      "file": "<path>",
      "line": <number or "X-Y">,
      "severity": "P0" | "P1" | "P2" | "P3",
      "axis": "<short bug-class tag>",
      "claim": "<one sentence>",
      "reproduction": "<how to trigger/confirm — concrete>",
      "confidence": "high" | "medium" | "low",
      "age_note": "<optional: 'present since initial commit' / 'introduced in phase18 migration' / etc.>"
    }
  ],
  "clean_lenses": ["<sub-concern you cleared>", ...]
}
```

## Persona Library

**Reuse the full library from `/criticalreview`** (`.claude/commands/criticalreview.md`) — every persona there applies to retrospective audit too. Below are the **additional or upgraded** personas specific to audit mode.

### Retrospective-Only Personas

- **test-thoroughness-auditor** — This is stronger than /criticalreview's test-coverage-auditor. For the feature in scope, evaluate:
  - Is there ANY test? (line-counting coverage is the weakest signal; prefer reading the tests)
  - Do tests exercise **real edge cases** (empty input, max input, concurrent writes, tenant isolation, permission denial), or only the happy path?
  - Are **security invariants** tested — does a test assert that user A can't see user B's data? That a route rejects expired JWTs? That dangerous Aegis tools require approval?
  - Are tests **mocking the database** where they shouldn't? Project memory: *"don't mock the database in these tests — we got burned last quarter when mocked tests passed but the prod migration failed"*. Integration tests should hit a real Supabase instance or a transactional test DB, not in-memory mocks of `.from().select()`.
  - Are mocks **chained-return shaped** matching the Deptex `setTableResponse` / `pushTableResponse` conventions, or do they drift into brittle one-off stubs?
  - Are there **integration tests** for multi-step flows (extraction job lifecycle, Aegis plan-then-execute, policy evaluation + notification dispatch), or only unit tests?
  - For each code path the persona reads, answer: "If I introduced a bug here, which test would catch it?" If the answer is "none," that's a finding.
  - Output findings at P2 for missing happy-path tests, P1 for missing security-invariant tests, P0 for mocked-DB tests on migration-sensitive code.
- **pattern-drift-detector** — Compare this feature's conventions to current codebase conventions elsewhere. Examples:
  - Older Aegis code may use bare `supabase.from(...)` while newer code uses a wrapper with org scoping
  - Frontend pages built before the shadcn migration may use older primitives
  - Error response shapes may differ between legacy and current routes
  - Permission-check patterns may predate current helpers
  - Flag each drift as P2 with an "older pattern here, newer pattern at `<file:line>`" note. Don't demand rewrites — just surface the debt.
- **doc-truth-auditor** — For every statement in `CLAUDE.md`, `DEVELOPERS.md`, or inline comments that describes this feature, verify it matches current code. Docs rot fast on existing features. Examples:
  - "Phase 17 complete" — are the Phase 17 tables/routes actually deployed and used?
  - "BYOK keys are AES-256-GCM" — still true, or did we switch algorithms?
  - "Aegis has 50+ tools" — actual count?
  - Flag mismatches as P2; P1 if the doc misleads developers into introducing bugs (e.g., docs say "RLS is enforced" but RLS is off).
- **observability-audit** — Stronger than `/criticalreview`'s observability-auditor. For this feature, imagine you're oncall at 3am and a customer reports it's broken. Do you have:
  - Log lines on the happy path AND every error branch, with `organization_id` for correlation?
  - A metric / dashboard to spot this feature degrading before the customer does?
  - Error reporting (Sentry, console.error with context) that captures enough to debug?
  - A runbook or comment explaining what to do when it fails?
  - Output gaps as P2 (no observability) or P1 (silent failure mode — code catches errors and returns success).
- **performance-at-scale-auditor** — For existing code at realistic data volumes. For every query in scope:
  - Check the table's approximate size by reading recent migrations + any seed/backfill scripts
  - Verify supporting indexes exist in `backend/database/`
  - Flag N+1 patterns, unbounded result sets (`.select()` without pagination), missing LIMIT, client-side filtering of large sets
  - Flag real-data-dependent slow queries: P0 if user-facing and >1s, P1 if background and >30s
- **query-efficiency-auditor** — Latency from how the data is fetched, independent of table size. For every route/page-load handler in scope, trace the actual call sequence and flag:
  - **Sequential awaits that are independent** — `await a(); await b();` where `b` doesn't depend on `a` (should be `Promise.all`). The single most common waste; pin each `file:line` pair.
  - **Per-row external calls** — `await thing(x)` inside a `.map`/loop, especially `supabase.auth.admin.getUserById` per member, registry/GitHub/LLM calls per item. Recommend a batch query (`.in(ids)`) or a single RPC.
  - **Two-query lookups that should be a JOIN** — fetch ids from table A, then `.in('id', ids)` on table B, when a join/RPC returns both in one round-trip.
  - **Count-then-fetch / count-in-JS** — selecting all rows to count or band them in Node instead of aggregating in SQL (`count(*) FILTER (...)`), or PostgREST's 1000-row cap silently truncating counts.
  - **Eager-load-all-tabs** — a sidebar/page firing every tab's data on open regardless of the active tab. Ask: which calls serve only a non-default tab or a dialog, and could defer to tab-select / dialog-open? Quantify calls-on-open vs calls-actually-needed.
  - Severity: P1 for anything on a user-facing critical path (sidebar/page open), P2 for background. Every finding cites `file:line` + the concrete fix (parallelize / batch / join / move-to-RPC / defer).
- **loading-skeleton-fidelity-auditor** — Loading states that lie. For every skeleton / loading placeholder in scope, compare it against the REAL loaded component it stands in for, and flag:
  - **Layout mismatch** — wrong column set, missing/extra columns, a control row (filter bar / search / toggle) that the loaded view has but the skeleton doesn't (or vice versa), wrong row shape. A skeleton showing two dropdowns when the real view has a pill-toggle + one dropdown is a lie that causes a visible jump on load.
  - **Not a real skeleton** — a bare spinner or "Loading…" where the rest of the app uses a shimmer that mirrors the content; or a shimmer that doesn't match the app's house pattern (e.g. the Vercel-style **downward fade**, `maskImage` gradient, that the other tables use).
  - **No hover/interaction guard** — skeleton rows that accept hover/click while loading (missing `pointer-events-none`).
  - Flag layout mismatches as P2, bare-spinner-where-shimmer-expected as P3. Cite the skeleton file:line + the loaded component it should mirror.
- **stale-feature-flag-detector** — Grep for feature flags, env-gated branches, `if (process.env.X === 'true')` in scope. For each:
  - Is the flag still actively toggled, or is it vestigial?
  - Is the disabled branch dead code now?
  - Flag as P2 (dead branch) or P3 (still-toggled flag with no plan to remove).
- **accumulated-dead-code-scout** — Beyond what linters catch: exported functions with zero importers, commented-out blocks, `deprecated` markers with no removal date, TODO/FIXME older than 3 months (check git blame). Flag as P3 cleanup tasks.
- **user-experience-walker** — For features with a UI component: walk through the full user flow as a first-time user with no context. Report:
  - Confusing states (what does this button do?)
  - Broken empty states (page loads but renders nothing)
  - Missing affordances (action exists but isn't discoverable)
  - Permission-based broken states (admin sees it, member sees a broken page)
  - Flag as P2 (real UX issue) or P3 (polish).
- **cost-profile-auditor** — For AI / external-API features: what's the steady-state cost profile at current scale? Any hot path calling the LLM / GitHub API / registry API in a loop? Any cache that should exist but doesn't? Flag expensive-at-scale patterns as P1, cost-optimizable patterns as P2.
- **security-retrospective** — Aggregator persona: runs all security personas in "retrospective" mode — "what was missed when this was built?" Look at when the feature shipped (git log earliest touch), check whether any CVE-class pattern in its dependencies, threat-model drift, or industry-standard controls absent. Output as P0/P1 specific findings; do not issue vague "consider a threat model".
- **operational-rollback-auditor** — For every feature in scope, answer the oncall question: "If this goes wrong in production right now, what's my off switch?" Check for:
  - A way to halt in-flight operations (cancel Aegis runs, stop extraction machines, pause cron dispatch, suspend notification sending, freeze AI spending)
  - Migration reversibility — do the last 5 migrations in scope have an `-- DOWN` section or are they one-way?
  - Feature flags with a kill switch vs. code-only gates (code-only gates require a deploy to disable, which is slow in an incident)
  - Redis keys / DB flags that ops can flip without a deploy
  - Data-corruption recovery — if this feature writes bad data, is there a scripted way to reconcile, or is it a manual SQL session?
  - Flag missing kill switches as P1 (P0 for anything money-flowing: AI cost, billing, external API calls)
- **self-scan-dogfood-auditor** — Deptex sells dependency security. Check whether we practice it on our own code:
  - Does our `package.json` / `package-lock.json` pass our own dep-scan (cdxgen → VDR → advisory check)?
  - Are our own dependencies pinned, or do we have `^` ranges on security-critical packages (Express, Supabase, AI SDKs, Stripe)?
  - Do we run our own Semgrep / TruffleHog pre-commit or in CI, on our own codebase?
  - Is there a GitHub Action that scans our own PRs with the same checks we sell?
  - Are any of our own deps on our internal malicious-package blocklist, flagged by OpenSSF, or in an advisory we're ignoring?
  - Flag gaps as P2 (credibility debt for a security product) or P1 if we're ignoring an actual advisory on our own deps.

### Personas That Take On New Weight in Audit Mode

From the /criticalreview library, these deserve extra attention in retrospective mode because they reveal debt rather than new bugs:

- `multi-tenancy-auditor` — look for old routes that predate the current convention
- `rls-auditor` — look for tables shipped without RLS
- `type-safety-auditor` — look at accumulated `any` / `@ts-ignore` (more forgivable in old code but worth counting)
- `dead-code-detector` — more findings expected on old code
- `error-handling-auditor` — look for error paths that have never been tested in prod

## Phase 3 — Verification Pass

Same as `/criticalreview` — verifier subagents per P0/P1 finding, VERIFIED / UNVERIFIED / DISPUTED. Applied identically.

One retrospective-specific rule: if a verifier finds that a persona's "bug" is **actually caught by a test** (the test was there, you just didn't look), demote to P3 and tag `[CAUGHT BY TEST <path>]`. Existing test coverage is evidence the issue is bounded.

## Phase 4 — Aggregation

Same clustering + consensus promotion + anti-groupthink as `/criticalreview`.

Audit-mode addition: group findings **by layer** (frontend / backend-routes / lib / database / workers / tests / docs) in addition to by severity. This gives the user a mental map: "the security is fine but test thoroughness is P1 across the board," which is actionable.

## Phase 5 — Report

Write to `.cursor/audits/audit-<scope-slug>-<YYYY-MM-DD-HHMM>.md`. Create the directory if missing.

**Verdict framing** (different from `/criticalreview` — this isn't a merge gate):
- **Strong** — 0 P0, ≤2 P1 (all UNVERIFIED or in test-thoroughness only)
- **Needs Attention** — 0 P0, any P1 VERIFIED outside test-thoroughness, or heavy P2 across ≥3 axes
- **Significant Debt** — ≥1 P0 VERIFIED OR ≥3 P1 VERIFIED OR any security-axis P1 VERIFIED

Report structure:

```markdown
# Critical Audit — <scope>
Verdict: **<Strong | Needs Attention | Significant Debt>**
Generated: <UTC timestamp>
Scope: <N files across frontend/backend/workers/migrations>
Personas run: <N>
Findings: <P0> critical / <P1> high / <P2> medium / <P3> low / <K> opportunities

## Executive Summary
<3-4 sentences. What this feature does. Health of the major axes (security, RBAC, tests, observability, performance, UX). The top 2-3 debts to address. Whether an oncall engineer could debug it at 3am.>

## Feature Dossier (summary)
- Entry points: <list>
- Critical invariants: <list from Phase 0>
- Layers: frontend (N files), backend (N routes), lib (N modules), DB (N tables), workers, tests, docs

## Axis Health
| Axis | Status | Notes |
|---|---|---|
| Security | Strong / OK / At Risk | <1 sentence> |
| Multi-tenancy | | |
| RBAC | | |
| Test thoroughness | | |
| Observability | | |
| Performance at scale | | |
| Pattern consistency | | |
| Documentation truth | | |
| UX | | |
| Cost profile | | |

## P0 — Active Prod Risks
<same format as /criticalreview: axis, claim, file:line, repro, verifier evidence, personas that flagged>

## P1 — High Priority Debt
<same format>

## P2 — Medium (pay down when touching this area)
<condensed bullets>

## P3 — Nits & Cleanups
<bulleted>

## Findings Grouped by Layer
### Frontend
- P1 findings: <count>, P2: <count>, P3: <count>
- Top issues: <titles>
### Backend routes
...
### Lib
...
### Database
...
### Workers
...
### Tests
...
### Docs
...

## Test Thoroughness Scorecard
- Files with zero test coverage: <list>
- Files with happy-path-only tests: <list>
- Security invariants without a failing test: <list>
- Mocked-DB tests that should be integration: <list>
- Recommendation: <concrete next test to write to close the biggest gap>

## Observability Gaps
<concrete list of missing log lines / metrics / runbook entries>

## Pattern Drift Inventory
<what's older here than the rest of the codebase, with new-pattern pointers>

## Opportunities (non-blocking)
<same format as /criticalreview — cheap, high-leverage additions>

## Persona Coverage Map
| Persona | Findings | Clean lenses cleared |
|---|---|---|
```

Print a **short chat summary**: verdict, axis-health table one-liner, top 3 P0/P1 titles, path to full report.

## Rules

- **Never auto-fix.** Read-only. Produce a report and a prioritized punchlist — you don't edit code from this command.
- **File:line citations mandatory** — strip findings without them during aggregation.
- **Require specific clean rationales.** Generic "looks good" from a persona → treat lens as "not assessed," not "passed." Makes the coverage map honest.
- **Don't invent files.** Every cited path must exist. Verifier drops false-path findings.
- **Token budget guard** — for scopes over ~80 files or ~15 personas, estimate tokens and confirm with the user before spawning.
- **Don't let the planner skip test-thoroughness, doc-truth, observability, or pattern-drift.** These are the four most commonly-missed retrospective angles — they MUST be in every audit unless the scope is literally one function.
- **If the feature is itself a test directory or a docs file,** the relevant personas are different — ask the user what they mean rather than running a full security swarm on `backend/src/__tests__/`.
- **Don't open an interview loop.** This is a one-shot audit, not a discovery session. Ask at most one clarifying question (scope ambiguity); otherwise proceed.
- **Audit file output is not committed.** Goes in `.cursor/audits/` — note if that path isn't gitignored, but don't modify `.gitignore` unprompted.
- **Respect project memories.** If a memory says "Henry uses integration tests for X, mocks are OK for Y" or similar, cite it in relevant findings rather than contradicting it.
