# Entry-Point Auth Classification — Feature Brief

Date: 2026-07-07 · Worktree: `taint-precision` (off origin/main `8961b3b7`) · Pipeline: /brainstorm → /plan-feature → /review-plan → /implement

## Problem Statement

Every taint flow the engine emits is stamped `entry_point_tag: 'framework-input:PUBLIC_UNAUTH'` (`depscanner/src/taint-engine/storage.ts:275`), so EPD scores every finding as if its entry point were a public unauthenticated endpoint (weight 1.0 — the maximum). Flows behind `authenticateUser`, an `INTERNAL_API_KEY` check, or a QStash-signed cron get the same contextual_depscore inflation as a genuinely public route. On the audited Deptex backend, 6/8 active flows were mis-tagged this way. Prioritization honesty is the product promise; this is the named "biggest correctness lever" left from the taint-FP-reduction work.

## Current State in Deptex

The pieces exist but are **severed**:

- **Framework detectors already capture auth** — `EntryPoint` (`framework-rules/types.ts:26-48`) has `classification`, `authenticated`, `authMechanism`, `middlewareChain`. express.ts extracts per-route middleware chains (`collectMiddlewareChain`) and detects auth (`detectAuthMechanism`/`classifyFromAuth` in `framework-rules/util/javascript.ts:103-126`). Persisted to `project_entry_points` (`framework-rules/storage.ts:114-117`).
- **BUT detection is import-level**: a file importing an auth package flags ALL its routes AUTH_INTERNAL — never verifies the route applies the middleware. fastify.ts never fills `middlewareChain`; nextjs.ts hardcodes `PUBLIC_UNAUTH` everywhere. The other ~28 detectors are import-level at best.
- **The taint engine ignores all of it** — hardcoded tag at `storage.ts:275`. EPD's only live auth signal is the per-flow Qwen verdict from `fp-filter.ts` (DeepInfra `Qwen/Qwen3-235B-A22B-Instruct-2507`), which sees auth only if it lands in a snippet window — and the filter was disengaged on the audited org.
- **EPD is ready to consume**: `ENTRY_WEIGHT_BY_CLASS` (`epd.ts:97-102`) — `PUBLIC_UNAUTH=1.0, AUTH_INTERNAL=0.5, OFFLINE_WORKER=0.2, UNKNOWN=1.0`; `contextual = base_depscore_no_reachability × tierWeight × (entryWeight × 0.85^depth)` (`epd.ts:426-430, 629-631, 1113-1119`). The fallback classifier already parses explicit tags `framework-input:public_unauth|auth_internal|offline_worker` (`epd.ts:398-406`).
- **Aggregation nuance**: `aggregateEpdFromFlows` (`epd.ts:516-613`) uses ONLY AI verdicts inside `flow_nodes` JSONB, worst-case by `ENDPOINT_RANK`; the tag-based heuristic runs only on the `no_flows_evaluated` branch (`epd.ts:1421-1424`). Worst-case merging deterministic evidence therefore touches aggregation, not just the tag.
- **UI**: `EntryPointBadge.tsx` exists (Public=red / Authenticated=amber / Background=gray) but is imported ONLY by its own test — rendered nowhere. `DataFlowFindingCard.tsx:21-34` renders `entry_point_tag` with a **stale vocabulary** (`PUBLIC_AUTH`/`INTERNAL`) that mismatches the real enum. The flow stepper (`VulnerabilityOrgSidebarExpandedContent.tsx` PathCard) shows no auth context.
- **DAST already consumes** the detector auth columns (`dast/openapi-synth.ts:236-241` securitySchemes, `x-deptex-middleware`) — proof the data path works when populated.
- **Backend/DB blast radius is small**: `entry_point_classification` on PDV is pass-through to DTOs (findings-bundle, projects/teams routes) — no backend scoring keys on it; the two SQL recompute paths (phase30 composition multiply, phase67 DAST NULL-fill) are orthogonal to entryWeight. `project_reachable_flows` needs no new columns (tag carries the class).

## Competitive Landscape

### Snyk
- Risk Score contextual factors are **reachability + transitive depth only** — no static auth/attack-surface factor ([docs.snyk.io risk-score](https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing/risk-score)). Their "public facing" factor exists only in AppRisk and comes from **runtime/cloud integration** (container internet exposure), not code ([docs](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/assets-and-risk-factors-for-snyk-apprisk/risk-factor-public-facing)).

### Endor Labs
- Function-level reachability is their headline; "internet-exposed workload" context comes from **pairings with runtime vendors** (Upwind, MS Defender) ([endorlabs.com](https://docs.endorlabs.com/scan/sca/reachability-analysis), [upwind.io](https://www.upwind.io/feed/end-to-end-application-risk-management-with-upwind-and-endor-labs)). No static endpoint-auth factor.

### Apiiro
- Markets detection of "critical/high vulnerabilities accessible via unauthenticated, internet-facing APIs" via their Risk Graph, but the mechanism appears tied to **runtime API endpoint matching** ([apiiro.com blog](https://apiiro.com/blog/apiiro-achieves-true-runtime-api-endpoint-matching/)); static-vs-runtime specifics aren't public (product pages not fetchable in detail — unverified).

### route-detect (OSS, feasibility precedent)
- [mschwager/route-detect](https://github.com/mschwager/route-detect) classifies web routes authn/authz across ~20 frameworks (Django/Flask/FastAPI/Laravel/Symfony/Rails/Spring/JAX-RS/Gorilla/Gin/Chi/Express…) using Semgrep pattern rules on decorators/middleware. Proves per-framework static route-auth classification is tractable. It's a standalone linter — **not wired into vulnerability scoring**, which is exactly the gap Deptex can own.

## Landscape Synthesis

- **Table-stakes**: contextual priority scoring with reachability + exploit maturity.
- **Frontier**: internet-exposure context — every vendor sources it from runtime agents/cloud integrations.
- **Whitespace**: deriving the auth-exposure factor **statically from middleware chains** and feeding it into per-finding scoring. No SCA vendor ships this without a runtime agent. Deptex already has 34 framework detectors + EPD scoring + DAST consuming the same entry-point data — this is "reconnect existing plumbing + deepen detection", leveraging 2 moat pillars (tree-sitter reachability, EPD scoring).
- **Deptex position**: ahead on plumbing, behind on truthfulness (the hardcoded tag makes the current signal actively wrong).
- **Feasibility verdict**: known-tractable (route-detect precedent + our own express detector). Risks: (1) wrong-direction misclassification (public→authed under-scores real risk) — mitigated by fail-safe default PUBLIC_UNAUTH + positive-evidence-only demotion; (2) centralized-auth idioms per framework — scoped to well-known idioms, exotic setups stay PUBLIC (safe/noisy direction); (3) deterministic-vs-AI disagreement — worst-case merge.

## User Stories

- As a **security engineer**, I want findings behind auth ranked below identical findings on public endpoints, so my triage queue starts with what an unauthenticated attacker can actually reach.
- As a **developer**, I want to see WHY a finding is ranked lower (an "Authenticated" badge naming the middleware), so I trust the score instead of suspecting the scanner missed something.
- As an **org admin**, I want machine-only endpoints (signed webhooks, crons) weighted as background surface, so internal plumbing doesn't drown the dashboard.

## Locked Scope Decisions

1. **All 34 detectors get route-level classification in v1** (Henry, interview R1) — not a JS-only slice. Rationale: the labelled corpus already provides 2 validated apps per major ecosystem (discourse/mastodon=Rails, saleor/paperless=Django, petclinic/spring-security-polls=Spring, monica/koel=Laravel, flaskbb/fastapi-realworld=Flask/FastAPI, caddy/gitea=Go, express dogfood=JS), so per-framework validation targets exist for free.
2. **Internal/machine endpoints (internal-key header, signature-verified webhooks, crons) → OFFLINE_WORKER (0.2)** (Henry, R1). No enum change — zero DB/API/frontend blast radius; `epd.ts:410` already routes cron/worker substrings there. Recognition limited to well-known signature/verification idioms (QStash `Receiver.verify`, `stripe.webhooks.constructEvent`, svix, constant-time internal-key middleware patterns); unknown middleware is NOT internal evidence.
3. **Score + badge in this arc** (Henry, R1): wire `EntryPointBadge` into the vulnerability/flow UI and fix `DataFlowFindingCard`'s stale label vocabulary. Rationale: the scoring fix is invisible without it.
4. **Acceptance bar = 2-app + tripwire** (Henry, R1): Deptex-backend rescan (authed/internal flows drop class), a public-route control app (dogfood express fixture stays PUBLIC_UNAUTH), full-corpus diff proving **zero visible-set changes** (reachability levels untouched by design), full jest.
5. **Centralized auth = well-known idioms only** (Henry, R2): route-local evidence + each framework's canonical centralized idiom (Rails `before_action :authenticate…` in ApplicationController; Express `app.use(auth)`-before-registration ordering; DRF `DEFAULT_PERMISSION_CLASSES`; Spring `SecurityFilterChain` `anyRequest().authenticated()`; Laravel route-group middleware; Next.js middleware.ts existence-check at most). Exotic setups stay PUBLIC — the safe (over-scoring) direction. Full matcher-glob resolution explicitly out of scope.
6. **Worst-case merge with the AI verdict** (Henry, R2): PDV classification = highest-risk of (deterministic route evidence, Qwen per-flow verdict). Public beats authed from either side. Also feed `middleware_chain` into the Qwen prompt so its verdict improves. Rationale: fail-safe — a wrong authed-verdict from either side can't hide risk.
7. **One big PR** (Henry, R2) — atomic land after full validation, reachability-loop operating model. (Deploy remains worker-image-gated like everything since June.)
8. **Fail-safe default locked (mine, from the silence-FN discipline)**: a flow whose entry point can't be positively matched to a detected route with auth evidence stays `PUBLIC_UNAUTH`. Demotion requires positive, route-level (or locked-decision-5 centralized) evidence. Import-level residue alone must NOT demote — this reverses the current express/fastify behavior where file-level imports flag every route.

## Data Model

**No new tables. Likely zero migrations.**
- `project_entry_points` already has `classification`, `authenticated`, `auth_mechanism`, `middleware_chain`.
- `project_reachable_flows.entry_point_tag` (existing) carries the class as `framework-input:<class>` — `epd.ts:398-406` already parses it.
- `project_dependency_vulnerabilities.entry_point_classification` (existing, phase18) stores the aggregate.
- Open (plan-feature): whether worst-case merge needs the deterministic class persisted per-flow beyond the tag (probably not — tag suffices).

## API Endpoints

None new. Existing pass-through DTOs already carry `entry_point_classification` (findings-bundle, projects/teams routes) and `entry_point_tag` (flow endpoints).

## Frontend Surface

- Wire `EntryPointBadge` (exists, unrendered) into: the vulnerability sidebar flow context (PathCard area in `VulnerabilityOrgSidebarExpandedContent.tsx`) and/or the vuln row where reachability is shown — exact placement per ui-principles skill at plan time.
- Fix `DataFlowFindingCard.tsx:21-34` label vocabulary → real enum (`AUTH_INTERNAL`, `OFFLINE_WORKER`).
- No new pages.

## User Flows

1. Scan runs → detectors emit route-level `EntryPoint`s with real classification/middleware evidence → taint engine matches each flow's entry (file + enclosing function/line) to a detected entry point → stamps `entry_point_tag: framework-input:<class>` (PUBLIC_UNAUTH when unmatched).
2. Qwen FP-filter (when enabled) sees `middleware_chain` in its prompt; emits its endpoint verdict as today.
3. EPD aggregates worst-case across {deterministic tag, AI verdicts} → `entry_point_classification` + `entry_point_weight` → `contextual_depscore`.
4. User opens a finding → sees the badge ("Authenticated · requireAuth" / "Background · QStash-signed") next to the flow; authed findings rank below public ones with identical CVEs.

## Edge Cases & Failure-Mode Policy

- **No matching detected entry point for a flow** → PUBLIC_UNAUTH (fail-safe, current behavior preserved).
- **Detector has no auth support for a framework** → its routes classify PUBLIC_UNAUTH unless import-level signal is corroborated at route level; never authed on imports alone (Locked 8).
- **Conflicting evidence (deterministic authed vs AI public)** → public wins (Locked 6).
- **Middleware we can't identify** → not auth evidence; route stays public.
- **Multiple flows on one PDV with mixed classes** → worst-case (existing `ENDPOINT_RANK` behavior).
- **Atom/Semgrep-sourced flows** (`reachability.ts:173` writes real tags) → unchanged; only engine-sourced flows get the new stamping.
- **SQL recompute paths** (phase30 composition, phase67 DAST fill) → verified consistent; no changes expected.

## Non-Functional Requirements

- No new AI spend beyond marginal Qwen prompt tokens (middleware_chain strings).
- Detector work is tree-sitter walks already performed per file — perf budget ~zero; the flow→entry-point join is an in-memory lookup per flow.
- No behavior change to reachability levels, Gate-3, baseline-lock, or the visible/hidden finding set — contextual_depscore and tags only.

## RBAC Requirements

None new — display + scoring only, existing view permissions apply.

## Dependencies

- None schema-wise. Ships worker-side → same `FLY_DEPSCANNER_IMAGE` deploy gate as the reachability arcs (one bump ships all).
- Touches `depscanner/src/framework-rules/*` (34 detectors + util), `taint-engine/storage.ts`, `taint-engine/fp-filter.ts`, `epd.ts`, 2 frontend components.

## Success Criteria

1. **Deptex backend rescan**: the historically mis-tagged flows (authenticateUser routes, INTERNAL_API_KEY/QStash endpoints) classify AUTH_INTERNAL / OFFLINE_WORKER with visibly lower contextual_depscore; genuinely public routes (e.g. `notification-unsubscribe`) stay PUBLIC_UNAUTH.
2. **Control app**: dogfood express fixture's public routes all stay PUBLIC_UNAUTH — zero wrongful demotions.
3. **Corpus tripwire**: full-corpus diff shows zero reachability_level / visible-set changes; contextual_depscore movement only in the demote-safe direction on authed entry points.
4. **Per-framework fixtures**: each detector's auth idioms locked by `-authed/-public` fixture pairs (route-local + the Locked-5 centralized idiom), all green in CI.
5. Full backend+depscanner jest green; tsc 0.

## Open Questions

1. **(blocks /plan-feature — resolve there)** Exact flow→entry-point join semantics: match by (file, line-in-handler-span) vs (file, handlerName); behavior when detectors emit overlapping entry points.
2. **(defer to /implement)** Badge placement details + whether OFFLINE_WORKER displays as "Background" or "Internal" for webhook endpoints.
3. **(informational)** Whether `project_entry_points` rows should also be corrected retroactively for fastify/nextjs (they will be, on next scan — no backfill needed since scans are per-run).

## Recommended Next Step

`/plan-feature` — scope is locked; the one blocking open question (join semantics) is a plan-level design decision.
