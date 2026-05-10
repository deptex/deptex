# Feature Brief: Deptex Cross-File Taint Engine (Phase 6)

> **Historical context (2026-05-09):** This plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. Where this plan references BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, or `AI_ENCRYPTION_KEY` for AI key envelopes, treat those as historical implementation details — current AI runs on platform keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from worker env). `AI_ENCRYPTION_KEY` itself is still in use, but only for `organization_registry_credentials` (IaC v2 Phase 1).

## One-liner
A deterministic forward-propagation cross-file taint engine for JS/TS — built on the TypeScript Compiler API and wired into the `reachability_rules` pipeline — paired with an IRIS-style AI augmentation layer (spec inference + FP filter), designed to replace `atom` as the canonical reachability engine over time.

## Problem Statement
Today the `reachability_rules` pipeline step relies on `atom` (from dep-scan) for cross-file taint flows on JS/TS and Java. Atom has known gaps for languages it doesn't cover (Go, Kotlin, Swift, Python frameworks) and for dynamic dispatch / framework indirection in JS. Phase 5 added per-CVE AI rule generation on top, but that's a per-CVE rule, not whole-program reachability — orthogonal lever. The Phase 6 engine fills the engine-quality gap directly: better cross-file taint that we own end-to-end and can iterate on, instead of being bottlenecked by atom's roadmap.

## Competitive Landscape (summary — full detail in `research-cross-file-stitching.md`)
- **Joern** (OSS): CPG architecture, 30+ engineer-years cumulative, requires hand-written semantics for any external method. We chose not to integrate.
- **Snyk Code (DeepCode)**: Hybrid symbolic + ML from day 1 (per ETH Zurich). 3 years company time / 7 years counting research to first-language production. Closed source.
- **Semgrep Pro**: Interprocedural taint shipped Feb 2023 after 6 months focused work *on top of* a mature OCaml engine. 2 dedicated sub-teams.
- **CodeQL**: 13 years and ~80 people. **28 MB of hand-curated QL standard library** (per-framework taint specs) is the actual product; the engine is the smaller piece.
- **IRIS (ICLR 2025)** is the published frontier: deterministic engine + LLM-inferred specs + LLM FP filter beats CodeQL alone by **+103% on CWE-Bench-Java**. SAST-Genius shows **91% FP reduction** on Semgrep output via LLM post-filter.

We're deliberately positioning as a Snyk-Code-shaped hybrid (symbolic + AI) but open-core, BYOK-first, and built on the TypeScript Compiler API for JS/TS.

## User Stories
- *As an org admin*, I want our reachability data to keep getting more accurate without me reconfiguring anything, so my team trusts the depscores more over time.
- *As a security engineer*, I want fewer false-positive findings on my project's vuln list, so I'm not wasting triage time on un-reachable noise.
- *As a developer on a project with no tsconfig*, I want to still get reachability data with a clear note that quality is reduced, so I'm not blocked from using the product but I know what's missing.
- *As a self-host customer*, I want the deterministic engine to ship in extraction-worker without requiring an AI key, so my air-gapped install still gets cross-file taint.

## Architecture Decisions (locked from interview)

| # | Decision | Choice | Implication |
|---|---|---|---|
| 1 | Engine role | Replace atom over time | Aim for canonical-engine quality. Ship as second-opinion in v1; retire atom on three concrete gates. |
| 2 | Starting language | TS/JS only (TypeScript Compiler API substrate) | Maximum leverage win — tsc gives us callgraph + symbols + type-aware edges essentially free. |
| 3 | Vuln class scope | Aim big — 10+ classes | SQLi, SSRF, XSS, path traversal, command injection, prototype pollution, deserialization, ReDoS, file upload, open redirect, log injection. Each = 1-2 weeks of source/sink modeling. |
| 4 | OSS posture | Open-core, AI layer optional | Engine ships in extraction-worker (Apache/MIT). Self-hosters get deterministic-only. Cloud users get AI augmentation. |
| 5 | Framework models | Hybrid — hand-write top 5, AI infer long tail | Hand-written: Express, Fastify, NestJS, Next.js, Hono. AI-inferred for everything else, reviewable + editable in UI. |
| 6 | AI layering | Both spec inference AND FP filter | IRIS architecture exactly — spec inference once per (framework, version) cached; FP filter on each flow above confidence threshold. |
| 7 | Cost cap policy | New 'taint-engine AI' bucket | Separate org-level cap configurable in AI Settings page. Distinct cost shape from EPD per-vuln calls. |
| 8 | Untyped JS handling | Best-effort + UI quality warning | Run on everything. Info-level banner ("Reachability quality reduced — add tsconfig for full coverage") on projects with no types. |
| 9 | Pipeline integration | Feed existing `reachability_level` enum | Engine output yields `confirmed`/`data_flow`/etc. just like atom. Depscore weights stay the same. |
| 10 | UI surface | Fold silently into existing reachability UI | No new badges. Users see better depscores; framing is "we improved reachability." |
| 11 | Failure mode | Hard-fail the extraction step | If engine times out, crashes, or returns invalid output, the whole extraction fails. Forces a high robustness bar — needs circuit breaker + extensive testing before GA. |
| 12 | Atom retirement gates | Recall parity + 30 days A/B + zero regressions on test-npm | All three must pass to retire atom. Concrete and measurable. |
| 13 | Phase 8 (Joern) | **Drop entirely** | Roadmap simplification. We bet on Phase 6. |
| 14 | AI tier | Platform Gemini Flash (we pay) for now | Defer BYOK requirement until cost data tells us we need it. Mirrors Phase 5 platform tier. |
| 15 | Per-extraction time budget | 30 minutes | Generous to cover monorepos + spec inference + framework analyses. Hard timeout. Logged on exceed. |

## Data Model (high level)

New tables / columns to design in `/plan-feature`:
- `taint_engine_runs` — per-(extraction_run_id) run metadata: started_at, finished_at, status, total_flows, ai_filtered_flows_count, time_to_complete_ms, framework_models_loaded TEXT[], ai_cost_usd
- `taint_engine_flows` — normalized output flow records: project_id, extraction_run_id, vuln_class, source_file, source_function, source_line, sink_file, sink_function, sink_line, framework, confidence, ai_filter_verdict (kept | rejected | not_run), engine_version
- `taint_engine_framework_models` — per-(org_id, framework_name, framework_version) cached AI-inferred specs: org_id, framework, version, sources JSONB, sinks JSONB, sanitizers JSONB, inferred_at, edited_by_user, last_validated_at
- `taint_engine_settings` — per-org config: ai_layer_enabled BOOLEAN, taint_engine_ai_monthly_cap_usd NUMERIC, untyped_js_enabled BOOLEAN
- New columns on `project_dependency_vulnerabilities`: engine_source TEXT (atom | taint_engine_v1 | both), engine_v1_confidence NUMERIC

Connects to existing: `extraction_runs`, `project_reachable_flows` (the existing atom output table — engine v1 output goes into a sibling table during shadow mode, then merges in for canonical), `organization_ai_providers`, `organization_settings`.

## API Endpoints (high level)

To design in `/plan-feature`:
- `GET /api/internal/taint-engine/run/:extractionRunId` — internal endpoint for the worker to fetch settings and post results
- `POST /api/internal/taint-engine/result` — worker posts normalized flows + run metadata + AI cost
- `GET /api/orgs/:orgId/taint-engine/settings` — frontend, AI Settings page integration
- `PATCH /api/orgs/:orgId/taint-engine/settings` — update cost cap, AI layer toggle, untyped JS toggle
- `GET /api/orgs/:orgId/taint-engine/framework-models` — list AI-inferred framework specs for review/edit
- `PATCH /api/orgs/:orgId/taint-engine/framework-models/:modelId` — edit a spec; optionally invalidate cache for that framework
- `POST /api/orgs/:orgId/taint-engine/framework-models/:modelId/refresh` — re-run AI inference for a framework

All authenticated via `authenticateUser`. Org-level RBAC: viewing requires `view_ai_spending` or `manage_aegis`; editing requires `manage_aegis`.

## Frontend Views

- **AI Settings page** extension: new "Taint Engine" card alongside existing EPD card. Cost cap input, AI-layer-enabled toggle, untyped-JS-enabled toggle, link to framework models page.
- **Taint Engine Framework Models page** (`/orgs/:orgId/settings/taint-engine`): list of (framework, version, last inferred date, source) — admins can review AI-inferred specs, edit JSON manually, force re-inference, mark a model as "verified".
- **Reachability quality banner** on project pages where untyped JS reduces engine quality. Info-level styling, dismissible per-project.
- **Existing reachability UI**: no changes required (per decision #10). Findings render same as today; reachability_level just gets more accurate.
- **Admin / Extraction Failures page** extension: show taint-engine timeout / crash failures as a distinct error category with stack/log link.

## User Flows

1. **Org admin enables engine**: AI Settings → Taint Engine card appears (already on by default in cloud, off by default in self-host). Admin sets cost cap. Saves.
2. **Project gets first scan with engine**: extraction job runs, engine produces flows, FP filter trims, normalized flows feed reachability_level classifier, depscores recompute. User sees no new UI — just better data.
3. **Untyped JS project**: engine runs in best-effort mode. Banner appears on project page: "Reachability quality reduced — add a tsconfig.json for full coverage." Dismissible.
4. **Engine hits timeout (30min)**: extraction step hard-fails. extraction_step_errors logged. Admin sees on Extraction Failures page. User sees the standard "extraction failed, retrying" UI. Engineer investigates via admin tools.
5. **AI infers spec for new framework**: project's package.json contains tRPC (not in hand-written set). Engine triggers spec inference via platform Gemini. Spec cached per (org, framework, version). Admin sees the new spec in Framework Models page; can edit or accept.

## Edge Cases & Error Handling

- **No tsconfig in JS project** → run with `allowJs: true`, no type info; surface UI banner; quality marked "reduced" in run metadata.
- **Project too large for callgraph** (memory/time blowup) → 30min timeout trips → hard-fail extraction → admin sees on /admin/extraction-failures.
- **AI provider timeout / quota exhausted** during spec inference → engine continues with deterministic-only output for that framework; logs warning; flow records keep `ai_filter_verdict: not_run`.
- **Spec inference returns invalid JSON** → drop the inference, log warning, fall back to "no model for this framework" (engine produces no flows for that framework's sources).
- **Engine produces a flow with invalid file paths or out-of-bounds lines** → drop the flow, log to taint_engine_runs.invalid_flow_count.
- **First few weeks of beta**: many projects might trip the hard-fail. Need a feature flag or org-level kill switch for emergency rollback.

## Non-Functional Requirements

- **Performance budget**: engine must complete within 30min for 95% of typical npm projects (medium = 50k LOC, large = 500k LOC). Worst-case hard-fail.
- **Memory**: engine should run within the existing extraction-worker Fly.io VM size (4GB RAM). Callgraph + propagation must not blow this.
- **Output volume**: engine flows must round-trip into existing flow tables without bloating writes. Estimate ~5-50 flows per medium project, ~200-1000 per large.
- **AI cost**: spec inference for 5 hand-written frameworks = $0. AI inference for long-tail framework: estimate $0.05-$0.50 per (framework, version) on Gemini Flash. FP filter: ~$0.001 per flow at typical token counts. At 1000 weekly extractions × 50 flows × $0.001 = ~$50/wk in FP filter cost — manageable on platform tier.
- **Reliability**: hard-fail policy means engine bug = extraction failure. SLO: ≥99.5% engine completion rate on typical projects before GA. Circuit breaker: if engine hard-fails >5% of extractions in any 1-hour window, automatic kill switch reverts to atom-only.
- **Realtime**: not required. Engine output written at extraction commit time, surfaced via existing UI (which is already realtime-subscribed).

## RBAC Requirements

- View AI cost / engine status: `view_ai_spending` (existing org permission)
- Edit framework models / change settings: `manage_aegis` (reuses existing — fits "AI configuration" scope)
- Trigger framework re-inference: `manage_aegis`
- View admin failure dashboard: existing admin role

## Dependencies

- `extraction-worker` repo (Phase 1 self-host work shipped) — engine ships here
- `dep-scan` integration (still in pipeline for SBOM + atom) — engine runs alongside, not after
- `reachability_rules` pipeline step (Phase 3) — engine output feeds same `updateReachabilityLevels()` classifier
- AI provider infrastructure (Phase 5) — `getProviderForOrg()`, retry loops, cost tracking, withRateLimitRetry
- EPD cost cap pattern (Phase 4) — clone for new taint-engine cost cap
- Framework detector registry (Phase 2) — spec inference uses these to detect which frameworks need models loaded

## Success Criteria

**v1 GA bar:**
- Engine completes within 30min on ≥99.5% of test-npm + deptex-test-* + 10 OSS-control projects
- Engine produces ≥80% of atom's recall on the JS subset of the 88-CVE Phase 5 corpus (shadow mode comparison)
- AI FP filter reduces flow false-positive rate by ≥50% on a hand-labeled 200-flow sample
- Hard-fail circuit breaker successfully triggers on synthetic crash injection
- AI cost stays under $0.10 per typical extraction run (platform tier exposure ceiling)

**Atom retirement bar (separate gate, post-GA):**
- Recall parity OR better than atom on the 88-CVE Phase 5 corpus JS subset
- 30 days of shadow-mode A/B in prod with engine output captured but not surfaced
- Zero new false negatives on test-npm + deptex-test-npm full extraction vs atom-only baseline

**Beyond v1 (year-2 hedge):**
- Spec inference quality validated by hand-review of 50 AI-inferred framework models — ≥80% rated "usable as-is"
- Optional published OWASP-Benchmark-style F1 score for marketing — defer scoping until v1 ships

## Open Questions / Risks

1. **Hard-fail policy is aggressive.** Engine bugs literally break extractions. Will need (a) extensive integration tests, (b) staged rollout (canary org → 10% → 100%), (c) hard kill switch tied to error-rate threshold. Worth confirming we accept this risk before plan-feature.
2. **AI cost exposure on platform tier.** "We pay for now" is fine at small scale; at 10k+ orgs scanning daily, FP-filter calls become a real Gemini Flash bill. Set a date — month 4 of operation — to revisit BYOK requirement based on actual cost data.
3. **Untyped JS recall is unknown.** Best-effort + warning is the right user UX, but we don't yet know how bad untyped recall actually is. Could be 50% of npm projects look "broken" to users. Mitigation: instrument quality metrics per project type, decide if we need a hard "tsconfig required" gate before GA.
4. **Framework model quality for AI-inferred specs.** IRIS reports 87% recall on sink specs and >70% precision in their published numbers — but on Java with GPT-4. Need to validate similar quality on JS frameworks with our cheaper model tier (Gemini Flash).
5. **Time-budget creep on the 10+ vuln classes.** The "aim big" scope is 10+ classes × 1-2 weeks of source/sink modeling per class = 10-20 engineering weeks just for hand-modeling. Realistic if scoped to JS/Express only; impossibly slow if we widen to 3 frameworks at once. Need plan-feature to lock per-class effort estimates.
6. **Framework support cadence post-launch** — not decided in interview. Suggest: ship with 5 hand-written + AI long-tail at GA, then 1 new hand-written framework per quarter for famous additions, AI handles the long tail organically. Confirm in plan-feature.

## Scope: MVP vs Full

**MVP (Phase 6 v1 — what we're scoping in plan-feature):**
- TS/JS engine on TypeScript Compiler API
- Forward-propagation worklist taint engine
- 10+ vuln classes (with possibility of staging — start with the obvious 5 in M3, add the next 5-6 in M4-M6)
- Hand-written models for top 5 JS frameworks
- AI spec inference + FP filter (both, IRIS architecture)
- New taint-engine AI cost-cap bucket
- Best-effort untyped JS with UI warning
- Silent UI fold (no new badges, just better depscores)
- Hard-fail on engine errors with circuit breaker + kill switch
- Run as shadow mode (output not surfaced) until atom retirement gates pass
- AI Settings page + Framework Models page

**Full (post-MVP, year-2):**
- Atom retirement when gates pass
- Python via Pysa-as-subprocess + Scalpel/Jedi
- Go via golang.org/x/tools/go/callgraph
- BYOK requirement for AI layer (revisit based on cost data)
- OWASP Benchmark publication
- Java/Kotlin/Ruby/PHP/Rust/C# extension via tree-sitter + own engine — defer indefinitely until justified

**Out of scope forever:**
- Joern integration (Phase 8 dropped per decision #13)
- Aliasing precision (Andersen-style points-to)
- Context-sensitive analysis (k-CFA / object-sensitive)
- Cross-language flows (e.g. JS → WASM module)

## Recommended Next Step
Run `/plan-feature` against this brief. The plan should focus on:
1. M1-M3 deliverables (substrate + propagator + 5 vuln classes + Express)
2. Hard-fail safety story (circuit breaker, kill switch, staged rollout)
3. Schema design including `taint_engine_runs`, `taint_engine_flows`, `taint_engine_framework_models`, settings table
4. Per-vuln-class effort estimates so we can lock realistic milestone scope for the "10+ classes" goal

Reference: `.cursor/plans/research-cross-file-stitching.md` for the full technical evidence base.
