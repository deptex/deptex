# Plan Review — entry-point-auth

## R3 (2026-07-08, plan v3, 4 personas focused on the span mechanism): **REVISE — unanimous 4/4, 0 P0**
All four personas independently confirm **both R2 P0 clusters are structurally dead with no resurrection path** — the per-route handler-span containment join needs no httpMethod discriminator (null-method Django/Tornado/Starlette/net-http legs join via spans; public `.all()` routes carry their own spans → mixed files stamp per-route) and needs no export extraction/veto (the guard is per-file syntactic). 17 P1 / 10 P2 / 8 P3, all spec-precision on the new mechanism, all applied in v4:
- **Convergent P1 (r3-ec-3/skeptic3-f2/arch3-1/ts3-f5):** the exported-handler guard is JS-module-semantics-specific — Go's package privacy breaks "lowercase = private" (same-package cross-file re-mount → wrongful demote) and "uppercase = exported" guts the Go leg; declaration-bound families (Spring/Flask/Django/NestJS/…) need the guard N/A (evidence travels with the declaration). → v4 adds a per-language applicability table + Go same-package name-scan + same-file-reference ineligibility.
- **P1 span-node (r3-ec-1):** the detector holds both the call node and the handler node; the existing `lineOf(node)` precedent points at the call node → pre-auth middleware bodies would be inside an "authed" span. → v4 pins span = terminal handler-arg node only.
- **P1 export-form coverage (r3-ec-2/skeptic3-f1/ts3-f4):** the literal form list misses `export {h}`-after-declaration / `export default` / CJS shorthand → the exact R1 P0 counterexample resurrects. → v4 respecifies as a structural over-approximation.
- **P1 merge precision (skeptic3-f4/arch3-4):** "regardless of the sanitization filter" expands AI demotion power; the single aggregator filter must split into two vote sets. → v4 splits `sanitizationVoters`/`endpointVoters`, makes the expansion an explicit fail-safe decision.
- **P1 two-site join (arch3-2)** + **re-homed output channel (arch3-3)** + **span line convention (ts3-f1)** + **resolution whitelist (r3-ec-4)** + **T13(d) conjunct asserts (ts3-f8)** — all pinned in v4.
Every vote: "one focused editing pass, direction confirmed, no REWORK." Full R3 data: workflow wf_6f2e18b3-b3a journal + scratchpad r3-parsed.json.

---

## R2 (2026-07-07, plan v2, 8 personas via workflow): **REVISE — unanimous 8/8**
74 R1-fixes confirmed sound; 3 P0 / 19 P1 / 13 P2 / 18 P3 NEW findings, converging on the two v2-introduced join mechanisms:
- **P0-A (arch2-1/r2-ec-1/wpa2-f1/pragmatist-r2-f1):** the `concrete httpMethod` membership predicate is the wrong mount discriminator — django/tornado/starlette/nethttp emit null on every real route (those legs score-inert again) and public `.all()`/`any` routes are excluded from mixed files (wrongful demote).
- **P0-B (skeptic2-f1/arch2-4/r2-ec-2/r2-ec-3/wpa2-f2/pragmatist-r2-f4):** the exported-handler leg + cross-file veto is uncomputable (no export extraction exists; barrels produce no ImportBinding; "unresolvable handlerName" ambiguous both directions — strict reading kills the spine criterion via index.ts's inline /health, lenient reading resurrects the R1 P0).
- Key P1s: T13(c) rows the machinery can't produce (Stripe/GitHub cross-file verifiers → corrected to accepted-PUBLIC residuals); re-homed rows must be ctx-only (dedupe-key collision / DAST first-wins / snippet corruption); filtered-flows merge rule violated Locked-6 (AI-public must never be overridden); detector-flow legacy tag would vote as evidence-public (new `framework-route:` prefix); UNKNOWN must stamp unmatched; gate mechanics (baseline protocol, committed allow-list, filter-engaged ≥1-verdict assert, dogfood checker extension is real work); rails `resources` blindness (honest residual).
- Every vote's flip-to-READY condition: replace the membership predicate + cut-or-own the veto → **both resolved in v3 by the per-route handler-span containment join** (skeptic2-f1's own patch): flows demote only when their source line falls inside an authed, demotion-eligible (non-exported, same-file) handler span. Structurally fail-safe for every unseen/wrapped/exported/aliased route; no export extraction; no mount discriminator needed.
Full R2 data: workflow wf_265c7d31-580 journal + scratchpad r2-parsed.json. Plan v3 applies the complete batch.

---

## R1 (plan v1)
Verdict: **REWORK**
Plan reviewed: `.cursor/plans/entry-point-auth.plan.md` (worktree taint-precision)
Generated: 2026-07-07
Mode: lean (planner added 2 seats); debate: off
Personas: 8 — skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, worker-pipeline-auditor, edge-case-hunter
Vote tally: READY 1 / REVISE 5 / REWORK 2
Findings: 2 P0 / 25 P1 / 31 P2 / 12 P3 (70 total; all code-verified against the worktree)

## Summary

The plan's **direction is confirmed by every persona** — route-level auth evidence, evidence-based classification, EPD integration, fail-safe defaults, zero migrations. But two P0s invalidate load-bearing claims: (1) the file-level worst-case join's soundness argument is **false** (a flow's `entry_point_file` is the source-expression file; an exported handler mounted publicly from another file gets demoted by its neighbors' auth), and (2) the acceptance bar's only automated gate (corpus-diff) is **structurally blind** to this feature's dangerous failure mode (it compares only `reachability_level`, which can't change by construction). Around them sits a convergent P1 cluster: the Rails/Django join can never match (routes-file vs controller-file), the AI merge as designed destroys demotion power from both directions, DAST *does* behaviorally consume `classification` (OFFLINE_WORKER rows are dropped from the spec), and CI runs zero framework-detector tests today. Every finding has a bounded patch; REWORK here means **rewrite the plan's Core Semantics + T9 + T13 (plan v2), not rethink the feature**.

## Vote Tally

| Persona | Vote | Top concern | Rationale (what flips the vote) |
|---|---|---|---|
| skeptic | REVISE | skeptic-f1 | Corrected join semantics (handler-keyed) + matched-evidence-only merge → READY |
| pragmatist | REVISE | join-mismatch | Fix join keying; re-split XL tasks → ships fine |
| scope-cutter | REVISE | scope-cutter-f1 | Promote T5 to critical path w/ filter-engaged validation; cut nextjs body-walk → READY |
| architect | REVISE | architect-f3 | Fix T1/T6/T9 dependency graph (hook is shared infra); exclude detector/suppressed rows from join |
| test-strategy-auditor | REWORK | test-strategy-f1 | T13 must be redesigned around a class-aware diff + CI-wired runner before any detector is written |
| opportunity-scout | READY | (additive) | Record the evidence-string scope cut; note fast-follows |
| worker-pipeline-auditor | REVISE | worker-pipeline-f2 | Banked authFacts + per-detector isolation + right-stage perf gate → pipeline shape survives |
| edge-case-hunter | REWORK | edge-case-f1 | Core Semantics 5 redesigned around handler identity + veto tokens → REVISE |

## P0 — Fundamental Concerns

### join-unsoundness: the file-level worst-case join demotes public flows `[SOLO — but skeptic-f1 P1 is the same defect independently found]`
- **Plan section:** Core Semantics §5 / T3
- **Claim:** "Sound regardless of which handler the flow actually entered" is false. `entry_point_file` = the file where the taint source *expression* fires (`propagate-core.ts:1146`), not where the route is registered. Concrete shape: `routes/account.js` registers only authed routes AND exports `resetPasswordHandler` (reads `req.body`); `routes/public.js` mounts it on a public route. The flow's entry file is account.js → all entry points there are authed → wrongful `auth_internal` demotion on a genuinely public flow. Handler re-export between router files is a mundane Express/Koa shape; the AI backstop doesn't exist on filter-disengaged orgs (the audited org's actual state).
- **Suggested patch:** Redesign Semantics 5: the per-file worst-case must additionally include the classes of *other files' entry points whose handlerName resolves (via existing import bindings) to a function exported by this file*; if the file exports any function referenced as a route handler elsewhere that is public/unresolvable — or cross-file references can't be resolved — the flow stays PUBLIC_UNAUTH. Delete the soundness sentence; add the exported-handler jest fixture to T3.
- **Flagged by:** edge-case-hunter (P0), skeptic (P1, same counterexample independently)

### vacuous-gate: the acceptance bar cannot detect the feature's dangerous failure mode `[CONVERGENT ×3]`
- **Plan section:** T13 · Validation
- **Claim:** `corpus-diff.ts` compares only `reachability_level` — untouched by construction — so T13(d) passes trivially and *nothing automated* detects a wrongful PUBLIC→AUTH_INTERNAL/OFFLINE_WORKER demotion. Brief SC-3 ("contextual_depscore movement only in the demote-safe direction") names a property no tool measures. The corpus run dirs already dump everything needed (`vulns.json` has entry_point_classification/contextual_depscore; `reachable_flows.json` has entry_point_tag).
- **Suggested patch:** Add a class-diff mode to corpus-diff (or sibling script): per corpus app, diff per-flow tag class + per-PDV classification between runs; ALARM on any demotion transition not on a hand-adjudicated allow-list; print per-app class distributions. Make "zero unexplained class-demotions across 15 apps" the T13(d) exit criterion.
- **Flagged by:** test-strategy-auditor (P0), skeptic-f6 (P1), opportunity-scout-f2 (P2)

## P1 — High-Priority Gaps (25, clustered)

**Join & merge design (the Core-Semantics rewrite):**
1. **skeptic-f2 + pragmatist-f1 · T9 join-mismatch** — Rails/Django EntryPoints are emitted at routes.rb/urls.py; flows source in controller/views files → T9 yields *zero scoring change* as designed. Patch: postProcess re-homes (or additionally keys) resolved handler files into the join map; Rails fixture asserting a controller-sourced flow gets the authed tag.
2. **skeptic-f4 · T4 default-vote** — merging unmatched-default PUBLIC into max-risk destroys the AI verdict's demotion power (score RAISE vs today on filter-engaged orgs). Patch: distinguish `framework-input:unmatched` from evidence `public_unauth`; only detector-matched classes vote in the merge.
3. **scope-cutter-f1 · T5 load-bearing** — Qwen's prompt rules (never UNKNOWN; PUBLIC = "no visible auth") make the AI veto every centralized-idiom demotion under max-risk merge. Patch: T5 required-for-outcome; amend the fp-filter endpoint rules so injected route context counts as visible evidence; add a filter-ENGAGED validation scan to T13.
4. **architect-f1 · T3 detector-flows** — detector-coerced flows' entry_point_file = sink file (synthetic; `detector-flows.ts:61,102,148`) → exclude from stamping (keep the constant).
5. **architect-f2 · T4 suppression leak** — deterministic worst-case over ALL flows lets a user-suppressed public flow pin the PDV public forever. Patch: compute over non-suppressed flows only (both branches); mixed-suppression jest case.
6. **worker-pipeline-f4 · Semantics 5 membership** — express prefixed-mount `use` rows are EntryPoints (httpMethod null) defaulting PUBLIC → any file with authed routes + a mount never demotes. Patch: join membership = terminal http_route rows with concrete httpMethod only; mount rows become file-scoped middleware records.
7. **architect-f5 (P2→cluster) · ENDPOINT_RANK trap** — UNKNOWN=0 ranks below OFFLINE_WORKER; join must NOT reuse ENDPOINT_RANK (UNKNOWN counts as public).

**Consumer & invariant corrections:**
8. **skeptic-f3 · DAST behavioral consumer** — `openapi-synth.ts:170` DROPS OFFLINE_WORKER entry points from the DAST spec; "no behavioral consumer" is false. Patch: correct the claim; decide+document whether excluding newly-OFFLINE_WORKER webhooks from DAST is intended; assert synth output for that case in T13(c).
9. **worker-pipeline-f2 · postProcess failure isolation** — a hook throw soft-fails usage_extraction → zeroes httpEntryPointCount → flips reachability promotions → violates the plan's own invariant. Patch: per-detector try/catch into detector-errors; count+store must be unconditionally reachable; jest for throwing hook.
10. **worker-pipeline-f1 · postProcess data availability** — ExtractedFile has no source/AST; hook as specified can't read before_action kwargs. Patch: detectors bank `authFacts` during the per-file walk; postProcess joins in-memory facts only (also resolves the sync-loop/heartbeat concern).
11. **architect-f3 · false reuse + task ordering** — mount-prefix.ts exports nothing reusable; express cross-file inheritance needs the hook, introduced only in T9 while T6 depends on it. Patch: hook (with `{workspaceRoot}`, mutate-in-place, ordering: detect → resolveMountPrefixes → postProcess → ctx build → store) moves to T1 as shared infra.
12. **worker-pipeline-f3 · wrong perf gate** — new cost lands in usage_extraction's 5-min hard timeout, not taint. Patch: per-step duration gate on usage_extraction (largest corpus apps), bound postProcess work.

**Evidence-rule holes (all wrongful-demotion direction):**
13. **edge-case-f2 + skeptic-f7 · optional-auth** — `passport.authenticate('anonymous')`, `expressjwt({credentialsRequired:false})`, `Depends(get_current_user_optional)`/`auto_error=False`, chi `jwtauth.Verifier` (parse-not-enforce). Patch: veto tokens (`optional|anonymous|guest|maybe|try`), arg inspection, parse-vs-enforce distinction, negative fixtures per family.
14. **edge-case-f3 · Spring SpEL + carve-outs** — `@PreAuthorize("permitAll()")`/`isAnonymous()` are PUBLIC; SecurityFilterChain with any `permitAll()` carve-out (every real app) must not demote anything. Patch: parse SpEL public tokens as overrides; chain demotes only when NO carve-out exists.
15. **edge-case-f4 · DRF overrides missing** — `AllowAny`, `authentication_classes=[]`, `IsAuthenticatedOrReadOnly`(→not-covering), `@login_not_required`. The wrongly-demoted views are login/registration/webhooks — the highest-value public surfaces.
16. **edge-case-f5 · Rails conditional + non-halting** — `if:/unless:` kwargs not in Semantics 3's list; bare `authenticate` matches non-halting user-setters. Patch: ANY kwarg other than resolved matching `only:` → not covering; Ruby evidence requires bang-convention/known-halting allowlist.
17. **edge-case-f7 · express use-inheritance 4 holes** — prefixed use needs literal-prefix match (also skeptic-f8); only top-level unconditional statements count (also worker-pipeline-f6); keying per instance variable never per file; mount-before-auth ordering. One fixture per constraint.
18. **edge-case-f8 · aiohttp unprovable** — middleware-list demotion cut (carve-outs live inside middleware bodies); optional belt: well-known public route names (login/health/webhook…) never inherit centralized demotion.
19. **scope-cutter-f2 + pragmatist-f6 + edge-case-f6 · nextjs body-walk cut** — session-call presence ≠ enforcement (optional-personalization demoted); exceeds Locked-5's cap; cut to all-PUBLIC (or strict guard-shape analysis only).

**Delivery & validation mechanics:**
20. **test-strategy-f2 · CI wiring** — package.json registration runs in NO CI job (spring test proves it; framework snapshot fixtures all slow:true). Patch: aggregate runner (glob framework-detector-*-auth tests) wired into test.yml/preflight; cite from SC-4.
21. **test-strategy-f3 · T9 test infra** — single-file `extractInline` can't test cross-file; need `extractWorkspace(files[])` helper + required rails/django cases (before_action/skip/conditional/unresolvable).
22. **pragmatist-f5 · sizing** — T7 = XL (split T7a Java / T7b C#+PHP / T7c Python); carve express-centralized out of T6; pre-declare cut-to-follow-up candidates.
23. **pragmatist-f4 · false spine value** — T1 neuters imports while chain-classification only lands in T6 → spine demo produces all-PUBLIC. Patch: pull express middlewareChain classification into the spine.
24. **pragmatist-f7-adjacent · machine evidence packaging** — T13(b) depends on JS machine-evidence buried in T10; move to T6/spine; chain-name INTERNAL patterns may suffice.
25. **skeptic-f9 + pragmatist-f8 · ctx map too thin** — `Map<path, classification[]>` can't serve T5's chains; carry `{classification, middlewareChain, authMechanism}`.

## P2 — Quality Gaps (31, abridged — full detail in persona outputs)
- Legacy atom/semgrep_taint rows: scope the no_flows worst-case change to `reachability_source='taint_engine'` (skeptic-f5).
- T4 merge matrix unenumerated — esp. the AI-absent mainline (filter-disengaged) config (test-strategy-f5); T5 untested + fp-filter suite absent from preflight (f6); T13(b) needs the 8-flow expected-class table + byte-wise synth diff (f7); dogfood control not executable (f8, worker-pipeline-f9); snapshot re-baseline needs pre-declared expected diffs — CLAUDE.md forbids touching fixtures/test-* so the dangerous direction is barely exercised there (f4).
- postProcess contract underspecification (architect-f4); frontend must not hand-parse tags — vocabulary drift precedent (architect-f6); T5 anchoring — feed the chain, not our class verdict (pragmatist-f3); postProcess-vs-named-pass simplification (pragmatist-f2).
- NestJS guard-NAME matching (ThrottlerGuard fixture) (edge-case-f9); fastify plugin encapsulation scoping (f10); Laravel `withoutMiddleware`/Symfony `PUBLIC_ACCESS`/pattern-based override matcher (f11); sinatra path-scoped filters (f12); svix send-vs-verify shape + `/webhook`-route-name never internal (f13); koa-jwt `.unless()` → not covering (f14).
- Rocket/warp name-based idioms deferred (scope-cutter-f3); express mount-graph inheritance deferred with `-mounted-router` fixture (f4); Rails bounded to literal `application_controller.rb` path (f5); tornado same-file only (f6).
- ctx build order before DB write; verified no step-resume → ctx-only retry-safe (worker-pipeline-f5); express top-level-order semantics (f6); per-step perf methodology (f7); sync-loop yielding (f8).
- Evidence string silently cut vs brief's "Authenticated · requireAuth" promise — record or restore (opportunity-scout-f1, architect-f7); corpus-diff class-distribution mode (opportunity-scout-f2).

## P3 — Nits & Opportunities (12)
- Attack-surface log line to extraction_logs (o-s f3) · `x-deptex-classification` vendor extension (f4) · policy-engine exposure of entry_point_classification (f5, one-line select) · Aegis brief line (f6) · alias-resolved decorator matching (edge-case-f15) · dogfood expected.yaml explicit out-of-scope (scope-cutter-f7) · unknown-middleware + OFFLINE_WORKER required test cases (test-strategy-f9) · machine-evidence JS placement (pragmatist-f7) · shared plumb type (f8).

## Findings by Axis
| Axis | Count | Highest | Personas |
|---|---|---|---|
| Join soundness/membership/keying | 8 | P0 | edge-case, skeptic, pragmatist, architect, worker-pipeline |
| Validation/CI vacuity | 9 | P0 | test-strategy, skeptic, opportunity-scout |
| Evidence-rule holes (wrongful demote) | 12 | P1 | edge-case, skeptic, scope-cutter |
| Merge/EPD semantics | 5 | P1 | skeptic, architect, scope-cutter, test-strategy |
| Pipeline integrity (hook/perf/isolation) | 7 | P1 | worker-pipeline, architect, pragmatist |
| Task ordering/sizing | 5 | P1 | pragmatist, architect |
| Consumer corrections (DAST) | 2 | P1 | skeptic, opportunity-scout |
| Opportunities | 8 | P2 | opportunity-scout, architect |

## Persona Coverage Map
| Persona | R1 findings | Vote |
|---|---|---|
| skeptic | 9 | REVISE |
| pragmatist | 8 | REVISE |
| scope-cutter | 7 | REVISE |
| architect | 7 | REVISE |
| test-strategy-auditor | 9 | REWORK |
| opportunity-scout | 6 | READY |
| worker-pipeline-auditor | 9 | REVISE |
| edge-case-hunter | 15 | REWORK |

## Recommended Next Step
REWORK per the verdict rule (2 standing P0s + 2 REWORK votes) — but the panel is explicit that the **direction is confirmed** and every finding has a bounded patch. Rewrite the plan (v2) around: (1) redesigned join semantics (handler-identity aware, terminal-routes-only membership, UNKNOWN=public, detector-flows excluded, matched-evidence-only merge votes, suppressed excluded), (2) a redesigned T13 with a class-aware corpus diff + CI-wired aggregate runner + filter-engaged scan + the 8-flow expected table, (3) the hook as T1 shared infra with banked authFacts + failure isolation + usage-extraction perf gate, (4) the evidence-rule hardening batch (optional-auth vetoes, SpEL/DRF/Rails/express-use constraints, nextjs/aiohttp cuts). Then optionally re-run `/review-plan entry-point-auth` (lean) before `/implement`.
