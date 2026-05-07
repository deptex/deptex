# Malicious Packages v2 — Feature Brief

## Problem Statement

v1 (PR #20, merged 2026-04-30) put Deptex at **table-stakes** on malicious-package detection — OSV+GHSA feed lookup, GuardDog source-code scan, AI-explained findings, per-finding evidence, soft-fail pipeline. But Socket and Endor have moved on: both ship reachability-filtered malicious findings, Socket has capability detection across 70+ signals, Endor flags account-takeover patterns, and the Shai-Hulud worm (Sep 2025) made postinstall maintainer-signal triage urgent rather than nice-to-have. v2 closes that frontier-parity gap, finishes the v1 testing-pass loose ends, and broadens feed coverage. Quarantine Agent (autonomous PR removal) and pre-merge PR gating both remain whitespace differentiators but are explicitly deferred to later features so v2 stays a focused parity ship.

## Current State in Deptex

**Shipped in v1 (referenced surfaces):**
- `backend/database/malicious_packages_v1.sql` — `known_malicious_packages`, `package_security_cache`, `project_malicious_findings`, `malicious_feed_sync_runs`, `recompute_dependency_is_malicious` RPC, `insert_malicious_findings_with_recompute` RPC.
- `backend/database/malicious_packages_v1_unique_per_pkg.sql` — natural key widened to `(source, source_id, package_name, version, ecosystem) NULLS NOT DISTINCT`.
- `backend/src/lib/malicious/{ecosystem,explain,feed-sync,severity,staleness-watchdog,types}.ts`.
- `backend/src/routes/malicious.ts` — finding list/detail/PATCH/explain + internal feed-sync + watchdog routes.
- `backend/depscanner/src/malicious-scan.ts` and `backend/depscanner/src/malicious/guarddog.ts`.
- `frontend/src/components/security/MaliciousFindingCard.tsx`.

**Gaps still owed (Tier A from v1 testing pass):**
- `vulnerableVersionRange` parser — v1 collapses GHSA ranges (`= 2.10.1`, `>= 0`, `< 2.0.0`) to `version=null`, so `tanstack@1.0.0` (clean) gets flagged because `tanstack@2.0.7` (malicious) was ingested with `version=null`.
- `MaliciousFindingCard` hardcodes `canManage={true}` — non-managers see Suppress/Accept-Risk buttons that 403.
- Browser-side smoke + AI Explain end-to-end never run.
- Full extraction never run against `deptex-test-npm`.
- Org-wide allowlist not implemented (`project_policy_exceptions` extension planned).

**Frontier features not yet built:**
- Reachability filter on malicious findings (Phase 6 cross-file taint engine merged 2026-04-30, unblocked).
- Per-package capability detection (Socket-style capability tags).
- Maintainer / account-takeover signals (Shai-Hulud-class detection).

**Ops gaps:**
- GHSA page cap of 5000 silently misses PyPI/Maven malware further back in DESC order.
- `pip3 install --no-binary=:all:` fails for wheels-only packages (numpy, pillow, lxml) — worker silently skips.
- `tar -tzvf` is locale-dependent and breaks on filenames with whitespace.
- `package_security_cache` has no retention policy; will grow unbounded.

## Competitive Landscape (2026-Q2 verified)

### Socket
- **Capability detection:** explicit branding for "what the package CAN do" — 70+ signals across static + metadata + maintainer behavior.
- **Reachability:** added "Advanced reachability analysis" since the original v1 research; now both Socket and Endor ship reachability-filtered findings.
- **Recent catch:** PyPI litellm malware (March 2026), detected within minutes of publication.
- **Static today, dynamic "soon"** — sandboxed dynamic analysis still on the roadmap.
- **Source:** [socket.dev/features](https://socket.dev/features), [docs.socket.dev/docs/faq](https://docs.socket.dev/docs/faq).

### Endor Labs
- **Acquired Autonomous Plane** (Feb 2026) — full-stack reachability across applications + container images.
- **150+ signals:** banned authors, compromised domains, pre/post-install scripts running `curl/wget` to suspicious URLs, phone-home, DNS-info grabs, stealthy minimal file trees, HTTPS exfiltration.
- **Detailed malware reasoning** + warnings before malicious packages disappear from registries.
- **Headline:** "filters out up to 95% of scanner noise" via reachability.
- **Source:** [endorlabs.com/learn/malicious-package-detection](https://www.endorlabs.com/learn/malicious-package-detection), [docs.endorlabs.com/scan/malware](https://docs.endorlabs.com/scan/malware/).

### Aikido Safe Chain
- **200k+ weekly downloads** — install-time blocking is mainstream now.
- **Default 48-hour minimum package age** — packages younger than 48h get flagged by default.
- **Supports:** npm/yarn/pnpm/npx/pnpx/bun/bunx/pip/uv/poetry/pipx.
- **Aikido Intel:** AGPL-licensed live malicious feed; consumable by any third party.
- **Source:** [github.com/AikidoSec/safe-chain](https://github.com/AikidoSec/safe-chain), [aikido.dev/safe-chain](https://www.aikido.dev/safe-chain), [intel.aikido.dev/malware](https://intel.aikido.dev/malware).

### Shai-Hulud worm (Sep 2025) — context
- Self-replicating worm using postinstall scripts; compromised 500+ npm packages.
- Validated maintainer/account-takeover signal triage as urgent, not nice-to-have.
- **Source:** [cisa.gov — Widespread Supply Chain Compromise Impacting npm Ecosystem](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem).

### OSSF malicious-packages + Datadog dataset
- **OSSF:** github.com/ossf/malicious-packages — OSV-format, ~10,785 commits. Already an upstream of OSV.dev; direct ingestion is mostly duplicative.
- **Datadog dataset:** 26,123 confirmed malicious packages, GuardDog-shaped detections.
- **Source:** [github.com/ossf/malicious-packages](https://github.com/ossf/malicious-packages), [github.com/DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset).

## Landscape Synthesis

**Table-stakes today:** OSV/GHSA feed lookup, install-script behavior detection, typosquat detection, network exfil detection, obfuscation detection, per-finding severity + evidence + ignore/accept flow, PR gate or CI check.

**Frontier (multiple vendors):** reachability-filtered findings (Socket + Endor), capability detection (Socket signature), maintainer/account-takeover signals (Endor headline), install-time blocking (Aikido + Datadog scfw + Sonatype).

**Whitespace (uncontested):** open-core/self-host malicious detection, Aegis-style autonomous remediation, per-line AI annotations, cross-engine *function-level* reachability of malicious behavior, composable capability+age+maintainer policies, BYOK AI for novel-malware classification.

**Deptex position after v2:** at parity with Socket/Endor on detection axis (reachability + capability + maintainer signals all shipped), still uncontested on open-core posture, and stacked with Phase 6 reachability + flow builder + Aegis ready for a v3 quarantine pass.

**Feasibility verdict:** every locked v2 feature is incremental on existing primitives — Phase 6 reachability for the filter, tree-sitter for capability detection, registry APIs for maintainer signals, existing `package_security_cache` patterns for capability storage. Highest-risk item is capability detection across 8 languages with 15+ tags — known-hard problems (dynamic dispatch, obfuscated `eval`) will produce false negatives, but that's true for every competitor's static analysis too. Sources cited above.

## User Stories

- As a **security engineer**, I want malicious findings tagged with reachability so I can ignore findings on imported-but-unused malicious code.
- As a **developer**, I want per-package capability tags ("this package: spawns processes, makes network calls, reads env") so I can sanity-check what a new dep is allowed to do.
- As a **security engineer**, I want maintainer-signal alerts when a package's maintainer changes/email-changes/account-is-brand-new so account-takeover attacks (Shai-Hulud) get triaged before the malicious version ships.
- As an **org admin**, I want an org-wide allowlist for malicious-flagged packages we've vetted (e.g. red-team tooling) so they stop firing across every project.
- As a **developer**, I want `vulnerableVersionRange` to be respected so a fixed version doesn't get flagged because a different version was malicious.

## Locked Scope Decisions

1. **v2 = Socket-frontier parity, no Quarantine Agent.** Quarantine Agent (autonomous PR removal) defers to v3 to keep v2 a focused 'we caught up to Socket' moment. *Reason: faster ship, cleaner narrative, Quarantine is a true differentiator that earns its own feature pass.*
2. **Pre-merge PR gate is OUT of scope** — gets its own future feature folding extraction-worker + Aegis PR gating signals. *Reason: user flagged it should be its own pass; cross-cuts non-malicious signals too.*
3. **Tier A v1 gaps fold into v2 milestone 0**, not a separate v1.1 PR. *Reason: single PR shape matches v1; cleanest history.*
4. **Reachability filter granularity = package-level + function-level tiered.** Output: `reachability_level ∈ {unimported, imported_unused, module, function, data_flow}`. *Reason: matches Endor's tiered output; cheap early-exit on unimported saves Phase 6 cost on bulk feed-flagged matches.*
5. **Reachability runs synchronously in the malicious-scan pipeline step**, not async. *Reason: simpler data flow (no second-pass update path, no UI 'pending' state). Accepted ~1-8s typical extraction-time cost; flagged as a watchpoint.*
6. **Capability data lives in a new `package_capabilities` table** (per-(package, version, ecosystem) row, one boolean per capability tag, global cache). *Reason: easier to index for policy composition than JSONB; capabilities aren't findings so don't reuse `project_malicious_findings`.*
7. **Capability detection scope: match Socket's full ~15-tag set** (spawns_processes, network_io, reads_env, filesystem_write, eval_dynamic, clipboard, crypto_mining, native_binary_load, child_process_specific, websocket, iframe, telemetry, encrypted_payload, install_script, dns_query — exact list to be locked at /plan-feature). *Reason: aim-high direction; deterministic implementation keeps cost manageable.*
8. **Capability implementation: tree-sitter only, deterministic.** No AI fallback. *Reason: same 8 languages as Phase 6 taint engine, free, repeatable. Misses obfuscated capability use — same blind spot GuardDog source rules already accept.*
9. **Capability scan runs in the depscanner pipeline alongside GuardDog**, soft-fail per package, mirrors v1's `scan_status ∈ {complete, partial, failed}` pattern. *Reason: reuses tarball-cache infra; cache-hit on second viewer; consistent failure UX.*
10. **Maintainer signals use registry metadata only** (no OSSF Scorecard cross-reference). Computed signals: brand-new-account (<30d), maintainer-changed-in-last-30d, email-changed, signing-setup-changed. *Reason: free, fast, covers the Shai-Hulud-class signals; OSSF Scorecard adds patchy long-tail coverage at meaningful ingest cost.*
11. **Maintainer signals surface as `project_malicious_findings` with `scanner='maintainer'`.** *Reason (decided by Claude): reuses the entire suppress/accept-risk/Explain plumbing for free; matches how account-takeover signals are actually actionable for users.*
12. **Capability tags surface in the existing `PackageOverview` drawer**, not a dedicated tab and not on `MaliciousFindingCard`. v2 milestone 1b includes ~1 day of work to wire the drawer into the security tab — currently the tab uses inline row expansion (`VulnerabilityExpandableTable.tsx:682` renders `MaliciousFindingCard` inline) and `PackageOverview` is dependencies-page-only. M1b adds: clicking the package name in a finding row opens the drawer (which already shows is_malicious + vulns + maintainer + health), and capability tags drop in as a new section. *Reason: reuses the polished drawer instead of building a parallel UI; matches user-stated preference; capabilities aren't findings so don't compete for finding-card space.*
13. **Reachability surfaces as a badge on `MaliciousFindingCard`** (next to severity + scanner badges) + filter pill at top of Malicious tab + tooltip explaining the level. *Reason: mirrors how vulnerability findings already surface reachability post-Phase 4; consistent UX.*
14. **Policy code editor exposure of capabilities + maintainer signals deferred to a future PR.** *Reason: locks in v2 as 'detection + display' before policy composition; lets us test capability quality before exposing to org policies.*
15. **Feed sources expand to OSV + GHSA + OSSF malicious-packages** (CC-BY-4.0, license-clean). Aikido Intel **dropped from v2** to avoid AGPL isolation work; promoted to Tier D backlog for a future dedicated evaluation. *Reason: maximum-coverage instinct re-evaluated against the cost of AGPL isolation (~3-4 days, ongoing license-boundary discipline). OSSF is duplicative with OSV upstream but the marginal ingest is cheap and license-clean. Aikido revisited later only if production data shows a real coverage gap.*
16. **Hot rollout, no feature flag.** v1 already in main; v2 adds incremental tools to the same surface. *Reason: flag adds complexity for no risk-reduction benefit when the surface is already live.*
17. **Single PR for v2.** Matches v1's shape (15 commits, one PR). *Reason: reviewable at this size; cleanest narrative.*
18. **Tier C ops hardening folds in:** larger GHSA page cap, retention pruner cron, pip3 wheel fallback, tar parser robustness. *Reason: most touch the same surfaces v2 changes (cache schema, feed sync, depscanner pipeline); economical to bundle.*

## Data Model

### New tables
- `package_capabilities` — `(package_name, version, ecosystem)` natural key with boolean column per capability tag + `scanner_version` + `scanned_at`. Global cache like `package_security_cache`. Indexed for policy composition (future use).

### Schema changes
- `project_malicious_findings` — add `reachability_level text NULL CHECK (reachability_level IN ('unimported','imported_unused','module','function','data_flow'))` + `reachability_computed_at timestamptz NULL`.
- `project_malicious_findings.scanner` — relax CHECK to allow `'maintainer'` in addition to `'feed','guarddog'`.
- `project_policy_exceptions` — extend to malicious-finding allowlist (per-org pre-approval of specific malicious-flagged packages).

### New RPCs
- Reachability bulk update: backend writes findings, then invokes a single RPC to set `reachability_level` for all findings in a run (avoids N supabase round-trips).

### Migration ordering
- New migrations follow filename-sorted convention. Schema dump (`backend/database/schema.sql`) refreshed via `cd backend/depscanner && npm run schema:dump` in same PR — CI fails otherwise.

## API Endpoints

| Method | Route | Auth | Permission | Description |
|--------|-------|------|------------|-------------|
| GET | `/api/organizations/:id/projects/:projectId/malicious-findings` | authenticateUser | checkProjectAccess | Existing — extends response with `reachability_level`. |
| GET | `/api/organizations/:id/projects/:projectId/packages/:packageName/capabilities` | authenticateUser | checkProjectAccess | New — returns capability tags + scanner_version + scanned_at for a package version. Used by PackageOverview drawer. |
| POST | `/api/organizations/:id/malicious-allowlist` | authenticateUser | manage_organization_settings | New — add an org-wide allowlist entry. |
| DELETE | `/api/organizations/:id/malicious-allowlist/:entryId` | authenticateUser | manage_organization_settings | New — remove an org-wide allowlist entry. |
| GET | `/api/organizations/:id/malicious-allowlist` | authenticateUser | checkProjectAccess (read) / manage_organization_settings (mutate) | New — list current allowlist entries. |
| POST | `/api/internal/malicious/feed-sync/:source` | INTERNAL_API_KEY | n/a | Existing — extended to support `:source ∈ {osv, ghsa, ossf, aikido}`. |

No new RBAC permissions. Existing `manage_organization_settings` covers allowlist; `checkProjectAccess` + `checkProjectManagePermission` cover finding mutations.

## Frontend Surface

### Security tab (`/projects/:id/security`)
- **Reachability filter pill** at top of Malicious findings list. Values: All / Unreachable / Imported / Module / Function / Data flow.
- **Reachability badge** on `MaliciousFindingCard` next to severity + scanner badges. Tooltip explains the level + cites the source file/symbol if function-level.
- **Maintainer-signal findings** render through the same `MaliciousFindingCard`, with `scanner='maintainer'` displayed as a new scanner badge ("Maintainer signal").
- **`canManage` permission wiring** (Tier A) — drives the disabled state of Suppress / Accept-Risk buttons.

### PackageOverview drawer (existing, on dependencies page + security tab)
- **Capability tags** render as a labeled tag-cloud section in the drawer. Tags use distinct color tokens for high-signal (eval, network, spawn) vs low-signal (telemetry, clipboard).
- **`scanner_version` and `scanned_at`** rendered as small caption under tags.

### Org settings → Security
- **Malicious-finding allowlist** management UI. Table of (package_name, version_range, ecosystem, reason, added_by, added_at). Add / remove entries.

## User Flows

### Flow 1: Developer triages a new malicious finding
1. Extraction completes → finding lands with `reachability_level = function`.
2. Developer opens security tab → sees finding badged "Function-reachable" with severity high.
3. Filters by reachability=function to focus on actionable findings.
4. Clicks finding → drawer opens with capability tags ("network_io, eval_dynamic"), AI Explain narrative, and source-file annotation.
5. Decides to remove the dep (no Quarantine Agent in v2 — manual fix).

### Flow 2: Org-wide allowlist
1. Security engineer identifies a flagged-but-vetted package (red-team tooling, trusted internal pkg).
2. Goes to Org Settings → Security → Malicious allowlist.
3. Adds entry (package_name, version_range, ecosystem, reason).
4. On next extraction across all org projects, matching findings are auto-suppressed with `suppressed_reason` referencing the allowlist entry.

### Flow 3: Maintainer-signal account-takeover catch
1. Feed-sync runs → no advisories yet for `popular-pkg@2.5.0`.
2. Capability scan runs → finds eval_dynamic + network_io (existing in older versions, no anomaly).
3. Maintainer-signal scan runs → maintainer email changed 2 days ago AND new postinstall script.
4. Composite signal emits a `project_malicious_findings` row with `scanner='maintainer'`, severity=critical, message="Maintainer email changed and postinstall added since previous version — possible account takeover".
5. Developer sees high-severity finding before the malicious release becomes a confirmed advisory.

## Edge Cases & Failure-Mode Policy

- **Capability scan per-package failure** — soft-fail; row not written; pipeline continues. Aggregate `scan_status ∈ {complete, partial, failed}` mirrors v1's malicious-scan model.
- **Reachability stitch fails on a finding** — `reachability_level=null` left on row; UI renders "reachability unknown" badge; doesn't block extraction completion.
- **Aikido Intel ingest fails** (license-isolated process crashes) — staleness watchdog fires; OSV+GHSA+OSSF coverage continues.
- **`vulnerableVersionRange` parser doesn't recognize a range** — fall back to `version=null` (current v1 behavior); log warning; don't crash sync.
- **Maintainer-signal false positives** — Suppress/Accept-Risk plumbing handles the audit trail. Future iteration: heuristic to auto-suppress on legitimate ownership transfers.
- **Empty-state for capabilities** (package not yet scanned) — drawer shows "Capability scan pending" with `scanned_at=null`.
- **Empty-state for reachability** — finding badge shows "Reachability unknown" until backend updates.

## Non-Functional Requirements

- **Capability scan p95 latency budget per (package, version):** 1.5s tree-sitter pass on a typical package (≤ 50 source files, ≤ 10MB unpacked). Cache-hit on second viewer is O(1) DB lookup.
- **Reachability stitch p95 per finding:** ≤ 800ms on a project with ≤ 5000 cross-file edges. Worst-case repos may hit 2s+ — flagged for measurement during /implement.
- **Extraction-time cost ceiling:** total extra extraction time from v2 (capabilities + reachability) ≤ 60s on a 1500-package npm tree. If exceeded, fall back to async reachability path (revisit decision 5).
- **Feed-sync entries cap:** GHSA raised to 50k or per-ecosystem chunked; OSV `all.zip` per-ecosystem already streams.
- **Cache retention:** `package_security_cache` and `package_capabilities` retention pruner drops entries older than 180 days unscanned (configurable).
- **Aikido Intel deferred** to Tier D — v2 stays license-clean (OSV + GHSA + OSSF only).

## RBAC Requirements

- **No new permissions.** Allowlist mutations gate on existing `manage_organization_settings`. Finding mutations on existing `checkProjectManagePermission`. Reads on existing `checkProjectAccess`. Internal feed-sync routes on existing `INTERNAL_API_KEY`.
- **`canManage` permission wiring on `MaliciousFindingCard`** (Tier A) — uses existing `checkProjectManagePermission` from server-side context propagated via the existing org permissions API. No new endpoint.

## Dependencies

**Hard prereqs (already merged):**
- v1 malicious-packages (PR #20, `69e9098`).
- Phase 6 cross-file taint engine (PR #19, `142b495`) — provides reachability stitch primitives.
- Aegis Fix Agent (PR #17, merged 2026-04-29) — AI Explain reuses BYOK provider abstraction + AI usage logging.

**Soft prereqs (helpful, not blocking):**
- Flow builder (in flight on `worktree-flow-builder`) — no policy integration in v2 but capabilities will eventually compose into flow-builder rules. Don't conflict.
- Org graph multiplayer (in flight) — no overlap; just avoid pulling in churning files in the security tab area.

## Success Criteria

- All Tier A gaps closed: `vulnerableVersionRange` parser produces version-aware feed lookups, `canManage` wiring 403-prevents non-managers from clicking Suppress/Accept-Risk, full extraction against `deptex-test-npm` passes, org allowlist UI adds/removes entries, browser smoke + AI Explain end-to-end runs against real GHSA hits.
- Reachability filter working end-to-end on a real malicious finding: badge renders, filter pill filters, tooltip explains, at least `module`/`function`/`data_flow` levels observable in production data.
- Capability tags rendering in the `PackageOverview` drawer for at least 3 real packages from the deptex-test-npm dependency tree.
- Maintainer-signal findings firing on a synthetic 'recently published by new account' test package (committed as part of the smoke test, not real-world).
- v2 single PR merges with all jest+PGLite green; schema dump refreshed; no Phase 6 reachability regressions.
- Extraction-time cost hit on the 1500-package test tree: ≤ 60s total extra (measured + reported in PR description).

## Open Questions

Both prior `[Blocks /plan-feature]` items were resolved in the brainstorm follow-up:
- **Resolved:** Security tab does NOT currently use `PackageOverview` (it uses inline expansion via `VulnerabilityExpandableTable.tsx:682`). M1b includes ~1 day of drawer-integration work — see decision 12.
- **Resolved:** Aikido Intel dropped from v2; OSSF only — see decision 15.

Remaining items below are `/implement`-time refinements only:

- **[Defer to /implement] Capability detection on transitive deps — scan all deps or direct only?** Direct only saves 80%+ of capability scan cost on typical npm trees but loses transitive-package signals. Default position: scan all because capabilities are also used for transitive-import policies, but /implement validates with a measurement.
- **[Defer to /implement] Which exact ~15 capability tags ship in v1?** Provisional list in scope decision 7. /plan-feature locks the final set after a brief audit of GuardDog's existing pattern coverage so we don't duplicate.
- **[Defer to /implement] vulnerableVersionRange parser — npm-specific or shared library?** GHSA emits ranges in semver-ish dialect for npm but PEP 440 for PyPI, etc. Initial pragmatic answer: per-ecosystem parser modules, share an interface.
- **[Informational] Capability detection blind spot for obfuscated `eval`** — accepted in scope decision 8 but worth re-evaluating after v2 ships if production data shows a meaningful FN rate.

## Recommended Next Step

All blockers resolved — ready for `/plan-feature`. Milestone breakdown:

- **Milestone 0:** Tier A v1 finish (vulnerableVersionRange, canManage, allowlist, browser smoke, full extraction test).
- **Milestone 1a:** Reachability filter (schema + sync invocation + UI badge/filter/tooltip).
- **Milestone 1b:** Capability detection (table + tree-sitter pipeline step + wire `PackageOverview` drawer into security tab + render tags in drawer).
- **Milestone 1c:** Maintainer signals (registry pull + finding emission + reuses existing UI).
- **Milestone 2:** Feed expansion — OSSF malicious-packages only (license-clean).
- **Milestone 3:** Ops hardening (GHSA cap, retention pruner, pip3 wheel fallback, tar parser).

After /plan-feature, `/review-plan` is recommended (six load-bearing personas + capability-detection-feasibility-auditor + reachability-engine-fit-auditor) before kicking off `/create-worktree malicious-packages-v2` and `/implement`.
