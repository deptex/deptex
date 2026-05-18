# Malicious-Packages Future Plan

**Status:** Plan-only. No code changes proposed in this document — every PR-class change below is a separate ship that follows Section 9's roadmap.
**Audience:** Henry. Decisions queued in Section 10.
**Worktree:** `C:\Coding\Deptex\.claude\worktrees\depscanner-hardening\`
**Owning thesis:** Per `docs/depscanner-hardening-report.md:394-424` and the Day 1 Wave 1 #7 finding (`.cursor/plans/depscanner-hardening-DAILY-LOG.md:59`), **we are an SCA tool that runs GuardDog post-clone, not a real-time malware detector.** Socket flags Axios in 6 minutes; Aikido medians 5min; we wait for SBOM ingestion. Two halves of the gap matter: (a) **time-to-detection** vs Socket / Aikido / Phylum (P0 — table stakes once a customer compares dashboards); (b) **reachability-aware verdicts** (P1 — the wedge nobody else ships — Socket's reachability is shallow, Endor doesn't pivot reachability onto malicious-pkg verdicts). The plan below pursues both, leaning on the Phase 6 cross-file taint engine + the existing `project_malicious_findings` schema for the wedge while building a real-time publish-feed listener for the floor.

---

## Section 0 — Grounding (every reference grep-verified 2026-05-09)

| Claim | File:line |
|---|---|
| Hardening report identifies real-time publish-feed ingestion as #1 gap and reachability-aware verdicts as Wedge 1 | `docs/depscanner-hardening-report.md:399,412` |
| Day 1 Wave 1 #7 finding: "we are an SCA tool that runs GuardDog post-clone, not a real-time malware detector" | `.cursor/plans/depscanner-hardening-DAILY-LOG.md:59` |
| Malicious v2 IMPLEMENTED — 5 milestones + 2 e2e bug fixes; tip `1861b2c` on `worktree-malicious-packages-v2`, not yet merged into main | `docs/depscanner-hardening-report.md:396`; memory `malicious_packages_state.md` |
| `project_malicious_findings` schema (project_id, organization_id, extraction_run_id, project_dependency_id, dependency_id, rule_id, scanner, severity, message, depscore, suppressed, risk_accepted, reachability_level, reachability_details jsonb) | `backend/database/schema.sql:1216-1240` |
| `project_malicious_findings` reachability CHECK: `unimported / imported_unused / module / function` | `backend/database/schema.sql:6130` |
| `project_malicious_findings` scanner CHECK: `feed / guarddog / maintainer` | `backend/database/schema.sql:6131` |
| `known_malicious_packages` cache table — global, ecosystem CHECK across 10 canonical ecosystems, source CHECK = `osv / ghsa` | `backend/database/schema.sql:358-370,6078-6079` |
| `malicious_feed_sync_runs` — feed-sync state table, source CHECK = `osv / ghsa`, state CHECK = `pending/running/completed/failed/dlq` | `backend/database/schema.sql:384-394,6080-6081` |
| `organization_malicious_allowlist` — per-org override surface with revoke audit trail | `backend/database/schema.sql:532, 6004, 6092` |
| Pipeline step entry: `doMaliciousScan(ctx)` — soft-fail, `runStage` wrapper, severity `warn`, runs after tree-sitter | `depscanner/src/pipeline-steps/malicious.ts:18-80` |
| Worker scan loop — feed lookup → tarball download (zip-slip + decompression-bomb sandbox) → cached GuardDog → atomic `insert_malicious_findings_with_recompute` RPC | `depscanner/src/malicious-scan.ts:1-22` |
| Per-finding reachability resolver in worker (extractUsage → 4-level classification, no taint engine) | `depscanner/src/malicious/reachability.ts:1-40` |
| Maintainer-signal sync — npm + PyPI + RubyGems clients live; 7 stubbed ecosystems return null | `backend/src/lib/malicious/maintainer-signals.ts:1-30` |
| Feed-sync — OSV.dev + GHSA `MALWARE`-class advisories, daily QStash cron, `apply_malicious_allowlist` org-scoped suppression | `backend/src/lib/malicious/feed-sync.ts:1-37`; `backend/database/schema.sql:1977-2024` |
| Wave 1 (Day 3 evening) commit `42084c1` — heartbeat in-flight feed-sync runs + re-enabled strict types in routes | hardening daily log entry, marathon commit log |
| GuardDog version 2.9.0 wrapped with `--no-exec`, 60s timeout, 16MB buffer, venv binary validation, tarball name validation | `.cursor/plans/depscanner-hardening-DAILY-LOG.md:249` |
| Phase 6 cross-file taint engine (8-language) shipped + Phase 5 Autogrep generates per-org rules | `docs/depscanner-hardening-report.md:412,416`; memory `reachability_phase6_state.md` |
| GHSA GraphQL `ecosystem` arg lives on `securityVulnerabilities`, NOT `securityAdvisories` | memory `reference_ghsa_graphql_schema.md`; `.cursor/plans/depscanner-hardening-DAILY-LOG.md:249` |
| `package_security_cache` (scanner CHECK = `guarddog / ai_review`) — keyed (package, version, ecosystem, scanner) | `backend/database/schema.sql:6110` |
| Container OS-pkg layer (project_container_findings) is a SEPARATE surface from project_malicious_findings — no overlap | `backend/database/schema.sql:1216` (this table) vs IaC v2 plan |

**What does NOT exist today:**

- No real-time publish-feed listener for any registry. `feed-sync.ts` polls OSV / GHSA on a daily QStash cron; npm `_changes` / PyPI BigQuery / RubyGems events stream is greenfield.
- No `package_signals` (or similar) write surface for "this package was published <N hours ago" / "install-script-only-on-this-version" / "registry typosquat distance" — signals exist in code (`maintainer-signals.ts`) but nothing persists "first-N-hours" verdicts independent of org-scoped scans.
- No GitHub App `check_run` failing PRs that introduce a malicious-pkg dep. `pr_check_code` evaluates other policy code today (`backend/src/lib/policy-engine.ts`) but no surface ties it to `project_malicious_findings`.
- No "cooldown policy" surface. Endor / Bytesafe / JFrog all ship time-since-publish gating at install time; we have nothing.
- No public threat-feed surface (`deptex/malicious-packages` repo / OSV-format publication endpoint). Aikido publishes AGPL feed; Socket publishes via X; we are net consumer-only.
- No browser extension / IDE plugin. Socket Chrome ext annotates npmjs.com; we have nothing on the register-side surface.
- No reachability-flow joining for malicious findings. The `project_malicious_findings.reachability_level` column exists (`schema.sql:1237`) and is populated by per-package usage slices (`reachability.ts`), but it does NOT join the Phase 6 `project_reachable_flows` taint output — they're parallel surfaces. The wedge described in the hardening report (Wedge 1) requires a join layer that doesn't exist.
- No Aegis Fix Agent integration for malicious-pkg findings. Aegis can fix CVEs (`fix-worker/`); the trigger handler doesn't accept `malicious_finding_id` as a fix target.
- No investigation panel (analyst view: source map back to commit, scan run, file paths, transitive chain, time-of-first-appearance). The current frontend lists findings + their reachability_level; it does not surface where in the dep tree the malicious package entered the project, when, or by whose commit.

---

## Section 1 — Why this is the gap (4 bullets)

1. **Real-time detection is table-stakes once a buyer compares dashboards.** Socket / Aikido / Phylum print "we found the bad package N minutes after publish." We print "we found it on the next scan after CI runs." For dependency-bump-driven supply-chain attacks (the entire point of the post-2020 surge — npm `event-stream`, `ua-parser-js`, `colors`, `chalk`, `axios` campaigns), the gap between publish and lockfile-scan is the customer's actual exposure window. **Closing it is the cost of being on the shortlist.** Effort: medium. Risk: bounded — npm `_changes` is a public CouchDB feed, PyPI publishes RSS+BigQuery, RubyGems exposes events.
2. **Reachability-aware malicious-pkg verdicts are uncontested.** Per `docs/depscanner-hardening-report.md:412`: "Socket's reachability is shallow; Endor doesn't pivot reachability onto malicious-pkg verdicts." The Phase 6 taint engine + per-package source-slice scan + `project_reachable_flows` schema give us 90% of the engineering plumbing; the join layer doesn't exist yet. **Pitch writes itself: "Socket tells you 50 packages are compromised. We tell you which 3 actually expose your production app today."** This is the differentiator that survives a feature-list bake-off.
3. **The schema + worker plumbing are already in place.** `project_malicious_findings.reachability_level` already takes 4 values (`unimported / imported_unused / module / function`); `reachability_details` is a `jsonb`; the scanner CHECK already accepts `feed / guarddog / maintainer` and is trivial to extend. The fan-out cost of new signal types is one CHECK relaxation per type. **No new findings table needed for v1.**
4. **Aegis is a free moat multiplier.** A malicious-pkg verdict + reachable-flow + last-known-good version + Aegis-driven PR is one workflow our competitors structurally cannot ship — Socket / Endor / Phylum don't have a coding agent. Even if we shipped the real-time feed at parity (P0), the Aegis-driven autonomous remediation (P2) is a moat that compounds.

---

## Section 2 — Architecture (target end-state)

```
NEW: Real-time publish-feed ingestion (continuously running)
  ├─ npm: long-poll https://replicate.npmjs.com/_changes?since=<seq>&include_docs=true
  ├─ PyPI: poll https://pypi.org/rss/updates.xml + BigQuery (daily catch-up)
  ├─ RubyGems: poll https://rubygems.org/api/v1/activity/just_updated.json
  ├─ (Phase B) Maven: oss.sonatype.org RSS; NuGet: catalog feed; Cargo: crates.io API
  └─ Each new release event → enqueue to `package_release_events` (durable queue)
     └─ Lightweight scanner subscriber (Fly.io machine)
        ├─ tarball fetch (TarballCache reuse)
        ├─ GuardDog one-shot pass (existing scanner — no new code)
        ├─ heuristic suite (typosquat distance, install-script sniff, maintainer-age,
        │  network-call detection — see §6)
        └─ if any signal fires → upsert `package_malicious_signals`
           (independent of org scans; global cache; queryable)

EXISTING + ENRICHED: Per-org extraction-time scan (depscanner/src/pipeline-steps/malicious.ts)
  ├─ feed lookup (known_malicious_packages — UNCHANGED)
  ├─ NEW: package_malicious_signals lookup (DB-only, free, mirrors feed lookup)
  ├─ GuardDog (UNCHANGED — cached at package version level)
  ├─ NEW: cooldown-policy gate (per-org configurable; reads dependency.published_at)
  ├─ NEW: Phase-6 reachable-flow JOIN
  │   └─ for each malicious finding, query project_reachable_flows where
  │       sink_file_path matches one of the package's exported entrypoints
  │       (resolved via extractUsage import bindings)
  │   └─ write `reachability_details.flow_signature_hashes[]` and bump
  │      reachability_level to 'data_flow' or 'confirmed' when a flow lands
  └─ atomic insert via insert_malicious_findings_with_recompute (UNCHANGED)

NEW: GitHub App PR check (additive)
  └─ pr_check_code engine extended to read project_malicious_findings
     for changed deps; fail check_run when reachable + not on allowlist

NEW: Aegis Fix Agent integration
  └─ trigger_fix accepts malicious_finding_id; planner picks last-known-good
     version from known_malicious_packages.version_constraint; PR re-runs
     reachability; bot comment cites the reachable flow

NEW: Investigation panel (frontend)
  └─ For each finding: introduced-by commit (git blame on lockfile),
     transitive chain (project_dependency_edges), first-seen extraction_run_id,
     reachable flows from project_reachable_flows
```

**Two architectural notes:**

1. **The publish-feed listener does NOT replace per-extraction scans.** It writes to a global cache (`package_malicious_signals`) that the per-extraction scan reads. No org context flows through the listener; the listener is multi-tenant by absence — it sees only public registry data. This preserves the same multi-tenancy invariant `feed-sync.ts` enforces (`backend/src/lib/malicious/feed-sync.ts:14-17`). Per-org scanning still goes through `pipeline-steps/malicious.ts`; the listener just makes the cache hit-rate approach 100% within minutes of publish.
2. **Reachability join uses Phase 6 output, not a new pipeline.** The `project_reachable_flows` table already records `(source_file, sink_file, sink_line, flow_signature_hash)`. Mapping a malicious package to its sinks requires resolving the package's exported entry points to file paths via the existing `extractUsage` output (`depscanner/src/tree-sitter-extractor`). The join is a query, not a re-run.

---

## Section 3 — Data model

### 3.1 New tables

#### `package_release_events` (publish-feed work queue)

```sql
-- phaseXX_realtime_pkg_signals.sql (additive)
CREATE TABLE IF NOT EXISTS public.package_release_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  version TEXT NOT NULL,
  published_at TIMESTAMPTZ NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('npm_changes', 'pypi_rss', 'rubygems_activity', 'maven_rss', 'nuget_catalog', 'cargo_api')),
  source_seq TEXT,                             -- e.g. CouchDB seq id; nullable for sources without one
  state TEXT NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending', 'scanning', 'scanned', 'failed', 'dlq')),
  scanned_at TIMESTAMPTZ,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX package_release_events_dedup
  ON public.package_release_events (ecosystem, package_name, version);
CREATE INDEX idx_package_release_events_pending
  ON public.package_release_events (state, created_at)
  WHERE state IN ('pending', 'scanning');
```

#### `package_malicious_signals` (global per-(pkg, version) signal store)

```sql
CREATE TABLE IF NOT EXISTS public.package_malicious_signals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  version TEXT NOT NULL,
  signal_type TEXT NOT NULL
    CHECK (signal_type IN ('install_script', 'typosquat_candidate', 'unsigned_publish',
                           'low_account_age', 'network_call_in_install', 'unicode_homoglyph',
                           'cross_pkg_relationship', 'guarddog_finding', 'first_publish_window')),
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,    -- { "rule_id": "...", "evidence": [...] }
  scanner TEXT NOT NULL CHECK (scanner IN ('guarddog', 'heuristic', 'feed_correlator')),
  source_seq TEXT
);
CREATE INDEX idx_package_malicious_signals_lookup
  ON public.package_malicious_signals (package_name, ecosystem, version);
CREATE UNIQUE INDEX package_malicious_signals_natural_key
  ON public.package_malicious_signals (ecosystem, package_name, version, signal_type, scanner)
  NULLS NOT DISTINCT;
```

Multi-tenant invariant identical to `known_malicious_packages` — global, no org_id, public-data-only.

#### `organization_pkg_cooldown_settings` (per-org cooldown config)

```sql
CREATE TABLE IF NOT EXISTS public.organization_pkg_cooldown_settings (
  organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT false,
  cooldown_hours INTEGER NOT NULL DEFAULT 48 CHECK (cooldown_hours >= 0 AND cooldown_hours <= 720),
  enforcement_mode TEXT NOT NULL DEFAULT 'warn'
    CHECK (enforcement_mode IN ('off', 'warn', 'block')),
  applies_to_ecosystems TEXT[] NOT NULL DEFAULT ARRAY['npm','pypi','rubygems'],
  updated_at TIMESTAMPTZ DEFAULT now(),
  updated_by_id UUID REFERENCES auth.users(id) ON DELETE SET NULL
);
```

### 3.2 Additive columns on existing tables

```sql
-- project_malicious_findings: pivot to Phase-6-aware reachability
ALTER TABLE public.project_malicious_findings
  ADD COLUMN IF NOT EXISTS flow_signature_hashes TEXT[] NOT NULL DEFAULT '{}'::text[],
  ADD COLUMN IF NOT EXISTS reachability_source TEXT
    CHECK (reachability_source IN ('usage_slice', 'taint_engine', 'cooldown_policy', NULL));

-- Relax scanner CHECK to add new signal-derived scanners
-- existing: 'feed' / 'guarddog' / 'maintainer'
-- add:      'signal' (real-time signal-derived) / 'cooldown' (cooldown-policy-derived)
ALTER TABLE public.project_malicious_findings
  DROP CONSTRAINT project_malicious_findings_scanner_check,
  ADD CONSTRAINT project_malicious_findings_scanner_check
    CHECK (scanner IN ('feed', 'guarddog', 'maintainer', 'signal', 'cooldown'));

-- Relax reachability CHECK to mirror SCA's 5-tier vocabulary
-- existing: unimported / imported_unused / module / function
-- add:      data_flow / confirmed (Phase 6 taint engine)
ALTER TABLE public.project_malicious_findings
  DROP CONSTRAINT project_malicious_findings_reachability_chk,
  ADD CONSTRAINT project_malicious_findings_reachability_chk
    CHECK (reachability_level IS NULL OR reachability_level IN
      ('unimported', 'imported_unused', 'module', 'function', 'data_flow', 'confirmed'));
```

### 3.3 Investigation panel — read-side joins only, no schema

The investigation surface (PR 7) reuses existing tables; no new columns required:

| Field shown | Source |
|---|---|
| Introduced-by commit | `project_dependency_edges` join `extraction_runs.commit_sha`; first run where edge appeared |
| Transitive chain | `project_dependency_edges` recursive CTE from `project_dependency_id` |
| First-seen extraction run | `project_malicious_findings.extraction_run_id` (existing) |
| Reachable flows | `project_reachable_flows.flow_signature_hash` ∈ `flow_signature_hashes[]` |
| Time of first publish-feed signal | `package_malicious_signals.detected_at` (NEW) |
| Maintainer signals | `package_maintainer_snapshots` (existing v2 table) |

---

## Section 4 — Real-time publish-feed listener (P0 — closes Socket gap)

### 4.1 npm `_changes` long-poll

npm exposes a CouchDB `_changes` feed at `https://replicate.npmjs.com/_changes`. Each new package version emits a change document with `id`, `seq`, `doc` (the full package metadata). The listener:

```
loop:
  GET /_changes?feed=continuous&since=<last_seq>&include_docs=true&heartbeat=30000
  for each change line:
    parse doc → versions[].published_at
    for each new version published in last N seconds (usually 1):
      INSERT package_release_events (ecosystem='npm', name, version, published_at, source='npm_changes', source_seq=seq)
      ON CONFLICT (ecosystem, package_name, version) DO NOTHING
    persist last_seq to redis npm:changes:cursor
```

Operational mechanics:
- Single Fly.io machine, scale-1 (NOT scale-to-zero — this is a long-lived process).
- Heartbeat to Redis every 60s; recovery cron resumes from `npm:changes:cursor` if the process dies.
- Backpressure: if `package_release_events.state='pending'` count exceeds 10k, downgrade to PyPI/RubyGems-only sampling until drained.
- npm publishes ~500 versions/min steady-state; ~2-3k/min during NPM-incident bursts. Insert + dedup is cheap. The work is on the scanner side.

### 4.2 PyPI

PyPI does not expose a long-poll feed. Two complementary sources:
- RSS: `https://pypi.org/rss/updates.xml` (last 40 releases). Poll every 30s; same INSERT-on-conflict shape.
- BigQuery `bigquery-public-data.pypi.distribution_metadata` for catch-up (daily query for "anything we missed in the last 24h", capped at the last 6h to avoid re-ingesting).

### 4.3 RubyGems

`https://rubygems.org/api/v1/activity/just_updated.json` returns last 50 gem updates. Poll every 60s.

### 4.4 Phase B ecosystems

Maven Central RSS, NuGet catalog, Cargo registry-changes feed. Each is a separate listener module; ship after PR 1-3 prove the pattern.

### 4.5 Per-release scanner subscriber

A second Fly machine subscribes to `package_release_events.state='pending'` (claim via the same atomic-claim RPC pattern as `claim_scan_job`). For each event:

1. Tarball fetch (reuse `depscanner/src/malicious/tarball-cache.ts`).
2. GuardDog pass (reuse `runGuardDog` — `depscanner/src/malicious/guarddog.ts`).
3. Heuristic battery (§6).
4. Upsert findings into `package_malicious_signals`.
5. Mark event `scanned`.

**Time-to-detection budget:** publish → ingest event ≤30s; pending → claimed ≤10s; scan ≤120s; verdict-written-to-cache ≤180s p95. **Target: 3-min p95**, beating Aikido's 5-min median, approaching but not beating Socket's 6-min headline (Socket's number is for *Axios-class* events with a hot-cache; ours is steady-state).

---

## Section 5 — Reachability-aware verdicts (P1 — the wedge)

This is the differentiator. Per-extraction flow:

```
1. Existing per-extraction malicious-scan completes (pipeline-steps/malicious.ts).
   → produces N project_malicious_findings rows with reachability_level ∈
     {unimported, imported_unused, module, function} (today's resolver).

2. NEW post-scan join step (in pipeline-steps/malicious.ts, after insertFindingsBatch):
   FOR EACH finding WHERE reachability_level IN ('module', 'function'):
     a. Resolve the malicious package's exported file paths via extractUsage's
        ImportBinding[] table (already loaded).
     b. Query project_reachable_flows WHERE
          extraction_run_id = $current
          AND project_id = $current
          AND sink_file_path IN (those file paths).
     c. If any flow exists:
          UPDATE finding SET
            reachability_level = (data_flow if no sanitizer else confirmed),
            flow_signature_hashes = ARRAY[<matching flow signatures>],
            reachability_source = 'taint_engine'.
     d. If no flow but reachability_level was 'function':
          Keep current value; no downgrade.
```

**Why this works.** The Phase 6 engine emits one row per data path from a source to a sink. The malicious-pkg case treats *known-malicious imports* as sources by symmetry — but we don't need to re-run the engine. We're using its existing output (which catalogues every reachable sink for the project) and asking "did any of those sinks live in a malicious package's files?"

**Why this is the wedge.** Socket / Endor / Phylum stop at "this package is compromised." This says "this package is compromised AND your `payments/checkout.ts:42` HTTP handler can reach it via this 4-hop call chain." The pivot from "package-level red dot" to "actual production blast radius" is a story competitors structurally can't tell without a taint engine — and they'd have to rebuild the SCA layer to plug one in.

**Cost.** The join is one extra query per finding per extraction. For a typical project with 5-50 malicious findings, that's <100ms additional pipeline cost. Negligible.

---

## Section 6 — Heuristic surface beyond GuardDog

Five concrete heuristics, each shippable as one PR. All write to `package_malicious_signals` as `signal_type` rows. None replace GuardDog; all complement it.

| # | Heuristic | Detection logic | Effort | Cite |
|---|---|---|---|---|
| H1 | **Typosquat candidate** | Damerau-Levenshtein distance ≤2 from any package in top-10k popularity list (npm download-count, PyPI BigQuery rank). Emit on publish. | S | Socket's name-distance moat |
| H2 | **Install-script sniffer** | Parse `package.json.scripts.{preinstall,postinstall,install}` for: (a) any non-null value combined with `account_age_days < 30`; (b) presence of `curl`, `wget`, `eval`, `Function(`, `child_process`, `bash -c` tokens. PyPI: parse `setup.py` for `subprocess.*` / `os.system`. | S | already partially in `maintainer-signals.ts` |
| H3 | **Cross-package install relationship** | When package A's preinstall references package B by name, write a relationship row. If B is later flagged malicious, propagate to A. | M | first-seen relationship table |
| H4 | **Network-call detection in install hooks** | Static AST scan of preinstall/postinstall payloads for HTTP-call / DNS-resolve / exec patterns. Tree-sitter pass over the install script body. | M | reuses tree-sitter |
| H5 | **Unicode homoglyph + name confusable** | NFKC-normalize package name, compare against top-10k list. `reаct` (Cyrillic а) → `react`. | S | UTR #39 confusables |

PR 4-5 ship H1+H2 (cheapest, highest-signal). PR 6 ships H3-H5.

---

## Section 7 — Trust signals + provenance (P2 — Chainguard-tier positioning)

Surfaced as `signal_type` values in the same `package_malicious_signals` table — read at extraction time, decorated onto findings or surfaced in the UI as positive trust signals.

| Signal | Source |
|---|---|
| **npm provenance attestation** | npm's `dist.attestations` (Sigstore-signed SLSA attestation). Verify via `@sigstore/verify`. Surface on the dependency detail card as "build-attested." |
| **Sigstore-signed PyPI release** | PyPI's `provenance` API endpoint (rolled out 2024). |
| **OpenSSF Scorecard freshness** | Existing `OpenSSFScorecardFetcher` in `populate-dependencies` — extend to gate `Scorecard < 6` as a `low_trust_score` signal at extraction time. |
| **Maintainer 2FA enabled** | npm registry exposes `users[].npm_2fa` flag; PyPI exposes `2fa_required`. Cache + decorate. |
| **First publish from new account** | Already detectable via maintainer-signals account_age — surface as own signal_type. |

This is the *positive*-side trust ledger that complements the negative-side malicious signals. Each is its own small PR; bundle two per PR for batching.

---

## Section 8 — Active-defense posture (P2)

Once we have signals + reachability, the policy-engine layer can compose them into block / warn / allow decisions. Three concrete surfaces:

### 8.1 Cooldown policy (PR 8 — extends `pr_check_code`)

A new built-in policy primitive: `block deps published in last N hours`. Configurable via `organization_pkg_cooldown_settings` (§3.1). Enforcement:

- `enforcement_mode='off'`: column exists but no action.
- `enforcement_mode='warn'`: PR comment annotates "this dep was published 12h ago; cooldown=48h" but doesn't fail check.
- `enforcement_mode='block'`: GitHub App `check_run` fails until override added to `organization_malicious_allowlist`.

Reads `dependencies.published_at` (already populated by `populate-dependencies`).

### 8.2 Just-in-time scan-on-PR (PR 9)

When a PR introduces a new dep (delta on `project_dependency_edges`), trigger a synchronous scan of just the new packages BEFORE the PR check posts. Reuses the existing per-package scan path. Latency budget: 15s per package, max 10 packages parallel.

### 8.3 Signed allowlist + Aegis fix (PR 10)

When a malicious finding fires + reachable + the org has Aegis enabled, auto-trigger the fix planner with `malicious_finding_id`. Aegis picks last-known-good version (the highest version not in `known_malicious_packages` for that package) and opens a PR. Closes the loop.

---

## Section 9 — PR-by-PR roadmap

Eight PRs. Sequenced for risk + dependency. P0 first to close the Socket / Aikido detection-time gap; P1 second to ship the differentiator; P2 to compound.

| # | Tier | PR title | Effort | Depends on | Risk | Notes |
|---|---|---|---|---|---|---|
| 1 | **P0** | `feat(db): package_release_events + package_malicious_signals tables` | S (~0.5d) | nothing | Low | Two additive tables + indexes. Migration `phaseXX_realtime_pkg_signals.sql`. Run `cd depscanner && npm run schema:dump`. No code wired yet. |
| 2 | **P0** | `feat(depscanner): npm publish-feed listener` | M (~2-3d) | PR 1 | Med | Long-lived Fly machine subscribed to `replicate.npmjs.com/_changes`. Redis cursor + heartbeat. Insert into `package_release_events`. No scanner side yet. |
| 3 | **P0** | `feat(depscanner): per-release scanner subscriber + GuardDog one-shot` | M (~2-3d) | PR 2 | Med | Claim-job RPC for `package_release_events`. Reuses `runGuardDog` + `tarball-cache`. Writes `package_malicious_signals` with scanner='guarddog'. |
| 4 | **P0** | `feat(depscanner): heuristic suite phase 1 — typosquat (H1) + install-script sniffer (H2)` | M (~2d) | PR 1+3 | Low | Pure-function library. Top-10k popularity list bundled monthly. Writes `signal_type='typosquat_candidate'` / `'install_script'`. |
| 5 | **P0** | `feat(depscanner): pypi RSS + rubygems activity listeners` | S (~1d) | PR 2 (pattern) | Low | Same shape as PR 2; +120 LOC each. |
| 6 | **P1** | `feat(depscanner): reachability-flow JOIN onto project_malicious_findings` | M (~2d) | nothing pre-req on PR 1-5 (independent) | Med-High | THE WEDGE. Ships independently; query-only join in `pipeline-steps/malicious.ts` post-insert. Migration relaxes scanner + reachability CHECKs. Risk: false-positive flow matches when source-file mapping is fuzzy; mitigated by exact-path equality + ImportBinding resolution. |
| 7 | **P1** | `feat(frontend): malicious-pkg investigation panel` | M (~2-3d) | PR 6 | Low | Source-map back to introduced-by commit / transitive chain / reachable flows / first-seen extraction / time-of-first signal. Per-finding detail drawer. |
| 8 | **P2** | `feat: cooldown policy + GitHub App PR check + Aegis trigger integration` | L (~3-5d) | PR 1+6 | Med | Multi-surface: org settings UI, `pr_check_code` extension, GitHub App `check_run` shape, Aegis `trigger_fix` accepts `malicious_finding_id`. Big surface; consider splitting at review. |

**Total path to P0+P1 customer-visible:** PRs 1-7 = ~13-17 dev-days. PR 8 (P2) is independently shippable.

**Phase B (deferred — gated on signal):**
- H3-H5 heuristics (cross-pkg relationships, network-call AST, unicode homoglyphs)
- Maven / NuGet / Cargo listeners
- Trust-signal surfacing (npm provenance, sigstore, scorecard freshness)
- Public threat-feed publication (`deptex/malicious-packages` repo, OSV format)

---

## Section 10 — Open questions for Henry

### 10.1 Should the publish-feed listener live in depscanner or a new worker?

The depscanner is scale-to-zero; the listener is scale-1 (long-lived). Two options:
- **(a)** Add a new `mode=listener` flag to depscanner; the same image runs in two configurations on two Fly apps.
- **(b)** Spin up a dedicated `deptex-pkg-listener` Fly app (third worker, alongside depscanner + fix-worker).

**Recommend (b).** Cleaner ops boundary, separate logs, separate scaling. Deployment cost is one extra Fly app + secrets duplication; ~30min one-time setup.

### 10.2 Reachability source-file mapping — exact path or fuzzy?

PR 6's join needs to resolve "this finding is for package X" → "files contributed to the project by X." Two paths:
- **(a) Exact:** map via `extractUsage` ImportBinding's resolved file-paths (where the import's resolved entry came from `node_modules/X/...`). Deterministic but misses re-exports.
- **(b) Fuzzy:** any sink file under `node_modules/X/` regardless of which file imported it.

**Recommend (a) for v1**, expand to (b) only if false-negative rate is high in dogfood.

### 10.3 Cooldown default — opt-in or default-on?

Endor defaults cooldown ON; Bytesafe defaults OFF. Cooldown defaults `enabled=false` in §3.1. **Question:** flip default to `true` for new orgs after PR 8 ships? Trade-off: opt-in respects autonomy; default-on closes attack windows for the median customer.

Recommend **default-off** for now; revisit after one quarter of production data.

### 10.4 Should `package_malicious_signals` records expire?

A typosquat-candidate signal from 18 months ago might be stale (the legit package may have since been renamed or the typosquat removed). Two options:
- **(a)** Never expire; signals are evidence-of-fact at the time.
- **(b)** Expire after 90d unless re-confirmed.

**Recommend (a).** Customer can suppress per-finding via `organization_malicious_allowlist`. Expiring globals would lose forensic record.

### 10.5 GuardDog rerun on existing packages?

When GuardDog's rule corpus updates (~quarterly), do we re-scan packages we've already scanned? `package_security_cache` is keyed (pkg, version, ecosystem, scanner) — adding a `scanner_version` column would let us bust on rule updates. **Question:** add `scanner_version` to `package_security_cache` cache key + auto-rescan on bump?

Recommend **yes**, but defer to a Phase B follow-up after PR 1-7 ship. Rerun cost is bounded — at 100 versions/sec from steady state and current ~1M-package universe, full re-scan is a 3-day burn.

### 10.6 Public threat feed — when to ship?

Aikido publishes AGPL feed; Socket publishes via X. We have all the data after PR 1-7 lands. Publishing sooner = research credibility + community contribution; later = competitive moat preservation.

**Question:** publish after PR 7 lands (P1 wedge in production), or hold until v1 launch?

Recommend **publish after PR 7**. The reachability-aware verdict moat is ours; the raw feed of malicious package names is not.

### 10.7 Cross-feature alignment — does this conflict with the open-core OSS launch?

Memory `future_oss_launch_prep.md` calls out OSS launch prep. The publish-feed listener's Fly machine + Redis cursor are infrastructure that's harder for OSS self-hosters to replicate than a daily QStash cron. Two options:
- **(a)** Listener is a hosted-only feature; self-hosters fall back to the existing daily feed-sync.
- **(b)** Listener ships in OSS but documents a "DIY long-lived process" path.

**Recommend (a).** Real-time is a hosted product feature; consistent with the open-core split.

### 10.8 Aegis fix integration — autonomous or HITL by default?

PR 8's Aegis tie-in could auto-PR (no human gate) or require explicit `manage_incidents` approval. Malicious-pkg findings are high-stakes; an auto-PR that swaps a malicious version for an older "known-good" version is the right call >90% of the time, but the failure mode (version pin breaks build) is loud.

**Question:** require `manage_incidents` permission to auto-trigger, or default-on for orgs that have Aegis enabled?

Recommend **HITL-by-default with org-level opt-in to autonomous.** Mirror `trigger_fix` semantics.

### 10.9 Bundle this into one marathon-followup PR train, or stage across sprints?

Memory `marathon_scope_alignment.md` is a hard rule that mid-marathon scope additions stack on top, don't replace. This plan is brief item #2 in the original marathon brief. **Question:** do PRs 1-3 (P0) ship in this marathon, or queue for the next sprint?

Recommend **queue for next sprint**. The marathon is a depscanner *hardening* pass; this plan is a depscanner *expansion*. Different shape.

### 10.10 Naming: "signals" vs "verdicts"?

`package_malicious_signals` carries individual-rule output. A "verdict" is the composite — does the package as-a-whole get blocked? Today, the composite lives in `project_malicious_findings`. **Question:** add a `package_malicious_verdicts` view (or materialized view) that rolls signals into a single per-(pkg, version) state for UI consumption, or just join in the UI?

Recommend **defer the materialized view**. The per-finding row already carries the rolled-up state for the project context, and global-verdict rolls aren't needed until we have a global-view product (which is Phase B).

---

## Section 11 — Future work (not in this plan)

- **Browser extension / IDE plugin.** Socket Chrome ext + Endor Cursor hooks. Surfaces verdicts at install time / autocomplete. Distribution + ops cost is non-trivial; defer.
- **Registry-side firewall proxy.** Socket Firewall / Bytesafe / JFrog Curation. Heavy build (own DNS / TLS termination / cache layer). Defer until PRs 1-7 prove the data side.
- **Per-org Autogrep tuned to org-dep idiom.** Phase 5 Autogrep generates per-org reachability rules; same machinery could generate per-org malicious-detection rules (e.g. "this org imports crypto SDKs — care more about credential exfil patterns"). Reuses the rule-generation infra; one-week scope; defer until at least one org is asking.
- **Maintainer-reputation graph.** Phylum + Endor leverage maintainer history (which other packages does this author maintain? have any been compromised?). Requires extending `package_maintainer_snapshots` to a graph store. Defer.
- **AI-agent / MCP integration.** SafeDep MCP, Endor Cursor hooks, Aikido Endpoint. Aegis already speaks tool-calling — adding a `lookup_package_signals` MCP tool is small. Defer to Aegis roadmap.
- **`supply-chain-levels` metric on each project.** SLSA-shaped composite — what fraction of deps have provenance, signed releases, scorecard ≥7. Marketing-visible "supply chain health score." Defer to v1 launch surface.
- **AI explainer on findings.** Tier-1 LLM summary of what GuardDog rule triggered + what malicious behavior is implied + remediation guidance. Cheap, useful, defers cleanly.
- **Multi-ecosystem typosquat detection.** H1 ships single-ecosystem; cross-ecosystem typosquats (`requests` PyPI → `requests` npm) need a shared name-graph. Defer.
- **Honey-deploy / deception layer.** Maintain a private registry of "tripwire" malicious-looking package names; if any customer scan touches them, alert. Out of scope for v1; interesting for an enterprise tier later.

---

## Appendix — files referenced (grep-verified)

**Will create:**
- `backend/database/phaseXX_realtime_pkg_signals.sql` (~80 LOC; 2 new tables + cooldown settings + 2 ALTER TABLEs)
- `depscanner/src/realtime/npm-changes-listener.ts` (~200 LOC; long-poll consumer)
- `depscanner/src/realtime/pypi-rss-listener.ts` (~100 LOC)
- `depscanner/src/realtime/rubygems-listener.ts` (~100 LOC)
- `depscanner/src/realtime/release-event-scanner.ts` (~250 LOC; claim + scan + persist)
- `depscanner/src/malicious/heuristics/typosquat.ts` (~120 LOC)
- `depscanner/src/malicious/heuristics/install-script.ts` (~150 LOC)
- `depscanner/src/malicious/heuristics/popularity-list.json` (top-10k names, monthly snapshot)
- `frontend/src/components/malicious/InvestigationPanel.tsx` (~250 LOC)
- `backend/src/routes/internal/realtime-listener.ts` (~80 LOC; health + cursor inspection)

**Will edit:**
- `depscanner/src/pipeline-steps/malicious.ts:18-80` (post-insert flow-join — ~80 LOC)
- `depscanner/src/malicious-scan.ts` (signal-cache lookup before GuardDog — ~30 LOC)
- `depscanner/src/malicious/insert-finding.ts` (relax scanner enum — ~5 LOC)
- `backend/src/routes/malicious.ts` (read flow_signature_hashes; investigation-panel JSON — ~30 LOC)
- `backend/src/lib/policy-engine.ts` (cooldown built-in primitive — ~40 LOC)
- `backend/src/routes/organizations.ts` (cooldown settings PUT/GET — ~30 LOC)
- `backend/src/routes/aegis-v3.ts` (trigger_fix accepts malicious_finding_id — ~25 LOC)
- `fix-worker/src/executor.ts` (malicious-finding fix-plan — ~40 LOC)
- `frontend/src/lib/api.ts` (typed clients — ~10 LOC)

**Will read (no edits):**
- `depscanner/src/malicious/reachability.ts:1-40` (existing per-package usage-slice resolver)
- `depscanner/src/malicious/feeds.ts` (existing feed-lookup contract)
- `depscanner/src/malicious/guarddog.ts` (existing scanner wrapper)
- `depscanner/src/malicious/tarball-cache.ts` (download + sandbox unpack)
- `backend/src/lib/malicious/feed-sync.ts:1-37` (existing daily feed sync)
- `backend/src/lib/malicious/maintainer-signals.ts:1-30` (existing maintainer-signal computation)
- `backend/database/schema.sql:1216-1240` (project_malicious_findings shape)
- `backend/database/schema.sql:358-394` (known_malicious_packages + feed_sync_runs shapes)
- `backend/database/schema.sql:6130-6131` (existing CHECK constraints to relax)
- `docs/depscanner-hardening-report.md:394-424` (competitive context)
- `.cursor/plans/depscanner-hardening-DAILY-LOG.md:59` (Wave 1 #7 finding)

**Total expected diff:** ~1100 LOC of new TypeScript across worker + backend + frontend, ~80 LOC of new SQL (1 migration), ~250 LOC of edits to existing files. The data-model changes are surgical (2 new tables + 2 CHECK relaxations + 1 settings table); the bulk of the work is the listener infrastructure (P0) and the join-and-decorate pass (P1).
