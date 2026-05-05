# Feature Brief: Malicious Packages

## One-liner
A first-class malicious-package detection layer in the extraction pipeline — multi-feed lookup + GuardDog source scanning + Tier 1 AI review + Socket-style capability detection — surfaced as a dedicated "Malicious Packages" tab in the unified project security page and folded into the existing org-level security dashboard, with notifications wired through the flow builder.

---

## Problem Statement
Today Deptex's malicious-package detection is one boolean (`dependencies.is_malicious`) sourced from a single feed (GHSA `MALWARE` classification on advisories). It catches the narrow case where a malicious package has already been formally advisored and rejects nothing else: no install-script analysis, no obfuscation detection, no typosquat detection, no per-finding evidence, no findings table, no surface UI.

Real attackers ship novel malicious packages — typosquats, account-takeover poison, install-time exfil — that never appear in GHSA. Every serious competitor (Socket, Endor Labs, Aikido, Sonatype, Snyk) runs a multi-layer detection stack (known-feed lookup + heuristic source scan + AI/dynamic review). Deptex has 1/10th of layer 1 and zero of layers 2 and 3. This feature brings Deptex to Socket-tier parity using open-source tooling (GuardDog, OSSF malicious-packages, Datadog dataset, Aikido Intel) plus the platform AI we already pay for.

---

## Competitive Landscape

Drawn from `.cursor/plans/research-malicious-packages.md`. Summary of where v1 lands relative to each competitor:

| Vendor | Their stack | Our v1 posture |
|---|---|---|
| **Socket** | 70+ signals, static + capability detection + LLM tier, real-time monitoring | Match: GuardDog 6-ecosystem rules + multi-feed + Gemini Flash review + capability tags |
| **Endor Labs** | 150+ signals, OSV + proprietary feed, ML, sandboxing, **reachability filtering** | Partial: matched on signals + feeds + AI; reachability filtering deferred to v2 (depends on Phase 5/6) |
| **Aikido** | Pro-tier malware detection + AGPL Aikido Intel feed + free Safe Chain blocker | Matched on detection; ingest Aikido Intel (license-isolated); no install-time blocker in v1 |
| **Sonatype Repository Firewall** | Registry-proxy quarantine | Different model (ours runs at extraction, not registry); functionally equivalent for SCA purpose |
| **Snyk** | Advisory-driven only | Already exceeded by v1's heuristic + AI layers |

**What v1 explicitly does NOT match (deferred to follow-on):**
- Endor's reachability filtering of malicious findings → depends on Phase 5/6 settling
- Sandboxed dynamic analysis → Endor-only frontier feature, complex to operate
- Aegis Quarantine Agent (auto-PR remove + alternative) → user explicitly deferred to v1.1+
- Self-hosted `deptex install` Safe-Chain-style blocker → moonshot for separate phase

**Open feeds ingested in v1:**
- [OSSF malicious-packages](https://github.com/ossf/malicious-packages) (OSV format, queryable via osv.dev)
- [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (~26k samples)
- [Aikido Intel](https://intel.aikido.dev/malware) (live feed; AGPL — needs license-isolated process)
- GHSA `MALWARE` (already wired)

**Detection engine:**
- [GuardDog](https://github.com/DataDog/guarddog) v2.9+ — Apache-2.0, 6 ecosystems (npm, PyPI, Go, RubyGems, GitHub Actions, VSCode), Semgrep + YARA rules + metadata heuristics

---

## User Stories

**As a developer reviewing a dep tree:**
- I want to see a "Malicious" badge on packages that triggered any finding so I can recognize them at a glance.
- I want to click into a flagged package and immediately see *why* it's malicious in plain English, with the actual offending code highlighted.
- I want to see capability tags on every dep I open (network_io / spawns_processes / eval_dynamic) so I have base context even on unflagged packages.

**As a security engineer triaging across the org:**
- I want a dedicated "Malicious Packages" view in the project security page where I can filter by severity / scanner / age / status.
- I want an org-level rollup card on the security dashboard showing total malicious findings across all projects, broken down by severity.
- I want to ignore individual findings on a project (with reason) when they're false positives I've validated.
- I want to accept-risk findings I'm aware of but won't fix immediately.
- I want to add an org-wide allowlist entry for a package I've vetted, so it never fires again across any project.

**As an org admin:**
- I want a malicious-package detection event to flow through our existing notification rules (Slack, email, etc.) so the right team gets paged when something critical lands.
- I want the existing `analyze_package_security` Aegis tool to use the new findings data so when I ask "is this package safe to add?" Aegis gives a real answer with evidence.

---

## Data Model

### New tables

**`package_security_cache`** — Global, cross-org cache of all per-(package, version, scanner) results. Cache key includes `scanner_version` so rule updates invalidate cleanly.
```
id                uuid PK
package_name      text NOT NULL
version           text NOT NULL
ecosystem         text NOT NULL          -- npm, pypi, maven, golang, rubygems, github-actions, vscode
scanner           text NOT NULL          -- 'guarddog' | 'ai_review' | 'capabilities'
scanner_version   text NOT NULL          -- e.g. 'guarddog@2.9.0', 'gemini-flash@2.5'
findings          jsonb                  -- [{rule_id, severity, message, evidence: {file, lines, snippet}}, ...]
capabilities      jsonb                  -- null unless scanner='capabilities'; {network_io: bool, spawns_processes: bool, ...}
ai_narrative      text                   -- null unless scanner='ai_review'
risk_level        text                   -- 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none'
scanned_at        timestamptz NOT NULL DEFAULT now()
UNIQUE (package_name, version, ecosystem, scanner, scanner_version)
```

**`known_malicious_packages`** — Global, ingested daily from open feeds. Lookup table for layer-1 detection.
```
id                uuid PK
package_name      text NOT NULL
version           text                   -- null = all versions
ecosystem         text NOT NULL
source            text NOT NULL          -- 'osv' | 'ghsa' | 'aikido_intel' | 'datadog'
source_id         text NOT NULL          -- the OSV/GHSA ID or feed-specific ref
severity          text
description       text
first_seen_at     timestamptz NOT NULL DEFAULT now()
last_seen_at      timestamptz NOT NULL DEFAULT now()
withdrawn_at      timestamptz            -- non-null = OSV withdrawn / FP
UNIQUE (source, source_id)
INDEX (package_name, ecosystem)
```

**`project_malicious_findings`** — Per-project finding records. Same shape as `project_semgrep_findings`/`project_secret_findings`.
```
id                  uuid PK
project_id          uuid NOT NULL
extraction_run_id   text NOT NULL
dependency_id       uuid NOT NULL
dependency_version  text NOT NULL
cache_id            uuid NOT NULL → package_security_cache
rule_id             text NOT NULL          -- denormalized for filtering
scanner             text NOT NULL          -- denormalized
severity            text NOT NULL
message             text
depscore            integer
status              text NOT NULL DEFAULT 'open'   -- 'open' | 'ignored' | 'risk_accepted' | 'resolved'
ignore_reason       text
ignored_by          uuid
ignored_at          timestamptz
risk_accepted_by    uuid
risk_accepted_at    timestamptz
risk_accepted_reason text
created_at          timestamptz NOT NULL DEFAULT now()
INDEX (project_id, status)
INDEX (extraction_run_id)
```

**`organization_malicious_allowlist`** — Per-org allowlist entries. A finding matching an allowlist entry is suppressed at insert time, never reaches `project_malicious_findings`.
```
id              uuid PK
organization_id uuid NOT NULL
package_name    text NOT NULL
version         text                       -- null = all versions
ecosystem       text NOT NULL
reason          text NOT NULL
created_by      uuid NOT NULL
created_at      timestamptz NOT NULL DEFAULT now()
UNIQUE (organization_id, package_name, version, ecosystem)
```

### Modifications to existing tables
- `project_security_fixes` — add `malicious_finding_id uuid` (mirrors `semgrep_finding_id` / `secret_finding_id`).
- `dependencies.is_malicious` — keep as fast denormalized flag; recompute on every extraction as `EXISTS (SELECT 1 FROM project_malicious_findings WHERE … AND status='open') OR EXISTS (SELECT 1 FROM known_malicious_packages WHERE …)`.

### Schema dump
After migrations land, run `cd backend/extraction-worker && npm run schema:dump` to refresh `backend/database/schema.sql` (CI gate).

---

## API Endpoints

All new routes live in `backend/src/routes/malicious.ts` (new), registered in `backend/src/index.ts`.

| Method | Path | Purpose | Auth |
|---|---|---|---|
| GET | `/api/projects/:projectId/malicious-findings` | List findings for project (filters: severity, status, scanner, search) | `authenticateUser` + project access |
| GET | `/api/projects/:projectId/malicious-findings/:id` | Single finding with full cache evidence | same |
| PATCH | `/api/projects/:projectId/malicious-findings/:id` | Set status (`ignored` / `risk_accepted` / `open`), ignore_reason | same |
| GET | `/api/organizations/:orgId/malicious-findings` | Org-rollup view across projects | `authenticateUser` + org member |
| GET | `/api/organizations/:orgId/malicious-allowlist` | List org allowlist entries | same |
| POST | `/api/organizations/:orgId/malicious-allowlist` | Add allowlist entry | `manage_organization_settings` |
| DELETE | `/api/organizations/:orgId/malicious-allowlist/:id` | Remove allowlist entry | `manage_organization_settings` |
| POST | `/api/internal/malicious/feed-sync` | QStash-invoked feed refresh job | `INTERNAL_API_KEY` |
| POST | `/api/internal/malicious/rescan-existing` | QStash daily rescan against updated feeds | `INTERNAL_API_KEY` |
| POST | `/api/internal/malicious/scan-package` | Worker callback to populate cache for a (package, version) | `INTERNAL_API_KEY` |

---

## Frontend Views

### Project security page — new "Malicious Packages" tab
- Lives next to Vulnerabilities / Secrets / Semgrep tabs in the unified security page
- Same expand-on-click finding-card pattern as Semgrep (per the security tab progress memory)
- Filter bar: severity, scanner, status (open / ignored / accepted), age, package search
- Card collapsed: dep name + version + scanner badge + severity + one-line message
- Card expanded:
  - Plain reason
  - **AI narrative** (rendered first when present, falls back to rule reason)
  - **Highlighted code snippet** that triggered the rule (when GuardDog source-code rule fired)
  - **Capability tags** (`network_io`, `spawns_processes`, `eval_dynamic`, etc) as supporting context
  - Maintainer/registry metadata (publish age, weekly downloads, maintainer's other packages)
  - Action buttons: Ignore (with reason) / Accept risk (with reason) / Add to allowlist (org admin only)

### Package overview drawer (`PackageOverview.tsx`)
- Add capability-tag row alongside license / depscore / OpenSSF score
- When `is_malicious === true`, show a prominent malicious banner that links into the relevant finding card

### Organization security dashboard
- Add a "Malicious Packages" card folded into the existing org Security dashboard:
  - Total open findings (count)
  - Severity breakdown
  - Top 5 affected projects (linked)
  - Last 24h trend
- Org-rollup table is reachable from "View all" on this card, mirroring the org-level Watchtower/Aegis console pattern

### Reuse, not new
- Filter bar / card / ignore modal components from Semgrep tab
- Severity color tokens
- Permission gating utilities

---

## User Flows

### Extraction flow — new step `malicious-scan`
Slots in **after `tree-sitter-extract`, before `semgrep`** in the extraction pipeline:

1. **Feed lookup (cheap, fast):** for every `(package, version, ecosystem)` in the dep tree, check `known_malicious_packages`. Hits create immediate findings.
2. **Cache hit check:** for each `(package, version)`, look up `package_security_cache` for `scanner='guarddog'` AND current `scanner_version`. Hits skip step 3 for that package.
3. **GuardDog scan (cache miss only):** download package tarball, run GuardDog with the ecosystem-appropriate rule set, JSON output. Persist to `package_security_cache`. Apply rules also against repo-checkout sources for first-party detection (open question — see below).
4. **AI review (cache miss only, conditional):** if GuardDog flags or if metadata is suspicious (new + rare + has postinstall), Gemini Flash reviews the package and writes a narrative. Cached as `scanner='ai_review'`.
5. **Capability detection (cache miss only):** tree-sitter pass produces capability tag set. Cached as `scanner='capabilities'`.
6. **Allowlist filter:** any finding whose (package, version, ecosystem) matches `organization_malicious_allowlist` is suppressed at insert.
7. **Persist:** write `project_malicious_findings` rows linked to cache entries.
8. **Recompute denormalized flag:** update `dependencies.is_malicious` for the affected packages.
9. **Emit event:** `malicious_package_detected` event into the existing event bus per finding.

### Daily QStash crons
- **`malicious-feeds-sync`** (daily): pull latest from OSSF / Datadog / Aikido Intel / OSV.dev. Upsert into `known_malicious_packages`. Mark withdrawn entries.
- **`malicious-rescan-existing`** (daily, after feed-sync): for any newly-added `known_malicious_packages` entry, find affected `project_dependencies`, create findings as if extraction had just run. Emit detection events. Critical for account-takeover scenarios.

### Triage flow
- **Ignore (project-scope):** any role with current security-finding access on the project. Records `ignored_by` + `ignore_reason` + timestamp. Status = `ignored`. Reuses semgrep ignore UX.
- **Accept risk (project-scope):** same access. Status = `risk_accepted` + reason + acceptor. Carries forward across re-extractions matched by `(dependency_id, rule_id)`.
- **Org-wide allowlist:** requires `manage_organization_settings`. Adds row to `organization_malicious_allowlist`. Subsequent extractions filter at insert time. Existing open findings for that (package, version) get auto-resolved with status='resolved' on next extraction.

### Notification flow
- New event type `malicious_package_detected` registered in event bus
- Default trigger templates ship with the migration (e.g., "All critical malicious findings → org admin Slack")
- Dependency context for trigger code includes `malicious_indicator` field per the notification dispatcher pattern (already speced in `phase_09_notifications.plan.md`)

---

## Edge Cases & Error Handling

| Scenario | Handling |
|---|---|
| GuardDog scan times out or errors | **Hard-fail the extraction** (per Round 6 decision). Mark `extraction_step_errors` row at `error` level, set extraction status to failed. *Note: this is a deliberate deviation from the reachability plan's soft-fail default — malicious detection is load-bearing.* Per-package timeout cap of 60s; total step budget 5 min. |
| GuardDog rule set updates (new release) | Cache key includes `scanner_version='guarddog@2.10.0'`; rule update triggers full re-scan on next extraction since old cache entries no longer match. |
| Aikido Intel feed unreachable | Skip just that source on this run; log warn. Lookup table still works via remaining sources. |
| AI narrative generation fails (Gemini error / rate limit) | Cache nothing for `ai_review`; finding still saves with empty `ai_narrative`. UI gracefully falls back to rule reason. Retry on next extraction. |
| Package not on registry (private dep, dead version) | Skip GuardDog scan with `extraction_step_errors` warn entry. Feed lookup still applies. |
| OSV withdraws a malicious advisory (false positive) | Daily feed-sync sets `withdrawn_at`. Open findings sourced from that ID get auto-resolved on next rescan. |
| Allowlist matches an already-flagged dep | On allowlist add: bulk-update existing `project_malicious_findings` rows to `status='resolved'`, with `ignore_reason='allowlisted'`. |
| Massive monorepo with 5000+ deps | Parallelize GuardDog calls (worker concurrency cap), cap per-package scan at 60s. Most will be cache hits. |
| Empty state — no findings yet | "No malicious packages detected. We scan against [4] feeds plus GuardDog source rules on every extraction." Link to the most recent extraction run. |
| AGPL contamination concern (Aikido Intel) | Run Aikido Intel ingestion in an isolated worker process that does **only** "fetch feed → upsert into `known_malicious_packages`." No AGPL code linked into the main extraction worker. |
| GuardDog detects on first-party project source (not just deps) | v1 scope: deps only. First-party scanning deferred (potential overlap with existing Semgrep step). |

---

## Non-Functional Requirements

- **Latency budget:** +1-2 min p50 to extraction, +5 min p95. Most scans hit the global cache. First-encounter packages cost ~10-30s each (download + GuardDog + capability pass + AI review).
- **Throughput:** must handle dep trees up to ~5000 packages without timing out. Parallel scan concurrency configured per Fly machine size.
- **AI cost ceiling:** Gemini Flash usage capped at $50/mo platform-wide via existing `ai_usage_logs` cost telemetry. Cache hits keep this trivial in steady state.
- **Cache hit rate target:** ≥95% in steady state once popular packages are cached. Measured via `package_security_cache` hit/miss counters.
- **Detection benchmark:** ≥90% true-positive rate on a 100-500 sample subset of Datadog's malicious-software-packages-dataset. Run as automated benchmark in `backend/extraction-worker/test/`.
- **False-positive ceiling:** zero on top-100 npm + top-100 PyPI most-downloaded packages. Treated as launch-blocker.
- **Real-time semantics:** eventual consistency. Findings appear within seconds of extraction. Daily rescan provides ≤24h visibility on newly-disclosed malicious packages.
- **Data volume:** `project_malicious_findings` projected at <10k rows per project per year. `package_security_cache` global, projected at <1M rows in year 1 (one row per (package, version, scanner)).

---

## RBAC Requirements

- **Read findings (project-scoped):** any role with existing security-finding read access. No net-new permission.
- **Ignore / accept risk (project-scoped):** same as ignore-vuln-finding today on the project.
- **Manage org-wide allowlist:** `manage_organization_settings` (matches how org policy + status changes are gated).
- **Trigger fix from finding:** `trigger_fix` (existing permission). Ties into `project_security_fixes.malicious_finding_id` for the deferred Aegis Quarantine Agent.

---

## Dependencies

**On in-flight work:**
- Reachability Phase 5/6 — **NOT blocked**. v1 explicitly defers Endor-style reachability filtering. v2 plugs in once Phase 6 settles.
- Flow builder — uses existing event-bus plumbing already on main; no special dependency.

**On already-shipped work:**
- Tree-sitter extraction (`extraction-worker/src/tree-sitter-*`) — capability detection reuses this.
- Platform AI provider (`backend/src/lib/ai/provider.ts:getPlatformProvider`) — Tier 1 wiring.
- `ai_usage_logs` table + cost telemetry.
- Semgrep-finding card UI components (frontend).
- Notification flow builder + event-bus + `notification-dispatcher.ts` dependency context.
- `extraction_step_errors` table + per-step error logging pattern.
- Aegis tools (`backend/src/lib/aegis/tools/intelligence.ts:analyze_package_security`) — extended to surface new findings.

**External:**
- GuardDog v2.9+ binary (Apache-2.0) — bundled into extraction-worker Dockerfile.
- OSSF malicious-packages, Datadog dataset, Aikido Intel, OSV.dev (free, open).

---

## Success Criteria

1. **Detection rate ≥90%** on a 100-500 sample subset of Datadog's malicious-software-packages-dataset, measured by automated benchmark.
2. **Zero false positives** on top-100 npm + top-100 PyPI most-downloaded packages, measured before launch.
3. **Extraction p50 latency adds <2 min** on dogfood projects, measured in production over the week post-launch.

(Aegis tool integration is a v1 requirement but not a launch-gating success metric.)

---

## Open Questions

1. **First-party project scanning** — GuardDog can also scan the project's own source. v1 scope explicitly: deps only. Need to confirm there's no expected overlap with Semgrep that would cause user confusion.
2. **Severity mapping** — GuardDog rules use Semgrep `INFO`/`WARNING`/`ERROR`; we need a mapping table to our `critical/high/medium/low/info`. Likely: feed match (already-confirmed malicious) → critical, GuardDog ERROR → high, WARNING → medium, INFO → low. AI-only flag → medium with explainer required.
3. **Capability tag set** — exact list to ship. Proposed v1 starter: `network_io`, `filesystem_write`, `spawns_processes`, `reads_env`, `eval_dynamic`, `crypto_ops`, `native_binaries`, `obfuscated_code`. Open to additions.
4. **Hard-fail granularity** — if 1 package out of 500 fails to scan, do we hard-fail the whole extraction? Suggest a threshold: hard-fail if >5% of packages fail to scan, otherwise per-package warn. To confirm.
5. **AI re-review trigger** — re-run AI narrative generation when GuardDog rule version bumps? Or only when the (package, version) is genuinely new? Probably the latter to keep cost down, but worth nailing down.
6. **Capability detection for non-source-bearing deps** — packages distributed as compiled binaries (some npm bundles, native modules) won't be readable by tree-sitter. Set capability tags to `unknown_binary` and treat as a signal (not a finding) for the AI tier.

---

## Scope

### v1 — Phased rollout, no feature flag, ship straight to all orgs

Sequenced as four shippable milestones. Each milestone is dogfoodable on its own.

**Milestone 1 — Foundation (~2 wks):**
- Migrations: `package_security_cache`, `known_malicious_packages`, `project_malicious_findings`, `organization_malicious_allowlist`, `project_security_fixes.malicious_finding_id`. Schema dump refresh.
- GuardDog binary in extraction-worker Dockerfile.
- New extraction step `malicious-scan` with feed lookup + GuardDog scan + cache hit/miss flow.
- Allowlist filter at insert.
- Project routes: list/get/patch findings, list/add/delete allowlist.
- Frontend: "Malicious Packages" tab on project security page using Semgrep card pattern.
- Hard-fail extraction on scan error.
- Benchmark harness in `backend/extraction-worker/test/` against Datadog dataset.

**Milestone 2 — AI Layer (~1 wk):**
- AI narrative generation step (Tier 1 Gemini Flash via `getPlatformProvider`).
- AI narrative inline in finding cards.
- AI cost telemetry via existing `ai_usage_logs`.

**Milestone 3 — Capabilities (~1 wk):**
- Capability detection step using tree-sitter.
- Capability tags on package overview drawer.
- Capability tags as supporting context inside finding cards.

**Milestone 4 — Continuous + Notifications + Org Rollup (~1 wk):**
- QStash crons: `malicious-feeds-sync` daily + `malicious-rescan-existing` daily.
- New event type `malicious_package_detected` registered.
- Default notification rule templates.
- Org-level "Malicious Packages" card on existing org Security dashboard + view-all rollup table.
- Aegis `analyze_package_security` tool extended.

**Total: 4-6 weeks. Ship straight (no flag). Solo-pre-launch context.**

### Out of v1 (deferred)
- Aegis Quarantine Agent (auto-PR removal + alternative). User explicitly skipped; revisit after launch.
- Reachability filtering of malicious findings (Endor-tier). Depends on Phase 5/6 settling.
- `deptex install` Safe-Chain-style install-time blocker. Moonshot, separate phase.
- First-party (project source) GuardDog scanning. Scope creep risk vs Semgrep.
- Sandboxed dynamic analysis. Frontier-only feature.
- Cross-org reputation wisdom. Network-effect feature; meaningful only at scale.

---

## Recommended Next Step
Run `/plan-feature` against this brief to produce the milestone-by-milestone implementation plan with concrete file paths, migration order, and test plan.
