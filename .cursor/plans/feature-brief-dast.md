# Feature Brief: Reachability-Coupled DAST

## One-liner

Add Dynamic Application Security Testing as a fourth signal in the Security tab — and use Deptex's tree-sitter handler map to merge DAST hits with matching SCA + SAST findings into a single "Confirmed Exploitable" card.

## Problem Statement

Today the Security tab shows three static signals: SCA (CVE in dep), SAST (Semgrep code issue), and Secrets. None of them prove an app is actually exploitable — they prove a vulnerability *could* be reached. Users still triage "is this real?" by hand. DAST changes that: a DAST hit on `/api/users` is runtime proof, and when it lands on a handler that already has a SAST SQLi pattern + reachable mysql2 CVE, the three signals collapse into one high-confidence finding. The market is heading this way (Snyk's Code-Informed Dynamic Testing, April 2025) but no vendor has shipped a credible end-to-end story. Deptex's existing tree-sitter framework detection + EPD reachability + AI rule generation are the exact ingredients to fill that whitespace.

## Competitive Landscape

Detailed in `.cursor/plans/research-dast.md`. Summary:

- **Table-stakes (every vendor):** REST + GraphQL + SOAP + gRPC, CI-native, authenticated scanning, OWASP Top 10 + API Top 10, Docker/CLI scanner, PR feedback.
- **Frontier (2-3 vendors):** OWASP LLM Top 10 testing, MCP server testing, code-informed/reachability-aware DAST (Snyk only), AI-validated FP suppression, AI payload generation, schema-drift detection.
- **Whitespace:** Reachability-aware DAST end-to-end. Self-hostable polished ASPM with integrated DAST. Authenticated DAST without manual scripting.
- **Direct DAST competitors:** StackHawk (modern dev-first, $42-59/contributor/mo), Bright Security (AI, <3% FP claim), Snyk API & Web (built on Probely, 245% QoQ ARR growth), Aikido (ZAP+Nuclei hybrid in unified ASPM), Invicti/Acunetix (enterprise, proof-based scanning).
- **OSS engines:** OWASP ZAP (mature browser auth + automation API + March 2026 MCP server) — chosen for MVP. Nuclei (~12k templates, 1,496 KEV CVEs) — added in phase 2.

**Where Deptex differentiates:** the merged "Confirmed Exploitable" card driven by tree-sitter handler signature is genuine new ground.

## User Stories

- **As a security engineer**, I want DAST findings in the same Security tab as SCA/SAST/Secrets so I can triage one queue, not four.
- **As a security engineer**, I want DAST hits that match a SCA + SAST finding to collapse into one "Confirmed Exploitable" card so I don't triage the same vuln three times.
- **As a developer**, I want to point Deptex at my staging URL and get findings back without scripting — at least for unauthenticated endpoints.
- **As a developer**, I want findings linked back to the exact `file:line:function` so I can fix without URL-to-handler hunting.
- **As an org admin**, I want DAST configuration gated by `manage_integrations` so it follows the same RBAC story as my other connectors.

## Architecture Decisions (locked in interview)

- **Worker model:** Single worker — current `extraction-worker` renamed to **`depscanner`** (Fly app: `deptex-depscanner`, env: `FLY_DEPSCANNER_APP`) — with **selective pipeline mode**. A job declares which steps to run: `mode: 'extraction' | 'dast-only' | 'full'`. Existing extractions stay default; DAST scans run as a separate mode.
- **Job tracking:** New `dast_jobs` table mirroring `extraction_jobs` shape (status / heartbeat / retry / run_id) with DAST-specific columns (target_url, scan_engine, scan_profile, auth_strategy).
- **Config storage:** New `project_dast_config` table, one row per project. AES-256-GCM-encrypted credentials reusing the BYOK pattern.
- **Findings storage:** New `project_dast_findings` table mirroring `project_semgrep_findings` upsert-then-delete-stale pattern with `dast_run_id`. FK columns to `project_dependency_vulnerabilities` and `project_semgrep_findings` for the merged-card join.
- **Schedules (phase 2):** New `project_dast_schedules` table.
- **Cross-link mechanic:** Handler signature triple `(file_path, function_name, line)` is the deterministic join key. DAST endpoint hits resolve to a handler via the existing tree-sitter framework-route map; SAST + SCA findings already carry that triple. **No AI fallback in MVP** — deterministic only.
- **Engine MVP:** ZAP only. Nuclei phase 2.
- **Auth MVP:** Anonymous scan only. Basic credentials phase 2; Aegis NL login-script generator phase 3.
- **Spec source MVP:** Framework-detected routes from tree-sitter (already shipped). OpenAPI/GraphQL introspection deferred.
- **Concurrency:** 1 scan per project at a time, 30-minute hard timeout.
- **Spin-up failure:** Fall back to user-URL, surface "spin-up unavailable" warning in Scanning tab. Doesn't block other extraction findings.
- **RBAC:** Reuse `manage_integrations` for DAST config + manual trigger.

## Data Model

### New tables

**`dast_jobs`**
- `id` UUID PK
- `project_id` UUID FK
- `mode` TEXT — `'manual'` | `'scheduled'` | `'on_extraction'` | `'on_demand_aegis'`
- `status` TEXT — `'pending'` | `'running'` | `'completed'` | `'failed'` | `'timeout'` | `'cancelled'`
- `target_url` TEXT
- `scan_engine` TEXT — `'zap'` (MVP) | `'nuclei'` | `'both'`
- `scan_profile` TEXT — `'quick'` | `'full'` | custom (phase 2+)
- `auth_strategy` TEXT — `'anon'` | `'basic_creds'` | `'recorded_session'` | `'aegis_nl'`
- `claimed_by` TEXT, `claimed_at` TIMESTAMPTZ, `last_heartbeat_at` TIMESTAMPTZ — same shape as `extraction_jobs`
- `started_at`, `completed_at`, `attempt_count`, `error_message`, `run_id` TEXT
- Standard indexes on `(project_id, created_at DESC)`, `(status)` partial for pending.

**`project_dast_config`**
- `id` UUID PK, one row per project (`UNIQUE(project_id)`)
- `project_id` UUID FK
- `enabled` BOOLEAN
- `target_urls` TEXT[] (multiple environments per project — staging/prod)
- `default_target_url` TEXT
- `auth_strategy` TEXT
- `encrypted_credentials` BYTEA (AES-256-GCM, same key/version pattern as `organization_ai_providers`)
- `encryption_key_version` INTEGER
- `scan_profile` TEXT, `scan_engines` TEXT[]
- `scan_on_extraction` BOOLEAN DEFAULT false (phase 2 hook)
- `scan_concurrent_max` INTEGER DEFAULT 1
- `scan_timeout_minutes` INTEGER DEFAULT 30
- created/updated_at

**`project_dast_findings`**
- `id` UUID PK
- `project_id` UUID FK
- `dast_run_id` TEXT NOT NULL — upsert-then-delete-stale pattern, mirrors `project_semgrep_findings.extraction_run_id`
- `endpoint_url` TEXT, `http_method` TEXT
- `vulnerability_type` TEXT — `'sqli'` | `'xss'` | `'ssrf'` | `'cmd_injection'` | etc.
- `severity` TEXT — `'critical'` | `'high'` | `'medium'` | `'low'` | `'info'`
- `cwe_id` TEXT, `owasp_top10_ref` TEXT
- `payload_redacted` TEXT, `response_evidence_redacted` TEXT — never store full payload/response with possible secrets
- `confidence` TEXT — `'confirmed'` | `'high'` | `'medium'`
- `handler_file_path` TEXT, `handler_function_name` TEXT, `handler_line` INTEGER — the join triple, NULL when route can't be resolved to a handler
- `linked_sast_finding_id` UUID FK to `project_semgrep_findings(id)` — NULL unless cross-link found
- `linked_sca_finding_id` UUID FK to `project_dependency_vulnerabilities(id)` — NULL unless cross-link found
- `suppressed`, `risk_accepted` BOOLEAN, `risk_accepted_by`, `risk_accepted_at`, `risk_accepted_reason` (phase 2)
- created_at

**`project_dast_schedules`** (phase 2)
- `id` UUID PK, `project_id` FK
- `cron_expression` TEXT
- `timezone` TEXT
- `target_url` TEXT (override config default)
- `enabled` BOOLEAN
- `qstash_schedule_id` TEXT
- `last_run_at`, `last_run_status` TEXT
- `run_count` INTEGER

### Existing-table touches

- No required columns on existing tables for MVP. Phase 2: `projects.dast_enabled` mirror flag may be added for fast list-page filtering, decided later.

### Migration strategy

Additive-only. New tables with FK to existing primary keys. CI-friendly. Schema dump updated in same PR per repo convention.

## API Endpoints

All under existing JWT auth via `authenticateUser` middleware. Permission check: `manage_integrations` on the project's org/team for write ops; `view_*` for read.

- `GET    /api/projects/:projectId/dast/config` — read DAST config
- `PUT    /api/projects/:projectId/dast/config` — upsert config (target URLs, scan profile, auth strategy, scan_engines)
- `POST   /api/projects/:projectId/dast/credentials` — store encrypted credentials (phase 2; out of MVP)
- `POST   /api/projects/:projectId/dast/scan` — trigger manual scan, returns `dast_job_id`
- `GET    /api/projects/:projectId/dast/jobs` — paginated job/run history
- `GET    /api/projects/:projectId/dast/jobs/:jobId` — detail + logs ref
- `DELETE /api/projects/:projectId/dast/jobs/:jobId` — cancel running scan
- `GET    /api/projects/:projectId/dast/findings` — paginated findings, filterable by severity/suppressed
- Existing `GET /api/projects/:projectId/findings` (or current unified-finding endpoint) extended to include DAST source filter chip
- Internal worker endpoint: `POST /api/internal/dast-jobs/claim` — RPC equivalent of `claim_extraction_job`, atomic claim with FOR UPDATE SKIP LOCKED

## Frontend Views

### MVP

1. **Project Settings → new "Scanning" tab**
   - Toggle: DAST enabled
   - Target URL input (one URL for MVP, array UI ready for phase 2)
   - "Scan now" button (manual trigger)
   - Last-scan strip: "Last DAST: 3h ago • 12 findings • 8min"
   - Scan history table (mirrors the polished RunRow pattern from project settings activity table)

2. **Security tab**
   - Existing unified findings table gets a `source=DAST` chip filter
   - Empty state when no DAST has run: inline card "Run dynamic security tests — configure a target URL" → CTA to Scanning tab
   - Scan-status strip at the top: "Last DAST: 3h ago • 12 findings"
   - **Merged "Confirmed Exploitable" card:** single header row + 3 expandable evidence sections (SCA / SAST / DAST). When DAST + SAST + SCA findings share `(handler_file_path, handler_function_name)`, table renders one row instead of three.
     - Header: `Confirmed SQLi in users.ts:42 — mysql2 CVE-2024-X reachable from POST /api/users`
     - Expand → tabs: SCA evidence (CVE + reachable_flow), SAST evidence (Semgrep rule + match), DAST proof (request/response, redacted)

3. **Aegis chat (existing surface)**
   - New tool: `scan_dast(project_id)` triggers a manual scan via the API. Aegis returns job_id + ETA, then findings summary on completion.

### Phase 2+

- Ephemeral spin-up status panel (compose-up logs, port detection, fallback messaging)
- Schedule editor (cron picker, timezone)
- Basic-credentials editor (encrypted at rest)
- Aegis automation: scheduled DAST + Slack/PR-comment summary
- Aegis NL login-script generator UI
- Aegis Fix Agent integration: DAST finding → propose patch → open PR

## User Flows

### MVP flow: first-time DAST scan

1. User navigates to Project Settings → Scanning tab.
2. Empty state. User enters staging URL `https://staging.acme.com`. Saves.
3. User clicks "Scan now."
4. Backend creates `dast_jobs` row with status=pending, returns job_id. UI shows "Scanning…" with live status (Realtime sub on dast_jobs).
5. Worker (renamed) claims job in `dast-only` mode. Spins up ZAP container, points it at the URL, runs anon scan.
6. ZAP output parsed → upserted into `project_dast_findings` keyed on `dast_run_id`. Stale findings from prior `dast_run_id` deleted.
7. Cross-link pass: for each DAST finding, resolve `endpoint_url` → handler via tree-sitter route map (already in extraction artifacts). If a SAST finding shares `(handler_file_path, handler_function_name)`, set `linked_sast_finding_id`. Same for SCA via `reachable_flows.entry_point_file/method`.
8. Worker marks `dast_jobs.status='completed'`.
9. UI refreshes — Security tab now shows merged "Confirmed Exploitable" card for any cross-linked findings, plus standalone DAST chips for the rest.

### Aegis on-demand flow

1. User in Aegis chat: "Scan staging for vulns."
2. Aegis calls `scan_dast(project_id)` tool, gets job_id.
3. Aegis polls or subscribes; on completion, summarizes findings in chat.
4. Aegis can chain to Fix Agent (phase 3) — propose patch for confirmed findings.

### Spin-up fallback (phase 2)

1. Worker tries `docker-compose up` against the cloned repo. Fails (no compose, port clash, app crash).
2. Worker logs `dast_jobs.error_message='spin-up unavailable: <reason>'`, status=`failed`.
3. UI Scanning tab shows: "Auto spin-up unavailable. Provide a target URL to enable DAST." → CTA to config.
4. Other extraction findings (SCA/SAST/Secrets) unaffected.

## Edge Cases

- **No DAST findings on a successful scan:** distinguish "scanned, found nothing" (green) from "scan failed" (red) in scan history. Schema supports via status field.
- **DAST hits on routes with no handler match:** finding row stored with `handler_*` columns NULL. Renders as standalone DAST chip, not merged card. Don't drop the finding.
- **Same vulnerability hit in multiple places:** dedupe within a `dast_run_id` by `(endpoint_url, http_method, vulnerability_type)`. Across runs, upsert-then-delete-stale handles refresh.
- **User-suppressed DAST finding carries forward:** preserve `suppressed`/`risk_accepted` across reruns matched by stable identifier — same pattern as Semgrep findings (rule_id + file_path equivalent → endpoint + method + vuln_type).
- **Target URL unreachable / network error / TLS fail:** scan fails fast, error message captures HTTP/SSL detail, surfaced in Scanning tab.
- **30-minute timeout hits:** worker cancels scan, partial findings (whatever ZAP wrote so far) retained, status=`timeout`. User sees "scan timed out — partial results."
- **Concurrent scan request while one's running:** API returns 409 with current job_id. UI shows "Scan in progress, cancel or wait."
- **Worker crashes mid-scan:** existing extraction-worker recovery cron (60s heartbeat, 5min stuck detection) extends to dast_jobs — same pattern.
- **Deleted project mid-scan:** scan job FK cascade or soft-cancel — match existing extraction-job behavior.
- **Findings on internal staging URL the worker can't reach:** Fly.io worker has no VPN to user infra. Document this; phase 3+ for self-hosted runner option (existing roadmap item).
- **Redaction:** worker scrubs response bodies for likely secrets (reuse TruffleHog detector or simple regex pass) before storing `response_evidence_redacted`. Never store full request/response with credentials.

## Non-Functional Requirements

- **Scan duration:** target p50 ≤ 8min, p99 ≤ 30min (hard timeout).
- **Worker machine:** initially performance-4x or larger if memory-bound by ZAP + scanned app; right-size during phase 2 ephemeral spin-up.
- **Findings volume:** assume ≤ 200 findings per scan for typical repo (ZAP default profile produces ~50-200). Pagination at 50/page; full table virtualized if needed.
- **Concurrent scans across orgs:** Fly.io machine pool sized for N concurrent. Pre-launch: pool of 2-3 stopped machines. Scale-to-zero idle cost negligible.
- **Realtime:** Supabase Realtime sub on `dast_jobs.status` + `project_dast_findings` insert for live UI feedback during scan, mirrors extraction pattern.
- **Cost:** ZAP + scanned-app container time per scan, ~$0.05-0.10 worst case at performance-4x. Documented in API cost summary alongside extraction.
- **Eventual consistency OK:** findings UI may lag the actual scan completion by a Realtime tick. Manual refresh always reconciles.

## RBAC

- **`manage_integrations`** (org-level or team-level depending on project ownership) gates: edit `project_dast_config`, store credentials (phase 2), trigger manual scan, cancel scan, edit schedules (phase 2).
- **Anyone with project view access** can see findings + scan history.
- Aegis tool calls go through standard Aegis permission check (`interact_with_aegis` + tool-specific permission level — DAST scan trigger considered "medium" risk, may require approval for first run).

## Dependencies

- **Existing infra reused:**
  - Fly.io worker pattern (extraction-worker → renamed)
  - QStash for scheduled scans (phase 2)
  - Supabase Realtime for live UI status
  - Tree-sitter framework detection (`backend/extraction-worker/src/framework-detection/`) — provides handler signature map
  - Reachable flow data from EPD (`project_reachable_flows.entry_point_file/method`) — provides SCA cross-link
  - `project_semgrep_findings.file_path` + line — provides SAST cross-link
  - `claim_extraction_job` RPC pattern → new `claim_dast_job` RPC
  - AES-256-GCM encryption pattern from `organization_ai_providers.encrypted_api_key`
  - PR check engine (phase 2 — for diff-aware DAST as concept #5 fold-in)
  - Aegis tool-execution + approval flow (Aegis tool wrapper, phase 1.5)
- **External:**
  - OWASP ZAP Docker image (MVP)
  - Nuclei (phase 2)
- **Worker rename:** decide between `scan-worker`, `security-worker`, `deptex-worker` before implementation. Fly app rename is a config + DNS change, not a rewrite.

## Success Criteria

**MVP shipped means:**
- A user can configure a target URL on a project, click Scan, and see ZAP findings appear in the Security tab within 30 minutes.
- DAST findings appear with a `source=DAST` chip in the unified findings view.
- For at least one demo case, a DAST finding correctly merges with a SAST + SCA finding into a single "Confirmed Exploitable" card via handler signature.
- Scan history is visible in the Scanning tab with status, duration, finding count.
- Empty state, in-progress state, completed state, and error state all render cleanly.
- Aegis can trigger a scan via tool call.

**Quantitative signals (post-launch):**
- ≥ 1 DAST scan run per active project per week (adoption).
- ≥ 50% of triaged DAST findings collapse with at least one other finding via cross-link (cross-link mechanism is working).
- Mean scan duration ≤ 10min (UX is acceptable).
- < 5% of scans time out (engine config is right-sized).

## Resolved Decisions (post-interview locks)

- **Worker rename:** `depscanner`. Fly app: `deptex-depscanner`. Env vars: `FLY_DEPSCANNER_APP`, `FLY_DEPSCANNER_POOL_SIZE`. Migration is a Fly app rename + env-var rollover, not a code rewrite.
- **ZAP scan profile defaults:** detect-then-route. If framework-detection emits API routes (Express/Fastify/FastAPI/Spring/Rails/Gin/etc.) → ZAP `api-scan.py` against the route list. Otherwise → `full-scan.py` against the URL. No user-facing config in v1.
- **Route materialization:** new `project_routes` table populated per extraction by the existing framework-detection step. Schema: `(id, project_id, extraction_id, file_path, function_name, line, http_method, route_pattern)`. Makes the DAST cross-link join a one-line query and unblocks future PR-diff DAST + AI payload generation.
- **`dast-only` mode clone strategy:** re-clone every time. Don't try to reuse stale extraction artifacts. Clone is ~30s vs minutes of scan; the optimization isn't worth the staleness/coupling risk in v1.

## Open Questions (still TBD)

- **Scan-on-extraction trigger plumbing (phase 2):** extraction-worker calls `dast-only` mode at end of its own pipeline, or extraction completion fires a QStash job that creates a `dast_jobs` row. Probably the latter for clean job-table semantics.
- **Finding redaction depth:** how aggressively do we scrub response bodies? Reuse TruffleHog detector (slow), simple regex pass (fast), or heuristic (medium)? Probably regex MVP, TruffleHog phase 2.
- **Free-tier limits:** assume unlimited for now (solo pre-launch). Add when billing lands.

## Scope

### MVP (~2-3 weeks)

- Worker rename + selective pipeline mode
- `dast_jobs`, `project_dast_config`, `project_dast_findings` tables + indexes
- ZAP container integration (single engine)
- Anon-only scan
- User-provided target URL (single URL/project)
- Manual trigger only — no schedules, no on-extraction
- API: config CRUD, scan trigger, jobs list/detail, findings list
- UI: Project Settings → Scanning tab (config + history), Security tab DAST chip + last-scan strip + empty state, merged "Confirmed Exploitable" card for cross-linked findings
- Aegis tool: `scan_dast(project_id)`
- Cross-link via handler signature triple (deterministic only)
- 1-concurrent-per-project + 30min timeout

### Phase 2 (~3-4 weeks)

- Ephemeral spin-up via docker-compose with user-URL fallback
- Nuclei engine added (CVE-template + KEV checks)
- Basic-credentials auth (encrypted)
- `project_dast_schedules` + cron-based runs via QStash
- Aegis automation: scheduled DAST + Slack/PR-comment summary
- Multiple target URLs per project (staging/prod)
- Scan-on-extraction opt-in flag
- Suppression / risk-accepted UI for DAST findings
- API spec source: OpenAPI in repo + GraphQL introspection

### Phase 3 (~3-4 weeks)

- Aegis NL login-script generator (concept #4 from research)
- Aegis Fix Agent integration: DAST finding → patch → PR
- Diff-aware PR DAST (concept #5 from research) — only scan touched handlers
- Recorded session / HAR upload auth
- Custom scan profiles
- Self-hosted runner support (rides existing self-host roadmap)

### Phase 4+ (later)

- OWASP LLM Top 10 testing (when LLM SDK detected via framework detection)
- MCP server security testing
- AI payload generation (concept #3 — Aegis writes Nuclei templates from codebase)
- Surface monitoring (concept adjacent — subdomain enum, exposed services)
- Schema-drift detection

## Recommended Next Step

Run `/plan-feature` against this brief to produce the milestone-by-milestone implementation plan. Key planning decisions to lock in that round: worker rename, the `project_routes` materialization question, ZAP scan profile defaults, and whether `dast-only` mode reuses the extracted clone artifacts or re-clones.
