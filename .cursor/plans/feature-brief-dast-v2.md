# DAST v2 — Feature Brief

> **Historical context (2026-05-09):** This plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. Where this plan references BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, or `AI_ENCRYPTION_KEY` for AI key envelopes, treat those as historical implementation details — current AI runs on platform keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from worker env). `AI_ENCRYPTION_KEY` itself is still in use, but only for `organization_registry_credentials` (IaC v2 Phase 1).

## Problem Statement

Deptex DAST v1 shipped a baseline ZAP wrapper with a structurally novel SCA cross-link (Confirmed Exploitable badge), but the core scanning capabilities are roughly a decade behind serious competitors. Today we cannot scan authenticated sites, cannot crawl SPAs, do not actively fuzz state-changing endpoints, do not schedule scans, and have no triage workflow for findings. The result is a feature that produces a few low-confidence passive findings on anonymous spider runs, while customers expect what Burp Enterprise / Invicti / StackHawk / Snyk DAST ship today. v2 closes the parity gap in two phases (Engine + Workflow), then leans into the cross-link moat in a third (UX + SAST cross-link + EPD prioritization).

## Current State in Deptex

v1 (shipped 2026-04-30, PR `worktree-dast` → main `d8129d7`):

- **Engine**: ZAP-only, three helper scripts (`zap-baseline.py`, `zap-full-scan.py`, `zap-api-scan.py`) wrapped in `backend/depscanner/src/dast/runner.ts:382` via spawn. Anonymous scans only. 4 nominal profiles (auto/quick/full/api) but `auto` only picks `api` when entry-points exist, otherwise `baseline`.
- **Schema**: `project_dast_config` (single `target_url` TEXT, scan_profile, timeout); `project_dast_findings` with handler-resolved partial unique index + atomic-commit via `projects.active_dast_run_id` and `commit_dast_run` RPC; suppression carry-forward already wired (`backend/database/phase23b_dast_schema.sql`).
- **Routes**: `backend/src/routes/dast.ts` exposes config GET/PUT, scan POST, jobs GET, findings GET. RBAC via `manage_projects`. SSRF defense in 3 layers (route TS, DB `queue_scan_job`, depscanner pre-flight).
- **Cross-link**: `backend/depscanner/src/dast/pipeline.ts:132` resolves endpoint_url → handler via `route-matcher.ts` (8 frameworks: Express/Fastify/Sinatra/Rails/Gin/FastAPI/Spring/Laravel) → joins `project_reachable_flows.entry_point_file` → surfaces `linked_sca_osv_id`. SCA-only; SAST is explicitly deferred. Confirmed Exploitable badge in `frontend/src/components/dast/DastFindingsSection.tsx:247`.
- **Worker**: depscanner (formerly extraction-worker) on Fly with scale-to-zero. Concurrency caps in `queue_scan_job` RPC: 1/project, 3/org.
- **UI**: Settings → Scanning tab (`DastScanningTab.tsx`) for config + history; Security tab DAST section (`DastFindingsSection.tsx`) for findings. Realtime via Supabase channels.

**What is rudimentary**: scan profiles are a misnomer (we just pick a script, not a real config policy); no auth; no SPA support; no active body fuzzing of all-routes; no scheduling; no exclusion patterns; no header injection; no triage workflow on findings. **What is missing**: SAST cross-link, EPD-aware prioritization, finding detail page, multi-target per project, scope controls, scheduled scans, BYOK credential storage, hybrid engine (ZAP+Nuclei).

## Competitive Landscape

### Burp Suite Enterprise (PortSwigger)
- Authentication: login credentials (single-step) + recorded login sequences (multi-step / SSO). Burp AI auto-records sequences. API auth: API key, Basic, Bearer, dynamic refresh tokens.
- Custom scan configurations, BApps extensibility. Native Jira/GitLab integrations.
- Source: [PortSwigger Authenticated scanning](https://portswigger.net/burp/documentation/scanner/authenticated-scanning), [Burp Enterprise](https://portswigger.net/burp/enterprise).

### StackHawk
- Dev-first; runs *in* CI/CD. AuthZ modes: form, OAuth (Client Credential / Resource Owner), cookie, token, custom JS/Kotlin scripts. `loggedInIndicator` + `loggedOutIndicator` regex. Auto-detects REST/GraphQL/gRPC, generates OpenAPI from source.
- AI-powered remediation guidance per finding.
- Source: [StackHawk Auth docs](https://docs.stackhawk.com/hawkscan/configuration/authentication.html), [StackHawk Product](https://www.stackhawk.com/product/).

### Invicti (Netsparker) / Acunetix
- "Proof-Based Scanning" — actively exploits to confirm before reporting (claims 0% FP on confirmed). REST/SOAP discovery + JS-heavy frameworks. Compliance-grade reporting.
- Source: [Invicti scanner](https://www.invicti.com/web-vulnerability-scanner/).

### Bright Security
- AI-augmented; pitches business-logic detection + LLM-generated-code coverage. Direct GitHub/GitLab repo scanning, push/branch/scheduled triggers.
- Source: [Bright product](https://brightsec.com/product/).

### Snyk API & Web (DAST)
- AI-powered API mapping (115 vuln types claimed) + asset discovery. Connected reachability across SCA + SAST (no full DAST cross-link path published).
- Source: Checkmarx 2026 comparison ([Checkmarx](https://checkmarx.com/learn/dast/dast-tools-key-features-and-12-solutions-to-know-in-2026/)).

### 42Crunch
- Contract-based API security, not black-box DAST. Conformance scanning automated from OpenAPI contract. Differentiates by *eliminating* black-box guessing.
- Source: [42Crunch platform](https://42crunch.com/api-security-platform/).

### Mayhem (ForAllSecure)
- Behavioral fuzzing + symbolic execution + AI proof-of-vulnerability. Stateful, agentless API testing. 0-FP via exploit verification.
- Source: [Mayhem](https://www.mayhem.security/).

### OWASP ZAP (our engine)
- Automation Framework jobs we don't yet expose: `authentication`, `browserBased` (real Chromium), `replacer`, `sequence-import`, `sequence-activeScan`, `graphql`, `postman`, `script`, `alertFilter`, `spiderClient`. Wiring these unlocks ~80% of v2.1 capability.
- Source: [ZAP AF docs](https://www.zaproxy.org/docs/automate/automation-framework/), [ZAP auth methods](https://www.zaproxy.org/docs/desktop/start/features/authmethods/).

### Autonoma / behavioral testing trend
- Modern critique: DAST scanners "fire payloads, do not understand business rules." Gaps in multi-step workflow + authorization-boundary (BOLA) testing. AI Planner agents reading code → deriving test cases.
- Source: [Autonoma blog](https://getautonoma.com/blog/dast-tools).

## Landscape Synthesis

**Table-stakes** in 2026 DAST: authenticated scans (form + JWT + recorded multi-step), real headless-Chromium SPA crawling, active body fuzzing, REST + GraphQL ingestion, scope/exclusion controls, scheduling, CI/CD fail-build, compliance reports, finding triage workflow.

**Frontier**: proof-based / 0-FP scanning (Invicti, Mayhem); AI-recorded login sequences (Burp); behavioral / business-logic testing (Mayhem, Autonoma); auto-remediation PRs (Aikido); AI fix-guidance per finding (StackHawk, Bright).

**Whitespace**: DAST × SCA × SAST cross-link with code-aware reachability path (closest is Snyk Connected Reachability for SCA→SAST only); open-core self-host DAST (only ZAP + Wapiti are OSS); programmable policy-as-code on DAST severity; EPD-aware DAST prioritization deprioritizing auth-protected admin routes.

**Deptex position**: behind on auth + SPA + body fuzzing + scheduling + scope; at parity on baseline ZAP + redaction + severity tagging; **ahead on the SCA Confirmed Exploitable badge** (the structural moat we extend in v2.3).

**Feasibility verdict**: all engineering. ZAP Automation Framework already exposes `browserBased`, `authentication`, `replacer`, `sequence-import`, `graphql`, `postman`, `script`, `alertFilter` jobs we have not wired. Top risks:
1. Headless Chromium memory cost on Fly (~1GB extra per scan) — likely needs `performance-4x` for SPA scans.
2. Recorded-login fragility — login flows break on UI redesigns; need clear failure-mode policy.
3. Encrypted credential storage per-target — reuse the BYOK AES-256-GCM pattern from `organization_ai_providers`.
4. Hybrid engine result dedup — ZAP and Nuclei may report the same CVE; need a dedup pass keyed on (cwe_id, endpoint_url, vulnerability_type) before insert.
5. Active fuzzing against state-changing endpoints in staging can corrupt data — operators must explicitly opt in per target; document this clearly.

## User Stories

- As a **security engineer at a mid-market SaaS**, I want to scan our authenticated staging app for OWASP Top 10 issues weekly, so that I catch new vulnerabilities before they reach prod.
- As a **security engineer**, I want DAST findings on routes that load known-vulnerable dependencies to be flagged Confirmed Exploitable, so that I triage them first.
- As an **org admin**, I want to schedule recurring DAST scans against multiple environments (staging, preview, prod), so that I don't have to manually trigger every run.
- As a **developer reading a DAST finding**, I want the finding to point me to the handler file + function + line + linked SCA OSV ID + linked SAST source line, so that I know exactly where to look.
- As an **org admin**, I want EPD-aware prioritization that downranks DAST findings on internal admin handlers, so that the queue surfaces the public-facing, unauthenticated risks first.

## Locked Scope Decisions

### Phase split & ordering
1. **Three phases by capability bucket: v2.1 Engine → v2.2 Workflow → v2.3 UX + moat.** Each ships independently usable. _Reason: Henry's preference for capability-bucket slicing over urgency or competitive-moat-first._
2. **Parity-first, whitespace second.** v2.1 + v2.2 close the table-stakes gap with Snyk/Endor; v2.3 leans into the SCA × SAST cross-link + EPD moat. _Reason: catching up before differentiating prevents the v3 brainstorm from being "fix the basics."_

### Phase v2.1 — Engine
3. **Hybrid engine: ZAP (active) + Nuclei (template-based) — same machine, sequential, separate `scan_jobs.type` rows.** Each DAST scan request fans out to two scan_jobs (`type='dast_zap'` then `type='dast_nuclei'`) claimed back-to-back on the same depscanner machine. Both write to one `project_dast_findings` table with a new `engine` column distinguishing them; cross-engine dupes dedup-merged on (cwe_id, endpoint_url, vulnerability_type) before insert. _Reason: review consensus (6+4 personas) — sequential same-machine avoids the OOM risk on `shared-cpu-4x`, separate scan_jobs lets each engine fail/retry independently, and amortizes machine spin-up cost. Locked 2026-05-02 post-/review-plan as a structural correction over the original "parallel inside same machine" framing._
4. **All four authenticated-scan modes ship in v2.1**: form login (ZAP form-based job), JWT/Bearer header injection, recorded login sequence (HAR replay via ZAP `sequence-import`), cookie injection. _Reason: Henry chose all four; the parity gap is "we look like a toy" without complete auth coverage. Recorded-login is the heaviest but unlocks SSO/OAuth use cases we cannot reach otherwise._
5. **SPA support via auto-detect + ZAP browserBased job.** Probe target HTML for Vue/React/Angular/Svelte/Next runtime markers. If detected, switch from AJAX spider to ZAP `browserBased` (real headless Chromium via Selenium). Fly machine size bumps to `performance-4x` for SPA scans. _Reason: explicit "spa" profile adds UX friction; users do not always know whether their app is SPA._
6. **Passive-only `auto` profile; explicit `profile='full'` is the sole active-scan path.** `auto` runs spider + browserBased crawl + passive analysis (no fuzz payloads sent). To trigger active fuzzing the user must explicitly select `full`, which gates through the existing `ActiveScanOptInDialog` destructive-warning flow. _Reason: review consensus (5 personas) — combining the original brief (auto runs full active when reachable) with `auto` being the schema default created a structural hole where first-time users triggered destructive fuzz without seeing the consent dialog. Cutting auto-active-escalation closes the hole at the schema level, no server-side consent gate needed. Locked 2026-05-02 post-/review-plan._
7. **Multi-target per project: ALTER target_url → TEXT[].** Each scan job covers one target; concurrency cap stays per-project (1 active total, not per-target). Schema migration phase24a. _Reason: staging + preview + prod is a common ask; v1 schema already flagged this for v2._
8. **Scope controls in v2.1**: include + exclude regex/glob patterns + header-injection rules (mapped to ZAP `replacer` rules). New `project_dast_config.scope_config` JSONB column. _Reason: common ask ("don't fuzz /admin/destroy-all"; "inject `X-Test-User: scanner`"); ZAP `context.includePaths`/`excludePaths` covers it directly._
9. **Auth failure-mode policy: hard-fail + emit 'authentication_lost' finding.** If `loggedOutIndicator` fires more than 3 times during scan, abort and surface a high-severity special finding type. _Reason: silent soft-fail produces invalid scans that users trust; hard-fail forces them to fix the login flow._
10. **Concurrency caps: 1/project, 5/org** (was 1/3). _Reason: SPA + active + auth scans take longer; +2 org cap absorbs the longer tail without blocking other projects. Plan-tier-tunable in Phase 13._
11. **Encrypted credential storage**: new `project_dast_credentials` table, AES-256-GCM via `AI_ENCRYPTION_KEY`-style env var (`DAST_CREDENTIAL_KEY`). One credential row per (project, target_url) tuple with `auth_strategy` discriminator + JSONB `encrypted_payload`. _Reason: reuse the BYOK encryption pattern from `organization_ai_providers`._
12. **All v2.1 features open-core / self-hostable.** Auth, SPA, body fuzzing, scope all available in self-host depscanner image. _Reason: Henry's open-core stance — hardest open-core bar wins long-term._

### Phase v2.2 — Workflow
13. **Scheduling cadence**: manual / daily / weekly / on-deploy webhook. Mirrors `vuln_check_frequency` pattern; QStash cron similar to vuln-monitor. _Reason: simple presets cover 95% of needs; raw cron expressions defer to future power-user work._
14. **Findings management workflow matches SCA**: `status` (open/suppressed/risk_accepted/fixed) + `risk_accepted_reason` + `assignee_id` + `sla_due_at`. Single mental model across SCA/SAST/DAST. Reuses Phase 15 SLA infrastructure when ready. _Reason: Henry confirmed parity with planned SCA UX; one workflow per finding type fragments the experience._
15. **DAST findings flow into the flow-code editor as an event source** (Track E flow-builder integration). DAST event types: `dast.finding.created`, `dast.finding.confirmed_exploitable`, `dast.scan.completed`, `dast.scan.failed`. _Reason: this is how policy applies to DAST findings without building a dedicated PR check; piggybacks on the flow-code-editor that ships in Track E._
16. **Aegis Fix Agent integration: deferred / opportunistic.** No DAST-specific Aegis work in v2.2. When Aegis Fix Agent ships its DAST awareness, it will read existing `project_dast_findings` rows; no schema work needed in v2.2 to enable it. _Reason: Henry's call — Aegis isn't built; pre-baking DAST/Aegis hooks before Aegis exists guesses wrong._
17. **Dedicated DAST policy / PR check: deferred** until Henry redesigns the org `pr_check_code` sandbox. v2.2 surfaces DAST findings into flows; PR-blocking semantics get re-decided when the broader policy code redesign happens. _Reason: don't fork the policy story for DAST when org policy is itself in flux._
18. **Concurrency / cost guards on scheduled scans**: scheduled-source scans count against the same 1/project + 5/org caps; if a manual scan is in flight when cron fires, scheduled run logs as `skipped_concurrency` rather than queuing. _Reason: prevents schedule pile-up; users see why a run was skipped._

### Phase v2.3 — UX + moat
19. **SAST cross-link**: ALTER `project_semgrep_findings` ADD COLUMN `containing_function_name`. Tree-sitter extractor pass populates from existing AST data. Cross-link join: when DAST handler resolves AND a Semgrep finding exists at the same `(file_path, containing_function_name)`, surface `linked_sast_finding_id` + extend `cross_link_metadata.match_method` with `'route_flow_sast'`. Confirmed Exploitable badge fires when DAST + SAST + same handler align (in addition to the SCA path). _Reason: simplest schema change that reuses v1's join logic; full triple-cross-link via taint flow path waits for Phase 6.5._
20. **Per-finding detail page** (drill-in from findings table): full payload + response evidence + cross-link path visualization (DAST → handler → SCA OSV / SAST source) + risk-accept/suppress controls. Drill-in from both Settings → Scanning history and Security tab DAST section. _Reason: single-row table view loses information; users need a full context page to triage confidently._
21. **EPD-aware DAST prioritization**: `displayed_severity = base_severity × epd_factor`. Endpoint classifier (PUBLIC_UNAUTH / PUBLIC_AUTH / AUTH_INTERNAL / AUTH_ADMIN) bundled into v2.3 — not a prerequisite blocking. Classifier reads `project_entry_points` + auth middleware detection to assign a class to each handler. _Reason: Henry chose to bundle the classifier work into v2.3 rather than block on it; it's the foundational piece that enables both EPD and any future authorization-boundary testing._
22. **No VS Code extension, no CLI work in v2.3.** _Reason: Henry explicitly not interested. Keep v2.3 focused on UX surface that matters in the web app._
23. **No compliance reporting work in v2.3.** Defer to Phase 15 (SLA) / Phase 12 (docs). DAST findings flow into Phase 15's compliance pack automatically once that ships. _Reason: avoids parallel-forking the compliance work; ships when the rest of compliance ships._

## Data Model

### v2.1 — Engine
- `ALTER TABLE project_dast_config ALTER COLUMN target_url TYPE TEXT[]`. Add `scope_config JSONB DEFAULT '{}'` (shape: `{ include_patterns: [], exclude_patterns: [], header_rules: [{ name, value, scope }] }`).
- New `project_dast_credentials` (id, project_id, organization_id, target_url, auth_strategy ENUM('form','jwt','recorded','cookie'), encrypted_payload BYTEA, encryption_key_version INTEGER, created_at, updated_at, UNIQUE(project_id, target_url)). RLS by org_id.
- `ALTER TABLE project_dast_findings ADD COLUMN auth_state TEXT` (`anonymous` | `authenticated` | `authentication_lost`).
- `queue_scan_job` RPC: org cap raises from 3 → 5 for type='dast'. Per-project stays 1.
- New `commit_dast_run` parameter: `p_target_url` so multi-target scans flip per-target pointers (active_dast_run_id becomes JSONB keyed by target_url).
- Nuclei templates ship inside the depscanner Docker image (~50 MB layer, pinned to a specific Nuclei release).

### v2.2 — Workflow
- New `project_dast_schedules` (id, project_id, target_url, frequency ENUM('manual','daily','weekly','on_deploy'), qstash_schedule_id, last_run_at, next_run_at, enabled).
- `ALTER TABLE project_dast_findings ADD COLUMN assignee_id UUID REFERENCES auth.users(id), ADD COLUMN sla_due_at TIMESTAMPTZ`.
- New flow-builder event types in `flow_event_types`: `dast.finding.created`, `dast.finding.confirmed_exploitable`, `dast.scan.completed`, `dast.scan.failed`.

### v2.3 — UX + moat
- `ALTER TABLE project_semgrep_findings ADD COLUMN containing_function_name TEXT, ADD COLUMN containing_function_start_line INTEGER, ADD COLUMN containing_function_end_line INTEGER`. Backfill from a one-shot extractor pass; require for new findings going forward.
- `ALTER TABLE project_dast_findings ADD COLUMN linked_sast_finding_id UUID REFERENCES project_semgrep_findings(id) ON DELETE SET NULL`.
- New `project_endpoint_classifications` (project_id, entry_point_id, class ENUM('public_unauth','public_auth','auth_internal','auth_admin'), confidence NUMERIC, classifier_metadata JSONB). Populated by extractor pass.
- `ALTER TABLE project_dast_findings ADD COLUMN epd_factor NUMERIC, ADD COLUMN displayed_severity TEXT`. Computed at finding-insert time; no DB trigger.

## API Endpoints

### v2.1 — Engine
- `GET /api/projects/:projectId/dast/config` — extend response: `target_urls[]`, `scope_config`, `auth_strategies` summary per target.
- `PUT /api/projects/:projectId/dast/config` — accept `target_urls[]`, `scope_config`. RBAC: `manage_projects`.
- `GET /api/projects/:projectId/dast/credentials/:targetUrl` — auth: `manage_projects`. Returns redacted credential metadata only (never the encrypted payload).
- `PUT /api/projects/:projectId/dast/credentials/:targetUrl` — accept `auth_strategy` + `payload` (form: username/password; jwt: token; recorded: HAR JSON; cookie: cookie string). Encrypt server-side. Re-encryption on rotation supported via `encryption_key_version` bump.
- `DELETE /api/projects/:projectId/dast/credentials/:targetUrl` — RBAC: `manage_projects`.
- `POST /api/projects/:projectId/dast/scan` — body adds `target_url` (when project has multiple targets) + optional `auth_strategy_override`.

### v2.2 — Workflow
- `GET /api/projects/:projectId/dast/schedules` — list schedules.
- `PUT /api/projects/:projectId/dast/schedules/:targetUrl` — set frequency + on_deploy hook.
- `PATCH /api/projects/:projectId/dast/findings/:findingId` — update `status`, `risk_accepted_reason`, `assignee_id`. Reuses SCA findings PATCH shape.
- Webhook: `POST /api/webhooks/github/deployment` already exists; extend to fire `dast.scan.queue` for projects with `frequency='on_deploy'`.

### v2.3 — UX + moat
- `GET /api/projects/:projectId/dast/findings/:findingId` — single-finding detail with cross-link path expansion (`linked_sca_*` + `linked_sast_finding_id` joined to source-line code).
- `GET /api/projects/:projectId/endpoint-classifications` — list classifier output for the project (used by Security tab + EPD UI).

## Frontend Surface

### v2.1 — Engine
- **Settings → Scanning tab** (`DastScanningTab.tsx`) restructured: target list (add/edit/remove URLs); per-target auth panel (strategy picker + credential form); scope panel (include/exclude regex + header rules); profile + timeout per target. Concurrency cap text updates to "1 active per project, 5 across the org."
- New **Recorded login wizard** dialog: paste-as-HAR or in-browser-extension recording flow (extension build is its own follow-up; v2.1 ships HAR paste + JSON validator).
- Active-scan opt-in toast: when user enables active scanning against a target, show a destructive-warning dialog matching `feedback_dialog_pattern` ("Active scans send fuzz payloads to state-changing endpoints. Use staging only.").

### v2.2 — Workflow
- **Schedules card** in Scanning tab: per-target frequency picker (manual/daily/weekly/on_deploy) + last-run + next-run + skipped-concurrency badges.
- **Findings management drawer** on Security tab DAST section: status dropdown, reason textarea, assignee picker (org members), SLA countdown badge.
- **Flow-builder event source**: DAST appears alongside SCA/Semgrep/TruffleHog as a trigger source. Event payload schema rendered in flow-code-editor's Monaco hover docs.

### v2.3 — UX + moat
- **DAST finding detail page** at `/organizations/:orgId/projects/:projectId/security/dast/:findingId`. Three-column layout: (1) request/response with redacted-payload toggle, (2) cross-link path visualization (handler → SCA OSV / SAST source code excerpt), (3) triage controls.
- **EPD badge** on findings table rows: green ("Internal — auth admin"), yellow ("Auth internal"), orange ("Public auth"), red ("Public unauth"). Sort/filter on this attribute.
- **Confirmed Exploitable badge expansion**: now shows "SCA + SAST" when both cross-links resolve.

## User Flows

### Configure authenticated scan for staging (v2.1)
1. User opens Settings → Scanning tab, project has prod target_url already.
2. Clicks "Add target" → enters `https://staging.example.com`.
3. Selects auth strategy = "Recorded login (multi-step)".
4. Clicks "Record login" → wizard prompts to either paste HAR JSON or "Open recorder browser extension" (deferred).
5. Pastes HAR; UI validates the file shape, surfaces detected URL + form parameters.
6. Sets `loggedInIndicator` = "Logout" link regex (auto-suggested from HAR replay).
7. Clicks Save — backend encrypts the HAR + indicator regex into `project_dast_credentials`, redacted-summary returns to UI.
8. Clicks "Scan now" → depscanner machine boots, `commit_dast_run` flips per-target active pointer.

### Schedule weekly scan (v2.2)
1. User opens Scanning tab → Schedules card.
2. For target `staging.example.com`, picks frequency = "Weekly (Sunday 02:00 UTC)".
3. Backend creates QStash schedule; `qstash_schedule_id` stored.
4. Each Sunday QStash fires; backend checks for in-flight scans (skip if so), otherwise queues a `scheduled` scan_job.

### Triage Confirmed Exploitable finding (v2.3)
1. User clicks finding row in Security tab → DAST detail page.
2. Page shows: SQLi against `POST /api/users/:id` → handler `routes/users.ts:42` (`updateUser`) → linked SCA: `CVE-2024-12345` on `mysql2@3.0.0` → linked SAST: `routes/users.ts:51` (raw SQL concatenation, Semgrep `sql-injection-raw`).
3. EPD badge: "Public auth" (yellow).
4. User clicks "Risk accept", types reason "Mitigated by WAF rule WAF-2024-08", picks assignee, sets SLA → 30 days.
5. Status carries forward through `commit_dast_run` on the next scan thanks to v1's stable-identity dedup.

## Edge Cases & Failure-Mode Policy

- **Recorded login fails mid-scan**: hard-fail, emit `authentication_lost` finding (v2.1 decision 9).
- **Active fuzz against state-changing endpoint corrupts staging data**: not technically preventable; document loudly + require operator opt-in per target. Future hardening: a `read_only_active_scan` boolean that disables payloads on POST/PUT/DELETE.
- **Nuclei + ZAP report the same CVE**: dedup-merge before insert keyed on `(cwe_id, endpoint_url, vulnerability_type)`; pick the higher-confidence rule_id, merge `cross_link_metadata.engine` array.
- **SPA detection false positive (target has React script tags but isn't actually SPA)**: browserBased job runs but produces few findings; cost is wasted ~5min scan time. Mitigation: cache detection result in `project_dast_config.detected_runtime` so repeat scans skip detection.
- **Schedule fires while manual scan in-flight**: log `skipped_concurrency` in `scan_jobs.error_category`, don't queue, surface in Schedules card UI.
- **HAR payload contains plaintext credentials**: encrypt at rest; never echo back to the UI; redact in logs; add a HAR-sanitizer pre-encryption pass that strips `Authorization: Basic …` and obvious password fields from any embedded request bodies.
- **Multi-target finding from prod target accidentally rolls into staging's active set**: per-target dast_run_id pointer; commit_dast_run takes a target_url parameter; `projects.active_dast_run_id` becomes JSONB `{ "https://staging.example.com": "dast_xyz", "https://prod.example.com": "dast_abc" }`.
- **Endpoint classifier disagrees with itself across runs**: store classifier_version + recompute on extraction; if classification flips, log a `endpoint_class_changed` event — Aegis can investigate later.
- **Self-hosted deployment without QStash for schedules**: schedules table marks rows `mode='self_host'`; a self-host cron container polls schedules every minute. Avoids the QStash dependency for OSS users.

## Non-Functional Requirements

- **SPA scan duration ceiling**: 45 min hard cap (was 30 min in v1) for `browserBased` profile. Quick + baseline stay 30 min.
- **Memory**: SPA scans run on `performance-4x` (8 GB RAM). Quick/baseline/active stay on existing `performance-1x`.
- **Findings volume**: support ≥10K findings per project without UI degradation (use cursor-based pagination on findings detail navigation).
- **Cross-link rate target**: ≥30% of DAST findings cross-linked to SCA OR SAST handler (v1 baseline ≈5% from observed test data).
- **OWASP coverage target**: ≥80% of OWASP Web Top 10 + ≥60% of OWASP API Top 10 detectable on a representative test target (Juice Shop / DVWA / OWASP API Security Project test app). API1/3/5/6/10 are explicitly DAST-blind classes; 60% acknowledges that.
- **Open-core**: all v2 features must function in self-host depscanner image without cloud-only dependencies. AI-assisted features (recorded-login auto-suggestion, fix guidance) hit BYOK or local-LLM endpoints via `baseURL` per Henry's open-core stance.

## RBAC Requirements

- `manage_projects` — required to: edit DAST config, save credentials, trigger manual scans, configure schedules, change scope rules. (Same as v1.)
- `view_all_teams_and_projects` — required to: read DAST findings, scan history. (Same as v1.)
- New: `manage_credentials` (sub-permission of `manage_projects`) for the credential CRUD endpoints; if not granted, user sees redacted credential summary but cannot create or rotate. _Open question: should this be a separate permission or stay folded into `manage_projects`?_

## Dependencies

- **Phase 6.5 (cross-file taint engine)** — not a hard prereq for v2.3 SAST cross-link, but the eventual triple-link (DAST → SAST source → SCA sink via taint path) needs Phase 6.5 merged. v2.3 ships `route_flow_sast` (handler-level join only) without it.
- **Track E (flow-code-editor)** — v2.2 decision 15 (DAST as flow event source) requires the flow-builder runtime. If flow-builder slips, v2.2 still ships scheduling + findings management; flow-builder integration becomes a v2.2.5 follow-up.
- **Phase 18 (developer touchpoints)** — explicitly skipped in v2.3 per decision 22; flagged for transparency only.
- **Phase 13 (billing)** — concurrency cap `5/org` is a sensible default; plan-tier-tunable hooks land in Phase 13. v2.1 hardcodes 5.
- **Phase 15 (SLA)** — `sla_due_at` column lands in v2.2; full SLA computation + breach detection waits for Phase 15.
- **AES-256-GCM encryption pattern** — `organization_ai_providers` already provides it; reuse `backend/src/lib/crypto/byok-encryption.ts` (or whatever it's named at v2.1 implementation time) for `project_dast_credentials`.

## Success Criteria

- **OWASP Web Top 10 detection ≥ 80%** measured against Juice Shop with auth + active + browserBased profile.
- **OWASP API Top 10 detection ≥ 60%** measured against the OWASP crAPI / VAmPI test apps.
- **Cross-link rate ≥ 30%** of DAST findings on a project with both SCA findings + tree-sitter reachability data populated.
- **Scheduled scan success rate ≥ 99%** over a 30-day window (excluding skipped_concurrency).
- **Authenticated scan success rate ≥ 95%** for the four supported strategies (form, JWT, recorded, cookie) on canonical test apps.
- **Nuclei + ZAP dedup precision ≥ 95%** (manual review of 200 sample findings: ≤10 dupes slipped through).
- **Self-host parity** — depscanner Docker image runs all v2 scan modes on a developer laptop without cloud dependencies (including schedules via the self-host cron container).

## Open Questions

- **Q1 (can defer to /implement):** Recorded login HAR format — accept ZAP's native sequence-import JSON (XML-like), Burp's recorded login JSON, or a Deptex-canonical HAR shape with a normalizer? Affects v2.1 wizard implementation only.
- **Q2 (can defer to /implement):** Should `project_dast_credentials.encryption_key_version` default to 1 or pull from a `dast_credential_encryption_keys` table at insert time? Mirrors `organization_ai_providers.encryption_key_version` decision; keep both consistent.
- **Q3 (can defer to /implement):** Endpoint classifier confidence threshold for EPD multiplier application — at what classifier confidence do we apply the EPD factor vs fall back to base severity? Empirical decision once classifier ships.
- **Q4 (can defer to /implement):** `manage_credentials` as separate permission vs folded into `manage_projects` — Henry's call during planning.
- **Q5 (informational, blocks nothing):** Phase 6.5 cross-file taint engine merge timing — affects when triple-link DAST → taint-flow → SCA can ship. Out of v2 scope; mention only.
- **Q6 (can defer to /implement):** Dedup-merge precedence between ZAP and Nuclei when both report same CVE — prefer ZAP rule_id (higher confidence on active scan) or Nuclei (higher coverage on templates)? Empirical question.
- **Q7 (can defer to /plan-feature):** Self-host cron container — single binary that polls all schedules tables across the deployment, or per-table cron worker? Architectural call during v2.2 planning.

## Recommended Next Step

`/plan-feature dast-v2-1a-engine` — v2.1 was re-segmented post-`/review-plan` (REWORK 12/0/0 verdict 2026-05-02) into v2.1a (additive engine foundation), v2.1b (destructive migration cleanup after ≥7-day shadow), v2.1c (Nuclei split — its own scan_jobs.type), v2.1d (recorded-login HAR — deferred until first SSO ask). v2.1a is the foundation phase: ZAP-only with auth modes + SPA detect + multi-target additive schema + scope rules + three-layer cross-tenant validation + worker hard-fail on missing/stale `DAST_CREDENTIAL_KEY` + per-scan `credential_id`+`payload_hash` audit + DAST_CONFIG branched on detected_runtime + passive-only `auto` profile. v2.2 + v2.3 each get their own `/plan-feature` invocation post-shipping v2.1.
