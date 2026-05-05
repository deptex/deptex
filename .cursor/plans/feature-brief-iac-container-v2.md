# IaC + Container Scanning v2 — Feature Brief

> Status: brainstorm output, 2026-05-02. Next step: `/plan-feature` against **Phase 1** only. Phases 2-4 each get their own `/plan-feature` run when their turn comes.

## Problem Statement

v1 (merged 2026-04-30, PR #21) shipped a deliberately narrow foundation: Trivy + Checkov for **Terraform / Kubernetes / Dockerfile only**, ghcr.io via GitHub App, no per-project registry creds, no scan cache, no Aegis integration. v2 is the "final form" push that takes Deptex from "we have the basics" to category leadership: full table-stakes coverage parity with Snyk / Aikido (Phase 1), open-core static container reachability + IaC↔code cross-file taint that Endor's instrumentation-based approach can't match without a privileged runtime sensor (Phase 2), differentiated custom-policy authoring in JS (Phase 3), and Aegis-driven autofix with verify-before-PR that beats Aikido / GitHub Copilot Autofix (Phase 4). Phased delivery keeps each PR reviewable; the cumulative result is the most complete IaC + container scanning experience in the open-core space.

## Current State in Deptex

**v1 shipped surface (all in `main` as of 2026-04-30):**
- `backend/database/phase25_iac_container_scanning.sql` — `project_iac_findings`, `project_container_findings`, `projects.infra_types`, `enforce_finding_org_id` trigger, `finalize_extraction` RPC carry-forward extension.
- `backend/depscanner/src/scanners/` — orchestrator, detect-infra (TF/K8s/Dockerfile only), checkov adapter, trivy adapter, storage upserts, types.
- `backend/extraction-worker/Dockerfile` — Checkov in `/opt/checkov-venv`, Trivy 0.69.3, GuardDog venv (from malicious-packages merge).
- `backend/src/routes/scanner-findings.ts` — list + ignore + risk-accept.
- `frontend/src/components/security/VulnerabilityExpandableTable.tsx` — IaC + container row variants alongside semgrep/secrets/dep-vuln.
- `frontend/src/components/security/InfraFindingCard.tsx`, `ScannersPanel.tsx` — finding card + project-settings panel.
- Kill switches: `kill:scanner:trivy`, `kill:scanner:checkov` in Redis (1s timeout, soft-fail).
- Feature flags: `SCANNERS_IAC_ENABLED`, `SCANNERS_CONTAINER_ENABLED`, `SCANNERS_ROLLOUT_ALLOWLIST`.

**What's rudimentary:** narrow IaC format coverage; ghcr.io is the only authenticated registry; no scan cache (every extraction re-pulls every base image); compliance refs aren't surfaced in UI; no path-based asset tiering; no reachability filtering of base-image CVEs (the Endor pain point we set up to attack but didn't ship).

**What's missing entirely:** Helm, CFN, ARM, Bicep, Serverless, SAM, CDK; ECR/GCR/ACR/Docker Hub/Quay/Harbor/JFrog/custom registries; static container reachability; IaC↔app-code cross-file taint; custom IaC policies; base-image upgrade advisor; SBOM diff on PR; Aegis IaC autofix; Aegis chat tools for IaC; public benchmark/leaderboard.

## Competitive Landscape (refreshed 2026-05-02)

### Endor Labs — full-stack reachability now GA, **runtime-instrumented**
- The Feb 2026 Autonomous Plane acquisition shipped to docs by April. Mechanism: lightweight ptrace sensor embedded in container images, observes file access + process activity during sandbox execution, writes `creport.json` mapping runtime file usage to OS packages.
- **Explicitly runtime-dependent**, not static-only — needs Docker API 1.48+, privileged container access for ptrace.
- Published noise reduction on real OSS images: Consul 90% unreachable, nginx 78%, fluentd 82%, redis 75%.
- Sources: [Endor docs — Instrumented container reachability](https://docs.endorlabs.com/scan/containers/instrumented-reachability/), [Endor blog — Full Stack Reachability](https://www.endorlabs.com/learn/introducing-full-stack-reachability-container-scanning-that-actually-reduces-noise).
- **Strategic implication for Deptex:** static-only reachability (no privileged sensor, no runtime instrumentation) is a legitimate differentiated wedge if the false-positive reduction is even close. Open-core + no-runtime-required is the open-source-friendly framing.

### Snyk IaC + Container — table-stakes parity target
- Coverage: Terraform, CFN, ARM, K8s, Helm, Docker, OPA. Custom rules in OPA Rego, Enterprise-tier only.
- Container: Docker Hub, ECR, ACR, GCR, JFrog Artifactory, Harbor, Quay. Runtime monitoring across EKS / AKS / GKE / OpenShift (Enterprise).
- Auto-fix: actionable in-code remediations, PR comments via Git integration. **Doesn't verify the fix** — opens the PR and hopes.
- Sources: [Snyk IaC](https://snyk.io/product/infrastructure-as-code-security/), [Snyk Container](https://snyk.io/product/container-vulnerability-management/).

### Aikido — closest analogue + AI Autofix
- Coverage: Terraform, CFN, K8s, Helm, ARM, Bicep. CSPM + container + SAST + SCA + secrets + DAST + license + malware bundled.
- "AI AutoFix" generates patches and opens PRs in one click. Aggressive freemium pricing.
- Source: [Aikido IaC](https://www.aikido.dev/code/infrastructure-as-a-code-iac).

### Prisma Cloud — Bridgecrew/Checkov upstream
- Custom policies in Python / YAML / UI editor + graph-based multi-resource policies.
- "Smart Fixes" trace cloud misconfigs back to originating IaC.
- Source: [Prisma Cloud IaC](https://www.paloaltonetworks.com/prisma/cloud/infrastructure-as-code-security).

### Wiz — code-to-cloud correlation
- Bidirectional runtime↔code feedback. Drift detection between declared IaC and observed cloud state. Requires connected cloud accounts.
- Source: [Wiz IaC](https://www.wiz.io/academy/application-security/iac-security).

### GitHub Advanced Security (March 2026 launch)
- AI-powered detections in PR review. Coverage now: Terraform + Dockerfiles + Shell + Bash + PHP. Copilot Autofix bridges detection → remediation.
- Source: [Help Net Security coverage](https://www.helpnetsecurity.com/2026/03/24/github-ai-powered-detections-code-scanning/).

### Anchore — counter-position worth knowing
- Public stance: "reachability is becoming a noisy, diminishing metric." Pivots to "high-velocity hygiene" — fast upgrades, hardened images, CompOps.
- Critique angles: volume of CVEs growing faster than reachability filtering; weakly-typed languages (Python, Node.js) cause precision drops; "living off the land" attackers exploit code paths developers don't use.
- Source: [Anchore 2026 directions](https://anchore.com/blog/no-crystal-ball-but-2026-directions/).
- **Strategic implication:** reachability-only v2 is risky. Pair with hygiene levers (autofix, base-image advisor, SBOM diff). Already accommodated in the locked plan.

### Trivy "Next-Gen" 2026
- Announced on trivy.dev landing page. No public docs yet on what's included.
- Source: [Trivy](https://trivy.dev/).

## Landscape Synthesis

**Table-stakes (everyone has):** Terraform/K8s/Helm/CFN/Dockerfile coverage; container CVEs with EPSS/KEV/CVSS prioritization; suppress-as-code; PR comments; CIS/SOC2 mapping; AI-fix PRs (Snyk, Aikido, GitHub).

**Frontier (2-3 vendors):**
- Endor: instrumented container reachability with published noise-reduction benchmarks.
- Wiz / Prisma: code-to-cloud correlation and drift detection (cloud-cred-required).
- Aikido / GitHub: AI-driven IaC autofix (one-shot, no verification).

**Whitespace nobody owns:**
1. **Static-only container reachability** — Endor needs ptrace at runtime. Static joining of SCA call graph + image SBOM + tree-sitter usage = same idea, no privileged sensor, open-core friendly.
2. **IaC ↔ app-code cross-file taint** — "this S3 misconfig + this Lambda reads it + this handler takes user input." Phase 6 cross-file engine is the substrate; nobody else has anything analogous.
3. **Aegis IaC autofix that verifies itself** with `terraform validate` / `kubeval` / `kustomize build` / `cfn-lint` before opening PR.
4. **Custom IaC policy in JS** via the existing sandboxed engine (vs Snyk Enterprise-only Rego).
5. **Public benchmark / leaderboard** of container reachability — dataset moat + marketing wedge once item F exists.

**Deptex position today:** behind on table-stakes (v1 only covers TF/K8s/Dockerfile), uniquely positioned for whitespace because of pre-built engine pieces (tree-sitter usage data, Phase 6 cross-file taint, Aegis Fix Agent, JS policy engine, BYOK AI).

**Feasibility verdict + top risks:**
- **F (static container reachability):** known-hard, especially for dynamically-typed languages. Risk of high false-positive *and* false-negative rate against Endor's instrumented numbers. Mitigated by (a) shipping reachability *levels* not boolean, like the existing 5-tier taxonomy, and (b) pairing with hygiene levers per Anchore's critique.
- **G (IaC↔code taint):** depends entirely on Phase 6 engine being production-stable post-6.5 cutover. Hard prereq; do not start until the post-6.5 hardening pass lands.
- **C/D/E (registry expansion + cache + configured images):** known-tractable, mostly adapter glue + tenancy-correct encrypted storage. Lowest risk in the plan.
- **M (Aegis IaC autofix):** known-tractable on top of the shipped Aegis Fix Agent. Risk concentrated in validator availability across IaC formats (cfn-lint and arm-ttk are less mature than terraform validate / kubeval).

## User Stories

- As a **developer**, I want my Helm charts and CloudFormation templates scanned the same way my Terraform is, so I have one security signal across all my infra.
- As an **org admin**, I want to attach AWS / GCP / Azure / private Docker registry creds per project, so we scan production images, not just public bases.
- As a **security engineer**, I want a "reachable" filter on container CVEs so I'm not drowning in 1000 base-image findings — I want the 50 my app actually loads.
- As a **security engineer**, I want IaC misconfigs that are actually exploitable (S3 bucket reachable from a Lambda that takes user input) prioritized over abstract misconfigs.
- As an **org admin**, I want to write company-specific IaC policies in JS (not learn Rego), and run them in our existing policy editor.
- As a **developer**, I want Aegis to fix my Terraform misconfig and verify the fix passes `terraform validate` before opening a PR — so I'm not reviewing broken plans.
- As a **developer**, I want to ask Aegis "what's wrong with my K8s manifests" and get a real answer, not a doc lookup.
- As a **CTO/marketing**, I want a public reachability benchmark so I have a data-driven story for why Deptex's prioritization beats the noise.

## Locked Scope Decisions

### Master directive (Round 1 confirmed)
**v2 is the "most complete IaC + container scanning possible," delivered as 4 phases. Aegis fixing is the last phase.** Henry confirmed all 15 backlog items in scope; phasing sequences value delivery.

### Decision 1: Phase ordering — Coverage → Reachability → Policy → Aegis
**Why:** plumbing first lets reachability ship against the widest format coverage, policy ships against the widest finding surface, and Aegis ships against everything. Each phase delivers independent user value; Aegis caps the work because it's the highest-leverage / highest-risk piece and benefits from everything before it being stable.

### Decision 2: 4 PRs, ~10-13 weeks calendar, May 2 → mid-August
**Why:** matches the v1 cadence (single PRs, ~2-4 weeks each). Avoids the 8-10-week mega-PR rebase exposure and the 5-PR coordination overhead.

### Decision 3: v2 Phase 1 starts now in parallel with Phase 6.5; item G waits for post-6.5 hardening
**Why:** Phase 1 (coverage / plumbing) doesn't touch the reachability engine — fully decoupled from the Phase 6.5 cross-file taint cutover that's in flight on Track A. Item G is the only hard prereq because it literally extends Phase 6's engine across the IaC↔code boundary; building against shadow-mode atom-coupled output would mean rework after the post-6.5 hardening pass lands.

### Decision 4: Phase 1 IaC format coverage — full table-stakes parity
**Locked formats:** Terraform (v1) + Kubernetes (v1) + Dockerfile (v1) + **Helm + CloudFormation + Azure ARM + Bicep + Serverless framework + AWS SAM + AWS CDK**.

**Why:** Trivy + Checkov already support all of these natively — work is mostly adapter glue + framework detection + scanner-config UI surfacing. Tighter scopes (Helm-only, or Helm+CFN+Bicep) leave persistent "we don't support that format" objections that erode Phase 1's "complete coverage" framing. Helm requires render-then-scan with default `values.yaml`; project-supplied values files defer to a later iteration if false-negatives surface.

### Decision 5: Phase 1 GitHub Actions workflow scanning — Trivy/Checkov native only
**Why:** Both scanners have some GH Actions support natively. Adding a third scanner (Scorecards / KICS) means another Python venv or Go binary in the image, plus another findings-table type. Trade scanner depth for image-size / complexity discipline. Known gap: less coverage of action-pinning, harden-runner, and pull_request_target patterns than StepSecurity. Revisit as a focused Phase B follow-up if FP/FN data justifies it.

### Decision 6: Phase 1 registry expansion — full coverage
**Locked registries:** ghcr.io (v1) + **AWS ECR + Google Artifact Registry / GCR + Azure ACR + Docker Hub private + Red Hat Quay + Harbor (self-hosted) + JFrog Artifactory + custom (generic Docker Registry v2)**.

**Why:** matches Snyk's full registry coverage, eliminates the "we don't support that registry" objection. Architecturally identical (all registries share the per-project-encrypted-creds + DOCKER_AUTH_CONFIG pattern); only difference is the cred shape per registry. Per-project encrypted creds via `AI_ENCRYPTION_KEY` (same pattern as `organization_ai_providers`).

### Decision 7: Phase 1 image-digest scan cache — global Postgres, 7-day TTL
**Why:** at scale, every project pulling `node:20-bullseye` re-scans the same base layer. Digest is content-addressed so global tenancy is safe. 7-day TTL catches new CVEs published against unchanged digests. Building it into Phase 1 (vs deferring) avoids a forced data-migration when usage hits the threshold and lets Phase 2 reachability assume cache hits (digest → SBOM lookup is the join's hot path).

### Decision 8: Aegis IaC autofix is Phase 4, not earlier
**Why:** Aegis fix needs the validator to exist. Validators land naturally as part of Phase 1 (we'll have `terraform validate` / `kubeval` / `cfn-lint` / `kustomize build` available in the scanner image once those formats are scannable). Aegis fix on a single format is less compelling than Aegis fix across all formats. And there's higher-leverage Aegis work in flight (per `aegis_roadmap.md`) — Phase 4 timing aligns with Aegis bandwidth.

## Phase Decomposition

### Phase 1 — Complete Coverage (~3-4 weeks, starts ~2026-05-02)
| Item | Description |
|---|---|
| A | IaC format expansion: Helm, CFN, ARM, Bicep, Serverless, SAM, CDK |
| B | GitHub Actions scanning via Trivy/Checkov native support |
| C | Registry expansion: ECR, GCR, ACR, Docker Hub, Quay, Harbor, JFrog, custom |
| D | Global image-digest scan cache (Postgres, 7-day TTL) |
| E | Manually configured images (`project_configured_images`) |
| I | Compliance frame mapping (CIS / SOC2 / NIST refs surfaced in finding cards) |

**New tables (sketch — `/plan-feature` confirms):** `project_registry_credentials` (encrypted creds), `project_configured_images` (scan-target list), `container_image_scan_cache` (global digest→SBOM cache). New columns: extend `project_iac_findings.framework` enum with the 7 new format values; possibly `project_iac_findings.compliance_refs JSONB`.

**Out of scope for Phase 1:** anything reachability-related; Aegis integration; custom-policy authoring; Helm with project-supplied values files (defer if no FN signal).

### Phase 2 — Reachability Moat (~3-4 weeks, starts ~end May after Phase 6.5)
| Item | Description |
|---|---|
| F | Static container reachability — join SCA call graph + image SBOM + tree-sitter usage; classify CVEs by `reachable` taxonomy reusing the existing 5-tier (confirmed/data_flow/function/module/unreachable) |
| J | Base-image upgrade advisor — recommend Chainguard / distroless / alpine variants; rides on F's package-usage data |
| L | SBOM diff on PR — "this PR adds 17 OS packages, 3 high CVEs" |
| **G** | **IaC↔code reachability via Phase 6 cross-file taint** — slots in once post-6.5 hardening lands; possibly mid-Phase or rolls into Phase 3 head |

**Hard prereq for G:** Phase 6.5 cutover + post-6.5 hardening pass complete on Track A. Acceptable for items F + J + L to ship without G.

### Phase 3 — Policy + Tiering (~1.5-2 weeks, starts ~end July)
| Item | Description |
|---|---|
| H | Custom IaC policy via existing JS sandboxed policy engine — extend `package_policy_code` / Monaco editor / AI policy assistant to IaC findings |
| K | Path-based asset-tier inference (prod/staging/dev from path heuristics) |
| O | Public reachability benchmark / leaderboard — top 1000 Docker Hub images, % of CVEs reachable |

### Phase 4 — Aegis (~2-3 weeks, starts ~mid August)
| Item | Description |
|---|---|
| M | Aegis IaC autofix with verify-before-PR (`terraform validate` / `kubeval` / `cfn-lint` / `kustomize build`) |
| N | Aegis chat tools (`list_iac_findings`, `explain_iac_misconfig`, `fix_iac_finding`) |

## API Endpoints (sketch)

`/plan-feature` will firm these up per phase. High-level shape per phase:

**Phase 1:**
- Findings API extended with new framework values (no new endpoints).
- `GET/POST/DELETE /api/projects/:id/registry-credentials` — list/add/remove.
- `GET/POST/DELETE /api/projects/:id/configured-images` — list/add/remove.
- Internal worker reads decrypted creds + cache from Supabase directly.

**Phase 2:**
- `GET /api/projects/:id/container-findings?reachable=true|false|level` — filter param extension.
- `GET /api/projects/:id/base-image-recommendations` — paired with finding card.
- PR check extension for SBOM diff.

**Phase 3:**
- Extend existing `/api/organizations/:id/policy-code` endpoints to accept IaC-finding context.
- `GET /api/projects/:id/asset-tier-inferred` (or as a column on existing project response).

**Phase 4:**
- `POST /api/aegis/fix/iac/:findingId` — trigger Aegis IaC fix.
- Aegis tool registry additions (no new HTTP routes).

## Frontend Surface

**Phase 1:**
- `ScannersPanel.tsx` extended with registry-credentials + configured-images sections.
- `VulnerabilityExpandableTable.tsx` extended with new framework chips (Helm / CFN / ARM / Bicep / Serverless / SAM / CDK / GitHub Actions).
- `framework-icon.tsx` extended with the 7 new format icons.
- Compliance refs surfaced as badges on finding cards.

**Phase 2:**
- Reachability filter chips on container findings (reuse the existing 5-tier badges from package CVEs).
- Base-image upgrade advisor card on Dockerfile findings.
- PR-check UI extension for SBOM diff.

**Phase 3:**
- Policy editor (Monaco) extended with IaC-finding sample input + AI-assistant prompts tuned for IaC.
- Project settings: asset-tier override surface (already partial from project tier work).
- Public leaderboard page — separate route, marketing-site-style.

**Phase 4:**
- Aegis fix UI extended for IaC findings (same fix-card pattern as app-code fixes).
- Aegis chat: tools surfaced via existing tool-permission flow + RBAC checks.

**Note:** Henry plans to rename "security tab" → "issues" + combine with compliance, Vercel-env-vars-style (per `security_tab_progress.md`). Phase 1 work should land cleanly into either the current or renamed surface; the rename is independent.

## Edge Cases & Failure-Mode Policy

- **New IaC format scanner fails (e.g., CFN parser crashes on malformed template):** soft-fail / warn pattern — log structured error to `extraction_step_errors`, pipeline continues. Same as v1 Trivy/Checkov failure mode.
- **Registry pull fails (auth invalid, rate-limited, image gone):** log to `extraction_step_errors`, mark image scan as `failed` for that extraction. Surface in ScannersPanel so user sees credential breakage.
- **Image cache stale / digest collision unlikely but possible:** `scanner_version` column invalidates cache on Trivy upgrade. 7-day TTL forces re-pull anyway.
- **Helm rendering with default values produces no output:** treat as "no scan target" — log info, don't error.
- **Reachability engine produces low-confidence verdict (Phase 2):** classify as `module` or `unknown`, never silently mark `unreachable`. False-negatives are existential; false-positives only annoy.
- **Aegis fix's validator unavailable (Phase 4 — e.g., cfn-lint not in image):** fall back to "fix without verify" + warning banner on the PR. Don't block the user.
- **Concurrent re-extractions:** existing `extraction_run_id` upsert-then-soft-switch pattern handles this. New tables follow the same pattern.
- **Encrypted cred decryption fails (`AI_ENCRYPTION_KEY` rotated mid-flight):** surface 500-class error to user via ScannersPanel; never log raw error to user (per `feedback_no_raw_errors_to_users.md`).

## Non-Functional Requirements

- **Scan budget:** combined IaC + container scan adds <8 min wall-clock to typical extractions; <15 min on worst-case (1000+ IaC files + 5+ images). Existing 10-min per-scanner timeout enforced.
- **Image cache hit rate:** target >50% on shared base images across orgs by 30 days post-launch. Measurable via `container_image_scan_cache` `scanned_at` distribution.
- **Reachability false-negative rate (Phase 2):** target <5% on a held-out fixture set. False-positives are tolerable; false-negatives are not.
- **Phase 4 Aegis fix verify pass rate:** >70% of generated fixes pass validator on first try; fall back to "open PR with warning" otherwise.
- **Public benchmark refresh (Phase 3 item O):** monthly run, dashboard updated automatically.

## RBAC Requirements

Existing organization permissions cover most of v2:
- View IaC + container findings: project access.
- Suppress / risk-accept: existing project write permission.
- Configure scanners + registry creds: existing `manage_projects` (team) OR `manage_teams_and_projects` (org).
- View decrypted creds: server-only, never exposed via API.
- Aegis fix (Phase 4): existing `trigger_fix` permission. No new permission needed.
- Custom IaC policy authoring (Phase 3): existing `manage_policies` permission.

**No new permissions added in v2.** This is a deliberate scope choice — RBAC permission proliferation is a known critical-audit failure mode.

## Dependencies

- **v1 IaC + Container Scanning** (PR #21, merged 2026-04-30) — this brief extends the v1 surface, tables, scanner image.
- **Phase 6 cross-file taint engine** (PR #19, merged 2026-04-30, currently shadow-mode) — substrate for item G.
- **Phase 6.5 cutover + post-6.5 hardening** — hard prereq for item G specifically (production cutover replaces atom; output schema changes).
- **Aegis Fix Agent** (PR #17, merged 2026-04-29) — substrate for Phase 4 item M.
- **JS policy engine + Monaco editor + AI policy assistant** — substrate for Phase 3 item H.
- **`AI_ENCRYPTION_KEY`** — already required for BYOK; reused for `project_registry_credentials`.
- **Tree-sitter usage extractor** — substrate for Phase 2 item F (static container reachability).

## Success Criteria

**Phase 1:**
- All 10 IaC formats end-to-end on fixture repos: Terraform / K8s / Dockerfile / Helm / CFN / ARM / Bicep / Serverless / SAM / CDK.
- All 9 registries pull + scan successfully on test creds: ghcr / ECR / GCR / ACR / Docker Hub / Quay / Harbor / JFrog / custom.
- Image cache hit demonstrably reduces re-scan time to ~0 for cache-hit case; cache miss after 7 days re-pulls.
- Compliance refs render correctly on finding cards across all framework types.
- All v1 invariants preserved: kill switches work, fingerprint carry-forward works, finalize_extraction passes new-table-aware migration.

**Phase 2:**
- Static container reachability achieves <5% false-negative on held-out fixture set.
- Reachability filter chips work in the unified findings table.
- Base-image upgrade advisor surfaces ≥1 valid recommendation for top-20 base images.
- SBOM diff PR check renders inline on a real PR.
- Item G: at least 3 working IaC↔code fixture cases (S3+Lambda; SQS+Worker; SecretsManager+API handler).

**Phase 3:**
- A custom JS policy can be authored, saved, and evaluated against IaC findings end-to-end.
- Asset tiering overrides depscore on findings whose path matches `*/prod/*` heuristics.
- Public benchmark page deployed; reflects ≥1000 Docker Hub images scanned.

**Phase 4:**
- Aegis fix on an IaC finding produces a verifying patch + opens a PR for ≥3 IaC formats (TF, K8s, Helm minimum).
- Aegis chat answers `list_iac_findings` / `explain_iac_misconfig` / `fix_iac_finding` correctly with RBAC enforcement.

## Open Questions

| ID | Phase | Severity | Question |
|---|---|---|---|
| OQ1 | Phase 1 | informational | Helm with project-supplied values files vs default-only — defer until FN data justifies it. |
| OQ2 | Phase 1 | informational | Whether `cfn-lint` / `arm-ttk` / `kubeconform` get bundled into the scanner image now (for Phase 4 Aegis fix later) or only at Phase 4. Probably now to avoid a Dockerfile churn later. |
| OQ3 | Phase 2 | blocks /plan-feature for Phase 2 | Static container reachability technique — package-level mapping (cdxgen→image-SBOM join) vs symbol-level (file/function-level loaded-symbol detection). Decide at Phase 2 brainstorm. |
| OQ4 | Phase 2 | blocks /plan-feature for Phase 2 | Item G language scope at first cut — JS/TS + Python only, or all 8 Phase 6 languages. |
| OQ5 | Phase 3 | informational | Path-based asset-tier inference precedence — explicit project tier wins over path heuristic, or vice-versa? |
| OQ6 | Phase 4 | blocks /plan-feature for Phase 4 | Aegis fix approval flow for IaC — same "auto-execute up to PR open" as app-code fixes, or stricter (always require approval before validator runs)? |
| OQ7 | All phases | informational | Whether `security_tab_progress.md` rename → "issues" + compliance combine lands before, during, or after Phase 1. |

## Recommended Next Step

Run `/plan-feature .cursor/plans/feature-brief-iac-container-v2.md` to produce the **Phase 1 implementation plan only**. Phases 2-4 each get their own brainstorm + plan-feature when their turn comes — open questions OQ3/4/6 resolve at those points.
