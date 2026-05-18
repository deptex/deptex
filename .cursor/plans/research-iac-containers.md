# Research: IaC + Container Scanning

> **Historical context (2026-05-09):** This plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. Where this plan references BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, or `AI_ENCRYPTION_KEY` for AI key envelopes, treat those as historical implementation details — current AI runs on platform keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from worker env). `AI_ENCRYPTION_KEY` itself is still in use, but only for `organization_registry_credentials` (IaC v2 Phase 1).

## Current State in Deptex

**Not implemented.** Zero IaC scanning, zero container scanning. The only artifact in the codebase is a placeholder string in `backend/extraction-worker/src/cli/index.ts:254` that reserves a future pipeline step name `iac_container` — no scanner is invoked, no tables exist, no UI surfaces. `frontend/src/components/framework-icon.tsx` covers app frameworks but has no docker / terraform / kubernetes / cloudformation / helm icons. The reachability-analysis plan (`.cursor/plans/reachability-analysis.plan.md`) describes Phase 10 as a 1–1.5 week "Checkov + Trivy bolt-on" and is the only existing spec — it predates the 2026 competitive landscape and badly underweights the opportunity. New tables planned: `project_iac_findings`, `project_container_findings`. New column: `projects.infra_types TEXT[]`. None applied yet.

This is greenfield — no in-flight worktree to coordinate with.

---

## Competitive Landscape

### Snyk IaC
- **What they call it:** Snyk IaC.
- **Coverage:** Terraform, CloudFormation, ARM templates, Kubernetes, Helm, Docker, OPA. AWS / Azure / GCP.
- **Policy model:** Built-in CIS / threat-modeling rules + custom rules in **OPA Rego** via the `snyk-iac-rules` SDK. Custom rules are **Enterprise-tier only**.
- **Auto-fix:** "Actionable in-code remediations" surfaced inline. PR comments via Git integration.
- **Pricing:** Free / Team / Enterprise.
- **Source:** https://snyk.io/product/infrastructure-as-code-security/, https://snyk.io/blog/opa-rego-usage-for-policy-as-code/

### Snyk Container
- **Coverage:** Base images, OS packages, OSS dependencies inside images.
- **Distinctive features:** Base image upgrade recommendations + alternative image suggestions. Registry integrations: Docker Hub, ECR, ACR, GCR, JFrog Artifactory, Harbor, Quay. Runtime monitoring across EKS / AKS / GKE / OpenShift with **context-aware prioritization** (used at runtime → higher priority).
- **Pricing:** Free / Team / Enterprise. Runtime monitoring is Enterprise.
- **Source:** https://snyk.io/product/container-vulnerability-management/

### Wiz (Wiz Code)
- **Pitch:** "Code-to-cloud" correlation — links IaC misconfig in a Terraform file to a *live* exposed cloud resource.
- **Distinctive:** Bidirectional runtime-to-code feedback loop. Risk prioritization by actual cloud blast radius, not abstract severity. Drift detection between declared IaC and observed cloud state.
- **Caveat:** Requires connected cloud accounts — they're CSPM-first, IaC-second.
- **Source:** https://www.wiz.io/academy/application-security/iac-security

### Prisma Cloud (Palo Alto)
- **Coverage:** Hundreds of out-of-the-box policies on CIS, HIPAA, PCI benchmarks. Custom policies in **Python, YAML, or a UI editor**, plus graph-based multi-resource policies.
- **Distinctive:** "Smart Fixes" that trace cloud misconfigurations back to the originating IaC code. Auto-remediation for many policies.
- **Foundation:** Acquired Bridgecrew (Checkov's parent) — Checkov is their OSS engine.
- **Source:** https://www.paloaltonetworks.com/prisma/cloud/infrastructure-as-code-security

### Endor Labs — *the major 2026 signal*
- **February 2026:** Acquired **Autonomous Plane** (founded by Kyle Quest, creator of DockerSlim).
- **New product:** "Full-stack reachability from code to container" — uses application code dependency graph to determine which OS packages and libraries in container images are *actually loaded and reachable at runtime*.
- **Approach:** Combines static dependency graph analysis + automatic runtime profiling + dynamic and static container analysis to model end-to-end execution.
- **Claim:** Filters up to **90% of false positives** vs traditional container scanners.
- **Why it matters for Deptex:** This is the new frontier and it directly extends the same reachability moat we've been building. Endor is racing to own "container reachability" as a category. We're positioned to ship an open-core version of the same idea.
- **Source:** https://www.prnewswire.com/news-releases/endor-labs-acquires-autonomous-plane-expanding-ai-native-application-security-with-full-stack-reachability-from-code-to-container-302684888.html

### Aikido
- **Coverage:** Terraform, CloudFormation, Kubernetes manifests, Helm, ARM, Bicep. HCL/YAML/JSON. Pulumi forthcoming. CSPM + container + SAST + SCA + secrets + DAST + license + malware + API + VM + runtime — all bundled.
- **Distinctive:** "AI AutoFix" generates code patches and opens PRs in one click. Context-aware ignore rules for false-positive management.
- **Pricing:** Aggressive freemium. Their wedge is "consolidate 10 vendors into one cheap subscription."
- **Source:** https://www.aikido.dev/code/infrastructure-as-a-code-iac, https://www.aikido.dev/blog/iac-security-scanning-terraform-kubernetes-misconfigurations

### GitHub Advanced Security — *new March 2026 launch*
- **What's new:** AI-powered detections in PR review. Expanded coverage to **Terraform + Dockerfiles + Shell + Bash + PHP** (previously CodeQL was app-code only).
- **Copilot Autofix:** Bridges detection → remediation in the same review pane. Internal testing: 170k findings / 30 days, 80% positive developer feedback.
- **Pricing:** GHAS license (per-committer) on top of GitHub Enterprise.
- **Source:** https://www.helpnetsecurity.com/2026/03/24/github-ai-powered-detections-code-scanning/

### OSS Engines (free, available to us)
- **Checkov** (Apache 2.0, maintained by Prisma Cloud / Bridgecrew): Terraform, CFN, K8s, ARM, Serverless, Helm, AWS CDK. ~1000 built-in checks. Custom policies in Python (attribute-based) and YAML (graph-based). https://www.checkov.io/
- **Trivy** (Apache 2.0, Aqua Security): containers, IaC, SBOMs, secrets, licenses, K8s clusters in one binary. Absorbed tfsec in 2024. 31,700+ GitHub stars. "Next-Gen Trivy" arriving 2026. https://trivy.dev/
- **Grype + Syft** (Apache 2.0, Anchore): SBOM-first container vuln workflow. Narrower than Trivy.
- **Docker Scout:** Built on Snyk tech. SBOM + CVE matching, base-image recommendations. Free in Docker Desktop, paid for org features. https://docs.docker.com/scout/
- **StepSecurity Harden-Runner / Scorecards:** GitHub Actions workflow EDR + supply-chain hygiene. https://github.com/step-security/harden-runner

---

## Landscape Synthesis

### Table-stakes (every serious competitor has)
- IaC misconfiguration scanning across Terraform / CFN / K8s / Helm / Dockerfile
- CVE scanning of container images and base layers
- PR-time enforcement with check runs and inline comments
- CIS / SOC2 / PCI benchmark mapping
- Custom policy support (some flavor — Rego, Python, YAML)
- Auto-fix PRs (Snyk, Aikido, GitHub, Prisma all ship this now)

### Frontier (2-3 vendors, emerging)
- **Container reachability** (Endor only as of Feb 2026 — *fresh land grab*)
- Code-to-cloud correlation: IaC code ↔ live cloud resource (Wiz, Prisma)
- Drift detection between declared IaC and runtime state (Wiz, Prisma, env0)
- AI-driven explanation + autofix of misconfigs (Aikido, GitHub Copilot, Snyk DeepCode)
- Helm/Kustomize-aware scanning (render-then-scan; Aikido and a handful of OSS users)

### Whitespace (no one does well)
- **Truly open-core container reachability.** Endor charges enterprise prices; the OSS world has nothing comparable. Our tree-sitter usage extractor (Phase 2) already produces exactly the input data this needs.
- **IaC ↔ application-code reachability.** Linking "this S3 bucket misconfiguration" to "this Lambda function that handles user input" — nobody does this. Cross-file taint stitching (Phase 6) is the engine that would power it.
- **Agent-driven IaC fixes that verify themselves.** Aikido and Snyk write fix PRs; they don't run `terraform validate` / `kubeval` against the patch and re-attempt on failure. Our Aegis Fix Agent infra already does this for app code.
- **GitHub Actions workflow security as a first-class scan domain.** Major SCA vendors touch it; nobody specializes. StepSecurity is closest but is a runtime EDR, not a code scanner.
- **Custom policies in JS via a sandboxed engine** (vs Rego learning curve). Our existing org policy engine could be extended trivially.

### Deptex position today
- **Behind** on all table-stakes — we ship none of this.
- **Uniquely positioned to leapfrog** the frontier because we already have the engine pieces (tree-sitter usage data, AI rule generation, cross-file taint stitching, Aegis Fix Agent) that competitors are still building or charging premium for.
- **Open-core + BYOK AI** is a real wedge against Snyk / Endor / Wiz pricing.

---

## Shortlist (Recommended)

### 1. IaC + Container Scanning Foundation — 5/5 value, 5/5 leverage
- **One-liner:** Add Trivy + Checkov to the extraction-worker Docker image; emit findings into `project_iac_findings` and `project_container_findings`; ship infra badges + IaC/Container tabs in the security page.
- **Target user:** Any developer or org admin shipping infra-as-code or containers — currently invisible to Deptex.
- **Problem:** Deptex closes the loop on "package CVEs" but ignores half of every modern repo (Dockerfiles, Terraform, K8s manifests). Every competitor has this; we don't.
- **Competitive positioning:** Table-stakes parity with Snyk IaC, Snyk Container, Aikido, GitHub Code Scanning. Trivy alone is what most OSS users self-host today (https://trivy.dev/).
- **Deptex fit:** New pipeline step alongside dep-scan / Semgrep / TruffleHog; reuses the existing finding-card UI pattern, the `extraction_step_errors` infra, and the soft-switch atomic commit. Clean fork — no overlap with Phase 5 / Phase 6 in flight.
- **Size:** M (1.5–2 weeks aligned with the original Phase 10 scope, slightly larger to cover both engines properly).
- **Bucket:** table-stakes.
- **Why shortlisted:** Foundation everything else stacks on. Fast to ship. Closes the most embarrassing gap.

### 2. Container Reachability — 5/5 value, 5/5 leverage
- **One-liner:** Use our existing tree-sitter usage data + dependency graph to filter container CVE findings down to "OS packages and libraries the application actually invokes." Match Endor's Feb 2026 land grab in open-core.
- **Target user:** Security engineers drowning in "1,200 high CVEs in node:18-bullseye" noise. Org admins who need defensible prioritization.
- **Problem:** Container scanners flood teams with hundreds of base-layer CVEs in libraries the app never calls. Endor claims 90% false-positive reduction with this approach. Nobody else in OSS or open-core ships it.
- **Competitive positioning:** Direct response to Endor's Autonomous Plane acquisition (https://www.prnewswire.com/news-releases/endor-labs-acquires-autonomous-plane-expanding-ai-native-application-security-with-full-stack-reachability-from-code-to-container-302684888.html). Open-core + BYOK AI undercuts Endor's enterprise pricing on the same capability.
- **Deptex fit:** **Massive leverage** — tree-sitter usage extractor (Phase 2) already produces the exact "which functions/libraries are called" data this needs. Add: container-image package-list extraction (Trivy already does this) → join with usage data → reachability classification per OS-level package. Reachability levels reuse the existing 5-level taxonomy.
- **Size:** L (3–4 weeks). Engine work is the heavy lift — UI is reusing existing reachability badges.
- **Bucket:** differentiator (frontier).
- **Why shortlisted:** This is the strategic moat play. Same "we did open-core SCA reachability before anyone" story repeats for containers. Endor just validated the category for us.

### 3. Aegis IaC Auto-Fix Agent — 5/5 value, 5/5 leverage
- **One-liner:** Extend the Aegis Fix Agent (already shipped + dogfooded) to IaC findings — generate Terraform / K8s / CFN patches, run `terraform validate` / `kubeval` in a sandbox, retry on failure, open draft PR.
- **Target user:** Developers who want misconfigs fixed without becoming Terraform experts; security teams that want autonomous remediation.
- **Problem:** Snyk and Aikido write fix PRs but don't *verify* them — broken Terraform plans get merged. We can verify before opening the PR.
- **Competitive positioning:** Aikido AI AutoFix (https://www.aikido.dev/) and GitHub Copilot Autofix (https://www.helpnetsecurity.com/2026/03/24/github-ai-powered-detections-code-scanning/) both ship one-shot fixes. Ours retries with feedback the same way Aegis Fix Agent does for app code, and the same way our Phase 5 rule generator iterates with attempt-failure feedback.
- **Deptex fit:** Aegis Fix Agent (memory: shipped 2026-04-29) is the rails. Add a Terraform/K8s validator wrapper, swap the fix-strategies registry to include IaC strategies, reuse the same QStash + Fly.io machine pattern.
- **Size:** M (2 weeks).
- **Bucket:** differentiator.
- **Why shortlisted:** Plays to two of our strongest moats (Aegis + verification loops). Stacks naturally on Foundation (#1).

### 4. Custom IaC Policy via Existing Policy Engine — 4/5 value, 5/5 leverage
- **One-liner:** Extend the existing org `package_policy_code` / `project_status_code` engine to evaluate IaC findings — write custom rules in JS in the existing Monaco editor, sandboxed by isolated-vm.
- **Target user:** Org admins who want company-specific IaC rules ("S3 buckets in prod must have versioning + KMS encryption") without learning Rego.
- **Problem:** Snyk forces Rego (Enterprise-only); Aikido is opaque; Prisma offers Python/YAML but it's a separate config surface. Our policy engine already exists, has Monaco editor + AI assistance + change history — we just don't feed it IaC findings.
- **Competitive positioning:** JS-in-sandbox is *more accessible* than Rego for typical engineering teams. Combined with the AI policy assistant, this is materially easier to adopt than Snyk Enterprise's custom-rules workflow (https://docs.snyk.io/scan-with-snyk/snyk-iac/current-iac-custom-rules/sdk-reference).
- **Deptex fit:** Pure leverage — reuses the policy engine, isolated-vm sandbox, AI policy assistant, code editor, change history, Tier-1 Gemini. The new work is a thin schema extension and feeding IaC findings into the policy evaluation pipeline.
- **Size:** S (1 week) — assuming Foundation (#1) is in.
- **Bucket:** differentiator.
- **Why shortlisted:** Highest leverage on existing infra of any IaC concept. Differentiates against Rego-heavy competitors.

### 5. IaC Findings in Aegis Chat — 4/5 value, 5/5 leverage
- **One-liner:** Add Aegis tools for `list_iac_findings`, `explain_iac_misconfig`, `fix_iac_finding` — reuse the existing tool/permission/streaming infra; ride on the v3 chat tools wired in PR #15.
- **Target user:** Anyone using Aegis as their security copilot — they should be able to ask "what's wrong with my K8s manifests" and get a real answer.
- **Problem:** Once IaC findings exist, Aegis is the natural triage surface. Skipping this leaves the data stranded in the security tab.
- **Competitive positioning:** No competitor has a real conversational triage layer over IaC findings — Snyk has docs assistant chat, Aikido has dashboards, but neither is agentic.
- **Deptex fit:** Almost no new code — adds 3–5 tools to the existing 50+ tool registry, reuses BYOK AI provider, RBAC checks, audit log.
- **Size:** S (3–5 days) — assuming Foundation (#1).
- **Bucket:** differentiator.
- **Why shortlisted:** Cheapest possible way to multiply the value of #1 by riding on Aegis rails we already maintain.

---

## Moonshots to Consider

### IaC ↔ Application-Code Reachability (the cross-domain taint play)
Extend Phase 6 (cross-file taint stitching) across the IaC ↔ code boundary. Trace: "this S3 bucket has `versioning=disabled` (IaC) → this Lambda reads from it (Terraform `aws_lambda_function.s3_event_source`) → this handler calls `s3.getObject` with user-controlled input (app code) → confirmed exploitable misconfig." Nobody does this. The cross-file taint engine being designed for Phase 6 is the foundational primitive, and IaC is a new dialect of "file" we'd add to its stitcher. Potential category-creating feature, but only viable after Phase 6 is solid.

### Public IaC + Container Reachability Benchmark / Leaderboard
Once Container Reachability (#2) is shipping, publish a benchmark: scan top 1000 Docker Hub images, publish % of CVEs that are actually reachable by typical applications using that image. Marketing wedge, dataset moat, and a recruiting magnet for OSS contributors. Cheap once #2 exists.

---

## Full Brainstorm (Appendix)

### 6. Code-to-Cloud Drift Correlation (lite) — 3/5 value, 2/5 leverage
Parse `terraform plan` / state files in the repo (no cloud creds needed) to detect drift between declared IaC and last-known plan output. Lighter version of Wiz/Prisma drift detection. **Skipped from shortlist:** value is real but it pulls us toward CSPM territory and the leverage is low — we'd be writing terraform-state parsers from scratch.

### 7. GitHub Actions Workflow Scanner — 4/5 value, 3/5 leverage
First-class scanner for `.github/workflows/*.yml`: detect unpinned actions (mutable refs), broad `permissions:` blocks, untrusted `pull_request_target` patterns, missing `harden-runner`. Major SCA vendors only graze this; StepSecurity is the specialist (https://github.com/step-security/harden-runner). **Strong concept**, would be #6 on the shortlist if we wanted six. Probably ships better as a follow-up after Foundation lands.

### 8. Helm + Kustomize + ArgoCD Renderer — 3/5 value, 3/5 leverage
Render Helm charts and Kustomize overlays before scanning so misconfigs only visible after templating get caught. Aikido has a basic version. Solid parity-plus, but mostly extends the value of #1 rather than being a standalone feature.

### 9. Base Image Upgrade Advisor — 3/5 value, 4/5 leverage
For Dockerfiles, recommend safer base image alternatives (alpine variants, distroless, Chainguard images). Snyk Container has a basic version. Useful but feels more like a feature *of* #2 than a separate concept.

### 10. SBOM Diff on PR — 2/5 value, 4/5 leverage
"This PR adds 17 new OS packages to your container image: 3 with high CVEs." Currently nobody surfaces this prominently at PR time. Small, polish-y, would slot well into the existing PR check infrastructure but isn't strategically differentiating.

### 11. Compliance Frame Mapping for IaC Findings — 4/5 value, 2/5 leverage
Auto-map each IaC finding to SOC 2 / ISO 27001 / NIST controls and surface in the compliance tab. Genuine enterprise value, low fit until our compliance tab itself is more mature (it's still rudimentary per the Phase 5 compliance roadmap entry).

### 12. Public Coverage Stat / Marketing Wedge — 2/5 value, 4/5 leverage
"Deptex blocks X% of CIS benchmarks at PR time, free." Marketing rather than product, useful once #1 exists and we want a wedge for the OSS-launch.

---

## Recommended Next Step

Run **`/interview` on concept #2 — Container Reachability** to refine scope before planning. Reasoning: #1 (Foundation) is well-spec'd already in the existing reachability plan and could go straight to `/plan-feature`. #2 is the strategic standout — it directly counters Endor's February 2026 land grab, leverages our biggest unshipped engine assets (tree-sitter usage data + reachability levels), and the technical scope still has open questions worth pinning down before planning (which container engine to pair with, how to scope the OS-package usage join, how Aegis surfaces the prioritized findings).

If you'd rather move fast on parity first, run `/plan-feature` directly on #1 — it's ready.

---

## Sources

- [Snyk IaC product page](https://snyk.io/product/infrastructure-as-code-security/)
- [Snyk Container product page](https://snyk.io/product/container-vulnerability-management/)
- [Snyk OPA / Rego policy-as-code blog](https://snyk.io/blog/opa-rego-usage-for-policy-as-code/)
- [Snyk IaC custom rules SDK reference](https://docs.snyk.io/scan-with-snyk/snyk-iac/current-iac-custom-rules/sdk-reference)
- [Wiz IaC academy page](https://www.wiz.io/academy/application-security/iac-security)
- [Prisma Cloud IaC security](https://www.paloaltonetworks.com/prisma/cloud/infrastructure-as-code-security)
- [Endor Labs acquires Autonomous Plane (Feb 2026)](https://www.prnewswire.com/news-releases/endor-labs-acquires-autonomous-plane-expanding-ai-native-application-security-with-full-stack-reachability-from-code-to-container-302684888.html)
- [Aikido IaC product page](https://www.aikido.dev/code/infrastructure-as-a-code-iac)
- [Aikido IaC blog post](https://www.aikido.dev/blog/iac-security-scanning-terraform-kubernetes-misconfigurations)
- [GitHub AI-powered detections (March 2026)](https://www.helpnetsecurity.com/2026/03/24/github-ai-powered-detections-code-scanning/)
- [Checkov](https://www.checkov.io/)
- [Trivy](https://trivy.dev/)
- [Docker Scout docs](https://docs.docker.com/scout/)
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner)
- [GitHub Actions 2026 security roadmap](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/)
