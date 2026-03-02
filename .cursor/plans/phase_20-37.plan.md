---
name: Future ASPM Roadmap
overview: A comprehensive future roadmap (Phases 20-37) identifying 25+ features that top ASPM platforms like Snyk, Aikido Security, and Endor Labs offer -- organized into themed phases to bring Deptex to billion-dollar startup parity and beyond.
todos:
  - id: phase-20-byoc
    content: "Phase 20: Self-Hosted Runner / BYOC -- Downloadable Docker agent, air-gapped mode, runner fleet management"
    status: pending
  - id: phase-21-dast
    content: "Phase 21: DAST -- Nuclei-based dynamic testing, API scanning, surface monitoring"
    status: pending
  - id: phase-22-iac
    content: "Phase 22: IaC Scanning -- Terraform, CloudFormation, K8s, Docker Compose via Checkov/KICS"
    status: pending
  - id: phase-23-cspm
    content: "Phase 23: Cloud Security Posture Management -- AWS/GCP/Azure misconfiguration scanning via Prowler"
    status: pending
  - id: phase-24-runtime
    content: "Phase 24: Runtime Protection -- Lightweight SDK/middleware, request blocking, bot detection"
    status: pending
  - id: phase-25-asset-discovery
    content: "Phase 25: Asset Discovery & RSPM -- Auto repo discovery, coverage gaps, repo security posture"
    status: pending
  - id: phase-26-exec-dashboard
    content: "Phase 26: Executive Intelligence & CISO Dashboard -- MTTR, risk score, board reports, benchmarking"
    status: pending
  - id: phase-27-compliance-frameworks
    content: "Phase 27: Compliance Framework Mapping -- SOC 2, ISO 27001, NIST, OWASP mapping with evidence collection"
    status: pending
  - id: phase-28-public-api
    content: "Phase 28: Public API & Ecosystem -- REST API, OpenAPI spec, API keys, SDKs, Terraform provider"
    status: pending
  - id: phase-29-byos
    content: "Phase 29: Custom Scanner Integration (BYOS) -- SARIF import, cross-scanner dedup, connector framework"
    status: pending
  - id: phase-30-ai-ml
    content: "Phase 30: AI Model & ML Supply Chain Security -- Model inventory, ML-BOM, prompt injection detection"
    status: pending
  - id: phase-31-upgrade-impact
    content: "Phase 31: Upgrade Impact Analysis -- Breaking change prediction, blast radius, migration paths"
    status: pending
  - id: phase-32-asm
    content: "Phase 32: Attack Surface Management -- Domain enumeration, exposed services, cert monitoring"
    status: pending
  - id: phase-33-branch-scanning
    content: "Phase 33: Feature Branch & Pre-Merge Security -- Diff-aware scanning, security score comparison"
    status: pending
  - id: phase-34-vex
    content: "Phase 34: VEX & Supply Chain Attestation -- Auto VEX generation, Sigstore, SLSA attestation"
    status: pending
  - id: phase-35-threat-modeling
    content: "Phase 35: Threat Modeling -- Auto STRIDE analysis, DFDs, attack trees, threat-to-finding mapping"
    status: pending
  - id: phase-36-gamification
    content: "Phase 36: Security Culture & Gamification -- Champions program, training, leaderboards, challenges"
    status: pending
  - id: phase-37-marketplace
    content: "Phase 37: Marketplace & White-Label -- Plugin API, community marketplace, MSP multi-tenant, white-label"
    status: pending
isProject: false
---

# Deptex Future Vision Roadmap (Phases 20-37)

After reviewing all 18 existing phases and analyzing what Snyk AppRisk, Aikido Security, Endor Labs, AccuKnox, and other leading ASPM platforms offer, here are the gaps and opportunities organized into themed phases.

Note: add [socket.dev data, add container scanning?](http://socket.io)

---

## What Deptex Already Covers Well

For reference, the existing 18 phases already handle: SCA, SBOM (CycloneDX), vulnerability management (OSV/GHSA), SAST (Semgrep), secrets detection (TruffleHog), reachability analysis (dep-scan), policy-as-code, PR guardrails, AI fixing (Aider), AI copilot (Aegis), git integrations (GitHub/GitLab/Bitbucket), notifications (Slack/Discord/Jira/Linear), Watchtower monitoring, billing/Stripe, SSO/MFA, SLA management, incident response, developer tools (VS Code/CLI/GitHub Action), compliance dashboard, license management, malicious package detection (Socket.dev), SLSA provenance, and container scanning (grype/trivy).

---

## Phase 20: Self-Hosted Runner / Bring Your Own Cloud (BYOC)

**Why:** Many enterprises (finance, healthcare, gov) refuse to share source code or git credentials with third parties. This is the single biggest enterprise deal-blocker.

**Competitor reference:** Snyk has Snyk Broker, Endor Labs supports on-prem scanning, GitLab has self-managed runners.

**Features:**

- **Downloadable extraction agent** -- Docker-based runner that customers deploy in their own cloud (AWS/GCP/Azure) or on-prem
- **Air-gapped mode** -- source code never leaves the customer's network; only scan results (SBOM, findings, metadata) are uploaded to Deptex cloud via secure tunnel
- **Agent-to-cloud protocol** -- authenticated TLS tunnel where the runner pushes results to Deptex's API; no inbound firewall rules needed on customer side
- **Runner fleet management** -- dashboard showing runner health, version, last heartbeat, job queue depth
- **Auto-update mechanism** -- runners check for new versions and self-update (with customer approval)
- **Hybrid mode** -- scan locally, view and manage everything in Deptex cloud dashboard

**Implementation notes:** The extraction worker already runs on Fly.io (Phase 2). Refactor it into a standalone Docker image that can run anywhere. Add a "runner registration" flow where customers get a runner token, configure it with their git credentials locally, and results are pushed via `POST /api/runner/upload`.

---

## Phase 21: DAST (Dynamic Application Security Testing)

**Why:** Aikido, Snyk, and AccuKnox all offer DAST. It finds runtime vulnerabilities (XSS, SQL injection, auth bypass) that static analysis misses.

**Competitor reference:** Aikido has authenticated DAST + surface monitoring. OWASP ZAP and Nuclei are popular open-source engines.

**Features:**

- **Unauthenticated DAST** -- crawl and test public-facing web apps for OWASP Top 10 vulnerabilities
- **Authenticated DAST** -- support login sequences (cookie/token-based) to test behind auth
- **API scanning** -- import OpenAPI/Swagger specs and fuzz all endpoints
- **Scheduled scans** -- run DAST on a schedule (daily/weekly) against staging or production URLs
- **Finding integration** -- DAST findings appear in the same Security tab alongside SAST/SCA findings
- **Surface monitoring** -- discover subdomains and exposed services for a given domain

**Implementation notes:** Use Nuclei (open-source, Go-based, 8k+ templates) as the scanning engine. Run on Fly.io machines similar to extraction workers. Customers configure target URLs per project.

---

## Phase 22: IaC Scanning (Infrastructure as Code)

**Why:** Misconfigured infrastructure is a top attack vector. Every major ASPM platform includes IaC scanning.

**Competitor reference:** Aikido, Snyk IaC, Checkov (Prisma Cloud).

**Features:**

- **Terraform scanning** -- detect misconfigs in `.tf` files (open S3 buckets, overly permissive IAM, unencrypted storage)
- **CloudFormation scanning** -- AWS-specific template analysis
- **Kubernetes manifest scanning** -- detect privileged containers, missing resource limits, exposed services
- **Docker Compose scanning** -- detect insecure configurations
- **Helm chart scanning** -- Kubernetes package manager templates
- **Policy mapping** -- map IaC findings to CIS Benchmarks and cloud provider best practices

**Implementation notes:** Use Checkov (Python, open-source by Bridgecrew/Palo Alto) or KICS (Checkmarx). Add as an optional step in the extraction pipeline -- detect IaC files in the repo and run the scanner. Findings stored in a new `project_iac_findings` table.

---

## Phase 23: Cloud Security Posture Management (CSPM)

**Why:** Enterprises want to see cloud misconfigurations alongside code vulnerabilities in one place.

**Competitor reference:** Aikido has agentless CSPM. Wiz, Orca, Prisma Cloud are pure-play CSPM.

**Features:**

- **AWS account scanning** -- read-only IAM role to detect misconfigs (S3, EC2, RDS, IAM, VPC)
- **GCP project scanning** -- service account with viewer role
- **Azure subscription scanning** -- app registration with reader role
- **Finding categories** -- networking, identity, encryption, logging, storage, compute
- **Compliance mapping** -- map cloud findings to CIS Benchmarks, SOC 2, ISO 27001
- **Drift detection** -- alert when cloud config drifts from desired state

**Implementation notes:** Use Prowler (AWS/GCP/Azure, open-source) or ScoutSuite. Customers connect their cloud accounts via read-only credentials stored encrypted. Results feed into a new "Cloud" tab alongside existing Security tab.

---

## Phase 24: Runtime Protection & Monitoring

**Why:** Shift-right security. Detect and block attacks in production.

**Competitor reference:** Aikido's Zen firewall, Falco for container runtime.

**Features:**

- **Lightweight runtime agent** -- npm/Python/Go middleware package that customers add to their app
- **Request-level protection** -- block SQL injection, XSS, command injection, SSRF, path traversal at runtime
- **Bot detection** -- identify and block automated attack traffic
- **Zero-day protection** -- behavioral analysis to catch novel attack patterns
- **Runtime telemetry** -- which dependencies are actually loaded at runtime (confirms reachability)
- **Alert integration** -- runtime incidents feed into Deptex notifications and Aegis

**Implementation notes:** Build a lightweight SDK (start with Node.js/Express middleware). The agent intercepts HTTP requests, applies rules, and reports telemetry back to Deptex. This is a major differentiator but also a major engineering effort -- consider partnering or acquiring.

---

## Phase 25: Asset Discovery & Repository Security (RSPM)

**Why:** Snyk AppRisk's biggest selling point is automatic discovery of everything in an org. You can't secure what you can't see.

**Competitor reference:** Snyk AppRisk auto-discovery, Endor Labs RSPM.

**Features:**

- **Automatic repo discovery** -- scan all GitHub/GitLab/Bitbucket repos in an org, show which ones are monitored vs unmonitored by Deptex
- **Coverage gap analysis** -- "You have 47 repos but only 12 are connected to Deptex" with one-click onboarding
- **Repository security posture** -- audit branch protection rules, required reviews, signed commits, secret scanning enabled, Dependabot config
- **Service mapping** -- auto-detect microservice relationships from code imports, Docker Compose, Kubernetes manifests
- **Asset classification** -- auto-tag repos as frontend/backend/library/infrastructure based on content analysis
- **Ownership mapping** -- link repos to teams and identify unowned/orphaned repositories

**Implementation notes:** Leverage existing GitHub App installation to enumerate all repos via GitHub API. Add an "Asset Inventory" page at org level. `organization_assets` table tracks discovered repos with classification and coverage status.

---

## Phase 26: Executive Intelligence & CISO Dashboard

**Why:** Security leaders need board-ready metrics. This is what justifies enterprise contracts.

**Competitor reference:** Snyk reporting, Aikido compliance dashboards, every SIEM/SOAR platform.

**Features:**

- **CISO dashboard** -- single-pane view of org security posture: total vulns by severity, open vs resolved, trending up/down
- **MTTR tracking** -- Mean Time to Remediate by severity, team, project; trend over time
- **Risk posture score** -- aggregate org-level score (0-100) combining vuln counts, SLA compliance, policy adherence, coverage gaps
- **Board-ready reports** -- exportable PDF/PowerPoint with executive summary, risk trends, compliance status, top actions
- **Security benchmarking** -- compare your org's metrics against anonymized industry averages ("You remediate critical vulns 40% faster than average")
- **ROI dashboard** -- calculate cost savings: vulnerabilities prevented, breach risk reduction, developer time saved
- **Custom KPI builder** -- let security leaders define their own metrics and track them

**Implementation notes:** Build on top of existing `activities` table and vulnerability data. Add `security_metrics_snapshots` table for daily/weekly metric snapshots. New "Executive" section in org navigation.

---

## Phase 27: Compliance Framework Mapping & Evidence Collection

**Why:** Enterprises need to prove compliance to auditors. Automated evidence collection is a massive time saver.

**Competitor reference:** Aikido maps to SOC 2/ISO 27001/OWASP. Vanta and Drata are pure compliance platforms.

**Features:**

- **Framework library** -- SOC 2 Type II, ISO 27001, NIST CSF, NIST 800-53, OWASP Top 10, OWASP SAMM, PCI DSS, HIPAA, CIS Controls
- **Control mapping** -- map Deptex capabilities to specific framework controls (e.g., "SOC 2 CC7.1 -> Deptex vulnerability scanning")
- **Evidence auto-collection** -- automatically gather evidence for each control (scan results, policy configs, SLA reports, SBOM exports)
- **Compliance scoring** -- per-framework compliance percentage with drill-down
- **Audit export** -- generate audit-ready evidence packages (ZIP with organized PDFs, CSVs, and screenshots)
- **Gap analysis** -- identify which controls have no evidence and what actions are needed
- **Continuous monitoring** -- alert when compliance posture degrades

**Implementation notes:** Create a `compliance_frameworks` table with controls. Map existing Deptex features to controls. Build an "Audit Center" page. This is highly valuable for SOC 2/ISO 27001 audits that enterprises go through annually.

---

## Phase 28: Public API & Developer Ecosystem

**Why:** Every platform-scale product needs a public API. Partners, customers, and integrators need programmatic access.

**Competitor reference:** Snyk API, GitHub API, every major SaaS platform.

**Features:**

- **REST API** with OpenAPI 3.1 spec -- full CRUD for orgs, projects, vulnerabilities, policies, scans
- **API key management** -- org-level and project-level API keys with scoped permissions
- **Rate limiting** -- tiered rate limits by plan (Free: 100/hr, Pro: 1000/hr, Team: 10000/hr)
- **Webhook system** -- register webhook URLs to receive events (new vuln, scan complete, policy violation)
- **SDK generation** -- auto-generate SDKs from OpenAPI spec (Node, Python, Go)
- **API docs portal** -- interactive API documentation (Swagger UI or Redoc)
- **Terraform provider** -- manage Deptex configuration as code (projects, policies, integrations)

**Implementation notes:** The backend already has internal API routes. Formalize them with proper versioning (`/api/v1/`), add API key auth middleware, generate OpenAPI spec, and publish docs.

---

## Phase 29: Custom Scanner Integration (Bring Your Own Scanner)

**Why:** Enterprises already have tools. Let them pipe findings from any scanner into Deptex for unified management.

**Competitor reference:** Aikido's "Connect Your Own Scanner", DefectDojo.

**Features:**

- **SARIF import** -- universal format used by CodeQL, ESLint, Semgrep, and 50+ tools
- **CycloneDX/SPDX import** -- accept SBOMs from any generator
- **Generic finding API** -- `POST /api/v1/findings` with a normalized schema
- **Scanner connectors** -- pre-built connectors for popular tools (SonarQube, Checkmarx, Fortify, Veracode, Qualys)
- **Cross-scanner deduplication** -- Aikido's AutoTriage concept: same CVE from 3 scanners = 1 finding
- **Finding normalization** -- map different severity scales, confidence levels, and categories to Deptex's unified model

**Implementation notes:** Define a `custom_findings` table. Build a SARIF parser. The deduplication engine is the key differentiator -- use CVE ID + file path + line number as the dedup key.

---

## Phase 30: AI Model & ML Supply Chain Security

**Why:** AI/ML is everywhere now. Models have supply chain risks just like code dependencies.

**Competitor reference:** Endor Labs has AI model scanning. Protect AI / HiddenLayer focus on this.

**Features:**

- **AI model inventory** -- discover ML models in repos (PyTorch, TensorFlow, ONNX, Hugging Face references)
- **Model vulnerability scanning** -- check models against known CVEs and backdoor databases
- **ML-BOM generation** -- Software Bill of Materials for ML pipelines (datasets, models, frameworks)
- **Prompt injection detection** -- scan for prompt injection vulnerabilities in LLM-using code
- **Model provenance** -- verify model origin and integrity (Hugging Face signatures, model cards)
- **AI dependency risk** -- assess risk of AI/ML frameworks (PyTorch, TensorFlow, LangChain versions)

**Implementation notes:** Start with detecting AI/ML files (`.pt`, `.onnx`, `requirements.txt` with torch/tensorflow) and scanning their dependencies. Model-specific security is still emerging -- focus on dependency risks first.

---

## Phase 31: Upgrade Impact Analysis & Change Intelligence

**Why:** "Should I upgrade lodash from 4.17.20 to 4.17.21?" Answering this with confidence is incredibly valuable.

**Competitor reference:** Endor Labs' Upgrade Impact Analysis is a flagship feature.

**Features:**

- **Breaking change prediction** -- analyze changelogs, release notes, and API diffs to predict if an upgrade will break things
- **Dependency upgrade simulation** -- dry-run upgrades and report compatibility issues
- **Blast radius analysis** -- show which projects/services are affected by upgrading a shared dependency
- **Migration path recommendation** -- for major version upgrades, suggest the safest upgrade path (e.g., "upgrade X first, then Y")
- **Automated changelog analysis** -- parse GitHub releases and npm changelogs for breaking changes
- **Upgrade confidence score** -- 0-100 score combining test pass rate, community adoption, breaking change risk

**Implementation notes:** This builds on existing dependency graph data. Use Aegis AI to analyze changelogs. Track which org projects share dependencies for blast radius. `dependency_upgrade_analysis` table stores results.

---

## Phase 32: Attack Surface Management (External)

**Why:** Know what's exposed before attackers do. Complement internal scanning with external perspective.

**Competitor reference:** Aikido's surface monitoring. CrowdStrike, Censys, Shodan for ASM.

**Features:**

- **Domain enumeration** -- discover all subdomains for customer's domain
- **Exposed service detection** -- port scanning, technology fingerprinting
- **Certificate monitoring** -- SSL/TLS cert expiry, weak ciphers, misconfigurations
- **DNS security** -- DNSSEC, SPF, DKIM, DMARC configuration audit
- **Exposed secret detection** -- scan public GitHub, Pastebin, etc. for leaked credentials tied to the org
- **Attack surface scoring** -- quantify external exposure with a risk score

**Implementation notes:** Use tools like Subfinder (subdomain enumeration), httpx (HTTP probing), and custom cert checks. Run as scheduled scans. New "Attack Surface" tab at org level.

---

## Phase 33: Feature Branch & Pre-Merge Security

**Why:** Catch issues before they reach main. This is the ultimate "shift left."

**Competitor reference:** Aikido has feature branch scanning. Snyk has PR checks.

**Features:**

- **Branch-level scanning** -- scan any branch, not just main/master
- **PR diff-aware scanning** -- only scan changed files in a PR for faster results
- **Security score comparison** -- "This PR introduces 3 new highs and fixes 1 critical" comparison view
- **Pre-merge gates** -- configurable rules (e.g., "no new criticals", "no new secrets", "IaC must pass")
- **Shift-left metrics** -- track how many issues are caught before merge vs after
- **Developer feedback loop** -- inline PR comments with fix suggestions (builds on Phase 8)

**Implementation notes:** Extend Phase 8's PR management. When a PR webhook fires, run extraction on the PR branch and diff the results against the base branch. This is a refinement of existing PR guardrails.

---

## Phase 34: VEX & Supply Chain Attestation

**Why:** VEX (Vulnerability Exploitability eXchange) is becoming an industry standard. Required for many government contracts.

**Competitor reference:** CISA promotes VEX. Endor Labs supports it.

**Features:**

- **Automated VEX generation** -- based on reachability analysis, auto-generate VEX documents stating which CVEs are not exploitable
- **VEX lifecycle management** -- track VEX status (not_affected, affected, fixed, under_investigation) per vulnerability
- **SLSA attestation generation** -- generate SLSA provenance attestations for builds
- **Sigstore/Cosign integration** -- sign and verify SBOMs and attestations
- **Attestation policy enforcement** -- require SLSA level 2+ for all dependencies
- **VEX/SBOM distribution** -- publish VEX and SBOM documents for downstream consumers

**Implementation notes:** Builds on Phase 6B reachability data to generate VEX. Use `openvex/go` library format. Store in `project_vex_documents` table with status tracking.

---

## Phase 35: Threat Modeling

**Why:** Proactive security. Understand threats before they become vulnerabilities.

**Competitor reference:** IriusRisk, OWASP Threat Dragon. No ASPM platform does this well yet -- major differentiator opportunity.

**Features:**

- **Automated threat model generation** -- analyze codebase architecture (APIs, databases, auth, file uploads) and generate STRIDE-based threat models
- **Data flow diagrams** -- auto-generate DFDs from code analysis (which services talk to which)
- **Attack tree visualization** -- visual representation of attack paths
- **Threat-to-finding mapping** -- link theoretical threats to actual findings (e.g., "SQL Injection threat" maps to SAST SQL injection findings)
- **Threat model as code** -- version-controlled threat model definitions in YAML
- **AI-powered threat analysis** -- use Aegis to analyze architecture and suggest threats

**Implementation notes:** Use the dependency graph and code analysis from extraction to infer architecture. Aegis can analyze the codebase and generate threat models. This would be a first-of-its-kind feature in ASPM.

---

## Phase 36: Security Culture & Gamification

**Why:** Security is a people problem. Training and gamification drive adoption.

**Competitor reference:** Secure Code Warrior, HackEDU. No ASPM platform includes this natively.

**Features:**

- **Security champions program** -- designate security champions per team, track their engagement
- **Developer training modules** -- interactive lessons on OWASP Top 10, secure coding, dependency management
- **Gamification** -- points for fixing vulns, badges for streaks, team leaderboards
- **Security quizzes** -- auto-generated quizzes based on actual findings in their codebase ("What's wrong with this code?")
- **Fix streaks & challenges** -- weekly challenges like "Fix 5 medium vulns this week"
- **Security score per developer** -- individual contribution tracking (vulns introduced vs fixed)

**Implementation notes:** Build on existing `activities` table. Add `developer_security_profiles` and `security_achievements` tables. Leaderboard page at org level. This is a strong retention and adoption driver.

---

## Phase 37: Marketplace & White-Label

**Why:** Platform scale. Let the ecosystem build on top of Deptex.

**Competitor reference:** Snyk Apps, GitHub Marketplace, Vercel integrations.

**Features:**

- **Plugin API** -- extension points for custom scanners, dashboards, integrations
- **Community marketplace** -- browse and install community-built plugins
- **Custom dashboard widgets** -- build custom data visualizations
- **White-label mode** -- MSPs and resellers can rebrand Deptex for their customers
- **Multi-tenant management** -- MSP portal to manage multiple customer tenants
- **Custom domain support** -- `security.customer.com` pointing to their Deptex instance
- **Consolidated billing** -- MSPs bill their customers, pay Deptex wholesale

**Implementation notes:** This is a long-term platform play. Start with the Plugin API, then build marketplace. White-label requires tenant isolation in the database (already have org-level isolation).

---

## Priority Matrix

**Tier 1 -- Enterprise Deal Closers (build first):**

- Phase 20: Self-Hosted Runner / BYOC
- Phase 25: Asset Discovery & RSPM
- Phase 26: Executive Intelligence & CISO Dashboard
- Phase 27: Compliance Framework Mapping
- Phase 28: Public API

**Tier 2 -- Competitive Parity (catch up to Snyk/Aikido):**

- Phase 21: DAST
- Phase 22: IaC Scanning
- Phase 29: Custom Scanner Integration (BYOS)
- Phase 33: Feature Branch Scanning

**Tier 3 -- Differentiation (stand out):**

- Phase 31: Upgrade Impact Analysis
- Phase 34: VEX & Attestation
- Phase 35: Threat Modeling
- Phase 30: AI Model Security

**Tier 4 -- Platform Scale (billion-dollar plays):**

- Phase 23: CSPM
- Phase 24: Runtime Protection
- Phase 32: Attack Surface Management
- Phase 36: Security Gamification
- Phase 37: Marketplace & White-Label

