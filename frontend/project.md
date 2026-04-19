# Project: Org & Project Dependency Governance — Requirements & Feature Spec

> Editable requirements and product spec for the dependency governance + AI remediation project. Use this as the single source of truth for design, engineering, and go‑to‑market planning.

---

## 1. Executive summary

Build a developer- and security-first platform that helps organizations manage open source dependencies across projects and teams. Key capabilities:

- Organization and project management, with roles and inheritance
- Deep dependency tracking (direct + transitive), GitHub integration, branch tracking
- Policy-as-code enforcement (licenses, vulnerability thresholds, source policies)
- Rich collaboration via Watchlists (personal + project) and approval workflows
- Smart alerts (impact-based, grouped by root cause) and SBOM exports
- AI features: commit anomaly detection, AI patch generation (PRs), AI summarization and assistant
- Unique analytics such as Dependency Flattening Analysis and Risk/Reachability scoring

Goal: become a trusted open-source supply-chain governance platform that saves developer time and reduces organizational risk.

---

## 2. Key user personas

- **Org Owner / Admin**: configure org-wide policies, billing, audit, and integrations.
- **Security Officer**: audit and monitor vulnerabilities and compliance across all projects; tune policies.
- **Project Manager**: create and manage projects, appoint maintainers, run scans, manage watchlist approvals.
- **Developer / Maintainer**: propose dependencies, respond to alerts, review AI-generated PRs.
- **Auditor / Compliance Reviewer**: read-only access to compliance reports, SBOMs, and audit logs.
- **Individual Developer (personal watchlist user)**: explore packages, prototype, and promote packages to project watchlist.

---

## 3. Organization & project model (requirements)

- **Hierarchy**: Organization -> Projects. Projects are primary analysis units. Teams are optional constructs (groups/tags) to simplify membership.
- **Roles**: Org-level roles (Owner, Admin, Security Officer, Billing, Auditor), Project-level roles (Project Manager, Maintainer, Developer, Viewer). Support custom org-defined roles (Roles & Permissions config) with fine-grained permission toggles.
- **Membership management**: Org Members can be assigned tags and/or teams. Projects can add members by individual, tag, or team.
- **Default behavior**: Projects inherit org-level license/policy by default; projects may override locally (subject to org guardrails).

---

## 4. Integrations & data sources

- **Primary**: GitHub App integration (repo linking, dependency graph / SBOM), OAuth for private repos.
- **Optional**: GitLab, Bitbucket, Azure DevOps. Support for lockfile parsing for npm, pip, Maven, Go modules, etc.
- **Threat intelligence & CVE sources**: NVD, OSV.dev, GitHub Advisory DB, third-party feeds (optional plugin).
- **SBOM & runtime scanning**: integrate with Syft/Grype/Trivy for runtime SBOM generation and container/image scanning.
- **Notifications & workflow**: Slack, Microsoft Teams, Jira, Linear, PagerDuty.
- **Plugin system**: Event hooks, REST API, webhooks for third-party integrators and custom logic.

---

## 5. Core Product Features

### 5.1 Project creation & onboarding
- Create project, appoint Project Manager
- Link GitHub repo(s) via GitHub App or CLI `deply link <project_id>`
- Option to upload `package.json` or lockfile for initial scan
- Initial scan uses GitHub Dependency Graph or lockfile to build dependency graph

### 5.2 Dependency graph & display
- Show direct and transitive dependencies (tree). Default collapsed view; expand on demand.
- Tag dependency nodes with: version, license, vulnerabilities, popularity, last upstream commit, maintainer health, provenance flags (signed? SLSA?)
- Show branch presence (main vs tracked branches). Auto-track branches with commits in the last 30 days; manager adjustable.
- Support multi-ecosystem: npm, pip, Maven, Go modules (first target npm).

### 5.3 Project score and analytics
- Project Score: composite metric combining dependency health, vulnerabilities, compliance and activity.
- Trend charts for score, vulnerability counts, dependency churn.

### 5.4 Alerts system
- Smart, grouped alerts (group vulnerabilities by root package and impact path)
- Alert types: Vulnerability (direct/transitive), License violation, Upstream anomaly (suspicious commit), SBOM drift
- Severity and prioritization algorithm (severity × reachability × depth weight × usage importance)
- Delivery: in-app, email, Slack/Teams, webhook. PR comments on GitHub for blocking checks.

### 5.5 Watchlists
- **Personal Watchlist** (global button in header): personal, exploratory list of packages. No approvals; notifications optional.
- **Project Watchlist**: collaborative Kanban OR list view with statuses: Proposed, Under Review, Approved, Rejected, Archived.
  - Cards contain package metadata, AI summary, comment thread, approval controls, audit trail.
  - Auto-move to Approved when the dependency is detected in main after merge; auto-archive on removal.

### 5.6 Compliance & SBOM
- Compliance tab: project license, non-compliant packages list, remediation actions, and SBOM export (SPDX / CycloneDX JSON).
- SBOM Cross-Checker: compare declared SBOM vs runtime SBOM and alert on divergence (unexpected runtime packages).

### 5.7 Actions & Remediation
- **Bump**: UI action to open PR with version bump (patch/minor/major options). Respect org policy for auto-bumping.
- **AI Patch**: Attempt to apply targeted code-level patch for vulnerable function or to upgrade transitive subdependency when safe; create PR with tests (human review required for critical changes).
- **Auto PR Generation**: create PRs with changelog, test run results, and risk statement.

### 5.8 Transitive dependency handling
- Present transitive nodes in the Dependencies tab under each direct dependency.
- Group alerts by root cause and show the dependency path for each vulnerability.
- Reachability tagging (runtime / dev-only / optional) based on manifest classification and optional static import analysis.

### 5.9 Dependency Flattening Analysis (full spec included below)
- Flattening Score (0-100), Conflict detection, Low similarity package detection, Upgrade recommendations, Flattening suggestions, Impact ratings.

### 5.10 Risk & Health Scoring
- Package risk score combining: CVE history, maintainer activity, popularity, age, provenance, install-time risks (e.g. install scripts), typosquat signals.
- Project-level aggregated risk and dependency blast-radius analysis.

### 5.11 Provenance & Supply-Chain Integrity
- Show Sigstore signatures / Rekor/SLSA metadata where available.
- Highlight packages without provenance for elevated scrutiny.

### 5.12 Typosquat & Malicious package detection
- Name-similarity detection, new-publish anomalies, small-ownership indicators (e.g., recently created maintainer) and install-script detection.

### 5.13 Audit & Logs
- Full audit trail for policy changes, approvals, role changes, generated PRs, AI actions, and SBOM exports.

### 5.14 Integrations & APIs
- GitHub App and CI checks (blocking PR merges if policies violated)
- Webhooks / REST API to push/pull dependency & scan data
- Plugin architecture for third-party extensions

---

## 6. Dependency Flattening Analysis — (Incorporate verbatim spec)

### Dependency Flattening Analysis

- **Flattening Score (0-100)**
  - Overall dependency tree health metric
  - Measures how "flat" and manageable your dependency structure is
  - Higher scores indicate fewer conflicts and better organization

- **Conflict Detection**
  - Identifies duplicate/conflicting versions of the same package
  - Detects when multiple versions of a package exist in the dependency tree
  - Example: `lodash@4.17.20` and `lodash@4.17.21` both present
  - Each conflict reduces the flattening score by 5 points

- **Low Similarity Package Detection**
  - Finds "high-risk anchor" packages with isolated dependency trees
  - Identifies packages that share few dependencies with the rest of the project
  - These isolated packages can cause issues if they break or become unmaintained
  - Each low similarity package reduces the score by 3 points

- **Upgrade Recommendations**
  - Simulates different version combinations to find optimal upgrades
  - Suggests package upgrades that reduce conflicts
  - Provides upgrade paths that minimize dependency conflicts
  - Penalizes projects with more than 3 upgrade recommendations

- **Flattening Suggestions**
  - "Merge package versions" - Consolidate duplicate versions
  - "Upgrade package to version X" - Specific upgrade recommendations
  - "Review high-risk anchor package" - Isolated dependency warnings
  - Impact ratings (low, medium, high) for each suggestion

- **Benefits of Flattening**
  - Reduces version conflicts and build issues
  - Decreases bundle size by eliminating duplicates
  - Simplifies maintenance and updates
  - Improves build predictability
  - Enhances security by reducing duplicate vulnerable versions

---

## 7. Additional suggested features & analytics (ideas similar to Flattening)

These are proposed features that complement Dependency Flattening, targeted at enterprise needs.

### 7.1 Dependency Churn & Age Analysis
- **Metrics**: time since added, number of updates, frequency of changes
- **Alerts**: highlight packages that haven’t been updated in N months (configurable)
- **Visuals**: churn heatmap per project, top churn drivers
- **Value**: helps prioritize modernization and technical debt

### 7.2 Runtime Reachability Estimation
- **Primary heuristic**: manifest classification (`dependencies` vs `devDependencies`) to estimate runtime relevance
- **Optional advanced**: static import analysis to detect actual imports; runtime tracing (OpenTelemetry) to confirm usage in prod
- **Value**: reduce noise, prioritize only reachable vulnerabilities

### 7.3 Dependency Consolidation Opportunities
- Identify duplicated transitive dependencies across multiple direct dependencies
- Suggest consolidation plan (e.g., upgrade root package to a version that unifies transitive versions)
- Estimate impact on bundle size and security

### 7.4 SBOM Delta & Historical Comparison
- Store SBOM snapshots and provide diffs between releases/deployments
- Alert on newly-introduced runtime-only components

### 7.5 Maintainer Health & Bus-Factor Signals
- Monitor number of active maintainers, issue closure rate, PR merge frequency
- Flag packages with single-maintainer high criticality

### 7.6 Policy-as-Code Templates
- Provide default policy templates (startup, enterprise, regulated) that admins can import and customize

### 7.7 Dependency Usage Heatmap
- Visualize which parts of the codebase import a package most (files, modules)
- Correlate to test coverage and runtime usage

### 7.8 Dependency Diff in PRs
- Show delta in dependencies on every PR and surface high-risk additions inline

### 7.9 License Obligation Assistant
- For licenses that require action (e.g., copying notices), provide a checklist and automated reminders

### 7.10 Third-Party Risk Scoring & Prioritization
- Combine business-criticality (user input) with technical risk to prioritize remediation

---

## 8. AI Security Compliance Agent (Project-local Chatbot)

### Concept
An **AI-driven agent** that lives inside a project (or org) and can be queried in natural language to perform security/compliance tasks, generate reports, and even take automated actions with human approval. Think of it as a virtual security analyst embedded in the project UI.

### Capabilities
- **Queryable Chat**: Ask questions like:
  - "Summarize my project's vulnerabilities and email it to me."
  - "Which projects use lodash across the org?"
  - "List outstanding license violations for Project X."
- **Automated Report Generation**: Create PDF/HTML compliance reports on-demand or scheduled (weekly, monthly).
- **Action-Oriented Commands** (human-in-the-loop):
  - "Open upgrade PR to bump lodash in Project X to version Y" → AI drafts PR and notifies reviewers.
  - "Apply AI patch for CVE-2025-XXXX" → AI proposes code changes and creates a draft PR for review.
  - "Mark dependency ABC as approved for Project Y" (permission-gated)
- **Proactive Suggestions**: Periodic summaries: "Top 3 critical vulnerabilities open for >7 days"; "Top 5 high-risk packages across org"
- **Integrations**: Can send emails, create Jira tickets, or post Slack summaries as instructed.

### Permissions, Safety & Controls
- **Explicit Approval Flow**: Any action that changes code, creates PRs, or changes policies must require explicit approval from an authorized role (Project Manager / Maintainer / Security Officer depending on org policy).
- **Role & Scope Restriction**: Agent actions are governed by the same Roles & Permissions as humans. E.g., the agent cannot modify billing or delete orgs.
- **Audit Trail**: All agent queries & actions are logged with user context (who invoked the action), timestamps, and diff of changes. The audit trail is immutable and exportable.
- **Rate Limits & Kill Switch**: Admins can throttle or disable the agent at org or project level.
- **Explainability**: For any recommended code change, the agent summarizes why it made the change and highlights risk/reward.

### UX Patterns
- **Chat pane** docked in the project UI, with suggested prompts.
- **Action preview modal** for any risky action (shows diffs, tests, risk score, and reviewer list).
- **Scheduled automation workflows**: e.g., weekly patch PRs for low-risk dependency updates.

### Example flows
- **"Summarize and send"**: User asks agent to summarize vulnerabilities; agent prepares report, asks for recipients, and sends email; logs action.
- **"Patch & PR"**: Agent generates patch, runs test suite in ephemeral environment, creates PR with CI results, and ping reviewers.

---

## 9. Security, Compliance & Privacy considerations for AI features
- **Data handling**: Treat code and dependency metadata as sensitive. Options: on-prem/self-hosted mode, or strict tenancy and data retention policies.
- **Privacy**: Do not send raw source code to third-party LLMs by default. If using external LLMs, provide an opt-in and support enterprise private LLM connectors.
- **Verification**: Require CI checks and human review before merging AI-generated code.
- **Immutable audit logs** for all AI actions & user approvals.

---

## 10. UX & UI guidelines (high-level)
- Default to *minimal noise* — surface only impact-level alerts by default.
- Use progressive disclosure: summary → details → full tree explorer.
- Offer both **List View** and **Board View** for watchlist management.
- Keep personal workspace visible (header button) for personal watchlist access.
- Use color and badges consistently (severity, license state, watchlist state).

---

## 11. API & Data Model Notes (engineering starting points)
- **Core objects**: Org, Project, User, Role, Team/Tag, RepoLink, DependencyNode, Vulnerability, WatchlistCard, SBOMSnapshot, Alert, AuditEvent.
- **Dependency graph storage**: graph DB or relational DB with edge table (store parent->child, version, source, depth, reachable flag).
- **Event model**: publish events like `dependency.added`, `vuln.detected`, `watchlist.proposed`, `ai.pr.created` for plugin hooks.
- **Rate limiting & caching**: cache GitHub SBOM results and lockfile parses to reduce API usage.

---

## 12. Roadmap (MVP → v1 → v2 → v3)

### MVP (90 days)
- Org & Project model, roles, project creation
- GitHub integration for repo linking & fetching dependency graph
- Dependencies page (direct + transitive collapsed) with license & vuln listing
- Project Watchlist (basic list view) + Personal Watchlist (header button)
- Basic Alerts (critical vulns affecting main) & SBOM export (SPDX)
- Bump button (open PR) for patch/minor updates

### v1 (3–6 months)
- AI summarization for vulnerabilities
- Branch tracking (auto-track active branches), transitive alert grouping
- Compliance tab with non-compliant package list and SBOM cross-checker
- Dependency Flattening Analysis (score + suggestions)
- Plugin framework MVP (webhooks & basic SDK)

### v2 (6–12 months)
- AI patch generation (human-in-the-loop PRs)
- Advanced risk scoring, typosquat detection, maintainer health metrics
- Watchlist Kanban board, advanced search & filters
- Integrations: Slack, Jira, CI checks (GitHub Actions)

### v3 (12+ months)
- Runtime reachability tracing integration (OpenTelemetry) and SBOM delta automation
- Provenance checks (Sigstore/SLSA) and supply chain integrity features
- Plugin marketplace, local CLI, and IDE extensions
- Enterprise features: SSO/SCIM, advanced audit logs, on-prem/self-hosted offering

---

## 13. Success metrics
- Adoption: number of orgs, projects onboarded
- Engagement: % of projects with active watchlist / weekly scans
- Time-to-remediation: average time from vuln detection to PR merge
- False-positive rate for AI patch proposals (human rejection rate)
- Customer satisfaction / NPS for security & developer personas

---

## 14. Open questions & decisions (to finalize)
- Acceptable default for branch auto-tracking window (30 days recommended)
- Which ecosystems to support at MVP (npm recommended)
- Default policy templates to provide
- LLM provider & privacy model for AI features (in-house/private vs hosted)

---

## 15. Next actions
1. Prioritize MVP scope and agree on initial ecosystems (start with npm).
2. Draft API & event contract for GitHub integration and plugin hooks.
3. Build basic GitHub App and dependency ingestion pipeline.
4. Design the Dependencies & Watchlist UI wireframes (list + board toggle).
5. Prototype a lightweight AI summarizer (org-level weekly digest).

---

*Document created for iterative editing — use this as the canonical spec. Add sections or comments directly and we will refine.*

