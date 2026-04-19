# Deptex Roadmap

> **Living document.** Updated across conversations as priorities shift, scope changes, or items ship. Edit existing entries over rewriting. Reorder freely. Move items between sections as the picture sharpens.
>
> **How to read it.** "Now" is actively in flight. "Next" is what follows. After that, features are grouped by theme — ordered roughly by priority within each group, but not locked to a timeline. "Always-on" is cross-cutting. "Parking lot" is for unplaced ideas.
>
> **A note on phasing.** The legacy `phase_XX_*.plan.md` files are internal dev scaffolding and the term "phase" is being removed from the app and codebase. This roadmap intentionally avoids phase numbers — features are described by what they do, not when they were planned.

---

## Now

Active or imminent.

### Org overview graph redesign
The org overview tab is the first thing anyone sees. Current graph is functional but ugly. Target visual quality of n8n / Railway / Linear's graph interfaces. High-leverage polish win — changes the perceived quality of every other feature.
- Status: not started
- Bucket: Polish

### Extraction worker reachability — atomic pipeline refactor
Refactor `pipeline.ts` so all DB writes happen in a single commit phase at the end. Pre-generate UUIDs, accumulate state in memory, preserve user decisions (ignored / risk-accepted / notes) across re-extractions. Blocks every other extraction-worker upgrade.
- Status: not started
- Bucket: Differentiator (foundation for reachability work)

### Extraction worker reachability — tree-sitter universal usage extractor
Single TypeScript program using tree-sitter with per-language queries. Replaces broken JS/Go usage extraction. Outputs atom-compatible usage-slice JSON. Covers JS/TS, Python, Go, Rust, C#, Ruby, PHP, Java.
- Status: not started
- Bucket: Differentiator

### Extraction worker reachability — Semgrep rules engine + first ~20 CVE rules
Per-CVE rules for top CVEs (Log4Shell, lodash template, PyYAML, etc.). Rule engine loads only rules matching detected CVEs. Two tiers per CVE: taint rule (`confirmed`) and call-pattern rule (`function`).
- Status: not started
- Bucket: Differentiator

---

## Next

After Now wraps.

### Re-enable EPD wired to Semgrep taint sources
Use Semgrep taint sources + tree-sitter data for entry point classification. Real path depth from taint traces. EPD activates for CVEs with reachability rules. The "transparent contextual scoring" pillar finally working end-to-end.
- Bucket: Differentiator

### AI rule generation pipeline
LLM reads CVE advisory + patch diff, drafts Semgrep rule. Force multiplier — turns rule-writing from days-per-rule into hours-per-rule. Lets the rule library scale to 100+ CVEs without grinding.
- Bucket: Differentiator (and the unlock for the next item)

### Aegis hardening + comprehensive testing pass
Aegis is the most demo-able feature and currently the most untested. Manual end-to-end exercise of all 50+ tools. Identify the ones that are broken / slow / hallucinate. Add automated tests for the critical paths. Without this, every Aegis demo is a coin flip.
- Bucket: Polish + Risk reduction

### Aegis as "full security engineer" expansion
Push Aegis from "copilot answering questions" toward "agent that owns workflows end-to-end." Sprint orchestration, autonomous PR review, scheduled automations actually being trusted enough to run unattended.
- Bucket: Differentiator

### Sidebars overhaul (team / project / org)
Currently underweight. Should surface much richer context — recent activity, key metrics, action items, AI suggestions. Companion polish work to the org overview graph.
- Bucket: Polish

### Notifications-as-code: n8n-style trigger visualization
Notifications already exist as code. Add the visual layer: show users what their triggers will fire on, what destinations they hit, what the condition tree looks like — without making them read JS to understand it. AI-assisted trigger building.
- Bucket: Polish + Differentiator

### Vulnerabilities tab redesign
Better presentation of vulns across the app. SLA badges, EPD context, reachability level prominently shown, smarter sorting/filtering.
- Bucket: Polish

### SLA management UI + pro tier gating
Backend schema and logic already built (Phase 15). Need: SLA policy definition UI in org settings (per-severity windows, per-asset-tier overrides, pause/resume). SLA compliance dashboard on the org security tab (compliance rates, MTTR trends, breach counts by team/severity). Per-vuln countdown badges and status indicators across the app. Wire up warning + breach notifications through the notification system. Gate behind pro/paid plan — this is a natural monetization boundary (free = see your vulns, pro = enforce remediation windows and prove compliance).
- Bucket: Polish + Monetization

---

## AI & Analysis Depth

Pushing reachability and AI capabilities further — the features that make Deptex genuinely different from competitors.

### AI cross-file taint stitching
Mechanical import-chain tracing via tree-sitter, then LLM assessment for ambiguous multi-hop cases. Confidence-scored upgrades from `function` to `confirmed`. The differentiated AI feature competitors don't have.
- Bucket: Differentiator

### CodeQL integration
Selective CodeQL queries for top critical CVEs where maximum confidence matters.
- Bucket: Differentiator

### Pre-computed package reachability cache
Background analysis of top packages per ecosystem. Skip library re-analysis at scan time.
- Bucket: Differentiator

### Upgrade impact analysis
Breaking change prediction, blast radius, migration paths. AI-driven recommendation of *how* to upgrade safely, not just what to upgrade to.
- Bucket: Differentiator

---

## Scanner Expansion

New scanning domains beyond SCA. Each one widens the attack surface Deptex covers.

### Custom scanner integration (BYOS / SARIF import)
Accept findings from external scanners via SARIF. One integration framework, then incremental native scanners on top. Lets Deptex meet users where they already are instead of replacing every tool.
- Bucket: Surface area

### DAST scanning
Nuclei-based dynamic testing, API scanning. The most-requested ASPM feature beyond SCA.
- Bucket: Surface area

### IaC scanning
Terraform / CloudFormation / K8s / Docker Compose via Checkov or KICS. Integrates into the same Depscore + reachability + policy model.
- Bucket: Surface area

### CSPM (cloud security posture management)
AWS / GCP / Azure misconfiguration scanning via Prowler. Integrates findings into the org-wide context.
- Bucket: Surface area

### Asset discovery + RSPM
Auto-discover repos across connected git orgs, surface coverage gaps, repo security posture scoring.
- Bucket: Surface area

### Feature branch / pre-merge security
Diff-aware scanning, security score comparison. PRs show their own delta clearly.
- Bucket: Surface area

### Attack surface management
Domain enumeration, exposed services, cert monitoring. External view to complement internal scanning.
- Bucket: Surface area

### Runtime protection
Lightweight SDK / middleware, request blocking, bot detection. Closes the loop from "found a vuln" to "blocking exploitation."
- Bucket: Surface area

---

## Enterprise & Compliance

Features that make Deptex sellable to organizations with real security programs.

### Compliance framework mapping
SOC 2, ISO 27001, NIST, OWASP mapping with evidence collection. Turns Deptex into something a security team can defend in front of an auditor.
- Bucket: Enterprise

### Enterprise hardening
SSO via SAML (Team+ tier), MFA enforcement, session management, audit logs, IP allowlists. Already partially built — needs production polish.
- Bucket: Enterprise

### Self-hosted runner / BYOC
Downloadable Docker agent, air-gapped mode. The single biggest enterprise deal-blocker for finance / healthcare / gov.
- Bucket: Enterprise

### Plans, billing, usage metering (production-grade)
Stripe Checkout + Billing + Customer Portal + Webhooks. Usage metering tied to syncs/projects/members. Plan limit enforcement across all features. Real billing UX in org settings.
- Bucket: Enterprise

### VEX + supply chain attestation
Auto VEX generation, Sigstore integration, SLSA attestation. Makes Deptex output trustable upstream.
- Bucket: Enterprise

### Executive intelligence / CISO dashboard
MTTR trends, risk scoring, board-ready reports, industry benchmarking.
- Bucket: Enterprise

### Multi-tenant / white-label / MSP support
Lets agencies and MSPs run Deptex for their clients.
- Bucket: Enterprise

---

## Platform & Ecosystem

Making Deptex extensible and community-driven.

### Repo cleanup + open-source readiness
Restructure the repo so a stranger can clone it, understand the architecture, and contribute. Remove "phase" leakage from the codebase. Contributor docs, code of conduct, issue templates, clear module boundaries. Public roadmap page surfaced in the app.
- Bucket: Open source

### Public API + SDK ecosystem
REST API, OpenAPI spec, API keys, SDKs (Python / TypeScript / Go), Terraform provider. Lets the platform become extensible by users.
- Bucket: Platform

### Marketplace + plugin ecosystem
Community-contributed scanners, rules, automations, integrations. The "billion-dollar" surface that only matters when there are users.
- Bucket: Platform

### AI/ML supply chain security
Model inventory, ML-BOM, prompt injection detection. Becomes more important as orgs ship more AI.
- Bucket: Platform

### Threat modeling
Auto STRIDE analysis, DFDs, attack trees, threat-to-finding mapping. The most differentiated thing nobody has done well yet.
- Bucket: Platform

### Security culture / gamification
Champions program, training modules, leaderboards, challenges. Soft features but high engagement.
- Bucket: Platform

---

## Always-on

Cross-cutting work that runs in parallel with everything above.

- **Testing.** Especially Aegis. Especially anything that touches the extraction pipeline. Add tests as features land, not as a separate phase.
- **Documentation.** Both user-facing docs and contributor docs. Update with every shipped feature.
- **Polish & UX taste.** Every feature passes through a "would I show this in a demo?" filter before being called done.
- **Security of Deptex itself.** Audit logs, secret rotation, key versioning, dependency hygiene on Deptex's own deps. Eat the dog food.
- **Open-source community building.** Once the repo cleanup lands, sustained effort on issues, PRs, discussions, blog posts.

---

## Parking lot

Ideas mentioned but not yet placed. Move into a section when ready.

- AI-suggested asset tier classification on first project import
- Slack bot for Aegis (interactive, not just notifications)
- Browser extension for security-aware code review on GitHub.com
- Custom Depscore weight tuning per org (advanced policy users)
- Public benchmarks / leaderboard of OSS package reachability
- "Weakest link" rollup visualization improvements (blast radius UI)
- Onboarding flow rework (first-time-user experience)
- Mobile-friendly read-only views for execs

---

## Notes on this roadmap

- **Estimates intentionally absent.** Order matters; calendar dates don't.
- **Now is the only section that should be treated as committed.** Everything else is directional.
- **Reorder freely.** If something further down suddenly matters more, move it up. The point is a thinking surface, not a contract.
- **Update this file as decisions get made.** When a Now item ships, move it to a "Shipped" log (TBD section) or just delete it. When a new idea lands, drop it in Parking Lot until it's ready to slot in.
