# Research: DAST (Dynamic Application Security Testing)

## Current State in Deptex

**Zero DAST today.** Deptex's pipeline is entirely static: dependency parsing, SBOM, vulnerability lookup, Semgrep SAST, TruffleHog secrets, tree-sitter usage extraction, EPD reachability. None of it runs the application or sends a single HTTP request to it. Surface mentions: `ROADMAP.md` lists "DAST scanning — Nuclei-based dynamic testing, API scanning. The most-requested ASPM feature beyond SCA" under Scanner Expansion. An archived Phase 21 sketch exists in `.cursor/plans/archive/phase_20-37.plan.md` (Nuclei + authenticated DAST + API/OpenAPI fuzzing + scheduled scans + surface monitoring), but it predates the reachability/Aegis work and is not aligned to the current architecture. An older auto-memory note marked CSPM/DAST "out-of-scope" — superseded by ROADMAP.md.

What we *do* have that DAST can lean on heavily:
- **34 framework detectors** across 8 languages (`backend/extraction-worker/src/framework-detection/`) — we already know if a project is Express, Fastify, FastAPI, Spring, Rails, Gin, etc., and where its HTTP entry points are.
- **tree-sitter usage extractor** — knows which handlers are touched by which routes, what data flows through them.
- **Aegis** — autonomous agent with BYOK AI (OpenAI/Anthropic/Google), tool-using ReAct loop, approval workflow, scheduled automations via QStash.
- **Extraction-worker on Fly.io** scale-to-zero — same pattern would run a DAST scanner machine.
- **Self-hosting story** (shipped April 2026) — Docker-only extraction-worker + BullMQ path proven; DAST scanner could ride the same rails.
- **Security tab** unified UI for vulns/secrets/Semgrep — DAST findings would slot in alongside.
- **PR check engine** (GitHub/GitLab/Bitbucket) — natural home for diff-aware DAST.

## Competitive Landscape

### StackHawk — modern dev-first DAST
- **Surface:** REST, GraphQL, SOAP, gRPC. CLI-driven, YAML config, runs in CI alongside tests, diff-aware incremental scanning.
- **Pricing:** Pro $42/contributor/mo (5 min scans), Enterprise $59 (20 min), unlimited apps/scans on every tier.
- **2024-2026:** LLM application security testing, **MCP server security testing** (auto-discovers MCP tools and tests for vulns), code-based PII/PCI/PHI tagging.
- Source: [stackhawk.com/solutions/dast](https://www.stackhawk.com/solutions/dast/), [G2 pricing](https://www.g2.com/products/stackhawk/pricing)

### Bright Security (formerly NeuraLegion) — AI-driven DAST
- **Surface:** AI-validated findings, vendor claims **<3% false positives**, OWASP Top 10 + API Top 10 + **OWASP LLM Top 10** (one of few that explicitly does so).
- **Distribution:** CLI + Docker + IDE + branch/PR-scoped Git.
- **Pricing:** Freemium; commercial figures not public.
- Source: [appsecsanta.com/bright-security](https://appsecsanta.com/bright-security)

### Detectify — DAST + Attack Surface Management hybrid
- **Two-pillar:** Surface Monitoring (continuous external discovery, 100k+ subdomains scanned 3×/day) + Application Scanning (deep DAST).
- **2025 launches:** Intelligent Scan Recommendations (which assets warrant DAST), Scan Interference Detection (probes for WAF throttling).
- Source: [blog.detectify.com/news/detectify-year-in-review-2025/](https://blog.detectify.com/news/detectify-year-in-review-2025/)

### Snyk API & Web (built on Probely, acquired Nov 2024)
- **Confirmed live April 22, 2025.** AI-powered API testing using GenAI + traditional ML for OWASP API Top 10, especially **BOLA**. Added GraphQL.
- **Code-Informed Dynamic Testing** correlates SAST + DAST findings — early reachability-aware DAST. **245% QoQ ARR growth** since launch.
- **Akamai partnership (Aug 2025):** ingests API inventories from Akamai's API Security catalog.
- Source: [snyk.io/news/snyk-launches-snyk-api-and-web...](https://snyk.io/news/snyk-launches-snyk-api-and-web-to-reimagine-dast-innovation-for-ai-era/), [snyk.io/blog/snyk-akamai-integration-api-discovery-testing](https://snyk.io/blog/snyk-akamai-integration-api-discovery-testing/)

### Invicti / Acunetix — enterprise incumbents
- **Invicti's "proof-based scanning"** safely exploits findings to produce proof of exploit, drastically reducing FP triage. Acquired **Kondukto (Aug 2025)** for ASPM correlation.
- **Acunetix** is the SMB sibling. Both: REST/SOAP/GraphQL/gRPC + modern SPA crawling.
- Source: [invicti.com/blog/web-security/10-best-dast-tools](https://www.invicti.com/blog/web-security/10-best-dast-tools)

### Aikido Security — Deptex's closest peer
- **Engine:** Hybrid — **Nuclei** for self-hosted apps (WordPress, GitLab, Jira), **OWASP ZAP subset** for web apps with their own de-noising, **in-house** for API discovery REST/GraphQL.
- **Auth:** Authenticated DAST supported (manual credential provision, JWT weakness checks). No automated login scripts.
- **Pricing:** DAST included in unified flat-rate, not an add-on.
- **2024-2026:** Auto API discovery, AI Pentesting, Continuous Pentests, on-prem DAST planned for enterprise.
- Source: [aikido.dev/attack/surface-monitoring-dast](https://www.aikido.dev/attack/surface-monitoring-dast), [aikido.dev/blog/top-dynamic-application-security-testing-dast-tools](https://www.aikido.dev/blog/top-dynamic-application-security-testing-dast-tools)

### GitHub Advanced Security — confirmed no native DAST
- CodeQL is SAST only. 60+ marketplace integrations to third-party DAST. No public roadmap signal that GitHub will build first-party DAST.
- Source: [github.com/resources/articles/what-is-dast](https://github.com/resources/articles/what-is-dast)

### Jit.io — DAST included
- **Engine:** OWASP ZAP under the hood, automated config. Both unauth + authenticated. CI: GH Actions / GitLab / Bitbucket / Azure.
- Their **Context Engine** prioritizes findings by runtime context (production exposure, internet-facing).
- Source: [docs.jit.io/docs/run-a-web-application-scanner](https://docs.jit.io/docs/run-a-web-application-scanner)

### Arnica — no first-party DAST
- ASPM/code-side focus; writes about DAST tools but doesn't ship one. Unverified absence but no product page surfaced.

### ProjectDiscovery Nuclei (open-source engine)
- **Templates (April 2026):** 11,997 files / 873 dirs. Categories: http (9,281), cloud (659), file (436), network (259), code (251), **dast (240)**. **1,496 unique CVEs (454 CISA + 1,449 VulnCheck KEV).** Latest: v10.4.2, April 15 2026.
- MIT engine, open templates. Used commercially by Aikido and many ASPM vendors. ProjectDiscovery sells a managed Cloud platform.
- Source: [github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)

### OWASP ZAP (open-source engine)
- **2025 highlights:** Browser-based auth (auto-fills login forms, supports TOTP, multi-screen flows), Client Script Auth via recordable Zest scripts, alert de-dup in core 2.17.0.
- **2026 plans:** Third-party browser ext integration (PTK, Foxhound), SPA exploration improvements, **opt-in AI** with user-controlled LLM/model selection.
- **March 2026:** **ZAP MCP server released** — AI assistants can drive scans by NL.
- Source: [zaproxy.org/blog/2026-02-02-zap-updates-2025-highlights-2026-plans/](https://www.zaproxy.org/blog/2026-02-02-zap-updates-2025-highlights-2026-plans/), [zaproxy.org/blog/2026-04-03-zap-updates-march-2026/](https://www.zaproxy.org/blog/2026-04-03-zap-updates-march-2026/)

### Burp Suite (PortSwigger)
- **Renamed Burp Suite Enterprise → Burp Suite DAST** (April 2025).
- **Automation:** GraphQL API (recommended) + REST API. Bulk schedule across thousands of apps.
- **Pro 2025.2:** Montoya API + built-in AI (PortSwigger-mediated LLM calls in extensions).
- **Free programmable tier:** does not exist in 2026. Community is GUI-only. Pro ~$475/yr/user.
- Source: [portswigger.net/blog/the-year-so-far-how-burp-suite-dast-is-leveling-up...](https://portswigger.net/blog/the-year-so-far-how-burp-suite-dast-is-leveling-up-enterprise-security-in-2025)

### API-DAST wave: Akto / Pynt / APIsec / Salt / Wallarm / Escape
- **Akto:** OSS API-security pivoted to **AI Agent Security** in 2025 — first dedicated MCP security solution (June), full Agentic Security Platform (Sept). 1,000+ API tests, 40+ traffic connectors, free OSS tier, paid from $1,890/mo.
- **Pynt:** Lightweight, dev-centric, derives tests from real traffic captures. Reduces FPs ~90%.
- **APIsec:** AI-driven attack scenarios from API specs, 1,200+ playbooks. From $650/mo.
- **Salt Security:** Runtime-traffic discovery, out-of-band. 2025 rollouts: Salt Illuminate, Salt Surface, Ask Pepper AI, MCP/AI agent action security. Heavy "monthly innovation" cadence.
- **Wallarm:** Combined runtime protection + DAST. Schema-Based Testing as Docker agent in CI. 2025: API Session Blocking, Session Intelligence, Agentic AI Protection.
- **Escape:** Auto-generates OpenAPI from observed APIs + continuous schema drift detection. Front-end/SPA DAST in beta (2025).
- Source: [appsecsanta.com/akto](https://appsecsanta.com/akto), [pynt.io/learning-hub/...](https://www.pynt.io/learning-hub/api-security-testing-guides/api-security-testing-tools), [salt.security/blog/...12-months-of-innovation...](https://salt.security/blog/the-12-months-of-innovation-how-salt-security-helped-rewrite-api-ai-security-in-2025), [escape.tech/blog/front-end-dast-beta/](https://escape.tech/blog/front-end-dast-beta/)

## Landscape Synthesis

### Table-stakes (every serious vendor has these in 2026)
- REST + GraphQL + SOAP, with gRPC at the API-DAST tier.
- CI-native execution (GitHub Actions, GitLab CI, Jenkins, Azure) with YAML config-as-code.
- Authenticated scanning: form/cookie, JWT, OAuth/SSO redirect flows.
- OWASP Top 10 + API Top 10 detection.
- API discovery from source / traffic / schema (HAR / OpenAPI / Postman).
- Docker/CLI scanner for local + air-gapped use.
- PR-comment / feedback loop in GitHub/GitLab/Bitbucket.

### Frontier features (2-3 vendors do this well)
- **OWASP LLM Top 10 testing** — Bright STAR, StackHawk, Salt/Wallarm.
- **MCP server security testing** — StackHawk, Akto, Salt all shipped 2025.
- **Code-Informed / reachability-aware DAST** — Snyk's Code-Informed Dynamic Testing is the public poster child. Invicti's proof-based scanning is the older form.
- **AI-validated FP suppression** — Bright (<3% claim), Aikido de-noising layer.
- **AI-generated payloads** — Snyk GenAI for BOLA, APIsec 1,200 playbooks, Burp Montoya AI.
- **Schema-drift / OpenAPI auto-gen** — Escape leads.
- **Browser-based authenticated DAST with TOTP and multi-step flows** — ZAP made huge strides 2025; commercial vendors follow.

### Whitespace nobody does well
- **Reachability-aware DAST end-to-end** — Snyk gestures at it but messaging is thin. Nobody has demonstrated "this CVE in your dependency is reachable from THIS live HTTP entry point" credibly.
- **Self-hostable polished ASPM with integrated DAST** — Aikido is closest but SaaS-first; on-prem is enterprise Q4. No one offers a polished open-core self-host with SAST+SCA+DAST.
- **Authenticated DAST without manual scripting** — every vendor still struggles. AI-assisted login script generation from natural language is unsolved.
- **Honest open benchmarks** — vendor FP claims with no shared corpus. Whitespace for credible "we tested 100 known-vulnerable apps and DAST found N" data.

### Where the market is heading
1. **API-DAST is eating web-DAST.** Every "DAST 2026" comparison frames it as REST+GraphQL+gRPC, not HTML crawling.
2. **AI is both feature and target.** Generative payload synthesis on offense; OWASP LLM Top 10 + MCP testing as new attack surfaces on defense.
3. **DAST inside ASPM, not standalone.** Snyk+Probely, Invicti+Kondukto, Aikido (ZAP+Nuclei), Jit (ZAP). Consolidation is real.
4. **Reachability is the noise-reduction story.** SCA pioneered it. SAST adopted it. **DAST is next.** First mover wins the noise war.
5. **OSS engines are commoditized substrates.** Nuclei (~12k templates) and ZAP (mature auth + automation API + Docker + MCP). Custom engines no longer make sense for new entrants.
6. **Agentic / NL-driven scanning emerging.** ZAP MCP server, Salt Ask Pepper AI, Burp Montoya AI. Surface forming, still early.

### Deptex position today
Behind on **everything DAST**. But ahead of everyone on **tree-sitter framework detection** (34 detectors, 8 languages) and **EPD reachability** — and those are the exact ingredients for the reachability-aware-DAST whitespace nobody has filled.

---

## Shortlist (Recommended)

### 1. Reachability-Coupled DAST — 5/5 value, 5/5 leverage
- **One-liner:** Link DAST findings back to the exact code path that produced them — "this SQLi at `/api/users` is in `users.ts:42`, reachable from `app.use('/api/users', router)` at `index.ts:18`, and your CVE-2024-XXXX in `mysql2` is reachable through it."
- **Target user:** Security engineer triaging findings; developer who needs to know what to fix first.
- **Problem:** DAST findings come without code attribution. Triage is manual URL-to-handler mapping. SCA reachability + DAST runtime hits = both tools say "this is real" but nobody connects them.
- **Competitive positioning:** Snyk's "Code-Informed Dynamic Testing" gestures at this since April 2025 ([snyk.io/product/dast-api-web/](https://snyk.io/product/dast-api-web/)) but the public detail is thin and it's tied to Probely's web crawler, not a tree-sitter usage graph. We'd land it deeper because we already have the route-to-handler map and EPD entry-point classification.
- **Deptex fit:** Tree-sitter framework detectors (already shipped) + EPD entry points (Phase 4 shipped) + Semgrep rule engine (Phase 5 in flight) + new DAST engine output. Pure leverage.
- **Size:** XL (full pipeline integration + UI for the cross-link).
- **Bucket:** Differentiator.
- **Why shortlisted:** Hits whitespace nobody owns, leans on Deptex's strongest existing assets, and turns DAST from a noisy commodity feed into the most credible "yes this CVE matters" signal in the platform.

### 2. Self-Hostable DAST Scanner — 4/5 value, 5/5 leverage
- **One-liner:** A second extraction-worker mode that runs ZAP (or Nuclei) in Docker against a target URL, scale-to-zero on Fly.io for cloud or local-only for self-host. No SaaS dependency.
- **Target user:** Enterprise/regulated org that can't send their app to a SaaS scanner; OSS users who want to scan their staging env on their own infra.
- **Problem:** Aikido is SaaS-first. Snyk API & Web is SaaS-only. Bright has Docker but isn't an ASPM. The on-prem ASPM-with-DAST gap is real.
- **Competitive positioning:** Aikido on-prem DAST is "Q4 enterprise-first." StackHawk runs in CI but findings hit their cloud. We'd be the first polished open-core ASPM with self-hostable DAST.
- **Deptex fit:** The self-hosting work shipped April 2026 already runs the extraction-worker as Docker + BullMQ. DAST is one more worker mode. Same pattern, same infra.
- **Size:** M (worker plumbing + ZAP/Nuclei orchestration + scan-target config UI).
- **Bucket:** Differentiator.
- **Why shortlisted:** Compounds with the existing self-host story; opens the enterprise/regulated wedge that's blocked Snyk-style users; cheap because we own the worker pattern.

### 3. AI Payload Generator (Aegis-driven DAST customization) — 4/5 value, 5/5 leverage
- **One-liner:** Aegis reads the codebase (entity types, tenant fields, business-logic identifiers) and emits Nuclei templates / ZAP scan rules tuned to that org's actual data shape — not generic OWASP Top 10 fuzz.
- **Target user:** Security engineer who wants BOLA/IDOR coverage that actually exercises *their* tenant model.
- **Problem:** Generic DAST payloads hit ~5% of business-logic vulns. APIsec offers 1,200 playbooks but they're vendor-curated, not codebase-aware.
- **Competitive positioning:** Snyk uses GenAI for BOLA payload generation ([snyk.io/news/snyk-launches-snyk-api-and-web...](https://snyk.io/news/snyk-launches-snyk-api-and-web-to-reimagine-dast-innovation-for-ai-era/)) but it's based on observed traffic. Ours would be based on the *source code* — which we already have parsed.
- **Deptex fit:** Aegis (ReAct + BYOK AI) + tree-sitter route/handler map + Phase 5's AI-rule-generation pipeline (which already does codebase-aware Semgrep rule synthesis — same architecture extends to DAST templates).
- **Size:** L (template generator + Aegis tool + scan integration).
- **Bucket:** Differentiator.
- **Why shortlisted:** Direct extension of the Phase 5 AI-rule-generation infrastructure; only credible because we already have the code graph to feed.

### 4. Aegis Login Recorder — natural-language authenticated DAST — 4/5 value, 5/5 leverage
- **One-liner:** "Aegis, scan my staging app at staging.acme.com — log in with test@acme.com / password and look for vulns." Aegis generates the Zest/Playwright auth script from NL, runs the scan, summarizes findings.
- **Target user:** Developer or security engineer who hits the auth-scripting wall on every DAST tool.
- **Problem:** Authenticated DAST is table-stakes pain at every vendor. Aikido = manual creds, ZAP = recorded Zest scripts, Burp = recorded sessions. SaaS auth + MFA + SSO + device-bound = scripting hell.
- **Competitive positioning:** Nobody offers AI-written auth scripts from NL today. ZAP MCP server (March 2026) lets external AI drive a scan but the auth scripting itself is still manual.
- **Deptex fit:** Aegis ReAct loop + BYOK AI + ZAP/Playwright tool wrapping. Approval workflow gates anything destructive (e.g. password reset endpoints).
- **Size:** M (Aegis tool + ZAP/Playwright integration + approval flow).
- **Bucket:** Differentiator.
- **Why shortlisted:** Solves a universal pain point; pure leverage on Aegis; demo-friendly ("watch Aegis log into my app and pen-test it").

### 5. PR-Diff DAST — 4/5 value, 5/5 leverage
- **One-liner:** When a PR touches `users.ts:postUser`, only run DAST against `/api/users POST` — not the full app. Tree-sitter knows which routes are touched; PR check engine already integrates with GitHub/GitLab/Bitbucket.
- **Target user:** Developer who shouldn't wait 20 minutes for full-app DAST on a 3-line change.
- **Problem:** Full-app DAST is too slow for PR feedback. StackHawk diff-aware scanning is the closest analog but operates on URL diff, not source diff.
- **Competitive positioning:** StackHawk markets diff-aware ([stackhawk.com/solutions/dast](https://www.stackhawk.com/solutions/dast/)) but the diffing is at scan-config level. We'd diff at the *source-code* level via tree-sitter, which is more precise and doesn't need a baseline scan.
- **Deptex fit:** Tree-sitter route map (shipped) + PR check engine (shipped) + new DAST scanner (#2) gated by changed-handlers list.
- **Size:** M (after #2 lands).
- **Bucket:** Parity-plus, leaning differentiator.
- **Why shortlisted:** Devex win that competitors approximate but can't fully replicate without our code graph; cheap once #2 exists.

---

## Moonshots to Consider

### M1. DAST-on-Local-Dev via Aegis chat
"Aegis, scan localhost:3000 right now." Aegis spawns an ephemeral Nuclei/ZAP scan against the dev's local port (with Aegis's approval flow), summarizes findings into the chat thread, and offers to open a fix PR. Compounds with #4 (login recorder) for authenticated local scans. Would be the first DAST experience inside an AI assistant chat.

### M2. Prove-Exploit Mode (Invicti's proof-based scanning, but Aegis-driven)
For high-severity DAST findings, Aegis attempts a controlled exploit in an isolated sandbox to produce proof-of-exploit before paging humans. Invicti's proof-based scanning is the model ([invicti.com/blog/...](https://www.invicti.com/blog/web-security/10-best-dast-tools)) but it's deterministic; ours would be Aegis with safety guardrails. Hard problem (sandbox isolation, blast-radius control), but if it lands, the FP-rate story becomes "we don't claim a vuln unless we exploited it."

---

## Full Brainstorm (Appendix)

### A. MCP Server Security Scanner — 4/5 value, 3/5 leverage
- **One-liner:** Auto-discover MCP servers configured in repos (`.mcp/`, `claude_desktop_config.json`, etc.); scan for prompt injection, tool impersonation, leaked secrets in tool definitions.
- **Competitive:** StackHawk (Sept 2025), Akto (June 2025), Salt (Sept 2025) all shipped MCP testing in 2025. Frontier and crowded.
- **Deptex fit:** New scanner module; framework-detection-style discovery; Aegis tool wrapping. Fits the "AI security platform" narrative.
- **Size:** M. **Bucket:** Frontier.
- **Why not shortlisted:** Three competitors already shipped this in 2025; we'd be catching up, not leading. Worth doing eventually as table-stakes for the AI-platform thesis, but not the highest-leverage move now.

### B. OWASP LLM Top 10 Suite
- **One-liner:** Detect LLM SDK usage via tree-sitter (we already detect 34 frameworks); when found, run prompt-injection / data-exfil / output-handling tests at runtime.
- **Competitive:** Bright STAR is the explicit leader; StackHawk has an LLM testing product. Two vendors, frontier.
- **Deptex fit:** Framework detection extension + BYOK AI for adversarial prompt synthesis.
- **Size:** L. **Bucket:** Frontier.
- **Why not shortlisted:** Narrow audience today (only orgs running LLMs). Worth bundling into #3 (AI Payload Generator) as a payload type rather than a standalone product.

### C. Spec-Aware API Fuzzer
- **One-liner:** Auto-discover OpenAPI/GraphQL schema from the repo (parse spec files + framework decorators via tree-sitter), feed to a Nuclei + AI-payload pipeline.
- **Competitive:** Escape ([escape.tech](https://escape.tech/blog/new-product-improvements-jan-2025/)), Snyk (via Akamai partnership), Akto. Crowded.
- **Deptex fit:** Tree-sitter spec parsing + framework detection.
- **Size:** L. **Bucket:** Parity-plus.
- **Why not shortlisted:** Largely subsumed by #3 (AI Payload Generator) — the schema-awareness is one input to that pipeline, not a separate product.

### D. Continuous Schema Drift Watch
- **One-liner:** Diff observed API surface vs declared OpenAPI spec, alert on drift.
- **Competitive:** Escape leads.
- **Deptex fit:** Needs runtime traffic capture infrastructure we don't have. Lower leverage than other shortlist items.
- **Size:** L. **Bucket:** Parity-plus.
- **Why not shortlisted:** No existing capture path; would require a separate eBPF/proxy product first.

### E. Surface Monitoring (subdomain enum, exposed services)
- **One-liner:** Domain enumeration, subdomain discovery, exposed-service detection for connected git orgs.
- **Competitive:** Detectify ([blog.detectify.com](https://blog.detectify.com/news/detectify-year-in-review-2025/)) — entire product category.
- **Deptex fit:** Mostly net-new infrastructure, weak overlap with our code-side stack.
- **Size:** L. **Bucket:** Table-stakes for ASPM expansion, weak for DAST-specifically.
- **Why not shortlisted:** Adjacent to DAST, not core to it. Belongs in a dedicated "Asset discovery / RSPM" stream from `ROADMAP.md`.

---

## Recommended Next Step

Run `/interview` on **concept #1 (Reachability-Coupled DAST)** to refine scope before planning. It's the highest-value, highest-leverage move and the one most clearly differentiated from every competitor; the interview should narrow which engine (ZAP vs Nuclei vs both), which entry-point granularity, and what the cross-link UI looks like inside the existing Security tab.

Concept #2 (Self-Hostable DAST Scanner) is the natural sibling — they share the worker plumbing — and is a strong second `/interview` candidate if you want to scope the engine choice and worker shape *before* tackling the reachability coupling.

#3, #4, #5 are interview-ready after #1+#2 land the foundation.
