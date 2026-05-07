# Research: Malicious Packages

## Current State in Deptex

Today, Deptex's "malicious package" surface is one bit of state plumbed through several places, with no real ingestion or scanning behind it.

**What exists:**
- `dependencies.is_malicious BOOLEAN` (`backend/database/add_is_malicious_to_dependencies.sql`) — set in `backend/src/routes/workers.ts:1206` when **GHSA classifies any advisory for the package as `MALWARE`** (single source: GraphQL classification field on GHSA, see `backend/src/lib/ghsa.ts:20`).
- Depscore wiring: `backend/extraction-worker/src/depscore.ts:86` applies `maliciousWeight = 1.3` (raises priority); `calculateDependencyScore` applies `maliciousMultiplier = 0.15` (drops reputation score by 85%).
- Aegis surfaces it: `backend/src/lib/aegis/pr-review.ts:79`, `backend/src/lib/aegis/tools/intelligence.ts:165` ("DO NOT ADD - flagged as malicious").
- Notifications: `backend/src/lib/notification-dispatcher.ts:498` exposes `malicious_indicator` to user trigger code.
- Frontend badge: `frontend/src/components/PackageOverview.tsx:413` renders when `analysis?.is_malicious === true`.

**What's planned but NOT built:**
The reachability plan (`reachability-analysis.plan.md`, line 451 onward) sketches a Phase 9 with GuardDog + a global `package_security_cache(dep, version, scanner, findings JSONB, risk_level, scanned_at)` and a per-project `project_malicious_findings` table, plus a frontend tab. **None of this exists in `backend/database/`.** No GuardDog. No OSV malicious feed. No install-script scanning. No typosquat detection. No findings table. No frontend tab. The whole detection layer is a single boolean fed by GHSA.

Deptex is therefore at "behind table-stakes" on this axis — confirmed-malware-only flagging, sourced from one feed, with no per-finding context, severity, evidence, or remediation flow.

---

## Competitive Landscape

### Socket.dev
- **What they call it:** Supply Chain Risk (one of 5 alert categories alongside Quality / Maintenance / Vulnerability / License).
- **What it does:** 70+ signals across static analysis, package metadata, and maintainer behavior. Specific calls: install scripts, network requests, env var access, telemetry, obfuscated code, suspicious strings, native binaries, capability detection ("this package spawns processes / reads env / makes network calls").
- **AI layer:** "AI-detected potential malware" — when static heuristics raise suspicion, an LLM runs an in-depth evaluation; flagged samples go through human review before confirmed. Real-time monitoring of dependency changes.
- **Dynamic analysis:** Static today, dynamic "soon" per their own marketing.
- **Novel vs table-stakes:** Capability detection + AI-augmented review is frontier; the rest of the signal list is table-stakes for serious vendors.
- **Sources:** [socket.dev/features](https://socket.dev/features), [docs.socket.dev/docs/issues](https://docs.socket.dev/docs/issues), [almtoolbox.com — How Socket Helps Prevent Supply Chain Attacks](https://www.almtoolbox.com/blog/how-socket-prevents-supply-chain-attacks-malwares/), [socket.dev/alerts/gptMalware](https://socket.dev/alerts/gptMalware).

### Endor Labs
- **What they call it:** Malware Detection (part of their AI-Native AppSec Platform).
- **What it does:** 150+ signals. Cross-references OSV + proprietary malware feed. ML models trained on legitimate-package datasets to flag anomalies. **Sandboxed dynamic analysis** ("isolated execution environments to observe complete package behavior"). Cryptographic signature/reproducible-build checks. Specific signals listed in 2026 update: banned authors, compromised domains, pre/post-install scripts running `curl/wget` to suspicious URLs, phone-home, DNS-info grabs, stealthy minimal file trees, HTTPS exfiltration.
- **Differentiator claim:** Reachability filtering — "deterministically verifies whether potential threats are reachable in your specific application," claims 95% scanner-noise reduction.
- **Surface:** Finding/Action/Exception policies, `QueryMalware` API, integrates into PR/CI gates.
- **Sources:** [endorlabs.com/learn/malicious-package-detection](https://www.endorlabs.com/learn/malicious-package-detection), [docs.endorlabs.com/scan/malware](https://docs.endorlabs.com/scan/malware/), [csoonline.com — PhantomRaven returns to npm](https://www.csoonline.com/article/4144231/phantomraven-returns-to-npm-with-88-bad-packages.html).

### Phylum (now Veracode)
- **Status:** Acquired by Veracode January 6, 2025. Phylum's malicious-package database + package-management firewall are being folded into Veracode SCA through 2025.
- **Headline claim:** "Detects 60% more malicious packages than any other vendor" (Veracode/Phylum's own number).
- **Public surface today:** Phylum's standalone product is wound down; their detection runs inside Veracode SCA. Phylum was historically a major contributor to OSSF malicious-packages.
- **Sources:** [veracode.com — Innovating to Secure Software Supply Chains](https://www.veracode.com/blog/innovating-secure-software-supply-chains-veracode-acquires-phylum/), [securityweek.com — Veracode Targets Malicious Code Threats](https://www.securityweek.com/veracode-targets-malicious-code-threats-with-phylum-acquisition/).

### Aikido
- **What they call it:** Malware Detection in Open-Source Dependencies (Pro-tier feature) + **Aikido Intel** (free, AGPL threat feed) + **Aikido Safe Chain** (free OSS install-time blocker).
- **What it does:** Up to ~200 detections/day across npm/PyPI. Signals: obfuscated code, exfiltration to unknown servers, install-time command execution, crypto miners.
- **Aikido Intel:** AGPL-licensed live malicious-package + vulnerability feed. Anyone can ingest it. **The most aggressive open posture in the space.**
- **Aikido Safe Chain (OSS, github.com/AikidoSec/safe-chain):** Lightweight proxy that intercepts npm / yarn / pnpm / npx / pnpx / pip / uv / poetry installs, verifies in real time against Aikido Intel, blocks before code hits disk. No tokens required.
- **Sources:** [aikido.dev/code/malware-detection-in-dependencies](https://www.aikido.dev/code/malware-detection-in-dependencies), [intel.aikido.dev/malware](https://intel.aikido.dev/malware), [github.com/AikidoSec/safe-chain](https://github.com/AikidoSec/safe-chain).

### Snyk
- **What they call it:** Snyk Advisor (package scoring) + malicious-package detection inside Snyk Open Source SCA (paid).
- **Less differentiated on this axis** than Socket / Endor / Aikido — Snyk leans on advisory ingestion (their own + GHSA) rather than novel detection. Advisor's signals are popularity / maintenance / security / community.
- **Sources:** [security.snyk.io](https://security.snyk.io/) (Advisor moved here), [snyk.io](https://snyk.io/).

### Sonatype Repository Firewall
- **What it does:** Sits in front of Nexus / Artifactory and quarantines suspicious / malicious open-source components before they enter your private repo. Proprietary "AI" + research team. Runs at registry-proxy layer, not project-scan layer.
- **Distinction vs JFrog Xray:** Sonatype is proactive (block before download); JFrog Xray + Curation is reactive (alert after download). Both are paid + closed.
- **Sources:** [sonatype.com/products/sonatype-repository-firewall](https://www.sonatype.com/products/sonatype-repository-firewall), [help.sonatype.com — repository-firewall](https://help.sonatype.com/en/repository-firewall.html), [jfrog.com — block malicious or vulnerable packages](https://jfrog.com/help/r/jfrog-security-user-guide/products/curation/how-tos/how-to-block-malicious-or-vulnerable-packages-from-entering-the-repository).

### GuardDog (DataDog, OSS)
- **License:** Apache-2.0. v2.9.0 released Feb 6, 2026. Active. 1.1k stars.
- **Ecosystems:** PyPI, npm, Go, RubyGems, GitHub Actions, VSCode extensions.
- **Approach:** Source-code heuristics via **Semgrep + YARA rules** + per-ecosystem metadata heuristics.
- **Rule counts (representative):** PyPI ~16 source + 7 metadata, npm ~10 source + 8 metadata, smaller sets for Go/Ruby/Actions/VSCode.
- **Specific patterns covered:** base64 execution, clipboard access, DLL hijacking, obfuscation, env serialization, pre/post-install scripts, steganography, direct URL deps, bundled binaries, typosquatting, compromised emails, single-file packages.
- **Invocation:** CLI (`guarddog pypi scan requests`), Docker, JSON / SARIF output. Custom rules accepted as `.yml` (Semgrep) or `.yar` (YARA).
- **Sources:** [github.com/DataDog/guarddog](https://github.com/DataDog/guarddog).

### OSSF malicious-packages (OSV-format)
- **What it is:** Cross-ecosystem malicious-package reports in OSV JSON format. Ingests from GitHub Advisory Database (npm), Datadog dataset (PyPI), academic research, bulk imports.
- **Volume:** ~10,785 commits, daily-stats dashboard. Consumable via OSV ecosystem (osv.dev API, osv-scanner).
- **Sources:** [github.com/ossf/malicious-packages](https://github.com/ossf/malicious-packages), [openssf.org/blog — Introducing OpenSSF's Malicious Packages Repository](https://openssf.org/blog/2023/10/12/introducing-openssfs-malicious-packages-repository/).

### Datadog malicious-software-packages-dataset
- **What it is:** 26,123 confirmed malicious packages (npm, PyPI, IDE extensions, AI Skills) — most identified via GuardDog + human triage. Encrypted ZIP samples.
- **Honest caveat (theirs):** "Selection bias, as it was mostly identified by a single ruleset" — i.e. GuardDog-shaped detections.
- **Sources:** [github.com/DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset), [safedep.io — Analysis of 5000+ Malicious Open Source Packages](https://safedep.io/malysis-evaluation-using-datadog-malicious-packages-dataset/).

### Datadog supply-chain-firewall (scfw)
- **What it is:** OSS CLI wrapper. `scfw run npm install …` intercepts the install, looks up packages against Datadog dataset + OSV.dev + registry metadata + custom blocklists. Apache-2.0, Linux/macOS only.
- **Sources:** [github.com/DataDog/supply-chain-firewall](https://github.com/DataDog/supply-chain-firewall).

---

## Landscape Synthesis

### Table-stakes (every serious competitor has it)
- Lookup against ≥ 1 known-malicious feed (OSV / GHSA / vendor proprietary)
- Install-script behavior detection (pre/post-install, `curl|sh` style exfil)
- Typosquat / namesquat detection
- Network exfiltration / phone-home detection
- Obfuscated-code detection
- Per-finding severity, reason text, and remediation pointer
- Per-project findings list with ignore / accept / suppress
- GitHub Actions / CI gate so a PR introducing flagged deps fails

### Frontier (2-3 vendors do it, emerging)
- **AI/LLM-augmented detection** of novel/obfuscated samples (Socket "AI-detected potential malware", Endor ML models, Sonatype proprietary AI)
- **Real-time install-time blocking** via proxy/firewall (Aikido Safe Chain, Datadog scfw, Sonatype Repository Firewall)
- **Sandboxed dynamic analysis** of suspicious packages (Endor confirmed, Socket "soon")
- **Reachability-filtered malicious findings** ("is the malicious code path actually called from your app?") — Endor-only headline claim
- **Capability detection / behavior catalog** ("this package can: spawn processes, read env, make network") — Socket signature feature
- **Account-takeover signals** (maintainer changed, email changed, signing setup changed) — Endor explicit, Socket implicit
- **Threat-actor / campaign clustering** across packages (Socket has this in their threat-report blog, Aikido Intel cross-references campaigns)

### Whitespace (no one does well)
- **Open-core, BYOK, self-hostable malicious detection.** Every paid vendor is closed SaaS. Aikido is the closest with Intel+SafeChain, but their core platform is still SaaS + Pro-tier gated.
- **Aegis-style autonomous response.** Nobody has "agent receives malicious finding → opens PR removing it → suggests safer alternative → re-runs scan on the alternative." Closest is Sonatype quarantining, which is reactive blocking, not active remediation.
- **AI-explained findings tied to specific lines.** Socket's AI says "looks malicious"; nobody walks the user through *why* in plain English with annotated evidence.
- **Cross-engine reachability of the malicious behavior itself** — same Phase 5/6 reachability we're building for CVEs, applied to "is the postinstall script triggered? is the obfuscated function called?" Endor claims this but it's locked behind their enterprise tier.
- **Policy-engine integration of malicious detection** — "block any new dep that is < 30 days old AND has a postinstall script AND was published by an author with no other packages." Nobody offers code-defined policies that compose malicious signals.
- **Pre-merge gate via PR-check engine** with full signal context (most do IDE / CI block; few wire it into a richer PR check that links back to project policies, asset tier, owner, SLA).

### Deptex position today
- **Behind table-stakes:** only one feed (GHSA MALWARE), no install-script analysis, no obfuscation/typosquat/exfil heuristics, no per-finding evidence, no findings table, no frontend tab.
- **At parity:** nothing yet.
- **Ahead — once wired in:** open-core posture (vs all-paid-SaaS), Aegis (autonomous remediation), reachability engine (Phase 5/6 in flight), policy engine + flow builder, BYOK AI. None of these competitors have all five together.

---

## Shortlist (Recommended)

### 1. GuardDog Pipeline + Malicious Findings Surface — 5/5 value, 5/5 leverage
- **One-liner:** Run GuardDog on every dependency in extraction, persist per-finding evidence into a real findings table, expose a "Malicious" tab in the security page.
- **Target user:** developer + security engineer.
- **Problem:** Today Deptex shows a binary `is_malicious` flag from GHSA only. Real attackers ship novel malicious packages that never get a GHSA entry; GuardDog's source heuristics catch the install-script / obfuscation / exfil patterns that GHSA misses entirely.
- **Competitive positioning:** Matches Socket's "supply chain risk" alert breadth and Aikido's pro-tier malware detection on day one — same underlying signal categories — but powered by Apache-licensed GuardDog instead of a vendor's closed engine ([github.com/DataDog/guarddog](https://github.com/DataDog/guarddog)). Catches up to table-stakes in one feature.
- **Deptex fit:** This is the planned reachability-plan Phase 9, and the schema (`package_security_cache` + `project_malicious_findings`) is already specced. Slots into the existing extraction pipeline as step 7d, mirrors the Semgrep/TruffleHog finding patterns we already render. Global cache means once anyone scans `lodash@4.17.20`, every other org reuses the result.
- **Size:** M (2-3 weeks).
- **Bucket:** table-stakes.
- **Why shortlisted:** Without this, every other concept on the list is built on sand. Highest combined value × leverage in the brainstorm.

### 2. Multi-Feed Lookup Layer — 4/5 value, 5/5 leverage
- **One-liner:** Daily ingest of OSSF malicious-packages (OSV) + Datadog dataset + Aikido Intel into a global `known_malicious_packages` table; lookup at extraction time before scanning.
- **Target user:** developer + org admin.
- **Problem:** GuardDog catches *novel* patterns; aggregator feeds catch *already-confirmed* malicious packages with near-zero false positives. The two layers are complementary, not redundant. Endor's 2026 differentiator was literally "we flag faster than OSV ingests."
- **Competitive positioning:** Matches Endor's "OSV + proprietary feed" stack, except our "proprietary feed" is the union of three open feeds — so we get most of the coverage without a dedicated threat-intel team. ([github.com/ossf/malicious-packages](https://github.com/ossf/malicious-packages), [intel.aikido.dev/malware](https://intel.aikido.dev/malware), [github.com/DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset))
- **Deptex fit:** A nightly QStash cron + new global table. Lookup is O(1) per dep at scan time. License-clean: OSSF is OSV (CC-BY-4.0 metadata), Datadog is Apache-2.0, Aikido Intel is AGPL — note the AGPL footprint may need to be a separate process if we want to keep MIT for the rest of the worker.
- **Size:** S (1 week, minus any AGPL-isolation work).
- **Bucket:** table-stakes.
- **Why shortlisted:** Lowest-effort coverage win available; pairs trivially with #1 to make findings additive.

### 3. Aegis Quarantine Agent — 5/5 value, 5/5 leverage
- **One-liner:** When a malicious package lands, Aegis autonomously opens a PR that removes the package, suggests an alternative (with reputation justification), and runs reachability across the project to enumerate the actual impact sites.
- **Target user:** developer (auto-fix), security engineer (audit trail).
- **Problem:** Sonatype Repository Firewall *blocks* malicious packages at install. Endor *flags* them with reachability. Nobody *removes* them with a coherent suggestion. That's an Aegis-shaped gap.
- **Competitive positioning:** No competitor has this. Sonatype quarantines passively at repo layer ([sonatype.com — Repository Firewall](https://www.sonatype.com/products/sonatype-repository-firewall)); Endor stops at "here's the finding, here's reachability" ([docs.endorlabs.com/scan/malware](https://docs.endorlabs.com/scan/malware/)). Active remediation is whitespace.
- **Deptex fit:** Reuses the entire Aegis Fix Agent stack that just shipped 2026-04-29. Reachability comes from Phase 5/6 work. Alternative-suggestion uses existing reputation score + OpenSSF criteria. Permission model already exists (`trigger_fix`).
- **Size:** L (3-4 weeks). Depends on #1 to have findings to act on.
- **Bucket:** differentiator (Aegis leverage).
- **Why shortlisted:** This is *the* thing competitors can't easily clone — they don't have an autonomous agent already wired into PR creation, fix planning, and reachability data. Highest strategic-fit score in the brainstorm.

### 4. Malicious Reachability — 4/5 value, 5/5 leverage
- **One-liner:** When GuardDog flags `postinstall: curl … | sh` or "function `evil()` defined in package", run the same Phase 5/6 reachability engine to determine if the project actually triggers it.
- **Target user:** developer (de-noise), security engineer (prioritize).
- **Problem:** Endor's headline claim is "95% scanner-noise reduction via reachability." For malicious packages, "is the malicious code path actually executed in this project?" is genuinely actionable: a transitive dep with a malicious postinstall is high-priority; a malicious function in a code path you never call is informational.
- **Competitive positioning:** Endor charges enterprise-tier prices for this ([endorlabs.com/learn/malicious-package-detection](https://www.endorlabs.com/learn/malicious-package-detection)). Nobody else does it. Our Phase 5/6 reachability engine is the same machinery — re-pointing it at malicious sinks instead of CVE sinks is a marginal, not foundational, lift.
- **Deptex fit:** Direct reuse of Phase 5 (Semgrep rule generation) and Phase 6 (cross-file taint stitching). Reachability levels (`module` / `function` / `data_flow` / `confirmed`) become the same vocabulary applied to malicious-finding sinks.
- **Size:** M (2-3 weeks). Hard-blocked by Phase 5/6 settling, soft-blocked by #1.
- **Bucket:** differentiator.
- **Why shortlisted:** Maximum leverage on in-flight reachability work; the only feature on the list that gets *cheaper* the more Phase 5/6 ship.

### 5. AI-Explained Malicious Findings — 4/5 value, 5/5 leverage
- **One-liner:** Aegis tool that takes a flagged package + the offending source/metadata snippets, returns a plain-English narrative of *why* the package is malicious, with per-line annotations.
- **Target user:** developer (understand), reviewer (audit).
- **Problem:** Socket's AI alert says "this looks malicious." Endor's alert says "rule X matched." Neither walks a developer through the actual code in human language tied to specific lines. The audit trail for "I ignored this finding" is weak across all competitors.
- **Competitive positioning:** Socket has the LLM tier ([socket.dev/alerts/gptMalware](https://socket.dev/alerts/gptMalware)) but treats it as another opaque label, not a narrative. This is the explainability gap.
- **Deptex fit:** Reuses BYOK provider abstraction + AI usage logging that's already shipped. Reuses Aegis's snippet-extraction infra. Caches per (package, version) so cost amortizes globally.
- **Size:** S-M (1-2 weeks).
- **Bucket:** parity-plus / differentiator (UX + audit trail).
- **Why shortlisted:** Cheap, high-perceived-quality, leans hard into BYOK AI, and is the kind of polish that makes screenshots look noticeably better than competitors.

---

## Moonshots to Consider

### Self-hosted Safe Chain CLI (`deptex install`)
- Wrap Datadog scfw or Aikido Safe Chain into the open-core CLI: `deptex install` proxies npm/pip/etc. and blocks before disk-write, using our aggregated feed (#2). Pairs with the open-source story; gives self-hosters install-time protection that Sonatype charges for. Distribution wedge: every developer who runs it sees the Deptex brand at every install.
- **Why moonshot, not shortlist:** Cross-platform install-proxy work is a meaningful lift (Windows support is missing in Datadog scfw). Also: distribution and onboarding are the hard part, not the engineering.
- **Sources:** [github.com/AikidoSec/safe-chain](https://github.com/AikidoSec/safe-chain), [github.com/DataDog/supply-chain-firewall](https://github.com/DataDog/supply-chain-firewall).

### Cross-org Reputation Wisdom (opt-in)
- Every paid org's "we accepted / we quarantined this package" decisions feed an aggregate, anonymized reputation signal — a Snyk-Advisor-style score built from real org behavior, not just registry stats. Self-host orgs default-out; cloud orgs default-in with strong opt-out. Becomes a network-effect moat that's impossible to replicate without users.
- **Why moonshot:** Real value only emerges past 1k orgs, and the privacy story is easy to get wrong.

---

## Full Brainstorm (Appendix)

### 6. Pre-merge Malicious Gate
- **One-liner:** Existing PR-check engine learns to block PRs introducing packages flagged by #1 or #2.
- **Bucket:** parity-plus. **Size:** S. **V/L:** 4/4.
- **Notes:** Leans on flow-builder + PR-check infra that's nearly done. Configurable per asset tier ("block on critical for prod tier, warn for dev tier"). Direct counterpart to Sonatype Repository Firewall but at PR layer, which is where developers actually live.

### 7. AI Novel-Malware Detector
- **One-liner:** BYOK LLM reads `package.json` + top files + install scripts of any *new + rare + postinstall-having* package, scores 0-100. Cached in `package_security_cache`.
- **Bucket:** parity-plus. **Size:** M. **V/L:** 4/4.
- **Notes:** Mirrors Socket's "AI-detected potential malware" tier ([socket.dev/alerts/gptMalware](https://socket.dev/alerts/gptMalware)) but BYOK, so cost falls on the org. Triggered conservatively to keep token spend low. Pairs with #5.

### 8. Capability Catalog per Package
- **One-liner:** Static tree-sitter pass over each dep produces a capability tag set: `spawns_processes`, `reads_env`, `network_io`, `filesystem_write`, `eval_dynamic`. Doesn't itself flag malice; lets policies say "block any new dep with `network_io` AND `eval_dynamic`."
- **Bucket:** differentiator. **Size:** M. **V/L:** 3/4.
- **Notes:** Direct Socket parity, with bonus that our policy engine can consume the tags. Reuses tree-sitter infra from Phase 2.

### 9. Threat-Actor Campaign Tracking
- **One-liner:** Cluster malicious findings into named campaigns by IOC overlap (HTTPS endpoints, package-name patterns, common author email domains, common exfil targets).
- **Bucket:** differentiator. **Size:** M-L. **V/L:** 3/2.
- **Notes:** Great in marketing ("we caught the *npm-stealer-2026-Q2* campaign of 88 packages"). Real engineering lift in clustering + naming, and most of the value is captured by simply linking findings via shared IOCs without naming campaigns.

### 10. Maintainer Reputation Signals
- **One-liner:** Track per-package: maintainer changed in last 30d, maintainer email changed, brand-new account, signing setup changed. Account-takeover early-warning system.
- **Bucket:** parity-plus. **Size:** M. **V/L:** 3/3.
- **Notes:** Endor publishes "banned authors / compromised domains" as one of their headline 2026 signals. Doable from registry metadata alone; no dynamic analysis needed.

### 11. Community Rules Marketplace (moonshot)
- **One-liner:** Community-uploaded GuardDog Semgrep/YARA rules, validated and shipped. Like the Semgrep rule registry, but for malicious-package patterns.
- **Bucket:** moonshot. **Size:** XL. **V/L:** 3/3.
- **Notes:** Pairs naturally with the Phase 5 reachability rule registry. Real value only after a critical mass of rule contributors.

---

## Recommended Next Step

Run `/interview` on **#1 ("GuardDog Pipeline + Malicious Findings Surface")** to refine scope before planning. It's the foundation everything else stacks on, and once it's specced, #2/#5 are 1-2 week add-ons in the same plan and #3/#4 become natural follow-on phases that reuse already-built primitives.

If you want a single bigger swing instead, fork **#1 + #3 ("Aegis Quarantine Agent")** as a combined "Malicious Detection + Autonomous Remediation" plan — the differentiator story is much stronger when the agent is part of the pitch from day one.
