# Reachability Analysis — Full Implementation Plan

## Overview

Build world-class reachability analysis competitive with Endor Labs, Semgrep Supply Chain, and Snyk. Three pillars:

1. **Semgrep reachability rules** — per-CVE rules that detect vulnerable usage patterns
2. **Tree-sitter universal usage extraction** — function-level analysis for ALL languages in one tool
3. **AI-augmented analysis** — cross-file taint stitching, AI rule generation, contextual scoring

All tools are free/open-source. ~6 month plan to full competitive parity.

---

## How Vulnerability Scanning Works (Context)

dep-scan checks dependency versions against public vulnerability databases (OSV/NVD/GHSA). These databases track every known CVE — e.g., "lodash < 4.17.21 has CVE-2021-23337." dep-scan finds ALL known vulnerabilities automatically.

But finding a vulnerability doesn't tell you if it MATTERS. CVE-2021-23337 is in `lodash.template()`, but if you only use `lodash.merge()`, you're not affected. Reachability analysis answers: "does your code actually use the vulnerable part?"

**dep-scan** = "Which packages have known bugs?" (detection)
**Reachability** = "Does your code call the buggy function?" (prioritization)

The CVE advisory + fix commit publicly document which function is vulnerable. Our Semgrep rules encode that information as machine-readable code patterns.

---

## Reachability Maturity Levels

| Level | What It Answers | How We Achieve It |
|-------|----------------|-------------------|
| **1 — Dependency Detection** | "Package X has a known CVE" | dep-scan (automatic, all CVEs) |
| **2 — Import/Module** | "You import the vulnerable package" | Tree-sitter import extraction |
| **3 — Function-Level** | "You call the specific vulnerable function" | Tree-sitter usage slices + fuzzy matching, OR Semgrep function rules |
| **4 — Data-Flow/Taint** | "Attacker input reaches the vulnerable function" | Semgrep taint rules (single-file) + AI cross-file stitching |
| **5 — Exploitability** | "Called in the exploitable way, from an exposed endpoint, unsanitized" | Semgrep `pattern-not` for safe patterns + EPD contextual scoring |

**Expected coverage after plan:**
- Level 5 for CVEs with Semgrep rules (fast, deterministic — top 100-200 CVEs)
- Level 5 for most CVEs WITHOUT rules via AI exploitability assessment (slower, ~$0.001-0.01/assessment, works for any CVE with advisory + code context)
- Level 3 for CVEs where AI assessment is skipped to save cost (low-severity long tail)
- Level 2 only for ambiguous cases where function name matching fails
- Explicit "unreachable" for transitive deps never imported

**Rules vs AI — the tradeoff:**

| | Hand-written Semgrep Rule | AI Assessment |
|---|---------------------------|---------------|
| Speed | Fast (~100ms) | Slow (~1-3s) |
| Cost | Free per scan | ~$0.001-0.01 per call |
| Determinism | Always same answer | Can vary |
| Coverage | Only written CVEs | Any CVE with advisory + code |

Hand-write rules for: top 50 most common CVEs, all CISA KEV entries, repeatedly-triggered CVEs. Use AI as fallback for everything else. This covers virtually all real-world CVEs at Level 5.

---

## Competitive Positioning

| Capability | Endor Labs | Semgrep SC | Snyk | **Deptex (target)** |
|-----------|------------|------------|------|---------------------|
| Vulnerability detection | All | All | All | All (dep-scan) |
| Function-level reachability | 7-8 ecosystems | 12 langs, direct only | 3-4 langs | All (tree-sitter + Semgrep) |
| Data-flow taint | Partial (Java best) | Per-CVE, single-file | DeepCode AI | Per-CVE + AI cross-file |
| Exploitability patterns | No | Yes | No | Yes (Semgrep + EPD) |
| Transitive deps | Yes | **No** | Yes | Yes |
| Unreachable classification | Implicit | No | No | **Explicit** |
| Contextual scoring | No | No | Opaque risk score | **Transparent EPD** |
| AI cross-file analysis | No | No | Proprietary DeepCode | **LLM stitching** |
| Custom rules | No | Limited | No | **Full Semgrep YAML** |
| Cost | ~$50-100/dev/mo | ~$40-110/dev/mo | ~$50-100/dev/mo | **Free (open source)** |

---

## The Complete Extraction Pipeline

### Step 1: Clone
Clone repo via GitHub/GitLab/Bitbucket App installation token.

### Step 2: Resolve Dependencies
`npm install` / `mvn dependency:resolve` / `go mod download` / `pip install` / `cargo fetch` / `bundle install` / `composer install`. Required for accurate SBOM.

### Step 3: Generate SBOM
`cdxgen --profile research --deep` → CycloneDX SBOM (all deps, versions, PURLs, licenses, dependency graph).

### Step 4: Parse SBOM → Local State
- Parse components → local arrays with pre-generated UUIDs (via `crypto.randomUUID()`)
- Resolve dependency graph (direct vs transitive), detect dev dependencies
- Write to GLOBAL tables only (`dependencies`, `dependency_versions`, `dependency_version_edges`) — shared, additive, safe
- Build local maps: depName → dependencyId, depName → projectDependencyId
- **No project-specific DB writes** — all project data stays in memory until commit phase

### Step 5: *(Moved to Step 14 — populate runs after commit)*

### Step 6: Tree-Sitter Universal Usage Extractor
Single TypeScript program using tree-sitter with per-language queries. For every source file:
- Extract all import/require/use statements → which packages are imported
- Extract all function/method calls on imported symbols → which library functions are called, where
- Output in atom usage-slice JSON format
- Covers: JS/TS, Python, Go, Rust, C#, Ruby, PHP, Java (extensible via query strings)

**Output (local):** Usage slices — package name, function called, file path, line number. Computes `files_importing_count` per dependency.

**Time:** Seconds (tree-sitter is extremely fast — used by GitHub for code search).

### Step 7: Vulnerability Scan (dep-scan + atom)

**7a — dep-scan:** Checks all dependency versions against VDB (OSV/NVD). Detects ALL known CVEs.

**Output:** Vulnerability records — CVE ID, severity, CVSS, EPSS, CISA KEV, affected/fixed versions. Stored locally.

**7b — atom** (via dep-scan or standalone): Supplementary analysis for supported languages.
- Java: usage slices + reachable flow traces (Level 3-4 bonus)
- Python: usage slices + some reachable flows (Django/Flask)
- Ruby/PHP: usage slices + framework-specific flows
- JS/TS/Go/Rust/C#: likely empty (tree-sitter + Semgrep handle these)

Atom is bonus data — pipeline works without it. If atom produces data, it supplements tree-sitter. If not, no impact.

**7c — Joern** (Phase 8, month 5): Expands Level 4 data-flow analysis to more languages. Joern is the upstream project atom forked from, has working frontends for Go, Kotlin, Swift, mature JS/TS, etc. Apache 2.0 licensed. Similar memory requirements to atom (16-64GB).
- Go → gosrc2cpg
- Kotlin → kotlin2cpg (Android market)
- Swift → swiftsrc2cpg (iOS market)
- JavaScript/TypeScript → jssrc2cpg (better than atom's JS)

Integration: install Joern CLI, invoke similar to atom, parse CPG output into usage-slice format. Cached per-package to avoid re-analysis.

**7d — Malicious Package Scan** (new pipeline step): Different from vulnerability scanning — detects INTENTIONALLY malicious packages (typosquatting, obfuscated install scripts, data exfiltration, crypto miners, hidden functionality).

Primary tool: **GuardDog** (DataDog, Apache 2.0) — https://github.com/DataDog/guarddog
- YARA-based rule detection for npm, PyPI, Go
- Patterns: typosquatting, install script malice, obfuscated code, exfiltration, crypto miners, env theft
- CLI: `guarddog <ecosystem> scan <package>`

Also consider: OSV-Scalibr (Google), Packj, dep-scan's built-in detection.

**Caching is critical** — scan results cached globally per package version. Once anyone's Deptex instance scans lodash 4.17.20, results are reused for every subsequent scan. First-time scans are slow, subsequent are instant.

New global table: `package_security_cache(dependency_id, version, scanner, findings JSONB, risk_level, scanned_at)` — UNIQUE on (dependency_id, version, scanner).

Findings stored in new `project_malicious_findings` table.

### Step 7e: IaC + Container Scanning (Phase 10, month 6)

Detects misconfigurations in infrastructure-as-code files and vulnerable OS packages in container base images. Different domain from app-dependency SCA — this covers deployment posture.

**Project-type detection** (runs after clone, before scanner routing):
```ts
const infraTypes: string[] = [];
if (await fileExists('Dockerfile') || await globFind('**/Dockerfile')) infraTypes.push('dockerfile');
if ((await globFind('**/*.tf')).length > 0)                           infraTypes.push('terraform');
if (await globFind('**/k8s/**/*.y?(a)ml', '**/charts/**'))            infraTypes.push('kubernetes');
if (await globFind('**/cloudformation/**/*.y?(a)ml'))                 infraTypes.push('cloudformation');
if (await globFind('**/.github/workflows/*.y?(a)ml'))                 infraTypes.push('github-actions');
```
Persisted to new `projects.infra_types TEXT[]` column so frontend can render infra badges on the project card (Node.js + Docker + Terraform, etc.).

**Scanner routing:**
| Detected | Scanner | Findings |
|---|---|---|
| `dockerfile` | Trivy (`trivy config` + `trivy image`) | Dockerfile misconfigs, vulnerable base-image OS packages |
| `terraform` | Checkov (`--framework terraform`) | S3 public access, IAM overly permissive, unencrypted RDS, etc. |
| `kubernetes` | Checkov (`--framework kubernetes`) + optional Kubescape | Root containers, missing resource limits, hostNetwork, etc. |
| `cloudformation` | Checkov (`--framework cloudformation`) | CFN-equivalent rules |
| `github-actions` | Checkov (`--framework github_actions`) | Unsafe workflow permissions, unpinned actions |

**Tools (all free, Apache 2.0 / MIT):**
- **Checkov** (Prisma/Palo Alto, Apache 2.0) — ~1000 policies across TF/K8s/Helm/ARM/CFN/Dockerfile/Actions. Python. De-facto default.
- **Trivy** (Aqua, Apache 2.0) — IaC + container image scanning + SBOM + secrets. Go, fast.
- **Kubescape** (optional, Apache 2.0) — K8s-specific, NSA/CISA + MITRE ATT&CK framework mapping.

Both emit JSON with `{rule_id, file_path, line, severity, message, remediation}` — same shape as Semgrep findings, so they slot into the existing security tab pattern with a `source` badge (IaC / Container).

**New tables:**
- `project_iac_findings(project_id, framework, rule_id, file_path, line, severity, message, remediation)`
- `project_container_findings(project_id, image, package, cve_id, severity, fixed_version, layer)`

Findings are commit-phase data (written atomically in Step 13 alongside everything else).

**Wiring into existing pipeline:**
- Extraction worker: add Checkov + Trivy to Dockerfile, ~1 week total implementation
- Frontend: add Docker/Terraform/K8s/CFN icons to `FrameworkIcon`, render infra badges in project card + `CreateProjectSidebar`, add IaC/Container tabs to security page (~1.5 days)
- Repo-scan endpoint: return `infra_types` alongside ecosystem/framework so the sidebar can preview what will be scanned

### Step 8: Semgrep Scan (SAST + Reachability — single pass)
```
semgrep scan --config auto --config reachability-rules/ --json
```

**SAST findings** (`--config auto`): General code quality/security issues.

**Reachability findings** (`--config reachability-rules/`): Per-CVE rules loaded ONLY for CVEs detected in Step 7. Each rule encodes the vulnerable function + dangerous usage pattern from the CVE advisory/fix commit.

Two tiers per CVE:
- **Taint rule** (`mode: taint`): traces user input → vulnerable function → `confirmed`
- **Function call rule** (pattern match): detects vulnerable function called in dangerous way → `function`

Example (CVE-2020-14343 — PyYAML):
```yaml
rules:
  - id: deptex-reach-CVE-2020-14343-taint
    mode: taint
    languages: [python]
    metadata: { osv_id: CVE-2020-14343, reachability_level: confirmed }
    pattern-sources:
      - pattern: flask.request.data
    pattern-sinks:
      - pattern: yaml.load($SINK)
      - pattern-not: yaml.load($SINK, Loader=...)

  - id: deptex-reach-CVE-2020-14343-call
    languages: [python]
    metadata: { osv_id: CVE-2020-14343, reachability_level: function }
    patterns:
      - pattern: yaml.load(...)
      - pattern-not: yaml.load(..., Loader=...)
```

### Step 9: AI Cross-File Taint Stitching
For `function` level findings from Step 8 (call detected, can't confirm taint across files):

**Stage 1 — Mechanical:** Use tree-sitter usage slices to trace import chains. File A imports function from file B → trace the argument passing.

**Stage 2 — AI:** For ambiguous multi-hop cases, send source + sink + intermediate code to LLM. "Does user input reach the vulnerable function?" Confidence threshold >0.8 to upgrade. Budget capped (~$1/extraction via Tier 1 Gemini Flash).

Each step degrades gracefully — if AI stitching fails, finding stays at `function` level.

### Step 10: Compute Reachability Levels
Combine ALL signals into one level per vulnerability:

| Priority | Source | Level |
|----------|--------|-------|
| 1 | Semgrep taint match | `confirmed` |
| 2 | AI cross-file confirmed (>0.8) | `confirmed` |
| 3 | Atom reachable flows | `data_flow` |
| 4 | Semgrep function call match | `function` |
| 5 | Tree-sitter usage slices match vulnerable function | `function` |
| 6 | Atom usage slices match | `function` |
| 7 | Import found, no function match | `module` |
| 8 | Transitive dep, zero imports | `unreachable` |

Each vuln gets highest matching level. Direct deps never marked unreachable.

### Step 11: Depscore + EPD
**Depscore** (all vulns):
```
depscore = CVSS × 10 × threat(EPSS, KEV) × tier(asset_tier) 
         × reachability(level) × context(direct/dev/malicious)
```
Weights: confirmed=1.0, data_flow=0.9, function=0.7, module=0.5, unreachable=0.2

**EPD Contextual Scoring** (confirmed/data_flow only):
- Classify entry point from Semgrep taint sources + tree-sitter data
  - HTTP route handler, no auth → `PUBLIC_UNAUTH` (weight 1.0)
  - Authenticated endpoint → `AUTH_INTERNAL` (weight 0.5)
  - Background job/cron → `OFFLINE_WORKER` (weight 0.1)
- Path depth from taint trace
- Sanitization check (Semgrep `pattern-not` + AI assessment)
- `contextual_depscore = base_depscore × epd_factor`

### Step 12: TruffleHog Secret Scan
`trufflehog filesystem --json` → detect exposed secrets. Already working.

### Step 13: Commit Phase (Soft-Switch Pattern)

Zero-downtime pointer-flip commit — old rows stay visible until new generation is fully written. Replaces delete-then-insert.

**Schema additions:**
- Every project-scoped table gets `extraction_id UUID NOT NULL` column, indexed on `(project_id, extraction_id)`
- `projects` gets `active_extraction_id UUID` pointing at the visible generation
- Read queries filter by `WHERE extraction_id = projects.active_extraction_id`

**Commit sequence:**
1. Read existing user decisions (ignored/risk-accepted/notes) keyed by stable identifiers: `osv_id + dep_name` for vulns, `rule_id + file_path` for Semgrep/IaC, `detector_type + file_path` for secrets.
2. Insert all new data under a fresh `extraction_id`. FK order enforced in insert function: deps → vulns → flows → usage slices → Semgrep → secrets → IaC → container → malicious.
3. Apply user decisions to new rows by matching stable identifiers.
4. **Flip pointer** — single atomic `UPDATE projects SET active_extraction_id = $new`. Frontend switches over instantly.
5. Async reaper (scheduled cron) deletes generations older than the two most recent (`active` + one prior for rollback).

**Benefits vs delete-then-insert:**
- No empty-state window during commit — frontend never sees partial data
- FK violations caught before pointer flip — only flips on a fully-consistent generation
- Instant rollback by flipping back to prior generation (via admin UI)
- No DELETE CASCADE lock contention on large projects

### Step 14: Populate Enrichment + Finalize
- Queue populate: registry metadata, OpenSSF scorecard, license, policy evaluation, health score (**no vulnerability fetching** — dep-scan handles that)
- Mark extraction job completed
- Machine exits → Fly.io stops it (scale-to-zero)

---

## Data Flow Diagram

```
Tree-sitter (Step 6) ──→ Usage slices for ALL languages, ALL deps
                    ├──→ Step 9: AI stitching uses call chain data
                    ├──→ Step 10: function-level for CVEs without Semgrep rules
                    ├──→ Step 10: unreachable classification  
                    └──→ Step 11: EPD entry point mapping

dep-scan (Step 7a) ───→ Vulnerability records (ALL CVEs)
                    └──→ Step 8: determines which Semgrep rules to load

atom (Step 7b) ────────→ Reachable flows (Java Level 4 bonus)
                    └──→ Usage slices (Java/Python supplement)

Semgrep rules (Step 8) ─→ Per-CVE reachability (confirmed/function)
                    ├──→ Step 9: function findings → AI upgrade candidates
                    └──→ Step 11: taint sources → EPD entry points

AI stitching (Step 9) ──→ Cross-file confirmed reachability
```

---

## Semgrep Rule Library

### Where Vulnerable Function Info Comes From
- **CVE advisory description** — usually names the vulnerable function
- **Fix commit on GitHub** — diff shows exactly what was patched
- **Semgrep community registry** — ~2,800+ free SAST rules, many match vulnerability patterns
- **AI rule generation** — LLM reads CVE description + patch diff, drafts rule

### Rule Structure
```
backend/extraction-worker/reachability-rules/
  ├── javascript/
  │   ├── lodash.yaml        # CVE-2021-23337
  │   ├── minimist.yaml      # CVE-2021-44906
  │   └── ...
  ├── python/
  │   ├── pyyaml.yaml        # CVE-2020-14343
  │   └── ...
  ├── java/
  │   ├── log4j.yaml         # CVE-2021-44228
  │   └── ...
  └── go/
      └── ...
```

### Priority CVEs (Initial 20)

| CVE | Package | Ecosystem | Vulnerable Pattern |
|-----|---------|-----------|-------------------|
| CVE-2021-44228 | log4j-core | Java | `logger.info(userInput)` — Log4Shell |
| CVE-2021-23337 | lodash | npm | `_.template(userInput)` — injection |
| CVE-2020-14343 | pyyaml | pypi | `yaml.load()` without SafeLoader |
| CVE-2022-42889 | commons-text | Java | `StringSubstitutor.createInterpolator()` |
| CVE-2021-44906 | minimist | npm | `minimist(argv)` — prototype pollution |
| CVE-2022-23529 | jsonwebtoken | npm | `jwt.verify/sign` — insecure key |
| CVE-2021-3749 | axios | npm | `axios.get(userUrl)` — ReDoS |
| CVE-2022-0235 | node-fetch | npm | `fetch(url, {headers})` — header leak |
| CVE-2022-32149 | golang.org/x/text | Go | `language.Parse(input)` |
| CVE-2023-3978 | golang.org/x/net | Go | `html.Parse(input)` |
| CVE-2024-21538 | cross-spawn | npm | `spawn(userCmd)` |
| CVE-2021-32804 | tar | npm | `tar.extract({file: userPath})` |
| CVE-2022-37601 | loader-utils | npm | `getHashDigest(input)` |
| CVE-2021-3807 | ansi-regex | npm | `ansiRegex.test(input)` |
| CVE-2024-4068 | braces | npm | `braces.expand(input)` |
| CVE-2023-26136 | tough-cookie | npm | `Cookie.parse(input)` |
| CVE-2022-25883 | semver | npm | `semver.parse(input)` |
| CVE-2021-23343 | path-parse | npm | `pathParse(input)` |
| CVE-2021-43138 | async | npm | `async.mapValues(input)` |
| CVE-2023-44270 | postcss | npm | `postcss.parse(input)` |

---

## Implementation Timeline

### Month 1: Foundation (Phases 1-3)

**Phase 1: Atomic Pipeline Refactor — Soft-Switch (~1-2 weeks)**
- Schema migration: add `extraction_id` to project-scoped tables, `active_extraction_id` to `projects`
- Migrate all read queries to filter by `active_extraction_id`
- Refactor pipeline.ts: accumulate all data in local PipelineState object with pre-generated UUIDs
- Commit phase: insert under fresh `extraction_id` → apply user decisions → flip pointer → async reap
- Preserve user decisions (ignored, risk accepted, notes) by matching stable identifiers to new rows
- Add `extraction_step_errors` table + structured per-step failure logging
- Audit existing timeout behavior; add per-step budgets where missing
- Add admin page at `/admin/extraction-failures` for Henry to find silent failures
- Remove GHSA vuln fetching from populate step

Files: `pipeline.ts`, new migration files, backend routes that read project-scoped data, new admin route + page

**Phase 2: Tree-Sitter Universal Usage Extractor (~1-2 weeks)**
- Build single TypeScript program using tree-sitter
- Per-language query definitions for imports + function calls
- Output atom-compatible usage-slice JSON format
- Support: JS/TS, Python, Go, Java, Rust, C#, Ruby, PHP
- Wire into pipeline Step 6

Files: new `backend/extraction-worker/src/tree-sitter-extractor.ts`

**Phase 3: Semgrep Reachability Rules Engine + First 20 Rules (~2-3 weeks)**
- Create `reachability-rules/` directory with YAML rules for top 20 CVEs
- Create `reachability-rules.ts`: loads rules matched to detected CVEs, invokes Semgrep, parses output
- Integrate into pipeline as combined SAST + reachability single Semgrep pass
- Integrate findings into `updateReachabilityLevels()` as highest-priority signal
- Add unreachable classification for transitive deps with zero imports

Files: new `reachability-rules/`, new `reachability-rules.ts`, modified `pipeline.ts`, `reachability.ts`

### Month 2: Contextual Scoring (Phases 4-5)

**Phase 4: Re-enable EPD (~2 weeks)**
- Wire Semgrep taint sources into EPD entry point classification
- Use tree-sitter data for entry point mapping
- Calculate real path depth from taint traces
- Re-enable EPD in pipeline for confirmed/data_flow vulns only

Files: `epd.ts`, `pipeline.ts`

**Phase 5: Scale Rules to 50+ (~2 weeks)**
- Write rules for all CISA KEV dependency CVEs
- Write rules for top EPSS CVEs per ecosystem
- Adapt existing Semgrep community patterns where available
- Add rule coverage metric to extraction logs

### Month 3: AI Rule Generation (Phase 6)

**Phase 6: AI Rule Drafting Pipeline (~3 weeks)**
- `tools/generate-rule.ts`: takes CVE ID → fetches advisory + patch diff → calls LLM → outputs draft YAML
- `tools/test-rule.ts`: validates rules against known-vulnerable test code
- Use Tier 1 Gemini Flash (free for us) for generation
- Generate + review rules to reach 100+ total
- Track `ai_generated: true` metadata on rules

### Month 4: AI Cross-File Analysis (Phase 7)

**Phase 7: AI-Stitched Cross-File Taint Tracking (~4-6 weeks)**
- `cross-file-resolver.ts`: mechanical import chain tracer using tree-sitter data
- `ai-taint-stitcher.ts`: LLM assessment of cross-file data flow
- Confidence scoring + budget caps (reuse EPD's budget system)
- Wire into pipeline after single-file Semgrep analysis
- Update CodeImpactView frontend to show cross-file flow visualization

### Month 5: Joern Integration + Malicious Package Detection (Phases 8-9)

**Phase 8: Joern Multi-Language Integration (~3-4 weeks)**
- Install Joern CLI in extraction worker Dockerfile
- Add Joern invocation for languages where atom is weak/empty:
  - Go (gosrc2cpg)
  - Kotlin (kotlin2cpg) — mobile/Android
  - Swift (swiftsrc2cpg) — iOS
  - JavaScript/TypeScript (jssrc2cpg) — better than atom
- Parse Joern CPG output → usage slices format
- Cache per package version to avoid repeated analysis
- Gives Level 4 data-flow for languages atom doesn't handle

**Phase 9: Malicious Package Detection (~3-4 weeks)**
- Install GuardDog (DataDog, Apache 2.0) in extraction worker
- New pipeline step 7d: scan each dependency for malicious patterns
- Global cache table `package_security_cache` keyed on (dep, version, scanner)
- New findings table `project_malicious_findings`
- New frontend section for "Malicious Packages" in security tab
- Block project status on critical malicious findings

**Phase 9b: Rule Library at 100+ (ongoing)**
- AI-generate rules to hit 100+
- Add coverage metric in UI: "X% of CVEs have reachability rules"

### Month 6: IaC + Container Scanning (Phase 10)

**Phase 10: IaC + Container Scanning (~1-1.5 weeks)**
- Install Checkov + Trivy in extraction worker Dockerfile
- Project-type detection (Dockerfile / *.tf / k8s YAML / CFN / Actions) — filesystem checks after clone
- New `projects.infra_types TEXT[]` column
- Scanner routing: Checkov for Terraform/K8s/CFN/Actions, Trivy for Dockerfile + base-image CVEs
- New tables: `project_iac_findings`, `project_container_findings`
- Frontend:
  - Extend `FrameworkIcon` with docker/terraform/kubernetes/cloudformation/helm icons
  - Stacked infra badges on project cards (Node.js + Docker + Terraform)
  - New IaC + Container tabs in unified security page (reuses existing finding-card pattern)
  - `CreateProjectSidebar` shows detected infra types in scan preview
- Repo-scan endpoint: return `infra_types` alongside ecosystem/framework
- Aegis tie-in: IaC findings become auto-fix candidates (Aider/Aegis generates Terraform PRs to encrypt S3, restrict security groups, etc.) — matches Snyk IaC's top paid feature

### Month 7+: Advanced (Phases 11-14)

**Phase 11: CodeQL Integration (~3-4 weeks)**
- Write CodeQL queries for top 10 critical CVEs
- Run selectively on critical findings where maximum confidence matters
- Parse CodeQL results into reachability levels

**Phase 12: Pre-Computed Package Reachability Cache (~4-6 weeks)**
- Background job analyzes top packages per ecosystem
- Cache: exported functions, CVE-to-function mapping per package version
- At scan time: skip library analysis for cached packages
- Seed with top 500 npm + 200 PyPI + 200 Maven

**Phase 13: Community/Custom Rules (~2-3 weeks)**
- Rule upload UI in Organization Settings
- Validation + sandbox testing
- Community contribution pipeline (PR review + merge)

**Phase 14: Hardening + Test Suite (~2-3 weeks)**

Final pass after all features ship. Lock in behavior against future regressions + validate edge cases the per-phase tests didn't cover.

Automated tests for critical paths (the stuff that's expensive to re-verify manually):
- Soft-switch commit: happy path, mid-commit failure, pointer-flip atomicity, rollback to prior generation, concurrent extractions of same project
- Reachability level computation: each of the 5 levels, priority ordering across signals, explicit `unreachable` classification for transitive deps
- User decision preservation across re-extractions, matched by stable identifiers (`osv_id + dep_name`, `rule_id + file_path`, etc.)
- Error logging: non-fatal `warn` vs fatal `error`, each step emits correctly, pipeline continues on `warn`
- Per-step timeout enforcement: step cancels cleanly, logs, pipeline proceeds to next step
- EPD factor correctness for each entry-point class

Edge-case fixture repos (beyond `deptex-test-{npm,python,java,go}`):
- Monorepo (multi-manifest) — graceful "scan root only" warning when secondary manifests found
- Project without lockfile — trust stated versions, flag uncertainty in UI
- Malformed SBOM — pipeline handles and logs, doesn't crash
- Zero-deps project — pipeline completes, no false errors
- Very large project (1000+ deps) — memory ceiling respected, timing within per-step budgets

Manual rigorous E2E walkthrough:
- Every tab of every security page (vulns, secrets, Semgrep, IaC, container, malicious)
- Policy blocking across every supported license pattern
- AI toggle on/off — verify graceful degradation, rule-only mode still produces usable findings
- Admin pages (extraction failures, rollback)
- Re-extraction flow — confirm user decisions stick, confirm soft-switch pointer flip looks instant

Performance pass:
- Review `extraction_step_errors` telemetry — any step regularly hitting timeout? Tune budgets
- Review AI cost telemetry — Phase 7 cross-file stitching within budget per-extraction?
- Memory profiling on largest real-world project

Documentation:
- User-facing docs: reachability levels explained, AI toggle, admin page usage, new finding types (IaC / container / malicious)
- Internal runbook: how to debug a stuck extraction, how to rollback a bad generation

Files: new `__tests__/` fixtures for pipeline modules, new edge-case test repos under `henryru/`, new docs pages.

---

## Cross-Cutting Concerns

### Error Logging + Admin Surface

Every pipeline step emits structured failure records to a new table:

```sql
CREATE TABLE extraction_step_errors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  extraction_job_id UUID NOT NULL REFERENCES extraction_jobs(id),
  step TEXT NOT NULL,        -- 'clone' | 'sbom' | 'tree_sitter' | 'dep_scan' | 'semgrep' | ...
  code TEXT NOT NULL,        -- structured code, e.g. 'timeout', 'oom', 'rule_parse_error'
  message TEXT NOT NULL,
  stack TEXT,
  machine_id TEXT,
  duration_ms INT,
  severity TEXT DEFAULT 'error',  -- 'warn' (non-fatal, pipeline continued) | 'error' (fatal)
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX ON extraction_step_errors(created_at DESC);
CREATE INDEX ON extraction_step_errors(step, code);
```

Non-fatal errors (atom OOM, Semgrep single-rule crash, GuardDog timeout on one package) log at `warn` severity — pipeline continues with graceful degradation. Fatal errors log at `error` and halt.

**Admin surface:** new page at `/admin/extraction-failures` showing recent errors grouped by step/code, filterable by org/project, with stack traces. Henry-only access via platform admin role.

### Per-Step Timeouts

Each pipeline step has a max duration. If exceeded: step marked `timeout`, error logged at `warn`, pipeline continues. Phase 1 includes an audit of current timeout behavior — some may already exist at the Fly machine level.

Draft budgets (tune via telemetry once running):

| Step | Budget |
|------|--------|
| Clone | 2 min |
| Dep resolution (npm/mvn/pip) | 10 min |
| SBOM (cdxgen) | 5 min |
| Tree-sitter extraction | 2 min |
| dep-scan | 10 min |
| atom | 15 min |
| Joern (per language) | 20 min |
| Semgrep (SAST + reachability) | 15 min |
| AI cross-file stitching | 5 min (budget-capped) |
| TruffleHog | 5 min |
| IaC + Container scan | 10 min |
| Commit | 2 min |

Total pipeline cap: ~90 min, matches the Fly machine hard kill.

### AI Augmentation Setting

New org setting: `use_ai_augmentation BOOLEAN DEFAULT TRUE` (configured in Organization Settings → AI).

When `FALSE`:
- Phase 4 EPD entry-point classification: skipped → heuristic fallback
- Phase 7 AI cross-file taint stitching: skipped → findings stay at `function` level, never upgraded to `confirmed` via AI
- Future AI exploitability assessment: skipped
- Phase 6 offline rule generation unaffected (runs on Henry's machines, not per-extraction)

Rule-only mode remains fully functional — just less precise on cross-file cases and entry-point scoring.

**UI disclosure** in Org Settings AI page:
> AI augmentation sends source code snippets to Google Gemini Flash during extraction for cross-file taint analysis and entry-point classification. Disable to scan with deterministic rules only, or configure BYOK to route AI calls through your own provider keys.

Future rework of AI pricing, multi-provider, local-LLM BYOK, and self-host options lives in a separate plan (see memory: `ai_architecture_future.md`). Not a blocker for the reachability plan.

### Schema Migration Strategy

All migrations follow this pattern to avoid downtime:
1. **Additive migration** — add column/table with NULL or empty default
2. **Deploy backend** — reads both old and new schema (null-safe fallback)
3. **Backfill** — populate new field for existing rows via batch script
4. **Deploy frontend** — assumes new field present
5. **Cleanup** — remove fallback branches in backend once backfill is 100%

Schema changes introduced by this plan, in order:

| Migration | Phase | Adds |
|-----------|-------|------|
| `phase19_atomic_commit.sql` | 1 | `extraction_id` columns on project-scoped tables, `projects.active_extraction_id`, `extraction_step_errors` table |
| `phase20_reachability_rules.sql` | 3 | Rule metadata tables, `deptex_rules_version` tracking |
| `phase21_epd_enabled.sql` | 4 | Re-enable EPD columns, `organizations.use_ai_augmentation` flag |
| `phase22_joern_cache.sql` | 8 | Per-package Joern analysis cache |
| `phase23_malicious_pkg.sql` | 9 | `package_security_cache` (with `scanner_rules_version`), `project_malicious_findings` |
| `phase24_iac_container.sql` | 10 | `projects.infra_types`, `project_iac_findings`, `project_container_findings` |

---

## Testing & Validation

Manual verification after **each phase**, not just at the end. Catches regressions while they're cheap to fix. Run the full pipeline against all 4 test repos (`deptex-test-npm`, `deptex-test-python`, `deptex-test-java`, `deptex-test-go`) + SQL queries + browser walkthrough of affected UI before starting the next phase.

### Per-Phase Verification

**Phase 1 (Atomic pipeline):**
- Start extraction, kill worker mid-pipeline → old data still intact
- Re-extract project → ignored vulns stay ignored
- Frontend shows consistent data throughout extraction

**Phase 2 (Tree-sitter):**
- Extract deptex-test-npm → usage slices populated for JS/TS (currently empty)
- `lodash.template`, `minimist()`, `jwt.sign` appear in slices
- Runs in <10 seconds for medium projects

**Phase 3 (Semgrep rules):**
- deptex-test-npm: lodash template CVE → `confirmed` (taint)
- deptex-test-java: Log4Shell → `confirmed` (taint)
- deptex-test-python: PyYAML → `confirmed` (yaml.load without SafeLoader)
- Transitive deps with no imports → `unreachable`

**Phase 4 (EPD):**
- `contextual_depscore` < `depscore` for internal/background entry points
- Entry point classification matches actual code

### SQL Verification
```sql
-- Reachability distribution
SELECT reachability_level, COUNT(*), ROUND(AVG(depscore), 1) as avg_depscore
FROM project_dependency_vulnerabilities WHERE project_id = '<ID>'
GROUP BY reachability_level;

-- Semgrep reachability findings
SELECT rule_id, file_path, severity
FROM project_semgrep_findings
WHERE project_id = '<ID>' AND rule_id LIKE 'deptex-reach-%';

-- EPD contextual scoring
SELECT osv_id, depscore, contextual_depscore, entry_point_classification, epd_factor
FROM project_dependency_vulnerabilities
WHERE project_id = '<ID>' AND contextual_depscore IS NOT NULL;
```

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Pipeline complexity (6 reachability sources) | Each step independent + graceful degradation. If any step fails, others still work. |
| Semgrep rule maintenance | AI rule generation (Phase 6) accelerates 5-10x. Community rules exist for many patterns. |
| AI hallucination in cross-file | Confidence threshold >0.8. Only upgrades (never downgrades). Reasoning logged for review. |
| Tree-sitter query accuracy per language | Fuzzy matching acceptable for Level 3. Semgrep handles precision for specific CVEs. |
| atom memory usage (64GB machine) | atom is supplementary — if it fails/OOMs, pipeline continues without it. |
| New CVEs without rules | Tree-sitter + fuzzy matching gives basic Level 3. Rule gap closes as library grows. |

---

## Success Criteria

| Metric | Today | Month 1 | Month 3 | Month 6 |
|--------|-------|---------|---------|---------|
| Pipeline atomicity | Broken (mid-pipeline writes) | Atomic commit | Atomic | Atomic |
| Function-level (all ecosystems) | Broken (JS/Go empty) | Tree-sitter (all langs) | All | All |
| CVEs with Semgrep rules | 0 | 20 | 100+ | 200+ |
| "Confirmed" findings | Never assigned | Top 20 CVEs | Top 100 CVEs | Most CVEs + cross-file |
| "Unreachable" classification | Never assigned | Working | Working | Working |
| Cross-file taint | None | None | None | AI-stitched |
| Contextual scoring (EPD) | Disabled | Disabled | Working | Working + AI |
| Noise reduction | 0% | ~60-70% | ~80% | ~90% |
| Competitive level | Below all | On par basic | Competitive | Strong open-source leader |

---

## Key Files

| File | Role |
|------|------|
| `backend/extraction-worker/src/pipeline.ts` | Main pipeline orchestration |
| `backend/extraction-worker/src/tree-sitter-extractor.ts` | Universal usage extraction (NEW) |
| `backend/extraction-worker/src/reachability-rules.ts` | Semgrep rule engine (NEW) |
| `backend/extraction-worker/src/reachability.ts` | Reachability level computation |
| `backend/extraction-worker/src/depscore.ts` | Depscore calculation |
| `backend/extraction-worker/src/epd.ts` | EPD contextual scoring |
| `backend/extraction-worker/src/cross-file-resolver.ts` | Import chain tracing (NEW, Phase 7) |
| `backend/extraction-worker/src/ai-taint-stitcher.ts` | AI cross-file assessment (NEW, Phase 7) |
| `backend/extraction-worker/reachability-rules/` | Per-CVE Semgrep rules (NEW) |
| `tools/generate-rule.ts` | AI rule drafting CLI (NEW, Phase 6) |

## Dependencies (All Free)

- Semgrep OSS (MIT) — already installed
- tree-sitter (MIT) — npm package, fast universal parser
- atom (MIT) — already installed, supplementary
- dep-scan (MIT) — already installed
- Go callgraph tools (BSD) — Phase 8
- CodeQL CLI (free for OSS) — Phase 10
