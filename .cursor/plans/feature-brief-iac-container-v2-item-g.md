# IaC + Container v2 — Item G: Composed IaC↔Code Reachability — Feature Brief

**Slug:** `iac-container-v2-item-g`
**Captured:** 2026-05-21
**Status:** Brainstorm complete, ready for `/plan-feature`

## Problem Statement

Deptex currently runs two independent reachability layers — Phase 2 classifies container OS-package CVEs as reachable/unreachable based on what the image entrypoint loads (`depscanner/src/scanners/container-reachability.ts`), and Phase 6 classifies code-dependency CVEs as reachable/unreachable based on cross-file taint analysis in application code (`depscanner/src/taint-engine/`). The two layers don't talk to each other. When a single underlying vulnerability surfaces in both (e.g. an OpenSSL CVE shows up as a finding on `libssl.so.3` AND on the Python `cryptography` package that wraps it), users see two separate rows in the Security tab, scored independently, and have no way to know they're the same bug. Item G composes the two layers into a single signal per CVE so users get one finding with one honest score, and noise-reduction stacks — a CVE is only fully reachable when both layers say so.

## Current State in Deptex

**Phase 2 — Container reachability (shipped, on main `8f2ccda`):**
- `depscanner/src/scanners/container-reachability.ts` classifies findings on `project_container_findings` rows by `reachability_level` (reachable / unreachable)
- `storage.ts:31` defines `CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER = 0.4`
- `storage.ts:107` `containerDepscore(f)` applies the multiplier when `reachability_level === 'unreachable'`
- Static analysis using `readelf -d` over the extracted container filesystem; DT_NEEDED walk + dlopen detection

**Phase 6 — Code reachability (shipped, PR #30 merged 2026-04-30):**
- `depscanner/src/taint-engine/` runs cross-file taint per-CVE via FrameworkSpecs in `framework-models/`
- Output: `Flow[]` persisted to `project_reachable_flows`; level rolled up to `project_dependency_vulnerabilities.reachability_level` via `updateReachabilityLevels` RPC
- Depscore weights in `depscore.ts:35-59`: unreachable=0.0, module=0.5, function=0.7, data_flow=0.9, confirmed=1.0
- Per-ecosystem recall as of active sprint: npm 86%, python ~62%, maven 10%, cargo 67%, gem/golang ~0%

**The gap:**
- `project_container_findings` and `project_dependency_vulnerabilities` are separate tables with no cross-reference
- A CVE appearing in both is two rows, scored independently
- There's no language-package → OS-shared-library binding lookup anywhere in the codebase (one minimal `psycopg2-binary → psycopg2` alias in `reachability.ts`, nothing about OS libs)
- Endor markets exactly this composition as of 2026-02-11 — pitch is real and customers will start asking

## Competitive Landscape

### Endor Labs
- **What:** "Full-stack reachability from code to container." Acquired Autonomous Plane (DockerSlim founder) 2026-02-11 to ship this. Listed as the 5th of their "5 reachability types" — "Package Used in Image."
- **How:** Two reachability outputs (function-level SCA + ptrace-based container OS-package reachability) shown side-by-side. Container side requires a **privileged ptrace sensor running inside the image** — runtime DX wart.
- **Sources:** [PR](https://www.prnewswire.com/news-releases/endor-labs-acquires-autonomous-plane-expanding-ai-native-application-security-with-full-stack-reachability-from-code-to-container-302684888.html), [Missing Layer blog](https://www.endorlabs.com/learn/the-missing-layer-why-container-os-libraries-need-reachability-analysis), [instrumented reachability docs](https://docs.endorlabs.com/scan/containers/instrumented-reachability/), [5 types blog](https://www.endorlabs.com/learn/5-types-of-reachability-analysis-and-which-is-right-for-you), [container use case](https://www.endorlabs.com/use-cases/container-scanning)
- **Honest read on the pitch:** Marketing reads "code AND container" but technically it's two side-by-side reachability scores, not an AND-composed single signal. Numbers cited (~9.5% reachable / ~90% noise reduction) are on the SCA side alone, not on the composition.

### Snyk
- **What:** Snyk Open Source has "Reachable Vulnerabilities" (Java, JS/TS, Python, C# EA). Snyk Container exists separately.
- **Composition:** None. Two products, two outputs, no cross-reference. Container is presence-based.
- **Sources:** [Reachability docs](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/reachability-analysis), [Reachable Vulns blog](https://snyk.io/blog/reachable-vulnerabilities/), [Container](https://docs.snyk.io/scan-with-snyk/snyk-container/how-snyk-container-works)

### Socket
- **What:** Three-tier reachability (Dependency / Precomputed / Full Application) for JS/TS/Python/Go/Java/Scala/Kotlin/Ruby + .NET/Rust at lower tiers.
- **Composition:** None. Reachability docs don't mention containers.
- **Source:** [Reachability](https://docs.socket.dev/docs/reachability-analysis)

### Aikido, Wiz, Chainguard, Trivy/Grype/Anchore
- **Aikido:** Code reachability + container scanning, but framed as separate visualizations across surfaces, not composed
- **Wiz:** No native code-level reachability — integrates *with Endor* for that side
- **Chainguard:** Opposite philosophy — minimize base images so OS-package CVE count is near-zero by construction. Relevant alternative for buyers; if a customer adopts Chainguard, Item G's container half collapses to "near-empty"
- **Trivy/Grype/Anchore:** Presence-based; no reachability layer. Confirms no OSS does this today

### Academic / research frontier
- IRIS (Cornell, ICLR 2025) is Java-only LLM-assisted whole-repo static analysis — code-only, not container-aware
- No published paper found in 2022-2026 window formally composing call-graph reachability with linker/OS-package reachability. Soft confirmation the composition is undertheorized in the literature

### OS-pkg ↔ language-pkg mapping prior art
- No public curated dataset (PURL → SONAME)
- Debian's `dpkg-shlibdeps` solves the reverse direction at OS-package build time, not bottom-up from language packages
- cdxgen and Syft emit per-binary SBOM rows but don't connect them upward to the language package
- Building this is genuinely greenfield

## Landscape Synthesis

- **Table-stakes:** Single-axis reachability (code OR container) — everyone serious has at least one side
- **Frontier (Feb 2026):** Composing code + container reachability — Endor is the only vendor explicitly marketing this. Their technical surface is weaker than the marketing implies (side-by-side, not AND-composed; privileged ptrace required)
- **Whitespace:** True AND-composed semantics with multiplicative scoring; no-ptrace static approach; the PURL→SONAME binding dataset as a first-class persisted artifact
- **Deptex position:** Behind on the marketing claim ("first to combine" is gone post-2026-02-11), at parity on the eventual product, ahead on the DX (no privileged ptrace)
- **Feasibility verdict:** Known-tractable, mostly. The bridge mechanism (in-scan readelf on native binding files) reuses Phase 2 machinery; the composition logic is a small multiplier-folding change; the biggest engineering chunk is the UI unification on the Security tab
- **Top risks:**
  1. Phase 6 recall outside JS/Python is too low for the composition to be meaningful in Java/Go/Ruby/Rust (mitigated: v1 restricts to JS+Python)
  2. ctypes/dlopen-via-string-args misses without source-grep fallback (mitigated: v1 ships source-grep)
  3. The UI unification chunk being larger than estimated (mitigated: scoped explicitly as the biggest single chunk in scope planning)

## User Stories

- As a **security engineer** triaging a Deptex Security tab, I want to see one row per CVE — not two — with an honest composed score, so I'm not double-counting the OpenSSL/zlib/curl-class bugs that surface in both layers.
- As an **org admin** looking at the dashboard, I want my "actionable findings" count to drop by ~40-60% after Item G ships, so the team can actually triage what's left.
- As a **developer** clicking into a single composed finding, I want a 2-line breakdown showing "container says X, code says Y," so I understand why this row is scored the way it is and what I'd have to fix.

## Locked Scope Decisions

1. **Strategic positioning: fast-follower parity with Endor, with a sharper technical wedge.**
   *Why:* Endor took the "first to combine" headline 2026-02-11; trying to beat their marketing is a losing game. But their technical surface (privileged ptrace + side-by-side outputs) has real wedges Deptex can punch through: no-ptrace static-only path, true AND-composed (multiplicative) semantics, and the PURL→SONAME binding dataset as a first-class artifact.

2. **v1 language scope: JS/TS + Python only.**
   *Why:* Phase 6 recall is strongest here (npm 86%, python ~62%). Including Java (10% maven recall) or Go/Ruby/Rust (~0% recall) would ship Item G with the code-side half of the AND-gate collapsing to noise, giving customers misleading "unreachable" classifications. Wait for v3 recall lifts in flight (per `reachability_noise_reduction_v3_state`) before expanding.

3. **Bridge mechanism: in-scan `readelf -d` over native binding files inside the extracted image filesystem.**
   *Why:* No curated PURL→SONAME table to maintain. Version-exact and image-exact (every scan derives its own ground-truth bridge). Reuses Phase 2's existing `readelf` machinery in `container-reachability.ts` — incremental code, not a new tool. Static-only, unlike Endor's ptrace — no privileged container required, no app-must-start-cleanly requirement.

4. **ctypes/CDLL fallback covered in v1 via source-grep.**
   *Why:* `readelf -d` misses Python packages that dynamically load shared libs at runtime via `ctypes.CDLL('libfoo.so')`. `cryptography` does this in some versions. ~70 lines to grep .py files in each native-binding package for `ctypes.CDLL(...)` / `ctypes.cdll.LoadLibrary(...)` and capture string args. Adds maybe 1-2 days to v1 scope but closes a real coverage gap.

5. **UI: one unified row per (CVE, language-pkg) pair with a 2-line layer breakdown.**
   *Why:* Two-rows-per-CVE is the experience Item G exists to fix. Unified rows with the per-layer breakdown ("⚛ libssl.so.3 reachable / ✕ code unreachable") preserve auditability while collapsing the noise. Disclosure expands to show original Phase 2 + Phase 6 evidence.

6. **Scoring: multiplicative composition.**
   *Why:* `composed_depscore = base × container_mult × code_mult`. Both unreachable → 0 (full suppress). Container unreachable + code data_flow → `base × 0.4 × 0.9 = 0.36×`. Container reachable + code unreachable → `base × 1.0 × 0.0 = 0` (also full suppress). Either layer can suppress alone. Most aggressive noise-reduction; defensible because we have ground-truth bindings from `readelf`, not heuristic guesses.

7. **Fallback when composition can't fire: fall back to Phase 6 alone.**
   *Why:* When the project has no Dockerfile, when the package is pure-Python/pure-JS with no `.so` files, or when `readelf` finds no NEEDED entries — composition simply doesn't fire and the finding is scored by Phase 6's existing logic. Correct because: pure packages have no OS-side exposure to compose with; no-Dockerfile projects have no container-side findings; readelf-misses-everything is rare and equivalent to "no binding."

8. **Rollout: just ship.**
   *Why:* Solo-user-prelaunch per `feedback_solo_user_prelaunch` — direct rewrites are fine, no backwards-compat shims, no feature flag debt. One-shot backfill migration (similar shape to phase29) re-computes existing `project_container_findings.depscore` with the composed multipliers at ship.

9. **Success metric: noise-reduction % on a benchmark corpus extending the existing 49-CVE / 4-repo setup with Docker images.**
   *Why:* Falsifiable, defensible to design partners. Target: 40-60% reduction in HIGH/CRITICAL findings count vs pre-composition baseline on the same repos+images. Honest — not Endor's marketing 90% — but real and reproducible. The 4-repo corpus already has the code-side baseline at 79.6%; adding representative images per repo gives the composed measurement.

10. **PURL→SONAME bindings persisted to a new `project_native_bindings` table.**
    *Why:* Debug + tooltip surface — when a user asks "why is this composed this way?" we can answer "we found this .so at `/usr/local/lib/python3.11/site-packages/cryptography/.../<file>.so` linking `libssl.so.3`." Also enables auditing when scoring looks wrong. ~50 rows per scan, low storage cost.

## Data Model (sketch — /plan-feature locks specifics)

**New table: `project_native_bindings`**
- Keyed on `(extraction_run_id, package_purl, soname)`
- Columns: install_path, link_method (`elf_needed` | `ctypes_grep`), discovered_at
- Used at composition time to bridge `project_container_findings.os_package_name` ↔ `project_dependency_vulnerabilities.package_purl`

**Composition surface — two reasonable options for /plan-feature to choose between:**
- (a) New `project_composed_findings` join table referencing both sides, with composed_depscore stored
- (b) Add `composition_partner_id` + `composed_depscore` columns to both existing findings tables

(b) is lower-migration-risk and preserves history; (a) is cleaner conceptually. Decision deferred to /plan-feature.

**Backfill migration:** one-shot recomputation of `project_container_findings.depscore` and `project_dependency_vulnerabilities.depscore` for rows where a composition partner exists, at the ship cutover.

## API Endpoints (sketch)

No new endpoints expected — composition is computed in the depscanner worker during the extraction run and persisted. The existing Security tab routes (`GET /api/orgs/:orgId/projects/:projectId/vulnerabilities` and `GET /api/orgs/:orgId/projects/:projectId/container-findings`) get updated response shapes to include:
- `composed_depscore` (the merged number)
- `composition_partner` (the linked finding's id, if any)
- `bindings` (the SONAME list that justifies the composition, for tooltip surface)

May want one new helper endpoint: `GET .../findings/:findingId/bindings` to lazy-load the binding evidence on tooltip expand. /plan-feature decides.

## Frontend Surface

**Primary surface: existing Security tab** (per `org_security_tab_state` — currently in-flight on `worktree-org-security-tab`). Item G integrates with that tab's unified findings table.

**Row shape:** one row per (CVE, language-pkg) pair. Container findings without a code-side partner remain as today. Code findings without a container-side partner remain as today. Composed rows show:
- CVE id + language-pkg name + linked OS library names (e.g. `libssl.so.3`)
- Composed depscore (the merged number)
- 2-line breakdown:
  - `⚛ libssl.so.3 reachable` / `⚛ libssl.so.3 unreachable`
  - `✓ cryptography reachable (data_flow)` / `✕ cryptography unreachable (no call into vuln function)`

**Disclosure on click:** expands to show original Phase 2 + Phase 6 evidence (sink/source flows, dlopen chain, install path of the binding file).

**Empty state:** unchanged — Security tab's existing empty state.

**Loading state:** unchanged — Security tab's existing loading skeleton. Bindings tooltip has its own small spinner if lazy-loaded.

**Error state:** if composition logic errors during a scan, the worker logs the error and finding falls back to Phase 6-only / Phase 2-only behavior (degraded, not failed). UI shows the un-composed row with a small "couldn't compose" badge.

## User Flows

**Happy path — composed finding (suppression case):**
1. User opens Security tab
2. CVE-2026-XYZ row shows composed depscore of 28 (was 70 in container, 63 in code today — separate rows)
3. User reads the 2-line breakdown: `⚛ libssl.so.3 reachable / ✕ cryptography unreachable`
4. User hovers depscore → tooltip: "Container layer says libssl is loaded by the runtime. Code layer says cryptography.encrypt is never called. Score = base 70 × 1.0 × 0.0 = 0."
5. User clicks row → side panel shows both original Phase 2 evidence (dlopen chain) and Phase 6 evidence (no taint flow reaches the vuln function)

**Happy path — composed finding (both reachable):**
1. CVE-2026-XYZ row shows composed depscore of 70 (full base, both reachable)
2. 2-line breakdown: `⚛ libssl.so.3 reachable / ✓ cryptography reachable (data_flow)`
3. User clicks row → side panel shows the actual taint flow from `req.body.password` → `cryptography.encrypt(...)` AND the libssl loading chain

**Edge path — package has no container partner:**
1. Finding is a pure-Python package (e.g. `requests`)
2. No native bindings → no composition fires
3. Row shows as today (Phase 6 alone) — no change to existing behavior, no "couldn't compose" badge

## Edge Cases & Failure-Mode Policy

- **No Dockerfile in project:** No Phase 2 findings, no composition fires, Phase 6 surfaces alone. *Soft-no-op.*
- **Multi-stage Dockerfile, package only in build stage:** No `.so` file in runtime image → no binding inferred → composition correctly skips this CVE. *Correct behavior.*
- **Multi-arch image (linux/amd64 + linux/arm64):** Scan one arch (existing Phase 2 behavior). *No change.*
- **Distroless / scratch images with no readelf inside:** We run `readelf` from depscanner against the extracted FS, not inside the image. Distroless is fine. Scratch images with statically-linked Go binaries: no language SBOM → no composition → Phase 2 alone. *Soft-no-op.*
- **Package with vendored statically-linked libs (e.g. some `cryptography` builds):** `readelf -d` won't show the vendored libssl as NEEDED → no binding for system libssl → composition correctly skips. *Correct behavior (the vendored copy isn't affected by the system libssl CVE).*
- **Package uses `ctypes.CDLL('libfoo.so')` at runtime:** Static `readelf` misses it. Source-grep fallback (v1) catches the string literal. *Mitigated.*
- **Package uses dynamically-constructed library names (`ctypes.CDLL(f'lib{x}.so')`):** Source-grep can't resolve. *Accepted gap, documented.*
- **Composition logic throws mid-scan:** Worker logs, falls back to un-composed scoring for that scan, finding still surfaces. *Soft-fail.*
- **Phase 6 hasn't classified a finding yet (taint engine still processing):** Composition waits for Phase 6 completion (it's per-scan synchronous today). No partial composed rows in the DB.
- **CVE on libssl with multiple Python packages binding to it (`cryptography`, `pyopenssl`, `paramiko`, `urllib3[secure]`):** One composed row per (CVE, language-pkg) pair — each gets its own row with its own code-reachability assessment, sharing the same container-side evidence. The 4 rows are not collapsed into one; they ARE different code-side situations. *Decision deferred to /plan-feature if UX wants further collapsing.*

## Non-Functional Requirements

- **Per-scan latency budget:** Composition + binding extraction adds at most 15 seconds to a typical Python-on-Docker scan. Walking native files inside the extracted FS is cheap compared to existing `crane export` + tree-sitter passes
- **Storage:** ~50 binding rows per scan on `project_native_bindings`. Negligible at expected scale
- **Composition correctness:** target 0 false-negatives on the benchmark corpus (we never miss a CVE that should have surfaced); false-positive suppression rate < 1%
- **No new AI calls:** Item G is pure static analysis, no Tier 1 or Tier 2 spend
- **No new external integrations**

## RBAC Requirements

**None new.** Item G is a scoring + display change. Existing `view_all_teams_and_projects` covers viewing composed findings; project-team membership covers access. No new permission strings, no new approval flows.

## Dependencies

- ✅ Phase 2 (container OS-pkg reachability) — shipped on main `8f2ccda`
- ✅ Phase 6 (cross-file taint engine) — shipped via PR #30
- ✅ Phase 6.5 (CVE-targeted FrameworkSpecs) — merged
- ⚠️ Phase 6 per-ecosystem recall lifts ([[reachability_noise_reduction_v3_state]]) — in flight on `worktree-reachability-noise-reduction-v3`. NOT a hard blocker for v1 (JS+Python recall is already adequate) but determines how meaningful the composition is in ecosystems Item G expands into post-v1
- ✅ Security tab refactor ([[org_security_tab_state]]) — in flight on `worktree-org-security-tab`. Item G's unified row shape lands inside whatever Security tab structure ships; ordering matters but they don't conflict

## Success Criteria

1. **Noise-reduction benchmark:** On a corpus of (existing 4 reachability repos) × (representative Docker images per repo), the count of HIGH+CRITICAL findings drops by 40-60% with composition enabled vs disabled. Measured via `npm run e2e:iac-code-composition` harness.
2. **Per-layer auditability:** Every composed finding has retrievable evidence for both layers (binding file + dlopen chain on container side; flow + sink on code side). Spot-check 20 random findings.
3. **No false-negatives:** No CVE that should be HIGH/CRITICAL is suppressed below `module` weighting due to composition. Verified against the 49-CVE corpus.
4. **One row per (CVE, language-pkg) on the Security tab.** Hand-verified UI against 5 representative real-world projects.
5. **Latency:** depscanner P50 scan time on a Python-on-Docker project increases by <15 seconds vs pre-composition.

## Open Questions

1. **(can defer to /implement)** Should the composition_partner relationship be a join table or columns on both findings tables? Both work; preference for whichever leaves migration cleanest given the 2-table starting shape.
2. **(can defer to /implement)** Should multi-package CVE rows (`cryptography`, `pyopenssl`, `paramiko` all bind to libssl) collapse further at the UI layer, or stay as one row per (CVE, language-pkg)? Brief locks "one row per pair" as the v1 default; v2 can collapse if UX feedback says it's noisy.
3. **(informational)** Corpus extension — which Docker images do we add to the existing 4-repo reachability corpus? Probably the repos' own Dockerfiles if they have one, plus a `python:3.11-slim` baseline. /plan-feature should pin specific image refs.
4. **(can defer to /implement)** Where does the bindings tooltip lazy-load from? An endpoint per finding, or are bindings included in the initial findings response payload? Probably the latter for ≤100 findings, the former above that — /plan-feature can decide.
5. **(informational)** Source-grep ctypes fallback: should we cap at top-N PyPI packages (resource-bound) or grep every Python package in the SBOM (thorough but slower)? Probably the latter — grep cost is trivial compared to scan time.

## Recommended Next Step

`/plan-feature` from this brief. All blocking decisions are locked; open questions are /plan-feature-or-later detail. Estimated scope: ~3 weeks from plan-lock to merge, broken roughly as:
- Binding extraction (in-scan readelf + ctypes source-grep): 3-5 days
- Composition logic + scoring + backfill migration: 2-3 days
- UI unification on Security tab (single largest chunk): 5-7 days
- Tests + corpus extension + e2e harness: 3-4 days
- Hardening pass + /criticalreview + fix patches: 2-3 days
