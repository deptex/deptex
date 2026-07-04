# Arc 2 — Dependency-Source Import Graphs (plan v2, 2026-07-03)

**Worktree:** `dep-import-graphs` (branch `worktree-dep-import-graphs`, base `origin/main` @ `288b9e64`).
**Process:** master-plan per-arc cycle — PLAN → adversarial REVIEW → FIX → IMPLEMENT → VALIDATE → RECORD.
**Status: v2 — all 6 review lenses (gate3-soundness, code-facts, scope-overfit, ops-perf, security, api-tests) returned REVISE on v1; every MUST-FIX is addressed below; the review log at the bottom records each finding and its disposition.**

## 1. Objective

Extend the reachability engine's submodule-absence demotion gates from **first-party-only** import proofs to **transitive** proofs. v2 scope, sharpened by review:

1. **Go — full transitive proofs** via the toolchain (`go list -deps`): restores the removed `x/net/idna` gate soundly (removed `9f1f0355`-era commit `9f1f0235`; in-code comment at `reachability-go-preconditions.ts:202-211` defers to this arc) and adds a `protojson` gate — the flagship two-directional corpus win (gitea CVE-2024-24786 labelled `unreachable`, currently shown `module`, demotes; caddy same-CVE refuses via the labelled cel-go → protojson transitive path). Existing Go gates gain a transitive **veto** (fixes the idna-class latent unsoundness with zero regression when the oracle is unavailable).
2. **pypi — VETO-ONLY in v1** (unanimous 4-lens review consensus on ask #2): per-dist wheel import extraction adds *refusals* to the submodule-load Django rows (owner-excluded); it never makes absence claims, never bypasses a hard list, and never demotes anything the current engine wouldn't. The absence/bypass direction is deferred to v2 of this arc behind the enumeration-trust requirements recorded in §8.
3. Hard lists stay. Consumer-semantics rows (sqlparse, brotli, h11) are **not** touched — their `hasAnyProdDep` encodes "an attacker-input-feeding consumer exists", not an import approximation (review caught that converting sqlparse would reverse paperless's two labelled `unreachable` wins: Django itself imports sqlparse for trusted sqlmigrate SQL).

Non-goals (v1): npm leg (no consuming model), gem/composer legs (no sources, no import signals in those models), cargo, any promotion change, any label change, any pypi absence claim.

## 2. Grounding (map results — verified this session)

- **Evaluators are pure/sync and run up to twice per PDV** (demotion pass + promotion `wouldDemote` backstop, `reachability.ts:2136-2194`). The oracle must be **precomputed data embedded in the signals objects** so both passes see identical answers. Threading precedent: `UpdateReachabilityOptions.usedTransitives` / `cveSinkPatterns` set at `pipeline-steps/reachability.ts:183-210`.
- **Three-valued discipline is load-bearing**: `resolve(present, s)` maps truncated→`unknown`→refuse (`django-preconditions.ts:152-156`); Go refuses all demotions when `signals.truncated` (`go-preconditions.ts:239`).
- **Descendant-counts-as-imported, ancestor does not** (`importsSubpackage` go:102-115; `moduleImported` django:157-171).
- **Transitive "yes" must never become promotion evidence** (go:47-49).
- **The resolve step materializes sources** for golang (`go mod download`) — but **pypi only when `requirements.txt` exists** (`resolve.ts:81`): saleor (poetry) and paperless (Pipfile) get no site-packages, so the pypi leg acquires per-dist. gem/composer download nothing.
- **Hardened per-dist fetch precedent**: `malicious/tarball-cache.ts` — name-shape SSRF gates, zip-slip + 500MB/100:1 bomb guards, 30s/pkg timeouts. **But its sdist-first flags are the wrong precedent for this leg** (see S5): the reachability fetch is wheel-only.
- **Pipeline order** (`pipeline.ts:94-146`): clone → resolve → sbom → deps-sync → usage-extraction → dep-scan → rule-gen → taint → **reachability**. `project_dependencies` is queryable before reachability; reachability runs before the `DEPTEX_SKIP_OPTIONAL_SCANS` block, so the oracle step must too.
- **Corpus validation targets labelled**: caddy CVE-2024-24786 protobuf `module` vs gitea same-CVE `unreachable`; gitea+caddy CVE-2026-39821 x/net(idna) `module` both; paperless sqlparse GHSA-27jp-wm6q-gp25 + CVE-2024-4340 `unreachable` (regression assertions); paperless tqdm-cli + filelock demotions (pt29/pt30 wins — owner-exclusion regression assertions); saleor cryptography pkcs7/pkcs12/ssh-certs demotions (regression assertions).
- **Wall-time** measured from `runs/<repo>/summary.json duration_ms`, paired same-session runs; the dep-import leg gets its own step timer and is reported separately (assembled reports drop durations). Freshest baselines: `C:/Coding/Deptex/depscanner/arc4a-runs/`.
- **Tripwire semantics**: new demotions are corpus-diff REVIEW class (module→unreachable); any VISIBLE→SILENCED is an ALARM and a hard block. **v2 adds: any unreachable→module flip on a labelled-`unreachable` CVE (veto over-fire) is a regression to adjudicate, not wave through.**
- **PGLite corpus reality (ops lens):** CLI/corpus scans boot a fresh **in-memory** PGLite per run — the DB cache never warms across corpus runs; its beneficiary is prod cross-org scans. Corpus runs bear bounded cold cost each run, controlled via env knobs forwarded through `bin/deptex-scan`.

## 3. Design

### D1. Oracle shape — `TransitiveImportIndex` (per-package granularity; owner-excludable)

Declared in a new home `depscanner/src/transitive-imports.ts` (types + pure membership helpers; no imports from reachability.ts or the pipeline step — both import *it*; kills circular-import risk). Computed once per scan by the new pipeline step, threaded via `UpdateReachabilityOptions.transitiveImports`, merged into the per-ecosystem signals object inside `updateReachabilityLevels`:

```ts
interface PackageImportSummary {
  modules: Set<string>;      // lowercased dotted module paths (pypi) / full import paths (go)
  tokenHits: Set<string>;    // question-token substring hits (pypi only)
}
interface TransitiveImportIndex {
  ecosystem: 'golang' | 'pypi';
  /**
   * complete    — every enumerated package extracted; absence answers valid (GO ONLY in v1).
   * partial     — some packages failed/capped/wheel-less; only POSITIVE answers valid (veto-only).
   * unavailable — nothing usable; behave exactly as today.
   */
  status: 'complete' | 'partial' | 'unavailable';
  perPackage: Map<string, PackageImportSummary>;  // key: normalized package name
  extractedPackages: Set<string>;                 // names successfully extracted (NOT a count — review fix)
  failedPackages: string[];
}
```

Pure helpers (owner exclusion is the review's core fix — the vulnerable package's own wheel always self-hits: PIL's ImageFont.py contains 'imagefont', cryptography's pkcs7.py contains 'pkcs7', sqlparse self-imports absolutely; without exclusion every absence is unprovable and every veto always fires, undoing shipped demotions):

```ts
transitivelyImported(idx, module, { excludeOwners: string[] }): boolean   // descendant semantics, owners skipped
transitiveTokenHit(idx, tokens, { excludeOwners: string[] }): boolean     // owners skipped
```

**Status asymmetry (unchanged, all lenses endorsed):** positive answers are sound on `partial` (they only ever refuse demotions); absence claims require `complete` — which in v1 only the Go leg can reach. The pypi index is an **unrooted union** over installed dists (a conservative superset of the rooted closure) — sound for vetoes on every dist *except the owner*, whose own loading is exactly the question being asked; owner exclusion restores the question and matches today's first-party `textIncludes` standard (an app whose only 'imagefont' mention is pillow's own code demotes today too).

For `silence_events.classifier_inputs` (Sets don't JSON-serialize): record `{ transitive_import_status, extracted_count, failed_count }` only — no URLs, no package lists.

### D2. Go leg — `go list -deps` (hardened, module-boundary-aware)

- **Trigger guard (review: don't run on every golang scan):** run only when ≥1 golang PDV's dep matches a `SUBPACKAGE_GATES` module. Zero matches → skip (index null).
- **Module enumeration first (MUST-FIX: `./...` does not cross nested go.mod boundaries):** enumerate `go.mod` files under the workspace (excluding `vendor/`, `testdata/`, `node_modules/`, depth-capped). Exactly one at root → single run. Multiple (or any `go.work`) → run `go list -deps ./...` once per module directory and **union** the outputs; any per-module failure → whole index `unavailable` (Go has no `partial`: a missing module's compile set could hide the import).
- **Hardened invocation:** `execFileSync('go', ['list', '-deps', './...'], { cwd, timeout: 180_000, maxBuffer: 50MB, env: { ...process.env, GOTOOLCHAIN: 'local', GOFLAGS: '-mod=readonly', CGO_ENABLED: '0' } })`. `GOTOOLCHAIN=local` pins the image's Go 1.22.10 — a repo demanding a newer toolchain fails → `unavailable` → refuse (no repo-chosen toolchain download/execution; review security fix). **No `-mod=mod` retry** (it re-enables network + mutates go.mod/go.sum mid-pipeline — dropped). **Never pass `-e`**; any nonzero exit → `unavailable`, stdout of a failed run is discarded (no partial-output parsing).
- **Soundness posture:** output = exact compile set under linux/amd64 default tags — matches the deploy assumption and the model's existing windows-only doctrine (windows-only imports excluded by design, same as the `django-windows-only`/Rails windows rows). Build-tag-enabled deploys (`-tags gogit`) are out of scope the same way they are for every existing gate. Test files excluded (no `-test`). Dev/test-only module deps never appear (`-deps` follows real imports) — prod-path filtering is inherent.
- **Consumption** (`reachability-go-preconditions.ts`):
  - `GoImportSignals` gains `transitiveImportedPackages?: Set<string>` + `transitiveStatus?: 'complete' | 'unavailable'` (populated by the merge in reachability.ts, not the gatherer).
  - `SubpackageRule` gains `requiresTransitiveProof?: boolean`. `GoDemotionResult` gains `proofStandard?: 'first_party' | 'prod_path'` (drives the verdict stamp).
  - `evaluateGoSubpackageDemotion`, per matched rule:
    1. First-party `importsSubpackage` → refuse (unchanged).
    2. Transitive positive (subpackage or descendant in `transitiveImportedPackages`) → **refuse** (veto; any status).
    3. `requiresTransitiveProof` → demote only when `transitiveStatus === 'complete'` and absent; else refuse. Stamps `proofStandard: 'prod_path'`.
    4. No flag → demote on first-party absence as today (`proofStandard: 'first_party'`; byte-identical behavior when the oracle is unavailable).
  - **Pattern criterion for `requiresTransitiveProof` rows (review fix): patterns may only NAME the affected subpackage** — no generic terms. Restored idna row: `/\bidna\b/i`, `/punycode/i`. New protojson row (`google.golang.org/protobuf` → `google.golang.org/protobuf/encoding/protojson`): `/protojson/i` ONLY (CVE-2024-24786's summary names `protojson.Unmarshal` explicitly; `/json/i` was rejected as enabling cross-subpackage demotion of future core-protobuf CVEs).
- New verdict for `prod_path` demotions: `go_subpackage_not_on_prod_path`, reason "…is not imported by any first-party source file nor by any package on the production dependency path". The existing `go_subpackage_not_imported` verdict/reason stays byte-stable (consumer contract, `reachability.ts:1727-1729`).

### D3. pypi leg — wheel-only per-dist extraction, veto-only consumption

- **Trigger guard:** ≥1 pypi PDV whose dep matches an owner of a transitive-consulting row (static registry exported from the models). None → skip entirely.
- **Enumerate:** `project_dependencies` for the run, `environment !== 'dev'` (explicit-dev exclusion only; unknown counts as prod — inclusion errs toward refusal = safe; see S4). Names PEP-503-normalized. Cap `MAX_DISTS` (env `DEPTEX_DEP_IMPORT_MAX_DISTS`, default 500); **cap-hit or wall-cap-hit → status `partial`, stated explicitly.**
- **Acquire — WHEEL-ONLY (security MUST-FIX):** `pip3 download --no-deps --only-binary=:all: --isolated --no-input --dest <dir> <name>==<version>`. **Never sdist:** pip's sdist metadata preparation executes the package's build backend (setup.py / PEP 517) — arbitrary code execution in the credential-bearing scan container. A dist with no wheel = failed dist → `partial`. This deliberately diverges from `malicious/tarball-cache.ts`'s sdist-first flags (that scanner wants source for GuardDog and accepts different tradeoffs); the generalized `src/lib/dep-sources.ts` therefore takes an explicit `artifactPolicy: 'sdist-first' | 'wheel-only'` knob, `malicious/` keeps `'sdist-first'` byte-identically, this leg uses `'wheel-only'`. Name/version shape gates (`PYPI_NAME_RE` + version regex) and the zip-slip/bomb guards apply on the `.whl` (zip) path exactly as today.
- **Extract per dist:** run the (already-exported — v1 plan error) `extractPythonImports` over every `.py` (caps: 2MB/file, 3000 files/dist) + liberal lowercase substring scan of the same bytes for the static question tokens. **Unpack → extract → delete immediately, per dist** (disk discipline; bounded by concurrency 4, not by job length). Store per dist: `{ importedModules, questionHits, truncated }`; a truncated/zero-scannable-file dist = failed.
- **Wall cap:** `DEPTEX_DEP_IMPORT_WALL_MS`, default 240_000 (prod). Both knobs forwarded through `bin/deptex-scan` + `bin/deptex-scan.ps1` env allowlists (files-touched updated); **corpus runs set 900_000** so the fetch completes and results are deterministic.
- **Cache:** global table `package_import_summaries` — **unique key `(ecosystem, package_name, version)`** with `extractor_version` as a **column** (the `package_capabilities` precedent: replace-in-place on version change; a version-in-key design accumulates stale rows forever — review fix). Columns: `imported_modules jsonb, question_hits jsonb, files_scanned int, artifact_sha256 text, extractor_version text, created_at`. `package_name` stored PEP-503-normalized. Read = one batched `.in('package_name', names)` + client-side (version, ecosystem, extractor_version) filter; mismatched extractor_version = miss → refetch → upsert-replace. Skip-write for failed/truncated dists. Cross-org rationale + residual risk in S6. Migration **`phase72_package_import_summaries.sql`** (phase69/70/71 are consumed by the unpushed aegis-task branch and applied to prod) + `npm run schema:dump`.
- **Consumption — veto only.** `DjangoFeatureSignals`/`FlaskFeatureSignals` gain `transitiveImports?: TransitiveImportIndex` (merged, not gathered). One shared helper, routed through the existing `resolve()` so truncated→unknown survives (review fix):

```ts
// in transitive-imports.ts; owners = the PDV's normalized dep name(s)
transitiveConsumerVeto(idx, { modulePrefixes, tokens, excludeOwners }): boolean
```

Converted rows (submodule-load class ONLY) change from
`detect: (s) => resolve(firstParty(s) || hasAnyProdDep(s, HARD_LIST), s)` to
`detect: (s, ownerNames) => resolve(firstParty(s) || transitiveConsumerVeto(s.transitiveImports, {...row.question, excludeOwners: ownerNames}) || hasAnyProdDep(s, HARD_LIST), s)` — the evaluator already knows the dep name; it threads `ownerNames` (normalized dep name) into detect. Hard lists remain necessary-for-demotion; the oracle only ADDS `present` answers.

### D4. Row classification (review-corrected table)

**Submodule-load rows — get the owner-excluded transitive veto (v1):**

| Row (`django-preconditions.ts`) | Question modules | Question tokens |
|---|---|---|
| `pillow-imagefont` (:241-252) | `pil.imagefont` | `imagefont`, `truetype(` |
| `cryptography-pkcs7` (:276-283) | — | `pkcs7` |
| `cryptography-pkcs12` (:285-292) | — | `pkcs12` |
| `cryptography-ssh-certificates` (:297-308) | — | `load_ssh`, `ssh_certificate`, `sshcertificate` |
| `fonttools-untrusted-fonts` (:351-357) | `fonttools` | `fonttools`, `ttlib` |
| `setuptools-packageindex` (:362-367) | — | `package_index`, `easy_install` |
| `tqdm-cli-injection` (:376-387) | `tqdm.cli` | `tqdm.cli`, `tqdm.__main__` |
| `filelock-softfilelock` (:395-401) | — | `softfilelock` |

**Consumer-semantics rows — NOT converted, no veto (the question is "does an attacker-input-feeding consumer exist", not "who imports X"):** `sqlparse-untrusted-sql` (Django itself imports sqlparse for trusted sqlmigrate SQL — a veto would reverse paperless's two labelled `unreachable` wins), `brotli-scrapy-consumer`, `h11-parser-shadowed-by-httptools`. Also untouched: all first-party-detection-only rows (humanize, windows-only, pdfparser, imagemath) and every Flask row.

The **question registry** (`TRANSITIVE_QUESTION_TOKENS`) is **derived from the row tables** (each converted row carries its `question` field; the registry is computed, not hand-synced — review fix). `extractor_version` = const string incorporating a hash of the registry.

### D5. Pipeline integration + signals merge rule (pinned)

New step `depscanner/src/pipeline-steps/dep-import-graph.ts`, invoked in `pipeline.ts` between `doTaintEngine` (:143) and `doReachabilityAndEpd` (:146). `runStage` severity `'warn'`, budget 6min, own step timer (wall-time reported separately). Any throw → index null → today's behavior.

**Merge rule (review fix — pinned exactly):** in `updateReachabilityLevels`, right after the gather expressions (`reachability.ts:1307-1359`):
- Signals resolution stays `options.<eco>Signals ?? gather<Eco>(...)` (injected wins, unchanged).
- The merge **constructs a NEW object**: `goSignals = base ? { ...base, transitiveImportedPackages: base.transitiveImportedPackages ?? idx?.perPackageUnion, transitiveStatus: base.transitiveStatus ?? idx?.status } : null` — injected transitive fields win; caller-owned injected objects are never mutated; transitive data lives ONLY in new fields; index applied only when `idx.ecosystem` matches the run's ecosystem.
- `silence_events.classifier_inputs` gains `{ transitive_import_status, extracted_count, failed_count }` (:2383-2387).

Files touched:
- `depscanner/src/transitive-imports.ts` (new) — types + pure helpers + question-registry derivation.
- `depscanner/src/pipeline-steps/dep-import-graph.ts` (new) — trigger guards, go list runner (module enumeration, hardened env), pypi wheel fetch/extract/cache.
- `depscanner/src/lib/dep-sources.ts` (new) — TarballCache generalized with `artifactPolicy` knob; `malicious/tarball-cache.ts` becomes a thin `'sdist-first'` wrapper (its tests must stay green unchanged).
- `depscanner/src/reachability-go-preconditions.ts` — signals fields, `requiresTransitiveProof` + `proofStandard`, restored idna + new protojson rows, evaluator steps 2-3.
- `depscanner/src/reachability-django-preconditions.ts` — signals field, row `question` fields + ownerNames threading, veto in detect.
- `depscanner/src/reachability-flask-preconditions.ts` — signals field only (no row changes; keeps type parity for the merge).
- `depscanner/src/reachability.ts` — options field, pinned merge, new verdict string, classifier_inputs.
- `depscanner/src/pipeline-steps/reachability.ts` — thread the index.
- `depscanner/src/pipeline.ts` — invoke the step.
- `depscanner/bin/deptex-scan` + `bin/deptex-scan.ps1` — forward `DEPTEX_DEP_IMPORT_WALL_MS`, `DEPTEX_DEP_IMPORT_MAX_DISTS`.
- `backend/database/phase72_package_import_summaries.sql` (new) + `backend/database/schema.sql` (schema:dump).
- Tests: `depscanner/src/__tests__/transitive-imports.test.ts` + `dep-import-graph.test.ts` (new), extensions to `reachability-go-preconditions.test.ts` + `reachability-django-preconditions.test.ts` (incl. e2e FakeStorage cells).
- Harness fix (bundled): `oss-corpus.ts:258` timeout sweep `ancestor=` parameterized to `DEPTEX_CLI_IMAGE`.

## 4. Safety analysis (v2)

- **S1. Unknown always refuses.** `unavailable`, `partial`-absence, wheel-less dists, failed go list, multi-module failure, toolchain-pin failure — all → refuse. A failure can never look like "no".
- **S2. Positive evidence is monotone-safe — but only after owner exclusion.** The veto direction is conservative *between packages*; the owner's self-hits are excluded because they are the question, not evidence (and an always-on self-veto would silently reverse shipped demotions: saleor pkcs7/pkcs12/ssh-certs, paperless tqdm/filelock — now explicit regression assertions).
- **S3. The only new demotion power is Go `prod_path` rows**: proof = toolchain-computed compile set, single-module-verified, pinned-toolchain, union across nested modules — the same evidence class the labels were verified with. pypi makes no absence claims in v1.
- **S4. Dev-scope:** explicit-dev exclusion only; unknown→include→more refusals→safe. Go: inherent.
- **S5. No package code execution.** pypi: wheel-only (`--only-binary=:all:`), `--isolated --no-input` (no PIP_* / pip.conf index redirection), name/version shape gates, existing zip guards; **the sdist path is forbidden in this leg** (pip's sdist metadata prep executes build backends). Go: `GOTOOLCHAIN=local` (no repo-chosen toolchain execution), `-mod=readonly`, `CGO_ENABLED=0`, no retry that mutates go.mod. Wording corrected: *zero network on the Go happy path; anything requiring network/toolchain is refused, not attempted.*
- **S6. Cross-org cache.** Veto-only makes the worst case of a wrong/poisoned/dependency-confusion row an **over-refusal** (monotone-safe). The fetch is public-PyPI-only regardless of org private-index config — documented; absence claims (v2) must revisit this (recorded in §8). `artifact_sha256` stored now for future integrity checks. Keys PEP-503-normalized (the FlaskBB/Pillow name-join lesson).
- **S7. Wall-time + billing.** Go: one (or per-module) toolchain invocation, no network, trigger-guarded. pypi: trigger-guarded, wheel-only (no builds), wall-capped 240s prod / 900s corpus, cache-amortized for prod, per-dist cleanup bounds disk. Metering impact bounded by the caps (verified against metering code by the ops lens).
- **S8. No promotion changes.**
- **S9. Consumer contracts:** existing verdict strings byte-stable; one new verdict `go_subpackage_not_on_prod_path`.

## 5. Validation plan (deterministic expectations — no either-outcome-passes cells)

1. **Unit (3-layer):**
   - Pure: Go evaluator matrix — {first-party present/absent} × {transitive present/absent} × {status complete/unavailable} × {requiresTransitiveProof y/n} incl. proofStandard stamps; idna + protojson rows; pattern-criterion cells (a `/json/i`-style summary must NOT demote). Django veto matrix per converted row — {first-party} × {oracle veto hit/miss} × {hard-list present/absent} × {status} incl. **owner-self-mention-only → still demotes** and truncated→unknown routing. Consumer-semantics rows: assert NO transitive influence (sqlparse cell).
   - Gatherer/step: module enumeration (single, nested go.mod → union, go.work → per-module), hardened env assertion, mkdtemp fake wheels (imports, tokens, caps→failed, zero-scannable→failed, wheel-less→partial), owner exclusion, cache read/write round-trip incl. extractor_version replace-in-place.
   - E2E FakeStorage: gitea-shaped (protojson absent, complete → module→unreachable w/ verdict `go_subpackage_not_on_prod_path`), caddy-shaped (protojson present → refuse), oracle-unavailable (requiresTransitiveProof refuses; legacy rows still demote), Django veto e2e + backstop consistency + classifier_inputs recorded.
2. **Two-app e2e (rebuild `deptex-cli:selfimprove`; `git checkout -- depscanner/src/lib/encryption.ts` before commits):**
   - **caddy:** CVE-2024-24786 stays `module` (veto via cel-go). idna CVE-2026-39821 stays `module`. Everything else byte-identical (tripwire).
   - **gitea:** CVE-2024-24786 `module → unreachable` (the flagship REVIEW-class transition, matches its `unreachable` label). idna stays `module`. No other transitions.
   - **saleor:** pkcs7/pkcs12/ssh-certs demotions **still fire** (owner exclusion works); fonttools stays `module` (veto via weasyprint's genuine fontTools import — a correct new refusal is acceptable ONLY if fonttools is currently demoted by a row whose veto now fires for a non-owner reason; expected: no change, since the row's first-party check already refuses on saleor — assert no transition either way in the tripwire and adjudicate any).
   - **paperless:** sqlparse both CVEs stay `unreachable` (row untouched — named regression assertion); tqdm-cli + filelock demotions still fire; pillow-imagefont refusal unchanged (direct first-party import).
3. **Tripwire:** corpus-diff vs `arc4a-runs` baselines for every rescanned app: ZERO ALARMs; every REVIEW transition adjudicated against labels in the ledger; **any unreachable→module flip on a labelled-`unreachable` CVE = veto over-fire, must be root-caused** (not waved through).
4. **Full-corpus rescore:** Gate-3 / Baseline-lock / Oracle / recall-floor PASS; TRUE active-FP 0.
5. **Wall-time:** dep-import step reports its own duration; per-repo total ≤+20% with the step's cost itemized (corpus cap 900s makes pypi runs deterministic; prod default stays 240s).
6. **Suite:** depscanner+backend tsc, full backend jest, taint preflight, dogfood:check, integration-pglite (phase72 table boots in PGLite from schema.sql), malicious-scanner tests green (dep-sources extraction is behavior-preserving).

## 6. Review asks — resolved

1. Existing Go gates keep first-party-only behavior when oracle unavailable (all lenses concurred; reverting shipped wins on go-list failure serves no one).
2. **pypi = veto-only in v1** (4-lens consensus; the absence direction was independently killed by owner-self-hits, non-.py content, enumeration divergence, and dependency-confusion).
3. Cache table ships now — corrected rationale: it benefits **prod** cross-org scans (corpus loops use in-memory PGLite and never warm it); corpus determinism comes from the env knobs instead.
4. `partial` = veto-only confirmed sound by every lens; not collapsed to unavailable (it would discard valid positive evidence — the common first-scan state on large apps).
5. Verdict `go_subpackage_not_on_prod_path` confirmed non-colliding; old strings byte-stable.
6. Merge rule pinned (D5); pure/sync + backstop consistency verified by three lenses.

## 7. Rollout

Worker-side + one additive migration (`phase72`). Merge ≠ deploy (image rebuild + `FLY_DEPSCANNER_IMAGE` bump; Arc 2 stacks behind the already-open deploy gate carrying prior merged worker-side work). One PR at arc end; Henry pushes/merges.

## 8. Deferred to Arc-2 v2 (recorded requirements, do not implement now)

pypi **absence claims / hard-list bypass** require ALL of: (a) enumeration-trust signal (lockfile-derived SBOM or resolve success) gating `complete`; (b) `extractedPackages ⊇ (manifest-depUniverse ∩ hard-list names)` cross-check per row (the SBOM-vs-manifest divergence fix); (c) non-.py content handling (dists with .so/.pyd or .pyc-without-.py = failed; token-scan entry_points.txt/.cfg/.toml); (d) a position on public-vs-private artifact trust (dependency confusion) — likely "absence claims only for registry-verified public dists"; (e) a second labelled app exercising the bypass direction per converted row. npm/gem/composer legs: future arcs.

---

## Review log (v1 → v2)

6 lenses, all REVISE. MUST-FIXes and dispositions:

| # | Lens(es) | Finding | Disposition |
|---|---|---|---|
| 1 | gate3, scope, api-tests | Owner-dist self-hits saturate the flat-Set oracle: absence never provable, vetoes always fire (undoing saleor pkcs7/pkcs12/ssh + paperless tqdm/filelock wins) | Per-package index + `excludeOwners` in every membership helper (D1); regression assertions added (§5.2) |
| 2 | gate3 | `go list -deps ./...` misses nested go.mod modules → complete-but-wrong absence proofs | Module enumeration; multi-module → per-module union or `unavailable` (D2) |
| 3 | gate3, code-facts, api-tests | pypi `complete` unsound: non-.py wheel content, .pyc-only, entry_points strings; enumeration incompleteness (resolve soft-fail, SBOM-vs-manifest depUniverse divergence); cap-hit status unspecified | **v1 = veto-only** (no pypi absence claims); requirements for v2 recorded (§8); cap-hit → `partial` explicit (D3) |
| 4 | scope | sqlparse conversion reverses paperless's two labelled `unreachable` wins (consumer-semantics ≠ import-fact) | Row classification introduced; sqlparse/brotli/h11 excluded (D4); paperless sqlparse named regression assertion |
| 5 | security | sdist fallback executes attacker build backends in the credential-bearing container | Wheel-only (`--only-binary=:all:` `--isolated --no-input`); wheel-less → failed → partial; `artifactPolicy` knob so malicious/ keeps its own behavior (D3) |
| 6 | ops | PGLite is in-memory → cache never warms corpus runs; wall-cap env not forwarded through bin/deptex-scan; validation as written can't pass | Env knobs forwarded (+ files-touched); corpus cap 900s; wall gate itemizes the step's own timer; ask-3 rationale corrected (D3, §5.5, §6.3) |

Key SHOULD-FIXes folded in: protojson `/json/i` dropped + pattern criterion stated (subpackage-naming only); GOTOOLCHAIN=local + no `-mod=mod` retry + CGO_ENABLED=0; merge rule pinned (new objects, injected-wins, new-fields-only); shared veto helper routed through `resolve()`; migration renumbered phase72; cache extractor_version as column w/ replace-in-place (no stale accumulation) + artifact_sha256 + PEP-503 keys; per-dist unpack→extract→delete; Go trigger guard; batched cache reads; `GoDemotionResult.proofStandard`; TransitiveImportIndex housed in its own module; question registry derived from rows. Factual corrections: `extractPythonImports` already exported; fonttools row has no weasyprint hard list; `sourcedPackages` count → `extractedPackages` set.
