# Path to ~90% Recall — 88-CVE Iterate Corpus

Re-classification of the 36 non-validated CVEs in the clean run
`bench-iterate/v_base/2026-05-12T20-00-19/` (52/88 = 59.1%, $0.22, 33min).

This doc is the post-mortem of the 26.1% → 59.1% session arc and the
honest forward plan.

---

## Baseline funnel (clean run, tip `413ef48`)

```
schema_pass:      82/88
fixture_pre:      52/88   <-- dominant failure point
fixture_safe:     82/88
patch_post_clean: 55/88
validated:        52/88

Status breakdown:
  validated:               52
  failed_validation:       30   (all are: pre=0 post=0)
  vuln_class_out_of_scope:  6
```

**Every single failed_validation entry has `pre=0 post=0`.** The engine
finds zero taint flows in the AI's own vulnerable fixture, despite the
Gate 2 widening (`61def8e`) retrying with bundled-spec sinks of matching
`vuln_class`. So the gap is at one of four levers:

1. Engine cannot see the taint shape the AI emitted.
2. Bundled spec library has no sinks for that library/vuln_class.
3. AI prompt does not teach Qwen the canonical shapes our engine matches.
4. `vuln_class` enum rejects the AI's chosen string.

## Per-CVE classification

| Bucket | CVEs | Fix lever | Estimated work |
|---|---|---|---|
| **A. F4 hoisted-const blocker** (`const opts = {...}; f(x, opts)`) | jsonwebtoken 22-23539, follow-redirects 24-28849, requests 24-35195, urllib3 20-26137, flask 23-30861 | Engine | ~50–100 LOC |
| **B. Java property-path matching** | spring-beans 22-22965 (Spring4Shell) | Engine | ~175 LOC, design at `docs/engine-property-path-matching.md` |
| **C. Go struct-field-init sink** (`&ssh.ServerConfig{PublicKeyCallback: f}`) | golang/x/crypto 24-45337 | Engine + spec.ts | ~80 LOC |
| **D. Python kwarg-aware sink matching (audit)** | urllib3 20-26137, requests 23-32681 | Engine | ~30 LOC (extends F3b) |
| **E. Computed-key full taint** (`obj[src] = v` taints `obj`) | lodash 26-4800 | Engine | ~40 LOC (extends E2) |
| **F. Method-chain on awaited results** (`(await axios.get(u)).data.x`) | axios 26-40175, 26-34043 | Engine | ~60 LOC |
| **G. Bundled-spec library gap** | snyk-go 24-21484/21503, pillow 24-26130, debug 17-16137 | New YAMLs | 1 file each |
| **H. vuln_class enum gap** (`dos`, `cardinality_dos`, `multipart_dos`) | 23-34053, 17-12626, 22-32149, 22-27664, 22-21698, 22-23837 | Enum + non-taint regime + version-only tier | ~3 day arc |
| **I. AI shape-mismatch** (spec exists, AI emits non-matching sink) | actionpack 22-23633, ruby-git 24-32465, sinatra 23-28120, spring-security 22-22978, log4j-1.x 23-26464, xmlsec 23-44483, x/net 23-3978 | AI prompt + few-shots | ~2 day arc |
| **J. Memory-safety / non-modelable but coverable via lints** | cryptography 23-49083, jinja2 sandbox 19-10906, jinja2 redos 20-28493, setuptools 24-6345 | F4 ReDoS + memory-safety regime | ~2 days |
| **K. Genuinely uncoverable** (3 CVEs, **3.4% floor**) | certifi 23-37920, HTTP/2 rapid-reset 23-44487, runc 24-21626, pillow 21-25287 | Package-version-only tier | accept |

## Ceiling analysis

- **K** is unfixable inside any reachability regime (3-4 CVEs, ~3-4% floor).
- **J** is partially fixable (+2–3 realistic CVEs via ReDoS / insecure-default lints).
- **Hard ceiling on this corpus: ~88–91%**.
- Realistic landing zone after all phases below: **82–86%**.

## Five-phase plan

### Phase 1 — Methodology (½ day, prereq)

- **1a** 3-trial averaging in `iterate.ts`. Seed each run; report majority validated + stddev.
- **1b** Per-CVE diagnostic dump on failure to `bench-iterate/<ts>/diag/<cve>.json`
  (sinks loaded, steps fired, steps dropped, sanitizer matches). Removes the need to
  re-Read engine source during triage.

Without this we can't tell engine wins from Qwen variance (currently ±3 CVEs run-to-run).

### Phase 2 — Engine features (3–4 days, 10 CVEs)

Ordered ascending LOC.

| Step | File(s) | LOC | CVEs unlocked |
|---|---|---|---|
| 2a — JS single-assignment const resolver for F4 inline-literal kwargs | `taint-engine/non-taint-detector.ts` + `propagate-core.ts` | ~50 | jsonwebtoken 22-23539, follow-redirects 24-28849 |
| 2b — Python kwarg-aware sink matching audit | `taint-engine/python/propagate.ts`, `python/ir.ts` | ~30 | urllib3 20-26137 |
| 2c — Computed-key full taint write (extends E2) | `taint-engine/ir.ts` | ~40 | lodash 26-4800 |
| 2d — Method-chain on awaited results | `taint-engine/ir.ts` | ~60 | axios 26-40175, 26-34043 |
| 2e — Go struct-field-init sink kind | `taint-engine/go/ir.ts` + `spec.ts` | ~80 | golang/x/crypto 24-45337 |
| 2f — Java property-path matching (Spring4Shell) | `taint-engine/java/*` per design doc | ~175 | spring-beans 22-22965 |

**Each step:**
1. Extend `cve-targeted-fixtures` runner with the exact AI-generated fixture
   that failed in the iterate run.
2. Land green.
3. Re-run 88-CVE iterate at 3 trials.
4. Commit. Don't bundle steps — each must show its own delta.

### Phase 3 — Non-taint regime + vuln_class enum (2–3 days, ~5 CVEs)

- **3a** Add `dos`, `cardinality_dos`, `multipart_dos`, `memory_safety`,
  `protocol_dos` to `ALL_VULN_CLASSES` across all 3 mirrors (spec.ts, zod, AI
  prompt) and write Supabase migration `phase28d_extend_vuln_class_enum`.
- **3b** Wire **ReDoS detector** as F4 sibling: match catastrophic regex literals
  in `RegExp` / `re.compile` / `.match()`. Unlocks debug 17-16137, jinja2 urlize
  20-28493.
- **3c** Wire **insecure-default detector**: `requests.Session(verify=False)`,
  `ssl.PROTOCOL_*` weak, `Math.random()` in security context.
- **3d** **Version-only credit tier.** Promote bucket K (and any H-class CVE that
  remains taint-unmatchable) to a "version-vulnerable, no reachability claim"
  result tier. Surfaces in the same UI as `module`-level reachability but with a
  distinct badge. Pending Henry sign-off — this changes the score's meaning.

### Phase 4 — Spec library + AI prompt tuning (2 days, ~6 CVEs)

- **4a** New bundled YAMLs: `actionpack.yaml`, `ruby-git.yaml`,
  `pillow.yaml` extension, `cryptography.yaml`, `x-net-html.yaml`,
  `spring-security.yaml`.
- **4b** Extend the rule-generator system prompt with a "shapes the engine
  matches" sidebar: 4-5 canonical examples per language showing positional vs
  kwarg, struct-init vs call, method-chain. Goal: shrink bucket I.
- **4c** Few-shot one good fixture pair per ecosystem alongside the existing
  prompt examples. Lock these as `prompt/few-shots/*.json`.

### Phase 5 — Push to ceiling and lock (1 day)

- Rerun 88-CVE iterate at 3 trials.
- Snapshot per-eco baseline to `bench-iterate/baselines/2026-XX-XX.json`.
- Update this doc with actual numbers.
- Open PR for the whole arc.

## Cumulative projection

| Stage | Δ | Cumulative |
|---|---|---|
| Today | — | 59.1% |
| Phase 2 engine (10 CVE TAM, ~9 land after AI-shape miss) | +9 | 69.3% |
| Phase 3 enum + non-taint + version-only tier | +5 | 75.0% |
| Phase 4 spec library + prompt | +6 | 81.8% |
| Phase 5 variance averaging settles | +3 | 85.2% |
| Stretch — every bucket-I CVE lands | +3 | 88.6% |

**Realistic 82–86%. Stretch 88–90%. Hard ceiling ~91%.**

## Risks

1. **Round-trip benchmark optimizes the wrong thing.** It measures Qwen-fixture
   self-validation, not customer-code recall. Customer recall depends on
   bundled spec coverage + engine on real code. Recommend a *second* benchmark
   of hand-curated real-CVE fixtures alongside the iterate harness.
2. **Bucket I is prompt-fragile.** Model rev can shift it ±3 CVE. Phase 4b needs
   a regression test that exercises the prompt against fixed sample CVEs.
3. **Phase 2f (Spring4Shell, 175 LOC, 1 CVE)** is the worst LOC/CVE ratio.
   Justified by Spring4Shell being the flagship corpus CVE, but defer if budget
   tightens.
4. **Version-only credit tier changes the score's meaning.** Henry must sign off
   before we count K-bucket CVEs as covered.

## Cross-references

- Latest clean run: `depscanner/bench-iterate/v_base/2026-05-12T20-00-19/`
- Engine cores: `depscanner/src/taint-engine/{propagator,python,java,go,ruby,php,csharp,rust}*`
- Bundled specs: `depscanner/src/taint-engine/framework-models/`
- Validator: `depscanner/src/rule-generator/validate.ts`
- Spring4Shell design: `depscanner/docs/engine-property-path-matching.md`
- F4 design: `depscanner/docs/non-taint-detector-regime.md`
- Maven diagnosis: `depscanner/docs/maven-recall-diagnosis.md`
- Golang diagnosis: `depscanner/docs/golang-recall-diagnosis.md`
- F4 hoisted-const blocker memory: `feedback_js_kwarg_inferencer_blocker.md`
