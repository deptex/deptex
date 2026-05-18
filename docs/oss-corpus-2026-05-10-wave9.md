# OSS corpus — Wave 9 rerun — 2026-05-10

Sequel to `docs/oss-corpus-2026-05-10.md` (Wave 7). Wave 9 was supposed to
exercise the post-Wave-8.5 cdxgen fix (commit `2a193cb` — drop
`--deep` by default) against the same 10-repo corpus and produce the first
real recall numbers.

- Harness: `depscanner/scripts/oss-corpus.ts`
- Corpus: `depscanner/scripts/oss-corpus.yaml` (10 repos, 12 ground-truth CVEs)
- Raw artefacts: `oss-corpus-runs/baseline/` (gitignored)
- Wave 7 reference: `docs/oss-corpus-2026-05-10.md`
- Wave 8.5 cdxgen fix: `2a193cb`

## Headline — Wave 9 produced no new data

**The on-disk Wave 9 artefacts in `oss-corpus-runs/baseline/` are
byte-identical-in-shape to the Wave 7 run.** Both record 0/10 scanned,
0/12 matched, 27.5 min wall time, $0 AI cost, and the same six
`clone_failed` repos with Windows error `3221225794`.

Timeline check that confirms the data is pre-fix:

| Event | Timestamp |
|---|---|
| `report.json` generated_at | `2026-05-11T02:19:40Z` (= 2026-05-10 19:19 PDT) |
| Wave 8.5 cdxgen fix (`2a193cb`) committed | `2026-05-10 19:39 PDT` |
| **Delta** | **fix landed ~20 min AFTER baseline finished** |

The scan that produced `oss-corpus-runs/baseline/` ran against the
pre-fix `sbom.ts` that still hardcoded `--profile research --deep`.
Whatever process the Wave 9 agent kicked off either (a) terminated
mid-thought before launching a fresh run, or (b) re-used the existing
output directory without overwriting. Either way: **there is no new
recall data on disk to analyse.**

Additional corruption note: the per-repo `runs/<repo>/stdout.json` and
`stderr.log` files are zero bytes for all four scans that got past clone
(express, fastify, flask, nextjs) except `runs/nextjs/stdout.json` (161
bytes), whose single line is:

```
⚠ [resolve] Dependency resolution failed (non-fatal): npm dependency
resolution failed: Command failed: npm install --ignore-scripts ...
```

The two referenced log files (`baseline-run.log` + `baseline-trial.log`)
do not exist anywhere in the worktree.

## Aggregate (re-confirmed Wave 7 numbers)

| Metric | Value |
|---|---|
| Repos in corpus | 10 |
| Scanned ok | **0** |
| Failed | 10 (scan_timeout 2, scan_failed 2, clone_failed 6) |
| Ground-truth CVEs | 12 |
| Matched | 0 |
| **Recall** | **0%** |
| Noise (reachable + high/critical, off-allowlist) | 0 |
| Total wall time | 27.5 min |
| Total AI cost | $0 (rule-gen disabled) |

## Per-repo

| Repo | Eco | Framework | Status | Findings | Reachable | GT match | Duration |
|---|---|---|---|---|---|---|---|
| express | npm | express | scan_timeout | — | — | 0/2 | 656s |
| fastify | npm | fastify | scan_timeout | — | — | 0/1 | 656s |
| nextjs | npm | nextjs | scan_failed (137) | — | — | 0/2 | 155s |
| flask | pypi | flask | scan_failed (137) | — | — | 0/1 | 184s |
| django | pypi | django | clone_failed | — | — | 0/1 | 0s |
| fastapi | pypi | fastapi | clone_failed | — | — | 0/1 | 0s |
| gin | golang | gin | clone_failed | — | — | 0/1 | 0s |
| spring-petclinic | maven | spring | clone_failed | — | — | 0/1 | 0s |
| sinatra | gem | sinatra | clone_failed | — | — | 0/1 | 0s |
| laravel | composer | laravel | clone_failed | — | — | 0/1 | 0s |

`scan_failed (137)` = SIGKILL / OOM-kill of the docker child. `clone_failed`
exit code `3221225794` = Windows `STATUS_DLL_INIT_FAILED`, same as Wave 7.

## Top 5 missed CVEs (still all of them, expected reachability)

Per `report.json` → `results[].missed_examples`. With zero successful
scans these are pre-scan misses, not engine misses:

1. **CVE-2024-29041** — `express` 4.18.2, expected `function` reachability — GHSA-rv95-896h-c2vc
2. **CVE-2022-24999** — `express` 4.18.2 (`qs<=6.9.6`), expected `data_flow` — GHSA-hrpp-h998-j3pp
3. **CVE-2024-34351** — `nextjs` v14.1.0, expected `confirmed` — GHSA-fr5h-rqp8-mj6g
4. **CVE-2024-46982** — `nextjs` v14.1.0, expected `data_flow` — GHSA-gp8f-8m7h-r9q9
5. **CVE-2023-30861** — `flask` 3.0.2 (Flask<2.2.5/<2.3.2), expected `function` — GHSA-m2qf-hxjv-5gpq

Gap classification (per `report.json`): every miss is **stage-0 (no SBOM
emitted)** because no scan reached the `vulns.json` write step. None can
be attributed to the sbom / advisory / taint / rule-gen layers from this
data.

## Top 5 noise modes

`report.json` → `total_noise: 0`. Cannot populate — no scan produced
flagged findings.

## Comparison to Wave 7 (0/12 → 0/12)

| Dimension | Wave 7 | Wave 9 (this run) | Delta |
|---|---|---|---|
| Scanned ok | 0/10 | 0/10 | 0 |
| Recall | 0% | 0% | 0 |
| Noise | 0 | 0 | 0 |
| Wall time | 27.5 min | 27.5 min | 0 |
| AI cost | $0 | $0 | 0 |
| `scan_timeout` repos | express, fastify | express, fastify | same |
| `scan_failed` repos | nextjs, flask | nextjs, flask | same |
| `clone_failed` repos | django, fastapi, gin, spring-petclinic, sinatra, laravel | same six | same |

**Lift from Wave 8.5 cdxgen fix: indeterminate.** The fix is not
exercised by the data on disk because the data is pre-fix. The next
hardening tick that actually launches a scan against `2a193cb`-or-later
HEAD will produce the first measurable lift.

## Top 3 recommended actions

1. **Re-run the corpus against current HEAD.** This is the smallest
   step that produces real data. Command (from Wave 7 reproduction
   block, unchanged): `cd depscanner && npm run scan:oss-corpus --
   --repos=scripts/oss-corpus.yaml --output=../oss-corpus-runs/baseline
   --parallel=2 --scan-timeout=600 --no-rule-gen`. The directory
   needs to be cleaned first — the runner appears to skip work when
   `report.json` already exists.

2. **Fix the per-repo log capture.** Of 4 scans that got past clone, 3
   wrote 0-byte `stdout.json` + `stderr.log`. The runner is dropping
   stdio. Without these, post-mortem of any future timeout / OOM is
   blind. Inspect `oss-corpus.ts` `spawn`/`writeFileSync` of the child
   stdio streams.

3. **Pre-flight check the Windows `STATUS_DLL_INIT_FAILED` cascade.**
   The same six repos clone-fail in identical order every run. Wave 7
   hypothesised SIGKILL-cascade fallout from the earlier docker kill.
   Add a `git --version` smoke at corpus start + a between-scan
   `Start-Sleep` knob; rule out Git for Windows DLL-init contention
   before declaring the cdxgen fix unproductive.

## Data-integrity note (load-bearing)

The Wave 9 agent's mid-thought exit appears to have left the previous
Wave 7 artefacts in place. This report **describes the Wave 7 data as
re-observed today**, not a real post-fix rerun. Any future "Wave 9
delta" framing should treat this document as a null result — the only
new information is the timeline reconstruction proving the data is
pre-fix.
