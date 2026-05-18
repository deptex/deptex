# OSS corpus baseline — 2026-05-10

First-ever OSS corpus pass for the depscanner hardening marathon. 10 popular
public repos across 6 ecosystems (npm, pypi, maven, golang, gem, composer),
ground-truthed against 12 CVE IDs from NVD / GHSA / OSV. Future hardening
ticks rerun the same harness to measure delta.

- Harness: `depscanner/scripts/oss-corpus.ts` (continuous testing mechanism)
- Corpus: `depscanner/scripts/oss-corpus.yaml` (10 repos + ground-truth)
- Contributor guide: `depscanner/scripts/README-oss-corpus.md`
- Raw artefacts: `oss-corpus-runs/baseline/` (gitignored, re-derivable)

Reproduction:

```bash
cd depscanner
npm run scan:oss-corpus -- \
  --repos=scripts/oss-corpus.yaml \
  --output=../oss-corpus-runs/baseline \
  --parallel=2 --scan-timeout=600 --no-rule-gen
```

## Aggregate

| Metric | Value |
|---|---|
| Repos in corpus | 10 |
| Scanned ok | **0** |
| Failed | 10 (scan_timeout 2, scan_failed 2, clone_failed 6) |
| Total ground-truth CVEs | 12 |
| Matched (recall numerator) | 0 |
| **Aggregate recall** | **0%** |
| Noise (reachable+high/critical, off-allowlist) | 0 |
| Total wall time | 27.5 min |
| Total AI cost | $0.0000 (rule-gen disabled this run) |

The harness itself works end-to-end (the Windows-Docker bring-up fixes from
the `fix(depscanner): make OSS corpus harness work end-to-end…` commit got
the pipeline past clone → SBOM stage). The **recall number is zero because
no scan completed**, not because the engine missed reachable CVEs. The next
hardening tick that fixes the cdxgen bottleneck will produce the first
real recall number from this corpus.

## Per-ecosystem

| Ecosystem | Scanned | Ground-truth | Matched | Recall |
|---|---|---|---|---|
| composer | 0 | 1 | 0 | 0% |
| gem | 0 | 1 | 0 | 0% |
| golang | 0 | 1 | 0 | 0% |
| maven | 0 | 1 | 0 | 0% |
| npm | 0 | 5 | 0 | 0% |
| pypi | 0 | 3 | 0 | 0% |

## Per-repo

| Repo | Eco | Framework | Status | Findings | Reachable | GT match | Duration |
|---|---|---|---|---|---|---|---|
| express | npm | express | scan_timeout | - | - | 0/2 | 656s |
| fastify | npm | fastify | scan_timeout | - | - | 0/1 | 656s |
| nextjs | npm | nextjs | scan_failed | - | - | 0/2 | 155s |
| flask | pypi | flask | scan_failed | - | - | 0/1 | 184s |
| django | pypi | django | clone_failed | - | - | 0/1 | 0s |
| fastapi | pypi | fastapi | clone_failed | - | - | 0/1 | 0s |
| gin | golang | gin | clone_failed | - | - | 0/1 | 0s |
| spring-petclinic | maven | spring | clone_failed | - | - | 0/1 | 0s |
| sinatra | gem | sinatra | clone_failed | - | - | 0/1 | 0s |
| laravel | composer | laravel | clone_failed | - | - | 0/1 | 0s |

## Failure modes encountered

### 1. `cdxgen --profile research --deep` dominates per-scan cost (express, fastify)

Both express (a tiny ~1.4MB repo) and fastify hit the 600s scan timeout.
Container introspection showed both stuck in cdxgen for the full duration:

```text
worker  43  cdxgen ... --profile research --deep -t npm
worker 1077  git ls-remote git://github.com/jaredhanson/utils-merge.git
worker  155  git clone --branch v7.29.0 https://github.com/babel/babel.git
```

cdxgen's research profile recursively clones the upstream source repo
of every transitive dependency for license/origin enrichment. On a host
without an npm-registry mirror this is the dominant cost — for Express'
~30 transitive deps that is ~30 sequential `git clone` calls against
github.com, plus `git ls-remote` for each.

**Source citation**: `depscanner/src/pipeline-steps/sbom.ts:33-39`
hardcodes `--profile research --deep` with no env override.

### 2. Bash-wrapper SIGKILL does not propagate to the docker child (express, fastify)

When the harness's per-scan timer fires, it calls `proc.kill('SIGKILL')`
on the bash wrapper. The wrapper has already `exec`'d into a `docker run`
process, but `docker run -i` does not exit when its parent stdin closes
mid-syscall — so the container kept running another ~5 min until I
manually `docker kill`ed it. The 656s reported duration reflects the
manual-kill latency, not the timer. **The harness's `oss-corpus.ts` has
been patched** (commit `4c25e53` + the SIGKILL extension in this commit)
to also `docker ps --filter ancestor=deptex-cli:local | docker kill` on
timeout. The patch can't take effect mid-run; next baseline will exercise it.

### 3. `git clone exited 3221225794` (django/fastapi/gin/spring-petclinic/sinatra/laravel)

After the harness killed the bash+docker tree for express/fastify and
SIGKILLed the flask/nextjs scans, the next round of `git clone` calls
all exited with the Windows DLL-init failure status. Root cause is
under-investigated but likely related to the SIGKILL cascade or to the
ancillary docker-kill loop perturbing Git for Windows' DLL load. Next
baseline run from a clean shell will isolate this.

## Top 5 most-impactful gaps (cannot populate today)

The "missed-but-reachable" analysis requires at least one successful scan
that produces a populated `vulns.json`. The next hardening tick that
unblocks the cdxgen path will be the first to populate this section.

The ground-truth CVE list (`oss-corpus.yaml`) has 12 entries pre-mapped
to expected reachability tiers + GHSA citations. Once a scan completes,
the harness already classifies each entry as observed-or-missed
(`report.json` → `results[].missed_examples`) — no extra work needed.

## Top 5 noise modes (cannot populate today)

Same blocker — no scan produced `vulns.json` rows. The harness's noise-
proxy filter (reachable + high/critical, not in ground-truth allowlist)
is wired and ready.

## Recommendations (initial)

Ordered by expected impact on the next baseline:

1. **Add `--profile generic` env override to `pipeline-steps/sbom.ts`**.
   Honor `DEPTEX_CDXGEN_PROFILE` so the OSS corpus harness can run without
   the source-repo enrichment. Research-mode stays on for the Fly.io
   cloud worker where the time cost is amortized. Single one-line patch.

2. **Add an `npm-registry mirror` env knob** (or `--registry` flag to
   the cdxgen wrapper). Most of the per-dep `git clone` cost is the
   network-side latency; a local Verdaccio/proxy could cut SBOM time by
   >90%.

3. **Wrapper-level docker timeout**: add `--stop-timeout` and
   `--label deptex-scan-<run-id>` to the `docker run` invocation in
   `deptex-scan`, plus a SIGTERM-then-SIGKILL ladder so the harness's
   timer kills the container cleanly. Removes the manual-kill latency.

4. **Per-ecosystem `expected_scan_seconds`** field in `oss-corpus.yaml`.
   So the harness's `--scan-timeout` can be a sensible floor (e.g. 1200s
   for npm/maven, 300s for gem/composer) instead of a global ceiling.

5. **Skip-clone reuse**: the harness already supports `--skip-clone`;
   ensure the workspace dirs survive between runs so reruns are
   workspace-cache-warm.

## Next-batch candidates (5 repos for the next 10)

Once the baseline produces a non-zero recall number, the next wave should
broaden framework + framework-version coverage:

1. **`socketio/socket.io`** (npm) — websocket entry-points (`socket.on(...)`)
   exercise a taint-source class not covered by the express/fastify
   request-handler models.
2. **`sqlalchemy/sqlalchemy`** (pypi) — pure-library ORM. Tests whether
   the engine over-flags internal SQL-construction helpers as sinks.
3. **`hashicorp/terraform-provider-aws`** (golang) — AWS SDK call-graph
   stress-test for the cross-file engine; many millions of LOC.
4. **`rails/rails`** (gem) — the biggest Ruby framework. Once the Sinatra
   DSL spec lands, Rails ActionController + ActiveRecord is the natural
   next coverage target.
5. **`symfony/symfony`** (composer) — Laravel's CVE history in
   `laravel/laravel` is sparse; Symfony has multiple per-year and
   exercises HttpFoundation → Doctrine ORM, a different sink class.
