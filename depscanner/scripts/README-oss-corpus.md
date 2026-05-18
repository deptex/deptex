# OSS corpus testing harness

Continuous testing harness for the depscanner hardening marathon.

The harness clones N public OSS repos, runs the local `deptex-scan` Docker CLI
against each, and reports recall (vs a hand-curated ground-truth CVE list),
noise (reachable + high/critical findings outside ground-truth), scan duration,
and AI cost. Each run produces both `report.json` (machine-readable) and
`report.md` (human-readable) under the output directory.

## Files

- `oss-corpus.yaml` — corpus definition + ground-truth CVE list per repo
- `oss-corpus.ts` — runner (clone -> scan -> aggregate -> report)
- `README-oss-corpus.md` — this file

## Prerequisites

1. `npm run docker:build` (from `depscanner/`) to build the `deptex-cli:local`
   image. The harness shells out to `./bin/deptex-scan` which requires the
   image to be present.
2. `backend/.env` populated with at least one of `ANTHROPIC_API_KEY`,
   `OPENAI_API_KEY`, `DEEPINFRA_API_KEY`. The harness loads these and
   forwards them to the container. EPD / rule generation only fire when
   the matching key is present.
3. `GITHUB_TOKEN` (or `GITHUB_PAT`) in `backend/.env` is strongly
   recommended — without it, GHSA patch fetches hit the anon 60/hr rate
   limit and most CVEs fail to resolve.

## Run all 10 repos

```bash
cd depscanner
npm run scan:oss-corpus -- \
  --repos=scripts/oss-corpus.yaml \
  --output=oss-corpus-runs/$(date +%Y-%m-%d) \
  --parallel=2
```

Expect ~30-50min wall time depending on repo size and Docker host. Outputs
land at `oss-corpus-runs/<date>/`:

```
report.json                 # aggregate + per-repo metrics
report.md                   # human-readable summary
workspaces/<repo>/          # shallow clone (reused with --skip-clone)
runs/<repo>/                # per-scan artifacts (summary, vulns, flows, ...)
  stdout.json
  stderr.log                # capture both so failure modes are forensic
```

## Re-run after an engine change

The harness is the continuous regression mechanism for the marathon. After
landing an engine change, rerun the same corpus to measure delta:

```bash
# Reuse cloned workspaces (saves ~5min); only the scan step reruns.
npm run scan:oss-corpus -- \
  --repos=scripts/oss-corpus.yaml \
  --output=oss-corpus-runs/$(date +%Y-%m-%d)-postfix \
  --parallel=2 \
  --skip-clone

# Compare report.json files with whatever diff tool fits — recall %, noise
# count, missed CVEs, and AI cost are the four numbers that matter.
```

## Add a repo

Edit `oss-corpus.yaml` and append an entry:

```yaml
- name: <slug>                    # unique, kebab-case
  repo_url: https://github.com/<org>/<repo>.git
  ecosystem: npm|pypi|maven|golang|cargo|gem|composer
  framework: express|django|...   # optional, surfaced in report
  ref: <tag-or-branch>            # optional but recommended for stability
  ground_truth_cves:
    - id: CVE-2024-XXXXX
      expected_reachability: confirmed|data_flow|function|module
      source: <NVD/GHSA/OSV link or advisory ID>
  expected_min_findings: 1        # soft floor; smoke check
  notes: |
    Anything a future tick should know (e.g. known gaps, clone size).
```

Then run with `--only=<slug>` first to validate before adding to the full
corpus:

```bash
npm run scan:oss-corpus -- \
  --repos=scripts/oss-corpus.yaml \
  --output=/tmp/oss-corpus-validate \
  --only=<slug>
```

## Flags

| Flag | Purpose |
|---|---|
| `--repos=<path>` | Required. YAML/JSON corpus file. |
| `--output=<dir>` | Required. Where per-repo artifacts + report.* land. |
| `--parallel=<n>` | Concurrent scans (default 2). Docker is the bottleneck — past 3 thrashes. |
| `--only=<csv>` | Restrict to a subset by `name`. |
| `--skip-clone` | Reuse existing workspace dirs under `<output>/workspaces/`. |
| `--no-rule-gen` | Disable AI rule generation. Default: on if `DEEPINFRA_API_KEY` is set. |
| `--scan-timeout=<sec>` | Per-scan wall-time cap. Default 600s. |

## Failure handling

The harness captures failure modes per-repo without aborting the run:

- `clone_failed` — `git clone` exited non-zero (network, bad ref).
- `scan_timeout` — depscanner exceeded `--scan-timeout` (default 600s).
- `scan_failed` — depscanner exited non-zero AND no `summary.json` exists.
- `skipped` — entry has a `skip:` reason in the YAML.

`report.md` lists every failure with the reason so the data is preserved.

## Ground-truth caveat

Ground-truth is intentionally toy / approximate at first. We cite NVD or
GHSA IDs inline but haven't manually verified every flow path. The harness
exists so that ground-truth accuracy can improve iteratively: as we triage
each scan, we promote/demote entries in the YAML.

Recall % is a directional metric, not a contract. A 0% recall on Sinatra
(known framework-spec gap) is expected today; the number to track is the
delta after a framework spec lands.
