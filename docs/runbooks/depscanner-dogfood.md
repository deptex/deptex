# Depscanner Dogfood — Walkthrough Runbook

Per-fixture manual walkthrough that exercises Deptex's real
create-project + scan + findings + DAST flow against
`depscanner/test-repos/<framework>/`. The harness
(`npm run dogfood:check`) provides the executable cross-batch gate, but
the walkthrough is what catches UI bugs and pipeline regressions the
harness can't see.

## Prerequisites

- **Existing `deptex` prod org** with admin access. We don't spin up a
  dedicated test org — fixtures live in the production org under a
  dedicated team for isolation.
- **`Vulnerable Projects` team** inside the `deptex` org. Henry creates
  this manually (one-time) via Org Settings → Teams → New Team before any
  fixture walkthrough.
- `sync_frequency=manual` setting available on the connected-repo settings
  page (existing surface).
- DAST HAR import working (PR #52, merged main `b8b3162`) — needed for
  step (f) on every server-side fixture.

## Walkthrough — per fixture

Per the plan, every fixture follows the same shape. Estimate ~30-45 min
per server-side fixture (most of that is DAST + HAR capture).

### (a) Confirm fixture exists

The fixture directory must exist under `depscanner/test-repos/<framework>/`
with an `.deptex/expected.yaml`. Greenfield fixtures also need a
`.deptex/SOURCE.md` noting "greenfield"; copies record the upstream
taint-engine fixture SHA.

### (b) Create the project in Deptex UI

In `deptex` prod org:

1. Switch into `Vulnerable Projects` team.
2. Create Project → name = `dogfood-<framework>` (e.g. `dogfood-express`).
3. Connect to the `deptex/deptex` GitHub repository.
4. **Set `package_json_path` to the fixture's relative path**
   (e.g. `depscanner/test-repos/express`). This pins the project to the
   sub-path; the worker scans only that directory.
5. **Set `sync_frequency=manual`** on the connected repo's Settings →
   Sync page. This prevents the fixture from re-scanning on every push to
   `deptex/deptex` (which would fan out 13 simultaneous extractions).

### (c) Wait for scan

Watch the extraction logs in the UI. A successful scan takes 2-15 minutes;
>20 minutes is a bug.

Note the `project_id` (UUID) for use in (g).

### (d) Walk per-tab UI checklist

Open the project in the UI and confirm each scan category surfaced its
expected findings:

- **Findings tab** (`OrganizationFindingsPage.tsx`, PR #55) — vulnerable
  dependencies appear with the expected reachability classification
  (confirmed / data_flow / function / module / unreachable).
- **IaC tab** — Checkov + Trivy findings on Dockerfile / k8s.yaml.
- **Container tab** — base-image CVEs from the fixture's `FROM` line.
- **Secrets tab** — TruffleHog finds the seeded test key in
  `.env.example`.
- **Semgrep tab** — SAST rules fire on intentional taint flows.
- **Malicious tab** — historical-malicious package names flagged.

### (e) Manual DAST trigger (server-side fixtures only)

For every server-side fixture:

1. Run `.deptex/deploy.sh` locally (or in a sandbox host). The script
   boots the fixture on `4000 + alphabetical-index`
   (express=4001, fastapi=4002, …).
2. In the Deptex UI, navigate to DAST → New Scan, point at the local URL,
   trigger the scan.
3. Confirm DAST findings appear under the project.

### (f) Capture DAST baseline HAR (one-time per server-side fixture)

The HAR baseline makes DAST regression testable without re-deploying the
fixture every time:

1. After the DAST scan completes, use the DAST UI's "Export HAR" feature
   (PR #52 surface).
2. Save the file as `depscanner/test-repos/<framework>/.deptex/dast-baseline.har`
   and commit it in the same batch PR.
3. Future runs can re-import this HAR via the HAR-import endpoint to
   verify DAST output is stable without spinning up the deploy script.

### (g) Run the harness

```bash
cd depscanner
npm run dogfood:check -- --fixture <framework> --project-id <uuid-from-step-c>
```

The harness will:
- Read `depscanner/test-repos/<framework>/.deptex/expected.yaml`.
- Query Supabase directly (service-role key) for the project's findings.
- Compare expected vs actual, alias-aware, with bucket/subset semantics
  (see schema below).
- Exit 0 on PASS, non-zero on FAIL with a per-category diff.

If the harness reports a missing finding:
- Check whether the OSV alias rotated (see "drift handling" below).
- If the scanner is missing the finding, file in
  `docs/dogfood-bug-backlog.md` and iterate.
- If the expected.yaml drifted from the OSV index, update it and re-run.

### (h) Fill RESULTS.md

Update the fixture's row in `depscanner/test-repos/RESULTS.md` with:
- `scan_passed`, `harness_passed`, `findings_matched`, `dast_har_captured`
- `bugs_found` count (anything filed as a scanner bug in the same arc)
- `walkthrough_date` (UTC)
- Performance snapshot in the secondary table.

## `expected.yaml` schema

The harness's contract. Every fixture's `.deptex/expected.yaml` follows
this shape — categories absent for a given fixture are simply omitted.

```yaml
# Per-fixture expected findings. The harness asserts every entry below
# is matched by the actual findings (alias-aware, bucket-tolerant).
# Extras in the actual findings are allowed; they're logged for triage
# in RESULTS.md but don't fail the harness.

reachable_vulns:
  - osv_id: CVE-2021-23337
    # OSV identifiers alias across registries (GHSA, CVE, GO, RUSTSEC, …).
    # The harness will match against EITHER `osv_id` OR any `aliases` entry.
    aliases: [GHSA-35jh-r3h4-6jhm]
    # File + line are informational (carried into RESULTS.md, not asserted).
    file: server.js
    line: 12
    # Bucket-tolerant: `reachable` accepts {confirmed, data_flow, function};
    # `unreachable` accepts {module, unreachable}. If a finding flickers
    # across the bucket boundary, set this to `any` for that fixture's row.
    reachability_bucket: reachable

unreachable_vulns:
  - osv_id: CVE-2020-28500
    aliases: [GHSA-29mw-wpgm-hmr9]
    reachability_bucket: unreachable

iac_findings:
  # rule_id is the Checkov / Trivy canonical id.
  - rule_id: CKV_DOCKER_3
    file: Dockerfile
    line: 5

container_cves:
  - osv_id: CVE-XXXX-YYYY
    aliases: [GHSA-...]
    base_image: node:14.0

secrets:
  - rule_id: aws-secret-key
    file: .env.example
    line: 3

malicious_pkg:
  # Historical / unpublished — see .github/dependabot.yml exclusion in repo root.
  - package: <historical-name>
    ecosystem: npm
    note: historical-not-published

semgrep_findings:
  - rule_id: javascript.express.security.injection.tainted-sql-string
    file: routes/api.js
    line: 18

dast_findings:
  # Only populated for fixtures with a deploy.sh. Each entry is one passive-
  # or active-scan alert ZAP / Nuclei is expected to surface.
  - alert: Reflected XSS
    url_pattern: /search?q=
```

### Match semantics

- **Subset, not 1:1** — actual findings ⊇ expected findings. Extras in the
  actual set are categorized in RESULTS.md's "Extras / drift log" but don't
  fail the harness.
- **Alias-aware** — when matching `osv_id`, the harness accepts any value
  in the entry's `aliases` array as equivalent. Necessary because OSV
  publishes the same vuln under both `CVE-…` and `GHSA-…` ids and the
  primary identifier rotates over time.
- **Bucket-tolerant reachability** — `reachability_bucket: reachable`
  matches if the actual finding's reachability level is in
  `{confirmed, data_flow, function}`; `unreachable` matches
  `{module, unreachable}`. The DeepInfra Qwen non-determinism captured in
  `feedback_deepinfra_qwen_nondeterministic` makes strict 1:1
  reachability assertions flaky.

### Drift handling

Findings that disappear between batches usually mean either
(a) the OSV publisher rotated the alias chain, or
(b) a real scanner regression.

The decision tree (run in M6.3 of the plan):

1. Re-query the OSV API for the CVE. If the canonical `id` rotated,
   update `aliases:` in expected.yaml + note in RESULTS.md as
   `allowed-extra` for the drift run.
2. If OSV still lists the CVE for this version and the scanner missed it,
   file in `docs/dogfood-bug-backlog.md` as a real bug and iterate.

## Aegis interaction

Aegis context loaders see `depscanner/test-repos/` like any other code in
the repo. Aegis-triggered PRs against these fixtures are acceptable and
sometimes instructive (they exercise the Aegis Fix Agent on real
seeded vulns), but **do not auto-merge them** — the seeds are intentional
and the fixes would invalidate the corpus.

## Stop conditions

If you hit any of these, stop and file a P0:

| Symptom | Likely cause |
|---|---|
| Scan exceeds 20 minutes | Worker hang / scanner timeout regression |
| Scan completes but Findings tab is empty for a fixture with reachable vulns in expected.yaml | Findings pipeline regression OR write-path bug |
| DAST scan returns zero findings on a fixture with seeded XSS / SQLi | DAST engine regression (check ZAP / Nuclei dispatch) |
| Harness reports a missing alias that OSV still confirms exists for the pinned version | Scanner identifier-handling bug (likely cve_alias resolver) |
| Harness exits 0 but Findings tab UI shows no findings | DB → API → UI plumbing bug — file even if harness is green |
