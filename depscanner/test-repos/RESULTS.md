# Dogfood Corpus — RESULTS

Per-fixture rolling table. Update the row when a fixture's walkthrough lands.

Legend:
- `scan_passed`: extraction job finished without crash/timeout.
- `harness_passed`: `npm run dogfood:check --fixture <name>` exits 0.
- `findings_matched`: every expected `osv_id` / `rule_id` / `secret_id` /
  IaC misconfig appears in the actual findings, alias-aware. Extras are
  categorized below (allowed-extra / add-annotation / false-positive).
- `dast_har_captured`: `.deptex/dast-baseline.har` committed for server-side
  fixtures (n/a for SPA-only fixtures).
- `bugs_found`: count of scanner / pipeline / UI bugs found via this fixture
  that landed as separate fixes in the same arc.
- `walkthrough_date`: UTC date of the latest successful walkthrough.

| Framework | scan_passed | harness_passed | findings_matched | dast_har_captured | bugs_found | walkthrough_date | notes |
|---|---|---|---|---|---|---|---|
| express | — | — | — | — | — | — | — |
| nextjs | — | — | — | — | — | — | — |
| react | — | — | — | n/a | — | — | — |
| django | — | — | — | — | — | — | — |
| fastapi | — | — | — | — | — | — | — |
| flask | — | — | — | — | — | — | — |
| spring-boot | — | — | — | — | — | — | — |
| gin-gonic | — | — | — | — | — | — | — |
| axum | — | — | — | — | — | — | — |
| rails | — | — | — | — | — | — | — |
| laravel | — | — | — | — | — | — | — |
| aspnet | — | — | — | — | — | — | — |

## Per-fixture performance snapshots

| Framework | scan_duration | dogfood_check_duration | ai_cost_usd |
|---|---|---|---|
| express | — | — | — |
| nextjs | — | — | — |
| ... | — | — | — |

Performance gates per fixture (from the plan):
- scan_duration: 2-15 min ok; >20 min is a bug.
- ai_cost_usd: <$0.50 ok; >$5 is a bug.

## Extras / drift log

When the harness sees an *extra* finding that's not in `expected.yaml`, it
passes (subset semantics) but the extra is logged here for human triage.

| Date | Fixture | Category | OSV / rule | Verdict | Action |
|---|---|---|---|---|---|

Verdicts: `add-annotation` (real, missed in expected.yaml — update the file),
`false-positive` (scanner over-reports — file in dogfood-bug-backlog.md),
`allowed-extra` (e.g. a new CVE published between scan and walkthrough,
captured in M6 OSV alias refresh).
