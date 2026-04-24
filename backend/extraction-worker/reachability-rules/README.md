# Deptex reachability rules

Hand-authored Semgrep taint-tracking rules that upgrade matching vulnerabilities
to `confirmed` reachability — the highest-priority signal in the depscore
pipeline.

When the extraction pipeline detects a CVE in a project's dependencies, the
reachability-rules engine looks up the rule pack for that CVE (if any) and
runs Semgrep against the project source. A taint match means the user's code
actually wires an attacker-controlled source into the vulnerable sink, not
just that the vulnerable library is installed.

## Layout

```
reachability-rules/
├── README.md                              ← this file
├── CVE-YYYY-NNNNN-<short-slug>/
│   ├── rule.yml                           ← native Semgrep YAML, mode: taint
│   └── __fixtures__/
│       ├── vulnerable.<ext>               ← must match
│       └── safe.<ext>                     ← must NOT match
└── ...
```

One folder per CVE. The folder name is `CVE-<year>-<id>-<short-slug>` —
the slug helps humans recognise the rule at a glance (`lodash-template`,
`log4shell`, etc.).

## Required `metadata` fields

The loader (`src/reachability-rules.ts`) validates these and skips any rule
file missing them:

| Field | Used by |
|---|---|
| `cve` | Rule selection — only rules whose `cve` matches a vulnerability detected in the run get executed. |
| `package` | Cross-check that the dep firing the rule is actually the package the rule targets. |
| `ecosystem` | Sanity check (e.g. `npm` rules don't run against Maven coordinates). |
| `affected_versions` | Display only — the version range is already enforced by OSV/dep-scan. |
| `confidence` | Informational — taint matches always upgrade to `confirmed`. |
| `cwe` | Propagates to finding metadata. Recommended but not required. |
| `references` | Recommended — at least one OSV / GHSA / NVD link. |

## Fixture conventions

Each rule ships with a vulnerable + safe pair. The test runner asserts:

- `vulnerable.<ext>` produces **at least one** finding from the rule.
- `safe.<ext>` produces **zero** findings from the rule.

Keep fixtures minimal:

- One source location, one sink location, ~10–15 lines.
- The safe fixture should differ from the vulnerable one in exactly one
  meaningful way (e.g. fixed template string, sanitizer call, non-tainted
  source). Anything else is noise that makes test failures harder to read.

## Rule IDs

Use the convention `deptex.<package-short>.<slug>` (e.g. `deptex.lodash.template-injection`,
`deptex.log4j.log4shell`). The invoker loads every rule into a single Semgrep
config dir per run, so rule IDs **must be unique across the whole library** —
`runReachabilityRules` enforces this up front with a clear error rather than
letting Semgrep fail later.

## Authoring gotchas

- **Quote brace-shaped patterns.** Semgrep patterns that contain `{ ... }` —
  e.g. `axios.request({ url: $URL, ... })` or `&ssh.ClientConfig{User: $SRC, ...}` —
  must be wrapped in quotes. Unquoted, YAML parses them as flow-style maps
  and rejects the file; the loader then skips the whole rule pack with
  `YAML parse failed`. When in doubt, quote.
- **One rule per `rules:` array.** The loader rejects rule files that
  declare more than one rule. Split multi-mode rules into separate
  CVE-folder subdirs so `metadata.cve` selection stays 1:1 with files.
- **Metadata is load-bearing.** `cve`, `package`, and `ecosystem` are the
  only required fields; rules missing any of them are silently skipped at
  load time. The test harness will *not* tell you the rule didn't fire —
  it was never loaded. Run the validator (below) to be sure.

## Adding a new rule

1. Pick a CVE that's already detected by OSV (otherwise the rule will never
   fire — rule selection pre-filters by detected CVEs).
2. Read the advisory + the patch diff to identify the exact vulnerable sink.
3. Create `CVE-YYYY-NNNNN-<slug>/rule.yml` using one of the existing rules
   as a template.
4. Write `__fixtures__/vulnerable.<ext>` and `__fixtures__/safe.<ext>`.
5. Run the bundled validator to prove the loader accepts the new pack:

   ```bash
   cd backend/extraction-worker
   npx tsx scripts/validate-reachability-rules.ts
   ```

   You should see your CVE listed with the rule id, package, ecosystem,
   and confidence. Any YAML/metadata problem surfaces here.

6. If `semgrep` is on PATH locally, verify the rule matches the right
   fixture:

   ```bash
   semgrep --validate --config reachability-rules/CVE-YYYY-NNNNN-<slug>/rule.yml
   semgrep --config reachability-rules/CVE-YYYY-NNNNN-<slug>/rule.yml \
           reachability-rules/CVE-YYYY-NNNNN-<slug>/__fixtures__/
   ```

   Vulnerable should produce >=1 finding; safe should produce 0.

7. Run the Jest suite — the live-Semgrep block auto-runs in CI/Docker, so a
   rule that loads but fails its own fixture will be caught there:

   ```bash
   cd backend
   npm test -- --testPathPatterns=reachability-rules
   ```

8. If you're changing level-classification behaviour (vs. just adding a
   rule), also run the PGLite end-to-end smoke:

   ```bash
   cd backend/extraction-worker
   npm run test:reachability-rules-e2e
   ```

   It seeds a project + dep + two PDVs, writes one atom flow and one
   semgrep-taint flow, then runs `updateReachabilityLevels` against a real
   Postgres-shaped store and asserts the taint PDV lands on `confirmed`
   while the unrelated PDV falls through to `data_flow`.

## How rule selection works

The pipeline calls `selectRulesForCves(allRules, detectedCveSet)`. Only rules
whose `metadata.cve` is in the detected set get loaded into the temp Semgrep
config dir for the run. This means:

- A project with no detected CVEs runs zero reachability rules (free).
- A project that imports `lodash@4.17.20` triggers `CVE-2021-23337` rule only.
- The rule library can grow to 100+ entries without slowing scans on small
  projects — only matched rules ever execute.

## How taint matches flow through the pipeline

1. `runReachabilityRules` invokes Semgrep with `--dataflow-traces`.
2. Each finding is normalised into a `TaintFinding` (source loc, sink loc,
   intermediate steps, rule id, CVE).
3. The pipeline writes one `project_reachable_flows` row per finding with
   `reachability_source = 'semgrep_taint'`, `osv_id = <CVE>`, `rule_id = <semgrep id>`.
4. `updateReachabilityLevels()` reads these flows. For any PDV whose
   `(dependency_id, osv_id)` matches a taint flow, the level is set to
   `confirmed` (highest priority — trumps `data_flow`/`function`/`module`).

The atom-derived `data_flow` signal still applies for vulns *without* a
hand-authored rule — they fall through to the existing classification ladder.
