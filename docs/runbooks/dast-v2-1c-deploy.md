# DAST v2.1c deploy runbook

v2.1c adds **Nuclei** as a second DAST engine alongside ZAP, plus the
runtime → SCA reachability flip. Pairs with phase25a (additive migration).

The migration is **additive** — new columns, one widened CHECK, one new RPC,
and a re-creation of `commit_extraction` / `finalize_extraction` with three
extra carry-forward columns. No destructive step; no two-phase split needed.

## Step 0 — Snapshot

Trigger a Supabase manual snapshot (or note the PITR timestamp) before
applying. Record it in the PR description.

## Step 1 — Apply the migration via MCP

`phase25a` is applied in two `apply_migration` calls (the carry-forward
function bodies are large):

```
mcp__claude_ai_Supabase__apply_migration {
  name: "phase25a_dast_v2_1c_nuclei",
  query: "<steps 1-6 of backend/database/phase25a_dast_v2_1c_nuclei.sql>"
}
mcp__claude_ai_Supabase__apply_migration {
  name: "phase25a_dast_v2_1c_carry_forward",
  query: "<the two CREATE OR REPLACE FUNCTION blocks>"
}
```

Then refresh the schema dump locally: `cd depscanner && npm run schema:dump`.

Rollback script: `backend/database/phase25a_revert.sql` (drops the RPC,
restores the narrow CHECK, re-creates the unpatched functions, drops the
additive columns).

## Step 2 — Build + deploy the depscanner image

The Nuclei binary and the SHA-pinned `nuclei-templates` corpus are baked into
the image. Rebuild and deploy the `deptex-depscanner` Fly app:

```
docker buildx build --platform linux/amd64 -t <registry>/deptex-depscanner:v2.1c depscanner/
# then fly deploy for the depscanner app
```

`buildx` is required so `TARGETARCH` populates (the Nuclei + crane installs
fail fast otherwise).

## Step 3 — Verify the image

In a shell on the running depscanner machine (`fly ssh console`):

```
nuclei -version
# expected: v3.8.0

find /opt/nuclei-templates -name '*.yaml' | wc -l
# expected: > 9000
```

## Step 4 — Smoke: a Nuclei scan against a known-vulnerable target

Stand up `vulhub/CVE-2017-12615` (Apache Tomcat PUT RCE) as a DAST target,
then trigger a scan with `engine: 'nuclei'`:

```
POST /api/projects/:projectId/dast/scan
{ "target_id": "<target>", "engine": "nuclei" }
```

Expected after the scan completes:

- A `project_dast_findings` row with `engine='nuclei'` and `kev=true`
  (CVE-2017-12615 is in the CISA KEV catalog).
- The DAST findings table renders the **Nuclei** engine chip + the KEV star.

## Step 5 — Smoke: the runtime → SCA reachability flip

On a project that has a Tomcat dependency in its SBOM with an open
`project_dependency_vulnerabilities` row for CVE-2017-12615 (reachability
below `confirmed`):

1. Run the Nuclei scan from Step 4 against that project's target.
2. The end-of-scan `confirm_pdvs_from_dast_run` batch flips the PDV row to
   `reachability_level='confirmed'` and sets `runtime_confirmed_at`.
3. The security tab shows the emerald **Runtime Confirmed** badge on that row.

```sql
SELECT osv_id, reachability_level, runtime_confirmed_at, runtime_confirmed_prior_level
FROM project_dependency_vulnerabilities
WHERE project_id = '<project>' AND osv_id ILIKE '%2017-12615%';
-- expected: reachability_level='confirmed', runtime_confirmed_at set
```

## Step 6 — Smoke: carry-forward survival

Re-run extraction on the same project. The runtime confirmation MUST survive
the new extraction generation (this is the load-bearing carry-forward fix —
PDV rows are extraction-run-scoped):

```sql
-- after re-extraction completes
SELECT reachability_level, runtime_confirmed_at
FROM project_dependency_vulnerabilities
WHERE project_id = '<project>' AND osv_id ILIKE '%2017-12615%'
  AND extraction_run_id = (SELECT active_extraction_run_id FROM projects WHERE id = '<project>');
-- expected: reachability_level still 'confirmed', runtime_confirmed_at still set
```

## Rollback / escape hatch

There is no per-org kill switch. If the runtime-confirmation false-positive
rate spikes:

1. Revert the route-level `engine='nuclei'` acceptance (one line in
   `backend/src/routes/dast.ts`) so new Nuclei scans cannot be queued.
2. `DELETE FROM project_dast_findings WHERE engine='nuclei' AND created_at > '<cutover>'`.
3. The next extraction's carry-forward drops the now-orphaned runtime
   confirmations (no Nuclei finding remains to re-confirm them).
