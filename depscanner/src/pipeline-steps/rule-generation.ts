/**
 * STEP: AI rule generation (Phase 5).
 *
 * For each CVE in this scan that matches the org's trigger policy AND
 * doesn't already have a rule (platform or org-generated), draft +
 * validate a Semgrep rule via the platform AI key. Validated rules
 * land in organization_generated_rules and the next step
 * (taint_engine, which loads CVE-targeted FrameworkSpecs) picks them up.
 *
 * Block-and-wait by design (see plan): scans wait for generation to
 * complete. Per-CVE timeout is 90s, with overall step bounded by the
 * org's max_wait_seconds. Concurrency is p-limit(5) — generation is
 * network-bound (AI calls) so a single Fly machine handles 5 in flight
 * without blowing CPU. Failures of one CVE never block others — they
 * log to extraction_step_errors at warn and the others continue.
 *
 * Skipped silently when:
 *   - no Semgrep binary (validation requires it)
 *   - no organization_reachability_settings row OR auto_generate_enabled=false
 *   - no platform key for the org's chosen provider
 *   - no candidate CVEs after trigger filter + dedup
 */

import { runStage } from '../pipeline-stage-runner';
import { runRuleGenerationStep, type PipelineVulnRow } from '../rule-generation-step';
import { buildPurl } from '../purl';
import { binaryAvailable } from '../pipeline-helpers';
import type { PipelineContext } from '../pipeline-types';

export async function doRuleGeneration(ctx: PipelineContext): Promise<void> {
  if (!binaryAvailable('semgrep')) return;

  const { supabase, job, projectId, organizationId, log, runId } = ctx;
  await runStage({
    name: 'rule_generation',
    severity: 'warn',
    omitDuration: true,
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    onError: async ({ err }) => {
      const msg = err instanceof Error ? err.message : String(err);
      await log.warn('rule_generation', `Step failed: ${msg}`);
    },
    fn: async () => {
      const candidatesQuery = await supabase
        .from('project_dependency_vulnerabilities')
        .select('osv_id, severity, cisa_kev, reachability_level, aliases, project_dependency_id')
        .eq('project_id', projectId)
        .eq('extraction_run_id', runId);
      if (candidatesQuery.error) throw new Error(candidatesQuery.error.message);

      const pdvRows = (candidatesQuery.data ?? []) as Array<{
        osv_id: string | null;
        severity: string | null;
        cisa_kev: boolean | null;
        reachability_level: string | null;
        aliases: string[] | null;
        project_dependency_id: string | null;
      }>;

      // Resolve project_dependency_id → name + version + namespace +
      // ecosystem in a single batch so we can build purls without
      // per-vuln round trips.
      const pdIds = Array.from(new Set(pdvRows.map((r) => r.project_dependency_id).filter((x): x is string => !!x)));
      const pdMap = new Map<string, { name: string; version: string | null; namespace: string | null; dependency_id: string | null }>();
      if (pdIds.length > 0) {
        const { data: pdRows } = await supabase
          .from('project_dependencies')
          .select('id, name, version, namespace, dependency_id')
          .in('id', pdIds);
        for (const r of (pdRows ?? []) as Array<{ id: string; name: string; version: string | null; namespace: string | null; dependency_id: string | null }>) {
          pdMap.set(r.id, { name: r.name, version: r.version, namespace: r.namespace, dependency_id: r.dependency_id });
        }
      }

      const depIds = Array.from(new Set(Array.from(pdMap.values()).map((r) => r.dependency_id).filter((x): x is string => !!x)));
      const ecoMap = new Map<string, string>();
      if (depIds.length > 0) {
        const { data: depRows } = await supabase
          .from('dependencies')
          .select('id, ecosystem')
          .in('id', depIds);
        for (const r of (depRows ?? []) as Array<{ id: string; ecosystem: string }>) {
          ecoMap.set(r.id, r.ecosystem);
        }
      }

      const pipelineVulns: PipelineVulnRow[] = pdvRows.map((r) => {
        const pd = r.project_dependency_id ? pdMap.get(r.project_dependency_id) : undefined;
        const eco = pd?.dependency_id ? ecoMap.get(pd.dependency_id) ?? null : null;
        const purl = pd && eco ? buildPurl(eco, pd.name, pd.version) : null;
        return {
          osv_id: r.osv_id,
          aliases: r.aliases,
          severity: r.severity,
          cisa_kev: r.cisa_kev,
          reachability_level: r.reachability_level,
          ecosystem: eco,
          package_purl: purl,
          package_name: pd?.name ?? null,
        };
      });

      await runRuleGenerationStep(
        {
          organizationId,
          projectId,
          runId,
          jobId: job.jobId,
          supabase,
          log,
        },
        pipelineVulns,
      );
    },
  });
}
