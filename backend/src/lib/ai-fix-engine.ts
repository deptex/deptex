import { supabase } from '../lib/supabase';
import { getActiveExtractionId, NO_ACTIVE_RUN } from './active-extraction';

// The legacy aider-worker orchestrator (requestFix / cancelFixJob / status
// queries) was retired with the aider-worker itself. The new flow lives in
// lib/aegis-v3/fix-planner.ts (planning) and fix-worker (execution).
// Only the context-gathering helpers below remain — they're consumed by
// the planner to build its prompt.

export type FixStrategy =
  | 'bump_version'
  | 'code_patch'
  | 'add_wrapper'
  | 'pin_transitive'
  | 'remove_unused'
  | 'fix_semgrep'
  | 'remediate_secret';

export type FixType = 'vulnerability' | 'semgrep' | 'secret';

export interface FixRequest {
  projectId: string;
  organizationId: string;
  userId: string;
  strategy: FixStrategy;
  vulnerabilityOsvId?: string;
  dependencyId?: string;
  projectDependencyId?: string;
  targetVersion?: string;
  semgrepFindingId?: string;
  secretFindingId?: string;
}

export async function gatherVulnerabilityContext(req: FixRequest): Promise<Record<string, any>> {
  // Fetch the project dependency, dependency, and vulnerability records
  // the planner needs to reason about a fix. Mirrors the shape the legacy
  // aider-worker expected so the planner prompt has equivalent data.

  let projectDependency: any = null;
  let dependency: any = null;

  if (req.projectDependencyId) {
    const { data: pd } = await supabase
      .from('project_dependencies')
      .select('id, project_id, dependency_id, version, is_dev, depth, manifest_path')
      .eq('id', req.projectDependencyId)
      .single();
    projectDependency = pd;
  }

  if (projectDependency?.dependency_id || req.dependencyId) {
    const depId = projectDependency?.dependency_id ?? req.dependencyId;
    const { data: dep } = await supabase
      .from('dependencies')
      .select('id, name, ecosystem, latest_version')
      .eq('id', depId)
      .single();
    dependency = dep;
  }

  // Vuln metadata lives in dependency_vulnerabilities, keyed on
  // (dependency_id, osv_id) — the same OSV can affect multiple deps so we
  // scope by dependency when we know it. Falls back to "first match by
  // osv_id" when the dependency wasn't resolvable, which is fine for the
  // planner prompt (severity/summary/fixed_versions are repo-level facts).
  let vulnerability: any = null;
  if (req.vulnerabilityOsvId) {
    let query = supabase
      .from('dependency_vulnerabilities')
      .select(
        'osv_id, severity, summary, details, classification, fixed_versions, affected_versions, aliases, cwe_ids',
      )
      .eq('osv_id', req.vulnerabilityOsvId);
    if (dependency?.id) {
      query = query.eq('dependency_id', dependency.id);
    }
    const { data: vuln } = await query.limit(1).maybeSingle();
    vulnerability = vuln;

    // The current findings pipeline writes advisory data straight onto the
    // project's PDV rows and no longer populates dependency_vulnerabilities.
    // When the legacy row is missing, build the advisory from the PDV row so
    // the planner still sees severity + fixed_versions instead of refusing
    // with "no patched version available".
    if (!vulnerability) {
      let pdvQuery = supabase
        .from('project_dependency_findings')
        .select('osv_id, severity, summary, fixed_versions, aliases, cvss_score')
        .eq('project_id', req.projectId)
        .eq('osv_id', req.vulnerabilityOsvId);
      if (projectDependency?.id) {
        pdvQuery = pdvQuery.eq('project_dependency_id', projectDependency.id);
      }
      const { data: pdvVuln } = await pdvQuery.limit(1).maybeSingle();
      vulnerability = pdvVuln;
    }
  }

  // Reachability evidence — what we know about whether the vulnerable
  // dependency is actually exercised. Helps the planner prefer pinning
  // over global bumps.
  let reachability: any = null;
  if (projectDependency?.id && req.vulnerabilityOsvId) {
    const { data: rch } = await supabase
      .from('project_dependency_findings')
      .select('reachability_level, reachability_factor, importing_files, epd_factor')
      .eq('project_dependency_id', projectDependency.id)
      .eq('osv_id', req.vulnerabilityOsvId)
      .maybeSingle();
    reachability = rch;
  }

  return {
    projectDependency,
    dependency,
    vulnerability,
    reachability,
    targetVersion: req.targetVersion ?? null,
  };
}

export async function gatherSemgrepContext(findingId: string, projectId: string): Promise<Record<string, any>> {
  // Gate the lookup on the active extraction run to avoid leaking findings
  // from prior runs into the planner prompt (Phase 19 contract).
  const activeRunId = (await getActiveExtractionId(supabase, projectId)) ?? NO_ACTIVE_RUN;
  const { data } = await supabase
    .from('project_semgrep_findings')
    .select(
      'id, rule_id, message, severity, file_path, start_line, end_line, cwe_ids, owasp_ids, category, code_snippet',
    )
    .eq('id', findingId)
    .eq('extraction_run_id', activeRunId)
    .single();
  return data ? { semgrepFinding: data } : {};
}

export async function gatherSecretContext(findingId: string, projectId: string): Promise<Record<string, any>> {
  // Same Phase 19 contract as gatherSemgrepContext: validate the finding
  // belongs to the active extraction run before pulling code context.
  const activeRunId = (await getActiveExtractionId(supabase, projectId)) ?? NO_ACTIVE_RUN;
  const { data } = await supabase
    .from('project_secret_findings')
    .select('id, detector_type, file_path, start_line, is_verified, description, redacted_value, code_snippet')
    .eq('id', findingId)
    .eq('extraction_run_id', activeRunId)
    .single();
  return data ? { secretFinding: data } : {};
}
