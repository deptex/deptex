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
  | 'remediate_secret'
  | 'fix_iac'
  | 'bump_base_image'
  | 'sanitize_dataflow'
  | 'patch_handler';

export type FixType =
  | 'vulnerability'
  | 'semgrep'
  | 'secret'
  | 'iac'
  | 'container'
  | 'base_image'
  | 'dataflow'
  | 'dast';

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
        .from('project_dependency_vulnerabilities')
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
      .from('project_dependency_vulnerabilities')
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

// IaC misconfiguration (checkov / trivy). Structurally like a semgrep finding:
// a single file:line + rule + snippet the planner points a minimal edit at. The
// `framework` field (terraform / kubernetes / dockerfile / helm / …) tells the
// planner which syntax it's editing — and dockerfile-hardening rules land here.
export async function gatherIacContext(findingId: string, projectId: string): Promise<Record<string, any>> {
  const activeRunId = (await getActiveExtractionId(supabase, projectId)) ?? NO_ACTIVE_RUN;
  const { data } = await supabase
    .from('project_iac_findings')
    .select(
      'id, rule_id, framework, scanner, file_path, start_line, end_line, severity, message, description, cwe_ids, code_snippet, rule_doc_url',
    )
    .eq('id', findingId)
    .eq('extraction_run_id', activeRunId)
    .single();
  return data ? { iacFinding: data } : {};
}

// Container OS-package CVE. You can't patch an OS package baked into an image
// from app code, so the honest fix is to move the base image. We pull the
// matching base-image recommendation (by Dockerfile, when we can find one) so
// the planner has a concrete target image. `image_source` decides feasibility:
// `dockerfile_base` = we own the FROM line and can bump it; `configured_image`
// = a pre-built registry image, not fixable from this repo (planner refuses).
export async function gatherContainerContext(findingId: string, projectId: string): Promise<Record<string, any>> {
  const activeRunId = (await getActiveExtractionId(supabase, projectId)) ?? NO_ACTIVE_RUN;
  const { data: containerFinding } = await supabase
    .from('project_container_findings')
    .select(
      'id, image_reference, image_source, image_digest, os_package_name, os_package_version, os_package_ecosystem, osv_id, cve_id, severity, fix_versions, layer_digest, description',
    )
    .eq('id', findingId)
    .eq('extraction_run_id', activeRunId)
    .single();
  if (!containerFinding) return {};

  // Find a curated base-image recommendation for the same image so the planner
  // has a concrete `FROM` target. Match on the current image reference.
  const { data: recs } = await supabase
    .from('project_base_image_recommendations')
    .select(
      'dockerfile_path, current_image, recommended_image, recommended_image_cve_count, cve_delta, alternatives, shell_compat_verdict, drop_in_score',
    )
    .eq('project_id', projectId)
    .eq('extraction_run_id', activeRunId);
  const ref = String(containerFinding.image_reference ?? '');
  const baseImageRecommendation =
    (recs ?? []).find((r: any) => ref && String(r.current_image ?? '').split('@')[0] === ref.split('@')[0]) ??
    (recs ?? [])[0] ??
    null;

  return { containerFinding, baseImageRecommendation };
}

// Base-image recommendation. The fix is a deterministic `FROM` bump in the named
// Dockerfile — the worker does that without the LLM. We surface the shell-compat
// verdict so the planner refuses rather than hand back a broken (shell-less)
// image when the Dockerfile needs a shell.
export async function gatherBaseImageContext(recId: string, projectId: string): Promise<Record<string, any>> {
  const activeRunId = (await getActiveExtractionId(supabase, projectId)) ?? NO_ACTIVE_RUN;
  const { data } = await supabase
    .from('project_base_image_recommendations')
    .select(
      'id, dockerfile_path, current_image, current_image_cve_count, recommended_image, recommended_image_cve_count, cve_delta, alternatives, shell_compat_verdict, shell_compat_evidence, drop_in_score',
    )
    .eq('id', recId)
    .eq('extraction_run_id', activeRunId)
    .single();
  return data ? { baseImageRecommendation: data } : {};
}

// Reachable taint flow ("dataflow"). The row carries the exact ordered
// source→sink hop path (flow_nodes: {filePath,line,column,label,kind}) plus the
// entry-point and sink code windows and the vuln_class. That's what the worker
// explores to place a sanitizer. Keyed by the project_reachable_flows row id.
export async function gatherDataflowContext(flowId: string, projectId: string): Promise<Record<string, any>> {
  const activeRunId = (await getActiveExtractionId(supabase, projectId)) ?? NO_ACTIVE_RUN;
  const { data } = await supabase
    .from('project_reachable_flows')
    .select(
      'id, purl, vuln_class, osv_id, entry_point_file, entry_point_line, entry_point_method, entry_point_code, sink_file, sink_line, sink_method, sink_code, flow_nodes, reachability_source, flow_signature_hash',
    )
    .eq('id', flowId)
    .eq('extraction_run_id', activeRunId)
    .single();
  return data ? { dataflowFinding: data } : {};
}

// DAST finding. Endpoint-centric, not extraction-run scoped (keyed by
// dast_run_id), so we look it up by id alone. It already names the handler
// (handler_file_path:handler_line + handler_function_name) and the
// vulnerability_type, which the worker uses to locate and patch the handler.
export async function gatherDastContext(findingId: string, _projectId: string): Promise<Record<string, any>> {
  const { data } = await supabase
    .from('project_dast_findings')
    .select(
      'id, endpoint_url, http_method, vulnerability_type, severity, cwe_id, owasp_top10_ref, rule_id, message, confidence, handler_file_path, handler_function_name, handler_line, handler_code_snippet, cross_link_metadata',
    )
    .eq('id', findingId)
    .single();
  return data ? { dastFinding: data } : {};
}
