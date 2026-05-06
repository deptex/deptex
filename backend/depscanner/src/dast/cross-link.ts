// SCA cross-link: resolve a DAST finding's endpoint_url to a (handler_file,
// handler_function, handler_line) tuple by matching against
// project_entry_points.route_pattern, then look up the same handler in
// project_reachable_flows to surface the linked OSV ID.
//
// Carved out of pipeline.ts during the v2.1a rewrite — pipeline now owns
// orchestration; this file owns the link-resolution algorithm.

import type { Storage } from '../storage';
import { matchRoute } from './route-matcher';
import type { DastFindingRaw } from './runner';

export interface EntryPointRow {
  framework: string;
  http_method: string | null;
  route_pattern: string | null;
  handler_name: string | null;
  file_path: string;
  line_number: number;
}

export interface ReachableFlowRow {
  entry_point_file: string | null;
  entry_point_method: string | null;
  purl: string;
  dependency_id: string | null;
}

export interface PdvRow {
  id: string;
  project_dependency_id: string;
  osv_id: string;
}

export interface ProjectDependencyRow {
  id: string;
  dependency_id: string;
  purl: string;
}

export interface CrossLinkInput {
  finding: DastFindingRaw;
  entryPoints: EntryPointRow[];
  flows: ReachableFlowRow[];
  pdvByPurl: Map<string, PdvRow[]>;
  projectDependencyByPurl: Map<string, ProjectDependencyRow>;
}

export interface CrossLinkOutput {
  handler_file_path: string | null;
  handler_function_name: string | null;
  handler_line: number | null;
  linked_sca_osv_id: string | null;
  linked_sca_project_dependency_id: string | null;
  cross_link_metadata: Record<string, unknown>;
}

export function crossLinkFinding(input: CrossLinkInput): CrossLinkOutput {
  const { finding, entryPoints, flows, pdvByPurl, projectDependencyByPurl } = input;

  let matchedEp: EntryPointRow | null = null;
  for (const ep of entryPoints) {
    if (!ep.route_pattern) continue;
    if (ep.http_method && ep.http_method.toUpperCase() !== finding.http_method.toUpperCase()) continue;
    if (matchRoute(finding.endpoint_url, ep.route_pattern, ep.framework)) {
      matchedEp = ep;
      break;
    }
  }

  if (!matchedEp) {
    return {
      handler_file_path: null,
      handler_function_name: null,
      handler_line: null,
      linked_sca_osv_id: null,
      linked_sca_project_dependency_id: null,
      cross_link_metadata: { match_method: 'none' },
    };
  }

  const matchedFlow = flows.find(
    (f) =>
      f.entry_point_file === matchedEp!.file_path &&
      (matchedEp!.handler_name == null || f.entry_point_method === matchedEp!.handler_name),
  );

  if (!matchedFlow) {
    return {
      handler_file_path: matchedEp.file_path,
      handler_function_name: matchedEp.handler_name,
      handler_line: matchedEp.line_number,
      linked_sca_osv_id: null,
      linked_sca_project_dependency_id: null,
      cross_link_metadata: { match_method: 'route_only', framework: matchedEp.framework },
    };
  }

  const pdvs = pdvByPurl.get(matchedFlow.purl) ?? [];
  if (pdvs.length === 0) {
    return {
      handler_file_path: matchedEp.file_path,
      handler_function_name: matchedEp.handler_name,
      handler_line: matchedEp.line_number,
      linked_sca_osv_id: null,
      linked_sca_project_dependency_id: null,
      cross_link_metadata: {
        match_method: 'route_and_flow_no_vuln',
        framework: matchedEp.framework,
        purl: matchedFlow.purl,
      },
    };
  }

  const SEVERITY_ORDER: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  pdvs.sort(
    (a: PdvRow & { severity?: string }, b: PdvRow & { severity?: string }) =>
      (SEVERITY_ORDER[b.severity ?? 'info'] ?? 0) - (SEVERITY_ORDER[a.severity ?? 'info'] ?? 0),
  );

  const projectDep = projectDependencyByPurl.get(matchedFlow.purl);
  return {
    handler_file_path: matchedEp.file_path,
    handler_function_name: matchedEp.handler_name,
    handler_line: matchedEp.line_number,
    linked_sca_osv_id: pdvs[0].osv_id,
    linked_sca_project_dependency_id: projectDep?.id ?? null,
    cross_link_metadata: {
      match_method: 'route_flow_vuln',
      framework: matchedEp.framework,
      purl: matchedFlow.purl,
      sca_candidates: pdvs.length,
    },
  };
}

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

export async function getActiveExtractionRunId(
  supabase: Storage,
  projectId: string,
): Promise<string | null> {
  const { data, error } = await supabase
    .from('projects')
    .select('active_extraction_run_id')
    .eq('id', projectId)
    .single();
  if (error || !data) return null;
  return (data as { active_extraction_run_id: string | null }).active_extraction_run_id ?? null;
}

export async function loadEntryPoints(
  supabase: Storage,
  projectId: string,
  extractionRunId: string,
): Promise<EntryPointRow[]> {
  const { data, error } = await supabase
    .from('project_entry_points')
    .select('framework, http_method, route_pattern, handler_name, file_path, line_number')
    .eq('project_id', projectId)
    .eq('extraction_run_id', extractionRunId);
  if (error || !data) return [];
  return data as EntryPointRow[];
}

export async function loadReachableFlows(
  supabase: Storage,
  projectId: string,
  extractionRunId: string,
): Promise<ReachableFlowRow[]> {
  const { data, error } = await supabase
    .from('project_reachable_flows')
    .select('entry_point_file, entry_point_method, purl, dependency_id')
    .eq('project_id', projectId)
    .eq('extraction_run_id', extractionRunId);
  if (error || !data) return [];
  return data as ReachableFlowRow[];
}

export async function loadPdvsForProject(
  supabase: Storage,
  projectId: string,
): Promise<{
  pdvByPurl: Map<string, PdvRow[]>;
  projectDependencyByPurl: Map<string, ProjectDependencyRow>;
}> {
  const [{ data: pdData, error: pdError }, { data: flowDepData, error: flowDepError }] =
    await Promise.all([
      supabase.from('project_dependencies').select('id, dependency_id').eq('project_id', projectId),
      supabase
        .from('project_reachable_flows')
        .select('purl, dependency_id')
        .eq('project_id', projectId),
    ]);
  if (pdError || !pdData || flowDepError || !flowDepData) {
    return { pdvByPurl: new Map(), projectDependencyByPurl: new Map() };
  }
  const projectDeps = pdData as Array<{ id: string; dependency_id: string | null }>;
  const flowDeps = flowDepData as Array<{ purl: string | null; dependency_id: string | null }>;

  if (projectDeps.length === 0) {
    return { pdvByPurl: new Map(), projectDependencyByPurl: new Map() };
  }

  const pdByDepId = new Map<string, { id: string; dependency_id: string }>();
  for (const pd of projectDeps) {
    if (pd.dependency_id) pdByDepId.set(pd.dependency_id, { id: pd.id, dependency_id: pd.dependency_id });
  }

  const projectDependencyByPurl = new Map<string, ProjectDependencyRow>();
  for (const f of flowDeps) {
    if (!f.purl || !f.dependency_id) continue;
    if (projectDependencyByPurl.has(f.purl)) continue;
    const pd = pdByDepId.get(f.dependency_id);
    if (pd) projectDependencyByPurl.set(f.purl, { id: pd.id, dependency_id: pd.dependency_id, purl: f.purl });
  }

  const pdIds = projectDeps.map((p) => p.id);
  const { data: pdvData, error: pdvError } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('id, project_dependency_id, osv_id, severity')
    .in('project_dependency_id', pdIds);
  if (pdvError || !pdvData) {
    return { pdvByPurl: new Map(), projectDependencyByPurl };
  }

  const pdIdToPurl = new Map<string, string>();
  for (const [purl, pd] of projectDependencyByPurl) pdIdToPurl.set(pd.id, purl);

  const pdvByPurl = new Map<string, PdvRow[]>();
  for (const pdv of pdvData as Array<PdvRow & { severity?: string }>) {
    const purl = pdIdToPurl.get(pdv.project_dependency_id);
    if (!purl) continue;
    const list = pdvByPurl.get(purl) ?? [];
    list.push(pdv);
    pdvByPurl.set(purl, list);
  }

  return { pdvByPurl, projectDependencyByPurl };
}
