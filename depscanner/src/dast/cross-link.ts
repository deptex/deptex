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
  // Phase 35 (v1.1 OpenAPI synthesis): optional fields the synthesizer reads
  // when building OpenAPI 3.1 ops + the x-deptex-handler sidecar. Optional
  // so existing call sites + mock fixtures stay green; the SELECT in
  // loadEntryPoints widens to pull them.
  entry_point_type?: string;
  classification?: string;
  auth_mechanism?: string | null;
  middleware_chain?: string[] | null;
  metadata?: Record<string, unknown> | null;
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

/**
 * Per-operation handler attribution emitted by the OpenAPI synthesizer
 * alongside the YAML. Keys are `${METHOD} ${openApiPath}` (e.g.
 * "GET /users/{id}"); values point at the handler `(file, function, line)`.
 *
 * v1.1: only the synthesis path produces this. URL-imported specs fall back
 * to today's regex matchRoute.
 */
export interface HandlerSidecarEntry {
  file_path: string;
  function_name: string | null;
  line_number: number;
}
export type HandlerSidecar = Record<string, HandlerSidecarEntry>;

export interface CrossLinkInput {
  finding: DastFindingRaw;
  entryPoints: EntryPointRow[];
  flows: ReachableFlowRow[];
  pdvByPurl: Map<string, PdvRow[]>;
  projectDependencyByPurl: Map<string, ProjectDependencyRow>;
  /**
   * Phase 35 (v1.1 OpenAPI synthesis): pre-pass attribution for findings on
   * synthesized-spec scans. When provided, a deterministic (method, path)
   * lookup runs BEFORE the framework-specific regex match — eliminating the
   * URL-encoding / trailing-slash false-negative class. Falls back to regex
   * when the sidecar key isn't found (case 4 of the test matrix: sidecar
   * stale because handler moved).
   */
  sidecar?: HandlerSidecar;
}

export interface CrossLinkOutput {
  handler_file_path: string | null;
  handler_function_name: string | null;
  handler_line: number | null;
  linked_sca_osv_id: string | null;
  linked_sca_project_dependency_id: string | null;
  cross_link_metadata: Record<string, unknown>;
}

// OpenAPI `{param}` path-template → regex. Used by the sidecar matcher to
// turn keys like "GET /users/{id}/posts/{postId}" into a check against
// ZAP's concrete request path. Trailing slash is tolerated (some ZAP
// shapes normalize differently). Static paths skip the regex entirely.
function openApiPathToRegex(openApiPath: string): RegExp {
  const escaped = openApiPath
    // Escape regex specials EXCEPT braces (we want {param} to be replaceable).
    .replace(/[.+?^$()|[\]\\]/g, '\\$&')
    // {paramName} → [^/]+
    .replace(/\{[^}]+\}/g, '[^/]+');
  return new RegExp('^' + escaped + '/?$');
}

function urlToPath(endpointUrl: string): string | null {
  try {
    return new URL(endpointUrl).pathname;
  } catch {
    return endpointUrl.startsWith('/') ? endpointUrl.split(/[?#]/)[0] : null;
  }
}

function matchSidecar(
  endpointUrl: string,
  httpMethod: string,
  sidecar: HandlerSidecar,
): HandlerSidecarEntry | null {
  const path = urlToPath(endpointUrl);
  if (!path) return null;
  const method = httpMethod.toUpperCase();
  for (const [key, entry] of Object.entries(sidecar)) {
    const sp = key.indexOf(' ');
    if (sp <= 0) continue;
    const keyMethod = key.slice(0, sp).toUpperCase();
    if (keyMethod !== method) continue;
    const keyPath = key.slice(sp + 1);
    // Fast path: exact match (static OpenAPI paths).
    if (keyPath === path) return entry;
    // {param}-aware regex match.
    if (openApiPathToRegex(keyPath).test(path)) return entry;
  }
  return null;
}

export function crossLinkFinding(input: CrossLinkInput): CrossLinkOutput {
  const { finding, entryPoints, flows, pdvByPurl, projectDependencyByPurl, sidecar } = input;

  // Phase 35 (v1.1) — sidecar pre-pass. Synthesized-spec scans get
  // deterministic handler attribution via the OpenAPI sidecar. Stale
  // sidecar (handler moved/renamed since synthesis) falls through to the
  // regex matcher below — the test matrix's case 4.
  if (sidecar) {
    const hit = matchSidecar(finding.endpoint_url, finding.http_method, sidecar);
    if (hit) {
      // Stale-detection: if the sidecar handler's file_path is NOT in the
      // current entryPoints set, treat it as stale and fall through to the
      // regex matcher. The synthesizer keyed the sidecar at scan-build time;
      // if the source has moved since, regex on live entry_points beats
      // a dangling file path.
      const stillExists = entryPoints.some(
        (ep) => ep.file_path === hit.file_path,
      );
      if (stillExists) {
        return {
          handler_file_path: hit.file_path,
          handler_function_name: hit.function_name,
          handler_line: hit.line_number,
          linked_sca_osv_id: null,
          linked_sca_project_dependency_id: null,
          cross_link_metadata: { match_method: 'sidecar', via: 'sidecar' },
        };
      }
    }
  }

  let matchedEp: EntryPointRow | null = null;
  for (const ep of entryPoints) {
    if (!ep.route_pattern) continue;
    if (ep.http_method && ep.http_method.toUpperCase() !== finding.http_method.toUpperCase()) continue;
    if (matchRoute(finding.endpoint_url, ep.route_pattern, ep.framework)) {
      matchedEp = ep;
      break;
    }
  }

  // `via` tags the lookup mechanism for telemetry: 'sidecar' returns above;
  // every other branch uses regex matchRoute and reports 'regex_fallback'.
  const via = sidecar ? 'regex_fallback' : 'regex';

  if (!matchedEp) {
    return {
      handler_file_path: null,
      handler_function_name: null,
      handler_line: null,
      linked_sca_osv_id: null,
      linked_sca_project_dependency_id: null,
      cross_link_metadata: { match_method: 'none', via },
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
      cross_link_metadata: { match_method: 'route_only', framework: matchedEp.framework, via },
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
        via,
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
      via,
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
    .select(
      'framework, http_method, route_pattern, handler_name, file_path, line_number, entry_point_type, classification, auth_mechanism, middleware_chain, metadata',
    )
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
