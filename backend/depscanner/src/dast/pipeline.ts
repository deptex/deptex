// Phase 23b PR 3: DAST pipeline. Owns the full lifecycle of a DAST scan from a
// claimed scan_jobs row → ZAP run → cross-link to SCA findings → atomic-commit
// of project_dast_findings.
//
// Stable-identity cross-link (v1: SCA only):
//   1. For each ZAP finding, normalize endpoint_url against
//      project_entry_points.route_pattern via lib/route-matcher.ts
//   2. Match populates handler_file_path / handler_function_name / handler_line
//   3. Join project_reachable_flows on
//      (entry_point_file = handler_file_path AND entry_point_method = handler_function_name)
//   4. From flow.purl + flow.dependency_id we look up
//      project_dependency_vulnerabilities to produce linked_sca_osv_id +
//      linked_sca_project_dependency_id.
//
// SAST cross-link is deferred to v2 (project_semgrep_findings doesn't yet
// store containing_function_name).

import { randomUUID } from 'crypto';
import type { Storage } from '../storage';
import type { ExtractionJobRow } from '../job-db';
import { matchRoute } from './route-matcher';
import { runZap, type DastFindingRaw, type DastEntryPointInput, type DastScanProfile } from './runner';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DastJobPayload {
  // Mirrored from scan_jobs columns into payload at queue time so the worker
  // doesn't need a per-type column read. queue_scan_job populates these.
  target_url?: string;
  scan_profile?: DastScanProfile;
  scan_timeout_minutes?: number;
}

interface EntryPointRow {
  framework: string;
  http_method: string | null;
  route_pattern: string | null;
  handler_name: string | null;
  file_path: string;
  line_number: number;
}

interface ReachableFlowRow {
  entry_point_file: string | null;
  entry_point_method: string | null;
  purl: string;
  dependency_id: string | null;
}

interface PdvRow {
  id: string;
  project_dependency_id: string;
  osv_id: string;
}

interface ProjectDependencyRow {
  id: string;
  // dependency_id keeps us from having to round-trip the dependencies table
  // when matching reachable_flows.dependency_id back to project_dependencies.
  dependency_id: string;
  purl: string;
}

interface DastFindingInsert {
  project_id: string;
  organization_id: string;
  dast_run_id: string;
  endpoint_url: string;
  http_method: string;
  vulnerability_type: string;
  severity: DastFindingRaw['severity'];
  cwe_id: string | null;
  owasp_top10_ref: string | null;
  rule_id: string | null;
  message: string | null;
  payload_redacted: string | null;
  response_evidence_redacted: string | null;
  confidence: DastFindingRaw['confidence'];
  handler_file_path: string | null;
  handler_function_name: string | null;
  handler_line: number | null;
  linked_sca_osv_id: string | null;
  linked_sca_project_dependency_id: string | null;
  cross_link_metadata: Record<string, unknown>;
  status: 'open';
}

export interface RunDastPipelineOptions {
  // Allow tests to inject a runZap stub.
  runZapImpl?: typeof runZap;
}

export interface DastPipelineResult {
  dast_run_id: string;
  findings_count: number;
  duration_seconds: number;
  cross_linked_count: number;
}

// ---------------------------------------------------------------------------
// Cross-link
// ---------------------------------------------------------------------------

interface CrossLinkInput {
  finding: DastFindingRaw;
  entryPoints: EntryPointRow[];
  flows: ReachableFlowRow[];
  pdvByPurl: Map<string, PdvRow[]>;
  projectDependencyByPurl: Map<string, ProjectDependencyRow>;
}

interface CrossLinkOutput {
  handler_file_path: string | null;
  handler_function_name: string | null;
  handler_line: number | null;
  linked_sca_osv_id: string | null;
  linked_sca_project_dependency_id: string | null;
  cross_link_metadata: Record<string, unknown>;
}

/**
 * Resolve a DAST finding's endpoint_url to a (handler_file, handler_function,
 * handler_line) tuple by matching against project_entry_points.route_pattern.
 * Then look up the same handler in project_reachable_flows to find a vulnerable
 * dep, and surface the SCA OSV ID + project_dependency_id pair.
 *
 * On no match, returns nulls and `cross_link_metadata.match_method = 'none'`.
 * Failures here are non-fatal — DAST findings without a cross-link still ship.
 */
export function crossLinkFinding(input: CrossLinkInput): CrossLinkOutput {
  const { finding, entryPoints, flows, pdvByPurl, projectDependencyByPurl } = input;

  // Try each entry point. First HTTP-method-and-path match wins; on tie within
  // that, the first one we iterate. Future iterations can rank by classifier
  // (PUBLIC_UNAUTH > AUTH_INTERNAL etc.) but v1 keeps it simple.
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

  // Now JOIN project_reachable_flows on (entry_point_file = file_path AND
  // entry_point_method = handler_name). The flow tells us which dep is
  // reachable from this handler.
  const matchedFlow = flows.find(
    (f) =>
      f.entry_point_file === matchedEp!.file_path &&
      (matchedEp!.handler_name == null || f.entry_point_method === matchedEp!.handler_name)
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

  // Pick the first vulnerability for this dep.
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

  // Severity-rank PDVs so the linked finding surfaces the worst one.
  const SEVERITY_ORDER: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  pdvs.sort((a: any, b: any) => (SEVERITY_ORDER[b.severity ?? 'info'] ?? 0) - (SEVERITY_ORDER[a.severity ?? 'info'] ?? 0));

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
// DB helpers (scoped to this module — kept thin to make pipeline-level tests
// possible by injecting a Storage stub)
// ---------------------------------------------------------------------------

async function getActiveExtractionRunId(supabase: Storage, projectId: string): Promise<string | null> {
  const { data, error } = await supabase
    .from('projects')
    .select('active_extraction_run_id')
    .eq('id', projectId)
    .single();
  if (error || !data) return null;
  return (data as { active_extraction_run_id: string | null }).active_extraction_run_id ?? null;
}

async function loadEntryPoints(
  supabase: Storage,
  projectId: string,
  extractionRunId: string
): Promise<EntryPointRow[]> {
  const { data, error } = await supabase
    .from('project_entry_points')
    .select('framework, http_method, route_pattern, handler_name, file_path, line_number')
    .eq('project_id', projectId)
    .eq('extraction_run_id', extractionRunId);
  if (error || !data) return [];
  return data as EntryPointRow[];
}

async function loadReachableFlows(
  supabase: Storage,
  projectId: string,
  extractionRunId: string
): Promise<ReachableFlowRow[]> {
  const { data, error } = await supabase
    .from('project_reachable_flows')
    .select('entry_point_file, entry_point_method, purl, dependency_id')
    .eq('project_id', projectId)
    .eq('extraction_run_id', extractionRunId);
  if (error || !data) return [];
  return data as ReachableFlowRow[];
}

async function loadPdvsForProject(
  supabase: Storage,
  projectId: string
): Promise<{ pdvByPurl: Map<string, PdvRow[]>; projectDependencyByPurl: Map<string, ProjectDependencyRow> }> {
  // First fetch project_dependencies → purl mapping.
  const { data: pdData, error: pdError } = await supabase
    .from('project_dependencies')
    .select('id, dependency_id, purl')
    .eq('project_id', projectId);
  if (pdError || !pdData) {
    return { pdvByPurl: new Map(), projectDependencyByPurl: new Map() };
  }
  const projectDeps = pdData as ProjectDependencyRow[];

  const projectDependencyByPurl = new Map<string, ProjectDependencyRow>();
  for (const pd of projectDeps) projectDependencyByPurl.set(pd.purl, pd);

  if (projectDeps.length === 0) {
    return { pdvByPurl: new Map(), projectDependencyByPurl };
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
  for (const pd of projectDeps) pdIdToPurl.set(pd.id, pd.purl);

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

async function insertFindings(
  supabase: Storage,
  rows: DastFindingInsert[]
): Promise<void> {
  if (rows.length === 0) return;
  const CHUNK_SIZE = 200;
  for (let i = 0; i < rows.length; i += CHUNK_SIZE) {
    const chunk = rows.slice(i, i + CHUNK_SIZE);
    const { error } = await supabase.from('project_dast_findings').insert(chunk);
    if (error) {
      throw new Error(`Failed to insert DAST findings (batch ${i / CHUNK_SIZE}): ${error.message}`);
    }
  }
}

async function commitDastRun(
  supabase: Storage,
  projectId: string,
  dastRunId: string
): Promise<void> {
  const { error } = await supabase.rpc('commit_dast_run', {
    p_project_id: projectId,
    p_dast_run_id: dastRunId,
  });
  if (error) {
    throw new Error(`commit_dast_run failed: ${error.message}`);
  }
}

async function finalizeJob(
  supabase: Storage,
  jobId: string,
  findingsCount: number,
  durationSeconds: number
): Promise<void> {
  const { error } = await supabase
    .from('scan_jobs')
    .update({
      status: 'completed',
      findings_count: findingsCount,
      duration_seconds: durationSeconds,
      completed_at: new Date().toISOString(),
    })
    .eq('id', jobId);
  if (error) {
    throw new Error(`Failed to finalize DAST scan_jobs row: ${error.message}`);
  }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export async function runDastPipeline(
  job: ExtractionJobRow,
  supabase: Storage,
  options: RunDastPipelineOptions = {}
): Promise<DastPipelineResult> {
  const startedAt = Date.now();
  const tag = `[dast-${job.id}]`;
  const payload = job.payload as DastJobPayload;

  const targetUrl = payload.target_url;
  const scanProfile = payload.scan_profile ?? 'auto';
  const timeoutMinutes = payload.scan_timeout_minutes ?? 30;
  if (!targetUrl) {
    throw new Error('DAST job payload missing target_url');
  }

  console.log(`${tag} Starting DAST pipeline: ${scanProfile} profile against ${targetUrl}`);

  // Cross-link prerequisites — we read entry points + flows from the LAST
  // committed extraction. If extraction has never run, we skip cross-link with
  // a clear log line and ship findings without handler metadata.
  const extractionRunId = await getActiveExtractionRunId(supabase, job.project_id);
  let entryPoints: EntryPointRow[] = [];
  let flows: ReachableFlowRow[] = [];
  let pdvByPurl = new Map<string, PdvRow[]>();
  let projectDependencyByPurl = new Map<string, ProjectDependencyRow>();

  if (!extractionRunId) {
    console.warn(`${tag} No active_extraction_run_id on project ${job.project_id} — skipping cross-link`);
  } else {
    [entryPoints, flows, { pdvByPurl, projectDependencyByPurl }] = await Promise.all([
      loadEntryPoints(supabase, job.project_id, extractionRunId),
      loadReachableFlows(supabase, job.project_id, extractionRunId),
      loadPdvsForProject(supabase, job.project_id),
    ]);
    console.log(
      `${tag} Loaded ${entryPoints.length} entry_points, ${flows.length} flows, ${pdvByPurl.size} pdv-purls for cross-link`
    );
  }

  // Run ZAP. spawn-based, never blocks the event loop, heartbeat survives.
  const runZapImpl = options.runZapImpl ?? runZap;
  const zapInputs: DastEntryPointInput[] = entryPoints.map((ep) => ({
    framework: ep.framework,
    http_method: ep.http_method,
    route_pattern: ep.route_pattern,
    handler_name: ep.handler_name,
  }));
  const zapResult = await runZapImpl({
    targetUrl,
    scanProfile,
    routes: zapInputs,
    timeoutMs: timeoutMinutes * 60_000,
  });
  console.log(
    `${tag} ZAP ${zapResult.scriptUsed} returned ${zapResult.findings.length} findings in ${zapResult.durationMs}ms`
  );

  // Cross-link.
  const dastRunId = `dast_${randomUUID()}`;
  let crossLinkedCount = 0;
  const inserts: DastFindingInsert[] = zapResult.findings.map((f) => {
    const link = crossLinkFinding({
      finding: f,
      entryPoints,
      flows,
      pdvByPurl,
      projectDependencyByPurl,
    });
    if (link.linked_sca_osv_id) crossLinkedCount++;
    return {
      project_id: job.project_id,
      organization_id: job.organization_id,
      dast_run_id: dastRunId,
      endpoint_url: f.endpoint_url,
      http_method: f.http_method,
      vulnerability_type: f.vulnerability_type,
      severity: f.severity,
      cwe_id: f.cwe_id,
      owasp_top10_ref: f.owasp_top10_ref,
      rule_id: f.rule_id,
      message: f.message,
      payload_redacted: f.payload_redacted,
      response_evidence_redacted: f.response_evidence_redacted,
      confidence: f.confidence,
      handler_file_path: link.handler_file_path,
      handler_function_name: link.handler_function_name,
      handler_line: link.handler_line,
      linked_sca_osv_id: link.linked_sca_osv_id,
      linked_sca_project_dependency_id: link.linked_sca_project_dependency_id,
      cross_link_metadata: link.cross_link_metadata,
      status: 'open',
    };
  });
  console.log(`${tag} Cross-linked ${crossLinkedCount} of ${inserts.length} findings to SCA`);

  await insertFindings(supabase, inserts);

  // Atomic pointer flip — visibility gated by projects.active_dast_run_id.
  await commitDastRun(supabase, job.project_id, dastRunId);

  const durationSeconds = Math.round((Date.now() - startedAt) / 1000);
  await finalizeJob(supabase, job.id, inserts.length, durationSeconds);

  console.log(`${tag} DAST scan completed: ${inserts.length} findings, ${durationSeconds}s`);

  return {
    dast_run_id: dastRunId,
    findings_count: inserts.length,
    duration_seconds: durationSeconds,
    cross_linked_count: crossLinkedCount,
  };
}
