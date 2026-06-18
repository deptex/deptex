/**
 * Persistence layer for the taint engine. Two responsibilities:
 *
 *   1. writeFlows() — insert engine output into project_reachable_flows with
 *      reachability_source = 'taint_engine'. The classifier
 *      (updateReachabilityLevels) is source-agnostic; once flows land, the
 *      next pipeline step picks them up unchanged. Atom rows and engine
 *      rows coexist at the same coords because phase23.4's source-aware
 *      UNIQUE keys osv_id+rule_id (both NULL for engine + atom; the
 *      remaining (project_id, run_id, purl, entry_file, entry_line,
 *      sink_method) coords still vary per-flow).
 *
 *      Phase 6.5 layered three changes over this:
 *        - flow.osv_id (set by the propagator on CVE-targeted sinks) is now
 *          written into project_reachable_flows.osv_id, mirroring the
 *          existing rule_id pattern. The classifier's confirmed-tier
 *          OR-clause keys on (osv_id IS NOT NULL AND dependency_id IS NOT
 *          NULL).
 *        - flow_signature_hash is computed at write time from canonicalized
 *          (source_file:line, sink_file:line, sink_method, osv_id) so the
 *          per-flow suppression hash survives re-extractions of the same
 *          logical flow even though writeFlows wipe-and-rewrites every run.
 *        - resolveSinkDep replaces the old internal-sentinel default. Caller
 *          supplies a resolver that maps a flow to its dependency
 *          (typically: createOsvIdResolver(depsByOsvId) for CVE-tagged
 *          flows; the fallback for unmatched flows is a per-flow-unique
 *          synthetic purl + dependencyId=null so the classifier OR-clause
 *          naturally excludes them from confirmed-tier promotion). The
 *          original 'pkg:internal/taint-engine' sentinel is gone — it was
 *          dead code on every taint_engine row written today (verified at
 *          M0.1; see plan section 0.1).
 *
 *   2. writeRun() — upsert a row into taint_engine_runs that captures
 *      per-extraction telemetry. The circuit breaker reads this table to
 *      decide whether to engage the killswitch on the next extraction.
 *      Status transitions: 'running' (initial insert at step start) →
 *      'completed' | 'failed' | 'aborted' | 'skipped'.
 *
 * Both helpers swallow per-row errors to keep telemetry write failures from
 * cascading into engine hard-failures (the engine has its own failure mode
 * tracked separately in the runs table); the caller logs warnings.
 */

import { createHash } from 'crypto';
import * as path from 'path';
import * as fs from 'fs';
import type { Storage } from '../storage';
import type { Flow } from './flow';
import type { FilterTriple, TripleResult } from './fp-filter';

function isFilterTriple(v: TripleResult): v is FilterTriple {
  return v.verdict === 'kept' || v.verdict === 'rejected';
}

/**
 * Read a small window of source around `line` from `filePath` (relative to the
 * engine's workspace root — the callgraph stores `path.relative(rootDir, …)`,
 * and rootDir === workspaceRoot, so `path.join(workspaceRoot, filePath)`
 * resolves to the file on disk). Formatted to match the legacy reachability
 * code_snippet (`→ NN │ code` markers; the UI strips them and re-numbers from
 * the affected line). Best-effort: returns null on any miss so a read failure
 * never fails the scan. `cache` memoizes each file's line array so a flow set
 * sharing a file reads it once.
 */
function readFlowSnippet(
  workspaceRoot: string | undefined,
  filePath: string | null | undefined,
  line: number | null | undefined,
  cache: Map<string, string[] | null>,
  contextLines = 4,
): string | null {
  if (!workspaceRoot || !filePath || !line || !Number.isFinite(line) || line <= 0) return null;
  let lines = cache.get(filePath);
  if (lines === undefined) {
    lines = null;
    // atom-era paths were sometimes src/-relative; try that too, mirroring the
    // reachability.ts readCodeSnippet resolution.
    const candidates = [path.join(workspaceRoot, filePath), path.join(workspaceRoot, 'src', filePath)];
    for (const c of candidates) {
      try {
        if (fs.existsSync(c) && fs.statSync(c).isFile()) {
          lines = fs.readFileSync(c, 'utf8').split(/\r?\n/);
          break;
        }
      } catch { /* try the next candidate */ }
    }
    cache.set(filePath, lines);
  }
  if (!lines) return null;
  const start = Math.max(0, line - contextLines - 1);
  const end = Math.min(lines.length, line + contextLines);
  if (start >= end) return null;
  return lines.slice(start, end)
    .map((l, i) => {
      const num = start + i + 1;
      const marker = num === line ? '→' : ' ';
      return `${marker} ${num.toString().padStart(4)} │ ${l}`;
    })
    .join('\n');
}

const FLOW_BATCH_SIZE = 100;

/** Same UNIQUE key Phase 3 reachability_rules.ts upserts on. */
const REACHABLE_FLOWS_CONFLICT_KEY =
  'project_id,extraction_run_id,purl,entry_point_file,entry_point_line,sink_method,osv_id,rule_id';

export interface WriteFlowsResult {
  attempted: number;
  written: number;
  errors: string[];
}

export interface ResolvedDep {
  purl: string;
  dependencyId: string | null;
}

export interface WriteFlowsOptions {
  projectId: string;
  extractionRunId: string;
  flows: Flow[];
  /**
   * Resolver from a Flow to its owning dependency. Phase 6.5 default: callers
   * pass `createOsvIdResolver(depsByOsvId)` so CVE-tagged flows resolve to
   * the real (dependencyId, purl) for classifier confirmed-tier promotion.
   * Framework-generic flows (no osv_id) fall through to a per-flow-unique
   * synthetic purl with dependencyId=null — written so the row exists, but
   * the classifier OR-clause's `dependency_id IS NOT NULL` guard naturally
   * excludes them. Returning `null` skips the flow entirely.
   */
  resolveDep?: (flow: Flow) => ResolvedDep | null;
  /**
   * Optional per-flow AI filter verdicts (M7 → M4 triple). Embedded into the
   * flow_nodes JSONB so admins can see why a borderline flow survived (or,
   * for rejected flows, this map skips them entirely upstream and we never
   * see them here). Keyed by Flow.id.
   *
   * Phase 6.5 / M4 expands one synthetic node into THREE:
   *   - ai_filter_verdict      — keep/reject/kept_on_error/ai_truncated
   *   - ai_sanitization_verdict — is_sanitized + reasoning + sanitizer_line + confidence
   *   - ai_endpoint_verdict     — classification + reasoning
   * All carry `synthetic: true` so revert paths and frontend filters can
   * distinguish AI-generated nodes from real hops.
   *
   * Status precedence (locked, also documented at top of fp-filter.ts and
   * planned for top of epd.ts when M5 lands):
   *   'ai_truncated' > 'kept_on_error' > '_anthropic_fallback_failed' >
   *   '_anthropic_fallback_skipped_cost_cap' >
   *   '_anthropic_fallback_skipped_burn_breaker' > '_anthropic_fallback' >
   *   'flow_aggregated'
   */
  filterVerdicts?: Map<string, TripleResult>;
  /**
   * Phase 6.5 — workspace clone root, used to strip the random clone-dir
   * prefix from file paths before they're hashed into flow_signature_hash.
   * Without this, a re-extraction of the same logical flow would produce a
   * different hash on each run (clone dir is randomized) and break user
   * suppressions every time. When undefined, paths are hashed as-is and the
   * suppression-survives-re-extraction guarantee degrades — caller should
   * always pass it for production extractions.
   */
  workspaceRoot?: string;
}

/**
 * Convert engine Flow records to project_reachable_flows row shape and
 * upsert in chunks. Returns counts + per-chunk errors (not thrown).
 */
export async function writeFlows(
  storage: Storage,
  options: WriteFlowsOptions,
): Promise<WriteFlowsResult> {
  const { projectId, extractionRunId, flows, workspaceRoot } = options;
  const resolveDep = options.resolveDep ?? fallbackUnresolvedResolveDep;
  const verdicts = options.filterVerdicts;
  const errors: string[] = [];

  const rows: Record<string, unknown>[] = [];
  // Per-call cache of file line-arrays so a flow set sharing a source file
  // reads it from disk once.
  const snippetCache = new Map<string, string[] | null>();
  for (const flow of flows) {
    const dep = resolveDep(flow);
    if (!dep) continue;
    // Capture the source line + the sink call line off the clone (best-effort)
    // so the detail view can show the code without a live repo fetch. The line
    // numbers match the scanned commit.
    const entryPointCode = readFlowSnippet(workspaceRoot, flow.entry_point_file, flow.entry_point_line, snippetCache);
    const sinkCode = readFlowSnippet(workspaceRoot, flow.sink_file, flow.sink_line, snippetCache);
    // Embed AI verdict triple (M4) into the JSONB so admins can see why a
    // borderline flow survived. We append synthetic nodes rather than
    // adding top-level columns (keeps the project_reachable_flows schema
    // identical between engine + atom + reachability_rules sources). For
    // error paths (kept_on_error / ai_truncated) only the ai_filter_verdict
    // node is appended — sanitization + endpoint signals are unavailable.
    // Attach a per-hop code window to every real hop (not just the source/sink
    // ends) so the path stepper can show each step's code. Best-effort; shares
    // the same file-line cache as the entry/sink reads above.
    const hopNodesWithCode = flow.flow_nodes.map((node) => {
      const code = readFlowSnippet(workspaceRoot, node.filePath, node.line, snippetCache);
      return code ? { ...node, code } : node;
    });

    const v = verdicts?.get(flow.id);
    let flowNodesWithVerdict: unknown = hopNodesWithCode;
    if (v) {
      const appended: unknown[] = [...hopNodesWithCode];
      if (isFilterTriple(v)) {
        appended.push({
          kind: 'ai_filter_verdict',
          verdict: v.verdict,
          reasoning: v.verdict_reasoning,
          confidence: v.verdict_confidence,
          model: v.model,
          synthetic: true,
        });
        appended.push({
          kind: 'ai_sanitization_verdict',
          is_sanitized: v.sanitization.is_sanitized,
          reasoning: v.sanitization.reasoning,
          sanitizer_line: v.sanitization.sanitizer_line,
          confidence: v.sanitization.confidence,
          model: v.model,
          synthetic: true,
        });
        appended.push({
          kind: 'ai_endpoint_verdict',
          classification: v.endpoint.classification,
          reasoning: v.endpoint.reasoning,
          model: v.model,
          synthetic: true,
        });
      } else {
        // kept_on_error | ai_truncated — only the error-shaped synthetic node.
        appended.push({
          kind: 'ai_filter_verdict',
          verdict: v.verdict,
          reasoning: v.reasoning,
          error_message: v.errorMessage,
          // M5 aggregator filters on epd_status; mirror the verdict so the
          // status precedence ordering is readable from a single field.
          epd_status: v.verdict,
          synthetic: true,
        });
      }
      flowNodesWithVerdict = appended;
    }
    rows.push({
      project_id: projectId,
      extraction_run_id: extractionRunId,
      purl: dep.purl,
      dependency_id: dep.dependencyId,
      reachability_source: 'taint_engine',
      // Phase 6.5: osv_id is now populated from the matched sink (when the
      // sink came from a CVE-targeted FrameworkSpec row). Framework-generic
      // flows leave osv_id null, matching the legacy behaviour. rule_id
      // stays null — that column belongs to the Phase 3 Semgrep rule pack
      // path, which writes its own rows separately.
      osv_id: flow.osv_id ?? null,
      rule_id: null,
      // The propagator's vuln_class for this flow (sql_injection / xss / …).
      // Carried straight through so first-party flows (osv_id null) are
      // self-describing as findings — there's no CVE to borrow a title from.
      vuln_class: flow.vuln_class,
      flow_nodes: flowNodesWithVerdict,
      entry_point_file: flow.entry_point_file,
      entry_point_method: flow.entry_point_method,
      entry_point_line: flow.entry_point_line,
      // entry_point_tag feeds EPD's heuristic classifier the same way
      // reachability_rules does: framework-input:<class>. The taint engine
      // doesn't yet split by request-handler class (M5 may), so we tag all
      // engine flows with PUBLIC_UNAUTH which matches the spec's source
      // patterns (req.body etc).
      entry_point_tag: 'framework-input:PUBLIC_UNAUTH',
      entry_point_code: entryPointCode,
      sink_file: flow.sink_file,
      sink_method: flow.sink_method,
      sink_line: flow.sink_line,
      sink_code: sinkCode,
      sink_is_external: flow.sink_is_external,
      flow_length: flow.flow_length,
      llm_prompt: null,
      // Phase 6.5 — stable hash for per-flow suppression survival across
      // writeFlows wipe-and-rewrite (Patch 9 / OD-4 Option B). The hash
      // input is canonicalized so re-extractions of the same logical flow
      // re-produce the same hash even though the workspace clone path is
      // randomized.
      flow_signature_hash: computeFlowSignatureHash(flow, workspaceRoot),
    });
  }

  let written = 0;
  for (let i = 0; i < rows.length; i += FLOW_BATCH_SIZE) {
    const chunk = rows.slice(i, i + FLOW_BATCH_SIZE);
    const { error } = await storage
      .from('project_reachable_flows')
      .upsert(chunk, {
        onConflict: REACHABLE_FLOWS_CONFLICT_KEY,
        ignoreDuplicates: true,
      });
    if (error) {
      errors.push(`chunk ${Math.floor(i / FLOW_BATCH_SIZE)}: ${error.message}`);
    } else {
      written += chunk.length;
    }
  }
  return { attempted: rows.length, written, errors };
}

/**
 * Phase 6.5 — fallback resolver for flows the caller didn't supply a
 * resolveDep for, OR for flows that the caller's resolver returned null/
 * synthetic for. Produces a per-flow-unique synthetic purl built from
 * sink coords; dependencyId=null. The synthetic namespace `pkg:internal/
 * taint-engine-unresolved-<sha>` is per-flow-unique so unresolved flows
 * never collide with each other or with real SBOM purls (preserves the
 * reachability.ts join invariant that a synthetic purl never matches a
 * PDV).
 *
 * Classifier behaviour: the M5 confirmed-tier OR-clause requires
 * `dependency_id IS NOT NULL`, so unresolved-synthetic rows naturally drop
 * out of promotion. The row still exists for telemetry (admin-facing
 * "engine emitted these flows but couldn't tie them to a SBOM dep").
 */
export function fallbackUnresolvedResolveDep(flow: Flow): ResolvedDep {
  const sha = createHash('sha256')
    .update(`${flow.sink_file}:${flow.sink_line}`)
    .digest('hex')
    .slice(0, 8);
  return { purl: `pkg:internal/taint-engine-unresolved-${sha}`, dependencyId: null };
}

/**
 * Phase 6.5 — `osv_id → ResolvedDep` resolver factory. Used by pipeline.ts:
 * the caller builds `depsByOsvId` from `project_dependency_vulnerabilities`
 * + `project_dependencies` joined on this extraction's PDV rows, then wraps
 * the map in this helper before passing to writeFlows. CVE-tagged flows
 * resolve to their real (dependencyId, purl); framework-generic flows (no
 * osv_id) and CVE-tagged flows whose dep didn't make it into the map fall
 * through to fallbackUnresolvedResolveDep.
 */
export function createOsvIdResolver(
  depsByOsvId: Map<string, ResolvedDep>,
): (flow: Flow) => ResolvedDep {
  return (flow) => {
    if (flow.osv_id) {
      const hit = depsByOsvId.get(flow.osv_id);
      if (hit) return hit;
    }
    return fallbackUnresolvedResolveDep(flow);
  };
}

/**
 * Phase 6.5 — compute the stable per-flow signature hash from canonical
 * inputs. Locked canonicalization rules (Patch 9 / re-review):
 *
 *   1. Repo-relative POSIX paths — strip workspace clone-root prefix; replace
 *      backslashes with forward slashes. NO realpath / symlink resolution
 *      (could escape the workspace on Windows-with-symlink hosts).
 *   2. Lowercased ASCII — covers macOS HFS+ + Windows path case-insensitivity.
 *      Safe on Linux: customer code shouldn't have case-only-different sibling
 *      files; if it does, the hash collision is acceptable for suppression
 *      purposes.
 *   3. UTF-8 BOM stripped — defensive; shouldn't occur in repo paths.
 *   4. Integer line numbers — Math.trunc; non-finite/non-positive lines throw
 *      (programming error, not user data).
 *   5. sink_method = engine's matched callee text — `flow.sink_method` is the
 *      IR node's callee.text, NOT a model-emitted string. (parseTriple's
 *      sanitizer_line cannot be the source — that's model-emitted.)
 *   6. osv_id || '' — empty string for non-CVE-tagged flows so the hash is
 *      well-defined on framework-generic flows even though they aren't
 *      CVE-suppressible.
 *
 * Known degradation: line-shift drift. A whitespace-only commit that adds a
 * blank line above the source/sink shifts every line number by 1 → all
 * suppressions for that flow break. Acceptable in v1; future Phase 6.5b can
 * replace line numbers with structural identifiers (function-qualified-name
 * from tree-sitter usage extraction).
 */
export function computeFlowSignatureHash(flow: Flow, workspaceRoot?: string): string {
  const sourcePath = canonicalRepoPath(flow.entry_point_file, workspaceRoot);
  const sinkPath = canonicalRepoPath(flow.sink_file, workspaceRoot);
  const sourceLine = canonicalLine(flow.entry_point_line, 'entry_point_line');
  const sinkLine = canonicalLine(flow.sink_line, 'sink_line');
  const osvKey = flow.osv_id ?? '';
  const input = `${sourcePath}:${sourceLine}|${sinkPath}:${sinkLine}|${flow.sink_method}|${osvKey}`;
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Strip clone-root prefix, normalize separators, drop UTF-8 BOM, lowercase.
 * Exported so tests can lock down the canonicalization contract.
 */
export function canonicalRepoPath(filePath: string, workspaceRoot?: string): string {
  let p = filePath;
  // Drop UTF-8 BOM if it leaked into a path string (defensive).
  if (p.charCodeAt(0) === 0xfeff) p = p.slice(1);
  // Strip the workspace clone-root prefix so the random clone dir
  // (e.g. /tmp/depscanner-workspace-abc123/) doesn't drift the hash.
  if (workspaceRoot) {
    // Compare on both raw + normalized variants of the workspace root so we
    // don't miss a prefix that already had its slashes normalized upstream.
    const candidates = new Set<string>();
    candidates.add(workspaceRoot);
    candidates.add(workspaceRoot.replace(/\\/g, '/'));
    if (!workspaceRoot.endsWith('/') && !workspaceRoot.endsWith(path.sep)) {
      candidates.add(workspaceRoot + path.sep);
      candidates.add(workspaceRoot + '/');
      candidates.add(workspaceRoot.replace(/\\/g, '/') + '/');
    }
    for (const root of candidates) {
      if (p.startsWith(root)) {
        p = p.slice(root.length);
        break;
      }
    }
  }
  // Normalize separators after the prefix strip so a `\\`-form workspace
  // root prefix doesn't fail to match a `/`-form path.
  p = p.replace(/\\/g, '/');
  // Drop a leading slash so `lib/foo.js` and `/lib/foo.js` collapse — the
  // workspace strip above might leave a leading separator depending on
  // whether the root carried its trailing slash.
  if (p.startsWith('/')) p = p.slice(1);
  return p.toLowerCase();
}

function canonicalLine(line: number, field: string): number {
  if (!Number.isFinite(line) || line <= 0) {
    throw new Error(`computeFlowSignatureHash: ${field}=${line} is not a finite positive integer`);
  }
  return Math.trunc(line);
}

export type TaintEngineRunStatus = 'running' | 'completed' | 'failed' | 'aborted' | 'skipped';

export interface WriteRunOptions {
  projectId: string;
  organizationId: string;
  extractionRunId: string;
  status: TaintEngineRunStatus;
  callgraphBuildMs?: number;
  taintPropagationMs?: number;
  aiSpecInferenceMs?: number;
  aiFpFilterMs?: number;
  totalMs?: number;
  flowsEmitted?: number;
  flowsAfterAiFilter?: number;
  aiCostUsd?: number;
  frameworksDetected?: string[];
  isTypedJsProject?: boolean | null;
  typedFilesPct?: number | null;
  vulnClassesEvaluated?: string[];
  errorCode?: string | null;
  errorMessage?: string | null;
}

/**
 * Upsert the per-extraction telemetry row. Idempotent on
 * (project_id, extraction_run_id) so the pipeline can write 'running'
 * at step start and 'completed'/'failed' on exit without dance.
 */
export async function writeRun(
  storage: Storage,
  options: WriteRunOptions,
): Promise<{ ok: boolean; error?: string }> {
  const isTerminal = options.status !== 'running';
  const row: Record<string, unknown> = {
    project_id: options.projectId,
    organization_id: options.organizationId,
    extraction_run_id: options.extractionRunId,
    status: options.status,
    callgraph_build_ms: options.callgraphBuildMs ?? null,
    taint_propagation_ms: options.taintPropagationMs ?? null,
    ai_spec_inference_ms: options.aiSpecInferenceMs ?? null,
    ai_fp_filter_ms: options.aiFpFilterMs ?? null,
    total_ms: options.totalMs ?? null,
    flows_emitted: options.flowsEmitted ?? 0,
    flows_after_ai_filter: options.flowsAfterAiFilter ?? 0,
    ai_cost_usd: options.aiCostUsd ?? 0,
    frameworks_detected: options.frameworksDetected ?? [],
    is_typed_js_project: options.isTypedJsProject ?? null,
    typed_files_pct: options.typedFilesPct ?? null,
    vuln_classes_evaluated: options.vulnClassesEvaluated ?? [],
    error_code: options.errorCode ?? null,
    error_message: options.errorMessage ?? null,
    completed_at: isTerminal ? new Date().toISOString() : null,
  };
  const { error } = await storage
    .from('taint_engine_runs')
    .upsert(row, { onConflict: 'project_id,extraction_run_id' });
  if (error) return { ok: false, error: error.message };
  return { ok: true };
}
