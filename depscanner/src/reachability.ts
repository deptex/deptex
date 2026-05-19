/**
 * Phase 6B: Reachability engine -- parse atom/dep-scan deep analysis output,
 * store reachable flows & usage slices, update reachability levels on vulnerabilities.
 */

import * as fs from 'fs';
import * as path from 'path';
import { Readable } from 'stream';
import type { Storage } from './storage';
import { parsePurl, resolvePurlToDependencyId } from './purl';

interface LogLike {
  info(step: string, msg: string): Promise<void>;
  warn(step: string, msg: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Streaming JSON parser for large reachables files (>50MB)
// ---------------------------------------------------------------------------

async function streamParseJsonArray(filePath: string): Promise<any[]> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const streamJson = require('stream-json');
  const streamArray = require('stream-json/streamers/StreamArray').streamArray;

  return new Promise((resolve, reject) => {
    const items: any[] = [];
    const stream = fs.createReadStream(filePath)
      .pipe(streamJson.parser())
      .pipe(streamArray());

    stream.on('data', ({ value }: { value: any }) => {
      items.push(value);
    });
    stream.on('end', () => resolve(items));
    stream.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// Parse reachable flows from *-reachables.slices.json
// ---------------------------------------------------------------------------

export async function parseReachableFlows(
  reportsDir: string,
  projectId: string,
  runId: string,
  supabase: Storage,
  logger: LogLike,
): Promise<void> {
  const reachableFiles = fs.readdirSync(reportsDir)
    .filter(f => f.endsWith('-reachables.slices.json'));

  if (reachableFiles.length === 0) {
    await logger.info('reachability', 'No reachable slices found — skipping deep reachability');
    return;
  }

  let totalFlows = 0;
  let skippedFlows = 0;
  let unmatchedPurls = 0;

  for (const rf of reachableFiles) {
    const filePath = path.join(reportsDir, rf);
    const fileSize = fs.statSync(filePath).size;

    let slices: any[];
    if (fileSize > 50 * 1024 * 1024) {
      try {
        slices = await streamParseJsonArray(filePath);
      } catch (err: any) {
        await logger.warn('reachability', `Failed to stream-parse ${rf}: ${err.message}. Skipping.`);
        continue;
      }
    } else {
      try {
        slices = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      } catch (err: any) {
        await logger.warn('reachability', `Failed to parse ${rf}: ${err.message}. Skipping.`);
        continue;
      }
    }

    if (!Array.isArray(slices)) {
      await logger.warn('reachability', `${rf} is not an array. Skipping.`);
      continue;
    }

    const batch: any[] = [];

    for (const slice of slices) {
      if (!slice.flows?.length || !slice.purls?.length) {
        skippedFlows++;
        continue;
      }
      if (slice.flows.length < 2) {
        await logger.warn('reachability', `Skipping flow with ${slice.flows.length} node(s) — need >= 2`);
        skippedFlows++;
        continue;
      }

      const firstNode = slice.flows[0];
      const lastNode = slice.flows[slice.flows.length - 1];

      for (const purl of slice.purls) {
        if (!purl || typeof purl !== 'string') continue;
        const parsed = parsePurl(purl);
        let dependencyId: string | null = null;
        if (parsed) {
          dependencyId = await resolvePurlToDependencyId(supabase, parsed);
          if (!dependencyId) {
            unmatchedPurls++;
          }
        }

        batch.push({
          project_id: projectId,
          extraction_run_id: runId,
          purl,
          dependency_id: dependencyId,
          flow_nodes: slice.flows,
          entry_point_file: firstNode.parentFileName ?? null,
          entry_point_method: firstNode.parentMethodName ?? null,
          entry_point_line: firstNode.lineNumber ?? null,
          entry_point_tag: firstNode.tags || null,
          sink_file: lastNode.parentFileName ?? null,
          sink_method: lastNode.fullName || lastNode.name || null,
          sink_line: lastNode.lineNumber ?? null,
          sink_is_external: lastNode.isExternal ?? true,
          flow_length: slice.flows.length,
          llm_prompt: null,
        });
        totalFlows++;
      }
    }

    for (let i = 0; i < batch.length; i += 100) {
      const chunk = batch.slice(i, i + 100);
      // Must match phase23.4's source-aware UNIQUE exactly. Atom rows carry
      // NULL osv_id / NULL rule_id; under NULLS NOT DISTINCT they dedup on
      // coords alone, which preserves the original atom-vs-atom semantics.
      await supabase.from('project_reachable_flows').upsert(chunk, {
        onConflict: 'project_id,extraction_run_id,purl,entry_point_file,entry_point_line,sink_method,osv_id,rule_id',
      });
    }
  }

  await logger.info('reachability', `Parsed ${totalFlows} reachable flows (${skippedFlows} skipped, ${unmatchedPurls} unmatched PURLs)`);
}

// ---------------------------------------------------------------------------
// Parse usage slices from *-usages.slices.json
// ---------------------------------------------------------------------------

export async function parseUsageSlices(
  reportsDir: string,
  projectId: string,
  runId: string,
  ecosystem: string,
  supabase: Storage,
  logger: LogLike,
): Promise<void> {
  const usageFiles = fs.readdirSync(reportsDir)
    .filter(f => f.endsWith('-usages.slices.json'));

  if (usageFiles.length === 0) {
    await logger.info('reachability', 'No usage slices found — skipping usage analysis');
    return;
  }

  let totalUsages = 0;

  for (const uf of usageFiles) {
    const filePath = path.join(reportsDir, uf);
    let content: any;
    try {
      content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (err: any) {
      await logger.warn('reachability', `Failed to parse ${uf}: ${err.message}. Skipping.`);
      continue;
    }

    const batch: any[] = [];

    const objectSlices = content?.objectSlices;
    if (Array.isArray(objectSlices)) {
      for (const objSlice of objectSlices) {
        const fileName = objSlice.fileName ?? null;
        const containingMethod = objSlice.fullName ?? null;

        if (!Array.isArray(objSlice.usages)) continue;

        for (const usage of objSlice.usages) {
          const targetObj = usage.targetObj;
          if (!targetObj) continue;

          const targetName = targetObj.name ?? 'unknown';
          const lineNumber = targetObj.lineNumber ?? objSlice.lineNumber ?? 0;
          const targetType = targetObj.typeFullName ?? null;
          const usageLabel = targetObj.label ?? null;

          let resolvedMethod: string | null = null;
          if (Array.isArray(usage.invokedCalls) && usage.invokedCalls.length > 0) {
            resolvedMethod = usage.invokedCalls[0].resolvedMethod ?? null;
          }

          if (fileName && lineNumber > 0) {
            batch.push({
              project_id: projectId,
              extraction_run_id: runId,
              file_path: fileName,
              line_number: lineNumber,
              containing_method: containingMethod,
              target_name: targetName,
              target_type: targetType,
              resolved_method: resolvedMethod,
              usage_label: usageLabel,
              ecosystem,
            });
            totalUsages++;
          }
        }
      }
    }

    const userDefinedTypes = content?.userDefinedTypes;
    if (Array.isArray(userDefinedTypes)) {
      for (const udt of userDefinedTypes) {
        if (!Array.isArray(udt.procedures)) continue;
        for (const proc of udt.procedures) {
          if (!proc.callName || !proc.lineNumber) continue;
          batch.push({
            project_id: projectId,
            extraction_run_id: runId,
            file_path: udt.fileName ?? 'unknown',
            line_number: proc.lineNumber,
            containing_method: null,
            target_name: proc.callName,
            target_type: udt.name ?? null,
            resolved_method: `${udt.name ?? ''}.${proc.callName}`,
            usage_label: 'userDefinedType',
            ecosystem,
          });
          totalUsages++;
        }
      }
    }

    for (let i = 0; i < batch.length; i += 100) {
      const chunk = batch.slice(i, i + 100);
      await supabase.from('project_usage_slices').upsert(chunk, {
        onConflict: 'project_id,file_path,line_number,target_name,extraction_run_id',
      });
    }
  }

  // parsed usage slices (no user-facing log)
}

// ---------------------------------------------------------------------------
// Parse LLM prompts and attach to reachable flows
// ---------------------------------------------------------------------------

export async function parseLlmPrompts(
  reportsDir: string,
  projectId: string,
  runId: string,
  supabase: Storage,
  logger: LogLike,
): Promise<void> {
  const promptFiles = fs.readdirSync(reportsDir)
    .filter(f => f.endsWith('.explain.json') || f.endsWith('-llm-prompts.json') || f.endsWith('.prompts.json'));

  if (promptFiles.length === 0) {
    // LLMPrompts may be embedded in other output files — check for explanation fields
    const explainFiles = fs.readdirSync(reportsDir)
      .filter(f => f.endsWith('.json') && !f.endsWith('.slices.json') && !f.endsWith('.vdr.json'));

    for (const ef of explainFiles) {
      try {
        const content = JSON.parse(fs.readFileSync(path.join(reportsDir, ef), 'utf8'));
        if (!content?.explanations && !content?.prompts && !Array.isArray(content)) continue;

        const prompts: Array<{ purl?: string; entry_file?: string; entry_line?: number; prompt?: string }> =
          content.explanations ?? content.prompts ?? (Array.isArray(content) ? content : []);

        await matchPromptsToFlows(prompts, projectId, runId, supabase);
      } catch { /* skip non-parseable files */ }
    }
    return;
  }

  let totalPrompts = 0;

  for (const pf of promptFiles) {
    try {
      const content = JSON.parse(fs.readFileSync(path.join(reportsDir, pf), 'utf8'));
      const prompts: any[] = Array.isArray(content) ? content : (content.prompts ?? content.explanations ?? []);

      totalPrompts += await matchPromptsToFlows(prompts, projectId, runId, supabase);
    } catch (err: any) {
      await logger.warn('reachability', `Failed to parse LLM prompts from ${pf}: ${err.message}`);
    }
  }

  if (totalPrompts > 0) {
    await logger.info('reachability', `Matched ${totalPrompts} LLM prompts to reachable flows`);
  }
}

async function matchPromptsToFlows(
  prompts: any[],
  projectId: string,
  runId: string,
  supabase: Storage,
): Promise<number> {
  let matched = 0;

  for (const p of prompts) {
    if (!p) continue;
    const promptText = p.prompt ?? p.text ?? p.explanation ?? (typeof p === 'string' ? p : null);
    if (!promptText) continue;

    const purl = p.purl ?? p.package_url ?? null;
    const entryFile = p.entry_file ?? p.entryPoint?.file ?? null;
    const entryLine = p.entry_line ?? p.entryPoint?.line ?? null;

    let query = supabase
      .from('project_reachable_flows')
      .update({ llm_prompt: promptText })
      .eq('project_id', projectId)
      .eq('extraction_run_id', runId);

    if (purl) query = query.eq('purl', purl);
    if (entryFile) query = query.eq('entry_point_file', entryFile);
    if (entryLine) query = query.eq('entry_point_line', entryLine);

    const { data: updated } = await query.select('id').limit(1);
    if (updated && updated.length > 0) matched++;
  }

  return matched;
}

// ---------------------------------------------------------------------------
// Update reachability levels on project_dependency_vulnerabilities
// ---------------------------------------------------------------------------

/**
 * Read a snippet of source code around a given line number.
 * Returns ~5 lines before and ~5 lines after for context.
 */
function readCodeSnippet(workspaceRoot: string, filePath: string, lineNumber: number, contextLines: number = 5): string | null {
  if (!workspaceRoot || !filePath || !lineNumber) return null;
  // Try multiple path resolutions (atom may return paths relative to src/ or workspace root)
  const candidates = [
    path.join(workspaceRoot, filePath),
    path.join(workspaceRoot, 'src', filePath),
  ];
  let fullPath: string | null = null;
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) {
      fullPath = c;
      break;
    }
  }
  if (!fullPath) return null;

  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    const lines = content.split(/\r?\n/);
    const startLine = Math.max(0, lineNumber - contextLines - 1);
    const endLine = Math.min(lines.length, lineNumber + contextLines);
    const snippet = lines.slice(startLine, endLine)
      .map((line, i) => {
        const num = startLine + i + 1;
        const marker = num === lineNumber ? '→' : ' ';
        return `${marker} ${num.toString().padStart(4)} │ ${line}`;
      })
      .join('\n');
    return snippet;
  } catch {
    return null;
  }
}

export interface UpdateReachabilityOptions {
  /**
   * Phase 6.5 — set of CVE ids whose FrameworkSpec actually loaded for this
   * extraction (the keys of `cveSpecResult.specs[].sinks[].osv_id`). When a
   * `taint_engine` flow's `osv_id` is NOT in this set, we treat it as data
   * drift (CHECK disabled, dual-read window, manual SQL) and demote the
   * promotion to `data_flow` instead of `confirmed`. Mismatches log a
   * `osv_id_drift_rejected` security event.
   *
   * Optional: when undefined we skip the drift check entirely so legacy
   * callers (CLI tests, snapshot harness) keep working — the M5 confirmed
   * tier still promotes, just without the defense-in-depth guard.
   */
  validOsvIds?: Set<string>;
  /** Organization id for audit-log writes when an `osv_id_drift_rejected` event fires. */
  organizationId?: string;
  /**
   * Whether the tree-sitter usage-extraction step produced output for this
   * run (ctx.astParsedSuccessfully). When false the absence of usage slices
   * is NOT evidence of unreachability — extraction crashed/timed-out — so the
   * classifier must never collapse a PDV to `unreachable`; it floors at
   * `module` instead. Defaults to true so legacy callers keep prior behavior.
   */
  astParsedSuccessfully?: boolean;
  /**
   * Whether the direct/transitive split on `project_dependencies` is
   * trustworthy (ctx.graphTrusted). False when cdxgen returned an unwired
   * dependency graph AND graph recovery couldn't rebuild the direct set — in
   * that case `is_direct` is meaningless, so the `unreachable` verdict (which
   * keys on `!is_direct`) would hide real vulns. When false the classifier
   * floors at `module`. Defaults to true so legacy callers keep prior behavior.
   */
  graphTrusted?: boolean;
  /**
   * osv_id → the vulnerable call patterns of every CVE-targeted FrameworkSpec
   * sink that loaded this run (from the taint-engine step). When a PDV's
   * osv_id has an entry, the classifier verifies whether the CVE's *specific*
   * vulnerable symbol is on a call path — rather than the weaker "package name
   * appears somewhere" heuristic. Absent / empty for legacy callers and for
   * CVEs with no generated spec, which keep the package-name `function` tier.
   */
  cveSinkPatterns?: Map<string, string[]>;
}

/**
 * Extract substring-match tokens from a CVE-targeted FrameworkSink pattern.
 * The pattern grammar (see taint-engine/spec.ts) is `Foo.bar`, `Foo.bar.*`,
 * or `Foo.bar(*)`. Returns the lowercased full dotted callee plus its last
 * segment — both matched against `project_usage_slices` strings. Segments
 * shorter than 3 chars are dropped as too generic to match reliably.
 */
export function extractSymbolTokens(pattern: string): string[] {
  let p = pattern.trim().toLowerCase();
  p = p.replace(/\(\s*\*?\s*\)\s*$/, ''); // strip trailing (*) / ()
  p = p.replace(/\.\*$/, '');             // strip trailing .*
  p = p.replace(/\*+$/, '').trim();
  if (!p) return [];
  const tokens = new Set<string>();
  if (p.length >= 3) tokens.add(p);
  const segs = p.split(/[.#:/]/).filter(Boolean);
  const last = segs[segs.length - 1];
  if (last && last.length >= 3) tokens.add(last);
  return [...tokens];
}

/**
 * Framework-embedded runtime components — servlet containers, embedded
 * app-servers, reactive runtimes and template engines that a framework's
 * starter / auto-configuration wires into the application. The app's own
 * first-party code never `import`s them (Spring Boot embeds Tomcat; the app
 * never imports `org.apache.catalina`), so the import-absence heuristic below
 * would wrongly collapse them to `unreachable` — yet the servlet container is
 * on every request path and the template engine renders every view. Never
 * emit `unreachable` for a dep whose name matches one of these; floor it at
 * `module` (we know it runs; we just can't pin the vulnerable function).
 *
 * Surfaced by the M4 reachability corpus: spring-petclinic's tomcat-embed-core
 * and thymeleaf-spring6 were false-negative `unreachable` verdicts.
 */
const FRAMEWORK_EMBEDDED_RUNTIME = [
  'tomcat-embed', 'jetty', 'undertow', 'netty', 'spring-boot-starter-tomcat',
  'thymeleaf', 'freemarker', 'mustache', 'pebble', 'groovy-templates',
];

/** True when `depName` is a framework-embedded runtime component (see above). */
export function isFrameworkEmbeddedRuntime(depName: string | undefined): boolean {
  if (!depName) return false;
  const n = depName.toLowerCase();
  return FRAMEWORK_EMBEDDED_RUNTIME.some((p) => n.includes(p));
}

/**
 * True when `project_dependencies.environment` marks a dependency as
 * dev/test/build scope. A dev-scoped dependency's vulnerable code is, by
 * definition, not on the production call path — the classifier floors it at
 * `unreachable`. `environment` is derived from the manifest (`deps-sync.ts`)
 * and from transitive dev-only propagation; it is the single dev-scope signal.
 */
export function isDevScoped(environment: string | null | undefined): boolean {
  return environment === 'dev';
}

export async function updateReachabilityLevels(
  projectId: string,
  runId: string,
  supabase: Storage,
  logger: LogLike,
  workspaceRoot?: string,
  options: UpdateReachabilityOptions = {},
): Promise<void> {
  const { data: pdvs, error: pdvErr } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('id, project_dependency_id, osv_id, aliases')
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);

  if (pdvErr) {
    throw new Error(`updateReachabilityLevels: failed to fetch PDVs: ${pdvErr.message}`);
  }
  if (!pdvs || pdvs.length === 0) return;

  const { data: pds, error: pdErr } = await supabase
    .from('project_dependencies')
    .select('id, dependency_id, is_direct, files_importing_count, environment, dependency_version_id')
    .eq('project_id', projectId)
    .eq('last_seen_extraction_run_id', runId);
  if (pdErr) {
    throw new Error(`updateReachabilityLevels: failed to fetch project_dependencies: ${pdErr.message}`);
  }

  const depIdMap = new Map(pds?.map((pd: any) => [pd.id, pd.dependency_id]) ?? []);
  const pdMetaMap = new Map<
    string,
    { isDirect: boolean; filesImporting: number; scope: string | null; versionId: string | null }
  >(
    pds?.map((pd: any) => [
      pd.id,
      {
        isDirect: !!pd.is_direct,
        filesImporting: Number(pd.files_importing_count ?? 0),
        scope: (pd.environment ?? null) as string | null,
        versionId: (pd.dependency_version_id ?? null) as string | null,
      },
    ]) ?? []
  );

  // Precision-fix support: a forward closure over the dependency edge graph
  // from every *imported* dependency (files_importing_count > 0). A production
  // transitive that the import heuristic below would call `unreachable` is
  // demoted to `module` when an imported ancestor reaches it — the jackson-core
  // / rustix false-positive class (reached via Spring / std I/O, never
  // first-party-imported). When the edge graph is unavailable (cdxgen graph
  // unwired) the closure is empty and the heuristic-unreachable branch floors
  // at `module` rather than guessing.
  const importedReachable = new Set<string>();
  let edgeGraphAvailable = false;
  {
    const projectVersionIds = [
      ...new Set(
        (pds ?? [])
          .map((pd: any) => pd.dependency_version_id)
          .filter((v: unknown): v is string => typeof v === 'string' && v.length > 0),
      ),
    ];
    if (projectVersionIds.length > 0) {
      const edges: Array<{ parent_version_id: string; child_version_id: string }> = [];
      for (let i = 0; i < projectVersionIds.length; i += 200) {
        const chunk = projectVersionIds.slice(i, i + 200);
        const { data: edgeRows } = await supabase
          .from('dependency_version_edges')
          .select('parent_version_id, child_version_id')
          .in('parent_version_id', chunk);
        if (edgeRows) edges.push(...(edgeRows as typeof edges));
      }
      edgeGraphAvailable = edges.length > 0;
      if (edgeGraphAvailable) {
        const adjacency = new Map<string, string[]>();
        for (const e of edges) {
          const kids = adjacency.get(e.parent_version_id);
          if (kids) kids.push(e.child_version_id);
          else adjacency.set(e.parent_version_id, [e.child_version_id]);
        }
        const queue = [
          ...new Set(
            (pds ?? [])
              .filter(
                (pd: any) =>
                  Number(pd.files_importing_count ?? 0) > 0 && pd.dependency_version_id,
              )
              .map((pd: any) => pd.dependency_version_id as string),
          ),
        ];
        for (const r of queue) importedReachable.add(r);
        while (queue.length > 0) {
          const vid = queue.pop()!;
          for (const child of adjacency.get(vid) ?? []) {
            if (!importedReachable.has(child)) {
              importedReachable.add(child);
              queue.push(child);
            }
          }
        }
      }
    }
  }

  // Try the full phase23 column list first. On pre-migration schemas the
  // select returns `42703 undefined_column` — fall back to the pre-phase23
  // column list (which still produces atom-based module/function/data_flow
  // classification) rather than silently collapsing every PDV to `module`
  // with no log. Any other error is a real failure and must surface.
  let flows: Array<{
    dependency_id: string | null;
    reachability_source?: string | null;
    osv_id?: string | null;
    rule_id?: string | null;
    flow_signature_hash?: string | null;
    entry_point_file: string | null;
    entry_point_line: number | null;
    entry_point_tag: string | null;
    sink_method: string | null;
  }> = [];
  {
    const { data, error } = await supabase
      .from('project_reachable_flows')
      .select('dependency_id, reachability_source, osv_id, rule_id, flow_signature_hash, entry_point_file, entry_point_line, entry_point_tag, sink_method')
      .eq('project_id', projectId)
      .eq('extraction_run_id', runId);

    if (error) {
      const code = (error as { code?: string }).code ?? '';
      const msg = error.message ?? '';
      const isMissingColumn = code === '42703' || /reachability_source|osv_id|rule_id/.test(msg);
      if (!isMissingColumn) {
        throw new Error(`updateReachabilityLevels: failed to fetch flows: ${msg}`);
      }
      // Phase23 not applied to this DB — retry with the pre-phase23 shape so
      // atom-only classification still works. Confirmed promotions are
      // impossible until the migration lands; log it once so operators see
      // the degradation instead of silent 'no confirmed levels ever'.
      await logger.warn(
        'reachability',
        'project_reachable_flows missing phase23 columns; taint classification disabled until migration lands',
      );
      const { data: baseData, error: baseErr } = await supabase
        .from('project_reachable_flows')
        .select('dependency_id, entry_point_file, entry_point_line, entry_point_tag, sink_method')
        .eq('project_id', projectId)
        .eq('extraction_run_id', runId);
      if (baseErr) {
        throw new Error(`updateReachabilityLevels: pre-phase23 fallback select failed: ${baseErr.message}`);
      }
      flows = (baseData ?? []) as typeof flows;
    } else {
      flows = (data ?? []) as typeof flows;
    }
  }

  // Phase 6.5 — fetch suppressions for this project so we can demote any
  // confirmed-tier promotion whose flow_signature_hash matches a user
  // suppression. Hash-keyed (Option B / OD-4): a re-extraction recomputes
  // the same canonical hash and re-matches the suppression row.
  const suppressedHashes = new Set<string>();
  {
    const { data: suppressions, error: suppErr } = await supabase
      .from('project_reachable_flow_suppressions')
      .select('flow_signature_hash')
      .eq('project_id', projectId);
    if (suppErr) {
      // Pre-phase27a schema or table-missing. Continue without the
      // suppression filter — confirmed-tier promotion still works; users
      // simply can't suppress yet.
      const code = (suppErr as { code?: string }).code ?? '';
      const isMissing = code === '42P01' || /project_reachable_flow_suppressions/.test(suppErr.message ?? '');
      if (!isMissing) {
        await logger.warn('reachability', `flow suppression fetch failed: ${suppErr.message}`);
      }
    } else {
      for (const row of (suppressions ?? []) as Array<{ flow_signature_hash: string | null }>) {
        if (row.flow_signature_hash) suppressedHashes.add(row.flow_signature_hash);
      }
    }
  }

  // Flows are polymorphic over their source. `flowsByDep` preserves the
  // original "any flow for this dep" semantics used by the data_flow branch
  // — atom, semgrep-derived, and taint_engine rows all count there since
  // any one of them proves the dep is actually wired into the project's
  // call graph.
  //
  // `taintByDepOsv` is the narrower index used by the confirmed branch:
  // a match requires not just the right dep but the specific CVE the taint
  // rule was authored for. Phase 6.5 / M5 task 27 extends this to also
  // pick up `taint_engine` flows whose `osv_id` was stamped by a
  // CVE-targeted FrameworkSpec sink (the new generator path), so the
  // OR-clause matches both Phase 3 Semgrep packs (`semgrep_taint`) and
  // the new cross-file engine path (`taint_engine`). Suppressed flows are
  // excluded so a user-suppressed promotion stays out of `confirmed`.
  type StoredFlow = (typeof flows)[number];
  const flowsByDep = new Map<string, StoredFlow[]>();
  const taintByDepOsv = new Map<string, StoredFlow[]>();
  let driftRejectedCount = 0;
  for (const flow of flows) {
    if (!flow.dependency_id) continue;
    const existing = flowsByDep.get(flow.dependency_id) ?? [];
    existing.push(flow);
    flowsByDep.set(flow.dependency_id, existing);

    const isSemgrepTaint = flow.reachability_source === 'semgrep_taint';
    const isCveTargetedEngine =
      flow.reachability_source === 'taint_engine' && !!flow.osv_id;
    if (!flow.osv_id) continue;
    if (!isSemgrepTaint && !isCveTargetedEngine) continue;

    // Phase 6.5 / M5 task 27 — server-side osv_id drift guard. The osv_id
    // on a `taint_engine` row was substituted server-side at engine-emission
    // time from the loaded CVE spec. Mismatch at classifier time means the
    // CHECK constraint was disabled, the dual-read window leaked, or someone
    // ran manual SQL — i.e. data drift, not model hallucination. Demote the
    // flow to data_flow tier and log a security event so the alert is
    // attributable. We only run the check when the caller passed the spec
    // set (M5 pipeline path); legacy callers without specs skip the guard
    // and inherit the prior behaviour.
    if (isCveTargetedEngine && options.validOsvIds && !options.validOsvIds.has(flow.osv_id)) {
      driftRejectedCount++;
      try {
        await supabase.from('security_audit_logs').insert({
          organization_id: options.organizationId ?? null,
          action: 'osv_id_drift_rejected',
          target_type: 'project_reachable_flow',
          target_id: null,
          severity: 'warn',
          metadata: {
            project_id: projectId,
            extraction_run_id: runId,
            flow_osv_id: flow.osv_id,
            flow_dependency_id: flow.dependency_id,
            flow_signature_hash: flow.flow_signature_hash ?? null,
            reason: 'taint_engine flow osv_id not in loaded cve_spec set',
          },
        });
      } catch (logErr) {
        // Audit-log failure must not block the classifier; log a warn and
        // continue with the demotion semantics.
        const msg = logErr instanceof Error ? logErr.message : String(logErr);
        await logger.warn('reachability', `osv_id_drift_rejected audit-log write failed: ${msg}`);
      }
      continue;
    }

    // Suppression: a user-suppressed flow stays out of the confirmed-tier
    // bucket. It still appears in `flowsByDep` for the data_flow branch
    // (the dep is still wired into the call graph), so the PDV doesn't
    // collapse all the way back to `module`/`unreachable` just because a
    // user suppressed one specific flow.
    if (flow.flow_signature_hash && suppressedHashes.has(flow.flow_signature_hash)) {
      continue;
    }

    const key = `${flow.dependency_id}|${flow.osv_id}`;
    const taintBucket = taintByDepOsv.get(key) ?? [];
    taintBucket.push(flow);
    taintByDepOsv.set(key, taintBucket);
  }
  if (driftRejectedCount > 0) {
    await logger.warn(
      'reachability',
      `${driftRejectedCount} taint_engine flow(s) demoted: osv_id not in loaded cve_spec set (osv_id_drift_rejected)`,
    );
  }

  const { data: usages, error: usagesErr } = await supabase
    .from('project_usage_slices')
    .select('target_type, resolved_method, file_path, line_number')
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);
  if (usagesErr) {
    throw new Error(`updateReachabilityLevels: failed to fetch usages: ${usagesErr.message}`);
  }

  // Fail-open guard for the `unreachable` verdict. `unreachable` (depscore
  // weight 0.0) is only safe to emit when usage analysis actually ran and
  // produced output for this run. If the tree-sitter usage-extraction step
  // crashed/timed-out (astParsedSuccessfully=false), or it produced zero
  // slices at all, the absence of a match is not evidence of unreachability —
  // floor every otherwise-unreachable PDV at `module` instead.
  const astParsedSuccessfully = options.astParsedSuccessfully ?? true;
  const usageAnalysisProducedOutput = astParsedSuccessfully && (usages?.length ?? 0) > 0;
  if (!usageAnalysisProducedOutput) {
    await logger.warn(
      'reachability',
      'Usage analysis produced no output (extraction crashed/timed-out or zero slices) — ' +
        'flooring unreachable verdicts at module to avoid hiding real vulnerabilities',
    );
  }

  // Second fail-open guard: `unreachable` keys on `!is_direct`, so it is only
  // safe when the direct/transitive split is trustworthy. cdxgen sometimes
  // returns an unwired dependency graph; when graph recovery also couldn't
  // rebuild the direct set, every dep looks transitive and a real direct vuln
  // could be hidden. Floor at `module` in that case.
  const graphTrusted = options.graphTrusted ?? true;
  if (!graphTrusted) {
    await logger.warn(
      'reachability',
      'Dependency graph untrusted (cdxgen graph unwired, recovery unavailable) — ' +
        'flooring unreachable verdicts at module',
    );
  }

  // Collect all type/method strings from usage slices for fuzzy matching
  const allUsageStrings: string[] = [];
  for (const u of usages ?? []) {
    if (u.target_type) allUsageStrings.push(u.target_type.toLowerCase());
    if (u.resolved_method) allUsageStrings.push(u.resolved_method.toLowerCase());
  }

  // Check if a dependency name appears in any usage slice (fuzzy)
  // e.g. "jackson-databind" matches "com.fasterxml.jackson.databind.ObjectMapper"
  // e.g. "log4j-core" matches "org.apache.logging.log4j.Logger"
  function isDepUsed(depName: string): boolean {
    if (!depName || allUsageStrings.length === 0) return false;
    const lower = depName.toLowerCase();
    // Direct match
    if (allUsageStrings.some(s => s.includes(lower))) return true;
    // Convert hyphens to dots for Java package matching: "jackson-databind" → "jackson.databind"
    const dotted = lower.replace(/-/g, '.');
    if (dotted !== lower && allUsageStrings.some(s => s.includes(dotted))) return true;
    // Also try just the last segment for short names: "log4j-core" → check for "log4j"
    const parts = lower.split('-');
    if (parts.length > 1 && allUsageStrings.some(s => s.includes(parts[0]))) return true;
    return false;
  }

  const depNameCache = new Map<string, string>();
  let updatedCount = 0;
  let detailsSetCount = 0;
  const levelCounts: Record<string, number> = {
    confirmed: 0,
    data_flow: 0,
    function: 0,
    module: 0,
    unreachable: 0,
  };

  for (const pdv of pdvs) {
    const dependencyId = depIdMap.get(pdv.project_dependency_id);
    if (!dependencyId) continue;

    // A PDV's primary osv_id may be a GHSA advisory while the taint engine
    // and CVE-targeted specs key on the CVE id. Match on the primary id plus
    // every alias so a GHSA-primary PDV still resolves its CVE-keyed flow.
    const candidateOsvIds: string[] = [];
    if (pdv.osv_id) candidateOsvIds.push(pdv.osv_id);
    if (Array.isArray(pdv.aliases)) {
      for (const a of pdv.aliases) {
        if (typeof a === 'string' && a && !candidateOsvIds.includes(a)) candidateOsvIds.push(a);
      }
    }

    const matchingFlows = flowsByDep.get(dependencyId) ?? [];
    const taintMatches: StoredFlow[] = [];
    {
      const seen = new Set<StoredFlow>();
      for (const osv of candidateOsvIds) {
        for (const f of taintByDepOsv.get(`${dependencyId}|${osv}`) ?? []) {
          if (!seen.has(f)) { seen.add(f); taintMatches.push(f); }
        }
      }
    }

    let level: string = 'module';
    let details: any = null;

    if (taintMatches.length > 0) {
      // A taint signal specific to this CVE on this specific dep —
      // either a hand-authored Phase 3 Semgrep rule (`semgrep_taint`,
      // legacy until M5 retires it) or a CVE-targeted FrameworkSpec
      // sink in the cross-file engine (`taint_engine`, Phase 6.5).
      // Trumps the heuristic ladder below regardless of usage slices.
      level = 'confirmed';
      const sources = [
        ...new Set(taintMatches.map((f) => f.reachability_source).filter((x): x is string => !!x)),
      ];
      details = {
        // rule_ids carry the Phase 3 rule id when present; taint_engine
        // rows leave it null. Keep the field for backwards compat with
        // any frontend reader that already iterates it.
        rule_ids: [...new Set(taintMatches.map((f) => f.rule_id).filter((x): x is string => !!x))],
        sources,
        flow_count: taintMatches.length,
        entry_points: taintMatches.map((f) => `${f.entry_point_file}:${f.entry_point_line}`),
        sink_methods: [...new Set(taintMatches.map((f) => f.sink_method).filter((x): x is string => !!x))],
      };
    } else if (matchingFlows.length > 0) {
      level = 'data_flow';
      details = {
        flow_count: matchingFlows.length,
        entry_points: matchingFlows.map((f) => `${f.entry_point_file}:${f.entry_point_line}`),
        sink_methods: [...new Set(matchingFlows.map((f) => f.sink_method).filter((x): x is string => !!x))],
        tags: [...new Set(matchingFlows.map((f) => f.entry_point_tag).filter((x): x is string => !!x))],
      };
    } else {
      // Dependency scope out-ranks the usage heuristic: a dev/test/build-scope
      // dependency's vulnerable code is by definition not on the production
      // call path. A genuine taint/data_flow signal (handled above) still wins;
      // this branch only runs when no flow was found.
      const scopeMeta = pdMetaMap.get(pdv.project_dependency_id);
      const devScoped = !!scopeMeta && isDevScoped(scopeMeta.scope);
      if (devScoped) {
        level = 'unreachable';
        details = {
          reason: 'dependency is dev/test/build scope — not on the production call path',
          scope: 'dev',
          verdict: 'dev_scope_unreachable',
        };
      }

      let depName = depNameCache.get(dependencyId);
      if (depName === undefined) {
        const { data: dep } = await supabase
          .from('dependencies')
          .select('name')
          .eq('id', dependencyId)
          .single();
        depName = dep?.name ?? '';
        depNameCache.set(dependencyId, depName as string);
      }

      // M2: CVE-targeted vulnerable-symbol verification. When a CVE-targeted
      // FrameworkSpec sink loaded for this PDV's CVE, we know the *specific*
      // vulnerable call pattern — verify it is on a call path instead of the
      // weaker "package name appears somewhere" heuristic below.
      let sinkPatterns: string[] | undefined;
      if (options.cveSinkPatterns) {
        for (const osv of candidateOsvIds) {
          const p = options.cveSinkPatterns.get(osv);
          if (p && p.length > 0) { sinkPatterns = p; break; }
        }
      }
      const symbolTokens = [...new Set((sinkPatterns ?? []).flatMap(extractSymbolTokens))];
      let symbolClassified = false;
      if (!devScoped && symbolTokens.length > 0) {
        const matchedToken = symbolTokens.find((tok) => allUsageStrings.some((s) => s.includes(tok)));
        const symMeta = pdMetaMap.get(pdv.project_dependency_id);
        if (matchedToken) {
          // The vulnerable symbol itself is referenced — a genuine function-tier hit.
          level = 'function';
          details = {
            reason: `vulnerable symbol "${matchedToken}" found in project usage`,
            vulnerable_symbols: symbolTokens,
          };
          symbolClassified = true;
        } else if (usageAnalysisProducedOutput && symMeta && symMeta.filesImporting > 0) {
          // The package is imported, but the CVE's specific vulnerable symbol
          // is on no call path the usage extractor could see — down-rank to
          // `unreachable`. Tunable knob: if the M4 corpus surfaces a
          // false-negative, demote this branch to `module` instead.
          level = 'unreachable';
          details = {
            reason: `vulnerable symbol(s) ${symbolTokens.join(', ')} not found on any call path`,
            vulnerable_symbols: symbolTokens,
          };
          symbolClassified = true;
        }
        // else: usage analysis incomplete, or the dep isn't imported at all —
        // fall through to the heuristic ladder; never invent unreachable here.
      }

      if (!devScoped && !symbolClassified) {
      if (depName && isDepUsed(depName)) {
        level = 'function';
        // Populate details with matching usage data (file, line, methods called)
        const lower = depName.toLowerCase();
        const dotted = lower.replace(/-/g, '.');
        const firstPart = lower.split('-')[0];
        const matchingUsages = (usages ?? []).filter((u: any) => {
          const t = (u.target_type ?? '').toLowerCase();
          const m = (u.resolved_method ?? '').toLowerCase();
          return t.includes(lower) || t.includes(dotted) || m.includes(lower) || m.includes(dotted)
            || (firstPart.length > 3 && (t.includes(firstPart) || m.includes(firstPart)));
        });
        if (matchingUsages.length > 0) {
          const files = [...new Set(matchingUsages.map((u: any) => u.file_path).filter(Boolean))];
          const methods = [...new Set(matchingUsages.map((u: any) => u.resolved_method).filter(Boolean))];
          const locations = matchingUsages
            .filter((u: any) => u.file_path && u.line_number)
            .slice(0, 10)
            .map((u: any) => {
              const loc: any = { file: u.file_path, line: u.line_number, method: u.resolved_method ?? null };
              // Read actual source code around this line
              if (workspaceRoot) {
                const snippet = readCodeSnippet(workspaceRoot, u.file_path, u.line_number);
                if (snippet) loc.code_snippet = snippet;
              }
              return loc;
            });
          details = {
            usage_count: matchingUsages.length,
            impacted_paths: locations.length,
            files,
            methods_called: methods.slice(0, 20),
            locations,
          };
        }
      } else {
        // No usage slices referenced this dep. If it's a transitive dep that
        // nothing in the source imports, classify as `unreachable` (depscore
        // weight 0.0). Direct deps and deps with at least one import stay
        // `module` — we know they're touched, we just don't know the function.
        //
        // Fail-safe: if usage extraction did not produce output (crashed /
        // timed-out — astParsedSuccessfully=false), the absence of slices is
        // NOT evidence of unreachability. Never emit `unreachable` in that
        // case; floor the verdict at `module` so real vulns aren't hidden.
        const meta = pdMetaMap.get(pdv.project_dependency_id);
        const heuristicUnreachable =
          graphTrusted &&
          usageAnalysisProducedOutput &&
          !!meta &&
          !meta.isDirect &&
          meta.filesImporting === 0 &&
          !isFrameworkEmbeddedRuntime(depName);
        if (heuristicUnreachable) {
          // Precision guard: a production transitive is only genuinely
          // unreachable when no *imported* ancestor reaches it in the
          // dependency graph. A dep reached via an imported parent (the
          // jackson-core / rustix class — Spring, std I/O) is exercised —
          // demote to `module`. With no edge graph we cannot tell reached
          // from orphaned, so floor at `module` rather than risk a false
          // `unreachable`.
          const versionId = meta?.versionId ?? null;
          const reachedByImport =
            !edgeGraphAvailable || (versionId != null && importedReachable.has(versionId));
          if (reachedByImport) {
            level = 'module';
          } else {
            level = 'unreachable';
            details = {
              reason:
                'no source file imports this transitive dependency, and no imported dependency reaches it in the graph',
              scope: 'orphan',
              verdict: 'orphan_transitive_unreachable',
            };
          }
        } else {
          // Direct deps, deps with >=1 import, and framework-embedded runtime
          // components (servlet container / template engine wired in by a
          // framework starter) floor at `module` — we know they run, we just
          // can't pin the vulnerable function to a call path.
          level = 'module';
        }
      }
      }
    }

    const isReachable = level !== 'unreachable';

    const { error: updateErr } = await supabase
      .from('project_dependency_vulnerabilities')
      .update({ reachability_level: level, reachability_details: details, is_reachable: isReachable })
      .eq('id', pdv.id);

    if (updateErr) {
      console.error(`[REACHABILITY] Failed to update vuln ${pdv.id}: ${updateErr.message}`);
    }
    if (details) detailsSetCount++;
    updatedCount++;
    if (level in levelCounts) levelCounts[level]++;
  }

  // Surface per-level counts so on-call can answer "did any vuln actually get
  // promoted to confirmed in this run?" without running ad-hoc SQL.
  const summary =
    `confirmed=${levelCounts.confirmed} data_flow=${levelCounts.data_flow} ` +
    `function=${levelCounts.function} module=${levelCounts.module} ` +
    `unreachable=${levelCounts.unreachable}`;
  await logger.info('reachability', `Classified ${updatedCount} vuln(s): ${summary}`);

  if (process.env.DEPTEX_CLI_MODE !== '1') {
    console.log(`[REACHABILITY] Updated ${updatedCount} vulns, ${detailsSetCount} with details, ${allUsageStrings.length} usage strings available`);
  }
}

// ---------------------------------------------------------------------------
// Compute files_importing_count from atom usage slices (all ecosystems)
// ---------------------------------------------------------------------------

// Python packages where pip name differs from import name
const PYPI_IMPORT_ALIASES: Record<string, string[]> = {
  pillow: ['pil'],
  pyyaml: ['yaml'],
  'beautifulsoup4': ['bs4'],
  'scikit-learn': ['sklearn'],
  'opencv-python': ['cv2'],
  'opencv-python-headless': ['cv2'],
  'python-dateutil': ['dateutil'],
  'python-dotenv': ['dotenv'],
  'python-jose': ['jose'],
  'python-multipart': ['multipart'],
  'pyjwt': ['jwt'],
  'pycryptodome': ['crypto', 'cryptodome'],
  'pymysql': ['pymysql'],
  'psycopg2-binary': ['psycopg2'],
  'protobuf': ['google.protobuf'],
  'attrs': ['attr'],
  'ruamel.yaml': ['ruamel'],
};

/**
 * Check if a usage slice entry matches a dependency name.
 * Returns true if the target_type or resolved_method contains the dep name
 * using fuzzy matching (hyphen-to-dot, first-segment, aliases, etc.)
 */
function usageMatchesDep(
  targetType: string,
  resolvedMethod: string,
  depNameLower: string,
  depNameDotted: string,
  depFirstPart: string,
  importAliases?: string[],
): boolean {
  const t = targetType.toLowerCase();
  const m = resolvedMethod.toLowerCase();
  // Direct name match
  if (t.includes(depNameLower) || m.includes(depNameLower)) return true;
  // Dotted variant (Java: jackson-databind → jackson.databind)
  if (depNameDotted !== depNameLower && (t.includes(depNameDotted) || m.includes(depNameDotted))) return true;
  // First segment for compound names (log4j-core → log4j), only if segment is meaningful (>3 chars)
  if (depFirstPart.length > 3 && (t.includes(depFirstPart) || m.includes(depFirstPart))) return true;
  // Python import aliases (pillow → PIL, pyyaml → yaml, etc.)
  if (importAliases) {
    for (const alias of importAliases) {
      if (t.includes(alias) || m.includes(alias)) return true;
    }
  }
  // Strip common Python prefixes: py*, python-* → check remainder
  if (depNameLower.startsWith('py') && depNameLower.length > 3) {
    const stripped = depNameLower.slice(2);
    if (t.includes(stripped) || m.includes(stripped)) return true;
  }
  return false;
}

/**
 * Supplemental file-count pass that runs after the tree-sitter extractor has
 * already populated `project_dependencies.files_importing_count` and written
 * `project_usage_slices`. This re-reads the slices with looser name-matching
 * (package-name variants, PyPI distribution↔module aliases) so transitive
 * usages the extractor couldn't map directly still get counted.
 *
 * For npm we treat the tree-sitter count as the floor and only bump upward;
 * for other ecosystems we overwrite with the looser count (or NULL if no
 * slices exist) since the extractor may not have resolved the full import set.
 */
export async function computeImportCountsFromUsageSlices(
  projectId: string,
  runId: string,
  ecosystem: string,
  supabase: Storage,
  logger: LogLike,
): Promise<void> {
  // npm gets special treatment: tree-sitter extractor already ran the precise
  // AST pass, so we never downgrade its count — only bump it upward if this
  // looser matcher finds more files.
  const isNpm = ecosystem === 'npm';

  // Fetch all direct project dependencies for this run only
  const { data: projectDeps } = await supabase
    .from('project_dependencies')
    .select('id, name, dependency_id, files_importing_count')
    .eq('project_id', projectId)
    .eq('is_direct', true)
    .eq('last_seen_extraction_run_id', runId);

  if (!projectDeps || projectDeps.length === 0) return;

  // Fetch usage slices for this run only
  const { data: usages } = await supabase
    .from('project_usage_slices')
    .select('target_type, resolved_method, file_path')
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);

  if (!usages || usages.length === 0) {
    // No usage data — for non-npm, explicitly set null to indicate "not analyzed".
    // For npm, the tree-sitter extractor's count is authoritative, so don't overwrite.
    if (!isNpm) {
      for (const pd of projectDeps) {
        if (pd.files_importing_count === 0) {
          await supabase
            .from('project_dependencies')
            .update({ files_importing_count: null })
            .eq('id', pd.id);
        }
      }
      await logger.info('import_analysis', 'No usage slices available — import counts not determined');
    }
    return;
  }

  // Pre-compute name variants for each dependency
  const depVariants = projectDeps.map((pd: any) => {
    const lower = (pd.name ?? '').toLowerCase();
    const dotted = lower.replace(/-/g, '.');
    const firstPart = lower.split('-')[0];
    const aliases = PYPI_IMPORT_ALIASES[lower] ?? undefined;
    return { id: pd.id, name: pd.name, lower, dotted, firstPart, aliases, existingCount: pd.files_importing_count ?? 0 };
  });

  // For each usage, find which dependency it belongs to, and track unique files
  const depFileMap = new Map<string, Set<string>>(); // dep id → set of file paths

  for (const usage of usages) {
    const targetType = usage.target_type ?? '';
    const resolvedMethod = usage.resolved_method ?? '';
    const filePath = usage.file_path;
    if (!filePath || (!targetType && !resolvedMethod)) continue;

    for (const dep of depVariants) {
      if (!dep.lower) continue;
      if (usageMatchesDep(targetType, resolvedMethod, dep.lower, dep.dotted, dep.firstPart, dep.aliases)) {
        if (!depFileMap.has(dep.id)) depFileMap.set(dep.id, new Set());
        depFileMap.get(dep.id)!.add(filePath);
      }
    }
  }

  // Update files_importing_count and persist file paths into project_dependency_files
  let updatedCount = 0;
  for (const dep of depVariants) {
    const fileSet = depFileMap.get(dep.id);
    const newCount = fileSet ? fileSet.size : 0;

    if (isNpm) {
      // npm: only bump upward — never downgrade the tree-sitter extractor's count.
      if (newCount > dep.existingCount) {
        await supabase
          .from('project_dependencies')
          .update({ files_importing_count: newCount })
          .eq('id', dep.id);
        updatedCount++;
      }
    } else {
      // Non-npm: set the count directly — the looser matcher is authoritative.
      await supabase
        .from('project_dependencies')
        .update({ files_importing_count: newCount > 0 ? newCount : null })
        .eq('id', dep.id);
      updatedCount++;
    }

    // Persist file paths into project_dependency_files so analyze-usage can fetch real code
    if (fileSet && fileSet.size > 0) {
      const rows = [...fileSet].map(fp => ({ project_dependency_id: dep.id, file_path: fp, extraction_run_id: runId }));
      await supabase
        .from('project_dependency_files')
        .upsert(rows, { onConflict: 'project_dependency_id,file_path,extraction_run_id' });
    }
  }

  // Internal metric — not shown in user-facing logs
}

