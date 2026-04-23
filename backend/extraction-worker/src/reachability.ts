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
      await supabase.from('project_reachable_flows').upsert(chunk, {
        onConflict: 'project_id,extraction_run_id,purl,entry_point_file,entry_point_line,sink_method',
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

export async function updateReachabilityLevels(
  projectId: string,
  runId: string,
  supabase: Storage,
  logger: LogLike,
  workspaceRoot?: string,
): Promise<void> {
  const { data: pdvs } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('id, project_dependency_id, osv_id')
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);

  if (!pdvs || pdvs.length === 0) return;

  const { data: pds } = await supabase
    .from('project_dependencies')
    .select('id, dependency_id, is_direct, files_importing_count')
    .eq('project_id', projectId)
    .eq('last_seen_extraction_run_id', runId);

  const depIdMap = new Map(pds?.map((pd: any) => [pd.id, pd.dependency_id]) ?? []);
  const pdMetaMap = new Map<string, { isDirect: boolean; filesImporting: number }>(
    pds?.map((pd: any) => [
      pd.id,
      { isDirect: !!pd.is_direct, filesImporting: Number(pd.files_importing_count ?? 0) },
    ]) ?? []
  );

  const { data: flows } = await supabase
    .from('project_reachable_flows')
    .select('dependency_id, reachability_source, osv_id, rule_id, entry_point_file, entry_point_line, entry_point_tag, sink_method')
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);

  // Flows are polymorphic over their source (Phase 23). `flowsByDep` preserves
  // the original "any flow for this dep" semantics used by the data_flow
  // branch — atom and semgrep-derived rows both count there, since either
  // proves the dep is actually wired into the project's call graph.
  //
  // `taintByDepOsv` is the narrower index used by the new confirmed branch:
  // a match requires not just the right dep but the specific CVE the taint
  // rule was authored for, so a semgrep hit on CVE-A can't promote a PDV
  // for CVE-B on the same package.
  const flowsByDep = new Map<string, any[]>();
  const taintByDepOsv = new Map<string, any[]>();
  for (const flow of flows ?? []) {
    if (!flow.dependency_id) continue;
    const existing = flowsByDep.get(flow.dependency_id) ?? [];
    existing.push(flow);
    flowsByDep.set(flow.dependency_id, existing);

    if (flow.reachability_source === 'semgrep_taint' && flow.osv_id) {
      const key = `${flow.dependency_id}|${flow.osv_id}`;
      const taintBucket = taintByDepOsv.get(key) ?? [];
      taintBucket.push(flow);
      taintByDepOsv.set(key, taintBucket);
    }
  }

  const { data: usages } = await supabase
    .from('project_usage_slices')
    .select('target_type, resolved_method, file_path, line_number')
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);

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

  for (const pdv of pdvs) {
    const dependencyId = depIdMap.get(pdv.project_dependency_id);
    if (!dependencyId) continue;

    const matchingFlows = flowsByDep.get(dependencyId) ?? [];
    const taintMatches = pdv.osv_id
      ? taintByDepOsv.get(`${dependencyId}|${pdv.osv_id}`) ?? []
      : [];

    let level: string;
    let details: any = null;

    if (taintMatches.length > 0) {
      // A hand-authored Semgrep taint rule for this specific CVE fired on
      // this specific dep — the highest-confidence signal we produce.
      // Trumps the heuristic ladder below regardless of what atom thinks.
      level = 'confirmed';
      details = {
        rule_ids: [...new Set(taintMatches.map((f: any) => f.rule_id).filter(Boolean))],
        flow_count: taintMatches.length,
        entry_points: taintMatches.map((f: any) => `${f.entry_point_file}:${f.entry_point_line}`),
        sink_methods: [...new Set(taintMatches.map((f: any) => f.sink_method).filter(Boolean))],
      };
    } else if (matchingFlows.length > 0) {
      level = 'data_flow';
      details = {
        flow_count: matchingFlows.length,
        entry_points: matchingFlows.map((f: any) => `${f.entry_point_file}:${f.entry_point_line}`),
        sink_methods: [...new Set(matchingFlows.map((f: any) => f.sink_method).filter(Boolean))],
        tags: [...new Set(matchingFlows.map((f: any) => f.entry_point_tag).filter(Boolean))],
      };
    } else {
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
        const meta = pdMetaMap.get(pdv.project_dependency_id);
        if (meta && !meta.isDirect && meta.filesImporting === 0) {
          level = 'unreachable';
        } else {
          level = 'module';
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
  }

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

