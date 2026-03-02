/**
 * Phase 6B: Reachability engine -- parse atom/dep-scan deep analysis output,
 * store reachable flows & usage slices, update reachability levels on vulnerabilities.
 */

import * as fs from 'fs';
import * as path from 'path';
import { Readable } from 'stream';
import { SupabaseClient } from '@supabase/supabase-js';
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
  supabase: SupabaseClient,
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
  supabase: SupabaseClient,
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
        onConflict: 'project_id,file_path,line_number,target_name',
      });
    }
  }

  await logger.info('reachability', `Parsed ${totalUsages} usage slices`);
}

// ---------------------------------------------------------------------------
// Parse LLM prompts and attach to reachable flows
// ---------------------------------------------------------------------------

export async function parseLlmPrompts(
  reportsDir: string,
  projectId: string,
  runId: string,
  supabase: SupabaseClient,
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
  supabase: SupabaseClient,
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

export async function updateReachabilityLevels(
  projectId: string,
  supabase: SupabaseClient,
  logger: LogLike,
): Promise<void> {
  const { data: pdvs } = await supabase
    .from('project_dependency_vulnerabilities')
    .select('id, project_dependency_id, osv_id')
    .eq('project_id', projectId);

  if (!pdvs || pdvs.length === 0) return;

  const { data: pds } = await supabase
    .from('project_dependencies')
    .select('id, dependency_id')
    .eq('project_id', projectId);

  const depIdMap = new Map(pds?.map((pd: any) => [pd.id, pd.dependency_id]) ?? []);

  const { data: flows } = await supabase
    .from('project_reachable_flows')
    .select('dependency_id, entry_point_file, entry_point_line, entry_point_tag, sink_method')
    .eq('project_id', projectId);

  const flowsByDep = new Map<string, any[]>();
  for (const flow of flows ?? []) {
    if (!flow.dependency_id) continue;
    const existing = flowsByDep.get(flow.dependency_id) ?? [];
    existing.push(flow);
    flowsByDep.set(flow.dependency_id, existing);
  }

  const { data: usages } = await supabase
    .from('project_usage_slices')
    .select('target_type, resolved_method')
    .eq('project_id', projectId);

  const usedTypes = new Set(usages?.map((u: any) => u.target_type).filter(Boolean) ?? []);

  const depNameCache = new Map<string, string>();
  let updatedCount = 0;

  for (const pdv of pdvs) {
    const dependencyId = depIdMap.get(pdv.project_dependency_id);
    if (!dependencyId) continue;

    const matchingFlows = flowsByDep.get(dependencyId) ?? [];

    let level: string;
    let details: any = null;

    if (matchingFlows.length > 0) {
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

      if (depName && usedTypes.has(depName)) {
        level = 'function';
      } else {
        level = 'module';
      }
    }

    const isReachable = level !== 'unreachable';

    await supabase
      .from('project_dependency_vulnerabilities')
      .update({ reachability_level: level, reachability_details: details, is_reachable: isReachable })
      .eq('id', pdv.id);
    updatedCount++;
  }

  await logger.info('reachability', `Updated reachability levels for ${updatedCount} vulnerabilities`);
}
