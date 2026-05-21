/**
 * IaC↔Code reachability composition (Phase 30 / Item G).
 *
 * Pairs container OS-package CVE findings (PCFs, written by doIaCContainer
 * + decorateContainerFindingsWithReachability) with code-side dependency
 * vulnerability findings (PDVs, written by Phase 6 + EPD) across a shared
 * SONAME bridge persisted by the native-bindings extractor.
 *
 * Per-edge composition_factor:
 *   container_mult ∈ {1.0, 0.4}  (1.0 unless PCF is `unreachable`)
 *   code_mult      ∈ {1.0, 0.9, 0.7, 0.5, 0.0}  (from REACHABILITY_LEVEL_WEIGHTS)
 *   composition_factor = container_mult × code_mult
 *
 * Per-PDV factor (multi-partner aggregation):
 *   pdv.composition_factor = MIN(edge factors)
 * The join table keeps every edge for forensics; the MIN is what gets
 * folded into PDV.contextual_depscore via apply_composition_results RPC.
 *
 * Sole-writer invariant: after doReachabilityAndEpd, only composition.ts
 * mutates contextual_depscore. Enforced by
 * `__tests__/contextual-depscore-writers.test.ts`.
 *
 * Failure policy: every failure is soft. composeFindings returns a summary
 * but never throws; orchestration is best-effort. A missing bindings table,
 * empty PDV/PCF set, or RPC failure leaves contextual_depscore untouched.
 */

import type { SupabaseClient } from '@supabase/supabase-js';
import type { ScannerSubprocessLogger } from '../with-timeout';

// ---- Constants ------------------------------------------------------------

/** Mirrors depscanner/src/depscore.ts:35-40 PLUS the explicit unreachable=0.
 *  Imported from depscore.ts would create a circular pull on shared types
 *  the depscore module also exports; duplicating the small constant table
 *  is the path of least friction. The sole-writer grep test guards drift. */
const CODE_REACHABILITY_WEIGHTS: Record<string, number> = {
  confirmed: 1.0,
  data_flow: 0.9,
  function: 0.7,
  module: 0.5,
  unreachable: 0.0,
};

/** Mirrors `CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER` in scanners/storage.ts.
 *  Same duplication rationale as above — locked at 0.4 by the storage module
 *  comment and consumed by composition for the PCF-side leg of the product. */
const CONTAINER_UNREACHABLE_MULT = 0.4;

/** Cap on `bindings_evidence` array length per edge — keeps JSONB rows
 *  small and bounds the trigger-time enforcement cost. */
const MAX_EVIDENCE_PER_EDGE = 20;

// ---- Types ----------------------------------------------------------------

export interface ComposeFindingsOptions {
  supabase: SupabaseClient;
  projectId: string;
  organizationId: string;
  runId: string;
  logger: ScannerSubprocessLogger;
}

export interface ComposeFindingsSummary {
  partnerable_pcf: number;
  partnerable_pdv: number;
  edges_written: number;
  pdvs_updated: number;
  suppressions_to_zero: number;
  os_family_seen: string[];
  bindings_by_ecosystem: Record<string, number>;
  pdvs_skipped: {
    no_reachability_level: number;
    no_osv_id: number;
    no_alias_match: number;
  };
  edges_skipped_unknown_reachability: number;
  pcfs_skipped_no_identifier: number;
  composition_coverage_pct: number;
  duration_ms: number;
}

interface ContainerFindingRow {
  id: string;
  project_id: string;
  os_package_name: string;
  osv_id: string | null;
  cve_id: string | null;
  reachability_level: string | null;
}

interface PdvRow {
  id: string;
  osv_id: string;
  aliases: string[] | null;
  reachability_level: string | null;
  contextual_depscore: number | null;
  project_dependency_id: string;
}

interface ProjectDependencyRow {
  id: string;
  name: string;
  dependency_id: string | null;
}

interface DependencyRow {
  id: string;
  ecosystem: string;
  name: string;
}

interface NativeBindingRow {
  scope: 'language' | 'os';
  package_identifier: string;
  package_ecosystem: string | null;
  soname: string;
  install_path: string;
  link_method: string;
  extractor_version: string;
}

interface BindingEvidenceEntry {
  soname: string;
  link_method: string;
  language_install_path?: string;
  os_install_path?: string;
  extractor_version: string;
}

interface PartnerEdge {
  pcf_id: string;
  pdv_id: string;
  container_mult: number;
  code_mult: number;
  composition_factor: number;
  bindings_evidence: BindingEvidenceEntry[];
}

// ---- Helpers --------------------------------------------------------------

/** Derive the CVE alias set for a PDV — osv_id plus any CVE-shaped alias. */
function pdvCveSet(pdv: PdvRow): Set<string> {
  const out = new Set<string>();
  if (pdv.osv_id) out.add(pdv.osv_id.toUpperCase());
  for (const a of pdv.aliases ?? []) {
    if (typeof a === 'string' && /^CVE-/i.test(a)) out.add(a.toUpperCase());
  }
  return out;
}

/** Decide whether a PCF and a PDV name the same vulnerability. */
function pcfMatchesPdv(pcf: ContainerFindingRow, pdvCves: Set<string>): boolean {
  if (pcf.cve_id && pdvCves.has(pcf.cve_id.toUpperCase())) return true;
  if (pcf.osv_id && pdvCves.has(pcf.osv_id.toUpperCase())) return true;
  return false;
}

/** Round a numeric to 3 dp for NUMERIC(4,3) storage. */
function round3(n: number): number {
  return Number(n.toFixed(3));
}

// ---- Main -----------------------------------------------------------------

export async function composeFindings(
  opts: ComposeFindingsOptions
): Promise<ComposeFindingsSummary> {
  const { supabase, projectId, organizationId, runId, logger } = opts;
  const startedMs = Date.now();
  const summary: ComposeFindingsSummary = {
    partnerable_pcf: 0,
    partnerable_pdv: 0,
    edges_written: 0,
    pdvs_updated: 0,
    suppressions_to_zero: 0,
    os_family_seen: [],
    bindings_by_ecosystem: {},
    pdvs_skipped: { no_reachability_level: 0, no_osv_id: 0, no_alias_match: 0 },
    edges_skipped_unknown_reachability: 0,
    pcfs_skipped_no_identifier: 0,
    composition_coverage_pct: 0,
    duration_ms: 0,
  };

  // ---- Step A: load partnerable rows.
  // Both filters mirror the partnerable criteria (per plan §M2 step 2A).
  // We DON'T filter PDVs by `reachability_level IS NOT NULL` server-side
  // because the count is small and we want the skipped reason telemetry.

  const { data: pcfsData, error: pcfErr } = await supabase
    .from('project_container_findings')
    .select('id, project_id, os_package_name, osv_id, cve_id, reachability_level')
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);
  if (pcfErr) {
    await logger.warn(
      'composeFindings',
      `partnerable PCF load failed: ${pcfErr.message}`
    );
    summary.duration_ms = Date.now() - startedMs;
    return summary;
  }
  // Server-side `IS NOT NULL` filter would shave one round trip but the
  // PGLite local-mode builder doesn't support `.not(...)`; JS filter is
  // equivalent and keeps prod + local-mode behaviour identical.
  const pcfs = ((pcfsData ?? []) as ContainerFindingRow[]).filter(
    (p) => p.reachability_level !== null
  );
  summary.partnerable_pcf = pcfs.length;

  // Filter out PCFs with no identifier; counter the skip.
  const usablePcfs = pcfs.filter((p) => {
    if (!p.cve_id && !p.osv_id) {
      summary.pcfs_skipped_no_identifier += 1;
      return false;
    }
    return true;
  });

  const { data: pdvsData, error: pdvErr } = await supabase
    .from('project_dependency_vulnerabilities')
    .select(
      'id, osv_id, aliases, reachability_level, contextual_depscore, project_dependency_id'
    )
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);
  if (pdvErr) {
    await logger.warn(
      'composeFindings',
      `partnerable PDV load failed: ${pdvErr.message}`
    );
    summary.duration_ms = Date.now() - startedMs;
    return summary;
  }
  const allPdvs = (pdvsData ?? []) as PdvRow[];
  const usablePdvs: PdvRow[] = [];
  for (const p of allPdvs) {
    if (!p.reachability_level) {
      summary.pdvs_skipped.no_reachability_level += 1;
      continue;
    }
    if (!p.osv_id) {
      summary.pdvs_skipped.no_osv_id += 1;
      continue;
    }
    usablePdvs.push(p);
  }
  summary.partnerable_pdv = usablePdvs.length;

  // Short-circuit when there is nothing to do — skips two more DB round-trips.
  if (usablePcfs.length === 0 || usablePdvs.length === 0) {
    summary.duration_ms = Date.now() - startedMs;
    await logComposeSummary(logger, summary);
    return summary;
  }

  // Resolve PDV → (ecosystem, name) via project_dependencies → dependencies.
  const pdIds = Array.from(new Set(usablePdvs.map((p) => p.project_dependency_id)));
  const { data: pdsData } = await supabase
    .from('project_dependencies')
    .select('id, name, dependency_id')
    .in('id', pdIds);
  const pds = (pdsData ?? []) as ProjectDependencyRow[];
  const depIds = Array.from(new Set(pds.map((d) => d.dependency_id).filter(Boolean) as string[]));
  const ecosystemByDepId = new Map<string, string>();
  if (depIds.length > 0) {
    const { data: depsData } = await supabase
      .from('dependencies')
      .select('id, ecosystem, name')
      .in('id', depIds);
    for (const d of (depsData ?? []) as DependencyRow[]) {
      ecosystemByDepId.set(d.id, d.ecosystem);
    }
  }
  const pdById = new Map<string, ProjectDependencyRow>();
  for (const pd of pds) pdById.set(pd.id, pd);

  // ---- Step B: load native bindings for this run.
  const { data: bindingsData, error: bindErr } = await supabase
    .from('project_native_bindings')
    .select(
      'scope, package_identifier, package_ecosystem, soname, install_path, link_method, extractor_version'
    )
    .eq('project_id', projectId)
    .eq('extraction_run_id', runId);
  if (bindErr) {
    await logger.warn(
      'composeFindings',
      `bindings load failed: ${bindErr.message}`
    );
    summary.duration_ms = Date.now() - startedMs;
    return summary;
  }
  const bindings = (bindingsData ?? []) as NativeBindingRow[];
  if (bindings.length === 0) {
    summary.duration_ms = Date.now() - startedMs;
    await logComposeSummary(logger, summary);
    return summary;
  }

  // ---- Index bindings two ways.
  // language: ecosystem|name → sonames + paths
  // os: os_package_name → sonames + paths
  const langIndex = new Map<string, NativeBindingRow[]>();
  const osIndex = new Map<string, NativeBindingRow[]>();
  for (const b of bindings) {
    if (b.scope === 'language') {
      const key = `${(b.package_ecosystem ?? '').toLowerCase()}|${b.package_identifier.toLowerCase()}`;
      let arr = langIndex.get(key);
      if (!arr) { arr = []; langIndex.set(key, arr); }
      arr.push(b);
      summary.bindings_by_ecosystem[b.package_ecosystem ?? 'unknown'] =
        (summary.bindings_by_ecosystem[b.package_ecosystem ?? 'unknown'] ?? 0) + 1;
    } else if (b.scope === 'os') {
      const key = b.package_identifier.toLowerCase();
      let arr = osIndex.get(key);
      if (!arr) { arr = []; osIndex.set(key, arr); }
      arr.push(b);
    }
  }

  // ---- Step C: match PCF × PDV by shared SONAME.
  const edges: PartnerEdge[] = [];
  for (const pdv of usablePdvs) {
    const pd = pdById.get(pdv.project_dependency_id);
    if (!pd) continue;
    const ecosystem = pd.dependency_id ? ecosystemByDepId.get(pd.dependency_id) : null;
    if (!ecosystem) continue;
    const langKey = `${ecosystem.toLowerCase()}|${pd.name.toLowerCase()}`;
    const langBindings = langIndex.get(langKey);
    if (!langBindings || langBindings.length === 0) continue;
    const langSonames = new Set(langBindings.map((b) => b.soname));

    const pdvCves = pdvCveSet(pdv);
    for (const pcf of usablePcfs) {
      if (!pcfMatchesPdv(pcf, pdvCves)) continue;
      const osBindings = osIndex.get(pcf.os_package_name.toLowerCase());
      if (!osBindings || osBindings.length === 0) continue;

      // SONAME intersection — exact string match per plan.
      const evidence: BindingEvidenceEntry[] = [];
      for (const ob of osBindings) {
        if (!langSonames.has(ob.soname)) continue;
        const lb = langBindings.find((l) => l.soname === ob.soname);
        evidence.push({
          soname: ob.soname,
          link_method: 'dpkg_soname',
          language_install_path: lb?.install_path,
          os_install_path: ob.install_path,
          extractor_version: ob.extractor_version,
        });
        if (evidence.length >= MAX_EVIDENCE_PER_EDGE) break;
      }
      if (evidence.length === 0) continue;

      // ---- Step D: compose factor.
      const container_mult =
        pcf.reachability_level === 'unreachable' ? CONTAINER_UNREACHABLE_MULT : 1.0;
      const code_mult = CODE_REACHABILITY_WEIGHTS[pdv.reachability_level ?? ''];
      if (code_mult === undefined) {
        summary.edges_skipped_unknown_reachability += 1;
        continue;
      }
      const factor = round3(container_mult * code_mult);

      edges.push({
        pcf_id: pcf.id,
        pdv_id: pdv.id,
        container_mult: round3(container_mult),
        code_mult: round3(code_mult),
        composition_factor: factor,
        bindings_evidence: evidence,
      });
    }
  }

  if (edges.length === 0) {
    // No PDV partnered with any PCF — record telemetry & return.
    summary.duration_ms = Date.now() - startedMs;
    await logComposeSummary(logger, summary);
    return summary;
  }

  // ---- Step E1: insert partner rows.
  const partnerRows = edges.map((e) => ({
    project_id: projectId,
    organization_id: organizationId, // overwritten by enforce_finding_org_id trigger
    extraction_run_id: runId,
    container_finding_id: e.pcf_id,
    pdv_id: e.pdv_id,
    container_reachability_multiplier: e.container_mult,
    code_reachability_multiplier: e.code_mult,
    composition_factor: e.composition_factor,
    bindings_evidence: e.bindings_evidence,
  }));

  const { error: insErr } = await supabase
    .from('project_composition_partners')
    .upsert(partnerRows, {
      onConflict: 'extraction_run_id,container_finding_id,pdv_id',
    });
  if (insErr) {
    await logger.warn(
      'composeFindings',
      `partner insert failed: ${insErr.message}`
    );
    summary.duration_ms = Date.now() - startedMs;
    return summary;
  }
  summary.edges_written = edges.length;

  // ---- Step E2: aggregate per-PDV MIN factor in JS.
  const minByPdv = new Map<string, number>();
  for (const e of edges) {
    const cur = minByPdv.get(e.pdv_id);
    if (cur === undefined || e.composition_factor < cur) {
      minByPdv.set(e.pdv_id, e.composition_factor);
    }
  }

  // Track suppressions-to-zero (a fully unreachable downstream).
  for (const factor of minByPdv.values()) {
    if (factor === 0) summary.suppressions_to_zero += 1;
  }

  // ---- Step E3: RPC fold.
  const updates = Array.from(minByPdv.entries()).map(([pdv_id, factor]) => ({
    pdv_id,
    factor,
  }));
  const { data: rpcData, error: rpcErr } = await supabase.rpc(
    'apply_composition_results',
    { p_project_id: projectId, p_run_id: runId, p_updates: updates }
  );
  if (rpcErr) {
    await logger.warn(
      'composeFindings',
      `apply_composition_results failed: ${rpcErr.message}`
    );
    summary.duration_ms = Date.now() - startedMs;
    return summary;
  }
  summary.pdvs_updated = typeof rpcData === 'number' ? rpcData : minByPdv.size;
  summary.composition_coverage_pct =
    summary.partnerable_pdv > 0
      ? Number(((minByPdv.size / summary.partnerable_pdv) * 100).toFixed(1))
      : 0;
  summary.duration_ms = Date.now() - startedMs;
  await logComposeSummary(logger, summary);
  return summary;
}

async function logComposeSummary(
  logger: ScannerSubprocessLogger,
  summary: ComposeFindingsSummary
): Promise<void> {
  try {
    await logger.info(
      'composition',
      `composeFindings.summary partnerable_pcf=${summary.partnerable_pcf} ` +
        `partnerable_pdv=${summary.partnerable_pdv} edges_written=${summary.edges_written} ` +
        `pdvs_updated=${summary.pdvs_updated} suppressions_to_zero=${summary.suppressions_to_zero} ` +
        `coverage_pct=${summary.composition_coverage_pct} duration_ms=${summary.duration_ms}`
    );
  } catch {
    /* logging is best-effort */
  }
}

// Internal test seam.
export const _internal = {
  CODE_REACHABILITY_WEIGHTS,
  CONTAINER_UNREACHABLE_MULT,
  pdvCveSet,
  pcfMatchesPdv,
  round3,
};
