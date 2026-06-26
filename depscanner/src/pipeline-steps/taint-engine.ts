/**
 * STEP: Cross-file taint engine (Phase 6, shadow mode).
 *
 * Runs the deterministic forward-propagation taint engine against the
 * cloned workspace. Output goes to project_reachable_flows with
 * reachability_source='taint_engine' and is picked up by the
 * updateReachabilityLevels classifier the same way atom flows are.
 *
 * Sits AFTER rule_generation so the engine's flow writes land in
 * the same finalize cluster as atom + reachability_rules. Earlier
 * (pre-dep-scan) placement orphaned engine rows when a later step
 * failed and finalize_extraction never ran.
 *
 * Policy (locked decisions from feature-brief):
 *   - HARD-FAIL: any engine exception aborts the extraction. Soft
 *     degradation only via the staged rollout pct + circuit breaker.
 *   - 30-minute hard timeout (the engine's M2 perf budget is 2min on a
 *     medium project — 30min covers M5+ AI passes too).
 *   - Circuit breaker: org-scoped failure-rate killswitch. Skips if
 *     >5% of last 60min failed (≥5-run minimum sample).
 *   - Rollout pct: DEPTEX_TAINT_ENGINE_ROLLOUT_PCT gates the engine
 *     across the fleet. Default 0 in production until M8 retirement
 *     gates are met.
 *
 * Returned bag: validOsvIds (set of CVE ids whose FrameworkSpec actually
 * loaded — the classifier uses this for defense-in-depth) plus the AI
 * fp-filter cost in USD (EPD step folds this into its burn-breaker
 * ceiling so fp-filter + Anthropic don't compound past the 25%-of-
 * monthly-cap per-extraction ceiling).
 */

import { withTimeout, logStepError, classifyError } from '../with-timeout';
import {
  runEngine as runTaintEngine,
  shouldRunForOrg as shouldRunTaintEngineForOrg,
  writeFlows as writeTaintEngineFlows,
  writeRun as writeTaintEngineRun,
  checkCircuitBreaker as checkTaintEngineCircuitBreaker,
  maybeEngageKillswitch as maybeEngageTaintEngineKillswitch,
  loadCveSpecsForExtraction,
  createOsvIdResolver,
  type ResolvedDep,
} from '../taint-engine';
import { buildPurl } from '../purl';
import { updateStep, setError } from '../pipeline-helpers';
import type { PipelineContext } from '../pipeline-types';

export interface TaintEngineOutput {
  validOsvIds: Set<string>;
  fpFilterCostUsd: number;
  /**
   * osv_id → the vulnerable call patterns (FrameworkSink.pattern) of every
   * CVE-targeted spec sink that loaded this run. The reachability classifier
   * uses these to verify whether a CVE's *specific vulnerable symbol* is on a
   * call path before assigning the `function` tier — see
   * `updateReachabilityLevels`. Empty when no CVE-targeted specs loaded.
   */
  cveSinkPatterns: Map<string, string[]>;
  /**
   * v3 (precision arc): lowercase set of dep package names the engine's
   * callgraph confirmed are reached by at least one CallEdge from workspace
   * code. JS callgraph populates this from resolved `node_modules/*` paths;
   * per-language callgraphs land their extractors in follow-up commits.
   * Empty Set means either the callgraph didn't extract for this language
   * yet, the engine was rollout-gated off, or the workspace genuinely calls
   * nothing — the classifier treats empty as "no signal" and falls back to
   * the v2 heuristic for every transitive.
   */
  usedDependencies: Set<string>;
}

/**
 * Confirm-or-deny aliases: extra CVEs that target the SAME vulnerable symbol as
 * a framework-model sink but which the SBOM/VDB reports under a different OSV
 * id (so the engine never tagged a sink with them). Seeded into cveSinkPatterns
 * so the reachability classifier's vulnerable-symbol check can demote them to
 * `unreachable` when the app never calls the symbol — exactly as it already
 * does for the primary CVE — instead of leaving them at the weaker `module`
 * fallback.
 *
 * These feed ONLY the confirm-or-deny check, never flow emission, so they carry
 * zero snapshot/flow impact. The classifier matches symbols by SUBSTRING, so
 * every token here must be DISTINCTIVE: `res.redirect` → `redirect` is safe; a
 * bare lodash `set` / `trim` would false-match `res.set` / String.trim and is
 * intentionally omitted until the matcher does word-boundary matching.
 */
const CONFIRM_OR_DENY_CVE_ALIASES: Record<string, string[]> = {
  // Express response.redirect CVEs — CVE-2024-43796 (XSS via response.redirect)
  // and CVE-2024-29041 (open redirect) share the identical `res.redirect` sink.
  // These live HERE (the PDV-side symbol check) rather than as an `osv_id` on
  // the bundled express.yaml sink: a bundled framework-model loads for EVERY JS
  // project, so stamping its sink with these Express CVEs false-attributed them
  // onto non-Express apps (e.g. Next.js). Keyed here, the confirm-or-deny symbol
  // check only fires for a PDV that actually carries the CVE (i.e. express IS a
  // vulnerable dependency) and never stamps an arbitrary res.redirect flow.
  'CVE-2024-43796': ['res.redirect(*)'],
  'CVE-2024-29041': ['res.redirect(*)'],
  // lodash prototype pollution via `_.unset` (CVE-2025-13465). `unset` is a
  // distinctive token; an app that only calls `_.template` never trips it.
  'CVE-2025-13465': ['_.unset(*)'],
};

export async function doTaintEngine(ctx: PipelineContext): Promise<TaintEngineOutput> {
  const { supabase, job, projectId, organizationId, log, workspaceRoot, runId } = ctx;

  // Phase 6.5 / M5 — set of CVE ids whose FrameworkSpec actually loaded for
  // this extraction. Lives outside the taint_engine block so the
  // updateReachabilityLevels call below can validate that every promoted
  // confirmed-tier flow has an osv_id matching a real loaded spec.
  const validOsvIds = new Set<string>();
  // osv_id → vulnerable call patterns from CVE-targeted spec sinks; consumed
  // by the reachability classifier for function-tier symbol verification.
  // Seeded with the confirm-or-deny aliases (extra CVEs sharing a framework
  // sink's symbol) so they apply on every return path; real cve-spec /
  // framework-model patterns merge on top below.
  const cveSinkPatterns = new Map<string, string[]>(
    Object.entries(CONFIRM_OR_DENY_CVE_ALIASES).map(([osv, pats]) => [osv, [...pats]]),
  );
  // v3 precision arc — lowercase npm/pypi/cargo/etc. package names the
  // engine's callgraph confirmed are reached. Empty here; populated when
  // the engine ran successfully and its callgraph carried usedDependencies.
  let usedDependencies = new Set<string>();
  let fpFilterCostUsd = 0;

  const stepStart = Date.now();
  await updateStep(supabase, projectId, 'taint_engine');

  if (!(await shouldRunTaintEngineForOrg(supabase, organizationId))) {
    await log.info('taint_engine', 'Skipped: rollout pct gate (DEPTEX_TAINT_ENGINE_ROLLOUT_PCT or rollout_pct_override)');
    await writeTaintEngineRun(supabase, {
      projectId,
      organizationId,
      extractionRunId: runId,
      status: 'skipped',
      totalMs: Date.now() - stepStart,
      errorCode: 'rollout_gate',
    });
    return { validOsvIds, fpFilterCostUsd, cveSinkPatterns, usedDependencies };
  }

  const breaker = await checkTaintEngineCircuitBreaker(supabase, organizationId);
  if (!breaker.shouldRun) {
    await log.warn(
      'taint_engine',
      `Skipped: circuit breaker ${breaker.blockedReason} (${breaker.recentFailures}/${breaker.recentRuns} failures = ${breaker.failurePct.toFixed(1)}%)`,
    );
    await writeTaintEngineRun(supabase, {
      projectId,
      organizationId,
      extractionRunId: runId,
      status: 'skipped',
      totalMs: Date.now() - stepStart,
      errorCode: breaker.blockedReason ?? 'circuit_breaker',
    });
    return { validOsvIds, fpFilterCostUsd, cveSinkPatterns, usedDependencies };
  }

  // Mark the run as 'running' first so a crash mid-engine still
  // leaves a row the breaker can see. The terminal upsert below
  // overwrites status + telemetry on success/failure.
  await writeTaintEngineRun(supabase, {
    projectId,
    organizationId,
    extractionRunId: runId,
    status: 'running',
  });

  // Phase 6.5 — pull CVE-targeted FrameworkSpec rows from
  // organization_generated_rules for the CVEs dep-scan detected
  // this extraction, plus the (osv_id → dependency_id, purl) map
  // the engine's writeFlows resolver needs to promote them to
  // confirmed-tier in the classifier. Both happen before the
  // engine call so a DB hiccup surfaces as a warn-and-continue
  // rather than a mid-engine failure (the engine still runs the
  // framework-generic pass with whatever specs validated).
  const detectedCves = new Set<string>();
  const depsByOsvId = new Map<string, ResolvedDep>();
  {
    const { data: pdvRows, error: pdvErr } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('osv_id, project_dependency_id, aliases')
      .eq('project_id', projectId)
      .eq('extraction_run_id', runId);
    if (pdvErr) {
      await log.warn(
        'taint_engine',
        `cve-specs PDV preload failed: ${pdvErr.message} (continuing with framework-generic specs only)`,
      );
    } else {
      const pdvList = (pdvRows ?? []) as Array<{
        osv_id: string | null;
        project_dependency_id: string | null;
        aliases: string[] | null;
      }>;
      const pdIds = new Set<string>();
      for (const r of pdvList) {
        // Expand to CVE-shaped osv_id + any CVE-shaped alias. Some
        // advisories (e.g. log4shell) arrive with GHSA-xxx as the
        // primary id with the CVE in aliases; without expansion the
        // generated framework_spec keyed on CVE-id never matches.
        if (typeof r.osv_id === 'string' && r.osv_id.startsWith('CVE-')) {
          detectedCves.add(r.osv_id);
        }
        if (Array.isArray(r.aliases)) {
          for (const a of r.aliases) {
            if (typeof a === 'string' && a.startsWith('CVE-')) detectedCves.add(a);
          }
        }
        if (r.project_dependency_id) pdIds.add(r.project_dependency_id);
      }
      if (pdIds.size > 0) {
        const { data: pdRows, error: pdErr } = await supabase
          .from('project_dependencies')
          .select('id, name, version, dependency_id')
          .in('id', Array.from(pdIds));
        if (pdErr) {
          await log.warn(
            'taint_engine',
            `cve-specs project_dependencies lookup failed: ${pdErr.message} (CVE-tagged flows will fall through to unresolved)`,
          );
        } else {
          const pdRowMap = new Map<
            string,
            { name: string; version: string | null; dependency_id: string | null }
          >();
          for (const r of (pdRows ?? []) as Array<{
            id: string;
            name: string;
            version: string | null;
            dependency_id: string | null;
          }>) {
            pdRowMap.set(r.id, {
              name: r.name,
              version: r.version,
              dependency_id: r.dependency_id,
            });
          }
          // Resolve dependency.ecosystem the same way the
          // reachability_rules step does — eco lives on the
          // dependencies table, not project_dependencies.
          const depIds = new Set<string>();
          for (const pd of pdRowMap.values()) {
            if (pd.dependency_id) depIds.add(pd.dependency_id);
          }
          const ecoByDepId = new Map<string, string>();
          if (depIds.size > 0) {
            const { data: depRows, error: depErr } = await supabase
              .from('dependencies')
              .select('id, ecosystem')
              .in('id', Array.from(depIds));
            if (depErr) {
              await log.warn(
                'taint_engine',
                `cve-specs dependencies lookup failed: ${depErr.message} (using project ecosystem fallback)`,
              );
            } else {
              for (const r of (depRows ?? []) as Array<{ id: string; ecosystem: string }>) {
                ecoByDepId.set(r.id, r.ecosystem);
              }
            }
          }
          for (const r of pdvList) {
            if (!r.osv_id || !r.project_dependency_id) continue;
            const pd = pdRowMap.get(r.project_dependency_id);
            if (!pd) continue;
            const eco =
              (pd.dependency_id ? ecoByDepId.get(pd.dependency_id) : undefined) ??
              job.ecosystem;
            if (!eco) continue;
            const purl = buildPurl(eco, pd.name, pd.version);
            if (!purl) continue;
            const resolved: ResolvedDep = { purl, dependencyId: pd.dependency_id };
            // Key the resolver under the PDV's primary osv_id AND every
            // CVE-shaped alias. CVE-targeted FrameworkSpecs are generated and
            // keyed by CVE id, so the engine emits flows with osv_id=CVE-xxxx.
            // When a PDV's primary id is a GHSA advisory (log4shell etc.) a
            // CVE-only lookup would miss and the flow would be written with a
            // null dependency_id — which the classifier can never promote to
            // `confirmed`. First write wins on a key collision (a single CVE
            // across two PDs — rare, e.g. a monorepo with duplicate deps).
            const osvKeys = [r.osv_id];
            if (Array.isArray(r.aliases)) {
              for (const a of r.aliases) {
                if (typeof a === 'string' && a.startsWith('CVE-')) osvKeys.push(a);
              }
            }
            for (const k of osvKeys) {
              if (!depsByOsvId.has(k)) depsByOsvId.set(k, resolved);
            }
          }
        }
      }
    }
  }

  const cveSpecResult = await loadCveSpecsForExtraction({
    storage: supabase,
    organizationId,
    detectedCves,
    onWarn: (m) => { void log.warn('taint_engine', m); },
  });
  if (cveSpecResult.failed.length > 0) {
    await log.warn(
      'taint_engine',
      `cve-specs: ${cveSpecResult.failed.length} row(s) failed schema validation (${cveSpecResult.failed.slice(0, 5).join(', ')}${cveSpecResult.failed.length > 5 ? ', …' : ''})`,
    );
  }
  // Phase 6.5 / M5 task 27 — surface every osv_id the loaded specs
  // tagged onto a sink. The classifier uses this to demote any
  // confirmed-tier promotion whose osv_id isn't in the set
  // (defense-in-depth for the JSONB CHECK + server-side substitution).
  for (const spec of cveSpecResult.specs) {
    for (const sink of spec.sinks) {
      if (!sink.osv_id) continue;
      validOsvIds.add(sink.osv_id);
      // Collect the vulnerable call pattern so the classifier can check
      // whether this CVE's specific symbol is actually on a call path.
      const patterns = cveSinkPatterns.get(sink.osv_id) ?? [];
      if (sink.pattern && !patterns.includes(sink.pattern)) patterns.push(sink.pattern);
      cveSinkPatterns.set(sink.osv_id, patterns);
    }
  }
  // Detected framework(s) for client-SPA scoping. A pure browser SPA
  // (framework=react/vue/…) has no server request boundary, so the engine
  // drops server application-framework specs + server-only vuln classes to
  // avoid the false-positive storm those produce on client code. Best-effort:
  // a missing/unknown framework leaves scoping off (full load-all behavior).
  let projectFrameworks: string[] | undefined;
  try {
    const { data: projRow } = await supabase
      .from('projects')
      .select('framework')
      .eq('id', projectId)
      .maybeSingle();
    const fw = (projRow as { framework?: string | null } | null)?.framework;
    if (fw && fw.trim()) projectFrameworks = [fw.trim()];
  } catch {
    // non-fatal — scoping just stays off
  }

  try {
    const engineResult = await withTimeout(
      async (signal) => runTaintEngine({
        workspaceRoot,
        ecosystem: job.ecosystem,
        signal,
        onWarn: (m) => { void log.warn('taint_engine', m); },
        cveSpecs: cveSpecResult.specs,
        projectFrameworks,
        fpFilter: {
          storage: supabase,
          organizationId,
          // No human triggered this extraction; we attribute the
          // platform AI spend to the org owner (the cost-cap
          // aggregator filters by organization_id, not user_id).
          userId: organizationId,
          projectId,
          extractionRunId: runId,
          // Phase 33: thread scan_jobs id so per-call cost rolls up
          // into the scan row + the per-scan cap is honoured.
          jobId: job.jobId,
        },
      }),
      30 * 60_000,
      'taint_engine',
    );

    if (!engineResult.ran || !engineResult.propagation) {
      await log.warn('taint_engine', `No-op: ${engineResult.skippedReason ?? 'unknown'}`);
      await writeTaintEngineRun(supabase, {
        projectId,
        organizationId,
        extractionRunId: runId,
        status: 'skipped',
        totalMs: Date.now() - stepStart,
        errorCode: 'no_specs_loaded',
      });
    } else if (engineResult.propagation.aborted) {
      // The worklist aborted mid-loop because the 30-min hard timeout fired.
      // propagation.flows is a PARTIAL set — un-walked CVEs would otherwise be
      // demoted to 'unreachable' by the downstream classifier on the strength
      // of absent flows. Stamp the run incomplete and SKIP the flow write so
      // the classifier has nothing to misread as a clean verdict.
      await log.warn(
        'taint_engine',
        `Aborted: 30-min hard timeout fired mid-propagation; partial flow set discarded (${engineResult.propagation.flows.length} flows walked so far)`,
      );
      await writeTaintEngineRun(supabase, {
        projectId,
        organizationId,
        extractionRunId: runId,
        status: 'aborted',
        callgraphBuildMs: engineResult.propagation.stats.callgraphMs,
        taintPropagationMs: engineResult.propagation.stats.propagationMs,
        totalMs: Date.now() - stepStart,
        flowsEmitted: engineResult.propagation.flows.length,
        errorCode: 'timeout_partial',
      });
    } else {
      const { propagation, frameworksLoaded, flowsAfterFilter, aiFilter, detectorFlows } = engineResult;
      // Fold the osv_ids the engine actually loaded — framework-model sinks
      // (e.g. lodash `_.template` → CVE-2021-23337) as well as the CVE-targeted
      // specs — into validOsvIds. Without this, a flow carrying a framework-model
      // osv_id would trip the classifier's osv_id drift guard (which only knew
      // about AI-generated CVE specs) and get demoted from `confirmed` to
      // `data_flow` plus a spurious `osv_id_drift_rejected` security event.
      for (const osv of engineResult.loadedOsvIds) validOsvIds.add(osv);
      // Fold every loaded sink's CVE→pattern mapping (framework-models +
      // CVE-specs) into the map the reachability classifier's M2
      // vulnerable-symbol check reads. This lets a framework CVE — e.g. express
      // `res.redirect(*)` → CVE-2024-43796 — be demoted to `unreachable` when
      // the app never calls the vulnerable function, instead of the weaker
      // `module` fallback. cve-spec patterns added above take precedence; this
      // only fills in osv_ids the cve-specs didn't already cover.
      for (const [osv, pats] of engineResult.loadedCveSinkPatterns) {
        const existing = cveSinkPatterns.get(osv) ?? [];
        for (const p of pats) if (!existing.includes(p)) existing.push(p);
        cveSinkPatterns.set(osv, existing);
      }
      // v3 precision — surface usedDependencies for the reachability
      // classifier even when zero specs matched / zero flows emitted: the
      // callgraph may still have crossed into dep code and we want to
      // credit those deps. Empty set when the engine's callgraph didn't
      // extract for this language (per-language extractors land later).
      usedDependencies = engineResult.usedDependencies ?? new Set();
      const taintSurvivors = flowsAfterFilter ?? propagation.flows;
      // Detector flows (Phase F4 sanitizer-absence + Phase 3.3 insecure-default)
      // are LLM-checked alongside taint flows and ride into
      // project_reachable_flows. Empty for projects whose specs don't carry
      // required_arguments / insecure_defaults entries.
      const survivors = detectorFlows.length > 0
        ? [...taintSurvivors, ...detectorFlows]
        : taintSurvivors;
      const writeResult = await writeTaintEngineFlows(supabase, {
        projectId,
        extractionRunId: runId,
        flows: survivors,
        filterVerdicts: aiFilter?.verdicts,
        workspaceRoot,
        resolveDep: createOsvIdResolver(depsByOsvId),
      });
      for (const e of writeResult.errors) {
        await log.warn('taint_engine', `flow write: ${e}`);
      }
      fpFilterCostUsd = aiFilter?.costUsd ?? 0;
      await writeTaintEngineRun(supabase, {
        projectId,
        organizationId,
        extractionRunId: runId,
        status: 'completed',
        callgraphBuildMs: propagation.stats.callgraphMs,
        taintPropagationMs: propagation.stats.propagationMs,
        aiFpFilterMs: aiFilter?.invoked ? aiFilter.durationMs : undefined,
        totalMs: Date.now() - stepStart,
        flowsEmitted: propagation.flows.length,
        flowsAfterAiFilter: survivors.length,
        aiCostUsd: fpFilterCostUsd,
        frameworksDetected: frameworksLoaded,
        isTypedJsProject: propagation.callgraph.isTypedJsProject,
        typedFilesPct: propagation.callgraph.typedFilesPct,
        // When the organization_generated_rules read failed, the engine ran
        // the framework-generic pass only — every CVE-targeted verdict is
        // missing. Stamp the run so the classifier can tell this apart from
        // a genuine 0-CVE project rather than silently demoting CVEs.
        errorCode: cveSpecResult.dbError ? 'cve_specs_db_error' : undefined,
      });
      const detectorSuffix =
        detectorFlows.length > 0 ? ` + ${detectorFlows.length} detector finding(s)` : '';
      if (aiFilter?.invoked) {
        await log.success(
          'taint_engine',
          `Emitted ${propagation.flows.length} flows${detectorSuffix}; AI filter checked ${aiFilter.flowsChecked}, rejected ${aiFilter.flowsRejected} (kept ${survivors.length}). Cost $${aiFilter.costUsd.toFixed(4)}. ${propagation.stats.totalMs}ms total.`,
          Date.now() - stepStart,
        );
      } else {
        const reason = aiFilter?.skippedReason ? ` (filter skipped: ${aiFilter.skippedReason})` : '';
        await log.success(
          'taint_engine',
          `Emitted ${propagation.flows.length} flows${detectorSuffix} from ${frameworksLoaded.length} framework spec(s) in ${propagation.stats.totalMs}ms${reason}`,
          Date.now() - stepStart,
        );
      }
    }
  } catch (err: unknown) {
    // HARD-FAIL: log telemetry, maybe engage killswitch, then rethrow.
    const { code, message, stack } = classifyError(err);
    await writeTaintEngineRun(supabase, {
      projectId,
      organizationId,
      extractionRunId: runId,
      status: 'failed',
      totalMs: Date.now() - stepStart,
      errorCode: code,
      errorMessage: message,
    });
    // Killswitch is best-effort — never let an RPC error here
    // shadow the original engine failure being reported below.
    try {
      const engaged = await maybeEngageTaintEngineKillswitch(
        supabase,
        organizationId,
        `taint_engine ${code}: ${message.slice(0, 200)}`,
      );
      if (engaged) {
        await log.warn('taint_engine', 'Killswitch engaged: failure rate exceeded threshold');
      }
    } catch (killswitchErr: unknown) {
      const ksMsg = killswitchErr instanceof Error ? killswitchErr.message : String(killswitchErr);
      await log.warn('taint_engine', `Killswitch RPC failed: ${ksMsg}`);
    }
    if (job.jobId) {
      await logStepError(supabase, {
        jobId: job.jobId,
        projectId,
        step: 'taint_engine',
        code,
        message,
        stack,
        durationMs: Date.now() - stepStart,
        severity: 'error',
      });
    }
    await setError(supabase, projectId, `Taint engine failed: ${message}`);
    throw err;
  }

  return { validOsvIds, fpFilterCostUsd, cveSinkPatterns, usedDependencies };
}
