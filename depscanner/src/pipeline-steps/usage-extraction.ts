/**
 * STEP: Usage extraction (tree-sitter) + framework entry-point detection.
 *
 * Replaces the old oxc-based npm-only AST pass. Language modules land
 * across Phase 2 milestones; unsupported ecosystems silently produce an
 * empty result and the step still succeeds.
 *
 * Sets ctx.astParsedSuccessfully when the tree-sitter pass produced files
 * AND its persistence write succeeded (or when no files were produced and
 * no per-file errors fired). finalize uses this to stamp ast_parsed_at on
 * project_repositories so the UI can flag projects with successful AST
 * coverage.
 */

import { runStage } from '../pipeline-stage-runner';
import { logStepError, classifyError } from '../with-timeout';
import { extractUsage, type SupportedEcosystem } from '../tree-sitter-extractor';
import { storeUsageExtractionResults } from '../tree-sitter-extractor/storage';
import { getDetectorErrorSummary, resetDetectorErrors } from '../tree-sitter-extractor/detector-errors';
import { storeEntryPoints } from '../framework-rules/storage';
import { buildEntryPointAuthMap, runPostProcess, summarizeAttackSurface } from '../framework-rules/build-auth-map';
import { resolveMountPrefixes } from '../param-harvest/mount-prefix';
import { updateStep } from '../pipeline-helpers';
import type { PipelineContext } from '../pipeline-types';

export async function doUsageExtraction(ctx: PipelineContext): Promise<void> {
  const { supabase, job, projectId, organizationId, log, workspaceRoot, jobEcosystem, runId } = ctx;
  await updateStep(supabase, projectId, 'usage_extraction');

  await runStage({
    name: 'usage_extraction',
    timeoutMs: 5 * 60_000,
    severity: 'warn',
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    fn: async () => {
      const deps: Array<{ name: string; namespace: string | null }> = [];
      {
        const { data: depRows, error: depFetchErr } = await supabase
          .from('project_dependencies')
          .select('name, namespace')
          .eq('project_id', projectId)
          .eq('last_seen_extraction_run_id', runId);
        if (depFetchErr) {
          await log.warn('usage_extraction', `Failed to load dependency list for import resolution: ${depFetchErr.message}`);
          throw depFetchErr;
        }
        for (const row of (depRows ?? []) as Array<{ name: string; namespace: string | null }>) {
          if (row.name) deps.push({ name: row.name, namespace: row.namespace ?? null });
        }
      }

      const supportedEcosystems: readonly SupportedEcosystem[] = [
        'npm', 'pypi', 'maven', 'golang', 'gem', 'composer', 'cargo', 'nuget',
      ];
      if (!supportedEcosystems.includes(jobEcosystem as SupportedEcosystem)) {
        ctx.astParsedSuccessfully = true;
        return;
      }

      let perFileErrorCount = 0;
      // Hard cap so a huge monorepo can't accumulate unbounded results and
      // OOM/timeout the worker.
      const MAX_FILES = 50_000;
      resetDetectorErrors();
      const result = await extractUsage({
        workspaceRoot,
        ecosystem: jobEcosystem as SupportedEcosystem,
        deps,
        maxFiles: MAX_FILES,
        onFileError: (filePath, fileErr) => {
          perFileErrorCount++;
          if (perFileErrorCount <= 5) {
            log.warn('usage_extraction', `Failed to parse ${filePath}: ${fileErr.message}`).catch(() => {});
            // Match the 5-log cap: persist the same first-5 per-file
            // errors so ops triage sees what surfaced in the realtime
            // stream. The outer timeout/throw catch (below) covers the
            // tail; this fills in granular tree-sitter failures.
            if (job.jobId) {
              const { code, message, stack } = classifyError(fileErr);
              logStepError(supabase, {
                jobId: job.jobId,
                projectId,
                step: 'usage_extraction',
                code,
                message: `${filePath}: ${message}`,
                stack,
                severity: 'warn',
              }).catch(() => {});
            }
          }
        },
      });

      // A grammar that failed to load means an entire language was skipped —
      // surface it loudly and don't claim full AST coverage.
      const grammarsFailed = result.failedGrammars.length > 0;
      if (grammarsFailed) {
        await log.warn('usage_extraction', `Tree-sitter grammar load failed for: ${result.failedGrammars.join(', ')} — those languages were skipped`);
      }

      if (result.files.length === 0) {
        if (perFileErrorCount > 0 || grammarsFailed) {
          await log.warn('usage_extraction', `Extractor returned zero files (per-file errors: ${perFileErrorCount}, grammar failures: ${result.failedGrammars.length}) — treating as soft failure`);
        } else {
          ctx.astParsedSuccessfully = true;
        }
        return;
      }

      const storeResult = await storeUsageExtractionResults(
        supabase,
        projectId,
        organizationId,
        runId,
        jobEcosystem,
        result,
      );
      if (storeResult.success && !grammarsFailed) {
        ctx.astParsedSuccessfully = true;
      } else if (storeResult.error) {
        await log.warn('usage_extraction', `Usage-extraction write failed: ${storeResult.error}`);
        if (job.jobId) {
          await logStepError(supabase, {
            jobId: job.jobId,
            projectId,
            step: 'usage_extraction',
            code: 'usage_store_failed',
            message: storeResult.error,
            severity: 'warn',
          });
        }
      }

      // Framework entry-point detection. Each language module already ran
      // its registered detectors during extraction (output attached to
      // ExtractedFile.entryPoints); here we just persist them. The step
      // is logged separately so users see the attribution in CLI output.
      await updateStep(supabase, projectId, 'framework_detection');
      // Compose express router mount prefixes onto served paths
      // (app.use('/api', router) → router.get('/x') becomes '/api/x'), in
      // memory before persistence, so the DAST synthesizer points ZAP at the
      // real URL. Pure mutation of result.files[*].entryPoints; no I/O.
      resolveMountPrefixes(result.files);
      // Count HTTP-route entry points from the just-detected (not re-detected)
      // entry points. Threaded to the reachability classifier as the "deployed
      // web app" signal that gates the always-on framework-runtime promotion
      // (see reachability.ts / reachability-feature-preconditions.ts). Counted
      // from the in-memory detector output so it's independent of the DB write
      // succeeding.
      let httpEntryPointCount = 0;
      for (const file of result.files) {
        for (const ep of file.entryPoints ?? []) {
          if (ep.entryPointType === 'http_route') httpEntryPointCount++;
        }
      }
      ctx.httpEntryPointCount = httpEntryPointCount;

      // Build the per-route auth map the taint engine joins each flow against
      // (entry-point auth classification, T2). Order is load-bearing:
      // detect (done during extraction) → resolveMountPrefixes (above) →
      // postProcess (cross-file re-homing) → build map → storeEntryPoints. The
      // map is built BEFORE the DB write so it exists even if the write fails
      // (retry-safe; no step-resume). postProcess RETURNS ctx-only records —
      // never appends to file.entryPoints — so httpEntryPointCount + the
      // persisted rows are untouched by it. A throwing postProcess is contained
      // per-detector; the whole assembly is ALSO guarded so a bug in map-building
      // or the attack-surface tally can never skip storeEntryPoints below — the
      // map is best-effort scoring context, but project_entry_points is durable.
      try {
        const postProcessRecords = await runPostProcess(result.files, workspaceRoot);
        ctx.entryPointAuth = buildEntryPointAuthMap(result.files, postProcessRecords, workspaceRoot);
        const surface = summarizeAttackSurface(result.files);
        if (surface.public + surface.authenticated + surface.background > 0) {
          await log.info(
            'framework_detection',
            `Attack surface: ${surface.public} public · ${surface.authenticated} authenticated · ${surface.background} background routes`,
          );
        }
      } catch (err) {
        // Degrade to the legacy no-map path (every flow stamps the PUBLIC
        // constant) rather than blocking entry-point persistence.
        ctx.entryPointAuth = new Map();
        await log.warn(
          'framework_detection',
          `Entry-point auth map build failed; scoring context degrades to public: ${err instanceof Error ? err.message : String(err)}`,
        );
      }

      const entryResult = await storeEntryPoints(supabase, projectId, runId, result.files, workspaceRoot);
      if (!entryResult.success && entryResult.error) {
        await log.warn('framework_detection', `Entry-point write failed: ${entryResult.error}`);
        if (job.jobId) {
          await logStepError(supabase, {
            jobId: job.jobId,
            projectId,
            step: 'usage_extraction',
            code: 'entry_point_write_failed',
            message: entryResult.error,
            severity: 'warn',
          });
        }
      } else if (entryResult.count > 0) {
        await log.info('framework_detection', `Detected ${entryResult.count} framework entry point(s)`);
      }

      // Surface detector exceptions once — a bare per-file catch would
      // otherwise silently zero a framework's entry points across the repo.
      const detectorErrors = getDetectorErrorSummary();
      if (detectorErrors.total > 0 && detectorErrors.firstError) {
        const offenders = Object.entries(detectorErrors.perDetector)
          .map(([name, count]) => `${name} (${count})`)
          .join(', ');
        await log.warn(
          'framework_detection',
          `${detectorErrors.total} detector error(s) across [${offenders}]; first: ${detectorErrors.firstError.detector}: ${detectorErrors.firstError.message}`,
        );
      }
    },
    // non-fatal — runner persists the failure as warn and swallows.
  });
}
