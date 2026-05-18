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
      const entryResult = await storeEntryPoints(supabase, projectId, runId, result.files);
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
