/**
 * STEP: Semgrep static analysis (OPTIONAL).
 *
 * Runs Semgrep with the bundled `auto` config against the workspace,
 * upserts results into project_semgrep_findings (deduped by
 * project_id, rule_id, file_path, start_line, extraction_run_id), and
 * stashes the raw JSON in project-imports storage. Filters out
 * generic.secrets.* (TruffleHog handles secrets better) and findings
 * inside our own intermediate output dirs (depscan-reports, node_modules).
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { runStage } from '../pipeline-stage-runner';
import { logStepError, classifyError } from '../with-timeout';
import { ScanFailedError } from '../scan-errors';
import { calculateSemgrepDepscore } from '../depscore';
import { binaryAvailable, INSTALL_HINTS } from '../pipeline-helpers';
import type { PipelineContext } from '../pipeline-types';

export async function doSemgrep(ctx: PipelineContext): Promise<void> {
  const { supabase, job, projectId, log, workspaceRoot, runId, importance } = ctx;

  if (!binaryAvailable('semgrep')) {
    // CLI/local dev legitimately lacks semgrep — skip quietly there.
    if (process.env.DEPTEX_CLI_MODE === '1') {
      await log.warn('semgrep', INSTALL_HINTS.semgrep);
      return;
    }
    // The worker image bundles semgrep, so a missing binary means a misbuilt
    // image that would silently ship SAST-off scans fleet-wide. Fail loudly.
    const msg = `Static analysis could not run: ${INSTALL_HINTS.semgrep}`;
    await log.error('semgrep', msg);
    if (job.jobId) {
      await logStepError(supabase, {
        jobId: job.jobId,
        projectId,
        step: 'semgrep',
        code: 'binary_missing_semgrep',
        message: INSTALL_HINTS.semgrep,
        severity: 'error',
      });
    }
    throw new ScanFailedError(msg);
  }

  await log.info('semgrep', 'Running static code analysis...');
  const semgrepStart = Date.now();
  await runStage({
    name: 'semgrep',
    timeoutMs: 20 * 60_000,
    severity: 'error',
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    onError: async ({ err }) => {
      const e = err as { status?: number; message?: string };
      const msg = e?.status === 137
        ? 'Static analysis ran out of memory'
        : `Static analysis failed: ${e?.message ?? 'unknown error'}`;
      await log.error('semgrep', msg);
      // severity: 'error' → rethrow; pipeline outer catch sets error state.
      return { rethrow: true, throwAs: new ScanFailedError(msg) };
    },
    fn: async () => {
      const semgrepPath = path.join(workspaceRoot, 'semgrep.json');
      try {
        execSync(`semgrep scan --config auto --json --output "${semgrepPath}" "${workspaceRoot}" 2>/dev/null`, {
          stdio: 'pipe',
          timeout: 19 * 60_000,
          maxBuffer: 64 * 1024 * 1024,
        });
      } catch (e: any) {
        // Semgrep exits non-zero on a partial scan (e.g. status 1 — some
        // target files failed to parse) while still writing a complete
        // results file. Only treat it as a real failure when no output
        // landed; otherwise proceed with the partial results it produced.
        if (!fs.existsSync(semgrepPath)) throw e;
        await log.warn('semgrep', `Semgrep exited non-zero (status ${e?.status ?? '?'}); using the partial results it wrote`);
      }
      if (fs.existsSync(semgrepPath)) {
        const content = fs.readFileSync(semgrepPath, 'utf8');
        let semgrepParsed: any = null;
        try {
          semgrepParsed = JSON.parse(content);
        } catch (e: any) {
          await log.warn('semgrep', `Semgrep emitted malformed JSON; findings for this run dropped: ${e?.message ?? e}`);
          if (job.jobId) {
            const { code, message, stack } = classifyError(e);
            await logStepError(supabase, {
              jobId: job.jobId,
              projectId,
              step: 'semgrep',
              code,
              message,
              stack,
              severity: 'warn',
            });
          }
        }
        try {
          await supabase.storage
            .from('project-imports')
            .upload(`${projectId}/${runId}/semgrep.json`, content, { contentType: 'application/json', upsert: true });
        } catch { /* upload failure non-fatal */ }

        if (semgrepParsed && Array.isArray(semgrepParsed.results) && semgrepParsed.results.length > 0) {
          try {
            const sanitizeMetadata = (metadata: any) => {
              if (!metadata) return {};
              const safe = { ...metadata };
              delete safe.source;
              delete safe.fix;
              return safe;
            };
            const findings = semgrepParsed.results
              // Filter out secret-detection rules (TruffleHog handles these better)
              .filter((r: any) => !(r.check_id ?? '').startsWith('generic.secrets.'))
              // Filter out generated/report files
              .filter((r: any) => {
                const p = r.path ?? '';
                return !p.includes('depscan-reports/') && !p.includes('node_modules/');
              })
              .map((r: any) => {
                const severity = r.extra?.severity ?? 'INFO';
                // Semgrep rule authors emit metadata.cwe / metadata.owasp as
                // either a string (e.g. "CWE-79") or an array depending on the
                // rule. The DB column is text[] and depscore calls .some() on
                // cweIds, so both branches need to land as arrays here.
                const cweIds: string[] = Array.isArray(r.extra?.metadata?.cwe)
                  ? r.extra.metadata.cwe
                  : r.extra?.metadata?.cwe != null
                  ? [String(r.extra.metadata.cwe)]
                  : [];
                const owaspIds: string[] = Array.isArray(r.extra?.metadata?.owasp)
                  ? r.extra.metadata.owasp
                  : r.extra?.metadata?.owasp != null
                  ? [String(r.extra.metadata.owasp)]
                  : [];
                const category = r.extra?.metadata?.category ?? 'security';
                // Semgrep reports absolute paths under the clone root (we invoke
                // it with the workspace as the scan target). Store repo-relative
                // so the UI never shows the ephemeral /tmp/deptex-extract-XXX/
                // clone dir, and so the path lines up with the other scanners'
                // relative paths. Keep the raw absolute path for the on-disk
                // snippet read below. Defensive: a path that resolves outside
                // the workspace (shouldn't happen) keeps its raw value.
                const rawPath = r.path ?? 'unknown';
                let filePath = rawPath;
                if (rawPath !== 'unknown' && path.isAbsolute(rawPath)) {
                  const rel = path.relative(workspaceRoot, rawPath).split(path.sep).join('/');
                  if (rel && !rel.startsWith('..')) filePath = rel;
                }
                const startLine = r.start?.line ?? null;

                // Extract code snippet around the affected line
                let codeSnippet: string | null = null;
                if (startLine != null && rawPath !== 'unknown') {
                  try {
                    const absPath = path.isAbsolute(rawPath) ? rawPath : path.join(workspaceRoot, rawPath);
                    if (fs.existsSync(absPath)) {
                      const fileLines = fs.readFileSync(absPath, 'utf8').split('\n');
                      const contextLines = 3;
                      const from = Math.max(0, startLine - 1 - contextLines);
                      const to = Math.min(fileLines.length, startLine + contextLines);
                      codeSnippet = fileLines.slice(from, to).join('\n');
                    }
                  } catch { /* non-fatal */ }
                }

                return {
                  project_id: projectId,
                  extraction_run_id: runId,
                  rule_id: r.check_id ?? 'unknown',
                  file_path: filePath,
                  start_line: startLine,
                  end_line: r.end?.line ?? null,
                  severity,
                  message: r.extra?.message ?? null,
                  cwe_ids: cweIds,
                  owasp_ids: owaspIds,
                  category,
                  metadata: sanitizeMetadata(r.extra?.metadata),
                  code_snippet: codeSnippet,
                  semgrep_fingerprint: r.extra?.fingerprint ?? null,
                  depscore: calculateSemgrepDepscore({ severity, cweIds, category, importance }),
                };
              });
            for (let i = 0; i < findings.length; i += 100) {
              await supabase.from('project_semgrep_findings').upsert(findings.slice(i, i + 100), {
                onConflict: 'project_id,rule_id,file_path,start_line,extraction_run_id',
              });
            }
          } catch (parseErr: any) {
            await log.warn('semgrep', `Failed to parse findings into DB: ${parseErr.message}`);
          }
        }

        await log.success('semgrep', 'Static analysis complete', Date.now() - semgrepStart);
      } else {
        await log.warn('semgrep', 'Static analysis skipped (Semgrep not installed)');
      }
    },
  });
}
