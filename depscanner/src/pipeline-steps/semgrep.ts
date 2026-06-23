/**
 * STEP: Semgrep static analysis (OPTIONAL).
 *
 * Runs Semgrep with a pinned `p/default` registry ruleset against the workspace,
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
    severity: 'warn',
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    onError: async ({ err }) => {
      const e = err as { status?: number; message?: string };
      const msg = e?.status === 137
        ? 'Static analysis ran out of memory'
        : `Static analysis failed: ${e?.message ?? 'unknown error'}`;
      // SAST is supplementary: a Semgrep crash (OOM, registry fetch failure,
      // a file it can't parse) must NOT discard a scan that
      // already resolved dependencies, dep-CVEs, secrets, IaC and container
      // findings. Degrade to "no SAST findings this run" and let the pipeline
      // continue instead of failing the whole extraction.
      await log.warn('semgrep', `${msg} — continuing without static-analysis findings`);
      return { rethrow: false };
    },
    fn: async () => {
      const semgrepPath = path.join(workspaceRoot, 'semgrep.json');
      // Pinned registry pack instead of `--config auto`. `auto` performs an
      // extra project-registration round-trip to semgrep.dev to tailor the
      // ruleset, and that call is what flakes: when it fails Semgrep aborts
      // before writing ANY output, silently disabling SAST for the run — which
      // is why fastapi produced zero findings while same-language django/flask
      // scanned fine. `p/default` is a plain, cacheable rule pack (pre-warmed
      // into the worker image), and `--disable-version-check` + `--metrics off`
      // drop the remaining phone-home calls so the step doesn't hang on a live
      // network fetch. stderr is intentionally NOT redirected to /dev/null so a
      // real failure surfaces its reason in the step log.
      const semgrepCmd =
        `semgrep scan --config p/default --disable-version-check --metrics off ` +
        `--json --output "${semgrepPath}" "${workspaceRoot}"`;
      try {
        execSync(semgrepCmd, {
          stdio: 'pipe',
          timeout: 19 * 60_000,
          maxBuffer: 64 * 1024 * 1024,
          // PYTHONNOUSERSITE=1: dependency resolution for some projects pip-installs the
          // repo's own deps into the worker user-site (~/.local). A fixture pinning an
          // OLD pydantic (v1) then shadows the system pydantic v2 that Semgrep's CLI
          // imports (`semgrep → mcp → pydantic.TypeAdapter`), crashing Semgrep with an
          // ImportError before it writes anything (observed on dogfood-fastapi). Ignoring
          // the user-site makes Semgrep use its own bundled pydantic, immune to whatever
          // the scanned project dragged in.
          env: { ...process.env, PYTHONNOUSERSITE: '1' },
        });
      } catch (e: any) {
        // Semgrep exits non-zero on a partial scan (e.g. status 1 — some
        // target files failed to parse) while still writing a complete
        // results file. Only treat it as a real failure when no output
        // landed; otherwise proceed with the partial results it produced.
        if (!fs.existsSync(semgrepPath)) {
          // Surface the captured stderr (no longer redirected to /dev/null) so
          // the log says *why* it died — registry fetch, parse crash, OOM —
          // instead of a bare "Command failed". Preserve `status` so the
          // onError OOM check (137) still fires.
          const stderrTail = (e?.stderr ? String(e.stderr) : '')
            .split('\n')
            .map((s: string) => s.trim())
            .filter(Boolean)
            .slice(-6)
            .join(' | ');
          const enriched: any = new Error(
            stderrTail ? `${e?.message ?? 'semgrep failed'} — ${stderrTail}` : (e?.message ?? 'semgrep failed'),
          );
          enriched.status = e?.status;
          throw enriched;
        }
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
              // Filter out Kubernetes manifest rules — Checkov owns IaC/k8s and
              // reports the same misconfigs (privileged container, allowPrivilege
              // Escalation, …) with rule docs + compliance refs. Semgrep's
              // yaml.kubernetes.* pack just double-reports them on the same file.
              .filter((r: any) => !(r.check_id ?? '').startsWith('yaml.kubernetes.'))
              // Filter out Dockerfile rules for the same reason — Checkov owns
              // Dockerfile IaC (CKV_DOCKER_*) and reports the same misconfigs with
              // rule docs + compliance refs. e.g. dockerfile.security.last-user-is-root
              // is a literal duplicate of CKV_DOCKER_8. Drop the namespace so the
              // user sees each Dockerfile misconfig once, from Checkov.
              .filter((r: any) => !(r.check_id ?? '').startsWith('dockerfile.'))
              // Filter out "missing middleware" best-practice nudges
              // (express-check-*-usage: csurf, helmet, directory-listing, …).
              // These are context-blind ABSENCE checks: they fire on every express
              // app that doesn't import the middleware — including token-auth JSON
              // APIs that legitimately don't need it — and anchor confusingly on the
              // `const app = express()` line (the absence has no real line to flag).
              // INFO severity, high false-positive rate, zero reachability signal.
              .filter((r: any) => !(r.check_id ?? '').includes('express-check-'))
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
