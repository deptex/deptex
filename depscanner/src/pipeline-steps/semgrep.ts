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
import { isPureClientSpa } from '../taint-engine/runner';
import type { PipelineContext } from '../pipeline-types';

/**
 * Noise filter for known low-signal `p/default` audit rules. Matched by
 * substring against the Semgrep `check_id` (rule_id) so a rule's full
 * namespace prefix doesn't have to be spelled out.
 *
 * - `drop`: the finding is discarded entirely (never persisted). Reserved for
 *   audit rules that carry no real signal on JS/TS, e.g. the printf
 *   format-string check — JavaScript has no printf format-string semantics, so
 *   it only ever fires on plain template literals (`console.error(`…${x}`, e)`).
 * - `downrank`: the finding is kept but forced to the lowest severity tier so
 *   it drops out of the default WARNING view. Reserved for notoriously noisy
 *   audit rules that occasionally matter, e.g. non-literal-RegExp (ReDoS),
 *   which fires on ANY `new RegExp(variable)` even when the value is a fixed
 *   literal/enum.
 */
const SEMGREP_NOISE_RULES: { drop: string[]; downrank: string[] } = {
  drop: ['unsafe-formatstring'],
  downrank: ['detect-non-literal-regexp'],
};

/**
 * Semgrep rules that are pure noise on a CLIENT-SIDE SPA (react / vue / svelte /
 * angular / …). Each targets a server-runtime construct or a self-DoS-only issue
 * that cannot be a real exploit once the code ships to a browser:
 *   - detect-non-literal-regexp        — ReDoS only hangs the user's OWN tab
 *     (self-DoS), never a shared server thread; CWE-1333 is a server concern.
 *   - detect-non-literal-fs-filename   — Node `fs`; no filesystem in a browser.
 *   - detect-child-process             — Node `child_process`; N/A in a browser.
 *   - detect-non-literal-require       — Node dynamic `require`; bundled SPAs
 *     resolve imports statically at build time.
 *   - detect-no-csrf-before-method-override — Express CSRF middleware; server-only.
 * Applied ONLY when the project's framework is a pure client SPA (isPureClientSpa);
 * server / SSR projects keep every rule. Matched by substring against the rule_id,
 * same as SEMGREP_NOISE_RULES.
 *
 * ▶ This is the place to silence future frontend-irrelevant Semgrep rules: add
 *   the rule-id substring here and a client SPA stops showing it. (For rules that
 *   are noise on EVERY project regardless of framework, use SEMGREP_NOISE_RULES
 *   above instead.)
 */
const SEMGREP_CLIENT_SPA_DROP_RULES: string[] = [
  'detect-non-literal-regexp',
  'detect-non-literal-fs-filename',
  'detect-child-process',
  'detect-non-literal-require',
  'detect-no-csrf-before-method-override',
];

// Lowest/least-severe tier the rest of this step uses (the same value the
// mapping falls back to when a finding carries no severity). Downranked
// findings are pinned here so they leave the default WARNING view.
const SEMGREP_INFO_SEVERITY = 'INFO';

const matchesNoiseRule = (checkId: string, patterns: string[]): boolean =>
  patterns.some((p) => checkId.includes(p));

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

  // Client-SPA noise scoping: on a pure browser SPA, the server-runtime /
  // self-DoS rules in SEMGREP_CLIENT_SPA_DROP_RULES carry no real signal. Read
  // the project framework once up front. Best-effort — on any read failure the
  // scoping stays off and every rule applies (server-safe default).
  let isClientSpaProject = false;
  try {
    const { data: projFw } = await supabase
      .from('projects')
      .select('framework')
      .eq('id', projectId)
      .maybeSingle();
    const fw = (projFw as { framework?: string | null } | null)?.framework;
    isClientSpaProject = fw ? isPureClientSpa([fw]) : false;
  } catch {
    // non-fatal — scoping just stays off
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
              // Drop tier of the noise filter (SEMGREP_NOISE_RULES.drop): audit
              // rules with no real signal on JS/TS. unsafe-formatstring (CWE-134)
              // fires on plain template literals — JS has no printf semantics.
              .filter((r: any) => !matchesNoiseRule(r.check_id ?? '', SEMGREP_NOISE_RULES.drop))
              // Client-SPA scope: drop server-runtime / self-DoS rules that
              // cannot be a real exploit in a browser bundle (ReDoS self-DoS,
              // Node fs/child_process/require, Express CSRF). Server/SSR
              // projects keep them all.
              .filter((r: any) => !(isClientSpaProject && matchesNoiseRule(r.check_id ?? '', SEMGREP_CLIENT_SPA_DROP_RULES)))
              // Filter out generated/report files
              .filter((r: any) => {
                const p = r.path ?? '';
                return !p.includes('depscan-reports/') && !p.includes('node_modules/');
              })
              .map((r: any) => {
                // Downrank tier of the noise filter (SEMGREP_NOISE_RULES.downrank):
                // keep the finding but pin it to the lowest severity so it drops out
                // of the default WARNING view. detect-non-literal-regexp (ReDoS) fires
                // on any new RegExp(variable), including fixed literals/enums.
                const severity = matchesNoiseRule(r.check_id ?? '', SEMGREP_NOISE_RULES.downrank)
                  ? SEMGREP_INFO_SEVERITY
                  : r.extra?.severity ?? 'INFO';
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
            // Surface how much the noise filter trimmed/demoted from the raw
            // results so the choice is auditable in the step log.
            const rawResults: any[] = semgrepParsed.results;
            const droppedNoise = rawResults.filter((r) =>
              matchesNoiseRule(r.check_id ?? '', SEMGREP_NOISE_RULES.drop)).length;
            const downrankedNoise = rawResults.filter((r) =>
              matchesNoiseRule(r.check_id ?? '', SEMGREP_NOISE_RULES.downrank)).length;
            const droppedClientSpa = isClientSpaProject
              ? rawResults.filter((r) =>
                  matchesNoiseRule(r.check_id ?? '', SEMGREP_CLIENT_SPA_DROP_RULES)).length
              : 0;
            if (droppedNoise > 0 || downrankedNoise > 0 || droppedClientSpa > 0) {
              await log.info(
                'semgrep',
                `Noise filter: dropped ${droppedNoise}, downranked ${downrankedNoise}` +
                  (droppedClientSpa > 0 ? `, dropped ${droppedClientSpa} client-SPA-irrelevant` : '') +
                  ` low-signal finding(s)`,
              );
            }
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
