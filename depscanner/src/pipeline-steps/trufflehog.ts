/**
 * STEP: TruffleHog secret scanning (OPTIONAL).
 *
 * Runs TruffleHog filesystem against the workspace, upserts findings into
 * project_secret_findings (deduped by detector_type/file_path/start_line/
 * extraction_run_id), and stashes a sanitized JSON (Raw stripped) into
 * project-imports storage. Excludes our own intermediate output files
 * (sbom.json, dep-scan reports, semgrep.json, etc.) so we don't pick up
 * tokens from upstream tooling output.
 */

import * as fs from 'fs';
import * as path from 'path';
import { runStage } from '../pipeline-stage-runner';
import { logStepError } from '../with-timeout';
import { ScanFailedError } from '../scan-errors';
import { calculateSecretDepscore } from '../depscore';
import { binaryAvailable, INSTALL_HINTS } from '../pipeline-helpers';
import type { PipelineContext } from '../pipeline-types';

/**
 * Structural false-positive filter for TruffleHog's GitLab detector.
 *
 * TruffleHog's `Gitlab` detector pattern-matches on identifier/JWT-shaped
 * substrings (e.g. a TS interface field like `role_display_name?: string`, or
 * a generic `fetchWithAuth(...)` wrapper) and, when it can't reach GitLab to
 * confirm them, emits them UNVERIFIED. A genuine GitLab personal-access token
 * always carries the canonical `glpat-` prefix followed by ~20 base64url chars.
 *
 * So: for the GitLab detector ONLY, drop a detection when it is unverified AND
 * its raw secret doesn't match the `glpat-` shape. We keep:
 *   - every VERIFIED detection (TruffleHog confirmed it live), and
 *   - unverified detections that DO look like a real `glpat-` token (could be a
 *     revoked-but-real token worth surfacing).
 * Every other detector is left completely untouched.
 *
 * `raw` is the unredacted matched string (TruffleHog's `Raw` field), captured
 * before we strip it for storage.
 */
const GITLAB_PAT_RE = /glpat-[0-9A-Za-z_-]{20,}/;
function isLowConfidenceGitlabFinding(args: {
  detectorType: string;
  isVerified: boolean;
  raw: string;
}): boolean {
  const isGitlab = args.detectorType.toLowerCase() === 'gitlab';
  if (!isGitlab) return false;
  if (args.isVerified) return false; // verified = confirmed live, always keep
  // Unverified GitLab match: keep only if it's actually `glpat-`-shaped.
  return !GITLAB_PAT_RE.test(args.raw);
}

export async function doTruffleHog(ctx: PipelineContext): Promise<void> {
  const { supabase, job, projectId, log, workspaceRoot, runId, importance } = ctx;

  if (!binaryAvailable('trufflehog')) {
    // CLI/local dev legitimately lacks trufflehog — skip quietly there.
    if (process.env.DEPTEX_CLI_MODE === '1') {
      await log.warn('trufflehog', INSTALL_HINTS.trufflehog);
      return;
    }
    // The worker image bundles trufflehog, so a missing binary means a misbuilt
    // image that would silently ship secret-scanning-off scans. Fail loudly.
    const msg = `Secret scanning could not run: ${INSTALL_HINTS.trufflehog}`;
    await log.error('trufflehog', msg);
    if (job.jobId) {
      await logStepError(supabase, {
        jobId: job.jobId,
        projectId,
        step: 'trufflehog',
        code: 'binary_missing_trufflehog',
        message: INSTALL_HINTS.trufflehog,
        severity: 'error',
      });
    }
    throw new ScanFailedError(msg);
  }

  await log.info('trufflehog', 'Scanning for exposed secrets...');
  const thStart = Date.now();
  await runStage({
    name: 'trufflehog',
    timeoutMs: 10 * 60_000,
    severity: 'error',
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    onError: async ({ err }) => {
      const msg = `Secret scanning failed: ${(err as Error).message ?? String(err)}`;
      await log.error('trufflehog', msg);
      // severity: 'error' → rethrow; pipeline outer catch sets error state.
      return { rethrow: true, throwAs: new ScanFailedError(msg) };
    },
    fn: async () => {
      const trufflehogOut = path.join(workspaceRoot, 'trufflehog.json');
      const wsPrefix = workspaceRoot.endsWith('/') ? workspaceRoot : workspaceRoot + '/';

      // Upstream tools (cdxgen, dep-scan, Semgrep, TruffleHog itself) all
      // drop their raw outputs into the workspace before TruffleHog runs, so
      // a naive scan picks up URLs + tokens from our own intermediates. Ship
      // an exclude file scoped to those known paths — relative matchers that
      // work regardless of the workspace's absolute location.
      //
      // Also exclude vendored dependency trees. cdxgen installs deps during
      // SBOM generation, so the workspace ends up holding node_modules/,
      // vendor/, site-packages/ etc. Secrets there belong to third-party
      // packages, not the user's code, and they're a large false-positive
      // surface (e.g. a GitHub avatar-URL hash in a dep's README that
      // TruffleHog's `github` detector flags as a token). Every secret
      // scanner skips these by default; we do too.
      const excludeFile = path.join(workspaceRoot, '.deptex-trufflehog-excludes');
      fs.writeFileSync(
        excludeFile,
        [
          'trufflehog.json',
          'semgrep.json',
          'sbom.json',
          'sbom.json.map',
          'deps.slices.json',
          'depscan-reports/',
          '.results/',
          '.buckets/',
          '.pglite-buckets/',
          // vendored dependency trees (regex matched against the full path)
          'node_modules/',
          'vendor/',
          '.venv/',
          'venv/',
          'site-packages/',
        ].join('\n') + '\n',
        'utf8',
      );

      // Run TruffleHog with spawnSync to capture stdout/stderr separately
      const thResult = require('child_process').spawnSync(
        'trufflehog',
        ['filesystem', workspaceRoot, '--json', '--no-update', `--exclude-paths=${excludeFile}`],
        { encoding: 'utf8', timeout: 120000, maxBuffer: 10 * 1024 * 1024 },
      );
      const stdout = thResult.stdout ?? '';
      const stderr = thResult.stderr ?? '';
      const exitCode = thResult.status ?? -1;

      if (exitCode !== 0) {
        // TruffleHog stderr can echo fragments of detected secrets. Keep raw
        // stderr in the worker console only; extraction_logs is browser-streamed.
        if (stderr.trim()) {
          console.error('[trufflehog] stderr:\n' + stderr.trim());
        }
        // No usable output on a non-zero exit = a real scanner failure. Throw so
        // the run hard-fails (severity: 'error'). When stdout DID land, TruffleHog
        // merely exited non-zero on a partial scan — use the partial results.
        if (!stdout.trim()) {
          throw new Error(`TruffleHog exited with code ${exitCode} and produced no output`);
        }
        await log.warn('trufflehog', `TruffleHog exited with code ${exitCode}; using the partial output it produced`);
      }

      if (stdout.trim()) {
        fs.writeFileSync(trufflehogOut, stdout, 'utf8');
      }

      if (fs.existsSync(trufflehogOut)) {
        const content = fs.readFileSync(trufflehogOut, 'utf8');
        const lines = content.trim().split('\n').filter(Boolean);

        if (lines.length > 0 && lines[0].startsWith('{')) {
          try {
            const findings = lines.map((line: string) => {
              const f = JSON.parse(line);
              const raw = f.Raw ?? '';
              const redacted = raw.length >= 20 ? `${raw.slice(0, 4)}...${raw.slice(-4)}` : '****';
              let filePath = f.SourceMetadata?.Data?.Filesystem?.file ?? f.SourceMetadata?.Data?.Git?.file ?? 'unknown';
              // Strip workspace temp prefix to store relative paths
              if (filePath.startsWith(wsPrefix)) {
                filePath = filePath.slice(wsPrefix.length);
              }
              const detectorType = f.DetectorName ?? 'Unknown';
              const isVerified = f.Verified ?? false;

              // Drop GitLab false positives: unverified, non-`glpat-`-shaped
              // matches (TS interface fields, generic auth wrappers, etc.) that
              // TruffleHog's GitLab detector pattern-matched but couldn't verify.
              // Only this detector's low-confidence matches are dropped; `raw`
              // (TruffleHog's unredacted `Raw`) is checked before it's stripped.
              if (isLowConfidenceGitlabFinding({ detectorType, isVerified, raw })) {
                return null;
              }

              const isCurrent = !!(f.SourceMetadata?.Data?.Filesystem);
              const startLine = f.SourceMetadata?.Data?.Filesystem?.line ?? f.SourceMetadata?.Data?.Git?.line ?? null;

              // Extract code snippet around the affected line
              let codeSnippet: string | null = null;
              if (startLine != null && filePath !== 'unknown') {
                try {
                  const absPath = path.join(workspaceRoot, filePath);
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
                detector_type: detectorType,
                file_path: filePath,
                start_line: startLine,
                is_verified: isVerified,
                is_current: isCurrent,
                description: `${detectorType} detected`,
                redacted_value: redacted,
                code_snippet: codeSnippet,
                depscore: calculateSecretDepscore({ detectorType, isVerified, isCurrent, importance }),
              };
            })
              // Drop the GitLab false positives nulled out above.
              .filter((f: any): f is NonNullable<typeof f> => f != null)
              .filter((f: any) => f.detector_type !== 'Unknown' || f.file_path !== 'unknown')
              // Filter out .git/ internals — these are clone credentials, not user code secrets
              .filter((f: any) => !f.file_path.startsWith('.git/') && !f.file_path.startsWith('.git\\'));

            // TruffleHog can emit the same (detector_type, file_path, start_line)
            // tuple more than once per scan (e.g. when the same value matches
            // multiple chunks of a big file). Postgres' ON CONFLICT DO UPDATE
            // rejects a statement that targets the same conflict-key row twice,
            // so an unfiltered batch crashes the whole upsert and we lose every
            // secret for the run. Dedupe on the upsert conflict key.
            const dedupeKey = (f: any): string =>
              `${f.detector_type}\x00${f.file_path}\x00${f.start_line ?? ''}`;
            const seen = new Set<string>();
            for (let i = findings.length - 1; i >= 0; i--) {
              const key = dedupeKey(findings[i]);
              if (seen.has(key)) findings.splice(i, 1);
              else seen.add(key);
            }

            if (findings.length > 0) {
              for (let i = 0; i < findings.length; i += 100) {
                const { error: upsertErr } = await supabase.from('project_secret_findings').upsert(findings.slice(i, i + 100), {
                  onConflict: 'project_id,detector_type,file_path,start_line,extraction_run_id',
                });
                if (upsertErr) {
                  await log.warn('trufflehog', `DB upsert error: ${upsertErr.message}`);
                }
              }
            }

            const sanitized = lines.map((line: string) => {
              try {
                const f = JSON.parse(line);
                delete f.Raw;
                return JSON.stringify(f);
              } catch { return line; }
            }).join('\n');
            fs.writeFileSync(trufflehogOut, sanitized, 'utf8');
          } catch (parseErr: any) {
            await log.warn('trufflehog', `Failed to parse findings: ${parseErr.message}`);
          }
        }

        const sanitizedContent = fs.readFileSync(trufflehogOut, 'utf8');
        try {
          await supabase.storage
            .from('project-imports')
            .upload(`${projectId}/${runId}/trufflehog.json`, sanitizedContent, { contentType: 'application/json', upsert: true });
        } catch { /* upload failure non-fatal */ }
        await log.success('trufflehog', 'Secret scan complete', Date.now() - thStart);
      } else {
        // Binary presence was already asserted above (line ~24), so reaching
        // here means TruffleHog ran and exited cleanly with empty output —
        // i.e. a successful scan that found zero secrets. Don't conflate that
        // with "not installed": a real no-binary case hard-fails earlier.
        await log.success('trufflehog', 'Secret scan complete — no secrets found', Date.now() - thStart);
      }
    },
  });
}
