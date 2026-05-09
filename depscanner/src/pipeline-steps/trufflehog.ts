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
import { calculateSecretDepscore } from '../depscore';
import { binaryAvailable, INSTALL_HINTS } from '../pipeline-helpers';
import type { PipelineContext } from '../pipeline-types';

export async function doTruffleHog(ctx: PipelineContext): Promise<void> {
  const { supabase, job, projectId, log, workspaceRoot, runId, assetTier, tierMultiplier } = ctx;

  if (!binaryAvailable('trufflehog')) {
    await log.warn('trufflehog', INSTALL_HINTS.trufflehog);
    return;
  }

  await log.info('trufflehog', 'Scanning for exposed secrets...');
  const thStart = Date.now();
  await runStage({
    name: 'trufflehog',
    timeoutMs: 10 * 60_000,
    severity: 'warn',
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    onError: async ({ err }) => {
      await log.warn('trufflehog', `Secret scanning failed: ${(err as Error).message ?? String(err)}`);
    },
    fn: async () => {
      const trufflehogOut = path.join(workspaceRoot, 'trufflehog.json');
      const wsPrefix = workspaceRoot.endsWith('/') ? workspaceRoot : workspaceRoot + '/';

      // Upstream tools (cdxgen, dep-scan, Semgrep, TruffleHog itself) all
      // drop their raw outputs into the workspace before TruffleHog runs, so
      // a naive scan picks up URLs + tokens from our own intermediates. Ship
      // an exclude file scoped to those known paths — relative matchers that
      // work regardless of the workspace's absolute location.
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
        await log.warn('trufflehog', `TruffleHog exited with code ${exitCode}`);
        if (stderr.trim()) {
          const stderrLines = stderr.trim().split('\n').slice(0, 10);
          for (const line of stderrLines) {
            await log.warn('trufflehog', `[stderr] ${line.trim()}`);
          }
        }
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
                depscore: calculateSecretDepscore({ detectorType, isVerified, isCurrent, assetTier, tierMultiplier }),
              };
            })
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
        await log.warn('trufflehog', 'Secret scanning skipped (TruffleHog not installed or no output)');
      }
    },
  });
}
