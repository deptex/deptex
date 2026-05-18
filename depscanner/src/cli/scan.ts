/**
 * Local "scan" command — boots PGLite, seeds minimal DB state, runs the
 * extraction pipeline against a local workspace, writes JSON outputs.
 *
 * This is the v1 local-mode entry point. It does not talk to Supabase,
 * GitHub, QStash, or any external service beyond the binaries the pipeline
 * already shells out to (dep-scan, cdxgen, semgrep, trufflehog) and the
 * public EPSS / CISA KEV APIs fetched in pipeline.ts.
 */

import * as fs from 'fs';
import * as path from 'path';

import { createPGLiteStorage, PGLiteStorage } from '../storage/pglite';
import { runPipeline, type ExtractionJob } from '../pipeline';
import { ExtractionLogger } from '../logger';
import { seedLocalDb } from './seed';
import { detectEcosystem, type Ecosystem } from './ecosystem';
import { writeOutputs, computeExitCode, SEVERITY_RANK, type RunSummary } from './output';
import { formatLogLine } from './format';

export interface ScanOptions {
  /** Path to the workspace (existing checked-out repo). Must exist. */
  workspacePath: string;
  /** Ecosystem override. If absent, auto-detected from manifest files. */
  ecosystem?: Ecosystem;
  /** Output directory for JSON artifacts. Created if missing. */
  outputDir: string;
  /** Severity filter (whitelist). If empty, no filtering. */
  severities?: string[];
  /** Exit-code gating: fail if any finding >= this severity. */
  failOn?: string | null;
  /** Optional label (defaults to workspace basename). */
  label?: string;
  /** Show info-level step chatter. */
  verbose?: boolean;
  /** Suppress everything except warnings + errors. */
  quiet?: boolean;
  /**
   * Opt-in: allow the workspace path to resolve outside the current working
   * directory. Off by default — without it, a path like `../../etc` is
   * rejected so a scan can't read arbitrary host files.
   */
  allowOutsideCwd?: boolean;
}

export interface ScanResult {
  exitCode: number;
  summary: RunSummary;
  outputDir: string;
  vulns: any[];
  deps: any[];
  semgrep: any[];
  secrets: any[];
}

export async function runScan(opts: ScanOptions): Promise<ScanResult> {
  const absWorkspace = path.resolve(opts.workspacePath);
  if (!fs.existsSync(absWorkspace)) {
    throw new Error(`workspace not found: ${absWorkspace}`);
  }
  if (!fs.statSync(absWorkspace).isDirectory()) {
    throw new Error(`workspace is not a directory: ${absWorkspace}`);
  }

  // Path confinement. Inside the Docker image the host wrappers always mount
  // the workspace at /workspace, so confinement is unnecessary (and would
  // mis-fire since cwd differs from the mount). Outside container mode,
  // resolve symlinks and reject any path that escapes process.cwd() — a
  // caller passing `../../etc` would otherwise scan arbitrary host files.
  // `--allow-outside-cwd` opts out for deliberate out-of-tree scans.
  const inContainer = process.env.DEPTEX_LOCAL_CLI === '1';
  if (!inContainer && !opts.allowOutsideCwd) {
    const realWorkspace = fs.realpathSync(absWorkspace);
    const realCwd = fs.realpathSync(process.cwd());
    const rel = path.relative(realCwd, realWorkspace);
    if (rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) {
      throw new Error(
        `workspace path '${realWorkspace}' is outside the current directory ` +
          `(${realCwd}); pass --allow-outside-cwd to scan it deliberately`,
      );
    }
  }

  const label = opts.label ?? path.basename(absWorkspace);
  const ecosystem = opts.ecosystem ?? detectEcosystem(absWorkspace);
  if (!ecosystem) {
    throw new Error(
      `no recognized manifest found in ${absWorkspace} — pass --ecosystem=npm|pypi|maven|golang to override`,
    );
  }

  const severitySet =
    opts.severities && opts.severities.length > 0
      ? new Set(opts.severities.map((s) => s.toLowerCase()))
      : undefined;
  if (severitySet) {
    for (const s of severitySet) {
      if (!(s in SEVERITY_RANK)) {
        throw new Error(
          `unknown severity '${s}' (expected: low, medium, high, critical)`,
        );
      }
    }
  }
  if (opts.failOn && !(opts.failOn.toLowerCase() in SEVERITY_RANK)) {
    throw new Error(
      `unknown --fail-on severity '${opts.failOn}' (expected: low, medium, high, critical)`,
    );
  }

  const startedAt = Date.now();
  log(opts, `booting local DB...`);
  const storage: PGLiteStorage = await createPGLiteStorage({
    outputDir: path.join(opts.outputDir, '.buckets'),
  });

  try {
    log(opts, `seeding org + project...`);
    const { organizationId, projectId, jobId } = await seedLocalDb(storage, {
      repoLabel: label,
      ecosystem,
    });

    const runId = `local_${Date.now()}`;
    const verbose = opts.verbose === true;
    const quiet = opts.quiet === true;
    const logger = new ExtractionLogger(storage, projectId, runId, {
      cliMode: true,
      sink: (message, level, step) => {
        // stdout is reserved for human-readable progress (gated by --quiet)
        // and the final --format=json or table dump.
        const line = formatLogLine(message, level, step, { verbose, quiet });
        if (line) console.log(line);
        // stderr always gets a minimal machine-readable step marker so that
        // harnesses that capture stderr incrementally (e.g. the OSS corpus
        // tee, container log forwarders) can diagnose hangs and OOMs even
        // when --quiet --format=json suppresses all stdout progress. The
        // final JSON only flushes on successful exit; without these markers
        // there's no forensic trail when the scan is SIGKILLed mid-pipeline.
        if (level !== 'info' || verbose) {
          const tag = level === 'success' ? 'ok' : level;
          process.stderr.write(`[scan] ${tag} ${step} ${message}\n`);
        }
      },
    });

    const job: ExtractionJob = {
      projectId,
      organizationId,
      jobId,
      repo_full_name: `local/${label}`,
      installation_id: 'local',
      default_branch: 'main',
      ecosystem,
      provider: 'local',
      localWorkspacePath: absWorkspace,
    };

    log(opts, `running pipeline against ${absWorkspace}...`);
    const pipelineResult = await runPipeline(job, logger, undefined, undefined, storage);

    // finalize_extraction already wrote active_extraction_run_id into
    // projects. Re-read it for the summary (the pipeline may have generated
    // a different run id internally than `runId` above).
    const { data: projRow } = await storage
      .from('projects')
      .select('active_extraction_run_id')
      .eq('id', projectId)
      .single();
    const activeRunId =
      (projRow as any)?.active_extraction_run_id ?? runId;

    log(opts, `writing outputs to ${opts.outputDir}...`);
    const { summary, vulns, deps, semgrep, secrets } = await writeOutputs(storage, {
      outputDir: opts.outputDir,
      organizationId,
      projectId,
      projectName: label,
      extractionRunId: activeRunId,
      ecosystem,
      startedAtMs: startedAt,
      severityFilter: severitySet,
      finalizeSummary: pipelineResult?.finalizeSummary ?? null,
    });

    const exitCode = computeExitCode(vulns, opts.failOn ?? null);
    return { exitCode, summary, outputDir: opts.outputDir, vulns, deps, semgrep, secrets };
  } finally {
    await storage.close();
  }
}

function log(opts: ScanOptions, msg: string): void {
  // Bootstrap noise (booting DB, seeding) — verbose only. Quiet-by-default
  // matches Trivy/OSV-Scanner: user sees only warnings/errors and the table.
  if (opts.verbose === true && !opts.quiet) console.log(`[scan] ${msg}`);
}
