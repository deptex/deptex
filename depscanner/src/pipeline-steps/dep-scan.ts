/**
 * STEP: Vulnerability scan (OPTIONAL).
 *
 * Runs `depscan` (CycloneDX VDR profile) against the workspace, then post-
 * processes results into project_dependency_vulnerabilities rows. Uses the
 * dep-scan VDR JSON as the source of truth for severity/affects/EPSS hints,
 * cross-referenced against the per-extraction PDV map to assign
 * project_dependency_id.
 *
 * Phase 6.5 / M5 task 34 — atom integration retired. The taint engine's
 * CVE-targeted FrameworkSpec rules + cross-file taint engine replace atom's
 * SemanticReachability path entirely. We keep dep-scan running for
 * vulnerability detection (`-i` + `-t`), dropping `--deep` (atom-only flag)
 * and `--reachability-analyzer SemanticReachability` (atom phase) so dep-scan
 * stops paying the atom CPU/OOM cost. `--explain` is also dropped — the
 * LLM-prompts path was atom-only.
 *
 * Side effects:
 *   - inserts rows into project_dependency_vulnerabilities (deduped by
 *     (pd_id, osv_id))
 *   - uploads dep-scan.json to project-imports storage (non-fatal)
 *   - fetches CISA KEV + EPSS feeds (non-fatal)
 *   - logs vuln_scan completion (the `Vulnerability scan complete` line is
 *     emitted later by the reachability step which owns the same scanStart
 *     timer in pipeline.ts — preserved here for shape parity).
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync, spawn } from 'child_process';
import { runStage } from '../pipeline-stage-runner';
import { logStepError } from '../with-timeout';
import { ScanFailedError } from '../scan-errors';
import {
  calculateBaseDepscoreNoReachability,
  calculateDepscore,
  SEVERITY_TO_CVSS,
} from '../depscore';
import {
  stripAnsi,
  updateStep,
  clearVdbVolumeForRecovery,
  getCachedKevSet,
  getCachedEpss,
  setCachedEpss,
} from '../pipeline-helpers';
import type { PipelineContext, PipelineLogger } from '../pipeline-types';
import { runOsvFallback, osvFallbackMode } from './osv-vuln-scan';

/**
 * dep-scan can exit 0 yet have produced ZERO usable vulnerability results
 * because its bundled VDB refresh/download broke mid-stream. The live P0 was a
 * transient `requests.exceptions.ChunkedEncodingError: Connection broken:
 * IncompleteRead(... bytes read, ... more expected)` while pulling the
 * vulnerability database. In that state dep-scan logs a WARNING
 * ("No vulnerability scan results available"), writes an empty/no VDR, and
 * STILL returns exit code 0. Keying success on the exit code alone therefore
 * reports a genuinely-vulnerable repo as CLEAN — a silent false-negative
 * (vulnerable express@4.18.2 scanned, 0 vulns written, scan exited OK).
 *
 * This inspects dep-scan's combined stdout+stderr for the DEGRADED signature so
 * the caller can treat an exit-0-but-broken run as a failed run (force the OSV
 * safety-net, and loud-fail if OSV is also unavailable) instead of a clean pass
 * — mirroring how a non-zero dep-scan exit already drives `depScanSucceeded`.
 *
 * It keys on the ERROR CAUSE (a broken VDB download / DB load), NOT on "0
 * results": a genuinely vuln-free project prints NONE of these strings
 * (dep-scan's clean path logs "No oss vulnerabilities..." / "No vulnerabilities
 * found"), so a legitimately clean scan is NOT turned into a failure.
 */
export function detectDegradedDepScan(
  combinedOutput: string | null | undefined,
): { degraded: boolean; reason?: string } {
  if (!combinedOutput) return { degraded: false };
  const signatures: Array<{ re: RegExp; reason: string }> = [
    // The exact live failure: the VDB download stream was truncated.
    { re: /ChunkedEncodingError/i, reason: 'VDB download connection broken (ChunkedEncodingError)' },
    { re: /IncompleteRead/i, reason: 'VDB download truncated (IncompleteRead)' },
    { re: /Connection broken/i, reason: 'VDB download connection broken' },
    // Any urllib3 / requests network exception bubbling out of the VDB refresh.
    { re: /requests\.exceptions\.\w+/, reason: 'VDB download network error (requests.exceptions)' },
    { re: /\b(?:ConnectionError|ReadTimeoutError|ConnectTimeoutError|NewConnectionError|MaxRetryError|ProtocolError|SSLError)\b/, reason: 'VDB download network error' },
    // dep-scan / VDB tooling could not obtain or load the vulnerability DB.
    { re: /(?:unable|failed|could not|error)\b[^\n]{0,60}\b(?:download|refresh|update|sync|fetch|load|build|create|prepare)\b[^\n]{0,60}\b(?:vuln\w*|vdb|database|db)\b/i, reason: 'VDB refresh/load failed' },
    { re: /\b(?:vdb|vulnerability database)\b[^\n]{0,40}\b(?:corrupt|malformed|missing|incomplete|empty|not (?:found|available))\b/i, reason: 'VDB missing/incomplete' },
    // dep-scan's explicit "the scan produced no results object" WARNING. This is
    // its degraded/error path — distinct from the clean "No vulnerabilities
    // found" success line — so an exit-0 run carrying it has not actually
    // checked the dependencies.
    { re: /No vulnerability scan results available/i, reason: 'dep-scan produced no vulnerability scan results' },
  ];
  for (const s of signatures) {
    if (s.re.test(combinedOutput)) return { degraded: true, reason: s.reason };
  }
  return { degraded: false };
}

function runDepScanProcess(
  depScanExe: string,
  args: string[],
  cwd: string,
  logger: Pick<PipelineLogger, 'info' | 'warn'>,
  heartbeat: () => Promise<void>,
  timeoutMs: number = 180 * 60 * 1000,
  signal?: AbortSignal,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const verboseLogs =
    process.env.DEPSCAN_VERBOSE_LOG === '1' || /^true$/i.test(process.env.DEPSCAN_VERBOSE_LOG ?? '');

  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('dep-scan aborted before start'));
      return;
    }

    const child = spawn(depScanExe, args, { cwd, stdio: 'pipe' });
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data: Buffer) => {
      const chunk = data.toString();
      stdout += chunk;
      if (verboseLogs) {
        const trimmed = stripAnsi(chunk).trim();
        if (trimmed) {
          logger.info('depscan', trimmed).catch(() => {});
        }
      }
    });
    child.stderr.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    const heartbeatInterval = setInterval(async () => {
      try {
        await heartbeat();
      } catch {}
    }, 60_000);

    // dep-scan (Python) ignores SIGTERM; escalate to SIGKILL after a grace
    // period so the child can't outlive the worker and leak as a zombie on a
    // scale-to-zero machine. Cleared on close so a clean exit doesn't kill.
    let sigkillTimer: NodeJS.Timeout | undefined;
    const escalateKill = () => {
      try { child.kill('SIGTERM'); } catch { /* already dead */ }
      if (!sigkillTimer) {
        sigkillTimer = setTimeout(() => {
          try { child.kill('SIGKILL'); } catch { /* already dead */ }
        }, 5000);
      }
    };

    const timeout = setTimeout(() => {
      escalateKill();
      clearInterval(heartbeatInterval);
      reject(new Error(`dep-scan timed out after ${timeoutMs / 60000} min`));
    }, timeoutMs);

    // On outer abort: kill the child only. Don't reject — SIGTERM is an async
    // OS signal so child.on('close') fires on a later I/O tick, by which time
    // Promise.race in withTimeout has already rejected with StepTimeoutError.
    // Rejecting here would race StepTimeoutError and win (synchronous reject
    // queues its microtask before the outer's), leaking an opaque error that
    // classifyError can't map to code='timeout'.
    const onAbort = () => {
      escalateKill();
    };
    if (signal) {
      signal.addEventListener('abort', onAbort, { once: true });
    }

    child.on('close', (code: number | null) => {
      clearInterval(heartbeatInterval);
      clearTimeout(timeout);
      if (sigkillTimer) clearTimeout(sigkillTimer);
      signal?.removeEventListener('abort', onAbort);
      resolve({ stdout, stderr, exitCode: code ?? 1 });
    });

    child.on('error', (err: Error) => {
      clearInterval(heartbeatInterval);
      clearTimeout(timeout);
      if (sigkillTimer) clearTimeout(sigkillTimer);
      signal?.removeEventListener('abort', onAbort);
      reject(err);
    });
  });
}

export interface DepScanOutput {
  /** Wall-clock start of vuln_scan, used by the reachability step to log scan completion. */
  scanStart: number;
}

/** A project_dependencies row, as far as dual-scope PDV attachment cares. */
export interface DualScopePdRow {
  id: string;
  name: string;
  version: string;
  environment: string | null;
}

/**
 * Build the `name@version → project_dependency_id` map dep-scan uses to attach
 * a vulnerability to a dependency row.
 *
 * When a package appears twice for one project — declared as a direct
 * devDependency and also pulled in as a production transitive — the PDV must
 * attach to the **production-scope** row. Otherwise a vuln on a genuine runtime
 * dependency could land on the dev row and be classed `unreachable` (a Gate-3
 * false negative once dev-scope classification lands). Preference order:
 * `environment !== 'dev'` (covers both `'prod'` and `null`) wins; remaining ties
 * break on lowest `id` so the choice is identical run-to-run regardless of the
 * order Postgres returns the rows in.
 */
function buildPdMap(
  pdRows: DualScopePdRow[],
  keyFn: (r: DualScopePdRow) => string,
): Map<string, string> {
  const pdByKey = new Map<string, string>();
  const pdEnvByKey = new Map<string, string | null>();
  for (const r of pdRows) {
    const key = keyFn(r);
    const incomingEnv = (r.environment ?? null) as string | null;
    const storedId = pdByKey.get(key);
    if (storedId === undefined) {
      pdByKey.set(key, r.id);
      pdEnvByKey.set(key, incomingEnv);
      continue;
    }
    const incomingIsProd = incomingEnv !== 'dev';
    const storedIsProd = pdEnvByKey.get(key) !== 'dev';
    if (
      (incomingIsProd && !storedIsProd) ||
      (incomingIsProd === storedIsProd && r.id < storedId)
    ) {
      pdByKey.set(key, r.id);
      pdEnvByKey.set(key, incomingEnv);
    }
  }
  return pdByKey;
}

export function resolveDualScopePdMap(pdRows: DualScopePdRow[]): Map<string, string> {
  return buildPdMap(pdRows, (r) => `${r.name}@${r.version}`);
}

/**
 * Registry name-normalization for the vuln→dependency join. The VDR
 * `affects[].ref` purl carries the *registry-normalized* name (lowercase; and
 * for PyPI, PEP 503 collapses runs of `-`, `_`, `.` to a single `-`), while a
 * `project_dependencies` row keeps the name cdxgen read verbatim from the
 * manifest — e.g. a `requirements.txt` line `Werkzeug` / `Flask-SQLAlchemy`.
 * A case-sensitive `name@version` join therefore drops EVERY CVE on a
 * capitalized- or underscore-declared PyPI package (Flask, Werkzeug, Jinja2,
 * MarkupSafe, SQLAlchemy, Pillow, PyYAML, …) — a silent false-negative. PyPI
 * and npm both enforce normalized-name uniqueness, so normalizing cannot merge
 * two distinct packages.
 */
export function normalizeDepName(name: string, ecosystem?: string | null): string {
  const lower = name.trim().toLowerCase();
  return (ecosystem ?? '').toLowerCase() === 'pypi' ? lower.replace(/[-_.]+/g, '-') : lower;
}

/**
 * Case/PEP-503-insensitive companion to {@link resolveDualScopePdMap}. Consulted
 * ONLY as a fallback after the exact-name join misses, so existing matches are
 * byte-for-byte unchanged (zero regression) — it purely recovers CVEs the
 * case-sensitive join was dropping.
 */
export function resolveDualScopePdMapNormalized(
  pdRows: DualScopePdRow[],
  ecosystem: string | null,
): Map<string, string> {
  return buildPdMap(pdRows, (r) => `${normalizeDepName(r.name, ecosystem)}@${r.version}`);
}

/** The slice of a project_dependencies row the vuln-depscore multiplier reads. */
export interface PdScoringContext {
  /** `false` ⇒ transitive (0.75× directness taper); true/null/undefined ⇒ direct. */
  is_direct?: boolean | null;
  /** `'dev'` ⇒ dev/test/build scope (0.4× env taper). */
  environment?: string | null;
}

/**
 * Compute a PDV's depscore + reachability-independent base depscore, threading
 * the dependency-context multiplier (directness 0.75×, dev-scope 0.4×) from the
 * matched project_dependencies row.
 *
 * SC1 fix: the old call site only passed `{cvss, epss, cisaKev, isReachable,
 * importance}`, so `calculateDepscore`'s directness/env/malicious/reputation
 * taper was dead — every vuln scored as if direct + prod. Wiring `is_direct`
 * and `environment` restores the intended taper for non-unreachable rows
 * (dev-scope's hard `unreachable` floor still comes later, from the
 * reachability classifier).
 *
 * NOTE — malicious + reputation are intentionally NOT passed here: the malicious
 * flag and the package reputation score are both populated AFTER extraction
 * (malicious-package scan + the QStash populate-dependencies pass), so they are
 * not yet known at dep-scan time. They taper correctly once the reachability
 * step's rescore picks them up — see the boundary note at the call site.
 */
export function scoreVulnRow(
  row: {
    cvss_score: number | null;
    epss_score: number | null;
    cisa_kev: boolean;
    severity: string | null;
    is_reachable: boolean;
  },
  pd: PdScoringContext | undefined,
  importance: number,
): { depscore: number; base_depscore_no_reachability: number } {
  const cvss = row.cvss_score ?? (row.severity ? (SEVERITY_TO_CVSS[row.severity] ?? 0) : 0);
  const epss = row.epss_score ?? 0;
  const isDirect = pd?.is_direct ?? undefined;
  const isDevDependency = pd?.environment === 'dev';
  return {
    base_depscore_no_reachability: calculateBaseDepscoreNoReachability({
      cvss, epss, cisaKev: row.cisa_kev, importance, isDirect, isDevDependency,
    }),
    depscore: calculateDepscore({
      cvss, epss, cisaKev: row.cisa_kev, isReachable: row.is_reachable,
      importance, isDirect, isDevDependency,
    }),
  };
}

export async function doDepScan(ctx: PipelineContext): Promise<DepScanOutput> {
  const { supabase, job, projectId, log, workspaceRoot, jobEcosystem, runId, heartbeat, importance } = ctx;

  await updateStep(supabase, projectId, 'scanning');
  await log.info('vuln_scan', 'Running vulnerability scan...');

  const scanStart = Date.now();
  const reportsDir = path.join(workspaceRoot, 'depscan-reports');
  let depScanSucceeded = false;

  // Capture the pipeline's own SBOM purls NOW, before dep-scan runs. dep-scan
  // can run for many minutes and crash (bad `-t`, VDB corruption, OOM), and its
  // run can churn the workspace — so reading sbom.json here, while it's pristine,
  // guarantees the OSV-API fallback below always has the real dependency set to
  // query even when dep-scan leaves reportsDir empty. cdxgen writes
  // `pkg:<type>/<name>@<version>` purls; we pass them straight through.
  let pipelinePurls: string[] = [];
  try {
    const pipelineSbomPath = path.join(workspaceRoot, 'sbom.json');
    if (fs.existsSync(pipelineSbomPath)) {
      const doc = JSON.parse(fs.readFileSync(pipelineSbomPath, 'utf8')) as {
        components?: Array<{ purl?: unknown }>;
      };
      const seen = new Set<string>();
      for (const c of doc.components ?? []) {
        if (typeof c?.purl === 'string' && c.purl.startsWith('pkg:') && !seen.has(c.purl)) {
          seen.add(c.purl);
          pipelinePurls.push(c.purl);
        }
      }
    }
  } catch { /* best-effort: a missing/partial SBOM just means no caller purls */ }

  // Captured when dep-scan crashes / its binary is missing, so the degraded
  // flag (set after the OSV fallback) carries the real cause to admin + logs.
  let depScanFailureDetail: string | null = null;

  // When OSV fallback is FORCED (the dogfood / OSS-corpus worker sets
  // DEPTEX_OSV_FALLBACK=force), skip the dep-scan subprocess entirely. dep-scan
  // crashes on several ecosystems and — worse — can spend many minutes
  // rebuilding its ~30GB VDB, which fills the volume and ENOSPC-fails the OSV
  // fallback's own VDR write. The fallback already has the full dependency set
  // via `pipelinePurls`, so it is a complete, fast, disk-cheap substitute here.
  const fallbackMode = osvFallbackMode();
  const skipDepScan = fallbackMode === 'force';
  if (skipDepScan) {
    fs.mkdirSync(reportsDir, { recursive: true });
    depScanFailureDetail =
      'dep-scan skipped (DEPTEX_OSV_FALLBACK=force) — OSV-API is the vulnerability source';
    await log.info(
      'vuln_scan',
      'Checking dependencies for known vulnerabilities via OSV (dep-scan skipped under forced fallback)',
    );
  } else {
  await runStage({
    name: 'dep_scan',
    timeoutMs: 45 * 60_000,
    severity: 'warn',
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    onError: async ({ err }) => {
      const msg = (err as Error).message ?? String(err);
      if (/timed out|timeout/i.test(msg)) {
        await log.warn('vuln_scan', 'Vulnerability scan timed out');
      } else {
        await log.warn('vuln_scan', `Vulnerability scan failed: ${msg}`);
      }
    },
    fn: async (signal) => {
      fs.mkdirSync(reportsDir, { recursive: true });

      // OSV-only mode (DEPTEX_OSV_FALLBACK=force — set globally and forced on
      // burst machines): skip the dep-scan subprocess entirely. dep-scan needs
      // its ~30GB local VDB, which burst machines have no volume for; without it
      // dep-scan grinds rebuilding the VDB on ephemeral disk and wedges the scan
      // at this step (the burst hang). The OSV API scan below replaces it — same
      // CVE coverage, no local DB. Seed reportsDir with the pipeline's SBOM so
      // the OSV fallback (which reads reportsDir/*.cdx.json) has components to
      // query; nothing else writes an SBOM there when dep-scan doesn't run.
      if (osvFallbackMode() === 'force') {
        const pipelineSbom = path.join(workspaceRoot, 'sbom.json');
        if (fs.existsSync(pipelineSbom)) {
          try {
            fs.copyFileSync(pipelineSbom, path.join(reportsDir, 'pipeline-sbom.cdx.json'));
          } catch (e) {
            await log.warn('vuln_scan', `Could not stage SBOM for OSV scan: ${(e as Error).message}`);
          }
        }
        return;
      }

      const outArg = reportsDir;

      let depScanExe = 'depscan';
      if (process.platform === 'win32') {
        try {
          const whereOut = execSync('where depscan.exe', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
          const first = whereOut.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)[0];
          if (first && fs.existsSync(first)) depScanExe = first;
        } catch { /* ignore */ }

        if (depScanExe === 'depscan') {
          try {
            const scriptsDir = execSync('py -c "import sysconfig; print(sysconfig.get_path(\'scripts\'))"', {
              encoding: 'utf8',
              stdio: ['pipe', 'pipe', 'pipe'],
            }).trim();
            const exePath = path.join(scriptsDir, 'depscan.exe');
            if (fs.existsSync(exePath)) depScanExe = exePath;
          } catch { /* ignore */ }
        }
      }

      // Phase 6.5 / M5 task 34 — atom integration retired. See file header.
      // The `research` profile is a preset that re-enables `--deep` +
      // `--reachability-analyzer` (the atom phase) — dropping the individual
      // flags but keeping the profile defeated the retirement and made the
      // step the dominant scan-time cost. dep-scan's default profile still
      // produces the CycloneDX VDR this step consumes.
      const depScanArgs = [
        '-i', workspaceRoot,
        '--reports-dir', outArg,
        '-t', jobEcosystem,
        '--no-banner',
      ];

      // dep-scan command logged at debug level only
      if (process.env.DEPTEX_CLI_MODE !== '1') {
        console.log(`[depscan] ${depScanExe} ${depScanArgs.join(' ')}`);
      }

      const heartbeatFn = heartbeat ?? (async () => {});
      try {
        let res = await runDepScanProcess(depScanExe, depScanArgs, workspaceRoot, log, heartbeatFn, undefined, signal);
        const rawStderr = stripAnsi((res.stderr ?? '').trim());
        const isVdbCorrupt = /CorruptError|malformed|database disk image is malformed/i.test(rawStderr);

        if (res.exitCode !== 0 && isVdbCorrupt) {
          await log.warn('vuln_scan', 'VDB on volume is corrupted (e.g. from previous out-of-space); clearing and retrying once...');
          clearVdbVolumeForRecovery();
          res = await runDepScanProcess(depScanExe, depScanArgs, workspaceRoot, log, heartbeatFn, undefined, signal);
        }

        if (res.exitCode !== 0) {
          const finalStderr = stripAnsi((res.stderr ?? '').trim());
          const lines = finalStderr ? finalStderr.split(/\r?\n/) : [];
          const excerpt = lines.length > 20 ? lines.slice(-20).join('\n') : finalStderr;
          const stderrSnippet = excerpt.slice(-2000) || 'unknown error';
          if (res.exitCode === 137) {
            depScanFailureDetail = 'dep-scan ran out of memory (exit 137)';
            await log.warn('vuln_scan', 'dep-scan out of memory during atom analysis — falling back to basic scan results');
          } else {
            depScanFailureDetail = `dep-scan exited with code ${res.exitCode}: ${stderrSnippet}`;
            await log.warn('vuln_scan', `Vulnerability scan exited with code ${res.exitCode}: ${stderrSnippet}`);
          }
        } else {
          // Exit code 0 is necessary but NOT sufficient. dep-scan returns 0 even
          // when its VDB refresh/download broke mid-stream and it produced zero
          // usable results (the live P0: a transient ChunkedEncodingError while
          // pulling the vulnerability DB → "No vulnerability scan results
          // available" → exit 0 → 0 vulns written → a vulnerable repo reported
          // CLEAN). Inspect the run output for that degraded signature; when
          // present, keep depScanSucceeded=false so the OSV fallback force-fires
          // (`force: !depScanSucceeded`) and the loud-fail guard trips if OSV is
          // also down — instead of silently shipping a false-clean. Keyed on the
          // error CAUSE, not on "0 results", so a genuinely vuln-free scan still
          // passes.
          const combinedOutput = `${stripAnsi((res.stdout ?? '').trim())}\n${stripAnsi((res.stderr ?? '').trim())}`;
          const degraded = detectDegradedDepScan(combinedOutput);
          if (degraded.degraded) {
            depScanFailureDetail = `dep-scan exited 0 but produced no usable results — ${degraded.reason}`;
            await log.warn(
              'vuln_scan',
              `Vulnerability scan degraded (${degraded.reason}); dep-scan exited 0 with no results — treating as failed so the OSV fallback runs`,
            );
          } else {
            depScanSucceeded = true;
          }
        }

        // Log stderr only on failure (exit code > 0)
        if (res.exitCode !== 0) {
          const stderrLines = stripAnsi((res.stderr ?? '').trim()).split(/\r?\n/).filter(Boolean);
          if (stderrLines.length > 0) {
            const stderrExcerpt = stderrLines.slice(-20).join('\n').slice(-2000);
            await log.warn('vuln_scan', `dep-scan stderr:\n${stderrExcerpt}`);
          }
        }

      } catch (spawnErr: any) {
        if (spawnErr.code === 'ENOENT') {
          depScanFailureDetail = 'dep-scan binary not found (ENOENT) — image may be misbuilt';
          await log.warn('vuln_scan', 'Vulnerability scanning unavailable (dep-scan not installed)');
        } else {
          throw spawnErr;
        }
      }
    },
  });
  }

  // === OSV-API fallback (mid-step, before VDR discovery) ===
  // dep-scan's bundled VDB has a silent per-ecosystem lookup gap (confirmed
  // 2026-05-20: returns empty for cargo/maven/npm-dev-cluster against PURLs
  // that OSV's HTTP API matches instantly). Rather than debug OWASP's tool,
  // we run OSV directly when dep-scan's VDR is missing/empty. The fallback
  // writes a CycloneDX-VDR-shaped file into `reportsDir` that the discovery
  // walk below picks up unchanged.
  // The OSV fallback reads a CycloneDX SBOM from reportsDir to harvest PURLs.
  // dep-scan normally writes one there, but when it crashes (bad -t, VDB
  // corruption, OOM) it may emit only an EMPTY .cdx.json — or none at all —
  // leaving the fallback with no PURLs to query. The pipeline's own SBOM step
  // already produced a complete SBOM at workspaceRoot/sbom.json, so always
  // seed reportsDir with it: runOsvFallback picks whichever cdx yields the most
  // PURLs, so the empty dep-scan SBOM can't starve the fallback. This makes the
  // fallback robust to dep-scan crashing after a valid SBOM was generated
  // upstream.
  try {
    const pipelineSbom = path.join(workspaceRoot, 'sbom.json');
    if (fs.existsSync(pipelineSbom)) {
      fs.copyFileSync(pipelineSbom, path.join(reportsDir, '_pipeline-sbom.cdx.json'));
    }
  } catch { /* best-effort: reportsDir always exists by here, sbom.json may not */ }

  if (fallbackMode !== 'off') {
    try {
      const result = await runOsvFallback({
        reportsDir,
        jobEcosystem,
        // Force the OSV query when dep-scan did not cleanly succeed (crash /
        // empty VDR) so its findings aren't silently lost. A clean dep-scan run
        // still skips the redundant query unless DEPTEX_OSV_FALLBACK=force.
        logger: log,
        force: fallbackMode === 'force' || !depScanSucceeded,
        // The pipeline SBOM purls captured before dep-scan ran — guarantees the
        // OSV query sees the real dependency set even if dep-scan emptied/churned
        // reportsDir or the workspace.
        callerPurls: pipelinePurls,
      });
      if (result.wrote && (result.vulnCount > 0 || fallbackMode === 'force')) {
        // In force mode OSV is the SOLE vulnerability source (dep-scan skipped),
        // so a successful run — even with zero matches — means the scan ran, and
        // a genuinely vuln-free project should pass rather than trip the
        // loud-fail check below.
        depScanSucceeded = true;
      } else if (skipDepScan && result.wrote) {
        // dep-scan was deliberately skipped, so a clean OSV query (even one that
        // legitimately found zero vulns) IS the vulnerability scan — don't let
        // the "fail loudly" guard below treat a vuln-free project as a failure.
        depScanSucceeded = true;
      } else if (result.failed) {
        // O2: the OSV query itself FAILED (network / non-2xx batch / unreadable
        // reportsDir) — this is NOT a clean "zero vulns". Treat it as a degraded
        // run: keep depScanSucceeded false so the loud-fail guard below fires
        // when OSV was the sole vulnerability source (forced fallback) or
        // dep-scan also failed. Capture the cause so the failure message names it
        // rather than reporting a misleading empty CVE picture.
        if (fallbackMode === 'force' || !depScanSucceeded) {
          depScanFailureDetail = `OSV fallback degraded — ${result.reason ?? 'query failed'}`;
        }
        await log.warn(
          'vuln_scan_osv',
          `OSV fallback degraded (${result.reason ?? 'query failed'}); pipeline purls captured: ${pipelinePurls.length}`,
        );
      } else if (!result.wrote && result.reason) {
        // Surface the skip reason to the run log (not just worker stdout) so a
        // "0 CVEs but deps resolved" outcome is diagnosable after the fact.
        await log.warn(
          'vuln_scan_osv',
          `OSV fallback found nothing (${result.reason}); pipeline purls captured: ${pipelinePurls.length}`,
        );
      }
    } catch (e) {
      // Network errors here must NOT fail the whole scan — dep-scan's own
      // findings (if any) still get processed below. In force mode there are no
      // dep-scan findings, so capture the cause for the loud-fail check.
      if (fallbackMode === 'force') depScanFailureDetail = `OSV scan failed: ${(e as Error).message}`;
      await log.warn('vuln_scan_osv', `OSV fallback errored (continuing): ${(e as Error).message}`);
    }
  }

  // dep-scan crashed (disk-full apsw.FullError, OOM-137, VDB-corruption,
  // ENOENT) AND the OSV fallback rescued nothing → the vulnerability scan did
  // not run, so the CVE picture is unknown, not clean. Fail the scan loudly
  // rather than silently reporting zero vulnerabilities. `depScanSucceeded` is
  // true on a clean exit (even with a genuinely empty VDR) or a successful OSV
  // fallback, so a legitimately vuln-free project still passes. Skipped in
  // CLI/local mode, where dep-scan's binary is legitimately absent.
  if (!depScanSucceeded && process.env.DEPTEX_CLI_MODE !== '1') {
    const detail = depScanFailureDetail ?? 'dep-scan produced no results';
    const userMsg = `Vulnerability scan failed — could not check your dependencies for known vulnerabilities: ${detail}`;
    await log.error('vuln_scan', userMsg);
    if (job.jobId) {
      await logStepError(supabase, {
        jobId: job.jobId,
        projectId,
        step: 'vuln_scan',
        code: 'depscan_failed',
        message: detail,
        severity: 'error',
      });
    }
    throw new ScanFailedError(userMsg);
  }

  // === Process dep-scan results ===
  const listVdrFiles = (dir: string): string[] => {
    try {
      return fs
        .readdirSync(dir, { withFileTypes: true })
        .filter((d) => d.isFile() && (d.name.endsWith('.vdr.json') || d.name === 'dep-scan.json'))
        .map((d) => path.join(dir, d.name));
    } catch { return []; }
  };

  // Discovery is restricted to `reportsDir` — freshly created this run via
  // mkdirSync above. A workspace-wide recursive walk could pick up stale
  // `*.vdr.json` / `dep-scan.json` from a prior run still on disk and silently
  // report old vulnerabilities for the current extraction.
  const vdrFiles = listVdrFiles(reportsDir);

  const tryParseJson = (p: string): Record<string, unknown> | null => {
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
  };

  const candidatePaths: string[] = [];
  const addCandidate = (p: string) => {
    if (!p || candidatePaths.includes(p) || !fs.existsSync(p)) return;
    candidatePaths.push(p);
  };
  for (const p of vdrFiles) addCandidate(p);
  try {
    for (const d of fs.readdirSync(reportsDir, { withFileTypes: true })) {
      if (d.isFile() && d.name.endsWith('.json')) addCandidate(path.join(reportsDir, d.name));
    }
  } catch { /* ignore */ }

  let depScanPath: string | null = null;
  for (const p of candidatePaths) {
    const parsed = tryParseJson(p);
    const vulns = parsed && (parsed as { vulnerabilities?: unknown }).vulnerabilities;
    if (Array.isArray(vulns)) { depScanPath = p; break; }
  }
  if (!depScanPath) depScanPath = vdrFiles[0] ?? path.join(reportsDir, 'dep-scan.json');

  const reportExists = fs.existsSync(depScanPath);

  if (reportExists) {
    try {
      const depScanContent = fs.readFileSync(depScanPath, 'utf8');
      try {
        await supabase.storage
          .from('project-imports')
          .upload(`${projectId}/${runId}/dep-scan.json`, depScanContent, {
            contentType: 'application/json',
            upsert: true,
          });
      } catch { /* upload failure is non-fatal */ }

      const depScan = JSON.parse(depScanContent) as Record<string, unknown>;
      const parsePurl = (ref: string): { name: string; version: string } | null => {
        if (!ref || typeof ref !== 'string') return null;
        const match = ref.match(/^pkg:[^/]+\/(.+?)@([^?#]+)/);
        if (!match) return null;
        return { name: decodeURIComponent(match[1]), version: decodeURIComponent(match[2]) };
      };

      type CycloneAffect = { ref?: string; versions?: Array<{ version?: string; status?: string; range?: string }> };
      type CycloneVuln = {
        id?: string; description?: string; detail?: string;
        ratings?: Array<{ severity?: string; score?: number }>;
        affects?: CycloneAffect[];
        properties?: Array<{ name?: string; value?: string }>;
        published?: string;
      };
      type LegacyVuln = {
        vuln_id?: string; id?: string; severity?: string; summary?: string;
        aliases?: string[]; fixed_version?: string; fixedVersions?: string[];
        epss?: number; component?: string; version?: string;
        ratings?: Array<{ severity?: string }>;
      };

      const topLevelVulns = Array.isArray(depScan.vulnerabilities) ? (depScan.vulnerabilities as unknown[]) : [];
      const isCycloneVdr =
        topLevelVulns.length > 0 &&
        typeof topLevelVulns[0] === 'object' &&
        topLevelVulns[0] !== null &&
        Array.isArray((topLevelVulns[0] as any).affects);

      const vulnsCyclone = (isCycloneVdr ? (topLevelVulns as CycloneVuln[]) : []) ?? [];
      const vulnsLegacy: LegacyVuln[] = (!isCycloneVdr ? (depScan.vulnerabilities as LegacyVuln[]) : []) || [];

      const { data: pdRows } = await supabase
        .from('project_dependencies')
        .select('id, name, version, environment, is_direct')
        .eq('project_id', projectId)
        .eq('last_seen_extraction_run_id', runId);

      // When two rows share name@version — a package declared both as a direct
      // devDependency and pulled as a production transitive — the PDV attaches
      // to the production-scope row (see resolveDualScopePdMap).
      const pdByNameVersion = resolveDualScopePdMap((pdRows ?? []) as DualScopePdRow[]);
      // Fallback join keyed on the registry-normalized name — recovers CVEs the
      // case-sensitive exact join drops (e.g. VDR purl `werkzeug` vs manifest
      // `Werkzeug`). Consulted only after the exact + Maven-`/` variants miss.
      const pdByNameVersionNorm = resolveDualScopePdMapNormalized(
        (pdRows ?? []) as DualScopePdRow[],
        jobEcosystem,
      );

      // id → directness/scope, for the SC1 dependency-context depscore taper.
      const pdById = new Map<string, PdScoringContext>();
      for (const r of (pdRows ?? []) as Array<{ id: string; environment: string | null; is_direct: boolean | null }>) {
        pdById.set(r.id, { is_direct: r.is_direct, environment: r.environment });
      }

      // Cached: the full CISA KEV catalog is global + daily-refreshed, so a
      // 6h in-process cache avoids re-downloading it on every scan (see
      // getCachedKevSet). A transient fetch failure yields an empty set and is
      // not cached, so the next scan retries.
      const kevCveSet = await getCachedKevSet(async () => {
        const set = new Set<string>();
        try {
          const kevRes = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { signal: AbortSignal.timeout(15000) });
          if (kevRes.ok) {
            const kevJson = (await kevRes.json()) as { vulnerabilities?: Array<{ cveID?: string }> };
            for (const entry of kevJson.vulnerabilities ?? []) {
              if (entry.cveID) set.add(entry.cveID);
            }
          }
        } catch { /* non-fatal */ }
        return set;
      });

      const vulnRows: Array<{
        project_id: string; project_dependency_id: string; osv_id: string;
        extraction_run_id: string;
        severity: string | null; summary: string | null; aliases: string[] | null;
        fixed_versions: string[] | null; is_reachable: boolean; epss_score: number | null;
        cvss_score: number | null; cisa_kev: boolean; depscore: number | null; published_at: string | null;
        base_depscore_no_reachability: number | null;
        reachability_status: string;
        epd_status: string;
        epd_schema_version: string;
        epd_prompt_version: string;
      }> = [];

      if (isCycloneVdr) {
        for (const v of vulnsCyclone) {
          const osvId = (v.id ?? 'unknown').toString();
          const severity = v.ratings?.[0]?.severity ?? null;
          const summary = (v.description ?? v.detail ?? null) as string | null;
          const insights = (v.properties || []).find((p) => p?.name === 'depscan:insights')?.value ?? null;
          const isReachable = typeof insights === 'string' ? insights.startsWith('Used in') : false;
          const epssProp = (v.properties || []).find((p) => p?.name === 'depscan:epss' || p?.name === 'epss')?.value;
          const epssFromVdr = epssProp != null ? parseFloat(String(epssProp)) : null;
          const epssFromVdrNum = Number.isFinite(epssFromVdr) ? epssFromVdr : null;
          const cvssRaw = v.ratings?.[0]?.score;
          const cvssFromVdr = cvssRaw != null && Number.isFinite(cvssRaw) ? cvssRaw : (severity ? (SEVERITY_TO_CVSS[severity] ?? null) : null);
          const fixedSet = new Set<string>();
          for (const a of v.affects || []) {
            for (const ver of a.versions || []) {
              if (ver?.status === 'unaffected' && ver?.version) fixedSet.add(ver.version);
            }
          }
          const fixed_versions = fixedSet.size > 0 ? Array.from(fixedSet) : null;
          for (const a of v.affects || []) {
            const parsed = parsePurl(a.ref ?? '');
            if (!parsed) continue;
            // For Maven/Go PURLs, the name includes group/artifact with '/'.
            // Try: full name, colon separator, and artifact-only (after last '/').
            let pdId = pdByNameVersion.get(`${parsed.name}@${parsed.version}`);
            if (!pdId && parsed.name.includes('/')) {
              const colonName = parsed.name.replace(/\//g, ':');
              pdId = pdByNameVersion.get(`${colonName}@${parsed.version}`);
            }
            if (!pdId && parsed.name.includes('/')) {
              const artifactOnly = parsed.name.split('/').pop()!;
              pdId = pdByNameVersion.get(`${artifactOnly}@${parsed.version}`);
            }
            if (!pdId) {
              // Registry-normalized fallback: VDR purl name is lowercase/PEP-503,
              // the manifest-declared project_dependencies name may be capitalized.
              pdId = pdByNameVersionNorm.get(`${normalizeDepName(parsed.name, jobEcosystem)}@${parsed.version}`);
            }
            if (!pdId) continue;
            vulnRows.push({
              project_id: projectId, project_dependency_id: pdId, osv_id: osvId,
              extraction_run_id: runId,
              severity, summary,
              aliases: Array.isArray((v as { aliases?: unknown }).aliases)
                ? ((v as { aliases?: string[] }).aliases as string[])
                : null,
              fixed_versions, is_reachable: isReachable,
              epss_score: epssFromVdrNum, cvss_score: cvssFromVdr, cisa_kev: false,
              depscore: null, published_at: v.published ?? null,
              base_depscore_no_reachability: null,
              reachability_status: isReachable ? 'reachable' : 'unreachable',
              epd_status: 'pending',
              epd_schema_version: 'epd-v1',
              epd_prompt_version: 'epd-v1',
            });
          }
        }
      } else {
        for (const v of vulnsLegacy) {
          const compName = (v.component ?? '').trim();
          const compVersion = (v.version ?? '').trim();
          let pdId = pdByNameVersion.get(`${compName}@${compVersion}`);
          if (!pdId) {
            pdId = pdByNameVersionNorm.get(`${normalizeDepName(compName, jobEcosystem)}@${compVersion}`);
          }
          if (!pdId) continue;
          const severity = v.severity ?? v.ratings?.[0]?.severity ?? null;
          vulnRows.push({
            project_id: projectId, project_dependency_id: pdId,
            osv_id: (v.vuln_id ?? v.id ?? 'unknown').toString(),
            extraction_run_id: runId,
            severity,
            summary: v.summary ?? null, aliases: v.aliases ?? null,
            fixed_versions: v.fixed_version ? [v.fixed_version] : null,
            is_reachable: true, epss_score: v.epss ?? null,
            cvss_score: severity ? (SEVERITY_TO_CVSS[severity] ?? null) : null,
            cisa_kev: false, depscore: null, published_at: null,
            base_depscore_no_reachability: null,
            reachability_status: 'reachable',
            epd_status: 'pending',
            epd_schema_version: 'epd-v1',
            epd_prompt_version: 'epd-v1',
          });
        }
      }

      const CVE_ID_RE = /^CVE-\d{4}-\d+$/i;
      const cvesToFetch = [...new Set(vulnRows.map((r) => r.osv_id).filter((id) => CVE_ID_RE.test(id)))];
      if (cvesToFetch.length > 0) {
        const epssByCve = new Map<string, number>();
        // Seed from the in-process EPSS cache; only query FIRST for CVEs we
        // haven't scored recently (see getCachedEpss). EPSS refreshes ~daily, so
        // the 6h TTL keeps the saved network round-trips fresh enough.
        const uncached: string[] = [];
        for (const cve of cvesToFetch) {
          const cached = getCachedEpss(cve);
          if (cached != null) epssByCve.set(cve, cached);
          else uncached.push(cve);
        }
        const EPSS_BATCH = 80;
        for (let i = 0; i < uncached.length; i += EPSS_BATCH) {
          const batch = uncached.slice(i, i + EPSS_BATCH);
          try {
            const epssRes = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(batch.join(','))}`, { signal: AbortSignal.timeout(15000) });
            if (epssRes.ok) {
              const json = (await epssRes.json()) as { data?: Array<{ cve?: string; epss?: string }> };
              for (const row of json.data ?? []) {
                if (row?.cve && row?.epss != null) {
                  const score = parseFloat(row.epss);
                  if (Number.isFinite(score)) {
                    epssByCve.set(row.cve, score);
                    setCachedEpss(row.cve, score);
                  }
                }
              }
            }
          } catch { /* non-fatal */ }
        }
        for (const row of vulnRows) {
          if (row.epss_score != null) continue;
          const score = epssByCve.get(row.osv_id);
          if (score != null) row.epss_score = score;
        }
      }

      for (const row of vulnRows) {
        const allIds = [row.osv_id, ...(row.aliases ?? [])];
        row.cisa_kev = allIds.some((id) => CVE_ID_RE.test(id) && kevCveSet.has(id));
        // SC1: thread directness + dev-scope from the matched project_dependencies
        // row so the dependency-context taper (0.75× transitive, 0.4× dev) is no
        // longer dead. See scoreVulnRow.
        //
        // BOUNDARY (cross-owner): this is the INITIAL score. The authoritative
        // FINAL rescore lives in pipeline-steps/reachability.ts (after the taint
        // classifier sets reachability_level) and is the value that actually
        // ships. That rescore currently re-reads only PDV columns and does NOT
        // join project_dependencies, so it still passes no directness/scope and
        // overwrites this taper away in the full pipeline. For SC1 to be durable
        // end-to-end, reachability.ts's rescore must join is_direct + environment
        // and pass them through the same way — flagged for the reachability owner.
        const { depscore, base_depscore_no_reachability } = scoreVulnRow(
          row,
          pdById.get(row.project_dependency_id),
          importance,
        );
        row.base_depscore_no_reachability = base_depscore_no_reachability;
        row.depscore = depscore;
      }

      if (vulnRows.length > 0) {
        // Deduplicate within this extraction run (same vuln reported twice by dep-scan
        // under different affects entries). Stable ID for this run: (pd_id, osv_id).
        const seenVuln = new Set<string>();
        const dedupedVulns = vulnRows.filter((r) => {
          const k = `${r.project_dependency_id}|${r.osv_id}`;
          if (seenVuln.has(k)) return false;
          seenVuln.add(k);
          return true;
        });
        for (let i = 0; i < dedupedVulns.length; i += 100) {
          const chunk = dedupedVulns.slice(i, i + 100);
          const { error: insertErr } = await supabase
            .from('project_dependency_vulnerabilities')
            .insert(chunk);
          if (insertErr) {
            // One bad chunk must not drop every remaining vulnerability — log
            // the failing chunk range and continue with the rest.
            await log.warn('vuln_scan', `Failed to insert vulnerability chunk ${i}-${i + chunk.length - 1}: ${insertErr.message}`);
          }
        }
      }

    } catch (e: any) {
      await log.warn('vuln_scan', `Vulnerability processing failed: ${e.message}`);
    }
  } else if (!depScanSucceeded) {
    await log.warn('vuln_scan', 'No vulnerability scan results available');
  }

  return { scanStart };
}
