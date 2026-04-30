import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { SupabaseClient } from '@supabase/supabase-js';
import { withTimeout, logStepError, classifyError, type ScannerSubprocessLogger } from '../with-timeout';
import {
  createInstallationToken,
  getInstallationAccount,
} from '../github';
import { detectInfraTypes, findDockerfiles, type InfraType } from './detect-infra';
import { runCheckov } from './checkov';
import {
  classifyImageRef,
  parseDockerfileFinalStage,
  runTrivyConfig,
  runTrivyImage,
} from './trivy';
import {
  upsertContainerFindings,
  upsertIaCFindings,
} from './storage';
import type { IaCFinding, IaCFramework, SkippedImage } from './types';

const CHECKOV_TIMEOUT_MS = Number(
  process.env.DEPTEX_CHECKOV_TIMEOUT_MS ?? 5 * 60_000
);
const TRIVY_CONFIG_TIMEOUT_MS = Number(
  process.env.DEPTEX_TRIVY_CONFIG_TIMEOUT_MS ?? 3 * 60_000
);
const TRIVY_IMAGE_TIMEOUT_MS = Number(
  process.env.DEPTEX_TRIVY_IMAGE_TIMEOUT_MS ?? 8 * 60_000
);
const VERBOSE_TRIVY = process.env.DEPTEX_TRIVY_VERBOSE_LOG === '1';
const VERBOSE_CHECKOV = process.env.DEPTEX_CHECKOV_VERBOSE_LOG === '1';

export interface ScannerSummary {
  infraTypes: InfraType[];
  iacFindingsWritten: number;
  containerFindingsWritten: number;
  skippedImages: SkippedImage[];
  warnings: string[];
}

export interface ScannerStepContext {
  supabase: SupabaseClient;
  projectId: string;
  organizationId: string;
  jobId: string | null;
  runId: string;
  repoPath: string;
  /** Pulled from organizations.github_installation_id at pipeline start. */
  githubInstallationId: string | null;
  logger: ScannerSubprocessLogger;
  onHeartbeat: () => Promise<void>;
}

interface KillSwitchContext {
  iacEnabled: boolean;
  containerEnabled: boolean;
  trivyKilled: boolean;
  checkovKilled: boolean;
  redisFallback: boolean;
}

/**
 * Read the IaC + container kill switches and feature flags. Redis lookups
 * carry a 1s timeout + try/catch — on Redis failure we fall back to env-flag
 * defaults rather than failing-closed (the env flag is the source of truth
 * for "is this scanner allowed to run at all"; Redis is the kill switch
 * layer on top of it).
 */
async function resolveKillSwitches(): Promise<KillSwitchContext> {
  const iacEnabled = process.env.SCANNERS_IAC_ENABLED !== 'false';
  const containerEnabled = process.env.SCANNERS_CONTAINER_ENABLED !== 'false';

  const redisUrl = process.env.UPSTASH_REDIS_URL ?? process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.UPSTASH_REDIS_TOKEN ?? process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!redisUrl || !redisToken) {
    return {
      iacEnabled,
      containerEnabled,
      trivyKilled: false,
      checkovKilled: false,
      redisFallback: false,
    };
  }

  const fetchOne = async (key: string): Promise<string | null> => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 1000);
    try {
      const res = await fetch(`${redisUrl}/get/${encodeURIComponent(key)}`, {
        headers: { Authorization: `Bearer ${redisToken}` },
        signal: ctrl.signal,
      });
      if (!res.ok) return null;
      const body = (await res.json()) as { result?: string | null };
      return body.result ?? null;
    } finally {
      clearTimeout(timer);
    }
  };

  try {
    const [trivy, checkov] = await Promise.all([
      fetchOne('kill:scanner:trivy'),
      fetchOne('kill:scanner:checkov'),
    ]);
    return {
      iacEnabled,
      containerEnabled,
      trivyKilled: trivy === '1' || trivy === 'true',
      checkovKilled: checkov === '1' || checkov === 'true',
      redisFallback: false,
    };
  } catch {
    return {
      iacEnabled,
      containerEnabled,
      trivyKilled: false,
      checkovKilled: false,
      redisFallback: true,
    };
  }
}

/**
 * Optional rollout allowlist for staged dogfood. Honors empty/unset = all
 * orgs. Per the v1 scope decision the allowlist defaults to disabled (Redis
 * kill switches and env flags already cover the rollback story for a 1-user
 * v1) but we still read SCANNERS_ROLLOUT_ALLOWLIST so an operator can
 * temporarily scope a re-enable to a subset of orgs without redeploying.
 */
function isAllowedOrg(orgId: string): boolean {
  const raw = process.env.SCANNERS_ROLLOUT_ALLOWLIST;
  if (!raw) return true;
  const list = raw.split(',').map((s) => s.trim()).filter(Boolean);
  if (list.length === 0) return true;
  return list.includes(orgId);
}

/**
 * Build a docker config.json suitable for Trivy's DOCKER_AUTH_CONFIG env.
 * Contains a single ghcr.io entry with x-access-token + the GitHub App
 * installation token. The token never appears in argv or environment except
 * inside this JSON blob.
 */
function buildGhcrDockerAuth(token: string): string {
  const auth = Buffer.from(`x-access-token:${token}`).toString('base64');
  return JSON.stringify({
    auths: {
      'ghcr.io': { auth },
    },
  });
}

/**
 * Pull the final-stage image for each Dockerfile and run Trivy image. Applies
 * Patch C namespace check before any pull. Returns aggregated findings +
 * skipped-image surface for the scanner-summary endpoint.
 */
async function scanDockerfileImages(
  ctx: ScannerStepContext
): Promise<{
  findings: import('./types').ContainerFinding[];
  scannerVersion: string;
  skipped: SkippedImage[];
  warnings: string[];
}> {
  const dockerfiles = findDockerfiles(ctx.repoPath);
  if (dockerfiles.length === 0) {
    return { findings: [], scannerVersion: '', skipped: [], warnings: [] };
  }

  const skipped: SkippedImage[] = [];
  const warnings: string[] = [];
  const aggregated: import('./types').ContainerFinding[] = [];
  let scannerVersion = '';

  // Resolve installation account ONCE per pipeline run (used by the namespace
  // check for every ghcr.io image).
  let installationLogin: string | null = null;
  if (ctx.githubInstallationId) {
    try {
      const acct = await getInstallationAccount(ctx.githubInstallationId);
      installationLogin = acct?.login.toLowerCase() ?? null;
    } catch {
      // Resolution failure is non-fatal — every ghcr.io image will be
      // conservatively skipped (better than risking a cross-tenant pull).
      installationLogin = null;
    }
  }

  for (const dockerfilePath of dockerfiles) {
    const finalStage = parseDockerfileFinalStage(dockerfilePath);
    if (!finalStage) {
      skipped.push({ image: dockerfilePath, reason: 'parse_failed' });
      continue;
    }
    const eligibility = classifyImageRef(finalStage.imageRef);

    let dockerAuthConfig: string | undefined;
    if (eligibility.kind === 'unsupported_registry') {
      skipped.push({
        image: finalStage.imageRef,
        reason: 'private_registry_unsupported_at_v1',
      });
      continue;
    }
    if (eligibility.kind === 'ghcr') {
      if (!ctx.githubInstallationId || !installationLogin) {
        skipped.push({
          image: finalStage.imageRef,
          reason: 'ghcr_namespace_mismatch',
        });
        continue;
      }
      if (eligibility.owner.toLowerCase() !== installationLogin) {
        skipped.push({
          image: finalStage.imageRef,
          reason: 'ghcr_namespace_mismatch',
        });
        continue;
      }
      try {
        const token = await createInstallationToken(ctx.githubInstallationId);
        dockerAuthConfig = buildGhcrDockerAuth(token);
      } catch (err: any) {
        warnings.push(`ghcr_token_failed:${err?.message ?? 'unknown'}`);
        skipped.push({
          image: finalStage.imageRef,
          reason: 'ghcr_namespace_mismatch',
        });
        continue;
      }
    }

    try {
      const result = await withTimeout(
        async (signal) =>
          runTrivyImage({
            imageRef: finalStage.imageRef,
            dockerAuthConfig,
            signal,
            onHeartbeat: ctx.onHeartbeat,
            logger: ctx.logger,
            verboseLog: VERBOSE_TRIVY,
          }),
        TRIVY_IMAGE_TIMEOUT_MS,
        'container_scan'
      );
      scannerVersion = result.version || scannerVersion;
      warnings.push(...result.warnings);
      aggregated.push(...result.findings);
    } catch (err: any) {
      warnings.push(`trivy_image_failed:${err?.message ?? 'unknown'}`);
    }
  }

  return { findings: aggregated, scannerVersion, skipped, warnings };
}

export async function runIaCAndContainerScans(
  ctx: ScannerStepContext
): Promise<ScannerSummary> {
  const summary: ScannerSummary = {
    infraTypes: [],
    iacFindingsWritten: 0,
    containerFindingsWritten: 0,
    skippedImages: [],
    warnings: [],
  };

  if (!isAllowedOrg(ctx.organizationId)) {
    summary.warnings.push('rollout_allowlist_excluded');
    await ctx.logger.warn('detect_infra', 'Org not in SCANNERS_ROLLOUT_ALLOWLIST — skipping');
    return summary;
  }

  const switches = await resolveKillSwitches();
  if (switches.redisFallback) {
    summary.warnings.push('redis_kill_switch_unreachable');
    await ctx.logger.warn(
      'detect_infra',
      'Redis kill-switch lookup failed; falling back to env flags'
    );
  }

  // ---- Detect ----
  await ctx.logger.info('detect_infra', 'Scanning workspace for infra files...');
  const infraTypes = detectInfraTypes(ctx.repoPath);
  summary.infraTypes = infraTypes;
  if (infraTypes.length === 0) {
    await ctx.logger.info('detect_infra', 'No infra files detected — skipping IaC + container scans');
    return summary;
  }
  await ctx.logger.info(
    'detect_infra',
    `Detected: ${infraTypes.join(', ')}`
  );

  // ---- IaC scan (Checkov + Trivy config in parallel) ----
  if (!switches.iacEnabled) {
    summary.warnings.push('iac_disabled_by_env');
    await ctx.logger.warn('iac_scan', 'SCANNERS_IAC_ENABLED=false — skipping IaC scan');
  } else {
    const iacFindings: IaCFinding[] = [];
    const iacFrameworks: IaCFramework[] = infraTypes.filter(
      (t): t is Exclude<IaCFramework, 'dockerfile'> => t === 'terraform' || t === 'kubernetes'
    );

    const tasks: Array<Promise<void>> = [];

    if (!switches.checkovKilled && iacFrameworks.length > 0) {
      tasks.push(
        (async () => {
          try {
            const result = await withTimeout(
              async (signal) =>
                runCheckov({
                  repoPath: ctx.repoPath,
                  frameworks: iacFrameworks,
                  signal,
                  onHeartbeat: ctx.onHeartbeat,
                  logger: ctx.logger,
                  verboseLog: VERBOSE_CHECKOV,
                }),
              CHECKOV_TIMEOUT_MS,
              'iac_scan_checkov'
            );
            iacFindings.push(...result.findings);
            summary.warnings.push(...result.warnings);
          } catch (err: any) {
            summary.warnings.push(`checkov_failed:${err?.message ?? 'unknown'}`);
            await logStepError(ctx.supabase as any, {
              jobId: ctx.jobId ?? 'unknown',
              projectId: ctx.projectId,
              step: 'iac_scan_checkov',
              ...classifyError(err),
              severity: 'warn',
            });
          }
        })()
      );
    } else if (switches.checkovKilled) {
      summary.warnings.push('checkov_killswitch');
      await ctx.logger.warn('iac_scan', 'kill:scanner:checkov is set — skipping');
    }

    const hasDockerfile = infraTypes.includes('dockerfile');
    if (!switches.trivyKilled && hasDockerfile) {
      tasks.push(
        (async () => {
          try {
            const result = await withTimeout(
              async (signal) =>
                runTrivyConfig({
                  repoPath: ctx.repoPath,
                  signal,
                  onHeartbeat: ctx.onHeartbeat,
                  logger: ctx.logger,
                  verboseLog: VERBOSE_TRIVY,
                }),
              TRIVY_CONFIG_TIMEOUT_MS,
              'iac_scan_trivy'
            );
            iacFindings.push(...result.findings);
            summary.warnings.push(...result.warnings);
          } catch (err: any) {
            summary.warnings.push(`trivy_config_failed:${err?.message ?? 'unknown'}`);
            await logStepError(ctx.supabase as any, {
              jobId: ctx.jobId ?? 'unknown',
              projectId: ctx.projectId,
              step: 'iac_scan_trivy',
              ...classifyError(err),
              severity: 'warn',
            });
          }
        })()
      );
    } else if (switches.trivyKilled) {
      summary.warnings.push('trivy_killswitch');
      await ctx.logger.warn('iac_scan', 'kill:scanner:trivy is set — skipping');
    }

    await Promise.all(tasks);

    try {
      const upsert = await upsertIaCFindings(
        ctx.supabase,
        ctx.projectId,
        ctx.runId,
        iacFindings
      );
      summary.iacFindingsWritten = upsert.inserted;
      await ctx.logger.info(
        'iac_scan',
        `IaC scan complete — ${upsert.inserted} findings written`
      );
    } catch (err: any) {
      summary.warnings.push(`iac_storage_failed:${err?.message ?? 'unknown'}`);
      await logStepError(ctx.supabase as any, {
        jobId: ctx.jobId ?? 'unknown',
        projectId: ctx.projectId,
        step: 'iac_scan_storage',
        ...classifyError(err),
        severity: 'warn',
      });
    }
  }

  // ---- Container scan (Trivy image on Dockerfile FINAL stage) ----
  if (!switches.containerEnabled) {
    summary.warnings.push('container_disabled_by_env');
    await ctx.logger.warn(
      'container_scan',
      'SCANNERS_CONTAINER_ENABLED=false — skipping container scan'
    );
  } else if (switches.trivyKilled) {
    summary.warnings.push('container_skipped_trivy_killswitch');
    await ctx.logger.warn(
      'container_scan',
      'kill:scanner:trivy is set — skipping container scan'
    );
  } else if (!infraTypes.includes('dockerfile')) {
    await ctx.logger.info(
      'container_scan',
      'No Dockerfile detected — skipping container scan'
    );
  } else {
    try {
      const containerResult = await scanDockerfileImages(ctx);
      summary.skippedImages.push(...containerResult.skipped);
      summary.warnings.push(...containerResult.warnings);
      const upsert = await upsertContainerFindings(
        ctx.supabase,
        ctx.projectId,
        ctx.runId,
        containerResult.findings
      );
      summary.containerFindingsWritten = upsert.inserted;
      await ctx.logger.info(
        'container_scan',
        `Container scan complete — ${upsert.inserted} findings written, ${containerResult.skipped.length} images skipped`
      );
    } catch (err: any) {
      summary.warnings.push(`container_failed:${err?.message ?? 'unknown'}`);
      await logStepError(ctx.supabase as any, {
        jobId: ctx.jobId ?? 'unknown',
        projectId: ctx.projectId,
        step: 'container_scan',
        ...classifyError(err),
        severity: 'warn',
      });
    }
  }

  return summary;
}

export const SCANNER_TIMEOUTS = {
  CHECKOV_TIMEOUT_MS,
  TRIVY_CONFIG_TIMEOUT_MS,
  TRIVY_IMAGE_TIMEOUT_MS,
};

/** Used by the rescan endpoint — exposed for parity with depscan setup. */
export function ensureWorkspaceTmp(): string {
  const tmp = path.join(os.tmpdir(), 'deptex-iac-cache');
  try {
    fs.mkdirSync(tmp, { recursive: true });
  } catch {
    /* non-fatal */
  }
  return tmp;
}
