/**
 * Pipeline step: malicious-package scan.
 *
 * Runs after tree-sitter, before Semgrep. For each (package, version) in
 * the project lockfile:
 *   1. Look up `known_malicious_packages` (feed lookup) — DB-only, free.
 *   2. On cache miss for `package_security_cache` (scanner='guarddog'),
 *      download the tarball into per-job ephemeral storage with zip-slip
 *      + decompression-bomb sandbox checks, then run GuardDog over the
 *      unpacked tree.
 *   3. Cache the GuardDog raw findings keyed (package, version, ecosystem,
 *      'guarddog') so a second viewer of the same package never re-pays
 *      the scan cost.
 *   4. Filter cached rules + feed hits into `PendingFinding` rows and
 *      hand them off to the atomic `insert_malicious_findings_with_recompute`
 *      RPC at the end of the loop.
 *
 * Soft-fail: per-package failures are caught and counted; the step
 * computes `scan_status` ∈ {complete, partial, failed} and ONLY throws
 * when 100% of packages errored (so the extraction job is correctly
 * marked failed for an obvious infrastructure outage).
 */
import * as crypto from 'crypto';
import type { Storage } from './storage';
import { canonicalizeEcosystem } from './malicious/ecosystem';
import { lookupFeed } from './malicious/feeds';
import { isGuardDogAvailable, runGuardDog, GUARDDOG_VERSION, type GuardDogRule } from './malicious/guarddog';
import { TarballCache } from './malicious/tarball-cache';
import {
  insertFindingsBatch,
  readCapabilityCache,
  severityForFeed,
  severityForGuardDogRule,
  upsertCapabilityCache,
  upsertGuardDogCache,
  type PendingFinding,
} from './malicious/insert-finding';
import {
  CAPABILITY_SCANNER_VERSION,
  detectCapabilities,
} from './malicious/capabilities';
import {
  buildReachabilityIndex,
  computeReachability,
  type ReachabilityIndex,
} from './malicious/reachability';
import {
  extractUsage,
  type SupportedEcosystem,
  type KnownDep,
} from './tree-sitter-extractor';

export type MaliciousScanStatus = 'complete' | 'partial' | 'failed';

export interface MaliciousScanResult {
  status: MaliciousScanStatus;
  total_packages: number;
  scanned_packages: number;
  failed_packages: number;
  feed_hits: number;
  guarddog_hits: number;
  inserted_findings: number;
  /**
   * Newly-inserted finding IDs, used for event emission. Empty array if
   * the RPC returned 0 (idempotent re-run with no new rows).
   */
  inserted_finding_ids: string[];
}

export interface MaliciousScanContext {
  supabase: Storage;
  projectId: string;
  organizationId: string;
  extractionRunId: string;
  jobId: string;
  packages: Array<{
    project_dependency_id: string;
    dependency_id: string;
    name: string;
    ecosystem: string;
    version: string | null;
  }>;
  /**
   * Absolute path to the workspace root the pipeline cloned/checked out.
   * Used to build the per-project tree-sitter index that powers
   * reachability classification. Optional so older callers (and unit
   * tests) can omit it — when null the resolver falls back to leaving
   * `reachability_level` null on every finding.
   */
  workspaceRoot?: string | null;
  /**
   * Canonical ecosystem of the workspace as a whole (matches the
   * `SupportedEcosystem` type the tree-sitter extractor accepts). Used
   * only to drive `extractUsage` — per-package import resolution still
   * dispatches per finding's own ecosystem.
   */
  workspaceEcosystem?: SupportedEcosystem | null;
  log: {
    info: (step: string, msg: string) => Promise<void> | void;
    warn: (step: string, msg: string) => Promise<void> | void;
    success: (step: string, msg: string, durationMs?: number) => Promise<void> | void;
    error?: (step: string, msg: string) => Promise<void> | void;
  };
  checkCancelled?: () => Promise<boolean>;
  heartbeat?: () => Promise<void>;
}

const STEP = 'malicious_scan';

export async function runMaliciousScan(ctx: MaliciousScanContext): Promise<MaliciousScanResult> {
  const start = Date.now();

  if (ctx.packages.length === 0) {
    return {
      status: 'complete',
      total_packages: 0,
      scanned_packages: 0,
      failed_packages: 0,
      feed_hits: 0,
      guarddog_hits: 0,
      inserted_findings: 0,
      inserted_finding_ids: [],
    };
  }

  await ctx.log.info(STEP, `Scanning ${ctx.packages.length} packages for malicious indicators...`);

  // Build the per-project reachability index ONCE up front. Self-contained:
  // does not depend on the Phase 6 taint engine's rollout-pct / circuit
  // breaker — runs unconditionally so reachability lands on every finding
  // regardless of `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT`.
  const reachabilityIndex = await buildWorkspaceReachabilityIndex(ctx);

  const cache = new TarballCache(ctx.jobId);
  const guarddogAvailable = isGuardDogAvailable();
  if (!guarddogAvailable) {
    await ctx.log.warn(STEP, 'GuardDog binary not available at /opt/guarddog-venv/bin/guarddog — feed lookup only this run.');
  }

  const pending: PendingFinding[] = [];
  let scanned = 0;
  let failed = 0;
  let feedHits = 0;
  let guarddogHits = 0;
  const lastHeartbeat = { at: Date.now() };

  try {
    for (const pkg of ctx.packages) {
      if (ctx.checkCancelled && (await ctx.checkCancelled())) {
        await ctx.log.warn(STEP, 'Scan cancelled — releasing worker.');
        break;
      }

      // Heartbeat every ~30s so the stuck-job recovery cron doesn't
      // reclaim a long-running scan.
      if (ctx.heartbeat && Date.now() - lastHeartbeat.at > 30_000) {
        try {
          await ctx.heartbeat();
        } catch { /* non-fatal */ }
        lastHeartbeat.at = Date.now();
      }

      const canonical = canonicalizeEcosystem(pkg.ecosystem);
      if (!canonical) {
        // Unrecognized ecosystem — skip cleanly (not a failure).
        scanned++;
        continue;
      }
      if (!pkg.version) {
        scanned++;
        continue;
      }

      try {
        // 1) Feed lookup
        const hits = await lookupFeed(ctx.supabase, pkg.name, canonical, pkg.version);
        for (const hit of hits) {
          feedHits++;
          pending.push(
            attachReachability(
              {
                project_id: ctx.projectId,
                organization_id: ctx.organizationId,
                extraction_run_id: ctx.extractionRunId,
                project_dependency_id: pkg.project_dependency_id,
                dependency_id: pkg.dependency_id,
                rule_id: `${hit.source}:${hit.source_id}`,
                scanner: 'feed',
                severity: severityForFeed(hit),
                message: hit.description ?? `Listed in ${hit.source.toUpperCase()} (${hit.source_id})`,
                depscore: null,
              },
              reachabilityIndex,
              pkg.name,
              canonical,
            ),
          );
        }

        // 2) Cache lookups for BOTH consumers — GuardDog and capability
        //    scan share an unpacked tree to avoid downloading the tarball
        //    twice. We check both caches up front and only unpack when at
        //    least one consumer needs the source.
        const cachedRules = guarddogAvailable
          ? await readGuardDogCache(ctx.supabase, pkg.name, pkg.version, canonical)
          : [];
        const cachedCapabilities = await readCapabilityCache(ctx.supabase, pkg.name, pkg.version, canonical);

        const guarddogCacheHit = !guarddogAvailable || cachedRules.length > 0;
        const capabilityCacheHit =
          cachedCapabilities !== null &&
          cachedCapabilities.scanner_version === CAPABILITY_SCANNER_VERSION;
        const needsUnpack = !guarddogCacheHit || !capabilityCacheHit;

        let rules: GuardDogRule[] = cachedRules;

        if (needsUnpack) {
          const entry = await cache.fetch(canonical, pkg.name, pkg.version);
          if (entry) {
            // GuardDog consumer
            if (guarddogAvailable && !guarddogCacheHit) {
              const result = runGuardDog(entry.dir, canonical, pkg.name);
              rules = result.rules;
              await upsertGuardDogCache(ctx.supabase, {
                package_name: pkg.name,
                version: pkg.version,
                ecosystem: canonical,
                scanner: 'guarddog',
                scanner_version: GUARDDOG_VERSION,
                findings: rules,
                risk_level: rules.length === 0 ? 'none' : highestSeverity(rules),
              });
            }

            // Capability consumer (soft-fail: errors land as scan_error
            // on the cache row; pipeline still inserts findings normally)
            if (!capabilityCacheHit) {
              const capResult = detectCapabilities(entry.dir, canonical, pkg.name);
              await upsertCapabilityCache(ctx.supabase, {
                package_name: pkg.name,
                version: pkg.version,
                ecosystem: canonical,
                scanner_version: capResult.scanner_version,
                capabilities: capResult.capabilities,
                scan_error: capResult.scan_error,
              });
            }
          }
        }

        if (guarddogAvailable) {
          for (const rule of rules) {
            guarddogHits++;
            pending.push(
              attachReachability(
                {
                  project_id: ctx.projectId,
                  organization_id: ctx.organizationId,
                  extraction_run_id: ctx.extractionRunId,
                  project_dependency_id: pkg.project_dependency_id,
                  dependency_id: pkg.dependency_id,
                  rule_id: `guarddog:${rule.rule_id}`,
                  scanner: 'guarddog',
                  severity: severityForGuardDogRule(rule),
                  message: rule.message,
                  depscore: null,
                },
                reachabilityIndex,
                pkg.name,
                canonical,
              ),
            );
          }
        }
        scanned++;
      } catch (err: any) {
        failed++;
        if (ctx.log.error) {
          await ctx.log.error(STEP, `Failed to scan ${pkg.name}@${pkg.version}: ${err?.message ?? err}`);
        } else {
          await ctx.log.warn(STEP, `Failed to scan ${pkg.name}@${pkg.version}: ${err?.message ?? err}`);
        }
      }
    }
  } finally {
    cache.cleanup();
  }

  const status: MaliciousScanStatus =
    failed === 0
      ? 'complete'
      : failed === ctx.packages.length
        ? 'failed'
        : 'partial';

  // Hard-fail only when every package errored (clear infra outage).
  if (status === 'failed') {
    throw new Error(`malicious-scan failed for all ${ctx.packages.length} packages`);
  }

  // Atomic batch insert + recompute is_malicious (RPC).
  const { inserted, rpcError } = await insertFindingsBatch(ctx.supabase, pending);
  if (rpcError) {
    await ctx.log.warn(STEP, `Failed to persist findings: ${rpcError}`);
  }

  // Apply org-wide allowlist after insert: any matching finding is
  // soft-suppressed with `suppressed_reason='allowlist:<entry_id>'`.
  // Soft-fail — RPC failure logs a warn but doesn't fail the scan.
  if (inserted > 0) {
    try {
      const { data: suppressed, error: allowlistError } = await ctx.supabase.rpc<number>(
        'apply_malicious_allowlist',
        { p_org_id: ctx.organizationId, p_extraction_run_id: ctx.extractionRunId },
      );
      if (allowlistError) {
        await ctx.log.warn(STEP, `apply_malicious_allowlist RPC failed: ${allowlistError.message}`);
      } else if (typeof suppressed === 'number' && suppressed > 0) {
        await ctx.log.info(STEP, `Auto-suppressed ${suppressed} finding(s) via org allowlist.`);
      }
    } catch (err: any) {
      await ctx.log.warn(STEP, `apply_malicious_allowlist threw: ${err?.message ?? err}`);
    }
  }

  // We don't get IDs back from the RPC currently; emit a single sha256
  // dedup key based on (org, project, run) instead — see M1.10.
  const insertedIds: string[] = [];

  await ctx.log.success(
    STEP,
    `${scanned}/${ctx.packages.length} scanned, ${feedHits} feed + ${guarddogHits} GuardDog hits, ${inserted} new findings (${status})`,
    Date.now() - start,
  );

  return {
    status,
    total_packages: ctx.packages.length,
    scanned_packages: scanned,
    failed_packages: failed,
    feed_hits: feedHits,
    guarddog_hits: guarddogHits,
    inserted_findings: inserted,
    inserted_finding_ids: insertedIds,
  };
}

async function readGuardDogCache(
  supabase: Storage,
  packageName: string,
  version: string,
  ecosystem: string,
): Promise<GuardDogRule[]> {
  const { data, error } = await supabase
    .from('package_security_cache')
    .select('findings')
    .eq('package_name', packageName)
    .eq('version', version)
    .eq('ecosystem', ecosystem)
    .eq('scanner', 'guarddog')
    .maybeSingle();
  if (error || !data) return [];
  const rows = (data as { findings?: GuardDogRule[] }).findings ?? [];
  return Array.isArray(rows) ? rows : [];
}

function highestSeverity(rules: GuardDogRule[]): 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none' {
  let best: 'high' | 'medium' | 'info' | null = null;
  for (const r of rules) {
    const cur = (r.severity ?? '').toUpperCase();
    if (cur === 'ERROR') return 'high';
    if (cur === 'WARNING' && best !== 'medium') best = 'medium';
    if (cur === 'INFO' && !best) best = 'info';
  }
  return best ?? 'none';
}

/**
 * Public dedup-key helper used by the event-emission path so the M1.6
 * step body and M1.10 wiring use the same hash function.
 */
export function eventDeduplicationKey(
  organizationId: string,
  projectId: string,
  extractionRunId: string,
): string {
  return crypto
    .createHash('sha256')
    .update(`${organizationId}|${projectId}|${extractionRunId}`)
    .digest('hex');
}

/**
 * Build the per-project tree-sitter usage index used by `attachReachability`.
 * Returns null when the workspace info isn't available (older callers /
 * unit tests / unsupported ecosystem) so the per-finding helper can skip
 * resolution cleanly.
 *
 * Exported for unit testing — production callers go through runMaliciousScan.
 */
export async function buildWorkspaceReachabilityIndex(
  ctx: MaliciousScanContext,
): Promise<ReachabilityIndex | null> {
  if (!ctx.workspaceRoot || !ctx.workspaceEcosystem) return null;

  // Derive the deps the extractor needs to resolve imports against from
  // the package list the pipeline already passed us. `namespace` is null
  // for flat ecosystems (npm/pypi/gem/go/cargo/composer/nuget); Maven is
  // the one ecosystem that needs groupId, but the pipeline currently
  // passes the colon-joined name in `pkg.name` so the namespace can be
  // null here too — the import-mapping module handles the split itself.
  const deps: KnownDep[] = ctx.packages.map((p) => ({ name: p.name, namespace: null }));

  try {
    const { files } = await extractUsage({
      workspaceRoot: ctx.workspaceRoot,
      ecosystem: ctx.workspaceEcosystem,
      deps,
    });
    return buildReachabilityIndex(files, ctx.workspaceEcosystem, deps);
  } catch (err: any) {
    await ctx.log.warn(
      STEP,
      `Reachability index build failed; findings will land with reachability_level=null: ${err?.message ?? err}`,
    );
    return null;
  }
}

/**
 * Resolve reachability for a single finding and attach to the payload.
 * Wrapped in its own try/catch so a single resolver throw doesn't drop
 * the finding — it lands with `reachability_level=null` and an
 * `error: 'compute_failed'` marker in `reachability_details`.
 *
 * Exported for unit testing — production callers go through runMaliciousScan.
 */
export function attachReachability(
  finding: PendingFinding,
  index: ReachabilityIndex | null,
  packageName: string,
  ecosystem: string,
): PendingFinding {
  if (!index) {
    return { ...finding, reachability_level: null, reachability_details: null };
  }
  try {
    const result = computeReachability(index, packageName, ecosystem);
    return {
      ...finding,
      reachability_level: result.level,
      reachability_details: result.details,
    };
  } catch (err: any) {
    return {
      ...finding,
      reachability_level: null,
      reachability_details: { error: 'compute_failed', message: String(err?.message ?? err) },
    };
  }
}
