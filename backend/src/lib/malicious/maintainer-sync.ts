/**
 * Daily maintainer-signal sync orchestrator.
 *
 * Driven by `POST /api/internal/malicious/maintainer-signal-sync` (QStash
 * cron-dispatched once per day):
 *
 *   1. Pull active dependencies (`last_seen_at > now-30d`) for the
 *      ecosystems v2 has registry clients for (npm, PyPI, RubyGems). Other
 *      canonical ecosystems are skipped — the maintainer-signals lib logs
 *      a "stub" warning once per ecosystem.
 *   2. Iterate top-N by `last_seen_at DESC` (cap per cron run so we stay
 *      inside QStash's 10-min execution budget — over a week, a 200-pkg
 *      cap covers ~1400 most-active packages).
 *   3. For each (dep, latest-observed-version), `computeMaintainerSignals`
 *      pulls registry metadata, snapshots it, and diffs against the 30-day
 *      baseline.
 *   4. `severityForMaintainerSignal` collapses the signal set into one
 *      best-fit finding (or null). Cold-start packages with no install
 *      hook produce null and are skipped.
 *   5. Fan out per-project — every `project_dependency` referencing this
 *      `(dependency_id, version)` writes a finding with `organization_id`
 *      derived via JOIN through `projects`. The `enforce_pmf_org_consistency`
 *      trigger backstops the JOIN result; never trust caller-supplied org_id.
 *   6. `notification_events` row + immediate dispatch trigger when severity
 *      is critical or high — same shim path the extraction worker uses.
 *
 * Multi-tenant invariants:
 *   - `organization_id` ALWAYS comes from `projects.organization_id` per
 *     row, never from the caller, the dep table, or any constant.
 *   - `package_maintainer_snapshots` is a global cache; rows never include
 *     project / org-derived data.
 *   - Per-package failures are caught and logged — one bad package can't
 *     kill the run.
 */
import { type SupabaseClient } from '@supabase/supabase-js';
import { canonicalizeEcosystem } from './ecosystem';
import {
  computeMaintainerSignalsForPackage,
  type ComputeOptions,
} from './maintainer-signals';
import { severityForMaintainerSignal } from './severity';

export interface MaintainerSyncOptions {
  /** Cap per run; defaults to 200 (≈10 min budget at ~3s/pkg). */
  limit?: number;
  /** Override clock for tests. */
  now?: Date;
  /** Inject fetch for tests (passed through to the registry-pull lib). */
  fetcher?: typeof fetch;
}

export interface MaintainerSyncResult {
  scanned: number;          // packages we successfully pulled metadata for
  signals_fired: number;    // packages whose severity calibration returned a finding
  findings_inserted: number;// rows actually inserted via the RPC (idempotent)
  errors: number;           // per-package fetch / classify failures (non-fatal)
  ecosystems_skipped: string[]; // ecosystems we don't have a registry client for
}

const DEFAULT_LIMIT = 200;
const SUPPORTED_ECOSYSTEMS = ['npm', 'pypi', 'rubygems'] as const;
const STALE_THRESHOLD_MS = 30 * 24 * 60 * 60 * 1000;

interface DependencyRow {
  id: string;
  name: string;
  ecosystem: string;
  last_seen_at: string;
}

interface ProjectDependencyRow {
  id: string;
  project_id: string;
  version: string;
  projects: { organization_id: string } | { organization_id: string }[];
}

export async function runMaintainerSignalSync(
  supabase: SupabaseClient,
  options: MaintainerSyncOptions = {},
): Promise<MaintainerSyncResult> {
  const limit = options.limit ?? DEFAULT_LIMIT;
  const now = options.now ?? new Date();
  const cutoffStale = new Date(now.getTime() - STALE_THRESHOLD_MS).toISOString();
  const runId = `maintainer-cron:${now.toISOString().slice(0, 10)}`;

  // Cron dispatcher hits this once per day; one row per (run-day, project,
  // pdep, rule_id) keeps repeated calls in the same day idempotent thanks
  // to the PMF unique constraint (project_id, project_dependency_id,
  // rule_id, scanner, extraction_run_id).
  const result: MaintainerSyncResult = {
    scanned: 0,
    signals_fired: 0,
    findings_inserted: 0,
    errors: 0,
    ecosystems_skipped: [],
  };

  // ── 1. Pull active deps, top-N by last_seen_at ──────────────────────
  const { data: depsData, error: depsErr } = await supabase
    .from('dependencies')
    .select('id, name, ecosystem, last_seen_at')
    .gt('last_seen_at', cutoffStale)
    .in('ecosystem', SUPPORTED_ECOSYSTEMS as unknown as string[])
    .order('last_seen_at', { ascending: false })
    .limit(limit);

  if (depsErr) {
    throw new Error(`maintainer-sync: failed to load dependencies: ${depsErr.message}`);
  }
  const deps = (depsData ?? []) as DependencyRow[];

  for (const dep of deps) {
    try {
      const eco = canonicalizeEcosystem(dep.ecosystem);
      if (!eco) continue;

      // Pick a representative version: the most-recently-inserted
      // project_dependencies row for this dep. Pulling per-version diffs
      // would multiply cron cost N-fold for popular packages with stable
      // version pinning — v2 scans the latest version we've observed in
      // any project; v3 can revisit per-version coverage.
      const { data: anchorPd } = await supabase
        .from('project_dependencies')
        .select('version')
        .eq('dependency_id', dep.id)
        .order('id', { ascending: false })
        .limit(1)
        .maybeSingle();

      const version = (anchorPd?.version as string | undefined) ?? null;
      if (!version) continue;

      const computeOptions: ComputeOptions = {
        now,
        fetcher: options.fetcher,
      };
      const computed = await computeMaintainerSignalsForPackage(
        supabase,
        dep.name,
        version,
        dep.ecosystem,
        computeOptions,
      );
      if (!computed) continue;
      result.scanned += 1;

      const finding = severityForMaintainerSignal(computed.signals);
      if (!finding) continue;
      result.signals_fired += 1;

      // ── 5. Fan out per-project — JOIN-derived organization_id ──────
      const { data: pdRowsData, error: pdErr } = await supabase
        .from('project_dependencies')
        .select('id, project_id, version, projects!inner(organization_id)')
        .eq('dependency_id', dep.id)
        .eq('version', version);

      if (pdErr) {
        console.warn(`[maintainer-sync] PD fan-out failed for ${dep.id}/${version}: ${pdErr.message}`);
        continue;
      }
      const pdRows = (pdRowsData ?? []) as ProjectDependencyRow[];
      if (pdRows.length === 0) continue;

      const findings = pdRows.map((pd) => {
        const orgId = Array.isArray(pd.projects)
          ? pd.projects[0]?.organization_id
          : pd.projects?.organization_id;
        return {
          project_id: pd.project_id,
          organization_id: orgId,
          extraction_run_id: runId,
          project_dependency_id: pd.id,
          dependency_id: dep.id,
          rule_id: finding.rule_id,
          scanner: 'maintainer',
          severity: finding.severity,
          message: finding.message,
          depscore: null,
          // No reachability for maintainer-class findings — the risk
          // surface is registry-side, not a per-call sink.
        };
      }).filter((row) => !!row.organization_id);

      if (findings.length === 0) continue;

      const { data: insertedCount, error: rpcErr } = await supabase.rpc(
        'insert_malicious_findings_with_recompute',
        { p_findings: findings },
      );

      if (rpcErr) {
        console.warn(`[maintainer-sync] insert RPC failed for ${dep.name}@${version}: ${rpcErr.message}`);
        result.errors += 1;
        continue;
      }
      const inserted = typeof insertedCount === 'number' ? insertedCount : 0;
      result.findings_inserted += inserted;

      // ── 6. Notification dispatch (critical / high only) ────────────
      if (inserted > 0 && (finding.severity === 'critical' || finding.severity === 'high')) {
        await emitNotificationEvents(supabase, findings, finding.rule_id, finding.severity, runId);
      }

      // ── 6.1 Refresh the denormalized overview summary per affected project ──
      // Maintainer-sync inserts malicious findings OUTSIDE any scan or route, yet
      // they feed the overview band counts. Recompute each affected project so the
      // stored summary reflects the new findings. Non-fatal; the daily self-heal
      // cron backstops any failure.
      if (inserted > 0) {
        const affectedProjectIds = Array.from(new Set(findings.map((f) => f.project_id)));
        for (const pid of affectedProjectIds) {
          const { error: recomputeErr } = await supabase.rpc('recompute_project_summary', { p_project_id: pid });
          if (recomputeErr) {
            console.warn(`[maintainer-sync] recompute_project_summary failed for ${pid}: ${recomputeErr.message}`);
          }
        }
      }
    } catch (err: any) {
      result.errors += 1;
      console.warn(`[maintainer-sync] dep ${dep.name}/${dep.ecosystem} failed: ${err?.message ?? err}`);
    }
  }

  return result;
}

interface InsertedFindingShape {
  project_id: string;
  organization_id: string;
  extraction_run_id: string;
  project_dependency_id: string;
  dependency_id: string;
}

async function emitNotificationEvents(
  supabase: SupabaseClient,
  findings: InsertedFindingShape[],
  ruleId: string,
  severity: string,
  runId: string,
): Promise<void> {
  // De-dup per (org, project, run) so a single dep-fan-out across one
  // project doesn't multiply notifications. The PMF-detected event
  // already groups findings on the read side.
  const seen = new Set<string>();
  for (const f of findings) {
    const key = `${f.organization_id}|${f.project_id}|${runId}|${ruleId}`;
    if (seen.has(key)) continue;
    seen.add(key);

    try {
      const { data: insertedEvent, error: insertErr } = await supabase
        .from('notification_events')
        .insert({
          event_type: 'malicious_package_detected',
          organization_id: f.organization_id,
          project_id: f.project_id,
          payload: {
            organization_id: f.organization_id,
            project_id: f.project_id,
            extraction_run_id: runId,
            scanner: 'maintainer',
            rule_id: ruleId,
            severity,
          },
          source: 'maintainer_signal_cron',
          priority: severity === 'critical' ? 'critical' : 'high',
          deduplication_key: key,
          status: 'pending',
        })
        .select('id')
        .maybeSingle();

      if (!insertErr && insertedEvent?.id) {
        // Trigger immediate dispatch via internal endpoint. Reconciler
        // catches stragglers within 10min if this fails.
        const backendBaseUrl = process.env.BACKEND_URL || process.env.API_BASE_URL || 'http://localhost:3001';
        const internalKey = process.env.INTERNAL_API_KEY;
        if (internalKey) {
          const url = `${backendBaseUrl.replace(/\/$/, '')}/api/workers/dispatch-notification`;
          await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Internal-Api-Key': internalKey },
            body: JSON.stringify({ eventId: insertedEvent.id }),
          }).catch(() => { /* reconciler retries */ });
        }
      } else if (insertErr && (insertErr as any).code !== '23505') {
        // 23505 = dedup hit on (org, dedup_key) — expected when re-running.
        console.warn(`[maintainer-sync] notification emission failed: ${insertErr.message}`);
      }
    } catch (err: any) {
      console.warn(`[maintainer-sync] notification dispatch failed: ${err?.message ?? err}`);
    }
  }
}
