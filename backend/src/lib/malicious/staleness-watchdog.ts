/**
 * Malicious-feed staleness watchdog.
 *
 * Independent cron (separate QStash schedule, every 6h) that watches
 * `malicious_feed_sync_runs` per source and emits a `feed_sync_stale`
 * critical event when:
 *
 *   - state='running' AND `updated_at` is older than 5 minutes (stuck heartbeat)
 *   - state='failed'
 *   - latest `completed_at` is older than 36 hours
 *
 * Per-source. One aggregated event per run when multiple sources are
 * stale at once (avoid N events for a single outage).
 */
import { supabase } from '../supabase';
import { emitEvent } from '../event-bus';
import type { MaliciousFeedSource } from './types';

const HEARTBEAT_STALE_MS = 5 * 60 * 1000;
const COMPLETED_STALE_MS = 36 * 60 * 60 * 1000;

export interface WatchdogResult {
  stale_sources: Array<{ source: MaliciousFeedSource; reason: string }>;
  events_emitted: number;
}

const SOURCES: MaliciousFeedSource[] = ['osv', 'ghsa'];

export async function runStalenessWatchdog(): Promise<WatchdogResult> {
  const stale: WatchdogResult['stale_sources'] = [];

  for (const source of SOURCES) {
    const reason = await checkSource(source);
    if (reason) stale.push({ source, reason });
  }

  let events_emitted = 0;
  if (stale.length > 0) {
    // One aggregated event covering all stale sources — saves N
    // pages-on-call incidents for a single OSV outage.
    try {
      await emitEvent({
        type: 'feed_sync_stale',
        organizationId: '00000000-0000-0000-0000-000000000000',
        source: 'malicious_feed_sync_watchdog',
        priority: 'critical',
        payload: {
          stale_sources: stale,
          checked_at: new Date().toISOString(),
        },
        deduplicationKey: stale.map((s) => `${s.source}:${s.reason}`).sort().join('|'),
      } as any);
      events_emitted = 1;
    } catch (err: any) {
      console.warn('[malicious watchdog] event emission failed:', err?.message ?? err);
    }
  }

  return { stale_sources: stale, events_emitted };
}

async function checkSource(source: MaliciousFeedSource): Promise<string | null> {
  // Latest run for this source ordered by completed_at DESC
  const { data: latest } = await supabase
    .from('malicious_feed_sync_runs')
    .select('id, state, started_at, updated_at, completed_at')
    .eq('source', source)
    .order('started_at', { ascending: false })
    .limit(1);

  const row = (latest ?? [])[0] as
    | { id: string; state: string; started_at: string; updated_at: string; completed_at: string | null }
    | undefined;

  if (!row) {
    // No runs ever recorded — surface so the cron can be wired up.
    return 'no_runs_recorded';
  }

  if (row.state === 'running') {
    const heartbeat = new Date(row.updated_at).getTime();
    if (Date.now() - heartbeat > HEARTBEAT_STALE_MS) {
      return 'heartbeat_stale';
    }
    return null;
  }

  if (row.state === 'failed' || row.state === 'dlq') {
    return `last_run_${row.state}`;
  }

  if (row.state === 'completed') {
    if (!row.completed_at) return 'completed_at_missing';
    const completedAt = new Date(row.completed_at).getTime();
    if (Date.now() - completedAt > COMPLETED_STALE_MS) {
      return 'last_completion_stale';
    }
    return null;
  }

  // pending — recent enqueue, fine
  return null;
}
