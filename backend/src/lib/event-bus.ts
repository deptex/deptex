/**
 * Phase 9: Central event emission system for the notification pipeline.
 *
 * Persists events to `notification_events` and queues async dispatch via QStash.
 * Critical events are dispatched immediately; normal/low events are batched and
 * delayed to allow coalescing.
 */

import { supabase } from '../lib/supabase';
import crypto from 'crypto';

// ─── Types ───

export interface DeptexEvent {
  type: string;
  organizationId: string;
  projectId?: string;
  teamId?: string;
  payload: Record<string, any>;
  source: string;
  priority: 'critical' | 'high' | 'normal' | 'low';
  deduplicationKey?: string;
}

// ─── Constants ───

const CRITICAL_EVENT_TYPES = ['malicious_package_detected', 'security_analysis_failure'];

const PRIORITY_DELAY: Record<string, string> = {
  critical: '0s',
  high: '0s',
  normal: '30s',
  low: '300s',
};

// ─── QStash helpers (lazy env reads) ───

function getQStashToken(): string | undefined {
  return process.env.QSTASH_TOKEN;
}

function getQStashBaseUrl(): string {
  return 'https://qstash.upstash.io';
}

function getApiBaseUrl(): string {
  return process.env.API_BASE_URL || process.env.BACKEND_URL || 'http://localhost:3001';
}

function log(message: string, extra?: Record<string, any>): void {
  console.log(JSON.stringify({ component: 'event-bus', message, ...extra }));
}

function logError(message: string, extra?: Record<string, any>): void {
  console.error(JSON.stringify({ component: 'event-bus', message, ...extra }));
}

// ─── Internal: QStash dispatch ───

async function queueNotificationDispatch(eventId: string, priority: string): Promise<void> {
  const token = getQStashToken();
  if (!token) {
    log('QSTASH_TOKEN not configured — skipping dispatch', { eventId });
    return;
  }

  const destination = `${getApiBaseUrl()}/api/workers/dispatch-notification`;
  const delay = PRIORITY_DELAY[priority] ?? '30s';

  try {
    const response = await fetch(
      `${getQStashBaseUrl()}/v2/publish/${encodeURIComponent(destination)}`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Upstash-Method': 'POST',
          'Upstash-Delay': delay,
          'Upstash-Retries': '5',
          'Upstash-Forward-Content-Type': 'application/json',
        },
        body: JSON.stringify({ eventId }),
      },
    );

    if (!response.ok) {
      const errorText = await response.text();
      logError('QStash dispatch failed', { eventId, status: response.status, error: errorText });
      return;
    }

    log('Queued notification dispatch', { eventId, priority, delay });
  } catch (error: any) {
    logError('Failed to queue notification dispatch', { eventId, error: error.message });
  }
}

async function queueBatchDispatch(batchId: string, count: number): Promise<void> {
  const token = getQStashToken();
  if (!token) {
    log('QSTASH_TOKEN not configured — skipping batch dispatch', { batchId });
    return;
  }

  const destination = `${getApiBaseUrl()}/api/workers/dispatch-notification-batch`;

  try {
    const response = await fetch(
      `${getQStashBaseUrl()}/v2/publish/${encodeURIComponent(destination)}`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Upstash-Method': 'POST',
          'Upstash-Delay': '30s',
          'Upstash-Retries': '5',
          'Upstash-Forward-Content-Type': 'application/json',
        },
        body: JSON.stringify({ batchId }),
      },
    );

    if (!response.ok) {
      const errorText = await response.text();
      logError('QStash batch dispatch failed', { batchId, status: response.status, error: errorText });
      return;
    }

    log('Queued batch notification dispatch', { batchId, count });
  } catch (error: any) {
    logError('Failed to queue batch notification dispatch', { batchId, error: error.message });
  }
}

// ─── Public API ───

/**
 * Persist a single event and queue its async dispatch.
 *
 * Deduplication: when `deduplicationKey` is set, a unique constraint violation
 * (Postgres 23505) returns the existing event's id instead of inserting a duplicate.
 */
export async function emitEvent(event: DeptexEvent): Promise<string> {
  const isCritical = CRITICAL_EVENT_TYPES.includes(event.type);

  try {
    const row = {
      id: crypto.randomUUID(),
      event_type: event.type,
      organization_id: event.organizationId,
      project_id: event.projectId ?? null,
      team_id: event.teamId ?? null,
      payload: event.payload,
      source: event.source,
      priority: event.priority,
      deduplication_key: event.deduplicationKey ?? null,
      status: 'pending',
      created_at: new Date().toISOString(),
    };

    const { data, error } = await supabase
      .from('notification_events')
      .insert(row)
      .select('id')
      .single();

    if (error) {
      if (error.code === '23505' && event.deduplicationKey) {
        const { data: existing } = await supabase
          .from('notification_events')
          .select('id')
          .eq('deduplication_key', event.deduplicationKey)
          .eq('organization_id', event.organizationId)
          .single();

        if (existing) {
          log('Deduplicated event', { eventType: event.type, orgId: event.organizationId, existingId: existing.id });
          return existing.id;
        }
      }
      throw error;
    }

    const eventId = data.id;

    await queueNotificationDispatch(eventId, event.priority);

    log('Event emitted', { eventType: event.type, orgId: event.organizationId, eventId });
    return eventId;
  } catch (err: any) {
    logError('emitEvent failed', { eventType: event.type, orgId: event.organizationId, error: err.message });

    if (isCritical) throw err;
    return 'emit-failed';
  }
}

/**
 * Emit a batch of events. Critical events are dispatched individually.
 * Non-critical events share a `batch_id` and are dispatched as a single QStash job.
 */
export async function emitEventBatch(events: DeptexEvent[]): Promise<string[]> {
  if (events.length === 0) return [];

  const critical: DeptexEvent[] = [];
  const batchable: DeptexEvent[] = [];

  for (const event of events) {
    if (CRITICAL_EVENT_TYPES.includes(event.type)) {
      critical.push(event);
    } else {
      batchable.push(event);
    }
  }

  const results: string[] = new Array(events.length).fill('');

  // Dispatch critical events individually
  const criticalPromises = critical.map(async (event) => {
    const originalIndex = events.indexOf(event);
    const id = await emitEvent(event);
    results[originalIndex] = id;
  });

  await Promise.all(criticalPromises);

  // Insert batchable events with a shared batch_id
  if (batchable.length > 0) {
    const batchId = crypto.randomUUID();
    const now = new Date().toISOString();

    const rows = batchable.map((event) => ({
      id: crypto.randomUUID(),
      event_type: event.type,
      organization_id: event.organizationId,
      project_id: event.projectId ?? null,
      team_id: event.teamId ?? null,
      payload: event.payload,
      source: event.source,
      priority: event.priority,
      deduplication_key: event.deduplicationKey ?? null,
      batch_id: batchId,
      status: 'pending',
      created_at: now,
    }));

    const { data, error } = await supabase
      .from('notification_events')
      .insert(rows)
      .select('id');

    if (error) {
      logError('Batch insert failed', { batchId, error: error.message });
      for (const event of batchable) {
        const idx = events.indexOf(event);
        results[idx] = 'emit-failed';
      }
    } else {
      const insertedIds = (data ?? []).map((r: any) => r.id);
      batchable.forEach((event, i) => {
        const idx = events.indexOf(event);
        results[idx] = insertedIds[i] ?? 'emit-failed';
      });

      await queueBatchDispatch(batchId, batchable.length);
      log('Batch emitted', { batchId, count: batchable.length });
    }
  }

  return results;
}

/**
 * Resolve the owner team for a project (is_owner = true in project_teams).
 */
export async function resolveTeamId(projectId?: string): Promise<string | null> {
  if (!projectId) return null;

  const { data } = await supabase
    .from('project_teams')
    .select('team_id')
    .eq('project_id', projectId)
    .eq('is_owner', true)
    .limit(1)
    .single();

  return data?.team_id ?? null;
}
