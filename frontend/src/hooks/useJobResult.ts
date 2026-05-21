/**
 * v2.1d — Generic job-polling hook used by the recorded-login Test button.
 *
 * Polls GET /api/projects/:projectId/dast/jobs?id=<jobId> with exponential
 * backoff until the job reaches a terminal status (completed | failed |
 * cancelled), `maxWaitMs` elapses, or the consumer unmounts.
 *
 * Polling cadence: 1.5s → 5s → 15s. The first probe is at +1.5s so the
 * Test-login banner shows the result almost immediately on warm-worker
 * runs. SSO + Fly cold-start can hit 2-3 min in practice — default
 * `maxWaitMs` is 5 min, and the hook surfaces a 'still_running' state
 * past 90s rather than ending the poll.
 *
 * NOT a refactor of DastScanningTab.tsx — that component keeps its existing
 * Supabase Realtime + setInterval pattern in v2.1d. Once both consumers are
 * battle-tested in production, a follow-up chore can extract the realtime
 * fallback. Per pragmatist-f5 in the v2.1d /review-plan: "ship one piece,
 * get sign-off, iterate."
 */

import { useEffect, useMemo, useRef, useState } from 'react';

import { api, type DastJobDTO } from '../lib/api';

type Status = 'idle' | 'polling' | 'still_running' | 'completed' | 'failed' | 'cancelled' | 'timeout' | 'error';

export interface UseJobResultOptions {
  /** Hard cap on total polling duration. Default 5 min (300_000 ms). */
  maxWaitMs?: number;
  /** Threshold past which `status` shifts from 'polling' to 'still_running'. Default 90s. */
  slowThresholdMs?: number;
  /**
   * If the FE knows the project id but the polling targets a generic
   * GET /dast/jobs?id=<jobId>, we need projectId to construct the URL.
   */
  projectId: string;
  /**
   * Polling cadence override (test seam). Production defaults to
   * [1500, 5000, 15000] ms, looping at the last value.
   */
  pollIntervalsMs?: number[];
}

export interface UseJobResultState {
  status: Status;
  job: DastJobDTO | null;
  /** Only populated when status === 'error' (network / fetch reject). */
  error: Error | null;
  /** ms since the hook started polling (or 0 when idle). */
  elapsedMs: number;
}

function isTerminalStatus(s: DastJobDTO['status']): boolean {
  return s === 'completed' || s === 'failed' || s === 'cancelled';
}

export function useJobResult(
  jobId: string | null,
  opts: UseJobResultOptions,
): UseJobResultState {
  const [state, setState] = useState<UseJobResultState>({
    status: 'idle',
    job: null,
    error: null,
    elapsedMs: 0,
  });

  // Hold the active controller in a ref so we can abort on unmount.
  const abortRef = useRef<AbortController | null>(null);
  // Track the active jobId so a re-mount with a stale jobId can ignore late
  // responses targeting the old id.
  const activeJobIdRef = useRef<string | null>(null);

  const maxWaitMs = opts.maxWaitMs ?? 5 * 60 * 1000;
  const slowThresholdMs = opts.slowThresholdMs ?? 90 * 1000;
  // Stabilise the poll-intervals reference so the effect doesn't re-fire on
  // every parent render (the `??` fallback is a fresh array literal each
  // call, which would force an effect cleanup + restart loop in tests).
  const pollIntervalsKey = opts.pollIntervalsMs ? opts.pollIntervalsMs.join(',') : 'default';
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const pollIntervals = useMemo(() => opts.pollIntervalsMs ?? [1500, 5000, 15000], [pollIntervalsKey]);

  useEffect(() => {
    if (!jobId) {
      setState({ status: 'idle', job: null, error: null, elapsedMs: 0 });
      activeJobIdRef.current = null;
      return;
    }

    activeJobIdRef.current = jobId;
    const startedAt = Date.now();
    let cancelled = false;
    let timerId: ReturnType<typeof setTimeout> | null = null;
    abortRef.current = new AbortController();

    setState({ status: 'polling', job: null, error: null, elapsedMs: 0 });

    async function probe(intervalIndex: number): Promise<void> {
      if (cancelled) return;
      const elapsed = Date.now() - startedAt;

      // Hard cap reached — surface as timeout but keep the last-known job.
      if (elapsed >= maxWaitMs) {
        setState((prev) => ({
          status: 'timeout',
          job: prev.job,
          error: null,
          elapsedMs: elapsed,
        }));
        return;
      }

      try {
        // The /dast/jobs endpoint accepts an `id` query and returns an array.
        // We filter client-side to defend against the array-of-one shape.
        const all = await api.getDastJobs(opts.projectId, { limit: 50 });
        if (cancelled || activeJobIdRef.current !== jobId) return;
        const match = all.find((j) => j.id === jobId) ?? null;
        const elapsedNow = Date.now() - startedAt;
        if (match && isTerminalStatus(match.status)) {
          setState({
            status:
              match.status === 'completed'
                ? 'completed'
                : match.status === 'failed'
                  ? 'failed'
                  : 'cancelled',
            job: match,
            error: null,
            elapsedMs: elapsedNow,
          });
          return;
        }
        const nextStatus: Status = elapsedNow >= slowThresholdMs ? 'still_running' : 'polling';
        setState({
          status: nextStatus,
          job: match,
          error: null,
          elapsedMs: elapsedNow,
        });
      } catch (e) {
        // AbortController firing on unmount throws AbortError — swallow.
        if ((e as { name?: string }).name === 'AbortError') return;
        if (cancelled) return;
        setState((prev) => ({
          status: 'error',
          job: prev.job,
          error: e instanceof Error ? e : new Error(String(e)),
          elapsedMs: Date.now() - startedAt,
        }));
        // Don't schedule another poll on error — let the user decide whether
        // to retry. The Test-login UI surfaces a retry hint banner.
        return;
      }

      // Schedule next probe at the indexed interval (cap at the last value).
      const next = Math.min(intervalIndex, pollIntervals.length - 1);
      timerId = setTimeout(() => probe(next + 1), pollIntervals[next]);
    }

    // Kick off the first probe immediately (after a tiny delay so the
    // "polling" state is visible). The fixed first delay also matches
    // tests using vi.useFakeTimers.
    timerId = setTimeout(() => probe(0), pollIntervals[0]);

    return () => {
      cancelled = true;
      if (timerId) clearTimeout(timerId);
      abortRef.current?.abort();
      activeJobIdRef.current = null;
    };
  }, [jobId, opts.projectId, maxWaitMs, slowThresholdMs, pollIntervals]);

  return state;
}
