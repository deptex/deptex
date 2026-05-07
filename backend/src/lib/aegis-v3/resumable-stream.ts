/**
 * Server-side resumable streams for Aegis v3.
 *
 * When the model is mid-generation and the user navigates away, the HTTP
 * socket dies but the SDK + agent keep running (route-level consumeStream).
 * The resulting bytes are still produced — we just have nowhere to send them.
 *
 * This module adds a parallel sink: as the SDK SSE bytes flow to the live
 * HTTP response, we also tee each chunk into a Redis list keyed by streamId.
 * A second connection (the user returning to the chat) hits the GET
 * /:threadId/stream endpoint, which looks up the active streamId, replays
 * every byte that's already landed in Redis, then tails the list for new
 * chunks until a sentinel marks the stream done.
 *
 * Storage:
 *   aegis:rstream:thread:{threadId}    -> active streamId (TTL 600s)
 *   aegis:rstream:chunks:{streamId}    -> RPUSH list of base64(SSE bytes)
 *                                          terminated by literal "__END__"
 *                                          (TTL 600s set on first push)
 *
 * Why base64: SSE bytes are valid UTF-8 in practice (the SDK emits text-only
 * frames), but Upstash Redis stringifies values and can corrupt edge bytes
 * across the REST boundary. Base64 sidesteps that whole class of bug for
 * ~33% storage overhead — fine for a 10-minute TTL on chat traffic.
 *
 * Why a Promise chain instead of fire-and-forget: order matters. If RPUSH-A
 * lands after RPUSH-B at Redis (network reorder, concurrent HTTP/2 streams),
 * resume replays bytes out of order and the SDK parser blows up. A linear
 * await chain is the simplest correct ordering — the live HTTP write isn't
 * gated on it, so Upstash latency doesn't slow the user-visible stream.
 */

import { getRedisClient } from '../cache';

const TTL_SECONDS = 600; // 10 minutes — long enough for slow agent runs, short enough that abandoned streams self-evict
const END_SENTINEL = '__END__';
const RESUME_POLL_MS = 250;
const RESUME_MAX_DURATION_MS = 10 * 60 * 1000; // 10 minutes — must outlive longest plausible agent run

function threadKey(threadId: string): string {
  return `aegis:rstream:thread:${threadId}`;
}

function chunksKey(streamId: string): string {
  return `aegis:rstream:chunks:${streamId}`;
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

/**
 * Register a new stream and clear any prior streamId mapping for the thread.
 * Safe to call when Redis is not configured — returns false and the caller
 * should treat the stream as non-resumable (graceful degrade).
 */
export async function registerStream(
  threadId: string,
  streamId: string,
): Promise<boolean> {
  const redis = getRedisClient();
  if (!redis) return false;
  try {
    await redis.set(threadKey(threadId), streamId, { ex: TTL_SECONDS });
    return true;
  } catch (err) {
    console.warn('[aegis-v3] resumable-stream registerStream failed', err);
    return false;
  }
}

/**
 * Returns an append() function that serializes Redis writes to preserve order
 * and an end() function that flushes the END sentinel. The first append also
 * sets the TTL (one-time) so we don't pay the round-trip on every chunk.
 *
 * Errors swallowed — resumability is best-effort; the live HTTP path is the
 * source of truth.
 */
export function createChunkSink(streamId: string): {
  append: (chunk: Uint8Array) => void;
  end: () => Promise<void>;
} {
  const redis = getRedisClient();
  const key = chunksKey(streamId);
  let chain: Promise<void> = Promise.resolve();
  let ttlSet = false;

  const append = (chunk: Uint8Array) => {
    if (!redis) return;
    const encoded = toBase64(chunk);
    chain = chain
      .then(async () => {
        await redis.rpush(key, encoded);
        if (!ttlSet) {
          ttlSet = true;
          await redis.expire(key, TTL_SECONDS);
        }
      })
      .catch((err) => {
        console.warn('[aegis-v3] resumable-stream append failed', err);
      });
  };

  const end = async () => {
    if (!redis) return;
    try {
      // Wait for in-flight chunk writes to settle, then push the sentinel
      // last. Resume readers stop the moment they see __END__, so any chunk
      // that lands after it would be silently dropped — order matters.
      await chain;
      await redis.rpush(key, END_SENTINEL);
      if (!ttlSet) await redis.expire(key, TTL_SECONDS);
    } catch (err) {
      console.warn('[aegis-v3] resumable-stream end failed', err);
    }
  };

  return { append, end };
}

/**
 * Clear the thread -> streamId mapping. Called after the stream completes so
 * a subsequent resume request returns 204 No Content instead of replaying a
 * finished stream (the client would just wait until __END__, which works but
 * costs needless polling).
 */
export async function clearActiveStream(threadId: string): Promise<void> {
  const redis = getRedisClient();
  if (!redis) return;
  try {
    await redis.del(threadKey(threadId));
  } catch (err) {
    console.warn('[aegis-v3] resumable-stream clearActiveStream failed', err);
  }
}

export async function getActiveStreamId(threadId: string): Promise<string | null> {
  const redis = getRedisClient();
  if (!redis) return null;
  try {
    const v = await redis.get(threadKey(threadId));
    return typeof v === 'string' && v.length > 0 ? v : null;
  } catch (err) {
    console.warn('[aegis-v3] resumable-stream getActiveStreamId failed', err);
    return null;
  }
}

/**
 * Replays an in-flight stream to a writable HTTP response. Caller is
 * responsible for writing SSE headers before calling this. Resolves when the
 * stream hits __END__ or the safety timeout fires; the response is left open
 * for the caller to res.end().
 *
 * Replay strategy: LRANGE from the next unread index on each tick. Sleeps
 * RESUME_POLL_MS between empty reads so we don't hammer Redis when the agent
 * is mid-tool-call. The HTTP response's writable status is checked each
 * iteration so a re-disconnect mid-replay tears down cleanly.
 */
export async function replayStream(
  streamId: string,
  res: { write: (b: Uint8Array) => boolean; writableEnded: boolean; destroyed: boolean; once: (e: 'drain', cb: () => void) => void },
): Promise<void> {
  const redis = getRedisClient();
  if (!redis) return;
  const key = chunksKey(streamId);
  const startedAt = Date.now();
  let nextIndex = 0;
  let sawEnd = false;

  while (!sawEnd) {
    if (res.writableEnded || res.destroyed) return;
    if (Date.now() - startedAt > RESUME_MAX_DURATION_MS) return;

    let entries: string[] = [];
    try {
      const raw = await redis.lrange(key, nextIndex, -1);
      entries = (raw as unknown as string[]) ?? [];
    } catch (err) {
      console.warn('[aegis-v3] resumable-stream lrange failed', err);
      return;
    }

    if (entries.length === 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, RESUME_POLL_MS));
      continue;
    }

    for (const entry of entries) {
      if (entry === END_SENTINEL) {
        sawEnd = true;
        break;
      }
      const bytes = fromBase64(entry);
      const ok = res.write(bytes);
      if (!ok) {
        await new Promise<void>((resolve) => res.once('drain', () => resolve()));
      }
      if (res.writableEnded || res.destroyed) return;
    }
    nextIndex += entries.length;
  }
}
