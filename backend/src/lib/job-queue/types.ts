/**
 * Abstraction over the async job queue. Two implementations:
 *
 *   QStashJobQueue  — Upstash QStash, HTTP-delivery, signature-verified.
 *                     Used in cloud deploys.
 *   BullMQJobQueue  — BullMQ + Redis. Jobs run inside the backend process and
 *                     POST to the same /api/workers/* endpoints with an
 *                     X-Internal-Api-Key header. Used for self-hosting.
 *
 * Selection via JOB_QUEUE_BACKEND=qstash|bullmq (default: auto — qstash if
 * QSTASH_TOKEN is set, else bullmq if REDIS_URL is set, else a no-op noop
 * queue that logs a warning and drops jobs so the rest of the app still boots).
 */

export interface PublishOpts {
  /** Delay in milliseconds before the job is delivered. */
  delayMs?: number;
  /** Flow-control key — all jobs sharing a key run serially (parallelism=1). */
  flowControlKey?: string;
  /** Retry count on delivery/processor failure. */
  retries?: number;
}

export interface PublishResult {
  messageId: string;
}

export interface PublishMessage {
  url: string;
  body: unknown;
  opts?: PublishOpts;
}

export interface JobQueue {
  /** Human-readable backend name (for logs / health checks). */
  readonly name: string;

  /** True if this backend is fully configured and can accept jobs. */
  isConfigured(): boolean;

  /** Enqueue a single job. Returns null on publish failure. */
  publish(
    url: string,
    body: unknown,
    opts?: PublishOpts,
  ): Promise<PublishResult | null>;

  /**
   * Enqueue many jobs. Returns per-message results in the same order.
   * Implementations should preserve flow-control semantics: messages sharing
   * a flowControlKey are delivered serially with respect to each other.
   */
  publishBatch(messages: PublishMessage[]): Promise<Array<PublishResult | null>>;

  /**
   * Verify that an inbound request is authorized. Accepts either the
   * provider-specific signature (QStash) or a shared INTERNAL_API_KEY.
   * `headers` is case-insensitive.
   */
  verifyRequest(
    headers: Record<string, string | string[] | undefined>,
    rawBody: string,
  ): Promise<boolean>;
}
