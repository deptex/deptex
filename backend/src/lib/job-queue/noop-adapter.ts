/**
 * Fallback queue used when neither QStash nor BullMQ is configured.
 * Drops jobs with a warning — lets the app boot for read-only exploration.
 */

import type { JobQueue, PublishMessage } from './types';
import { isValidInternalKey } from '../../middleware/internal-key';

let warned = false;

function warnOnce() {
  if (warned) return;
  warned = true;
  console.warn(
    '[job-queue:noop] no async job backend configured. Set JOB_QUEUE_BACKEND=qstash ' +
      '(with QSTASH_TOKEN) or JOB_QUEUE_BACKEND=bullmq (with REDIS_URL). ' +
      'Async features (dependency enrichment, scheduled jobs) are disabled.',
  );
}

export const noopAdapter: JobQueue = {
  name: 'noop',
  isConfigured: () => false,
  async publish() {
    warnOnce();
    return null;
  },
  async publishBatch(messages: PublishMessage[]) {
    warnOnce();
    return messages.map(() => null);
  },
  async verifyRequest(headers) {
    const presented = headers['x-internal-api-key'];
    const presentedStr = Array.isArray(presented) ? presented[0] : presented;
    return isValidInternalKey(presentedStr);
  },
};
