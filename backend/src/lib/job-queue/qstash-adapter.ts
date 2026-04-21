/**
 * QStash implementation of JobQueue. Wraps the existing region-aware
 * @upstash/qstash publish + Receiver logic.
 */

import { Receiver } from '@upstash/qstash';
import type {
  JobQueue,
  PublishMessage,
  PublishOpts,
  PublishResult,
} from './types';

function getRegionPrefix(): string | null {
  const region = process.env.QSTASH_REGION;
  return region ? `${region}_` : null;
}

function getToken(): string | undefined {
  const prefix = getRegionPrefix();
  if (prefix) {
    const t = process.env[`${prefix}QSTASH_TOKEN`];
    if (t) return t;
  }
  return process.env.QSTASH_TOKEN;
}

function getBaseUrl(): string {
  const prefix = getRegionPrefix();
  if (prefix) {
    const u = process.env[`${prefix}QSTASH_URL`];
    if (u) return u.replace(/\/$/, '');
  }
  return 'https://qstash.upstash.io';
}

function getSigningKeys(): { current: string; next: string } | null {
  const prefix = getRegionPrefix();
  const current = prefix
    ? process.env[`${prefix}QSTASH_CURRENT_SIGNING_KEY`]
    : process.env.QSTASH_CURRENT_SIGNING_KEY;
  const next = prefix
    ? process.env[`${prefix}QSTASH_NEXT_SIGNING_KEY`]
    : process.env.QSTASH_NEXT_SIGNING_KEY;
  return current && next ? { current, next } : null;
}

let receiver: Receiver | null = null;
let receiverInitialized = false;

function getReceiver(): Receiver | null {
  if (!receiverInitialized) {
    const keys = getSigningKeys();
    if (keys) {
      receiver = new Receiver({
        currentSigningKey: keys.current,
        nextSigningKey: keys.next,
      });
    }
    receiverInitialized = true;
  }
  return receiver;
}

function headersFor(opts: PublishOpts | undefined): Record<string, string> {
  const h: Record<string, string> = {
    'Content-Type': 'application/json',
    'Upstash-Method': 'POST',
    'Upstash-Forward-Content-Type': 'application/json',
  };
  if (opts?.delayMs !== undefined) h['Upstash-Delay'] = `${Math.ceil(opts.delayMs / 1000)}s`;
  if (opts?.retries !== undefined) h['Upstash-Retries'] = String(opts.retries);
  if (opts?.flowControlKey) {
    h['Upstash-Flow-Control-Key'] = opts.flowControlKey;
    h['Upstash-Flow-Control-Value'] = 'parallelism=1';
  }
  return h;
}

export const qstashAdapter: JobQueue = {
  name: 'qstash',

  isConfigured() {
    return !!getToken();
  },

  async publish(url, body, opts) {
    const token = getToken();
    if (!token) {
      console.warn('[job-queue:qstash] QSTASH_TOKEN not configured — dropping job');
      return null;
    }
    const baseUrl = getBaseUrl();
    const headers = { Authorization: `Bearer ${token}`, ...headersFor(opts) };
    try {
      const res = await fetch(`${baseUrl}/v2/publish/${encodeURIComponent(url)}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body ?? {}),
      });
      if (!res.ok) {
        console.error('[job-queue:qstash] publish failed', res.status, await res.text());
        return null;
      }
      const j = (await res.json()) as { messageId?: string };
      return j.messageId ? { messageId: j.messageId } : null;
    } catch (e) {
      console.error('[job-queue:qstash] publish error', e);
      return null;
    }
  },

  async publishBatch(messages: PublishMessage[]): Promise<Array<PublishResult | null>> {
    const token = getToken();
    if (!token) {
      console.warn('[job-queue:qstash] QSTASH_TOKEN not configured — dropping batch');
      return messages.map(() => null);
    }
    const baseUrl = getBaseUrl();
    const payload = messages.map((m) => ({
      destination: m.url,
      headers: headersFor(m.opts),
      body: JSON.stringify(m.body ?? {}),
    }));
    try {
      const res = await fetch(`${baseUrl}/v2/batch`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        console.error('[job-queue:qstash] batch publish failed', res.status, await res.text());
        return messages.map(() => null);
      }
      const results = await res.json();
      if (!Array.isArray(results)) return messages.map((_, i) => ({ messageId: `batch-${i}` }));
      return results.map((r: any) => (r?.messageId ? { messageId: r.messageId as string } : null));
    } catch (e) {
      console.error('[job-queue:qstash] batch error', e);
      return messages.map(() => null);
    }
  },

  async verifyRequest(headers, rawBody) {
    const internalKey = process.env.INTERNAL_API_KEY;
    const presented = headers['x-internal-api-key'];
    const presentedStr = Array.isArray(presented) ? presented[0] : presented;
    if (internalKey && presentedStr === internalKey) return true;

    const sig = headers['upstash-signature'];
    const sigStr = Array.isArray(sig) ? sig[0] : sig;
    const recv = getReceiver();
    if (!recv) {
      // Dev mode: no signing keys configured — allow (matches previous behavior).
      if (!sigStr) {
        console.warn('[job-queue:qstash] no signing keys configured — allowing request');
        return true;
      }
      return false;
    }
    if (!sigStr) return false;
    try {
      await recv.verify({ signature: sigStr, body: rawBody });
      return true;
    } catch (e) {
      console.error('[job-queue:qstash] signature verification failed', e);
      return false;
    }
  },
};
