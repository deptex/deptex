import express from 'express';
import { randomUUID } from 'crypto';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { checkRateLimit } from '../lib/rate-limit';
import { createAegisAgent } from '../lib/aegis-v3/agent';
import { getOrCreateThread, loadThreadHistory } from '../lib/aegis-v3/thread';
import { queryRelevantMemories } from '../lib/aegis-v3/memory';
import { saveUserMessage } from '../lib/aegis-v3/persistence';
import { classifyChatError, writeAegisChatError } from '../lib/aegis-v3/errors';
import { generateThreadTitle } from '../lib/aegis-v3/title';
import { getProviderInfoForOrg } from '../lib/aegis-v3/provider';
import {
  registerStream,
  createChunkSink,
  clearActiveStream,
  getActiveStreamId,
  replayStream,
} from '../lib/aegis-v3/resumable-stream';
import { checkMonthlyCostCap } from '../lib/ai/cost-cap';
import { getThreadForParticipant } from '../lib/aegis/participants';
import type { ModelMessage } from 'ai';

const router = express.Router();
router.use(authenticateUser);

async function hasAegisPermission(orgId: string, userId: string): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();
  if (!membership) return false;

  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', membership.role)
    .single();

  return role?.permissions?.interact_with_aegis === true;
}

router.post('/stream', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { organizationId, threadId, message, context, modelId } = req.body ?? {};

  if (!organizationId || !message) {
    return res.status(400).json({ error: 'organizationId and message are required' });
  }

  if (!(await hasAegisPermission(organizationId, userId))) {
    return res.status(403).json({ error: 'You do not have permission to use Aegis' });
  }

  const dailyLimit = await checkRateLimit(`ai:aegis:user:${userId}`, 200, 86400);
  if (!dailyLimit.allowed) {
    return res.status(429).json({ error: 'Daily message limit reached. Try again tomorrow.' });
  }

  let resolvedThreadId: string | null = null;
  try {
    resolvedThreadId = await getOrCreateThread(
      organizationId,
      userId,
      threadId,
      message,
      context,
    );

    // PREFLIGHT — every read-only setup that can fail goes BEFORE writeHead,
    // so a provider loader rejection / cost-cap block / DB error returns a
    // clean 500 + JSON body instead of a half-flushed SSE stream the client
    // can't make sense of. Once writeHead fires, we're committed to the SSE
    // channel.
    const [history, memoryContext, providerInfo] = await Promise.all([
      loadThreadHistory(resolvedThreadId),
      queryRelevantMemories(organizationId, message),
      getProviderInfoForOrg(organizationId, modelId),
    ]);

    const cap = await checkMonthlyCostCap(
      organizationId,
      providerInfo.model,
      [{ role: 'user', content: message }],
      providerInfo.monthlyCostCap,
    );

    // Build the agent here too — getLanguageModelForOrg throws on missing /
    // disabled platform keys, and we want that as a 500 not as a torn-down
    // SSE. If cap blocked above we skip agent construction (no model call
    // needed).
    const agent = cap.allowed
      ? await createAegisAgent({
          orgId: organizationId,
          userId,
          threadId: resolvedThreadId,
          userMessage: message,
          priorMessageCount: history.length,
          context,
          memoryContext,
          modelId,
        })
      : null;

    // Flush response headers (including X-Thread-Id) eagerly, BEFORE we
    // start streaming — but only AFTER preflight has succeeded. The client
    // needs the threadId on the wire before any SSE chunks arrive so a fast
    // Stop click during submission can still resolve the thread; flushing
    // earlier (pre-preflight) means a provider failure can't return a 500
    // anymore because the status is already 200. We bypass pipeUIMessageStreamToResponse
    // here so we control when writeHead fires.
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Vercel-AI-UI-Message-Stream': 'v1',
      'X-Accel-Buffering': 'no',
      'X-Thread-Id': resolvedThreadId,
    });

    if (!cap.allowed) {
      // Pre-flight cost cap blocked. Record a cost_cap error assistant
      // message and skip the model call. We deliberately also skip saving
      // the user message — there's nothing to answer it with. Headers are
      // flushed so the client picks up X-Thread-Id and treats no-content +
      // persisted error row the same as any other turn.
      await writeAegisChatError(resolvedThreadId, { type: 'cost_cap', message: cap.message });
      return res.end();
    }

    // Persist the user message before streaming starts. A refresh mid-stream
    // then keeps the question visible; only the in-flight assistant tokens
    // are lost (the user can resend).
    await saveUserMessage({ threadId: resolvedThreadId, userId, content: message });

    // Kick off title generation in parallel with the model stream. Decoupled
    // from the assistant onFinish so a Stop click on the response doesn't
    // also cancel the title gen — the user's intent to keep this thread is
    // committed the moment they sent the first message. We use the user
    // message alone (assistant text empty); the title prompt handles that
    // gracefully and the result is good enough for the sidebar.
    if (history.length === 0) {
      void generateThreadTitle(resolvedThreadId, message, '').catch((err) =>
        console.error('[aegis-v3] auto-title failed', err),
      );
    }

    const messages: ModelMessage[] = [...history, { role: 'user', content: message }];
    const result = await agent!.stream({ messages });

    // Force the agent to drive to completion regardless of whether the HTTP
    // response is consumed. This is the canonical AI SDK guarantee for
    // "client might disconnect mid-stream but I need onFinish to fire" —
    // without it, when the user navigates to another chat mid-stream the
    // server-side response gets torn down, the SDK stops generating, and
    // the agent's onFinish (which calls saveAssistantMessage) never runs.
    // consumeStream tees the underlying generation into a background drain
    // that's independent of the response pipe, so the agent always runs to
    // completion and onFinish always fires. Errors are swallowed — any
    // meaningful failure surfaces in toUIMessageStreamResponse's onError
    // below and/or in the agent's onFinish error path.
    void result.consumeStream({
      onError: (err: unknown) =>
        console.error('[aegis-v3] consumeStream error:', err),
    });

    // Resumable-stream registration. Each stream gets a fresh streamId; we
    // store thread->streamId in Redis so a reconnecting client can find it
    // via GET /:threadId/stream. The chunk sink tees every SSE byte into a
    // Redis list so the resume endpoint can replay. Best-effort — a Redis
    // outage just means resume falls back to the seed-load + tail-poll path
    // (the live HTTP write is the source of truth).
    const streamId = randomUUID();
    await registerStream(resolvedThreadId, streamId);
    const sink = createChunkSink(streamId);

    // onError fires for mid-stream failures (provider 429/5xx, network drops).
    // We persist the error as an assistant message so a subsequent /stream
    // call loads it as part of history; the SDK still sends a generic string
    // down the SSE channel for the live `useChat.error` hook on the client.
    // Persist is fire-and-forget — the SDK requires the callback to be sync.
    const sseResponse = result.toUIMessageStreamResponse({
      onError: (err) => {
        console.error('[aegis-v3] Stream error:', err);
        if (resolvedThreadId) {
          void writeAegisChatError(resolvedThreadId, classifyChatError(err)).catch(
            (writeErr) => console.error('[aegis-v3] error persistence failed', writeErr),
          );
        }
        return 'Something went wrong while generating a response.';
      },
    });

    // Pipe SDK response bytes to BOTH the live HTTP socket AND the Redis
    // chunk sink. The Redis tee is independent of the HTTP socket — if the
    // user navigates away, we keep capturing bytes for them to replay on
    // return. The agent itself keeps generating via consumeStream regardless.
    const reader = sseResponse.body!.getReader();
    let httpAlive = !res.writableEnded && !res.destroyed;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        sink.append(value);
        if (httpAlive) {
          const canContinue = res.write(value);
          if (!canContinue) {
            await new Promise<void>((resolve) => res.once('drain', () => resolve()));
          }
          if (res.writableEnded || res.destroyed) httpAlive = false;
        }
      }
    } finally {
      // Sentinel + mapping cleanup happen regardless of how the loop exits.
      // Replay readers see __END__ and close out cleanly; the thread mapping
      // is dropped so a re-resume after completion returns 204 immediately.
      await sink.end();
      await clearActiveStream(resolvedThreadId);
      if (!res.writableEnded) res.end();
    }
  } catch (err: any) {
    // Real cause stays in server logs; the user only ever sees the generic
    // "something went wrong" message. Leaking DB column names or supabase
    // error text into the chat is a UX failure and a small infosec leak.
    console.error('[aegis-v3] Stream setup error:', err);
    if (resolvedThreadId) {
      await writeAegisChatError(resolvedThreadId, classifyChatError(err));
    }
    if (!res.headersSent) {
      res.status(500).json({ error: 'Something went wrong. Please try again.' });
    } else if (!res.writableEnded) {
      res.end();
    }
  }
});

// Resume an in-flight stream. The AI SDK's HttpChatTransport.reconnectToStream
// hits this endpoint by default when useChat.resumeStream() is called — its
// canonical URL shape is `${api}/${chatId}/stream`. We look up the active
// streamId for the thread, replay every SSE byte already captured, then
// tail the Redis chunk list for new bytes until __END__. If there's no
// active stream (already finished, or never started), we 204 — the SDK
// treats that as "nothing to resume" and proceeds with whatever messages
// are already in state.
router.get('/stream/:threadId/stream', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { threadId } = req.params;
  if (!threadId) return res.status(400).end();

  const thread = await getThreadForParticipant(threadId, userId);
  if (!thread) return res.status(404).end();
  if (!(await hasAegisPermission(thread.organization_id, userId))) {
    return res.status(403).end();
  }

  const streamId = await getActiveStreamId(threadId);
  if (!streamId) {
    // No live stream to resume. SDK reads this as null and is a no-op.
    return res.status(204).end();
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Vercel-AI-UI-Message-Stream': 'v1',
    'X-Accel-Buffering': 'no',
  });

  try {
    await replayStream(streamId, res);
  } catch (err) {
    console.error('[aegis-v3] resume replay error', err);
  } finally {
    if (!res.writableEnded) res.end();
  }
});

// Regenerate trims the thread back to the last user message so a fresh
// /stream call (driven by useChat.regenerate on the client) re-runs against
// the same prompt. The actual streaming is the client's job — this route
// just owns the server-side cleanup.
router.post('/regenerate', async (req: AuthRequest, res) => {
  const userId = req.user!.id;
  const { threadId } = req.body ?? {};
  if (!threadId || typeof threadId !== 'string') {
    return res.status(400).json({ error: 'threadId is required' });
  }

  const thread = await getThreadForParticipant(threadId, userId);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  if (!(await hasAegisPermission(thread.organization_id, userId))) {
    return res.status(403).json({ error: 'You do not have permission to use Aegis' });
  }

  const { data: lastUser } = await supabase
    .from('aegis_chat_messages')
    .select('id, created_at')
    .eq('thread_id', threadId)
    .eq('role', 'user')
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  if (!lastUser) return res.status(400).json({ error: 'No user message to regenerate from' });

  const { error: deleteErr } = await supabase
    .from('aegis_chat_messages')
    .delete()
    .eq('thread_id', threadId)
    .gt('created_at', lastUser.created_at);
  if (deleteErr) {
    console.error('[aegis-v3] regenerate delete failed', deleteErr);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }

  res.json({ threadId });
});

export default router;
