import express from 'express';
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

    // Flush response headers (including X-Thread-Id) eagerly, BEFORE the
    // LLM is invoked. Otherwise the client doesn't see the threadId until
    // the first SSE chunk arrives, and a fast Stop click during the
    // submission phase would abort the fetch before headers are received —
    // the server has the thread, the client has no way to learn its id, and
    // the next message creates a duplicate. We bypass
    // pipeUIMessageStreamToResponse here so we control when writeHead fires.
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Vercel-AI-UI-Message-Stream': 'v1',
      'X-Accel-Buffering': 'no',
      'X-Thread-Id': resolvedThreadId,
    });

    const [history, memoryContext] = await Promise.all([
      loadThreadHistory(resolvedThreadId),
      queryRelevantMemories(organizationId, message),
    ]);

    // Pre-flight cost cap. If the org is over budget, record a cost_cap error
    // assistant message and skip the model call. We deliberately also skip
    // saving the user message — there's nothing to answer it with.
    const providerInfo = await getProviderInfoForOrg(organizationId, modelId);
    const cap = await checkMonthlyCostCap(
      organizationId,
      providerInfo.model,
      [{ role: 'user', content: message }],
      providerInfo.monthlyCostCap,
    );
    if (!cap.allowed) {
      await writeAegisChatError(resolvedThreadId, { type: 'cost_cap', message: cap.message });
      // Headers (including X-Thread-Id) are already flushed; just close the
      // empty SSE stream. The client treats no-content + persisted error row
      // the same as any other turn.
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

    const agent = await createAegisAgent({
      orgId: organizationId,
      userId,
      threadId: resolvedThreadId,
      userMessage: message,
      priorMessageCount: history.length,
      context,
      memoryContext,
      modelId,
    });

    const messages: ModelMessage[] = [...history, { role: 'user', content: message }];
    const result = await agent.stream({ messages });

    // Manual pipe (replicates pipeUIMessageStreamToResponse's read/write/drain
    // loop). We can't use that helper because it calls res.writeHead a second
    // time, which Node rejects after our eager flush above.
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

    const reader = sseResponse.body!.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (res.writableEnded || res.destroyed) break;
        const canContinue = res.write(value);
        if (!canContinue) {
          await new Promise<void>((resolve) => res.once('drain', () => resolve()));
        }
      }
    } finally {
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
