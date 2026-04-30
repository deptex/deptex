import express from 'express';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { checkRateLimit } from '../lib/rate-limit';
import { createAegisAgent } from '../lib/aegis-v3/agent';
import { getOrCreateThread, loadThreadHistory } from '../lib/aegis-v3/thread';
import { queryRelevantMemories } from '../lib/aegis-v3/memory';
import { saveUserMessage } from '../lib/aegis-v3/persistence';
import { classifyChatError, writeAegisChatError } from '../lib/aegis-v3/errors';
import { getProviderInfoForOrg } from '../lib/aegis-v3/provider';
import { checkMonthlyCostCap } from '../lib/ai/cost-cap';
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
  const { organizationId, threadId, message, context } = req.body ?? {};

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

    const [history, memoryContext] = await Promise.all([
      loadThreadHistory(resolvedThreadId),
      queryRelevantMemories(organizationId, message),
    ]);

    // Pre-flight cost cap. If the org is over budget, record a cost_cap error
    // assistant message and skip the model call. We deliberately also skip
    // saving the user message — there's nothing to answer it with.
    const providerInfo = await getProviderInfoForOrg(organizationId);
    const cap = await checkMonthlyCostCap(
      organizationId,
      providerInfo.model,
      [{ role: 'user', content: message }],
      providerInfo.monthlyCostCap,
    );
    if (!cap.allowed) {
      await writeAegisChatError(resolvedThreadId, { type: 'cost_cap', message: cap.message });
      res.setHeader('X-Thread-Id', resolvedThreadId);
      return res.json({ threadId: resolvedThreadId });
    }

    // Persist the user message before streaming starts. A refresh mid-stream
    // then keeps the question visible; only the in-flight assistant tokens
    // are lost (the user can resend).
    await saveUserMessage({ threadId: resolvedThreadId, userId, content: message });

    const agent = await createAegisAgent({
      orgId: organizationId,
      userId,
      threadId: resolvedThreadId,
      userMessage: message,
      priorMessageCount: history.length,
      context,
      memoryContext,
    });

    res.setHeader('X-Thread-Id', resolvedThreadId);

    const messages: ModelMessage[] = [...history, { role: 'user', content: message }];
    const result = await agent.stream({ messages });
    // onError fires for mid-stream failures (provider 429/5xx, network drops).
    // We persist the error as an assistant message so on reload the user sees
    // the regenerate-able error bubble; the SDK still sends a generic string
    // down the SSE channel for the live `useChat.error` hook on the client.
    result.pipeUIMessageStreamToResponse(res, {
      onError: (err) => {
        console.error('[aegis-v3] Stream error:', err);
        if (resolvedThreadId) {
          void writeAegisChatError(resolvedThreadId, classifyChatError(err));
        }
        return 'Something went wrong while generating a response.';
      },
    });
  } catch (err: any) {
    console.error('[aegis-v3] Stream setup error:', err);
    if (resolvedThreadId) {
      await writeAegisChatError(resolvedThreadId, classifyChatError(err));
    }
    if (!res.headersSent) {
      res.status(500).json({ error: err?.message ?? 'Failed to create Aegis stream' });
    } else if (!res.writableEnded) {
      res.end();
    }
  }
});

export default router;
