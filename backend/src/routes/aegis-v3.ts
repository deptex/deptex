import express from 'express';
import { authenticateUser, type AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { checkRateLimit } from '../lib/rate-limit';
import { createAegisAgent } from '../lib/aegis-v3/agent';
import { getOrCreateThread, loadThreadHistory } from '../lib/aegis-v3/thread';
import { queryRelevantMemories } from '../lib/aegis-v3/memory';
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

  try {
    const resolvedThreadId = await getOrCreateThread(
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

    const agent = await createAegisAgent({
      orgId: organizationId,
      userId,
      threadId: resolvedThreadId,
      userMessage: message,
      context,
      memoryContext,
    });

    res.setHeader('X-Thread-Id', resolvedThreadId);

    const messages: ModelMessage[] = [...history, { role: 'user', content: message }];
    const result = await agent.stream({ messages });
    result.pipeUIMessageStreamToResponse(res);
  } catch (err: any) {
    console.error('[aegis-v3] Stream error:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: err?.message ?? 'Failed to create Aegis stream' });
    } else if (!res.writableEnded) {
      res.end();
    }
  }
});

export default router;
