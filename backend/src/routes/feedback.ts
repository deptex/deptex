import { Router } from 'express';
import { supabase } from '../lib/supabase';
import { optionalAuth, AuthRequest } from '../middleware/auth';

const router = Router();

router.post('/', optionalAuth, async (req: AuthRequest, res) => {
  const { type, body } = req.body ?? {};
  if (!type || !body || typeof body !== 'string') {
    return res.status(400).json({ error: 'Missing type or body' });
  }
  if (type !== 'issue' && type !== 'idea') {
    return res.status(400).json({ error: 'type must be "issue" or "idea"' });
  }
  const trimmed = body.trim();
  if (!trimmed) {
    return res.status(400).json({ error: 'body cannot be empty' });
  }

  const userId = req.user?.id ?? null;

  const { error } = await supabase.from('feedback').insert({
    user_id: userId,
    type,
    body: trimmed.slice(0, 10000),
  });

  if (error) {
    return res.status(500).json({ error: error.message });
  }
  return res.status(201).json({ ok: true });
});

export default router;
