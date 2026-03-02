import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { supabase } from '../lib/supabase';

const router = Router();

router.get('/unsubscribe', handleUnsubscribe);
router.post('/unsubscribe', handleUnsubscribe);

async function handleUnsubscribe(req: any, res: any) {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Missing token' });

  const secret = process.env.INTERNAL_API_KEY;
  if (!secret) return res.status(500).json({ error: 'Server configuration error' });

  try {
    const payload = jwt.verify(token as string, secret) as { email: string; orgId: string; type: string };
    if (payload.type !== 'unsubscribe') return res.status(400).json({ error: 'Invalid token type' });

    const { data: users } = await supabase.auth.admin.listUsers();
    const targetUser = users?.users?.find((u: any) => u.email === payload.email);
    if (!targetUser) return res.status(404).json({ error: 'User not found' });

    await supabase.from('user_notification_preferences').upsert({
      user_id: targetUser.id,
      organization_id: payload.orgId,
      email_opted_out: true,
      updated_at: new Date().toISOString(),
    }, { onConflict: 'user_id,organization_id' });

    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html>
<html><head><title>Unsubscribed</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#09090b;color:#fafafa}
.card{text-align:center;padding:40px;border:1px solid #27272a;border-radius:12px;max-width:400px}
h1{font-size:24px;margin:0 0 12px}p{color:#a1a1aa;font-size:14px;line-height:1.6}
a{color:#3b82f6;text-decoration:none}</style></head>
<body><div class="card"><h1>Unsubscribed</h1>
<p>You will no longer receive email notifications from this organization.</p>
<p><a href="/settings">Manage all preferences</a></p></div></body></html>`);
  } catch (err: any) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Unsubscribe link has expired' });
    }
    return res.status(401).json({ error: 'Invalid unsubscribe token' });
  }
}

export default router;
