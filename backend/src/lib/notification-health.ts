import { supabase } from '../lib/supabase';

export async function updateConnectionHealth(connectionId: string, success: boolean, orgId?: string): Promise<void> {
  if (success) {
    await supabase.from('organization_integrations')
      .update({ consecutive_failures: 0, status: 'active' })
      .eq('id', connectionId)
      .neq('consecutive_failures', 0);
  } else {
    const { data } = await supabase.from('organization_integrations')
      .select('consecutive_failures, provider, organization_id')
      .eq('id', connectionId)
      .single();

    const newCount = (data?.consecutive_failures || 0) + 1;
    const updates: Record<string, any> = {
      consecutive_failures: newCount,
      last_failure_at: new Date().toISOString(),
    };

    if (newCount >= 3) {
      updates.status = 'error';
      try {
        const { emitEvent } = require('./event-bus');
        await emitEvent({
          type: 'integration_disconnected',
          organizationId: orgId || data?.organization_id,
          payload: { provider: data?.provider, reason: 'Auto-disabled after 3 consecutive failures' },
          source: 'notification_system',
          priority: 'high',
        });
      } catch (e) { /* ignore notification failure about notification failure */ }
    }

    await supabase.from('organization_integrations')
      .update(updates)
      .eq('id', connectionId);
  }
}
