import { supabase } from '../lib/supabase';

// Tables where integration connections can live
const INTEGRATION_TABLES = ['organization_integrations', 'team_integrations', 'project_integrations'] as const;

/**
 * Find which table a connection lives in and return its row.
 */
async function findConnection(connectionId: string): Promise<{ table: string; data: any } | null> {
  for (const table of INTEGRATION_TABLES) {
    const { data } = await supabase.from(table)
      .select('consecutive_failures, provider, organization_id')
      .eq('id', connectionId)
      .maybeSingle();
    if (data) return { table, data };
  }
  return null;
}

export async function updateConnectionHealth(connectionId: string, success: boolean, orgId?: string): Promise<void> {
  if (success) {
    // Try all tables — only the one that has this ID will update
    for (const table of INTEGRATION_TABLES) {
      await supabase.from(table)
        .update({ consecutive_failures: 0, status: 'active' })
        .eq('id', connectionId)
        .neq('consecutive_failures', 0);
    }
  } else {
    const found = await findConnection(connectionId);
    if (!found) return;

    const { table, data } = found;
    const newCount = (data.consecutive_failures || 0) + 1;
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
          organizationId: orgId || data.organization_id,
          payload: { provider: data.provider, reason: 'Auto-disabled after 3 consecutive failures', scope: table.replace('_integrations', '') },
          source: 'notification_system',
          priority: 'high',
        });
      } catch (e) { /* ignore notification failure about notification failure */ }
    }

    await supabase.from(table)
      .update(updates)
      .eq('id', connectionId);
  }
}
