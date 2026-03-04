// @ts-nocheck
import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../lib/supabase';

registerAegisTool('createScheduledJob', {
  category: 'automation',
  permissionLevel: 'moderate',
  requiredRbacPermissions: ['manage_aegis'],
}, tool({
  description: 'Create a scheduled automation that runs Aegis with a specific prompt on a cron schedule. Supports templates like daily security briefing, weekly digest, etc.',
  parameters: z.object({
    organizationId: z.string().uuid(),
    name: z.string(),
    prompt: z.string().describe('The prompt Aegis will execute on each run'),
    cronExpression: z.string().describe('Cron expression (e.g. "0 7 * * 1-5" for weekdays at 7am)'),
    timezone: z.string().default('UTC'),
    automationType: z.enum(['custom', 'template']).default('custom'),
    templateConfig: z.record(z.any()).optional(),
    deliveryConfig: z.object({
      channels: z.array(z.enum(['inbox', 'email', 'slack', 'discord'])).default(['inbox']),
      slackChannel: z.string().optional(),
    }).optional(),
    enabled: z.boolean().default(true),
  }),
  execute: async ({ organizationId, name, prompt, cronExpression, timezone, automationType, templateConfig, deliveryConfig, enabled }) => {
    try {
      const { data, error } = await supabase
        .from('aegis_automations')
        .insert({
          organization_id: organizationId,
          name,
          description: prompt,
          schedule: cronExpression,
          cron_expression: cronExpression,
          timezone,
          automation_type: automationType,
          template_config: templateConfig || {},
          delivery_config: deliveryConfig || { channels: ['inbox'] },
          enabled,
        })
        .select()
        .single();

      if (error) throw error;
      return JSON.stringify({ success: true, automation: { id: data.id, name: data.name, schedule: data.cron_expression, enabled: data.enabled } });
    } catch (err: any) {
      return JSON.stringify({ error: err.message });
    }
  },
}));

registerAegisTool('updateScheduledJob', {
  category: 'automation',
  permissionLevel: 'moderate',
  requiredRbacPermissions: ['manage_aegis'],
}, tool({
  description: 'Update an existing scheduled automation.',
  parameters: z.object({
    automationId: z.string().uuid(),
    name: z.string().optional(),
    prompt: z.string().optional(),
    cronExpression: z.string().optional(),
    timezone: z.string().optional(),
    enabled: z.boolean().optional(),
    deliveryConfig: z.record(z.any()).optional(),
  }),
  execute: async ({ automationId, name, prompt, cronExpression, timezone, enabled, deliveryConfig }) => {
    try {
      const updateData: any = {};
      if (name !== undefined) updateData.name = name;
      if (prompt !== undefined) updateData.description = prompt;
      if (cronExpression !== undefined) {
        updateData.cron_expression = cronExpression;
        updateData.schedule = cronExpression;
      }
      if (timezone !== undefined) updateData.timezone = timezone;
      if (enabled !== undefined) updateData.enabled = enabled;
      if (deliveryConfig !== undefined) updateData.delivery_config = deliveryConfig;

      const { data, error } = await supabase
        .from('aegis_automations')
        .update(updateData)
        .eq('id', automationId)
        .select('id, name, cron_expression, enabled')
        .single();

      if (error) throw error;
      return JSON.stringify({ success: true, automation: data });
    } catch (err: any) {
      return JSON.stringify({ error: err.message });
    }
  },
}));

registerAegisTool('deleteScheduledJob', {
  category: 'automation',
  permissionLevel: 'moderate',
  requiredRbacPermissions: ['manage_aegis'],
}, tool({
  description: 'Delete a scheduled automation.',
  parameters: z.object({
    automationId: z.string().uuid(),
  }),
  execute: async ({ automationId }) => {
    try {
      const { error } = await supabase
        .from('aegis_automations')
        .delete()
        .eq('id', automationId);

      if (error) throw error;
      return JSON.stringify({ success: true, deleted: automationId });
    } catch (err: any) {
      return JSON.stringify({ error: err.message });
    }
  },
}));
