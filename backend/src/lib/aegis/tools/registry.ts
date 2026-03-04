// @ts-nocheck
import { tool, CoreTool } from 'ai';
import { z } from 'zod';
import { AegisToolMeta, ToolContext, PermissionLevel, TOOL_PROFILES } from './types';
import { supabase } from '../../../lib/supabase';

interface RegisteredTool {
  meta: AegisToolMeta;
  aiTool: CoreTool<any, any>;
}

const toolStore = new Map<string, RegisteredTool>();

export function registerAegisTool(
  name: string,
  meta: AegisToolMeta,
  aiTool: CoreTool<any, any>,
) {
  toolStore.set(name, { meta, aiTool });
}

export function getAllToolMetas(): Array<{ name: string; meta: AegisToolMeta }> {
  return Array.from(toolStore.entries()).map(([name, t]) => ({ name, meta: t.meta }));
}

function resolveActiveProfiles(
  context: ToolContext,
  messageHint?: string,
): string[] {
  const profiles: string[] = ['default'];
  const hint = (messageHint || '').toLowerCase();

  const secKeywords = ['vuln', 'cve', 'fix', 'sprint', 'suppress', 'risk', 'reachab', 'lockdown', 'blast'];
  if (secKeywords.some(k => hint.includes(k)) || context.projectId) profiles.push('security');

  const polKeywords = ['policy', 'complian', 'license', 'exception', 'sbom', 'vex', 'audit'];
  if (polKeywords.some(k => hint.includes(k))) profiles.push('policy', 'compliance');

  const intKeywords = ['reputation', 'epss', 'kev', 'upgrade', 'dependency health', 'debt'];
  if (intKeywords.some(k => hint.includes(k))) profiles.push('intelligence');

  const extKeywords = ['slack', 'email', 'jira', 'linear', 'notify', 'alert', 'webhook', 'pr comment'];
  if (extKeywords.some(k => hint.includes(k))) profiles.push('external');

  profiles.push('admin');

  return [...new Set(profiles)];
}

function getActiveToolNames(profiles: string[]): Set<string> {
  const names = new Set<string>();
  for (const profile of profiles) {
    const list = TOOL_PROFILES[profile as keyof typeof TOOL_PROFILES];
    if (list) list.forEach(n => names.add(n));
  }
  return names;
}

async function checkToolPermission(
  toolName: string,
  meta: AegisToolMeta,
  context: ToolContext,
): Promise<{ allowed: boolean; reason?: string; requiresApproval?: boolean }> {
  if (meta.permissionLevel === 'safe') return { allowed: true };

  if (context.operatingMode === 'readonly' && meta.permissionLevel !== 'safe') {
    return { allowed: false, reason: 'Organization is in read-only mode.' };
  }

  const { data: settings } = await supabase
    .from('aegis_org_settings')
    .select('tool_permissions')
    .eq('organization_id', context.organizationId)
    .single();

  const overrides = settings?.tool_permissions || {};
  const categoryOverride = overrides[meta.category];
  const toolOverride = overrides[toolName];

  const effectiveLevel = toolOverride || categoryOverride;

  if (effectiveLevel === 'blocked') {
    return { allowed: false, reason: `Tool ${toolName} is blocked by organization settings.` };
  }

  if (effectiveLevel === 'always_require_approval') {
    return { allowed: true, requiresApproval: true };
  }

  if (effectiveLevel === 'auto_approve') {
    return { allowed: true };
  }

  if (meta.permissionLevel === 'dangerous') {
    return { allowed: true, requiresApproval: true };
  }

  if (meta.permissionLevel === 'moderate') {
    if (context.operatingMode === 'autopilot') return { allowed: true };
    return { allowed: true, requiresApproval: true };
  }

  return { allowed: true };
}

async function logToolExecution(
  toolName: string,
  meta: AegisToolMeta,
  context: ToolContext,
  params: any,
  result: any,
  success: boolean,
  durationMs: number,
) {
  try {
    await supabase.from('aegis_tool_executions').insert({
      organization_id: context.organizationId,
      user_id: context.userId,
      thread_id: context.threadId || null,
      task_id: context.taskId || null,
      tool_name: toolName,
      tool_category: meta.category,
      parameters: params,
      result: typeof result === 'string' ? { text: result.substring(0, 10000) } : result,
      success,
      permission_level: meta.permissionLevel,
      duration_ms: durationMs,
    });
  } catch (err) {
    console.error('[Aegis] Failed to log tool execution:', err);
  }
}

export function buildToolSet(
  context: ToolContext,
  messageHint?: string,
): Record<string, CoreTool<any, any>> {
  const profiles = resolveActiveProfiles(context, messageHint);
  const activeNames = getActiveToolNames(profiles);
  const tools: Record<string, CoreTool<any, any>> = {};

  for (const [name, registered] of toolStore) {
    if (!activeNames.has(name)) continue;

    const original = registered.aiTool;

    tools[name] = tool({
      description: (original as any).description,
      parameters: (original as any).parameters,
      execute: async (params: any) => {
        const perm = await checkToolPermission(name, registered.meta, context);
        if (!perm.allowed) {
          return JSON.stringify({ error: perm.reason, blocked: true });
        }

        if (perm.requiresApproval) {
          await supabase.from('aegis_approval_requests').insert({
            organization_id: context.organizationId,
            requested_by: context.userId,
            thread_id: context.threadId || null,
            task_id: context.taskId || null,
            tool_name: name,
            parameters: params,
            justification: `Aegis wants to execute ${name} (${registered.meta.permissionLevel} permission level)`,
          });

          return JSON.stringify({
            approval_required: true,
            tool: name,
            message: `This action requires approval. An approval request has been created.`,
          });
        }

        const start = Date.now();
        try {
          const result = await (original as any).execute(params);
          await logToolExecution(name, registered.meta, context, params, result, true, Date.now() - start);
          return result;
        } catch (err: any) {
          await logToolExecution(name, registered.meta, context, params, { error: err.message }, false, Date.now() - start);
          return JSON.stringify({ error: err.message, tool: name });
        }
      },
    });
  }

  return tools;
}
