import { tool, type FlexibleSchema, type Tool } from 'ai';
import type { SupabaseClient } from '@supabase/supabase-js';

export type ToolDanger = 'safe' | 'low' | 'medium' | 'high';

export type ToolPermissionKey =
  | 'interact_with_aegis'
  | 'manage_aegis'
  | 'trigger_fix'
  | 'view_ai_spending'
  | 'manage_incidents';

export type AegisOperatingMode = 'propose' | 'announce' | 'autopilot';

export interface AegisToolContext {
  orgId: string;
  userId: string;
  threadId: string;
  operatingMode: AegisOperatingMode;
  supabase: SupabaseClient;
}

export interface AegisToolEntry<Input = any, Output = unknown> {
  name: string;
  description: string;
  inputSchema: FlexibleSchema<Input>;
  permission?: ToolPermissionKey;
  danger?: ToolDanger;
  // Defaults to true. Set false for tools whose calls are pure UI bookkeeping
  // (e.g. set_todos) — they should not write a row to aegis_tool_executions
  // every step, which would otherwise pollute cost/usage dashboards.
  audit?: boolean;
  execute: (input: Input, ctx: AegisToolContext) => Promise<Output>;
}

async function checkOrgPermission(
  supabase: SupabaseClient,
  orgId: string,
  userId: string,
  permission: ToolPermissionKey,
): Promise<boolean> {
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

  return role?.permissions?.[permission] === true;
}

type ToolPermissionError = { error: string };

export function buildSDKTool<Input, Output>(
  entry: AegisToolEntry<Input, Output>,
  ctx: AegisToolContext,
) {
  const execute = async (input: Input): Promise<Output | ToolPermissionError> => {
    if (entry.permission) {
      const allowed = await checkOrgPermission(
        ctx.supabase,
        ctx.orgId,
        ctx.userId,
        entry.permission,
      );
      if (!allowed) {
        return { error: `Missing permission: ${entry.permission}` };
      }
    }
    return entry.execute(input, ctx);
  };

  return tool<Input, Output | ToolPermissionError>({
    description: entry.description,
    inputSchema: entry.inputSchema,
    execute,
  } as Tool<Input, Output | ToolPermissionError>);
}
