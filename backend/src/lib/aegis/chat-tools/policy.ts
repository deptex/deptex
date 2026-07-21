// ⚠️ DEPRECATED — policy-as-code. The policy-authoring UI has been removed. This
// read-only Aegis chat tool (list_policies) summarizes a retired feature. Retained.
import { jsonSchema } from 'ai';
import type { AegisToolEntry } from '../tool-types';

function summarize(code: string | null | undefined, updatedAt: string | null | undefined) {
  const configured = !!(code && code.trim().length > 0);
  return {
    configured,
    updatedAt: updatedAt ?? null,
    lines: configured ? (code!.match(/\n/g)?.length ?? 0) + 1 : 0,
    preview: configured ? code!.slice(0, 400) : null,
  };
}

const listPolicies: AegisToolEntry<Record<string, never>> = {
  name: 'list_policies',
  description:
    "List the org's policy code blobs: packagePolicy (per-dependency), projectStatus (per-project status assignment), and pullRequestCheck (PR blocking). Returns whether each is configured, its last-updated timestamp, and a short preview snippet.",
  danger: 'safe',
  inputSchema: jsonSchema({ type: 'object', properties: {}, additionalProperties: false }),
  execute: async (_input, ctx) => {
    const [pkgRes, statusRes, prRes, statusesRes] = await Promise.all([
      ctx.supabase
        .from('organization_package_policies')
        .select('package_policy_code, updated_at')
        .eq('organization_id', ctx.orgId)
        .maybeSingle(),
      ctx.supabase
        .from('organization_status_codes')
        .select('project_status_code, updated_at')
        .eq('organization_id', ctx.orgId)
        .maybeSingle(),
      ctx.supabase
        .from('organization_pr_checks')
        .select('pr_check_code, updated_at')
        .eq('organization_id', ctx.orgId)
        .maybeSingle(),
      ctx.supabase
        .from('organization_statuses')
        .select('name, is_passing, rank, description')
        .eq('organization_id', ctx.orgId)
        .order('rank', { ascending: true }),
    ]);

    return {
      packagePolicy: summarize(pkgRes.data?.package_policy_code, pkgRes.data?.updated_at),
      projectStatusPolicy: summarize(
        statusRes.data?.project_status_code,
        statusRes.data?.updated_at,
      ),
      pullRequestCheck: summarize(prRes.data?.pr_check_code, prRes.data?.updated_at),
      availableStatuses: (statusesRes.data ?? []).map((s: any) => ({
        name: s.name,
        isPassing: !!s.is_passing,
        rank: s.rank,
        description: s.description,
      })),
    };
  },
};

export const policyTools: AegisToolEntry[] = [listPolicies];
