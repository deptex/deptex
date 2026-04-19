import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../../../backend/src/lib/supabase';
import { preflightCheck } from '../../policy-engine';
import { DEFAULT_PACKAGE_POLICY_CODE, DEFAULT_PROJECT_STATUS_CODE, DEFAULT_PR_CHECK_CODE } from '../../policy-defaults';
import { getPlatformProvider } from '../../ai/provider';

const codeTypeSchema = z.enum(['package_policy', 'project_status', 'pr_check']);

registerAegisTool(
  'listPolicies',
  { category: 'policy', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Get organization policies. Returns package policy, project status, and PR check policy summaries.',
    parameters: z.object({
      organizationId: z.string().uuid(),
    }),
    execute: async ({ organizationId }) => {
      const [pkg, status, pr] = await Promise.all([
        supabase.from('organization_package_policies').select('id, package_policy_code').eq('organization_id', organizationId).single(),
        supabase.from('organization_status_codes').select('id, project_status_code').eq('organization_id', organizationId).single(),
        supabase.from('organization_pr_checks').select('id, pr_check_code').eq('organization_id', organizationId).single(),
      ]);
      const result = {
        packagePolicy: { hasCode: !!(pkg.data?.package_policy_code), length: pkg.data?.package_policy_code?.length ?? 0 },
        projectStatus: { hasCode: !!(status.data?.project_status_code), length: status.data?.project_status_code?.length ?? 0 },
        prCheck: { hasCode: !!(pr.data?.pr_check_code), length: pr.data?.pr_check_code?.length ?? 0 },
        errors: [pkg.error, status.error, pr.error].filter(Boolean).map(e => (e as { message: string }).message),
      };
      return JSON.stringify(result);
    },
  })
);

registerAegisTool(
  'getPolicy',
  { category: 'policy', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Get specific policy code by type (package_policy, project_status, pr_check).',
    parameters: z.object({
      organizationId: z.string().uuid(),
      codeType: codeTypeSchema,
    }),
    execute: async ({ organizationId, codeType }) => {
      const table = codeType === 'package_policy' ? 'organization_package_policies'
        : codeType === 'project_status' ? 'organization_status_codes'
        : 'organization_pr_checks';
      const column = codeType === 'package_policy' ? 'package_policy_code'
        : codeType === 'project_status' ? 'project_status_code'
        : 'pr_check_code';
      const { data, error } = await supabase.from(table as any).select(column).eq('organization_id', organizationId).single();
      if (error) return JSON.stringify({ error: error.message });
      return JSON.stringify({ codeType, code: (data as any)?.[column] ?? '' });
    },
  })
);

registerAegisTool(
  'createPolicy',
  { category: 'policy', permissionLevel: 'moderate', requiredRbacPermissions: ['manage_compliance'] },
  tool({
    description: 'Create or update a policy. Upserts into the appropriate organization policy table.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      codeType: codeTypeSchema,
      code: z.string(),
    }),
    execute: async ({ organizationId, codeType, code }) => {
      const table = codeType === 'package_policy' ? 'organization_package_policies'
        : codeType === 'project_status' ? 'organization_status_codes'
        : 'organization_pr_checks';
      const column = codeType === 'package_policy' ? 'package_policy_code'
        : codeType === 'project_status' ? 'project_status_code'
        : 'pr_check_code';
      const { error } = await supabase.from(table as any).upsert(
        { organization_id: organizationId, [column]: code },
        { onConflict: 'organization_id', ignoreDuplicates: false }
      );
      if (error) return JSON.stringify({ error: error.message });
      return JSON.stringify({ success: true, codeType, message: 'Policy created/updated.' });
    },
  })
);

registerAegisTool(
  'updatePolicy',
  { category: 'policy', permissionLevel: 'moderate', requiredRbacPermissions: ['manage_compliance'] },
  tool({
    description: 'Update policy code and record the change in organization_policy_changes.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      codeType: codeTypeSchema,
      code: z.string(),
      message: z.string().optional(),
    }),
    execute: async ({ organizationId, codeType, code, message }) => {
      const table = codeType === 'package_policy' ? 'organization_package_policies'
        : codeType === 'project_status' ? 'organization_status_codes'
        : 'organization_pr_checks';
      const column = codeType === 'package_policy' ? 'package_policy_code'
        : codeType === 'project_status' ? 'project_status_code'
        : 'pr_check_code';
      const { data: existing } = await supabase.from(table as any).select(column).eq('organization_id', organizationId).single();
      const previousCode = (existing as any)?.[column] ?? '';
      const { error: upsertErr } = await supabase.from(table as any).upsert(
        { organization_id: organizationId, [column]: code },
        { onConflict: 'organization_id', ignoreDuplicates: false }
      );
      if (upsertErr) return JSON.stringify({ error: upsertErr.message });
      const [ownerRes, anyRes] = await Promise.all([
        supabase.from('organization_members').select('user_id').eq('organization_id', organizationId).eq('role', 'owner').limit(1).single(),
        supabase.from('organization_members').select('user_id').eq('organization_id', organizationId).limit(1).single(),
      ]);
      const authorId = ownerRes.data?.user_id ?? anyRes.data?.user_id;
      if (!authorId) return JSON.stringify({ error: 'No organization member found for policy change author' });
      await supabase.from('organization_policy_changes').insert({
        organization_id: organizationId,
        code_type: codeType,
        author_id: authorId,
        previous_code: previousCode,
        new_code: code,
        message: message ?? `Updated ${codeType} via Aegis`,
      });
      return JSON.stringify({ success: true, codeType, message: 'Policy updated and change recorded.' });
    },
  })
);

registerAegisTool(
  'deletePolicy',
  { category: 'policy', permissionLevel: 'dangerous', requiredRbacPermissions: ['manage_compliance'] },
  tool({
    description: 'Reset a policy to its default. Deletes custom code.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      codeType: codeTypeSchema,
    }),
    execute: async ({ organizationId, codeType }) => {
      const defaults: Record<string, string> = {
        package_policy: DEFAULT_PACKAGE_POLICY_CODE,
        project_status: DEFAULT_PROJECT_STATUS_CODE,
        pr_check: DEFAULT_PR_CHECK_CODE,
      };
      const defaultCode = defaults[codeType];
      const table = codeType === 'package_policy' ? 'organization_package_policies'
        : codeType === 'project_status' ? 'organization_status_codes'
        : 'organization_pr_checks';
      const column = codeType === 'package_policy' ? 'package_policy_code'
        : codeType === 'project_status' ? 'project_status_code'
        : 'pr_check_code';
      const { error } = await supabase.from(table as any).update({ [column]: defaultCode }).eq('organization_id', organizationId);
      if (error) return JSON.stringify({ error: error.message });
      return JSON.stringify({ success: true, codeType, message: 'Policy reset to default.' });
    },
  })
);

registerAegisTool(
  'testPolicyDryRun',
  { category: 'policy', permissionLevel: 'safe', requiredRbacPermissions: [] },
  tool({
    description: 'Test a policy against a hypothetical package. Returns allowed/reasons.',
    parameters: z.object({
      organizationId: z.string().uuid(),
      projectId: z.string().uuid(),
      packageName: z.string(),
      version: z.string().optional(),
      ecosystem: z.string().optional(),
    }),
    execute: async ({ organizationId, projectId, packageName, version, ecosystem }) => {
      try {
        const result = await preflightCheck(organizationId, projectId, packageName, version ?? 'latest');
        return JSON.stringify({
          allowed: result.allowed,
          reasons: result.reasons,
          tierName: result.tierName,
          packageName,
          version: version ?? 'latest',
          ecosystem: ecosystem ?? 'npm',
        });
      } catch (err: any) {
        return JSON.stringify({ error: err.message });
      }
    },
  })
);

registerAegisTool(
  'generatePolicyFromDescription',
  { category: 'policy', permissionLevel: 'safe', requiredRbacPermissions: ['manage_compliance'] },
  tool({
    description: 'Generate policy code from a natural language description. Returns the generated code as a string for the LLM to present.',
    parameters: z.object({
      description: z.string(),
    }),
    execute: async ({ description }) => {
      try {
        const provider = getPlatformProvider();
        const result = await provider.chat([
          { role: 'system', content: `You are a policy-as-code assistant for Deptex. Generate JavaScript function code for a package policy (packagePolicy), project status (projectStatus), or PR check (pullRequestCheck) based on the user's description. Output ONLY valid JavaScript code - no markdown, no explanation. The function receives a context object. For packagePolicy: context has { dependency, tier }. For projectStatus: context has project and dependencies. For pullRequestCheck: context has the PR diff. Infer which type from the description.` },
          { role: 'user', content: description },
        ]);
        const code = (result.content || '').trim().replace(/^```(?:javascript|js)?\s*/i, '').replace(/\s*```$/i, '');
        return JSON.stringify({ code, raw: result.content });
      } catch (err: any) {
        return JSON.stringify({ error: err.message });
      }
    },
  })
);
