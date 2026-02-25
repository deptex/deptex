import { registerAction, ActionResult, ActionContext } from './index';
import { supabase } from '../../../../../backend/src/lib/supabase';

// Register listPolicies action
registerAction(
  {
    name: 'listPolicies',
    description: 'List organization policies (policy as code). Returns policy_code and backward-compat fields.',
    parameters: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  async (params: any, context: ActionContext): Promise<ActionResult> => {
    try {
      const { data: policies, error } = await supabase
        .from('organization_policies')
        .select('policy_code')
        .eq('organization_id', context.organizationId)
        .single();

      if (error) {
        if (error.code === 'PGRST116') {
          return {
            success: true,
            data: {
              policy_code: '',
              accepted_licenses: [],
              rejected_licenses: [],
              slsa_enforcement: 'none',
              slsa_level: null,
            },
          };
        }
        return {
          success: false,
          error: error.message || 'Failed to fetch policies',
        };
      }

      const policyCode = policies?.policy_code ?? '';
      return {
        success: true,
        data: {
          policy_code: policyCode,
          accepted_licenses: [],
          rejected_licenses: [],
          slsa_enforcement: 'none',
          slsa_level: null,
        },
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Unknown error occurred',
      };
    }
  }
);

// Register getPolicy action
registerAction(
  {
    name: 'getPolicy',
    description: 'Get detailed policy information (policy as code). Returns the same as listPolicies since there is only one policy per organization.',
    parameters: {
      type: 'object',
      properties: {
        policyId: {
          type: 'string',
          description: 'The ID of the policy (optional, since there is only one policy per organization)',
        },
      },
      required: [],
    },
  },
  async (params: { policyId?: string }, context: ActionContext): Promise<ActionResult> => {
    try {
      const { data: policies, error } = await supabase
        .from('organization_policies')
        .select('id, policy_code, created_at, updated_at')
        .eq('organization_id', context.organizationId)
        .single();

      if (error) {
        if (error.code === 'PGRST116') {
          return {
            success: true,
            data: {
              policy_code: '',
              accepted_licenses: [],
              rejected_licenses: [],
              slsa_enforcement: 'none',
              slsa_level: null,
              message: 'No policies configured for this organization',
            },
          };
        }
        return {
          success: false,
          error: error.message || 'Failed to fetch policy',
        };
      }

      const policyCode = policies?.policy_code ?? '';
      return {
        success: true,
        data: {
          id: policies.id,
          policy_code: policyCode,
          accepted_licenses: [],
          rejected_licenses: [],
          slsa_enforcement: 'none',
          slsa_level: null,
          created_at: policies.created_at,
          updated_at: policies.updated_at,
        },
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Unknown error occurred',
      };
    }
  }
);

