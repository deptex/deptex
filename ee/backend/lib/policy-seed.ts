/**
 * Seed default statuses, asset tiers, and policy code for a new organization.
 */

import { supabase } from '../../../backend/src/lib/supabase';
import {
  DEFAULT_STATUSES,
  DEFAULT_ASSET_TIERS,
  DEFAULT_PACKAGE_POLICY_CODE,
  DEFAULT_PROJECT_STATUS_CODE,
  DEFAULT_PR_CHECK_CODE,
} from './policy-defaults';

export async function seedOrganizationPolicyDefaults(organizationId: string): Promise<void> {
  const { error: statusError } = await supabase
    .from('organization_statuses')
    .insert(
      DEFAULT_STATUSES.map((s) => ({ ...s, organization_id: organizationId }))
    );

  if (statusError) {
    console.error('Failed to seed statuses:', statusError);
  }

  const { error: tierError } = await supabase
    .from('organization_asset_tiers')
    .insert(
      DEFAULT_ASSET_TIERS.map((t) => ({ ...t, organization_id: organizationId }))
    );

  if (tierError) {
    console.error('Failed to seed asset tiers:', tierError);
  }

  const { error: pkgPolicyError } = await supabase
    .from('organization_package_policies')
    .insert({
      organization_id: organizationId,
      package_policy_code: DEFAULT_PACKAGE_POLICY_CODE,
    });

  if (pkgPolicyError) {
    console.error('Failed to seed package policy:', pkgPolicyError);
  }

  const { error: statusCodeError } = await supabase
    .from('organization_status_codes')
    .insert({
      organization_id: organizationId,
      project_status_code: DEFAULT_PROJECT_STATUS_CODE,
    });

  if (statusCodeError) {
    console.error('Failed to seed status code:', statusCodeError);
  }

  const { error: prCheckError } = await supabase
    .from('organization_pr_checks')
    .insert({
      organization_id: organizationId,
      pr_check_code: DEFAULT_PR_CHECK_CODE,
    });

  if (prCheckError) {
    console.error('Failed to seed PR check code:', prCheckError);
  }
}
