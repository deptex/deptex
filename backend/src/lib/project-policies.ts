/**
 * Project policy helpers (effective licenses, license allowed check).
 * Shared by routes/projects and routes/integrations (PR guardrails).
 */

import { supabase } from './supabase';

function normalizeLicenseForComparison(license: string): string {
  return license
    .toLowerCase()
    .replace(/[-_]/g, ' ')
    .replace(/['"()]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractLicenseKey(license: string): string {
  const normalized = normalizeLicenseForComparison(license);
  const parts: string[] = [];

  if (normalized.includes('0bsd') || normalized.includes('0 bsd') || normalized.includes('zero clause')) {
    parts.push('0bsd');
  } else if (normalized.includes('bsd')) {
    parts.push('bsd');
    const clauseMatch = normalized.match(/(\d)\s*clause/);
    if (clauseMatch) parts.push(clauseMatch[1] + 'clause');
  }

  if (normalized.includes('apache')) parts.push('apache');
  if (normalized.includes('mit')) parts.push('mit');
  if (normalized.includes('isc')) parts.push('isc');
  if (normalized.includes('gpl') || normalized.includes('general public')) parts.push('gpl');
  if (normalized.includes('agpl') || normalized.includes('affero')) parts.push('agpl');
  if (normalized.includes('lgpl') || normalized.includes('lesser general')) parts.push('lgpl');
  if (normalized.includes('mpl') || normalized.includes('mozilla')) parts.push('mpl');
  if (normalized.includes('epl') || normalized.includes('eclipse')) parts.push('epl');
  if (normalized.includes('cc0') || normalized.includes('creative commons zero')) parts.push('cc0');
  if (normalized.includes('cc by') || normalized.includes('creative commons attribution')) parts.push('ccby');
  if (normalized.includes('unlicense')) parts.push('unlicense');
  if (normalized.includes('boost') || normalized.includes('bsl')) parts.push('boost');
  if (normalized.includes('blue oak') || normalized.includes('blueoak')) parts.push('blueoak');
  if (normalized.includes('python')) parts.push('python');

  if (!parts.includes('0bsd')) {
    const versionMatch = normalized.match(/(\d+\.?\d*)/);
    if (versionMatch) parts.push(versionMatch[1]);
  }

  return parts.join('-');
}

function checkSingleLicenseAllowed(singleLicense: string, acceptedLicenses: string[]): boolean {
  const licenseKey = extractLicenseKey(singleLicense);
  const normalizedLicense = normalizeLicenseForComparison(singleLicense);

  return acceptedLicenses.some((allowed) => {
    const allowedKey = extractLicenseKey(allowed);
    const normalizedAllowed = normalizeLicenseForComparison(allowed);

    if (licenseKey && allowedKey && licenseKey === allowedKey) return true;

    return normalizedLicense.includes(normalizedAllowed) || normalizedAllowed.includes(normalizedLicense);
  });
}

/**
 * Check if a license (possibly with OR expressions) is allowed by the given accepted list.
 * Returns true if allowed, false if not allowed, null if unknown.
 */
export function isLicenseAllowed(license: string | null, acceptedLicenses: string[]): boolean | null {
  if (!license || license === 'Unknown') return null;

  const orParts = license.split(/\s+or\s+/i).map((part) => part.replace(/[()]/g, '').trim());

  return orParts.some((part) => checkSingleLicenseAllowed(part, acceptedLicenses));
}

/**
 * Get effective policies for a project.
 * Policy is now stored as code (policy_code); license-based checks receive empty list until evaluator runs.
 */
export async function getEffectivePolicies(organizationId: string, projectId: string): Promise<{
  acceptedLicenses: string[];
}> {
  await supabase
    .from('organization_policies')
    .select('policy_code')
    .eq('organization_id', organizationId)
    .single();

  // Policy is defined as code; no accepted_licenses. Return empty so downstream checks see "no licenses".
  return { acceptedLicenses: [] };
}
