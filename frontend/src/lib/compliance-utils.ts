import type { ProjectDependency, ProjectEffectivePolicies } from './api';

// Types shared across compliance UIs
export type ComplianceStatus = 'COMPLIANT' | 'VIOLATION' | 'UNKNOWN';
export type IssueType = 'BANNED_LICENSE' | 'MISSING_LICENSE' | 'UNAPPROVED';

/** Minimal item shape for SBOM and legal notice generation */
export interface SbomNoticeItem {
  name: string;
  version: string;
  license: string | null;
  manuallyAssignedLicense?: string | null;
}

// License checking utilities
export function normalizeLicenseForComparison(license: string): string {
  return license
    .toLowerCase()
    .replace(/[-_]/g, ' ')
    .replace(/['"()]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

export function extractLicenseKey(license: string): string {
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

/**
 * True when the dependency license is the same as the accepted one, or the accepted
 * identifier appears as a whole word (so "MIT" matches "MIT", "MIT License" but not "SigmaMIT").
 */
function normalizedLicenseMatchesAccepted(normalizedLicense: string, normalizedAllowed: string): boolean {
  if (normalizedLicense === normalizedAllowed) return true;
  // Accepted as whole word: at start, end, or surrounded by spaces
  const w = normalizedAllowed;
  return (
    normalizedLicense.startsWith(w + ' ') ||
    normalizedLicense.endsWith(' ' + w) ||
    normalizedLicense.includes(' ' + w + ' ')
  );
}

function checkSingleLicenseAllowed(singleLicense: string, acceptedLicenses: string[]): boolean {
  const licenseKey = extractLicenseKey(singleLicense);
  const normalizedLicense = normalizeLicenseForComparison(singleLicense);

  return acceptedLicenses.some((allowed) => {
    const allowedKey = extractLicenseKey(allowed);
    const normalizedAllowed = normalizeLicenseForComparison(allowed);

    // Key match only counts when the dependency license actually expresses that identifier
    // (e.g. "MIT" or "MIT License"), not when the key was inferred from a substring (e.g. "SigmaMIT" → "mit").
    if (licenseKey && allowedKey && licenseKey === allowedKey) {
      if (normalizedLicenseMatchesAccepted(normalizedLicense, normalizedAllowed)) return true;
    }

    // Substring match only when accepted appears as a whole word in dependency (avoids "SigmaMIT" matching "MIT")
    if (normalizedLicenseMatchesAccepted(normalizedLicense, normalizedAllowed)) return true;
    // Or when dependency is contained in accepted (e.g. accepted "MIT License" and dependency "MIT")
    if (normalizedAllowed.includes(normalizedLicense)) return true;
    return false;
  });
}

export function isLicenseAllowed(license: string | null, policies: ProjectEffectivePolicies | null): boolean | null {
  if (!policies || !license || license === 'Unknown' || license === 'Pending...') return null;

  const orParts = license.split(/\s+or\s+/i).map((part) => part.replace(/[()]/g, '').trim());

  return orParts.some((part) => checkSingleLicenseAllowed(part, policies.effective.accepted_licenses));
}

export function getComplianceStatus(
  dep: ProjectDependency,
  policies: ProjectEffectivePolicies | null
): { status: ComplianceStatus; issueType?: IssueType } {
  const license = dep.license;

  if (!license || license === 'Unknown') {
    return { status: 'UNKNOWN', issueType: 'MISSING_LICENSE' };
  }

  if (!dep.analysis || dep.analysis.status === 'pending' || dep.analysis.status === 'analyzing') {
    return { status: 'COMPLIANT' };
  }

  const allowed = isLicenseAllowed(license, policies);

  if (allowed === null) {
    return { status: 'COMPLIANT' };
  }

  if (allowed) {
    return { status: 'COMPLIANT' };
  }

  const normalizedLicense = normalizeLicenseForComparison(license);
  const isCopyleft =
    normalizedLicense.includes('gpl') ||
    normalizedLicense.includes('agpl') ||
    normalizedLicense.includes('lgpl') ||
    normalizedLicense.includes('copyleft');

  if (isCopyleft) {
    return { status: 'VIOLATION', issueType: 'BANNED_LICENSE' };
  }

  return { status: 'VIOLATION', issueType: 'UNAPPROVED' };
}

export function getIssueLabel(issueType?: IssueType): string {
  switch (issueType) {
    case 'BANNED_LICENSE':
      return 'Banned License';
    case 'MISSING_LICENSE':
      return 'Missing License';
    case 'UNAPPROVED':
      return 'Unapproved';
    default:
      return '';
  }
}

export function getIssueBadgeVariant(issueType?: IssueType): 'destructive' | 'warning' | 'default' {
  switch (issueType) {
    case 'BANNED_LICENSE':
      return 'destructive';
    case 'MISSING_LICENSE':
      return 'warning';
    case 'UNAPPROVED':
      return 'destructive';
    default:
      return 'default';
  }
}

export function getSlsaEnforcementLabel(enforcement: string | null | undefined): string {
  switch (enforcement) {
    case 'none':
      return 'None';
    case 'recommended':
      return 'Recommended';
    case 'require_provenance':
      return 'Require Provenance';
    case 'require_attestations':
      return 'Require Attestations';
    case 'require_signed':
      return 'Require Signed';
    default:
      return 'Not Set';
  }
}

/** Generate CycloneDX SBOM JSON from dependency-like items */
export function generateSBOM(items: SbomNoticeItem[], projectName: string): string {
  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'Deptex',
          name: 'Compliance Scanner',
          version: '1.0.0',
        },
      ],
      component: {
        type: 'application',
        name: projectName,
        version: '1.0.0',
      },
    },
    components: items.map((item) => ({
      type: 'library',
      name: item.name,
      version: item.version,
      licenses: item.license
        ? [
            {
              license: {
                id: item.license,
              },
            },
          ]
        : [],
      purl: `pkg:npm/${item.name}@${item.version}`,
    })),
  };
  return JSON.stringify(sbom, null, 2);
}

/** Generate legal attribution notice text from dependency-like items */
export function generateLegalNotice(items: SbomNoticeItem[], projectName: string): string {
  const lines: string[] = [
    `THIRD-PARTY SOFTWARE NOTICES AND INFORMATION`,
    `Project: ${projectName}`,
    `Generated: ${new Date().toLocaleDateString()}`,
    ``,
    `This project incorporates components from the projects listed below.`,
    ``,
    `${'='.repeat(70)}`,
    ``,
  ];

  const grouped = items.reduce((acc, item) => {
    const license = item.manuallyAssignedLicense || item.license || 'Unknown';
    if (!acc[license]) acc[license] = [];
    acc[license].push(item);
    return acc;
  }, {} as Record<string, SbomNoticeItem[]>);

  Object.entries(grouped)
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([license, pkgs]) => {
      lines.push(`LICENSE: ${license}`);
      lines.push(`${'-'.repeat(70)}`);
      pkgs.forEach((pkg) => {
        lines.push(`  - ${pkg.name}@${pkg.version}`);
      });
      lines.push(``);
    });

  return lines.join('\n');
}

/** Merge multiple project notices into one org-level notice */
export function generateOrgLegalNotice(projectNotices: { projectName: string; items: SbomNoticeItem[] }[]): string {
  const lines: string[] = [
    `THIRD-PARTY SOFTWARE NOTICES AND INFORMATION`,
    `Organization-level export`,
    `Generated: ${new Date().toLocaleDateString()}`,
    ``,
    `This document aggregates third-party notices for all projects.`,
    ``,
    `${'='.repeat(70)}`,
    ``,
  ];
  projectNotices.forEach(({ projectName, items }) => {
    if (items.length === 0) return;
    const fullNotice = generateLegalNotice(items, projectName);
    const contentLines = fullNotice.split('\n').slice(6); // skip header (first 6 lines)
    lines.push(`Project: ${projectName}`, ``);
    lines.push(...contentLines);
    lines.push(``);
  });
  return lines.join('\n');
}

/** Generate org-level CycloneDX SBOM with multiple components (one per project) */
export function generateOrgSBOM(projectSboms: { projectName: string; items: SbomNoticeItem[] }[]): string {
  const allComponents = projectSboms.flatMap(({ projectName, items }) =>
    items.map((item) => ({
      ...item,
      _projectName: projectName,
    }))
  );
  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'Deptex',
          name: 'Compliance Scanner',
          version: '1.0.0',
        },
      ],
      component: {
        type: 'application',
        name: 'Organization',
        version: '1.0.0',
      },
    },
    components: allComponents.map((item) => ({
      type: 'library',
      name: item.name,
      version: item.version,
      licenses: item.license
        ? [{ license: { id: item.license } }]
        : [],
      purl: `pkg:npm/${item.name}@${item.version}`,
    })),
  };
  return JSON.stringify(sbom, null, 2);
}

export function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
