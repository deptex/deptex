/**
 * Stable corpus of 18 CVE candidates from the test-npm fixture, exactly as
 * surfaced by the Phase 5d full-pipeline run. Each entry is the input
 * generateRuleForCve consumes from the rule-generation step.
 *
 * Hardcoded so prompt-iteration runs are deterministic — the upstream OSV
 * data and GitHub patches change rarely but cache.ts pins them on first
 * fetch anyway.
 */

export interface Candidate {
  cveId: string;
  packageName: string;
  packagePurl: string;
  ecosystem: string;
}

export const CANDIDATES: Candidate[] = [
  { cveId: 'CVE-2025-62718', packageName: 'axios', packagePurl: 'pkg:npm/axios@0.21.1', ecosystem: 'npm' },
  { cveId: 'CVE-2026-40175', packageName: 'axios', packagePurl: 'pkg:npm/axios@0.21.1', ecosystem: 'npm' },
  { cveId: 'CVE-2026-4800', packageName: 'lodash', packagePurl: 'pkg:npm/lodash@4.17.20', ecosystem: 'npm' },
  { cveId: 'CVE-2020-28500', packageName: 'lodash', packagePurl: 'pkg:npm/lodash@4.17.20', ecosystem: 'npm' },
  { cveId: 'CVE-2022-23539', packageName: 'jsonwebtoken', packagePurl: 'pkg:npm/jsonwebtoken@8.5.1', ecosystem: 'npm' },
  { cveId: 'CVE-2022-23540', packageName: 'jsonwebtoken', packagePurl: 'pkg:npm/jsonwebtoken@8.5.1', ecosystem: 'npm' },
  { cveId: 'CVE-2022-23541', packageName: 'jsonwebtoken', packagePurl: 'pkg:npm/jsonwebtoken@8.5.1', ecosystem: 'npm' },
  { cveId: 'CVE-2022-3517', packageName: 'minimatch', packagePurl: 'pkg:npm/minimatch@3.0.4', ecosystem: 'npm' },
  { cveId: 'CVE-2024-11831', packageName: 'serialize-javascript', packagePurl: 'pkg:npm/serialize-javascript@6.0.0', ecosystem: 'npm' },
  { cveId: 'CVE-2024-55565', packageName: 'nanoid', packagePurl: 'pkg:npm/nanoid@3.2.0', ecosystem: 'npm' },
  { cveId: 'CVE-2025-13465', packageName: 'lodash', packagePurl: 'pkg:npm/lodash@4.17.20', ecosystem: 'npm' },
  { cveId: 'CVE-2025-27152', packageName: 'axios', packagePurl: 'pkg:npm/axios@0.21.1', ecosystem: 'npm' },
  { cveId: 'CVE-2025-64718', packageName: 'js-yaml', packagePurl: 'pkg:npm/js-yaml@4.1.0', ecosystem: 'npm' },
  { cveId: 'CVE-2026-25639', packageName: 'axios', packagePurl: 'pkg:npm/axios@0.21.1', ecosystem: 'npm' },
  { cveId: 'CVE-2026-26996', packageName: 'minimatch', packagePurl: 'pkg:npm/minimatch@3.0.4', ecosystem: 'npm' },
  { cveId: 'CVE-2026-27903', packageName: 'minimatch', packagePurl: 'pkg:npm/minimatch@3.0.4', ecosystem: 'npm' },
  { cveId: 'CVE-2026-27904', packageName: 'minimatch', packagePurl: 'pkg:npm/minimatch@3.0.4', ecosystem: 'npm' },
  { cveId: 'CVE-2026-34043', packageName: 'serialize-javascript', packagePurl: 'pkg:npm/serialize-javascript@6.0.0', ecosystem: 'npm' },
];
