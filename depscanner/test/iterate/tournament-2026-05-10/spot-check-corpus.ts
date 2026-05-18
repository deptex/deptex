/**
 * 10-CVE spot-check corpus — CVEs that v_base PASSED in the 2026-05-10
 * benchmark. Used to verify the tournament winner doesn't regress the
 * existing 33% baseline.
 *
 *   npm  6  |  pypi 3  |  rubygems 1  =  10
 *
 * If a variant regresses ≥2 of these (pass rate < 80%) we reject it and
 * pick the next-best non-regressing one.
 */

import type { Candidate } from '../candidates';
import { CANDIDATES } from '../candidates';

export const SPOT_CHECK_CVE_IDS: string[] = [
  // npm (6) — diverse vuln classes that v_base handles
  'CVE-2026-4800',
  'CVE-2020-28500',
  'CVE-2022-23540',
  'CVE-2022-3517',
  'CVE-2024-11831',
  'CVE-2021-23337',
  // pypi (3)
  'CVE-2020-14343',
  'CVE-2017-18342',
  'CVE-2022-29217',
  // rubygems (1)
  'CVE-2024-26143',
];

export function getSpotCheckCandidates(): Candidate[] {
  const byId = new Map(CANDIDATES.map((c) => [c.cveId, c]));
  const out: Candidate[] = [];
  for (const id of SPOT_CHECK_CVE_IDS) {
    const c = byId.get(id);
    if (!c) throw new Error(`spot-check CVE ${id} not in CANDIDATES`);
    out.push(c);
  }
  return out;
}
