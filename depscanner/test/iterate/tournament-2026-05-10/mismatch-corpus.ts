/**
 * 29-CVE source/sink-mismatch subsample drawn from the 2026-05-10 88-CVE
 * benchmark. Stratified across ecosystems to match the mismatch-failure
 * distribution (53 mismatch CVEs total → 29-CVE tournament sample).
 *
 * Selection rule: each CVE in this list has schema_pass=true,
 * pattern_compile_pass=true, fixture_pre_match=false in the v_base run at
 * runs/2026-05-10-marathon/v_base/2026-05-11T01-44-33/report.json.
 *
 *  npm   7   |  pypi 9   |  maven 7   |  golang 3   |  rubygems 3   =   29
 */

import type { Candidate } from '../candidates';
import { CANDIDATES } from '../candidates';

export const MISMATCH_CVE_IDS: string[] = [
  // npm (7)
  'CVE-2025-62718',
  'CVE-2026-40175',
  'CVE-2017-16137',
  'CVE-2022-25883',
  'CVE-2024-21484',
  'CVE-2024-28849',
  'CVE-2026-25639',
  // pypi (9)
  'CVE-2018-18074',
  'CVE-2023-32681',
  'CVE-2024-35195',
  'CVE-2023-43804',
  'CVE-2024-26130',
  'CVE-2024-22195',
  'CVE-2019-10906',
  'CVE-2022-22817',
  'CVE-2023-30861',
  // maven (7)
  'CVE-2017-7525',
  'CVE-2018-7489',
  'CVE-2021-44832',
  'CVE-2022-42889',
  'CVE-2022-22965',
  'CVE-2023-44483',
  'CVE-2023-26464',
  // golang (3)
  'CVE-2022-32149',
  'CVE-2024-28180',
  'CVE-2024-21626',
  // rubygems (3)
  'CVE-2022-23633',
  'CVE-2024-25126',
  'CVE-2024-32465',
];

export function getMismatchCandidates(): Candidate[] {
  const byId = new Map(CANDIDATES.map((c) => [c.cveId, c]));
  const out: Candidate[] = [];
  for (const id of MISMATCH_CVE_IDS) {
    const c = byId.get(id);
    if (!c) throw new Error(`mismatch CVE ${id} not in CANDIDATES — corpus drift`);
    out.push(c);
  }
  return out;
}
