/**
 * Disk-backed cache for OSV advisories + GitHub patch info. Generation
 * iteration burns through dozens of variants; without caching, every run
 * re-fetches OSV and GitHub commits and immediately starves the 5000/hr PAT
 * budget. With caching, each CVE pays the network cost exactly once.
 *
 * Cache layout: test/iterate/cache/<CVE>.json
 *   { advisory, patchInfo, affectedRange }
 *
 * Manual eviction: just delete the file. Programmatic eviction is intentionally
 * absent — OSV/GitHub data is stable enough that staleness is not a concern
 * within an iteration day.
 */

import * as fs from 'fs';
import * as path from 'path';
import { fetchOsvAdvisory, extractFixCommits, summarizeAffectedRange, type OsvAdvisory } from '../../src/rule-generator/osv-fetch';
import { fetchPatchInfo, type PatchInfo } from '../../src/rule-generator/patch-fetch';
import type { Candidate } from './candidates';

const CACHE_DIR = path.join(__dirname, 'cache');

export interface CachedCveData {
  cveId: string;
  status: 'ok' | 'no_advisory' | 'no_fix_commit' | 'fetch_failed';
  advisory: OsvAdvisory | null;
  patchInfo: PatchInfo | null;
  affectedRange?: string;
  error?: string;
}

function ensureDir(): void {
  if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
}

function cacheFile(cveId: string): string {
  return path.join(CACHE_DIR, `${cveId}.json`);
}

export function readCache(cveId: string): CachedCveData | null {
  const f = cacheFile(cveId);
  if (!fs.existsSync(f)) return null;
  try {
    return JSON.parse(fs.readFileSync(f, 'utf8')) as CachedCveData;
  } catch {
    return null;
  }
}

function writeCache(data: CachedCveData): void {
  ensureDir();
  fs.writeFileSync(cacheFile(data.cveId), JSON.stringify(data, null, 2), 'utf8');
}

export async function fetchAndCache(c: Candidate, githubToken?: string): Promise<CachedCveData> {
  const cached = readCache(c.cveId);
  if (cached) return cached;

  const result: CachedCveData = {
    cveId: c.cveId,
    status: 'ok',
    advisory: null,
    patchInfo: null,
  };

  let advisory: OsvAdvisory | null = null;
  try {
    advisory = await fetchOsvAdvisory(c.cveId);
  } catch (err) {
    result.status = 'fetch_failed';
    result.error = err instanceof Error ? err.message : String(err);
    writeCache(result);
    return result;
  }
  if (!advisory) {
    result.status = 'no_advisory';
    writeCache(result);
    return result;
  }
  result.advisory = advisory;
  result.affectedRange = summarizeAffectedRange(advisory, c.packageName);

  const fc = extractFixCommits(advisory)[0];
  if (!fc) {
    result.status = 'no_fix_commit';
    writeCache(result);
    return result;
  }

  try {
    result.patchInfo = await fetchPatchInfo(fc, { githubToken });
  } catch (err) {
    result.status = 'fetch_failed';
    result.error = err instanceof Error ? err.message : String(err);
    writeCache(result);
    return result;
  }

  writeCache(result);
  return result;
}

export async function prefetchAll(candidates: Candidate[], githubToken?: string): Promise<CachedCveData[]> {
  const out: CachedCveData[] = [];
  for (const c of candidates) {
    out.push(await fetchAndCache(c, githubToken));
  }
  return out;
}
