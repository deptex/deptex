/**
 * Loads hand-authored Semgrep rules from `reachability-rules/` and exposes
 * them as ecosystem-matched few-shot examples for the rule-generation prompt.
 *
 * The platform rules in `reachability-rules/<CVE-XXX>/` already passed both
 * fixture and patch round-trip validation when they were authored, so they're
 * the strongest available signal of "what a working rule looks like in this
 * codebase". Show 2-3 of these inline in the prompt so the AI mirrors the
 * style (taint mode, source/sink shape, sanitizer placement, metadata keys).
 *
 * Loaded once per process per directory and cached in module state — the
 * platform rules don't change at runtime.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

export interface FewShotExample {
  cveId: string;
  packageName: string;
  ecosystem: string;
  ruleYaml: string;
  vulnerableFixture: string;
  safeFixture: string;
  /** rule.yml LOC + vulnerable LOC + safe LOC — used to prefer compact
   *  examples when prompt budget is tight. */
  totalLoc: number;
}

const cache = new Map<string, FewShotExample[]>();

/** Test hook — production never calls this. */
export function clearFewShotCache(): void {
  cache.clear();
}

const FIXTURE_EXTENSIONS = ['js', 'ts', 'py', 'java', 'go', 'rb', 'php', 'rs', 'cs'];

function loadFromDisk(rulesDir: string): FewShotExample[] {
  if (!fs.existsSync(rulesDir)) return [];

  const examples: FewShotExample[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(rulesDir, { withFileTypes: true });
  } catch {
    return [];
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (!entry.name.startsWith('CVE-')) continue;

    const dirPath = path.join(rulesDir, entry.name);
    const rulePath = path.join(dirPath, 'rule.yml');
    const fixturesDir = path.join(dirPath, '__fixtures__');

    if (!fs.existsSync(rulePath) || !fs.existsSync(fixturesDir)) continue;

    let ruleYaml: string;
    try {
      ruleYaml = fs.readFileSync(rulePath, 'utf8');
    } catch {
      continue;
    }

    let parsed: unknown;
    try {
      parsed = yaml.load(ruleYaml);
    } catch {
      continue;
    }

    const doc = parsed as { rules?: unknown };
    if (!doc || typeof doc !== 'object' || !Array.isArray(doc.rules) || doc.rules.length !== 1) continue;
    const rule = doc.rules[0] as { metadata?: unknown };
    const meta = rule.metadata as { cve?: unknown; package?: unknown; ecosystem?: unknown } | undefined;
    if (!meta) continue;
    if (typeof meta.cve !== 'string' || typeof meta.package !== 'string' || typeof meta.ecosystem !== 'string') continue;

    const vulnerable = readFirstFixture(fixturesDir, 'vulnerable');
    const safe = readFirstFixture(fixturesDir, 'safe');
    if (vulnerable === null || safe === null) continue;

    examples.push({
      cveId: meta.cve,
      packageName: meta.package,
      ecosystem: meta.ecosystem,
      ruleYaml,
      vulnerableFixture: vulnerable,
      safeFixture: safe,
      totalLoc: countLines(ruleYaml) + countLines(vulnerable) + countLines(safe),
    });
  }

  return examples;
}

function readFirstFixture(fixturesDir: string, baseName: string): string | null {
  for (const ext of FIXTURE_EXTENSIONS) {
    const p = path.join(fixturesDir, `${baseName}.${ext}`);
    if (fs.existsSync(p)) {
      try {
        return fs.readFileSync(p, 'utf8');
      } catch {
        return null;
      }
    }
  }
  return null;
}

function countLines(s: string): number {
  if (!s) return 0;
  return s.split('\n').length;
}

/**
 * Returns up to `k` few-shot examples, preferring the requested `ecosystem`
 * and within that bucket preferring smaller examples (LOC ascending). Falls
 * back to other ecosystems if the target ecosystem yields fewer than `k`.
 *
 * Caches the directory scan in module state — call `clearFewShotCache()` in
 * tests to force re-read.
 */
export function loadFewShotExamples(rulesDir: string, ecosystem: string, k = 3): FewShotExample[] {
  let entries = cache.get(rulesDir);
  if (!entries) {
    entries = loadFromDisk(rulesDir);
    cache.set(rulesDir, entries);
  }

  if (entries.length === 0 || k <= 0) return [];

  const eco = ecosystem.trim().toLowerCase();
  const sortedByLoc = (xs: FewShotExample[]): FewShotExample[] =>
    xs.slice().sort((a, b) => a.totalLoc - b.totalLoc);

  const matched = sortedByLoc(entries.filter((e) => e.ecosystem.toLowerCase() === eco));
  if (matched.length >= k) return matched.slice(0, k);

  const others = sortedByLoc(entries.filter((e) => e.ecosystem.toLowerCase() !== eco));
  return [...matched, ...others].slice(0, k);
}
