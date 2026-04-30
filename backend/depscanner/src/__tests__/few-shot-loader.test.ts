/**
 * Unit tests for the few-shot example loader. Builds a synthetic rules
 * directory in os.tmpdir() per test so we can exercise ecosystem matching,
 * LOC sorting, and edge cases (missing fixtures, bad YAML) deterministically.
 *
 * The loader caches by directory path; clearFewShotCache() runs in beforeEach.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  loadFewShotExamples,
  clearFewShotCache,
  type FewShotExample,
} from '../rule-generator/few-shot-loader';

interface SyntheticRule {
  cveId: string;
  packageName: string;
  ecosystem: string;
  fixtureExt: string;
  // pad lines into both fixtures to make total LOC predictable
  padLines: number;
}

function makeRulesDir(rules: SyntheticRule[]): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fewshot-test-'));
  for (const r of rules) {
    const cveDir = path.join(dir, r.cveId);
    fs.mkdirSync(cveDir, { recursive: true });
    const ruleYaml = [
      'rules:',
      `  - id: deptex.${r.packageName}.example`,
      '    languages: [javascript]',
      '    severity: ERROR',
      '    mode: taint',
      `    message: example rule for ${r.cveId}`,
      '    metadata:',
      `      cve: ${r.cveId}`,
      `      package: ${r.packageName}`,
      `      ecosystem: ${r.ecosystem}`,
      '    pattern-sources:',
      '      - pattern: $REQ.body',
      '    pattern-sinks:',
      '      - pattern: dangerous($X)',
      '',
    ].join('\n');
    fs.writeFileSync(path.join(cveDir, 'rule.yml'), ruleYaml, 'utf8');

    const fixturesDir = path.join(cveDir, '__fixtures__');
    fs.mkdirSync(fixturesDir, { recursive: true });
    const padding = Array.from({ length: r.padLines }, (_, i) => `// pad ${i}`).join('\n');
    fs.writeFileSync(
      path.join(fixturesDir, `vulnerable.${r.fixtureExt}`),
      `// vulnerable\ndangerous(req.body.x);\n${padding}`,
      'utf8',
    );
    fs.writeFileSync(
      path.join(fixturesDir, `safe.${r.fixtureExt}`),
      `// safe\ndangerous("static");\n${padding}`,
      'utf8',
    );
  }
  return dir;
}

function pickIds(examples: FewShotExample[]): string[] {
  return examples.map((e) => e.cveId);
}

beforeEach(() => {
  clearFewShotCache();
});

describe('loadFewShotExamples', () => {
  it('returns empty array when rulesDir does not exist', () => {
    const got = loadFewShotExamples(path.join(os.tmpdir(), 'definitely-not-there-xyz-1234'), 'npm', 3);
    expect(got).toEqual([]);
  });

  it('prefers ecosystem-matched rules over others', () => {
    const dir = makeRulesDir([
      { cveId: 'CVE-2000-A', packageName: 'a', ecosystem: 'npm', fixtureExt: 'js', padLines: 2 },
      { cveId: 'CVE-2000-B', packageName: 'b', ecosystem: 'pypi', fixtureExt: 'py', padLines: 2 },
      { cveId: 'CVE-2000-C', packageName: 'c', ecosystem: 'npm', fixtureExt: 'js', padLines: 2 },
      { cveId: 'CVE-2000-D', packageName: 'd', ecosystem: 'maven', fixtureExt: 'java', padLines: 2 },
    ]);
    const got = loadFewShotExamples(dir, 'npm', 2);
    const ids = pickIds(got);
    expect(ids).toHaveLength(2);
    expect(ids.sort()).toEqual(['CVE-2000-A', 'CVE-2000-C']);
    for (const ex of got) {
      expect(ex.ecosystem).toBe('npm');
    }
  });

  it('falls back to other-ecosystem rules when target ecosystem has fewer than k matches', () => {
    const dir = makeRulesDir([
      { cveId: 'CVE-2001-A', packageName: 'a', ecosystem: 'npm', fixtureExt: 'js', padLines: 1 },
      { cveId: 'CVE-2001-B', packageName: 'b', ecosystem: 'pypi', fixtureExt: 'py', padLines: 1 },
      { cveId: 'CVE-2001-C', packageName: 'c', ecosystem: 'maven', fixtureExt: 'java', padLines: 1 },
    ]);
    const got = loadFewShotExamples(dir, 'npm', 3);
    expect(got).toHaveLength(3);
    // First slot must be the npm rule.
    expect(got[0].cveId).toBe('CVE-2001-A');
    expect(got[0].ecosystem).toBe('npm');
    // Remaining two are filled from other ecosystems (no order constraint
    // beyond LOC; both have equal LOC here so we just check the set).
    expect(pickIds(got.slice(1)).sort()).toEqual(['CVE-2001-B', 'CVE-2001-C']);
  });

  it('sorts within ecosystem by total LOC ascending', () => {
    const dir = makeRulesDir([
      { cveId: 'CVE-2002-BIG', packageName: 'big', ecosystem: 'npm', fixtureExt: 'js', padLines: 100 },
      { cveId: 'CVE-2002-SMALL', packageName: 'small', ecosystem: 'npm', fixtureExt: 'js', padLines: 0 },
      { cveId: 'CVE-2002-MID', packageName: 'mid', ecosystem: 'npm', fixtureExt: 'js', padLines: 20 },
    ]);
    const got = loadFewShotExamples(dir, 'npm', 3);
    expect(pickIds(got)).toEqual(['CVE-2002-SMALL', 'CVE-2002-MID', 'CVE-2002-BIG']);
    expect(got[0].totalLoc).toBeLessThan(got[1].totalLoc);
    expect(got[1].totalLoc).toBeLessThan(got[2].totalLoc);
  });

  it('caches by rulesDir and does not re-read after first call', () => {
    const dir = makeRulesDir([
      { cveId: 'CVE-2003-A', packageName: 'a', ecosystem: 'npm', fixtureExt: 'js', padLines: 1 },
    ]);
    const first = loadFewShotExamples(dir, 'npm', 3);
    expect(first).toHaveLength(1);

    // Mutate the rules dir behind the loader's back. Without cache, the next
    // call would now see an empty dir.
    fs.rmSync(path.join(dir, 'CVE-2003-A'), { recursive: true, force: true });

    const second = loadFewShotExamples(dir, 'npm', 3);
    expect(second).toHaveLength(1);
    expect(second[0].cveId).toBe('CVE-2003-A');

    // After explicit clear, the next read picks up the deletion.
    clearFewShotCache();
    const third = loadFewShotExamples(dir, 'npm', 3);
    expect(third).toEqual([]);
  });

  it('skips CVE folders missing rule.yml or fixtures', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fewshot-broken-'));
    // Folder with rule.yml but no fixtures
    const noFixDir = path.join(dir, 'CVE-2004-NO-FIX');
    fs.mkdirSync(noFixDir);
    fs.writeFileSync(path.join(noFixDir, 'rule.yml'), 'rules:\n  - id: x\n    metadata:\n      cve: CVE-2004-NO-FIX\n      package: x\n      ecosystem: npm', 'utf8');
    // Folder with fixtures but no rule.yml
    const noRuleDir = path.join(dir, 'CVE-2004-NO-RULE');
    fs.mkdirSync(path.join(noRuleDir, '__fixtures__'), { recursive: true });
    fs.writeFileSync(path.join(noRuleDir, '__fixtures__', 'vulnerable.js'), '// v', 'utf8');
    fs.writeFileSync(path.join(noRuleDir, '__fixtures__', 'safe.js'), '// s', 'utf8');
    // Folder with broken YAML
    const badYamlDir = path.join(dir, 'CVE-2004-BAD-YAML');
    fs.mkdirSync(path.join(badYamlDir, '__fixtures__'), { recursive: true });
    fs.writeFileSync(path.join(badYamlDir, 'rule.yml'), 'this: is\n  not: valid\n yaml: [', 'utf8');
    fs.writeFileSync(path.join(badYamlDir, '__fixtures__', 'vulnerable.js'), '// v', 'utf8');
    fs.writeFileSync(path.join(badYamlDir, '__fixtures__', 'safe.js'), '// s', 'utf8');

    const got = loadFewShotExamples(dir, 'npm', 5);
    expect(got).toEqual([]);
  });

  it('returns rule_yaml + vulnerable + safe fixture content verbatim', () => {
    const dir = makeRulesDir([
      { cveId: 'CVE-2005-A', packageName: 'pkg', ecosystem: 'npm', fixtureExt: 'js', padLines: 0 },
    ]);
    const got = loadFewShotExamples(dir, 'npm', 1);
    expect(got).toHaveLength(1);
    const ex = got[0];
    expect(ex.cveId).toBe('CVE-2005-A');
    expect(ex.packageName).toBe('pkg');
    expect(ex.ecosystem).toBe('npm');
    expect(ex.ruleYaml).toContain('id: deptex.pkg.example');
    expect(ex.vulnerableFixture).toContain('dangerous(req.body.x)');
    expect(ex.safeFixture).toContain('dangerous("static")');
    expect(ex.totalLoc).toBeGreaterThan(0);
  });

  it('returns empty when k = 0', () => {
    const dir = makeRulesDir([
      { cveId: 'CVE-2006-A', packageName: 'a', ecosystem: 'npm', fixtureExt: 'js', padLines: 1 },
    ]);
    expect(loadFewShotExamples(dir, 'npm', 0)).toEqual([]);
  });
});
