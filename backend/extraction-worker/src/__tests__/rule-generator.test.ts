import {
  extractFixCommits,
  parseGithubCommitUrl,
  summarizeAffectedRange,
  type OsvAdvisory,
} from '../rule-generator/osv-fetch';
import {
  buildGenerationPrompt,
  semgrepLanguageFor,
  getPromptVersion,
} from '../rule-generator/prompt-builder';
import {
  parseAndValidate,
  GeneratedPayloadSchema,
  estimateCostUsd,
  GenerationError,
} from '../rule-generator/generate';

describe('osv-fetch helpers', () => {
  describe('parseGithubCommitUrl', () => {
    it('parses canonical commit URL', () => {
      const c = parseGithubCommitUrl('https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c');
      expect(c).toEqual({
        url: 'https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c',
        owner: 'lodash',
        repo: 'lodash',
        sha: '3469357cff396a26c363f8c1b5a91dde28ba4b1c',
      });
    });

    it('strips trailing .git from repo segment', () => {
      const c = parseGithubCommitUrl('https://github.com/owner/repo.git/commit/abc1234');
      expect(c?.repo).toBe('repo');
    });

    it('rejects non-github URLs', () => {
      expect(parseGithubCommitUrl('https://gitlab.com/x/y/-/commit/abc1234')).toBeNull();
      expect(parseGithubCommitUrl('https://example.com/whatever')).toBeNull();
      expect(parseGithubCommitUrl('')).toBeNull();
    });

    it('lowercases SHA', () => {
      const c = parseGithubCommitUrl('https://github.com/x/y/commit/ABC1234');
      expect(c?.sha).toBe('abc1234');
    });
  });

  describe('extractFixCommits', () => {
    const advisory: OsvAdvisory = {
      id: 'CVE-2021-23337',
      aliases: [],
      summary: '',
      details: '',
      affected: [],
      references: [
        { type: 'WEB', url: 'https://example.com/blog' },
        { type: 'WEB', url: 'https://github.com/lodash/lodash/commit/aaaaaaa1111' },
        { type: 'FIX', url: 'https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c' },
        { type: 'FIX', url: 'https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c' }, // dup
      ],
    };

    it('prefers FIX-typed refs first, then deduplicates', () => {
      const commits = extractFixCommits(advisory);
      expect(commits.length).toBe(2);
      // FIX commit must come first
      expect(commits[0].sha).toBe('3469357cff396a26c363f8c1b5a91dde28ba4b1c');
      // Then the WEB-typed commit URL
      expect(commits[1].sha).toBe('aaaaaaa1111');
    });

    it('returns empty when no commit refs', () => {
      const empty: OsvAdvisory = { ...advisory, references: [{ type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337' }] };
      expect(extractFixCommits(empty)).toEqual([]);
    });

    it('falls back to affected[].ranges[] of type GIT when references have no commit URL', () => {
      // Real-world shape from OSV CVE-2021-23337 — references contain no
      // github.com commit URLs (only oracle/siemens/blob URLs), but the
      // affected GIT range carries the fix SHAs.
      const advisory: OsvAdvisory = {
        id: 'CVE-2021-23337',
        aliases: [],
        summary: '',
        details: '',
        references: [
          { type: 'WEB', url: 'https://github.com/lodash/lodash/blob/abcdef/lodash.js#L1' },
          { type: 'FIX', url: 'https://www.oracle.com/security-alerts/cpujul2021.html' },
        ],
        affected: [
          {
            ranges: [
              {
                type: 'GIT',
                repo: 'https://github.com/lodash/lodash',
                events: [
                  { introduced: '0' },
                  { fixed: 'c6e281b878b315c7a10d90f9c2af4cdb112d9625' },
                  { introduced: '0' },
                  { fixed: '506f585d78d236075f5d47b240518f3e1fdf5811' },
                ],
              },
            ],
          },
        ],
      };
      const commits = extractFixCommits(advisory);
      expect(commits.length).toBe(2);
      expect(commits[0].owner).toBe('lodash');
      expect(commits[0].repo).toBe('lodash');
      expect(commits[0].sha).toBe('c6e281b878b315c7a10d90f9c2af4cdb112d9625');
      expect(commits[1].sha).toBe('506f585d78d236075f5d47b240518f3e1fdf5811');
    });

    it('explicit FIX references still rank ahead of GIT-range SHAs', () => {
      const advisory: OsvAdvisory = {
        id: 'X', aliases: [], summary: '', details: '',
        references: [
          { type: 'FIX', url: 'https://github.com/owner/repo/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
        ],
        affected: [
          {
            ranges: [
              {
                type: 'GIT',
                repo: 'https://github.com/owner/repo',
                events: [{ introduced: '0' }, { fixed: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }],
              },
            ],
          },
        ],
      };
      const commits = extractFixCommits(advisory);
      expect(commits.length).toBe(2);
      expect(commits[0].sha).toBe('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      expect(commits[1].sha).toBe('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
    });

    it('skips non-github GIT range repos and malformed SHAs', () => {
      const advisory: OsvAdvisory = {
        id: 'X', aliases: [], summary: '', details: '',
        references: [],
        affected: [
          {
            ranges: [
              { type: 'GIT', repo: 'https://gitlab.com/x/y', events: [{ fixed: 'aaaaaaa' }] },
              { type: 'GIT', repo: 'https://github.com/x/y', events: [{ fixed: 'not-a-sha' }] },
              { type: 'SEMVER', events: [{ fixed: '1.0.0' }] },
            ],
          },
        ],
      };
      expect(extractFixCommits(advisory)).toEqual([]);
    });
  });

  describe('summarizeAffectedRange', () => {
    it('returns <fixed when introduced is 0', () => {
      const a: OsvAdvisory = {
        id: 'X', aliases: [], summary: '', details: '', references: [],
        affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
      };
      expect(summarizeAffectedRange(a, 'lodash')).toBe('<4.17.21');
    });

    it('returns range when both introduced and fixed are real', () => {
      const a: OsvAdvisory = {
        id: 'X', aliases: [], summary: '', details: '', references: [],
        affected: [{ package: { name: 'pkg', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '1.0.0' }, { fixed: '1.2.3' }] }] }],
      };
      expect(summarizeAffectedRange(a, 'pkg')).toBe('>=1.0.0 <1.2.3');
    });

    it('case-insensitive package name match', () => {
      const a: OsvAdvisory = {
        id: 'X', aliases: [], summary: '', details: '', references: [],
        affected: [{ package: { name: 'Lodash', ecosystem: 'npm' }, ranges: [{ events: [{ fixed: '1.0.0' }] }] }],
      };
      expect(summarizeAffectedRange(a, 'lodash')).toBe('<1.0.0');
    });

    it('returns undefined when package not in advisory', () => {
      const a: OsvAdvisory = {
        id: 'X', aliases: [], summary: '', details: '', references: [],
        affected: [{ package: { name: 'other', ecosystem: 'npm' }, ranges: [] }],
      };
      expect(summarizeAffectedRange(a, 'lodash')).toBeUndefined();
    });
  });
});

describe('prompt-builder', () => {
  it('semgrepLanguageFor maps known ecosystems', () => {
    expect(semgrepLanguageFor('npm')).toBe('javascript');
    expect(semgrepLanguageFor('pypi')).toBe('python');
    expect(semgrepLanguageFor('maven')).toBe('java');
    expect(semgrepLanguageFor('golang')).toBe('go');
    expect(semgrepLanguageFor('rubygems')).toBe('ruby');
    expect(semgrepLanguageFor('packagist')).toBe('php');
    expect(semgrepLanguageFor('cargo')).toBe('rust');
    expect(semgrepLanguageFor('nuget')).toBe('csharp');
  });

  it('semgrepLanguageFor falls back to generic for unknown', () => {
    expect(semgrepLanguageFor('cocoapods')).toBe('generic');
  });

  it('case-insensitive ecosystem match', () => {
    expect(semgrepLanguageFor('NPM')).toBe('javascript');
  });

  it('builds a prompt mentioning the CVE, package, and chosen language', () => {
    const prompt = buildGenerationPrompt({
      cveId: 'CVE-2021-23337',
      packagePurl: 'pkg:npm/lodash@4.17.20',
      packageName: 'lodash',
      ecosystem: 'npm',
      affectedVersionRange: '<4.17.21',
      osvSummary: 'Command injection in template',
      osvDetails: 'Lodash <4.17.21 allows command injection via _.template when supplied user input',
      patchDiff: 'diff --git a/lodash.js b/lodash.js\n@@ -1 +1 @@\n- old\n+ new',
      changedFiles: [],
    });
    expect(prompt).toContain('CVE-2021-23337');
    expect(prompt).toContain('lodash');
    expect(prompt).toContain('languages: [javascript]');
    expect(prompt).toContain('<4.17.21');
    expect(prompt).toContain('rule_yaml');
    expect(prompt).toContain('PUBLIC_UNAUTH');
    expect(prompt).toContain('vulnerable_fixture');
  });

  it('getPromptVersion is non-empty', () => {
    expect(getPromptVersion()).toMatch(/^rulegen-v\d+/);
  });

  it('omits the few-shot section when no examples provided', () => {
    const prompt = buildGenerationPrompt({
      cveId: 'CVE-2021-23337',
      packagePurl: 'pkg:npm/lodash@4.17.20',
      packageName: 'lodash',
      ecosystem: 'npm',
      osvSummary: '',
      osvDetails: '',
      patchDiff: '',
      changedFiles: [],
    });
    expect(prompt).not.toContain('Reference rules that previously validated');
  });

  it('renders few-shot examples under a clear section header', () => {
    const prompt = buildGenerationPrompt({
      cveId: 'CVE-2099-NEW',
      packagePurl: 'pkg:npm/widget@1.0.0',
      packageName: 'widget',
      ecosystem: 'npm',
      osvSummary: 'something bad',
      osvDetails: '',
      patchDiff: '',
      changedFiles: [],
      fewShotExamples: [
        {
          cveId: 'CVE-2021-23337',
          packageName: 'lodash',
          ecosystem: 'npm',
          ruleYaml: 'rules:\n  - id: deptex.lodash.template\n    languages: [javascript]',
          vulnerableFixture: '_.template(req.body.x)',
          safeFixture: '_.template("static")',
          totalLoc: 4,
        },
      ],
    });
    expect(prompt).toContain('# Reference rules that previously validated');
    expect(prompt).toContain('CVE-2021-23337');
    expect(prompt).toContain('deptex.lodash.template');
    expect(prompt).toContain('_.template(req.body.x)');
    expect(prompt).toContain('_.template("static")');
    // Must come BEFORE "Your task" so the AI reads the examples first.
    expect(prompt.indexOf('# Reference rules that previously validated'))
      .toBeLessThan(prompt.indexOf('# Your task'));
  });
});

describe('generate.parseAndValidate', () => {
  const validPayload = {
    rule_yaml: 'rules:\n  - id: deptex.lodash.template-injection\n    languages: [javascript]\n    severity: ERROR\n    mode: taint\n    metadata:\n      cve: CVE-2021-23337\n      package: lodash\n      ecosystem: npm\n    pattern-sources:\n      - pattern: $REQ.body\n    pattern-sinks:\n      - pattern: _.template($X)',
    vulnerable_fixture: "const _ = require('lodash');\nfunction h(req){_.template(req.body.tpl)}",
    safe_fixture: "const _ = require('lodash');\nfunction h(){_.template('static')}",
    reachability_level: 'confirmed',
    entry_point_class: 'PUBLIC_UNAUTH',
    rationale: 'taint flow from req.body to _.template',
  };

  it('parses a valid raw JSON response', () => {
    const raw = JSON.stringify(validPayload);
    const out = parseAndValidate(raw);
    expect(out.reachability_level).toBe('confirmed');
    expect(out.entry_point_class).toBe('PUBLIC_UNAUTH');
  });

  it('parses JSON wrapped in a markdown code fence', () => {
    const raw = '```json\n' + JSON.stringify(validPayload) + '\n```';
    const out = parseAndValidate(raw);
    expect(out.rule_yaml).toContain('deptex.lodash.template-injection');
  });

  it('extracts JSON when provider leaks trailing prose', () => {
    const raw = `Here is the rule:\n${JSON.stringify(validPayload)}\nLet me know if you need changes.`;
    const out = parseAndValidate(raw);
    expect(out.vulnerable_fixture).toContain('req.body.tpl');
  });

  it('throws GenerationError(parse_failed) on no JSON', () => {
    expect(() => parseAndValidate('I cannot help with that')).toThrow(GenerationError);
  });

  it('throws GenerationError(invalid_schema) on missing field', () => {
    const bad = { ...validPayload };
    delete (bad as any).rule_yaml;
    expect(() => parseAndValidate(JSON.stringify(bad))).toThrow(GenerationError);
  });

  it('throws GenerationError(invalid_schema) on unknown reachability_level', () => {
    const bad = { ...validPayload, reachability_level: 'module' };
    expect(() => parseAndValidate(JSON.stringify(bad))).toThrow(GenerationError);
  });

  it('throws GenerationError(invalid_schema) on unknown entry_point_class', () => {
    const bad = { ...validPayload, entry_point_class: 'INTERNAL' };
    expect(() => parseAndValidate(JSON.stringify(bad))).toThrow(GenerationError);
  });
});

describe('generate.estimateCostUsd', () => {
  it('uses Anthropic sonnet pricing for known model', () => {
    // 1k input @ $3/M = $0.003, 500 output @ $15/M = $0.0075. Total $0.0105.
    const cost = estimateCostUsd('claude-sonnet-4-6', 1000, 500);
    expect(cost).toBeCloseTo(0.0105, 6);
  });

  it('falls back to default pricing for unknown model', () => {
    const cost = estimateCostUsd('mystery-model-9000', 1000, 1000);
    // FALLBACK: input $1/M, output $5/M = $0.001 + $0.005 = $0.006
    expect(cost).toBeCloseTo(0.006, 6);
  });

  it('zero tokens returns zero', () => {
    expect(estimateCostUsd('gpt-4o', 0, 0)).toBe(0);
  });
});

describe('GeneratedPayloadSchema', () => {
  it('rejects too-short rule_yaml', () => {
    const r = GeneratedPayloadSchema.safeParse({
      rule_yaml: 'too short',
      vulnerable_fixture: 'function h(){_.template(req.body)}',
      safe_fixture: 'function h(){_.template("k")}',
      reachability_level: 'confirmed',
      entry_point_class: 'PUBLIC_UNAUTH',
    });
    expect(r.success).toBe(false);
  });

  it('accepts payload without rationale (defaulted to empty string)', () => {
    const r = GeneratedPayloadSchema.safeParse({
      rule_yaml: 'rules:\n  - id: x\n    languages: [js]\n    severity: ERROR\n    pattern: foo',
      vulnerable_fixture: 'function h(){_.template(req.body)}',
      safe_fixture: 'function h(){_.template("k")}',
      reachability_level: 'function',
      entry_point_class: 'AUTH_INTERNAL',
    });
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.rationale).toBe('');
  });
});
