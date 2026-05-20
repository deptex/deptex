/**
 * Transitive resolver pure-parsing tests.
 *
 * The resolvers shell out to `go list` / `pip` / `pipdeptree`, but the
 * stdout-parsing functions are pure and exported for direct unit test.
 * Real subprocess invocations are covered by Docker integration tests
 * (out of scope for jest — those need `go` + `pip` on PATH).
 *
 * Tests pin:
 *   - parseGoListJsonStream: stream of newline-separated JSON records
 *     including pretty-printed multi-line objects, malformed chunks,
 *     replace directives, main-module exclusion.
 *   - parsePipDryRunReport: pip's --report=- JSON shape extraction +
 *     metadata flattening.
 *   - parsePipdeptreeJson: package + dependencies → deps + relationships.
 */

import {
  parseGoListJsonStream,
} from '../transitive-resolvers/go';
import {
  parsePipDryRunReport,
  parsePipdeptreeJson,
} from '../transitive-resolvers/pypi';

describe('parseGoListJsonStream', () => {
  it('parses a stream of pretty-printed module records', () => {
    const stdout = `{
  "Path": "example.com/myapp",
  "Main": true,
  "Dir": "/tmp/myapp",
  "GoMod": "/tmp/myapp/go.mod",
  "GoVersion": "1.22"
}
{
  "Path": "github.com/spf13/cobra",
  "Version": "v1.8.0",
  "Time": "2024-01-15T10:00:00Z"
}
{
  "Path": "github.com/spf13/viper",
  "Version": "v1.18.2"
}
`;
    const records = parseGoListJsonStream(stdout);
    expect(records).toHaveLength(3);
    expect(records[0]).toMatchObject({ Path: 'example.com/myapp', Main: true });
    expect(records[1]).toMatchObject({ Path: 'github.com/spf13/cobra', Version: 'v1.8.0' });
    expect(records[2]).toMatchObject({ Path: 'github.com/spf13/viper', Version: 'v1.18.2' });
  });

  it('returns an empty array for empty stdout', () => {
    expect(parseGoListJsonStream('')).toEqual([]);
  });

  it('skips malformed chunks without crashing the whole parse', () => {
    const stdout = `{
  "Path": "good.com/one",
  "Version": "v1.0.0"
}
{
  "Path": "broken.com/two",
  "Version":
}
{
  "Path": "good.com/three",
  "Version": "v3.0.0"
}
`;
    const records = parseGoListJsonStream(stdout);
    // Middle (broken) record drops; first + third survive.
    expect(records).toHaveLength(2);
    expect(records[0].Path).toBe('good.com/one');
    expect(records[1].Path).toBe('good.com/three');
  });

  it('handles nested JSON objects inside a record', () => {
    // Replace directives nest a second module record inside.
    const stdout = `{
  "Path": "example.com/old",
  "Version": "v1.0.0",
  "Replace": {
    "Path": "example.com/new",
    "Version": "v2.0.0"
  }
}
`;
    const records = parseGoListJsonStream(stdout);
    expect(records).toHaveLength(1);
    expect(records[0].Replace).toMatchObject({ Path: 'example.com/new', Version: 'v2.0.0' });
  });
});

describe('parsePipDryRunReport', () => {
  it('extracts every install entry into a ParsedSbomDep', () => {
    const stdout = JSON.stringify({
      version: '1',
      pip_version: '23.0',
      install: [
        { metadata: { name: 'requests', version: '2.31.0' }, is_direct: true },
        { metadata: { name: 'urllib3', version: '2.0.7' }, is_direct: false },
        { metadata: { name: 'certifi', version: '2024.7.4' }, is_direct: false },
      ],
    });
    const result = parsePipDryRunReport(stdout, 'pip-dry-run-report');
    expect(result.deps).toHaveLength(3);
    expect(result.deps[0]).toMatchObject({
      name: 'requests',
      version: '2.31.0',
      is_direct: false, // resolver always emits transitives — the wire-in dedups
      source: 'transitive',
      devScoped: false,
    });
    expect(result.deps.map((d) => d.name)).toEqual(['requests', 'urllib3', 'certifi']);
    expect(result.rawModuleCount).toBe(3);
  });

  it('strips trailing pip warnings and finds the JSON block', () => {
    const stdout =
      'WARNING: PEP 668 environment detected\n' +
      JSON.stringify({ version: '1', install: [{ metadata: { name: 'flask', version: '3.0.0' } }] }) +
      '\n';
    const result = parsePipDryRunReport(stdout, 'pip-dry-run-report');
    expect(result.deps).toHaveLength(1);
    expect(result.deps[0].name).toBe('flask');
  });

  it('throws when no JSON object is found', () => {
    expect(() => parsePipDryRunReport('ERROR: nothing to install', 'pip-dry-run-report'))
      .toThrow(/no JSON/);
  });

  it('skips entries missing name or version', () => {
    const stdout = JSON.stringify({
      install: [
        { metadata: { name: 'good', version: '1.0.0' } },
        { metadata: { name: 'no-version' } },
        { metadata: { version: '1.0.0' } },
        { metadata: {} },
      ],
    });
    const result = parsePipDryRunReport(stdout, 'pip-dry-run-report');
    expect(result.deps).toHaveLength(1);
    expect(result.deps[0].name).toBe('good');
  });
});

describe('parsePipdeptreeJson', () => {
  it('emits one ParsedSbomDep per package + relationships for declared deps', () => {
    const stdout = JSON.stringify([
      {
        package: { key: 'requests', package_name: 'requests', installed_version: '2.31.0' },
        dependencies: [
          { key: 'urllib3', package_name: 'urllib3', installed_version: '2.0.7' },
          { key: 'certifi', package_name: 'certifi', installed_version: '2024.7.4' },
        ],
      },
      {
        package: { key: 'urllib3', package_name: 'urllib3', installed_version: '2.0.7' },
        dependencies: [],
      },
    ]);
    const result = parsePipdeptreeJson(stdout, 'pipdeptree-venv');
    expect(result.deps).toHaveLength(2);
    expect(result.deps[0]).toMatchObject({
      name: 'requests',
      version: '2.31.0',
      bomRef: 'pypi-resolver:requests@2.31.0',
    });
    expect(result.relationships).toHaveLength(2);
    expect(result.relationships[0]).toMatchObject({
      parentBomRef: 'pypi-resolver:requests@2.31.0',
      childBomRef: 'pypi-resolver:urllib3@2.0.7',
    });
  });

  it('skips records missing name or version', () => {
    const stdout = JSON.stringify([
      { package: { package_name: 'good', installed_version: '1.0.0' } },
      { package: { package_name: 'no-version' } },
      { package: {} },
    ]);
    const result = parsePipdeptreeJson(stdout, 'pipdeptree-venv');
    expect(result.deps).toHaveLength(1);
    expect(result.deps[0].name).toBe('good');
  });
});
