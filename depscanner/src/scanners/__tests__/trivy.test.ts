import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  extractGhcrOwner,
  normalizeDigest,
  parseDockerfileFinalStage,
  parseTrivyConfigOutput,
  parseTrivyImageOutput,
  RegistryUnavailableError,
  resolveImageDigest,
  resolvePullStrategy,
  type ConfiguredCredRef,
  type CraneRunner,
} from '../trivy';

function writeTempDockerfile(name: string, contents: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `deptex-trivy-test-${name}-`));
  const file = path.join(dir, 'Dockerfile');
  fs.writeFileSync(file, contents);
  return file;
}

describe('parseDockerfileFinalStage (Patch E)', () => {
  it('returns the only FROM in a single-stage Dockerfile', () => {
    const f = writeTempDockerfile('single', `FROM node:20\nCOPY . /app\n`);
    const stage = parseDockerfileFinalStage(f);
    expect(stage?.imageRef).toBe('node:20');
    expect(stage?.stageIndex).toBe(0);
    expect(stage?.totalStages).toBe(1);
  });

  it('selects the FINAL FROM in a two-stage build (Node→nginx)', () => {
    const f = writeTempDockerfile(
      'two-stage',
      `FROM node:20 AS builder\nRUN npm run build\n\nFROM nginx:alpine\nCOPY --from=builder /app/dist /usr/share/nginx/html\n`
    );
    const stage = parseDockerfileFinalStage(f);
    expect(stage?.imageRef).toBe('nginx:alpine');
    expect(stage?.stageIndex).toBe(1);
    expect(stage?.totalStages).toBe(2);
  });

  it('handles an intermediate FROM scratch correctly', () => {
    const f = writeTempDockerfile(
      'scratch-intermediate',
      `FROM golang:1.22 AS builder\nFROM scratch AS empty\nFROM alpine:3.19\nCOPY hello /\n`
    );
    const stage = parseDockerfileFinalStage(f);
    expect(stage?.imageRef).toBe('alpine:3.19');
  });

  it('returns null when the FINAL stage is FROM scratch', () => {
    const f = writeTempDockerfile(
      'scratch-final',
      `FROM golang:1.22 AS builder\nFROM scratch\nCOPY --from=builder /app /\n`
    );
    expect(parseDockerfileFinalStage(f)).toBeNull();
  });

  it('preserves digest pins on the final FROM', () => {
    const f = writeTempDockerfile(
      'digest',
      `FROM node:20 AS builder\nFROM nginx@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234\n`
    );
    const stage = parseDockerfileFinalStage(f);
    expect(stage?.imageRef).toMatch(/^nginx@sha256:/);
  });

  it('strips --platform but keeps the image ref', () => {
    const f = writeTempDockerfile(
      'platform',
      `FROM --platform=linux/amd64 node:20 AS builder\nFROM --platform=linux/amd64 nginx:alpine\n`
    );
    const stage = parseDockerfileFinalStage(f);
    expect(stage?.imageRef).toBe('nginx:alpine');
  });

  it('returns null on a Dockerfile with no FROM lines', () => {
    const f = writeTempDockerfile('no-from', `# just a comment\nRUN echo hi\n`);
    expect(parseDockerfileFinalStage(f)).toBeNull();
  });

  it('returns null when the final FROM references an earlier stage alias', () => {
    // `FROM builder AS production` flatten — the alias points to a prior
    // stage, not an external image. Without the alias-vs-imageRef check,
    // resolveImageDigest would crane-probe "builder" and waste budget.
    const f = writeTempDockerfile(
      'alias-final',
      `FROM node:20 AS builder\nRUN npm run build\nFROM builder AS production\nCMD ["node", "."]\n`
    );
    expect(parseDockerfileFinalStage(f)).toBeNull();
  });

  it('handles a FROM line that wraps with a backslash continuation', () => {
    const f = writeTempDockerfile(
      'continuation',
      `FROM \\\n  --platform=linux/amd64 \\\n  nginx:alpine AS final\nCOPY . /\n`
    );
    const stage = parseDockerfileFinalStage(f);
    expect(stage?.imageRef).toBe('nginx:alpine');
  });
});

describe('extractGhcrOwner', () => {
  it('extracts the owner from a ghcr.io image', () => {
    expect(extractGhcrOwner('ghcr.io/anthropic/foo:bar')).toBe('anthropic');
  });

  it('extracts the owner when a digest pin is present', () => {
    expect(
      extractGhcrOwner(
        'ghcr.io/anthropic/foo@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234'
      )
    ).toBe('anthropic');
  });

  it('returns null for non-ghcr hosts', () => {
    expect(extractGhcrOwner('docker.io/library/node:20')).toBeNull();
    expect(extractGhcrOwner('myorg.azurecr.io/foo:tag')).toBeNull();
    expect(extractGhcrOwner('quay.io/team/foo')).toBeNull();
  });

  it('returns null for bare-name images (implicit docker.io)', () => {
    expect(extractGhcrOwner('node:20')).toBeNull();
    expect(extractGhcrOwner('library/nginx')).toBeNull();
  });

  it('returns null when ghcr ref is missing the owner segment', () => {
    expect(extractGhcrOwner('ghcr.io/')).toBeNull();
  });
});

describe('parseTrivyConfigOutput', () => {
  it('emits Dockerfile findings only and computes a stable trivy:<rule>:<resource> fingerprint', () => {
    const sample = JSON.stringify({
      Results: [
        {
          Target: 'Dockerfile',
          Type: 'dockerfile',
          Misconfigurations: [
            {
              ID: 'AVD-DS-0001',
              AVDID: 'AVD-DS-0001',
              Title: 'ADD over COPY',
              Description: 'COPY is preferred over ADD',
              Severity: 'MEDIUM',
              PrimaryURL: 'https://avd.aquasec.com/misconfig/ds001',
              CauseMetadata: {
                Resource: 'Dockerfile:RUN',
                StartLine: 4,
                EndLine: 6,
              },
            },
          ],
        },
        // Non-Dockerfile result must be ignored — Checkov owns these.
        {
          Target: 'main.tf',
          Type: 'terraform',
          Misconfigurations: [{ ID: 'AVD-AWS-0042', Severity: 'HIGH' }],
        },
      ],
    });
    const findings = parseTrivyConfigOutput(sample, 'trivy@0.50.4');
    expect(findings).toHaveLength(1);
    expect(findings[0].framework).toBe('dockerfile');
    expect(findings[0].rule_id).toBe('AVD-DS-0001');
    // Fingerprint is `trivy:<rule-id>:<16-hex cause hash>` — the cause segment
    // is opaque free text (raw RUN instructions), so it is hashed rather than
    // embedded, and can never trip a regex validator.
    expect(findings[0].iac_fingerprint).toMatch(/^trivy:AVD-DS-0001:[a-f0-9]{16}$/);
  });

  it('produces a stable, regex-safe fingerprint for Resource values with shell metacharacters', () => {
    // Trivy emits Resource strings like `Dockerfile:RUN apt-get install -y curl`
    // containing whitespace, semicolons, backticks, etc. The fingerprint must
    // never be dropped to null over these — the cause is hashed.
    const make = (resource: string) =>
      JSON.stringify({
        Results: [
          {
            Target: 'Dockerfile',
            Type: 'dockerfile',
            Misconfigurations: [
              {
                ID: 'AVD-DS-0026',
                AVDID: 'AVD-DS-0026',
                Title: 'no-healthcheck',
                Severity: 'LOW',
                CauseMetadata: { Resource: resource, StartLine: 7, EndLine: 7 },
              },
            ],
          },
        ],
      });
    const a = parseTrivyConfigOutput(
      make('Dockerfile:RUN apt-get install -y curl && echo `id`; ls'),
      'trivy@0.50.4',
    );
    expect(a).toHaveLength(1);
    expect(a[0].iac_fingerprint).toMatch(/^trivy:AVD-DS-0026:[a-f0-9]{16}$/);
    // Same input → same fingerprint (status carry-forward depends on this).
    const a2 = parseTrivyConfigOutput(
      make('Dockerfile:RUN apt-get install -y curl && echo `id`; ls'),
      'trivy@0.50.4',
    );
    expect(a2[0].iac_fingerprint).toBe(a[0].iac_fingerprint);
    // Different cause → different fingerprint.
    const b = parseTrivyConfigOutput(make('Dockerfile:RUN something else'), 'trivy@0.50.4');
    expect(b[0].iac_fingerprint).not.toBe(a[0].iac_fingerprint);
  });

  it('returns [] on malformed JSON', () => {
    expect(parseTrivyConfigOutput('not json {{{', 'trivy@0.50.4')).toEqual([]);
  });
});

describe('parseTrivyImageOutput', () => {
  it('extracts container findings + a digest-independent fingerprint', () => {
    const sample = JSON.stringify({
      ArtifactName: 'nginx:alpine',
      Metadata: {
        ImageID: 'sha256:abcd1234',
        RepoDigests: ['nginx@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234'],
      },
      Results: [
        {
          Target: 'nginx:alpine (alpine 3.19)',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1234',
              PkgName: 'libssl3',
              InstalledVersion: '3.0.10-r0',
              FixedVersion: '3.0.11-r0',
              Severity: 'HIGH',
              CVSS: { nvd: { V3Score: 7.5 } },
              PrimaryURL: 'https://nvd.nist.gov/vuln/detail/CVE-2024-1234',
              Description: 'OpenSSL bug',
            },
          ],
        },
      ],
    });
    const parsed = parseTrivyImageOutput(sample, 'nginx:alpine', 'trivy@0.50.4');
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].cve_id).toBe('CVE-2024-1234');
    expect(parsed.findings[0].container_fingerprint).toBe('libssl3@CVE-2024-1234');
    expect(parsed.findings[0].cvss_score).toBe(7.5);
    expect(parsed.imageDigest).toMatch(/^nginx@sha256:/);
  });

  it('drops vulnerabilities missing PkgName', () => {
    const sample = JSON.stringify({
      Results: [
        {
          Class: 'os-pkgs',
          Vulnerabilities: [{ VulnerabilityID: 'CVE-x', InstalledVersion: '1' }],
        },
      ],
    });
    expect(parseTrivyImageOutput(sample, 'nginx:alpine', 'trivy@0.50.4').findings).toEqual([]);
  });

  it('returns empty imageDigest when neither RepoDigests nor ImageID is present (no tag fallback)', () => {
    // Trivy occasionally omits both RepoDigests and ImageID for images
    // pulled by tag from a registry that doesn't expose digests. Falling
    // back to the tag (e.g. `nginx:1.25`) would make every later rescan of
    // the same tag look like a different image once upstream re-pushes.
    // The parser must surface '' so the runner can warn instead.
    const sample = JSON.stringify({
      ArtifactName: 'nginx:1.25',
      Metadata: {},
      Results: [
        {
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-9999',
              PkgName: 'curl',
              InstalledVersion: '8.5.0-r0',
              Severity: 'MEDIUM',
            },
          ],
        },
      ],
    });
    const parsed = parseTrivyImageOutput(sample, 'nginx:1.25', 'trivy@0.50.4');
    expect(parsed.imageDigest).toBe('');
    expect(parsed.findings).toHaveLength(1);
    // image_reference still carries the tag for human-readable display, but
    // image_digest must NOT be the tag.
    expect(parsed.findings[0].image_reference).toBe('nginx:1.25');
    expect(parsed.findings[0].image_digest).toBe('');
  });

  it('falls back to ImageID when RepoDigests is empty', () => {
    const sample = JSON.stringify({
      Metadata: {
        ImageID: 'sha256:deadbeef',
        RepoDigests: [],
      },
      Results: [],
    });
    const parsed = parseTrivyImageOutput(sample, 'nginx:1.25', 'trivy@0.50.4');
    expect(parsed.imageDigest).toBe('sha256:deadbeef');
  });
});

// =============================================================================
// v2 — normalizeDigest, resolvePullStrategy, resolveImageDigest (M6)
// =============================================================================

const HEX64 = 'a'.repeat(64);

describe('normalizeDigest', () => {
  it.each([
    [HEX64, HEX64],
    [`sha256:${HEX64}`, HEX64],
    [`nginx@sha256:${HEX64}`, HEX64],
    [`docker.io/library/nginx@sha256:${HEX64}`, HEX64],
    [`123456789012.dkr.ecr.us-west-2.amazonaws.com/myorg/myimg@sha256:${HEX64}`, HEX64],
  ])('canonicalizes %s', (input, expected) => {
    expect(normalizeDigest(input)).toBe(expected);
  });

  it('round-trips: all input forms reduce to the same canonical digest', () => {
    const a = normalizeDigest(HEX64);
    const b = normalizeDigest(`sha256:${HEX64}`);
    const c = normalizeDigest(`repo/path@sha256:${HEX64}`);
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it('rejects too-short hex', () => {
    expect(() => normalizeDigest('a'.repeat(32))).toThrow(/invalid digest/);
  });

  it('rejects upper-case hex (digests are lower-case canonically)', () => {
    expect(() => normalizeDigest('A'.repeat(64))).toThrow(/invalid digest/);
  });

  it('rejects a mid-string sha256 prefix (anchored regex)', () => {
    expect(() =>
      normalizeDigest(`stuff@sha256:${HEX64}@trailing`)
    ).toThrow(/invalid digest/);
  });
});

describe('resolvePullStrategy', () => {
  const ECR_CRED: ConfiguredCredRef = {
    id: 'cred-ecr',
    registry_type: 'ecr',
    registry_url: 'https://123.dkr.ecr.us-west-2.amazonaws.com',
  };
  const GHCR_CRED: ConfiguredCredRef = {
    id: 'cred-ghcr',
    registry_type: 'ghcr',
    registry_url: null,
  };
  const ACR_CRED: ConfiguredCredRef = {
    id: 'cred-acr',
    registry_type: 'acr',
    registry_url: 'myorg.azurecr.io',
  };

  it.each([
    'node:20',
    'library/nginx:alpine',
    'docker.io/library/postgres:15',
    'public.ecr.aws/lambda/nodejs:20',
    'mcr.microsoft.com/dotnet/aspnet:8.0',
  ])('returns public for %s', (ref) => {
    expect(resolvePullStrategy(ref, [])).toEqual({ kind: 'public' });
  });

  it('returns authenticated when a cred matches the host', () => {
    expect(
      resolvePullStrategy('123.dkr.ecr.us-west-2.amazonaws.com/myimg:tag', [ECR_CRED])
    ).toEqual({
      kind: 'authenticated',
      credId: 'cred-ecr',
      hostname: '123.dkr.ecr.us-west-2.amazonaws.com',
    });
  });

  it('returns authenticated for ghcr when a ghcr cred is configured', () => {
    expect(resolvePullStrategy('ghcr.io/myorg/myapp:v1', [GHCR_CRED])).toEqual({
      kind: 'authenticated',
      credId: 'cred-ghcr',
      hostname: 'ghcr.io',
    });
  });

  it('returns skip for ghcr without a configured cred (v1 special case retired)', () => {
    expect(resolvePullStrategy('ghcr.io/myorg/myapp:v1', [])).toEqual({
      kind: 'skip',
      reason: 'no_matching_cred',
    });
  });

  it('returns skip for ECR when no matching cred is configured', () => {
    expect(
      resolvePullStrategy('999.dkr.ecr.eu-west-1.amazonaws.com/x:y', [ECR_CRED])
    ).toEqual({ kind: 'skip', reason: 'no_matching_cred' });
  });

  it('selects the first matching cred when multiple are configured', () => {
    const result = resolvePullStrategy(
      'myorg.azurecr.io/foo:bar',
      [ECR_CRED, ACR_CRED, GHCR_CRED]
    );
    expect(result).toEqual({
      kind: 'authenticated',
      credId: 'cred-acr',
      hostname: 'myorg.azurecr.io',
    });
  });

  it('skips a misconfigured cred (e.g. harbor with NULL registry_url) and tries the rest', () => {
    const broken: ConfiguredCredRef = {
      id: 'cred-broken',
      registry_type: 'harbor',
      registry_url: null,
    };
    expect(resolvePullStrategy('myorg.azurecr.io/foo:bar', [broken, ACR_CRED])).toEqual({
      kind: 'authenticated',
      credId: 'cred-acr',
      hostname: 'myorg.azurecr.io',
    });
  });

  it('treats a digest-pinned reference the same as a tagged one', () => {
    expect(
      resolvePullStrategy(
        `123.dkr.ecr.us-west-2.amazonaws.com/myimg@sha256:${HEX64}`,
        [ECR_CRED]
      )
    ).toEqual({
      kind: 'authenticated',
      credId: 'cred-ecr',
      hostname: '123.dkr.ecr.us-west-2.amazonaws.com',
    });
  });
});

describe('resolveImageDigest', () => {
  it('returns the canonical 64-hex digest from a successful crane run', async () => {
    const runner: CraneRunner = jest.fn().mockResolvedValue({
      stdout: `sha256:${HEX64}\n`,
      exitCode: 0,
    });
    await expect(
      resolveImageDigest('docker.io/library/nginx:1.27', { runner })
    ).resolves.toBe(HEX64);
    expect(runner).toHaveBeenCalledWith('docker.io/library/nginx:1.27', {
      dockerConfigDir: undefined,
      timeoutMs: 5000,
    });
  });

  it('passes dockerConfigDir through to the runner', async () => {
    const runner: CraneRunner = jest.fn().mockResolvedValue({
      stdout: `sha256:${HEX64}`,
      exitCode: 0,
    });
    await resolveImageDigest('nginx:1', { runner, dockerConfigDir: '/tmp/scan-x' });
    expect(runner).toHaveBeenCalledWith('nginx:1', {
      dockerConfigDir: '/tmp/scan-x',
      timeoutMs: 5000,
    });
  });

  it('classifies a runner timeout as RegistryUnavailableError', async () => {
    // Mirrors what defaultCraneRunner does on execFile timeout: rejects with
    // RegistryUnavailableError carrying the "timed out" cause.
    const runner: CraneRunner = () =>
      Promise.reject(new RegistryUnavailableError('private:1', 'crane probe timed out'));
    await expect(
      resolveImageDigest('private:1', { runner })
    ).rejects.toThrow(/timed out/);
  });

  it('wraps a non-RegistryUnavailableError rejection (e.g. ENOENT) into RegistryUnavailableError', async () => {
    const runner: CraneRunner = () =>
      Promise.reject(Object.assign(new Error('crane: command not found'), { code: 'ENOENT' }));
    const promise = resolveImageDigest('nginx:1', { runner });
    await expect(promise).rejects.toBeInstanceOf(RegistryUnavailableError);
    await expect(promise).rejects.toThrow(/command not found/);
  });

  it('classifies a non-zero exit as RegistryUnavailableError', async () => {
    const runner: CraneRunner = jest.fn().mockResolvedValue({ stdout: '', exitCode: 2 });
    await expect(resolveImageDigest('nginx:1', { runner })).rejects.toThrow(/crane exit 2/);
  });

  it('throws on malformed digest output (defensive parse)', async () => {
    const runner: CraneRunner = jest.fn().mockResolvedValue({
      stdout: 'not a digest',
      exitCode: 0,
    });
    await expect(resolveImageDigest('nginx:1', { runner })).rejects.toThrow(/invalid digest/);
  });
});
