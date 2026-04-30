import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  classifyImageRef,
  parseDockerfileFinalStage,
  parseTrivyConfigOutput,
  parseTrivyImageOutput,
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
});

describe('classifyImageRef (Patch C)', () => {
  it('treats bare-name images as public docker hub', () => {
    expect(classifyImageRef('node:20')).toEqual({ kind: 'public_dockerhub' });
  });

  it('treats library/* images as public docker hub', () => {
    expect(classifyImageRef('library/nginx:alpine')).toEqual({ kind: 'public_dockerhub' });
  });

  it('treats explicit docker.io as public docker hub', () => {
    expect(classifyImageRef('docker.io/library/postgres:15')).toEqual({
      kind: 'public_dockerhub',
    });
  });

  it('extracts the owner from a ghcr.io image', () => {
    expect(classifyImageRef('ghcr.io/anthropic/foo:bar')).toEqual({
      kind: 'ghcr',
      owner: 'anthropic',
    });
  });

  it('marks ECR / GCR / ACR / Quay / Harbor as unsupported_registry at v1', () => {
    expect(classifyImageRef('123456789.dkr.ecr.us-east-1.amazonaws.com/foo:tag').kind).toBe(
      'unsupported_registry'
    );
    expect(classifyImageRef('gcr.io/my-project/foo:tag').kind).toBe('unsupported_registry');
    expect(classifyImageRef('myorg.azurecr.io/foo:tag').kind).toBe('unsupported_registry');
    expect(classifyImageRef('quay.io/myorg/foo:tag').kind).toBe('unsupported_registry');
    expect(classifyImageRef('harbor.example.com/myorg/foo:tag').kind).toBe('unsupported_registry');
  });

  it('extracts ghcr owner correctly when a digest pin is present', () => {
    const result = classifyImageRef('ghcr.io/anthropic/foo@sha256:abcd1234');
    expect(result).toEqual({ kind: 'ghcr', owner: 'anthropic' });
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
    expect(findings[0].iac_fingerprint).toBe('trivy:AVD-DS-0001:Dockerfile:RUN');
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
});
