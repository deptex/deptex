import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { detectInfraTypes, findDockerfiles } from '../detect-infra';

function makeRepo(layout: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-detect-infra-'));
  for (const [rel, contents] of Object.entries(layout)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, contents);
  }
  return root;
}

describe('detectInfraTypes', () => {
  it('detects Terraform when .tf files exist', () => {
    const root = makeRepo({ 'main.tf': 'resource "aws_s3_bucket" "x" {}' });
    expect(detectInfraTypes(root)).toEqual(['terraform']);
  });

  it('detects Kubernetes via apiVersion + kind heuristic', () => {
    const root = makeRepo({
      'k8s/deploy.yaml': `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec: {}
`,
    });
    expect(detectInfraTypes(root)).toEqual(['kubernetes']);
  });

  it('detects Dockerfile (case-insensitive, with extension)', () => {
    const root = makeRepo({ 'Dockerfile': 'FROM node:20\n' });
    expect(detectInfraTypes(root)).toEqual(['dockerfile']);

    const root2 = makeRepo({ 'Dockerfile.prod': 'FROM nginx:alpine\n' });
    expect(detectInfraTypes(root2)).toEqual(['dockerfile']);
  });

  it('returns deduplicated + sorted list when all three are present', () => {
    const root = makeRepo({
      'Dockerfile': 'FROM nginx:alpine\n',
      'main.tf': 'resource "aws_s3_bucket" "x" {}',
      'k8s/deploy.yaml': `apiVersion: apps/v1
kind: Deployment
`,
    });
    expect(detectInfraTypes(root)).toEqual(['dockerfile', 'kubernetes', 'terraform']);
  });

  it('does NOT detect terraform when .tf is inside node_modules', () => {
    const root = makeRepo({
      'node_modules/some-pkg/example.tf': 'resource "aws_s3_bucket" "x" {}',
    });
    expect(detectInfraTypes(root)).toEqual([]);
  });

  it('does NOT detect kubernetes for AsciiDoc front-matter (kind: Document)', () => {
    const root = makeRepo({
      'docs/README.yaml': `apiVersion: ascii-doc/v1
kind: Document
content: hello
`,
    });
    expect(detectInfraTypes(root)).toEqual([]);
  });

  it('ignores .terraform/ cache and .git/', () => {
    const root = makeRepo({
      '.terraform/providers/aws.tf': 'should-be-ignored',
      '.git/config': '[core]',
    });
    expect(detectInfraTypes(root)).toEqual([]);
  });
});

describe('findDockerfiles', () => {
  it('returns absolute paths of every Dockerfile-like file', () => {
    const root = makeRepo({
      'Dockerfile': 'FROM node:20\n',
      'service-a/Dockerfile.prod': 'FROM nginx:alpine\n',
      'docs/Dockerfile.md': 'not a real dockerfile but matches pattern',
    });
    const found = findDockerfiles(root).map((p) => path.relative(root, p)).sort();
    // Note: The regex matches `Dockerfile.<anything>`, so the .md file is
    // included. Checking it surfaced is enough for the v1 contract.
    expect(found).toEqual(
      expect.arrayContaining([
        'Dockerfile',
        path.join('service-a', 'Dockerfile.prod'),
        path.join('docs', 'Dockerfile.md'),
      ])
    );
  });
});
