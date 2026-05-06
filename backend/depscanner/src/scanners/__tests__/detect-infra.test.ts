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

  it('detects Helm via Chart.yaml', () => {
    const root = makeRepo({
      'charts/myapp/Chart.yaml': `apiVersion: v2
name: myapp
version: 0.1.0
`,
    });
    expect(detectInfraTypes(root)).toContain('helm');
  });

  it('detects CloudFormation via AWSTemplateFormatVersion header', () => {
    const root = makeRepo({
      'infra/stack.yaml': `AWSTemplateFormatVersion: '2010-09-09'
Description: my stack
Resources:
  Bucket:
    Type: AWS::S3::Bucket
`,
    });
    expect(detectInfraTypes(root)).toEqual(['cloudformation']);
  });

  it('detects CloudFormation via Resources + AWS::* Type without explicit version header', () => {
    const root = makeRepo({
      'infra/stack.yaml': `Description: implicit
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: foo
`,
    });
    expect(detectInfraTypes(root)).toEqual(['cloudformation']);
  });

  it('detects SAM via the CloudFormation Transform header path', () => {
    // SAM templates are AWSTemplateFormatVersion + Transform: AWS::Serverless-*.
    // The CFN detector picks them up.
    const root = makeRepo({
      'sam/template.yaml': `AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
`,
    });
    expect(detectInfraTypes(root)).toEqual(['cloudformation']);
  });

  it('detects ARM via Azure deploymentTemplate $schema', () => {
    const root = makeRepo({
      'azure/template.json': JSON.stringify({
        $schema:
          'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
        contentVersion: '1.0.0.0',
        resources: [],
      }),
    });
    expect(detectInfraTypes(root)).toEqual(['arm']);
  });

  it('detects Bicep via .bicep extension', () => {
    const root = makeRepo({
      'azure/main.bicep': "param location string = resourceGroup().location\n",
    });
    expect(detectInfraTypes(root)).toEqual(['bicep']);
  });

  it('detects Serverless Framework via serverless.yml', () => {
    const root = makeRepo({
      'svc/serverless.yml': `service: my-svc
provider:
  name: aws
functions:
  hello:
    handler: handler.hello
`,
    });
    expect(detectInfraTypes(root)).toEqual(['serverless']);
  });

  it('detects GitHub Actions workflows at the repo root', () => {
    const root = makeRepo({
      '.github/workflows/ci.yml': `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps: []
`,
    });
    expect(detectInfraTypes(root)).toEqual(['github_actions']);
  });

  it('does NOT detect GitHub Actions inside a nested .github/workflows dir', () => {
    // Vendored sub-repo workflows must not trigger a scan (MTD-r2-8).
    const root = makeRepo({
      'third_party/some-tool/.github/workflows/ci.yml': 'name: vendored\n',
    });
    expect(detectInfraTypes(root)).toEqual([]);
  });

  it('tags kustomization.yaml as kubernetes (no separate kustomize value)', () => {
    const root = makeRepo({
      'overlays/prod/kustomization.yaml': `resources:
  - ../base
namespace: prod
`,
    });
    expect(detectInfraTypes(root)).toEqual(['kubernetes']);
  });

  it('returns deduplicated + sorted list when all three v1 types are present', () => {
    const root = makeRepo({
      'Dockerfile': 'FROM nginx:alpine\n',
      'main.tf': 'resource "aws_s3_bucket" "x" {}',
      'k8s/deploy.yaml': `apiVersion: apps/v1
kind: Deployment
`,
    });
    expect(detectInfraTypes(root)).toEqual(['dockerfile', 'kubernetes', 'terraform']);
  });

  it('detects all 9 frameworks in a multi-format repo', () => {
    const root = makeRepo({
      'Dockerfile': 'FROM nginx:alpine\n',
      'main.tf': 'resource "aws_s3_bucket" "x" {}',
      'k8s/deploy.yaml': `apiVersion: apps/v1
kind: Deployment
`,
      'charts/web/Chart.yaml': "apiVersion: v2\nname: web\nversion: 0.0.1\n",
      'cfn/stack.yaml': `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  B:
    Type: AWS::S3::Bucket
`,
      'azure/template.json': JSON.stringify({
        $schema:
          'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
        contentVersion: '1.0.0.0',
      }),
      'azure/main.bicep': "param x string = ''\n",
      'svc/serverless.yml': "service: s\nprovider:\n  name: aws\n",
      '.github/workflows/ci.yml': 'name: ci\non: [push]\njobs: {}\n',
    });
    expect(detectInfraTypes(root)).toEqual([
      'arm',
      'bicep',
      'cloudformation',
      'dockerfile',
      'github_actions',
      'helm',
      'kubernetes',
      'serverless',
      'terraform',
    ]);
  });

  it('returns empty for a repo with no infra files', () => {
    const root = makeRepo({
      'src/index.ts': "export const x = 1;\n",
      'README.md': '# hello\n',
      'package.json': '{ "name": "noop" }\n',
    });
    expect(detectInfraTypes(root)).toEqual([]);
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

  it('coexists helm + kubernetes when chart templates contain k8s manifests', () => {
    // A Helm chart's templates/ directory is full of k8s YAML — both should
    // surface so Checkov runs both framework rule sets.
    const root = makeRepo({
      'charts/web/Chart.yaml': "apiVersion: v2\nname: web\nversion: 0.0.1\n",
      'charts/web/templates/deployment.yaml': `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
`,
    });
    expect(detectInfraTypes(root).sort()).toEqual(['helm', 'kubernetes']);
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
