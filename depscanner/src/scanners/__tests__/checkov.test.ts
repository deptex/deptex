import { extractComplianceRefs, parseCheckovOutput } from '../checkov';

describe('parseCheckovOutput', () => {
  it('parses a single-framework report and emits a stable checkov:<rule>:<resource> fingerprint', () => {
    const sample = JSON.stringify({
      check_type: 'terraform',
      results: {
        failed_checks: [
          {
            check_id: 'CKV_AWS_20',
            bc_check_id: 'CKV_AWS_20',
            check_name: 'Ensure S3 bucket has block-public-access enabled',
            resource: 'aws_s3_bucket.my_bucket',
            resource_address: 'aws_s3_bucket.my_bucket',
            file_path: '/main.tf',
            file_line_range: [10, 14],
            severity: 'HIGH',
            guideline: 'https://docs.bridgecrew.io/docs/s3_20',
          },
        ],
      },
    });
    const findings = parseCheckovOutput(sample, 'checkov@3.2.420');
    expect(findings).toHaveLength(1);
    expect(findings[0].framework).toBe('terraform');
    expect(findings[0].rule_id).toBe('CKV_AWS_20');
    expect(findings[0].iac_fingerprint).toBe('checkov:CKV_AWS_20:aws_s3_bucket.my_bucket');
    expect(findings[0].file_path).toBe('main.tf'); // leading slash stripped
    expect(findings[0].severity).toBe('HIGH');
  });

  it('defaults a severity-less hardening-nit check (CKV_K8S_*) to MEDIUM, not null', () => {
    const sample = JSON.stringify({
      check_type: 'kubernetes',
      results: {
        failed_checks: [
          {
            check_id: 'CKV_K8S_8', // liveness probe — a hardening nit, not high-impact
            check_name: 'Liveness Probe Should be Configured',
            resource: 'Deployment.default.web',
            resource_address: 'Deployment.default.web',
            file_path: '/k8s.yaml',
            file_line_range: [10, 14],
            // no `severity` — the common case for Checkov community checks
          },
        ],
      },
    });
    const findings = parseCheckovOutput(sample, 'checkov@3.2.420');
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('MEDIUM');
  });

  it('promotes a security-critical severity-less rule (privileged container) to HIGH', () => {
    const sample = JSON.stringify({
      check_type: 'kubernetes',
      results: {
        failed_checks: [
          {
            check_id: 'CKV_K8S_16', // container running as privileged
            check_name: 'Container should not be privileged',
            resource: 'Deployment.default.web',
            resource_address: 'Deployment.default.web',
            file_path: '/k8s.yaml',
            file_line_range: [10, 14],
            // no `severity` — community check, but this one is high-impact
          },
        ],
      },
    });
    const findings = parseCheckovOutput(sample, 'checkov@3.2.420');
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('HIGH');
  });

  it('parses an array-of-reports response (multi-framework run)', () => {
    const sample = JSON.stringify([
      {
        check_type: 'terraform',
        results: {
          failed_checks: [
            {
              bc_check_id: 'CKV_AWS_20',
              check_name: 'tf rule',
              resource_address: 'aws_s3_bucket.x',
              file_path: 'main.tf',
            },
          ],
        },
      },
      {
        check_type: 'kubernetes',
        results: {
          failed_checks: [
            {
              bc_check_id: 'CKV_K8S_8',
              check_name: 'k8s rule',
              resource_address: 'Deployment.app',
              file_path: 'k8s/deploy.yaml',
            },
          ],
        },
      },
    ]);
    const findings = parseCheckovOutput(sample, 'checkov@3.2.420');
    expect(findings).toHaveLength(2);
    expect(findings.find((f) => f.framework === 'kubernetes')).toBeDefined();
    expect(findings.find((f) => f.framework === 'terraform')).toBeDefined();
  });

  it('emits iac_fingerprint = null when resource_address is missing (NULL policy)', () => {
    const sample = JSON.stringify({
      check_type: 'terraform',
      results: {
        failed_checks: [
          {
            bc_check_id: 'CKV_AWS_20',
            check_name: 'orphan',
            file_path: 'main.tf',
            // No resource / resource_address — fingerprint must be null, not synthesized.
          },
        ],
      },
    });
    const findings = parseCheckovOutput(sample, 'checkov@3.2.420');
    expect(findings).toHaveLength(1);
    expect(findings[0].iac_fingerprint).toBeNull();
  });

  it('drops findings with no rule_id', () => {
    const sample = JSON.stringify({
      check_type: 'terraform',
      results: { failed_checks: [{ resource_address: 'aws_s3_bucket.x', file_path: 'main.tf' }] },
    });
    expect(parseCheckovOutput(sample, 'checkov@3.2.420')).toHaveLength(0);
  });

  it('drops findings whose check_type is outside the v2 framework taxonomy', () => {
    // bitbucket_pipelines is a real Checkov framework but not in our 9-value
    // IaCFramework union; such findings are dropped.
    const sample = JSON.stringify({
      check_type: 'bitbucket_pipelines',
      results: {
        failed_checks: [
          {
            check_id: 'CKV_BITBUCKET_1',
            resource_address: 'pipeline.steps[0]',
            file_path: 'bitbucket-pipelines.yml',
            check_name: 'bb',
          },
        ],
      },
    });
    expect(parseCheckovOutput(sample, 'checkov@3.2.420')).toHaveLength(0);
  });

  it.each([
    ['cloudformation', 'CKV_AWS_99', 'cfn.yml'],
    ['helm', 'CKV_K8S_8', 'charts/web/templates/deploy.yaml'],
    ['arm', 'CKV_AZURE_1', 'azure/template.json'],
    ['bicep', 'CKV_AZURE_50', 'main.bicep'],
    ['serverless', 'CKV_AWS_115', 'serverless.yml'],
    ['github_actions', 'CKV_GHA_1', '.github/workflows/ci.yml'],
  ])('maps Checkov check_type %s through to the canonical framework', (checkType, ruleId, filePath) => {
    const sample = JSON.stringify({
      check_type: checkType,
      results: {
        failed_checks: [
          {
            check_id: ruleId,
            resource_address: 'r.name',
            file_path: filePath,
            check_name: 'rule',
          },
        ],
      },
    });
    const findings = parseCheckovOutput(sample, 'checkov@3.2.420');
    expect(findings).toHaveLength(1);
    expect(findings[0].framework).toBe(checkType);
  });

  it('aliases the kustomize check_type to the kubernetes framework', () => {
    const sample = JSON.stringify({
      check_type: 'kustomize',
      results: {
        failed_checks: [
          {
            check_id: 'CKV_K8S_8',
            resource_address: 'Deployment.app',
            file_path: 'overlays/prod/kustomization.yaml',
            check_name: 'k',
          },
        ],
      },
    });
    const findings = parseCheckovOutput(sample, 'checkov@3.2.420');
    expect(findings).toHaveLength(1);
    expect(findings[0].framework).toBe('kubernetes');
  });

  it('returns [] on malformed JSON', () => {
    expect(parseCheckovOutput('not json', 'checkov@3.2.420')).toEqual([]);
  });

  it('uses canonical check_id (CKV_*) not bc_check_id (BC_*) for fingerprint', () => {
    // Real Checkov output: check_id is CKV_*, bc_check_id is BC_* — these
    // diverge for ~all rules. The fingerprint regex requires CKV_* so the
    // parser must prefer check_id over bc_check_id.
    const sample = JSON.stringify({
      check_type: 'terraform',
      results: {
        failed_checks: [
          {
            check_id: 'CKV_AWS_145',
            bc_check_id: 'BC_AWS_GENERAL_56',
            check_name: 'Ensure that S3 buckets are encrypted with KMS',
            resource: 'aws_s3_bucket.public_bucket',
            resource_address: null,
            file_path: '/main.tf',
          },
        ],
      },
    });
    const findings = parseCheckovOutput(sample, 'checkov@3.2.420');
    expect(findings).toHaveLength(1);
    expect(findings[0].rule_id).toBe('CKV_AWS_145');
    expect(findings[0].iac_fingerprint).toBe('checkov:CKV_AWS_145:aws_s3_bucket.public_bucket');
  });

  it('threads compliance_refs through from metadata.benchmark', () => {
    const sample = JSON.stringify({
      check_type: 'terraform',
      results: {
        failed_checks: [
          {
            check_id: 'CKV_AWS_20',
            resource_address: 'aws_s3_bucket.x',
            file_path: 'main.tf',
            check_name: 'r',
            metadata: {
              benchmark: {
                'CIS AWS V1.4': ['1.1.1', '1.1.2'],
                SOC2: ['CC6.1'],
              },
            },
          },
        ],
      },
    });
    const findings = parseCheckovOutput(sample, 'checkov@3.2.420');
    expect(findings).toHaveLength(1);
    expect(findings[0].compliance_refs).toEqual({
      cis_aws_v1_4: ['1.1.1', '1.1.2'],
      soc2: ['CC6.1'],
    });
  });

  it('emits compliance_refs = null when metadata.benchmark is absent', () => {
    const sample = JSON.stringify({
      check_type: 'terraform',
      results: {
        failed_checks: [
          {
            check_id: 'CKV_AWS_20',
            resource_address: 'aws_s3_bucket.x',
            file_path: 'main.tf',
            check_name: 'r',
            metadata: {},
          },
        ],
      },
    });
    const findings = parseCheckovOutput(sample, 'checkov@3.2.420');
    expect(findings).toHaveLength(1);
    expect(findings[0].compliance_refs).toBeNull();
  });
});

describe('extractComplianceRefs', () => {
  it('returns null for absent / empty metadata', () => {
    expect(extractComplianceRefs(null)).toBeNull();
    expect(extractComplianceRefs(undefined)).toBeNull();
    expect(extractComplianceRefs({})).toBeNull();
    expect(extractComplianceRefs({ benchmark: null } as any)).toBeNull();
  });

  it('parses the object-shaped benchmark map', () => {
    expect(
      extractComplianceRefs({
        benchmark: {
          'CIS Kubernetes V1.7': ['5.1.1', '5.1.2'],
          'NIST 800-53': ['AC-2'],
        },
      })
    ).toEqual({
      cis_kubernetes_v1_7: ['5.1.1', '5.1.2'],
      nist_800_53: ['AC-2'],
    });
  });

  it('parses the array-of-pairs benchmark shape', () => {
    expect(
      extractComplianceRefs({
        benchmark: [
          { name: 'PCI-DSS', ids: ['1.2.1'] },
          { name: 'HIPAA', ids: ['164.312(a)(1)'] },
        ],
      })
    ).toEqual({
      pci_dss: ['1.2.1'],
      hipaa: ['164.312(a)(1)'],
    });
  });

  it('returns null when the benchmark map exists but every entry is empty', () => {
    expect(
      extractComplianceRefs({
        benchmark: {
          'CIS AWS': [],
          SOC2: [null, undefined, ''] as any,
        },
      })
    ).toBeNull();
  });

  it('skips array entries that are missing name or ids', () => {
    expect(
      extractComplianceRefs({
        benchmark: [
          { name: 'CIS AWS', ids: ['1.1'] },
          { name: 'incomplete' }, // no ids
          { ids: ['x'] }, // no name
        ] as any,
      })
    ).toEqual({ cis_aws: ['1.1'] });
  });
});
