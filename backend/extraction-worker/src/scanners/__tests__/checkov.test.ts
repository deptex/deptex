import { parseCheckovOutput } from '../checkov';

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

  it('drops findings whose framework Checkov reports as unsupported at v1', () => {
    const sample = JSON.stringify({
      check_type: 'cloudformation',
      results: {
        failed_checks: [
          {
            bc_check_id: 'CKV_AWS_99',
            resource_address: 'AWS::S3::Bucket.x',
            file_path: 'cfn.yml',
            check_name: 'cfn',
          },
        ],
      },
    });
    expect(parseCheckovOutput(sample, 'checkov@3.2.420')).toHaveLength(0);
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
});
