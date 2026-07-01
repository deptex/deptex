/**
 * Locks the TruffleHog finding-filters (NFP1 / N5).
 *
 *  - isVendoredSecretPath  — the deterministic backstop that drops example
 *    tokens reported inside dependency trees (node_modules/**, vendor/**, …),
 *    which TruffleHog's --exclude-paths regex was observed to leak through
 *    (json5 / yargs / redis / keyv READMEs + CHANGELOGs).
 *  - isLowConfidenceGitlabFinding — the unverified-non-glpat GitLab FP drop.
 */
import {
  isVendoredSecretPath,
  isLowConfidenceGitlabFinding,
} from '../trufflehog';

describe('isVendoredSecretPath — drop dependency-tree secrets (NFP1)', () => {
  it('drops the exact node_modules markdown FPs from the real run', () => {
    expect(isVendoredSecretPath('node_modules/json5/README.md')).toBe(true);
    expect(isVendoredSecretPath('node_modules/yargs/CHANGELOG.md')).toBe(true);
    expect(isVendoredSecretPath('node_modules/redis/README.md')).toBe(true);
    expect(isVendoredSecretPath('node_modules/keyv/README.md')).toBe(true);
  });

  it('drops nested + non-npm vendored trees', () => {
    expect(isVendoredSecretPath('frontend/node_modules/x/docs.md')).toBe(true);
    expect(isVendoredSecretPath('node_modules/.pnpm/foo@1.0.0/node_modules/foo/README.md')).toBe(true);
    expect(isVendoredSecretPath('vendor/github.com/pkg/errors/errors.go')).toBe(true);
    expect(isVendoredSecretPath('.venv/lib/python3.11/site-packages/req/README.md')).toBe(true);
    expect(isVendoredSecretPath('api/venv/lib/site-packages/x.py')).toBe(true);
    // Windows-separator paths normalize before the segment split.
    expect(isVendoredSecretPath('node_modules\\json5\\README.md')).toBe(true);
  });

  it('keeps first-party paths — including ones whose names merely contain a vendor word', () => {
    expect(isVendoredSecretPath('src/index.ts')).toBe(false);
    expect(isVendoredSecretPath('config/.env.example')).toBe(false);
    // Segment-exact match: `vendoring-utils` is NOT `vendor`.
    expect(isVendoredSecretPath('src/vendoring-utils/config.ts')).toBe(false);
    expect(isVendoredSecretPath('lib/venvironment.py')).toBe(false);
    expect(isVendoredSecretPath('')).toBe(false);
    expect(isVendoredSecretPath('README.md')).toBe(false);
  });
});

describe('isLowConfidenceGitlabFinding — unverified non-glpat GitLab FP drop', () => {
  it('drops an unverified GitLab match that is not glpat-shaped', () => {
    expect(
      isLowConfidenceGitlabFinding({ detectorType: 'Gitlab', isVerified: false, raw: 'role_display_name' }),
    ).toBe(true);
  });

  it('keeps a verified GitLab match (confirmed live)', () => {
    expect(
      isLowConfidenceGitlabFinding({ detectorType: 'Gitlab', isVerified: true, raw: 'anything' }),
    ).toBe(false);
  });

  it('keeps an unverified but genuinely glpat-shaped token (could be revoked-but-real)', () => {
    expect(
      isLowConfidenceGitlabFinding({
        detectorType: 'gitlab',
        isVerified: false,
        raw: 'glpat-abcdef1234567890abcdef',
      }),
    ).toBe(false);
  });

  it('never touches other detectors', () => {
    expect(
      isLowConfidenceGitlabFinding({ detectorType: 'AWS', isVerified: false, raw: 'AKIA...' }),
    ).toBe(false);
  });
});
