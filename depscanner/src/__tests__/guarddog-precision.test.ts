import {
  isLowPrecisionGuardDogRule,
  isCorroboratingGuardDogRule,
  requiresCorroboration,
} from '../malicious/guarddog';

describe('isLowPrecisionGuardDogRule — drop noisy GuardDog source heuristics', () => {
  it('suppresses low-precision structural heuristics across ecosystem prefixes', () => {
    expect(isLowPrecisionGuardDogRule('npm-api-obfuscation')).toBe(true);
    expect(isLowPrecisionGuardDogRule('pypi-api-obfuscation')).toBe(true);
    expect(isLowPrecisionGuardDogRule('NPM-API-OBFUSCATION')).toBe(true);
    // Presence-of-install-hook (flagged esbuild / @types/node) and the
    // suspicious-domain-shape heuristic (flagged is-number / micromatch /
    // proxy-from-env) are structural, not behavioral — suppressed.
    expect(isLowPrecisionGuardDogRule('npm-install-script')).toBe(true);
    expect(isLowPrecisionGuardDogRule('npm-shady-links')).toBe(true);
  });

  it('keeps high-signal behavioral malware rules', () => {
    expect(isLowPrecisionGuardDogRule('npm-exfiltrate-sensitive-data')).toBe(false);
    expect(isLowPrecisionGuardDogRule('npm-silent-process-execution')).toBe(false);
    expect(isLowPrecisionGuardDogRule('npm-obfuscated-code')).toBe(false);
  });

  it('is safe on empty / unknown rule ids', () => {
    expect(isLowPrecisionGuardDogRule('')).toBe(false);
    expect(isLowPrecisionGuardDogRule('obfuscation-something-else')).toBe(false);
  });

  it('folds underscores so a separator change in GuardDog still matches', () => {
    expect(isLowPrecisionGuardDogRule('npm_api_obfuscation')).toBe(true);
    expect(isLowPrecisionGuardDogRule('npm_shady_links')).toBe(true);
  });
});

describe('requiresCorroboration — broad metadata heuristics (N3)', () => {
  it('flags the broad structural metadata heuristics that mis-fire on vetted packages', () => {
    expect(requiresCorroboration('npm-empty-information')).toBe(true);
    expect(requiresCorroboration('npm-release-zero')).toBe(true);
    expect(requiresCorroboration('pypi-single-python-file')).toBe(true);
    expect(requiresCorroboration('npm-bundled-binary')).toBe(true);
    expect(requiresCorroboration('npm-deceptive-author')).toBe(true);
    expect(requiresCorroboration('npm-metadata-mismatch')).toBe(true);
    expect(requiresCorroboration('pypi-repository-integrity-mismatch')).toBe(true);
    expect(requiresCorroboration('npm-direct-url-dependency')).toBe(true);
    // Robust to an underscore separator.
    expect(requiresCorroboration('npm_empty_information')).toBe(true);
  });

  it('does NOT gate the genuinely-high-signal standalone heuristics', () => {
    // Typosquatting + account-takeover (compromised maintainer email) can be the
    // ONLY indicator of real malware — they must surface standalone.
    expect(requiresCorroboration('npm-typosquatting')).toBe(false);
    expect(requiresCorroboration('npm-potentially-compromised-email-domain')).toBe(false);
    expect(requiresCorroboration('npm-unclaimed-maintainer-email-domain')).toBe(false);
  });

  it('does NOT gate behavioral / source rules', () => {
    expect(requiresCorroboration('npm-exfiltrate-sensitive-data')).toBe(false);
    expect(requiresCorroboration('npm-silent-process-execution')).toBe(false);
  });
});

describe('isCorroboratingGuardDogRule — what backs up a metadata heuristic (N3)', () => {
  it('behavioral / source rules corroborate', () => {
    expect(isCorroboratingGuardDogRule('npm-exfiltrate-sensitive-data')).toBe(true);
    expect(isCorroboratingGuardDogRule('npm-silent-process-execution')).toBe(true);
    expect(isCorroboratingGuardDogRule('npm-obfuscated-code')).toBe(true);
  });

  it('high-signal standalone metadata heuristics corroborate', () => {
    expect(isCorroboratingGuardDogRule('npm-typosquatting')).toBe(true);
    expect(isCorroboratingGuardDogRule('npm-potentially-compromised-email-domain')).toBe(true);
  });

  it('neither the dropped low-precision flags nor the corroboration-gated heuristics corroborate', () => {
    // Low-precision structural flags are dropped outright — they can't vouch for
    // anything.
    expect(isCorroboratingGuardDogRule('npm-api-obfuscation')).toBe(false);
    expect(isCorroboratingGuardDogRule('npm-install-script')).toBe(false);
    // A broad metadata heuristic can't corroborate another broad heuristic
    // (otherwise two weak signals would bootstrap each other).
    expect(isCorroboratingGuardDogRule('npm-empty-information')).toBe(false);
    expect(isCorroboratingGuardDogRule('npm-bundled-binary')).toBe(false);
  });
});
