/**
 * Locks the Semgrep noise-filter chain (N5/N7).
 *
 * The drop / downrank decisions are stringly-typed substring/prefix matches. A
 * typo (or a re-ordered `.startsWith`) would silently re-admit Checkov IaC
 * double-reports or TruffleHog secret double-reports into the SAST findings
 * table. These tests pin each branch so that drift fails loudly.
 */
import {
  shouldDropSemgrepRule,
  isGeneratedSemgrepPath,
  downrankSemgrepSeverity,
} from '../semgrep';

describe('shouldDropSemgrepRule — rule-id drop filters', () => {
  it('drops secret-detection rules (TruffleHog owns secrets)', () => {
    expect(shouldDropSemgrepRule('generic.secrets.security.detected-aws-secret-access-key')).toBe(true);
  });

  it('drops the IaC namespaces Checkov owns (k8s / Dockerfile / Terraform)', () => {
    expect(shouldDropSemgrepRule('yaml.kubernetes.security.privileged-container')).toBe(true);
    expect(shouldDropSemgrepRule('dockerfile.security.last-user-is-root')).toBe(true);
    // N7: terraform.* now dropped — Checkov runs Terraform too, so a Semgrep
    // terraform finding is a literal duplicate.
    expect(shouldDropSemgrepRule('terraform.aws.security.aws-s3-bucket-public')).toBe(true);
  });

  it('drops the express "missing middleware" absence nudges', () => {
    expect(shouldDropSemgrepRule('javascript.express.security.express-check-csurf-usage')).toBe(true);
    expect(shouldDropSemgrepRule('javascript.express.security.express-check-helmet-usage')).toBe(true);
  });

  it('drops the no-signal audit rules (SEMGREP_NOISE_RULES.drop)', () => {
    expect(shouldDropSemgrepRule('javascript.lang.security.audit.unsafe-formatstring')).toBe(true);
  });

  it('keeps real security rules untouched', () => {
    expect(shouldDropSemgrepRule('javascript.express.security.audit.express-cookie-session-no-httponly')).toBe(false);
    expect(shouldDropSemgrepRule('python.lang.security.audit.dangerous-system-call')).toBe(false);
    expect(shouldDropSemgrepRule('typescript.react.security.react-dangerouslysetinnerhtml')).toBe(false);
  });

  it('is safe on a missing check_id', () => {
    expect(shouldDropSemgrepRule(undefined)).toBe(false);
    expect(shouldDropSemgrepRule('')).toBe(false);
  });

  describe('client-SPA scoping', () => {
    const SPA_RULES = [
      'javascript.lang.security.detect-non-literal-regexp',
      'javascript.lang.security.detect-non-literal-fs-filename',
      'javascript.lang.security.detect-child-process',
      'javascript.lang.security.detect-non-literal-require',
      'javascript.express.security.detect-no-csrf-before-method-override',
    ];

    it('keeps the server-runtime / self-DoS rules on a non-SPA project', () => {
      for (const r of SPA_RULES) {
        expect(shouldDropSemgrepRule(r, { isClientSpaProject: false })).toBe(false);
      }
      // Default (no opts) is server-safe: nothing client-SPA dropped.
      for (const r of SPA_RULES) {
        expect(shouldDropSemgrepRule(r)).toBe(false);
      }
    });

    it('drops them on a pure client SPA', () => {
      for (const r of SPA_RULES) {
        expect(shouldDropSemgrepRule(r, { isClientSpaProject: true })).toBe(true);
      }
    });
  });
});

describe('isGeneratedSemgrepPath — path drop filter', () => {
  it('drops our own dep-scan report dir and installed deps', () => {
    expect(isGeneratedSemgrepPath('depscan-reports/vdr.json')).toBe(true);
    expect(isGeneratedSemgrepPath('node_modules/lodash/index.js')).toBe(true);
    expect(isGeneratedSemgrepPath('frontend/node_modules/x/y.js')).toBe(true);
  });

  it('keeps first-party source paths', () => {
    expect(isGeneratedSemgrepPath('src/server.ts')).toBe(false);
    expect(isGeneratedSemgrepPath('app/routes/index.js')).toBe(false);
    expect(isGeneratedSemgrepPath(undefined)).toBe(false);
  });
});

describe('downrankSemgrepSeverity — downrank tier', () => {
  it('pins detect-non-literal-regexp (ReDoS) to INFO regardless of reported severity', () => {
    expect(downrankSemgrepSeverity('javascript.lang.security.detect-non-literal-regexp', 'WARNING')).toBe('INFO');
    expect(downrankSemgrepSeverity('javascript.lang.security.detect-non-literal-regexp', 'ERROR')).toBe('INFO');
  });

  it('preserves the reported severity for everything else', () => {
    expect(downrankSemgrepSeverity('python.lang.security.audit.dangerous-system-call', 'ERROR')).toBe('ERROR');
    expect(downrankSemgrepSeverity('some.rule', 'WARNING')).toBe('WARNING');
  });

  it('falls back to INFO when a finding carries no severity', () => {
    expect(downrankSemgrepSeverity('some.rule', undefined)).toBe('INFO');
  });
});
