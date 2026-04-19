import { execSync } from 'child_process';
import { FixLogger } from './logger';
import { getSafeInstallCommand, getAuditCommand, getTestCommand } from './strategies';
import { clearLLMKeys } from './executor';

export interface ValidationResult {
  auditPassed: boolean | null;
  lintPassed: boolean | null;
  testsPassed: boolean | null;
  testsSkipped: boolean;
  notes: string[];
}

export async function validateFix(
  workDir: string,
  ecosystem: string,
  logger: FixLogger,
): Promise<ValidationResult> {
  const result: ValidationResult = {
    auditPassed: null,
    lintPassed: null,
    testsPassed: null,
    testsSkipped: false,
    notes: [],
  };

  clearLLMKeys();

  // Safe install (lockfile regeneration)
  const installCmd = getSafeInstallCommand(ecosystem);
  if (installCmd) {
    try {
      await logger.info('validate', `Running: ${installCmd}`);
      execSync(installCmd, { cwd: workDir, timeout: 120_000, stdio: 'pipe' });
      await logger.success('validate', 'Install succeeded');
    } catch (err: any) {
      const msg = err.stderr?.toString().slice(0, 500) || err.message;
      result.notes.push(`Install failed: ${msg}. Lockfile may need manual regeneration.`);
      await logger.warn('validate', `Install failed: ${msg}`);
    }
  }

  // Audit
  const auditCmd = getAuditCommand(ecosystem);
  if (auditCmd) {
    try {
      await logger.info('validate', `Running audit: ${auditCmd}`);
      execSync(auditCmd, { cwd: workDir, timeout: 60_000, stdio: 'pipe' });
      result.auditPassed = true;
      await logger.success('validate', 'Audit passed — no remaining vulnerabilities');
    } catch {
      result.auditPassed = false;
      result.notes.push('Audit tool reports remaining vulnerabilities.');
      await logger.warn('validate', 'Audit reports remaining vulnerabilities');
    }
  }

  // Tests
  const testCmd = getTestCommand(ecosystem, workDir);
  if (testCmd) {
    try {
      await logger.info('validate', `Running tests: ${testCmd}`);
      execSync(testCmd, { cwd: workDir, timeout: 120_000, stdio: 'pipe' });
      result.testsPassed = true;
      await logger.success('validate', 'Tests passed');
    } catch {
      result.testsPassed = false;
      result.notes.push('Tests failed after fix. Please verify locally.');
      await logger.warn('validate', 'Tests failed after fix');
    }
  } else {
    result.testsSkipped = true;
    result.notes.push('No test command detected.');
    await logger.info('validate', 'No test command detected — skipping tests');
  }

  return result;
}
