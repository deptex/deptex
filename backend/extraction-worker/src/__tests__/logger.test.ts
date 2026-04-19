/**
 * Phase 2M: ExtractionLogger unit tests
 */

process.env.SUPABASE_URL = 'https://fake.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'fake-key';

const mockInsert = jest.fn().mockResolvedValue({ data: null, error: null });
const mockFrom = jest.fn().mockReturnValue({ insert: mockInsert });

const mockSupabase = {
  from: mockFrom,
};

import { ExtractionLogger } from '../logger';

describe('ExtractionLogger', () => {
  const projectId = 'proj-1';
  const runId = 'run-1';
  let logger: ExtractionLogger;

  beforeEach(() => {
    jest.clearAllMocks();
    logger = new ExtractionLogger(mockSupabase as any, projectId, runId);
  });

  it('info() inserts row with correct step, level, message, run_id, project_id', async () => {
    await logger.info('cloning', 'Cloning repository...');

    expect(mockFrom).toHaveBeenCalledWith('extraction_logs');
    expect(mockInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        project_id: projectId,
        run_id: runId,
        step: 'cloning',
        level: 'info',
        message: 'Cloning repository...',
        duration_ms: null,
        metadata: null,
      })
    );
  });

  it('success() includes duration_ms', async () => {
    await logger.success('sbom', 'SBOM generated', 1234);

    expect(mockInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        step: 'sbom',
        level: 'success',
        message: 'SBOM generated',
        duration_ms: 1234,
      })
    );
  });

  it('warn() sets level to warning', async () => {
    await logger.warn('vuln_scan', 'Scan skipped');

    expect(mockInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'warning',
        message: 'Scan skipped',
      })
    );
  });

  it('error() includes error message in metadata', async () => {
    await logger.error('cloning', 'Clone failed', new Error('Connection refused'));

    expect(mockInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        level: 'error',
        message: 'Clone failed',
        metadata: expect.objectContaining({
          error_message: 'Connection refused',
        }),
      })
    );
  });

  it('logger failure (Supabase down) does NOT throw — error is caught silently', async () => {
    mockInsert.mockRejectedValueOnce(new Error('Connection refused'));

    await expect(logger.info('cloning', 'Test')).resolves.not.toThrow();
  });

  it('token patterns are redacted from log messages', async () => {
    await logger.info('cloning', 'Token: ghp_abc123def456ghi789jkl012mno345pqr678');

    expect(mockInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Token: [REDACTED]',
      })
    );
  });

  it('GitLab PAT redacted', async () => {
    await logger.info('clone', 'Using glpat-abc123def456789012345678'); // glpat needs 20+ chars to match

    expect(mockInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Using [REDACTED]',
      })
    );
  });

  it('Bearer tokens redacted', async () => {
    await logger.info('api', 'Auth: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxx.yyy');

    expect(mockInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Auth: [REDACTED]',
      })
    );
  });

  it('clone URLs with embedded tokens redacted', async () => {
    await logger.info('clone', 'Clone from https://oauth2:secret@github.com/owner/repo');

    // Pattern replaces oauth2:secret@ entirely with [REDACTED]
    expect(mockInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Clone from https://[REDACTED]github.com/owner/repo',
      })
    );
  });
});
