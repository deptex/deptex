import type { SupabaseClient } from '@supabase/supabase-js';

const SECRET_PATTERNS = [
  /ghp_[A-Za-z0-9]{36}/g,
  /gho_[A-Za-z0-9]{36}/g,
  /github_pat_[A-Za-z0-9_]{82}/g,
  /Bearer [A-Za-z0-9._-]+/g,
  /x-access-token:[^@\s]+@/g,
  /sk-ant-api03-[A-Za-z0-9_-]{20,}/g,
  /sk-[A-Za-z0-9]{32,}/g,
  /AIza[A-Za-z0-9_-]{35}/g,
];

function sanitize(message: string): string {
  let result = message;
  for (const pattern of SECRET_PATTERNS) {
    result = result.replace(pattern, '[REDACTED]');
  }
  return result;
}

export type FixLogStep =
  | 'init'
  | 'clone'
  | 'setup'
  | 'plan'
  | 'edit'
  | 'tests'
  | 'repair'
  | 'pr'
  | 'complete';

export type LogLevel = 'info' | 'success' | 'warning' | 'error';

export class FixLogger {
  constructor(
    private supabase: SupabaseClient,
    private projectId: string,
    private runId: string,
  ) {}

  async info(step: FixLogStep, message: string, metadata?: Record<string, unknown>) {
    await this.log(step, 'info', message, undefined, metadata);
  }

  async success(step: FixLogStep, message: string, durationMs?: number, metadata?: Record<string, unknown>) {
    await this.log(step, 'success', message, durationMs, metadata);
  }

  async warn(step: FixLogStep, message: string, metadata?: Record<string, unknown>) {
    await this.log(step, 'warning', message, undefined, metadata);
  }

  async error(step: FixLogStep, message: string, error?: unknown, metadata?: Record<string, unknown>) {
    const errorMeta: Record<string, unknown> = { ...metadata };
    if (error instanceof Error) {
      errorMeta.error_message = sanitize(error.message);
      errorMeta.error_stack = sanitize(error.stack ?? '');
    } else if (error) {
      errorMeta.error_message = sanitize(String(error));
    }
    await this.log(step, 'error', message, undefined, errorMeta);
  }

  private async log(
    step: FixLogStep,
    level: LogLevel,
    message: string,
    durationMs?: number,
    metadata?: Record<string, unknown>,
  ) {
    const sanitized = sanitize(message);
    console.log(`[FIX] [${step}] [${level}] ${sanitized}`);
    try {
      // extraction_logs is the shared streaming surface — same Realtime
      // subscription as extraction. job_type marker in metadata lets the UI
      // filter fix runs from extraction runs.
      await this.supabase.from('extraction_logs').insert({
        project_id: this.projectId,
        run_id: this.runId,
        step,
        level,
        message: sanitized,
        duration_ms: durationMs ?? null,
        metadata: { ...(metadata ?? {}), job_type: 'fix' },
      });
    } catch {
      // fire-and-forget
    }
  }
}
