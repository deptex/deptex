import { SupabaseClient } from '@supabase/supabase-js';

const SECRET_PATTERNS = [
  /ghp_[A-Za-z0-9]{36}/g,
  /gho_[A-Za-z0-9]{36}/g,
  /github_pat_[A-Za-z0-9_]{82}/g,
  /glpat-[A-Za-z0-9_-]{20,}/g,
  /Bearer [A-Za-z0-9._-]+/g,
  /oauth2:[^@\s]+@/g,
  /x-token-auth:[^@\s]+@/g,
  /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,
  /sk-[A-Za-z0-9]{20,}/g,
  /sk-ant-[A-Za-z0-9_-]{20,}/g,
];

function sanitize(message: string): string {
  let result = message;
  for (const pattern of SECRET_PATTERNS) {
    result = result.replace(pattern, '[REDACTED]');
  }
  return result;
}

export type FixStep =
  | 'init'
  | 'clone'
  | 'aider'
  | 'validate'
  | 'push'
  | 'pr'
  | 'complete';

export type LogLevel = 'info' | 'success' | 'warning' | 'error';

export class FixLogger {
  private supabase: SupabaseClient;
  private projectId: string;
  private runId: string;

  constructor(supabase: SupabaseClient, projectId: string, runId: string) {
    this.supabase = supabase;
    this.projectId = projectId;
    this.runId = runId;
  }

  async info(step: FixStep, message: string, metadata?: Record<string, unknown>): Promise<void> {
    await this.log(step, 'info', message, undefined, metadata);
  }

  async success(step: FixStep, message: string, durationMs?: number, metadata?: Record<string, unknown>): Promise<void> {
    await this.log(step, 'success', message, durationMs, metadata);
  }

  async warn(step: FixStep, message: string, metadata?: Record<string, unknown>): Promise<void> {
    await this.log(step, 'warning', message, undefined, metadata);
  }

  async error(step: FixStep, message: string, error?: unknown, metadata?: Record<string, unknown>): Promise<void> {
    const errorMeta: Record<string, unknown> = { ...metadata };
    if (error instanceof Error) {
      errorMeta.error_message = sanitize(error.message);
    } else if (error) {
      errorMeta.error_message = sanitize(String(error));
    }
    await this.log(step, 'error', message, undefined, errorMeta);
  }

  log(step: string, level: string, data: string): void;
  log(step: FixStep, level: LogLevel, message: string, durationMs?: number, metadata?: Record<string, unknown>): Promise<void>;
  log(
    step: string,
    level: string,
    message: string,
    durationMs?: number,
    metadata?: Record<string, unknown>,
  ): void | Promise<void> {
    const sanitizedMessage = sanitize(message);
    console.log(`[AIDER] [${step}] [${level}] ${sanitizedMessage}`);

    const insertOp = this.supabase.from('extraction_logs').insert({
      project_id: this.projectId,
      run_id: this.runId,
      step,
      level,
      message: sanitizedMessage,
      duration_ms: durationMs ?? null,
      metadata: metadata ? JSON.parse(JSON.stringify(metadata)) : null,
    });

    const p = Promise.resolve(insertOp).then(() => {}).catch(() => {});
    void p;

    if (durationMs !== undefined || metadata !== undefined) {
      return Promise.resolve(insertOp).then(() => {}).catch(() => {});
    }
  }
}
