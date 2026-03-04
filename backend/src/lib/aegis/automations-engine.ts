/**
 * Phase 7B: Aegis automations engine for scheduled and event-driven jobs.
 *
 * Handles:
 * - Cron-based scheduled automations (checkDueAutomations via QStash cron every 5 min)
 * - Event trigger matching (matchEventTrigger)
 * - Template instantiation (8 predefined configs)
 * - Failure tracking (auto-disable after 3 consecutive failures)
 */

import { supabase } from '../../lib/supabase';
import { executeMessage, ExecutionContext } from './executor';

// ─── Types ───

export interface AutomationTemplate {
  id: string;
  name: string;
  description: string;
  cronExpression?: string;
  timezone?: string;
  eventType?: string;
  prompt: string;
  templateConfig?: Record<string, unknown>;
}

export interface AutomationRecord {
  id: string;
  organization_id: string;
  name: string;
  description?: string;
  schedule?: string;
  enabled: boolean;
  cron_expression?: string;
  timezone?: string;
  automation_type?: string;
  delivery_config?: Record<string, unknown>;
  template_config?: Record<string, unknown>;
  last_run_status?: string;
  last_run_output?: string;
  run_count?: number;
  consecutive_failures?: number;
}

// ─── Predefined templates (8 configs) ───

export const AUTOMATION_TEMPLATES: AutomationTemplate[] = [
  {
    id: 'daily_security_briefing',
    name: 'Daily Security Briefing',
    description: 'Weekdays at 7am: New CVEs, EPSS changes, anomalies',
    cronExpression: '0 7 * * 1-5',
    timezone: 'UTC',
    prompt: 'Generate a daily security briefing for the organization. Include: new CVEs affecting our dependencies, significant EPSS score changes, Watchtower anomalies, and any stale vulnerabilities that need attention.',
    templateConfig: { focus: ['cve', 'epss', 'anomalies', 'stale_vulns'] },
  },
  {
    id: 'weekly_security_digest',
    name: 'Weekly Security Digest',
    description: 'Monday 9am: Full posture report with week-over-week trends',
    cronExpression: '0 9 * * 1',
    timezone: 'UTC',
    prompt: 'Generate a weekly security digest. Include: overall security posture, week-over-week trends in vulnerability counts, compliance status, top risks, and recommended actions.',
    templateConfig: { format: 'digest', include_trends: true },
  },
  {
    id: 'monthly_compliance_report',
    name: 'Monthly Compliance Report',
    description: '1st of month 9am: License compliance, policy adherence',
    cronExpression: '0 9 1 * *',
    timezone: 'UTC',
    prompt: 'Generate a monthly compliance report. Include: license compliance summary, policy adherence status, SBOM freshness, and any policy violations or exceptions that need review.',
    templateConfig: { focus: ['license', 'policy', 'sbom'] },
  },
  {
    id: 'critical_cve_alert',
    name: 'Critical CVE Alert',
    description: 'Event-driven: extraction_completed with critical vulns',
    eventType: 'extraction_completed',
    prompt: 'A critical CVE affects our dependencies. Assess blast radius: which projects use it, reachability, affected functions. Prioritize remediation and suggest fix actions.',
    templateConfig: { min_severity: 'critical', include_blast_radius: true },
  },
  {
    id: 'pre_release_gate',
    name: 'Pre-Release Security Gate',
    description: 'Event-driven: tag push',
    eventType: 'tag_push',
    prompt: 'A new tag is being released. Run full compliance check: policy evaluation, vulnerability status, license obligations. Report any blockers before release.',
    templateConfig: { gate_type: 'pre_release' },
  },
  {
    id: 'dependency_health_audit',
    name: 'Dependency Health Audit',
    description: 'Friday 10am: Reputation changes, maintenance drops',
    cronExpression: '0 10 * * 5',
    timezone: 'UTC',
    prompt: 'Run a dependency health audit. Report: packages with declining reputation scores, maintenance drops, deprecation warnings, and packages that may need replacement.',
    templateConfig: { focus: ['reputation', 'maintenance', 'deprecations'] },
  },
  {
    id: 'stale_vulnerability_report',
    name: 'Stale Vulnerability Report',
    description: 'Wednesday 10am: Unfixed vulns older than threshold',
    cronExpression: '0 10 * * 3',
    timezone: 'UTC',
    prompt: 'Generate a stale vulnerability report. List vulnerabilities that have been open for more than 7 days, grouped by severity. Include affected projects and suggested fix strategies.',
    templateConfig: { stale_days: 7 },
  },
  {
    id: 'new_dependency_review',
    name: 'New Dependency Review',
    description: 'Event-driven: new dep detected',
    eventType: 'new_dependency_detected',
    prompt: 'A new dependency was added to a project. Perform risk assessment: reputation score, known vulnerabilities, license compatibility, maintenance health. Suggest alternatives if risky.',
    templateConfig: { focus: ['risk', 'alternatives'] },
  },
];

// ─── Cron matching (5-field: minute hour day-of-month month day-of-week) ───

const DAY_OF_WEEK_MAP: Record<string, number> = {
  Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6,
};

function parseCronField(field: string, value: number): boolean {
  if (field === '*') return true;
  const expand = (s: string): number[] => {
    s = s.trim();
    if (s.includes('/')) {
      const [range, stepStr] = s.split('/');
      const step = parseInt(stepStr.trim(), 10) || 1;
      return expand(range).filter((_, i) => i % step === 0);
    }
    if (s.includes('-')) {
      const [a, b] = s.split('-').map(x => parseInt(x.trim(), 10));
      const out: number[] = [];
      for (let i = a; i <= b; i++) out.push(i);
      return out;
    }
    if (s.includes(',')) {
      return s.split(',').flatMap(x => expand(x.trim()));
    }
    const n = parseInt(s, 10);
    return isNaN(n) ? [] : [n];
  };
  const list = field.split(',').flatMap(s => expand(s));
  return list.length > 0 && list.includes(value);
}

/**
 * Check if the current time matches a cron expression.
 * Supports standard 5-field: minute hour day-of-month month day-of-week
 * - minute: 0-59, hour: 0-23, day-of-month: 1-31, month: 1-12
 * - day-of-week: 0-6 (0=Sunday, 1=Monday, ..., 6=Saturday). "7" also means Sunday.
 *
 * Supports: *, N, N-M, N,M,K, N-M/O (step)
 */
export function cronMatchesNow(cronExpression: string, timezone: string = 'UTC'): boolean {
  const parts = cronExpression.trim().split(/\s+/);
  if (parts.length < 5) return false;

  const now = new Date();
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    day: 'numeric',
    month: 'numeric',
    weekday: 'short',
  });
  const match = formatter.formatToParts(now);
  const getPart = (type: string) => match.find(p => p.type === type)?.value ?? '';

  const minute = parseInt(getPart('minute') || '0', 10);
  const hour = parseInt(getPart('hour') || '0', 10);
  const dayOfMonth = parseInt(getPart('day') || '1', 10);
  const month = parseInt(getPart('month') || '1', 10);
  const dayOfWeek = DAY_OF_WEEK_MAP[getPart('weekday')?.slice(0, 3) ?? ''] ?? 0;

  // day-of-week: cron 0-6 (Sun-Sat); "7" also means Sunday in some crons
  const dowMatch = parseCronField(parts[4], dayOfWeek) || (dayOfWeek === 0 && parseCronField(parts[4], 7));
  return (
    parseCronField(parts[0], minute) &&
    parseCronField(parts[1], hour) &&
    parseCronField(parts[2], dayOfMonth) &&
    parseCronField(parts[3], month) &&
    dowMatch
  );
}

// ─── Check due automations (called by QStash cron every 5 min) ───

/**
 * Query automations where enabled=true and cron_expression matches current time.
 * For each due automation, call runAutomation.
 */
export async function checkDueAutomations(): Promise<number> {
  const { data: automations, error } = await supabase
    .from('aegis_automations')
    .select('*')
    .eq('enabled', true)
    .not('cron_expression', 'is', null);

  if (error) {
    console.error('[Automations] Failed to fetch automations:', error);
    return 0;
  }

  let runCount = 0;
  for (const a of automations ?? []) {
    const rec = a as AutomationRecord;
    const tz = rec.timezone ?? 'UTC';
    if (rec.cron_expression && cronMatchesNow(rec.cron_expression, tz)) {
      await runAutomation(rec.id);
      runCount++;
    }
  }
  return runCount;
}

// ─── Run single automation ───

const CONSECUTIVE_FAILURE_THRESHOLD = 3;

/**
 * Load automation config, run Aegis execution, update last_run_* and run_count.
 * Auto-disables after 3 consecutive failures.
 * Note: aegis_automations may need a consecutive_failures column (default 0) for failure tracking.
 */
export async function runAutomation(automationId: string): Promise<void> {
  const { data: automation, error: loadError } = await supabase
    .from('aegis_automations')
    .select('*')
    .eq('id', automationId)
    .single();

  if (loadError || !automation) {
    console.error('[Automations] Automation not found:', automationId, loadError);
    return;
  }

  const rec = automation as AutomationRecord;
  if (!rec.enabled) return;

  const { data: org } = await supabase
    .from('organizations')
    .select('name')
    .eq('id', rec.organization_id)
    .single();

  const context: ExecutionContext = {
    organizationId: rec.organization_id,
    userId: rec.organization_id,
    organizationName: org?.name ?? 'Organization',
  };

  const prompt = rec.template_config?.prompt
    ? (rec.template_config.prompt as string)
    : rec.description ?? `Run automation: ${rec.name}`;

  try {
    const result = await executeMessage(prompt, context);
    const output = typeof result.message === 'string' ? result.message : JSON.stringify(result.message);

    const consecutiveFailures = (rec.consecutive_failures as number) ?? 0;

    await supabase
      .from('aegis_automations')
      .update({
        last_run_status: 'success',
        last_run_output: output,
        run_count: ((rec.run_count as number) ?? 0) + 1,
        consecutive_failures: 0,
        last_run_at: new Date().toISOString(),
      })
      .eq('id', automationId);
  } catch (err: any) {
    const consecutiveFailures = ((rec.consecutive_failures as number) ?? 0) + 1;
    const shouldDisable = consecutiveFailures >= CONSECUTIVE_FAILURE_THRESHOLD;

    await supabase
      .from('aegis_automations')
      .update({
        last_run_status: 'failed',
        last_run_output: err.message ?? 'Unknown error',
        run_count: ((rec.run_count as number) ?? 0) + 1,
        consecutive_failures: consecutiveFailures,
        last_run_at: new Date().toISOString(),
        ...(shouldDisable && { enabled: false }),
      })
      .eq('id', automationId);

    if (shouldDisable) {
      console.warn(`[Automations] Auto-disabled automation ${automationId} after ${CONSECUTIVE_FAILURE_THRESHOLD} consecutive failures`);
    }
  }
}

// ─── Event trigger matching ───

/**
 * Query aegis_event_triggers for matching event_type (and optionally filter_criteria).
 * Run associated automations for each match.
 */
export async function matchEventTrigger(
  eventType: string,
  payload: Record<string, unknown>,
  organizationId: string
): Promise<number> {
  const { data: triggers, error } = await supabase
    .from('aegis_event_triggers')
    .select('id, automation_id, filter_criteria')
    .eq('organization_id', organizationId)
    .eq('event_type', eventType)
    .eq('enabled', true);

  if (error) {
    console.error('[Automations] Failed to fetch event triggers:', error);
    return 0;
  }

  let runCount = 0;
  for (const t of triggers ?? []) {
    const filter = (t as any).filter_criteria as Record<string, unknown> | null;
    if (filter && !matchesFilter(filter, payload)) continue;

    const automationId = (t as any).automation_id;
    if (automationId) {
      await runAutomation(automationId);
      runCount++;
    }
  }
  return runCount;
}

function matchesFilter(filter: Record<string, unknown>, payload: Record<string, unknown>): boolean {
  for (const [key, expected] of Object.entries(filter)) {
    const actual = payload[key];
    if (expected === actual) continue;
    if (typeof expected === 'object' && actual && typeof actual === 'object') {
      if (!matchesFilter(expected as Record<string, unknown>, actual as Record<string, unknown>))
        return false;
    } else {
      return false;
    }
  }
  return true;
}
