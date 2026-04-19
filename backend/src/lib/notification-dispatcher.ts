/**
 * Phase 9: Core notification dispatch engine.
 *
 * When QStash delivers a dispatch job, this engine:
 * 1. Loads the event from notification_events
 * 2. Loads ALL matching notification rules (org + team + project, additive cascade)
 * 3. Builds the enriched context object
 * 4. Evaluates each rule's trigger code in the Function() sandbox
 * 5. Dispatches to destinations, tracking deliveries
 */

import { supabase } from '../lib/supabase';
import { executeNotificationTrigger } from './notification-validator';
import {
  dispatchToDestination,
  buildDefaultMessage,
  enforceMessageLimits,
  NotificationMessage,
  IntegrationConnection,
  NotificationEvent,
} from './destination-dispatchers';
import { checkOrgRateLimit, checkDestinationRateLimit } from './notification-rate-limiter';
import crypto from 'crypto';

// ─── Types ───────────────────────────────────────────────────────────────────

interface MatchedRule {
  id: string;
  name: string;
  trigger_type: string;
  custom_code: string | null;
  destinations: RuleDestination[];
  active: boolean;
  min_depscore_threshold: number | null;
  snoozed_until: string | null;
  dry_run: boolean;
  scope: 'organization' | 'team' | 'project';
  scope_id: string;
}

interface RuleDestination {
  type: string;
  integration_id?: string;
  config?: Record<string, any>;
}

interface RefreshedTokens {
  access_token: string;
  refresh_token?: string;
  expires_at: string;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const TICKETING_PROVIDERS = new Set(['jira', 'linear', 'asana']);
const OAUTH_PROVIDERS = new Set(['jira', 'asana', 'slack', 'discord', 'bitbucket', 'gitlab']);
const MAX_IN_APP_BATCH = 500;
const HEALTH_FAILURE_THRESHOLD = 3;
const LOCK_TTL_MS = 30_000;
const LOCK_WAIT_MS = 5_000;

const OAUTH_REFRESH_ENDPOINTS: Record<string, { url: string; clientIdEnv: string; clientSecretEnv: string }> = {
  jira: { url: 'https://auth.atlassian.com/oauth/token', clientIdEnv: 'JIRA_CLIENT_ID', clientSecretEnv: 'JIRA_CLIENT_SECRET' },
  asana: { url: 'https://app.asana.com/-/oauth_token', clientIdEnv: 'ASANA_CLIENT_ID', clientSecretEnv: 'ASANA_CLIENT_SECRET' },
  slack: { url: 'https://slack.com/api/oauth.v2.access', clientIdEnv: 'SLACK_CLIENT_ID', clientSecretEnv: 'SLACK_CLIENT_SECRET' },
  discord: { url: 'https://discord.com/api/v10/oauth2/token', clientIdEnv: 'DISCORD_CLIENT_ID', clientSecretEnv: 'DISCORD_CLIENT_SECRET' },
  gitlab: { url: 'https://gitlab.com/oauth/token', clientIdEnv: 'GITLAB_CLIENT_ID', clientSecretEnv: 'GITLAB_CLIENT_SECRET' },
  bitbucket: { url: 'https://bitbucket.org/site/oauth2/access_token', clientIdEnv: 'BITBUCKET_CLIENT_ID', clientSecretEnv: 'BITBUCKET_CLIENT_SECRET' },
};

// ─── Structured Logging ──────────────────────────────────────────────────────

function notificationLog(
  level: 'info' | 'warn' | 'error',
  message: string,
  context: Record<string, any>,
): void {
  console[level](
    JSON.stringify({
      component: 'notification-dispatcher',
      timestamp: new Date().toISOString(),
      level,
      message,
      ...context,
    }),
  );
}

// ─── Redis (lazy init for token refresh mutex) ───────────────────────────────

let _redis: any = null;

function getRedis(): any {
  if (_redis) return _redis;
  const url = process.env.UPSTASH_REDIS_URL;
  const token = process.env.UPSTASH_REDIS_TOKEN;
  if (!url || !token) return null;
  const { Redis } = require('@upstash/redis');
  _redis = new Redis({ url, token });
  return _redis;
}

// ═════════════════════════════════════════════════════════════════════════════
// Public API
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Process a single notification event: evaluate all matching rules,
 * create deliveries, dispatch to destinations, and create in-app notifications.
 */
export async function dispatchNotification(eventId: string): Promise<void> {
  const { data: event, error: loadErr } = await supabase
    .from('notification_events')
    .select('*')
    .eq('id', eventId)
    .single();

  if (loadErr || !event) {
    notificationLog('error', 'Event not found', { eventId, error: loadErr?.message });
    return;
  }

  if (event.status !== 'pending') {
    notificationLog('info', 'Event already processed', { eventId, status: event.status });
    return;
  }

  await supabase
    .from('notification_events')
    .update({ status: 'dispatching' })
    .eq('id', eventId);

  try {
    // Phase 17: Check incident triggers inline during dispatch
    try {
      const { checkIncidentTriggers } = require('./incident-triggers');
      await checkIncidentTriggers(event);
    } catch (_) {
      // Non-critical — incident trigger check failures should not block notification dispatch
    }

    const rules = await resolveMatchingRules(event);

    if (rules.length === 0) {
      notificationLog('info', 'No matching rules', { eventId, eventType: event.event_type });
      await supabase
        .from('notification_events')
        .update({ status: 'dispatched', dispatched_at: new Date().toISOString() })
        .eq('id', eventId);
      return;
    }

    const context = await buildNotificationContext(event);
    let deliveriesCreated = 0;

    for (const rule of rules) {
      if (rule.snoozed_until && new Date(rule.snoozed_until) > new Date()) continue;

      if (
        rule.min_depscore_threshold != null &&
        event.event_type === 'vulnerability_discovered' &&
        typeof event.payload?.depscore === 'number' &&
        event.payload.depscore < rule.min_depscore_threshold
      ) {
        continue;
      }

      let shouldNotify = false;
      let customMessage: string | undefined;
      let customTitle: string | undefined;
      let customPriority: string | undefined;

      if (rule.custom_code?.trim()) {
        const result = await executeNotificationTrigger(
          rule.custom_code,
          context,
          event.organization_id,
        );
        shouldNotify = result.notify;
        customMessage = result.message;
        customTitle = result.title;
        customPriority = result.priority;
      } else {
        shouldNotify = true;
      }

      if (!shouldNotify) continue;

      const destinations: RuleDestination[] = Array.isArray(rule.destinations)
        ? rule.destinations
        : [];

      for (const dest of destinations) {
        if (await shouldDedup(eventId, dest.integration_id ?? null)) {
          notificationLog('info', 'Dedup skipped', { eventId, ruleId: rule.id, integrationId: dest.integration_id });
          continue;
        }

        const { error: insertErr } = await supabase
          .from('notification_deliveries')
          .insert({
            event_id: eventId,
            rule_id: rule.id,
            organization_id: event.organization_id,
            destination: dest,
            integration_id: dest.integration_id || null,
            status: 'pending',
            dry_run: rule.dry_run || false,
            custom_message: customMessage || null,
            custom_title: customTitle || null,
            custom_priority: customPriority || null,
          });

        if (!insertErr) deliveriesCreated++;
      }
    }

    notificationLog('info', 'Deliveries created', {
      eventId,
      deliveriesCreated,
      rulesEvaluated: rules.length,
    });

    await processDeliveries(eventId, event.organization_id);

    const defaultMsg = buildDefaultMessage(event as NotificationEvent, context);
    await createInAppNotifications(event, defaultMsg);

    const { count: failedCount } = await supabase
      .from('notification_deliveries')
      .select('id', { count: 'exact', head: true })
      .eq('event_id', eventId)
      .eq('status', 'failed');

    const { count: totalCount } = await supabase
      .from('notification_deliveries')
      .select('id', { count: 'exact', head: true })
      .eq('event_id', eventId);

    const allFailed = (totalCount ?? 0) > 0 && failedCount === totalCount;

    await supabase
      .from('notification_events')
      .update({
        status: allFailed ? 'failed' : 'dispatched',
        dispatched_at: new Date().toISOString(),
      })
      .eq('id', eventId);

    notificationLog('info', 'Dispatch complete', {
      eventId,
      finalStatus: allFailed ? 'failed' : 'dispatched',
      totalDeliveries: totalCount,
      failedDeliveries: failedCount,
    });
  } catch (err: any) {
    notificationLog('error', 'Dispatch failed', { eventId, error: err.message });
    await supabase
      .from('notification_events')
      .update({ status: 'failed' })
      .eq('id', eventId);
  }
}

/**
 * Dispatch a batch of events grouped by a shared batch_id.
 * Groups events by (org, project, event_type) and sends summary notifications
 * so that e.g. 50 dependency_added events become one summary message.
 */
export async function dispatchNotificationBatch(batchId: string): Promise<void> {
  const { data: events, error } = await supabase
    .from('notification_events')
    .select('*')
    .eq('batch_id', batchId)
    .eq('status', 'pending');

  if (error || !events?.length) {
    notificationLog('warn', 'No pending batch events', { batchId, error: error?.message });
    return;
  }

  const groups = new Map<string, any[]>();
  for (const event of events) {
    const key = `${event.organization_id}:${event.project_id ?? 'null'}:${event.event_type}`;
    const group = groups.get(key);
    if (group) group.push(event);
    else groups.set(key, [event]);
  }

  for (const [groupKey, groupEvents] of groups) {
    const representative = groupEvents[0];
    const eventIds = groupEvents.map((e: any) => e.id);

    await supabase
      .from('notification_events')
      .update({ status: 'dispatching' })
      .in('id', eventIds);

    try {
      const baseContext = await buildNotificationContext(representative);

      const byType: Record<string, number> = {};
      for (const e of groupEvents) {
        byType[e.event_type] = (byType[e.event_type] || 0) + 1;
      }

      const summaryContext: Record<string, any> = {
        ...baseContext,
        batch: {
          total: groupEvents.length,
          by_type: byType,
          events: groupEvents.map((e: any) => ({
            type: e.event_type,
            dependency: e.payload?.dependency_name
              ? { name: e.payload.dependency_name, version: e.payload.version }
              : undefined,
            vulnerability: e.payload?.osv_id
              ? { osv_id: e.payload.osv_id, severity: e.payload.severity }
              : undefined,
          })),
        },
      };

      const rules = await resolveMatchingRules(representative);

      for (const rule of rules) {
        if (rule.snoozed_until && new Date(rule.snoozed_until) > new Date()) continue;

        let shouldNotify = false;
        let customMessage: string | undefined;
        let customTitle: string | undefined;

        if (rule.custom_code?.trim()) {
          const result = await executeNotificationTrigger(
            rule.custom_code,
            summaryContext,
            representative.organization_id,
          );
          shouldNotify = result.notify;
          customMessage = result.message;
          customTitle = result.title;
        } else {
          shouldNotify = true;
        }

        if (!shouldNotify) continue;

        const destinations: RuleDestination[] = Array.isArray(rule.destinations)
          ? rule.destinations
          : [];

        for (const dest of destinations) {
          if (await shouldDedup(representative.id, dest.integration_id ?? null)) continue;

          await supabase.from('notification_deliveries').insert({
            event_id: representative.id,
            rule_id: rule.id,
            organization_id: representative.organization_id,
            destination: dest,
            integration_id: dest.integration_id || null,
            status: 'pending',
            dry_run: rule.dry_run || false,
            custom_message: customMessage || null,
            custom_title: customTitle || null,
          });
        }
      }

      await processDeliveries(representative.id, representative.organization_id);

      const defaultMsg = buildDefaultMessage(representative as NotificationEvent, summaryContext);
      if (groupEvents.length > 1) {
        defaultMsg.title = `[${groupEvents.length} events] ${defaultMsg.title}`;
      }
      await createInAppNotifications(representative, defaultMsg);

      await supabase
        .from('notification_events')
        .update({ status: 'dispatched', dispatched_at: new Date().toISOString() })
        .in('id', eventIds);
    } catch (err: any) {
      notificationLog('error', 'Batch group failed', { batchId, groupKey, error: err.message });
      await supabase
        .from('notification_events')
        .update({ status: 'failed' })
        .in('id', eventIds);
    }
  }

  notificationLog('info', 'Batch complete', { batchId, groups: groups.size, totalEvents: events.length });
}

/**
 * Enrich a notification event with project, dependency, and vulnerability data
 * from the database to build the full context object for trigger code evaluation.
 */
export async function buildNotificationContext(
  event: any,
): Promise<Record<string, any>> {
  const context: Record<string, any> = {
    event: {
      type: event.event_type,
      timestamp: event.created_at,
      source: event.source,
    },
    project: null,
    dependency: null,
    vulnerability: null,
    pr: null,
    previous: event.payload?.previous ?? null,
    batch: null,
  };

  // ── Project ──
  if (event.project_id) {
    try {
      const { data: project } = await supabase
        .from('projects')
        .select('id, name, health_score, framework, asset_tier_id, status_id')
        .eq('id', event.project_id)
        .single();

      if (project) {
        let tierName = 'Unknown';
        let tierRank = 99;
        if (project.asset_tier_id) {
          const { data: tier } = await supabase
            .from('organization_asset_tiers')
            .select('name, rank')
            .eq('id', project.asset_tier_id)
            .single();
          if (tier) { tierName = tier.name; tierRank = tier.rank; }
        }

        let statusName = 'Unknown';
        let statusIsPassing = true;
        if (project.status_id) {
          const { data: status } = await supabase
            .from('organization_statuses')
            .select('name, is_passing')
            .eq('id', project.status_id)
            .single();
          if (status) { statusName = status.name; statusIsPassing = status.is_passing ?? true; }
        }

        const { count: depsCount } = await supabase
          .from('project_dependencies')
          .select('id', { count: 'exact', head: true })
          .eq('project_id', event.project_id);

        let teamName: string | null = null;
        if (event.team_id) {
          const { data: team } = await supabase
            .from('teams')
            .select('name')
            .eq('id', event.team_id)
            .single();
          teamName = team?.name ?? null;
        }

        context.project = {
          id: project.id,
          name: project.name,
          asset_tier: tierName,
          asset_tier_rank: tierRank,
          health_score: project.health_score ?? 0,
          status: statusName,
          status_is_passing: statusIsPassing,
          dependencies_count: depsCount ?? 0,
          team_name: teamName,
        };
      }
    } catch (err: any) {
      notificationLog('warn', 'Project enrichment failed', { projectId: event.project_id, error: err.message });
    }
  }

  if (!context.project && event.payload?.project_name) {
    context.project = {
      id: event.project_id ?? null,
      name: event.payload.project_name,
      asset_tier: event.payload.asset_tier || 'Unknown',
      asset_tier_rank: 99,
      health_score: event.payload.health_score ?? 0,
      status: 'Unknown',
      status_is_passing: true,
      dependencies_count: 0,
      team_name: null,
    };
  }

  // ── Dependency ──
  const depName: string | undefined = event.payload?.dependency_name;
  if (depName) {
    try {
      const { data: dep } = await supabase
        .from('dependencies')
        .select('id, name, license, score, openssf_score, weekly_downloads, is_malicious')
        .eq('name', depName)
        .single();

      if (dep) {
        const version: string = event.payload.version || event.payload.new_version || 'unknown';

        let versionData: any = null;
        if (version !== 'unknown') {
          const { data: dv } = await supabase
            .from('dependency_versions')
            .select('slsa_level, registry_integrity_status, install_scripts_status, entropy_analysis_status')
            .eq('dependency_id', dep.id)
            .eq('version', version)
            .maybeSingle();
          versionData = dv;
        }

        const { data: vulns } = await supabase
          .from('dependency_vulnerabilities')
          .select('osv_id, severity, cvss_score, cisa_kev')
          .eq('dependency_id', dep.id)
          .limit(20);

        let projectDepData: any = null;
        if (event.project_id) {
          const { data: pd } = await supabase
            .from('project_dependencies')
            .select('is_direct, environment')
            .eq('project_id', event.project_id)
            .eq('dependency_id', dep.id)
            .maybeSingle();
          projectDepData = pd;
        }

        context.dependency = {
          name: dep.name,
          version,
          license: dep.license,
          is_direct: projectDepData?.is_direct ?? event.payload.is_direct ?? true,
          is_dev_dependency: projectDepData?.environment === 'development',
          environment: projectDepData?.environment || 'production',
          score: dep.score ?? 0,
          dependency_score: dep.score ?? 0,
          openssf_score: dep.openssf_score ?? null,
          weekly_downloads: dep.weekly_downloads ?? null,
          malicious_indicator: dep.is_malicious
            ? (event.payload.malicious_indicator || { source: 'deptex', confidence: 'high', reason: 'Flagged as malicious' })
            : null,
          slsa_level: versionData?.slsa_level ?? 0,
          registry_integrity_status: versionData?.registry_integrity_status ?? null,
          install_scripts_status: versionData?.install_scripts_status ?? null,
          entropy_analysis_status: versionData?.entropy_analysis_status ?? null,
          vulnerabilities: (vulns || []).map((v: any) => ({
            osv_id: v.osv_id,
            severity: v.severity,
            cvss_score: v.cvss_score ?? 0,
            depscore: 0,
            is_reachable: false,
            cisa_kev: v.cisa_kev ?? false,
          })),
        };
      }
    } catch (err: any) {
      notificationLog('warn', 'Dependency enrichment failed', { depName, error: err.message });
    }
  }

  // ── Vulnerability ──
  const osvId: string | undefined = event.payload?.osv_id;
  if (osvId) {
    try {
      const { data: vuln } = await supabase
        .from('dependency_vulnerabilities')
        .select('osv_id, severity, cvss_score, fixed_versions, summary')
        .eq('osv_id', osvId)
        .limit(1)
        .maybeSingle();

      context.vulnerability = {
        osv_id: osvId,
        severity: vuln?.severity || event.payload.severity || 'unknown',
        cvss_score: vuln?.cvss_score ?? event.payload.cvss_score ?? 0,
        epss_score: event.payload.epss_score ?? 0,
        depscore: event.payload.depscore ?? 0,
        is_reachable: event.payload.is_reachable ?? false,
        cisa_kev: event.payload.cisa_kev ?? false,
        fixed_versions: vuln?.fixed_versions || event.payload.fixed_versions || [],
        summary: vuln?.summary || event.payload.summary || '',
      };
    } catch (err: any) {
      notificationLog('warn', 'Vulnerability enrichment failed', { osvId, error: err.message });
    }
  }

  // ── PR ──
  if (event.payload?.pr_number && event.project_id) {
    try {
      const { data: pr } = await supabase
        .from('project_pull_requests')
        .select(
          'pr_number, title, author, base_branch, head_branch, check_result, check_summary, deps_added, deps_updated, deps_removed, provider_url',
        )
        .eq('project_id', event.project_id)
        .eq('pr_number', event.payload.pr_number)
        .maybeSingle();

      if (pr) {
        context.pr = {
          number: pr.pr_number,
          title: pr.title || '',
          author: pr.author || '',
          base_branch: pr.base_branch || '',
          head_branch: pr.head_branch || '',
          check_result: pr.check_result || '',
          check_summary: pr.check_summary || '',
          deps_added: pr.deps_added ?? 0,
          deps_updated: pr.deps_updated ?? 0,
          deps_removed: pr.deps_removed ?? 0,
          provider_url: pr.provider_url || '',
        };
      }
    } catch (err: any) {
      notificationLog('warn', 'PR enrichment failed', { prNumber: event.payload.pr_number, error: err.message });
    }
  }

  return context;
}

// ═════════════════════════════════════════════════════════════════════════════
// Internal helpers
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Load active notification rules from all scopes (org + team + project).
 * Additive cascade: rules from all levels fire independently.
 * Weekly digest rules are excluded (those are cron-driven, not event-driven).
 */
async function resolveMatchingRules(event: any): Promise<MatchedRule[]> {
  const rules: MatchedRule[] = [];

  const mapRule = (
    r: any,
    scope: 'organization' | 'team' | 'project',
    scopeId: string,
  ): MatchedRule => ({
    id: r.id,
    name: r.name,
    trigger_type: r.trigger_type,
    custom_code: r.custom_code ?? null,
    destinations: Array.isArray(r.destinations) ? r.destinations : [],
    active: r.active,
    min_depscore_threshold: r.min_depscore_threshold ?? null,
    snoozed_until: r.snoozed_until ?? null,
    dry_run: r.dry_run ?? false,
    scope,
    scope_id: scopeId,
  });

  const { data: orgRules } = await supabase
    .from('organization_notification_rules')
    .select('*')
    .eq('organization_id', event.organization_id)
    .eq('active', true);

  for (const r of orgRules || []) {
    if (r.trigger_type !== 'weekly_digest') {
      rules.push(mapRule(r, 'organization', event.organization_id));
    }
  }

  if (event.team_id) {
    const { data: teamRules } = await supabase
      .from('team_notification_rules')
      .select('*')
      .eq('team_id', event.team_id)
      .eq('active', true);

    for (const r of teamRules || []) {
      if (r.trigger_type !== 'weekly_digest') {
        rules.push(mapRule(r, 'team', event.team_id));
      }
    }
  }

  if (event.project_id) {
    const { data: projectRules } = await supabase
      .from('project_notification_rules')
      .select('*')
      .eq('project_id', event.project_id)
      .eq('active', true);

    for (const r of projectRules || []) {
      if (r.trigger_type !== 'weekly_digest') {
        rules.push(mapRule(r, 'project', event.project_id));
      }
    }
  }

  return rules;
}

/**
 * Deduplication: prevent the same destination from receiving duplicate
 * notifications when multiple rules (org + team + project) target the same
 * integration. Only integration-backed destinations can be deduped; inline
 * destinations (email with ad-hoc recipients) are always dispatched.
 */
async function shouldDedup(
  eventId: string,
  integrationId: string | null,
): Promise<boolean> {
  if (!integrationId) return false;

  const { data } = await supabase
    .from('notification_deliveries')
    .select('id')
    .eq('event_id', eventId)
    .eq('integration_id', integrationId)
    .in('status', ['pending', 'sending', 'delivered'])
    .limit(1);

  return (data?.length ?? 0) > 0;
}

/**
 * Process all pending deliveries for an event: check rate limits, load
 * connections, optionally refresh OAuth tokens, dispatch, and track results.
 */
async function processDeliveries(eventId: string, orgId: string): Promise<void> {
  // Org-level notification pause
  const { data: org } = await supabase
    .from('organizations')
    .select('notifications_paused_until')
    .eq('id', orgId)
    .maybeSingle();

  if (org?.notifications_paused_until && new Date(org.notifications_paused_until) > new Date()) {
    notificationLog('info', 'Org notifications paused', { orgId, pausedUntil: org.notifications_paused_until });
    return;
  }

  const { data: event } = await supabase
    .from('notification_events')
    .select('*')
    .eq('id', eventId)
    .single();

  if (!event) return;

  const notifEvent: NotificationEvent = {
    id: event.id,
    event_type: event.event_type,
    organization_id: event.organization_id,
    project_id: event.project_id,
    payload: event.payload,
  };

  const { data: deliveries } = await supabase
    .from('notification_deliveries')
    .select('*')
    .eq('event_id', eventId)
    .eq('status', 'pending');

  if (!deliveries?.length) return;

  for (const delivery of deliveries) {
    const dest: RuleDestination = delivery.destination || {};
    const destType = dest.type || '';
    const isTicketing = TICKETING_PROVIDERS.has(destType);

    // ── Org rate limit ──
    const orgLimit = await checkOrgRateLimit(orgId);
    if (!orgLimit.allowed) {
      await supabase
        .from('notification_deliveries')
        .update({
          status: 'rate_limited',
          error_message: `Org rate limit exceeded (reset ${new Date(orgLimit.resetAt).toISOString()})`,
        })
        .eq('id', delivery.id);
      notificationLog('warn', 'Org rate limit hit', { orgId, deliveryId: delivery.id });
      continue;
    }

    // ── Destination rate limit ──
    const destId = delivery.integration_id || delivery.id;
    const destLimit = await checkDestinationRateLimit(destId, isTicketing);
    if (!destLimit.allowed) {
      await supabase
        .from('notification_deliveries')
        .update({
          status: 'rate_limited',
          error_message: `Destination limit exceeded (${isTicketing ? '10' : '30'}/hr)`,
        })
        .eq('id', delivery.id);
      notificationLog('warn', 'Destination rate limit hit', { destId, deliveryId: delivery.id });
      continue;
    }

    // ── Dry run ──
    if (delivery.dry_run) {
      await supabase
        .from('notification_deliveries')
        .update({ status: 'dry_run', sent_at: new Date().toISOString() })
        .eq('id', delivery.id);
      continue;
    }

    // ── Resolve integration connection ──
    let connection: IntegrationConnection | null = null;

    if (delivery.integration_id) {
      connection = await loadIntegrationConnection(delivery.integration_id);
    }

    if (!connection && dest.config) {
      connection = buildConnectionFromDestination(dest, orgId);
    }

    if (!connection) {
      await supabase
        .from('notification_deliveries')
        .update({ status: 'failed', error_message: 'Integration connection not found' })
        .eq('id', delivery.id);
      continue;
    }

    // ── OAuth token refresh ──
    if (OAUTH_PROVIDERS.has(connection.provider) && connection.refresh_token) {
      try {
        await refreshTokenWithMutex(connection);
      } catch (err: any) {
        notificationLog('warn', 'Token refresh failed', { connectionId: connection.id, error: err.message });
      }
    }

    // ── Mark sending ──
    await supabase
      .from('notification_deliveries')
      .update({ status: 'sending' })
      .eq('id', delivery.id);

    // ── Build message ──
    let message = buildDefaultMessage(notifEvent, event.payload);

    if (delivery.custom_title) message.title = delivery.custom_title;
    if (delivery.custom_message) message.body = delivery.custom_message;
    if (delivery.custom_priority) {
      const sevMap: Record<string, NotificationMessage['severity']> = {
        critical: 'critical',
        high: 'high',
        normal: 'medium',
        low: 'low',
      };
      message.severity = sevMap[delivery.custom_priority] || message.severity;
    }

    message = enforceMessageLimits(message, connection.provider);

    // ── Dispatch ──
    const result = await dispatchToDestination(connection, message, notifEvent);

    const now = new Date().toISOString();
    await supabase
      .from('notification_deliveries')
      .update({
        status: result.success ? 'delivered' : 'failed',
        external_id: result.externalId || null,
        error_message: result.error || null,
        status_code: result.statusCode || null,
        sent_at: now,
        delivered_at: result.success ? now : null,
        attempt_count: (delivery.attempt_count || 0) + 1,
      })
      .eq('id', delivery.id);

    // ── Connection health ──
    if (delivery.integration_id) {
      await updateConnectionHealth(delivery.integration_id, result.success);
    }
  }
}

/**
 * Load an integration connection by ID, trying org → team → project tables.
 */
async function loadIntegrationConnection(
  integrationId: string,
): Promise<IntegrationConnection | null> {
  const columns = 'id, organization_id, provider, access_token, refresh_token, token_expires_at, display_name, metadata';

  const { data: orgInt } = await supabase
    .from('organization_integrations')
    .select(columns)
    .eq('id', integrationId)
    .maybeSingle();
  if (orgInt) return orgInt as IntegrationConnection;

  const { data: teamInt } = await supabase
    .from('team_integrations')
    .select(columns)
    .eq('id', integrationId)
    .maybeSingle();
  if (teamInt) return teamInt as IntegrationConnection;

  const { data: projInt } = await supabase
    .from('project_integrations')
    .select(columns)
    .eq('id', integrationId)
    .maybeSingle();
  if (projInt) return projInt as IntegrationConnection;

  return null;
}

/**
 * Construct a virtual IntegrationConnection from an inline destination config
 * (e.g. email with ad-hoc recipients, or a custom webhook without a stored
 * integration record).
 */
function buildConnectionFromDestination(
  dest: RuleDestination,
  orgId: string,
): IntegrationConnection {
  return {
    id: `inline:${crypto.randomUUID()}`,
    organization_id: orgId,
    provider: dest.type,
    access_token: dest.config?.access_token || '',
    metadata: dest.config || {},
  };
}

/**
 * Track integration connection health. After 3 consecutive failures the
 * connection is marked as 'error' (auto-disabled).
 */
async function updateConnectionHealth(
  connectionId: string,
  success: boolean,
): Promise<void> {
  try {
    if (success) {
      await supabase
        .from('organization_integrations')
        .update({ consecutive_failures: 0, last_success_at: new Date().toISOString() })
        .eq('id', connectionId);
      return;
    }

    const { data: conn } = await supabase
      .from('organization_integrations')
      .select('consecutive_failures, status')
      .eq('id', connectionId)
      .maybeSingle();

    if (!conn) return;

    const failures = (conn.consecutive_failures || 0) + 1;
    const updates: Record<string, any> = {
      consecutive_failures: failures,
      last_failure_at: new Date().toISOString(),
    };

    if (failures >= HEALTH_FAILURE_THRESHOLD) {
      updates.status = 'error';
      notificationLog('warn', 'Integration auto-disabled after consecutive failures', {
        connectionId,
        failures,
      });

      try {
        const { emitEvent } = require('./event-bus');
        const { data: integration } = await supabase
          .from('organization_integrations')
          .select('organization_id, provider')
          .eq('id', connectionId)
          .single();

        if (integration) {
          emitEvent({
            type: 'integration_health_degraded',
            organizationId: integration.organization_id,
            payload: {
              integration_id: connectionId,
              provider: integration.provider,
              consecutive_failures: failures,
            },
            source: 'notification_dispatcher',
            priority: 'normal' as const,
          }).catch(() => {});
        }
      } catch (_) {
        // Non-critical — swallow circular-require or emit errors
      }
    }

    await supabase
      .from('organization_integrations')
      .update(updates)
      .eq('id', connectionId);
  } catch (err: any) {
    notificationLog('error', 'Failed to update connection health', { connectionId, error: err.message });
  }
}

/**
 * Create in-app notifications for organization members, respecting per-user
 * notification preferences (muted events, muted projects, in-app toggle).
 */
async function createInAppNotifications(
  event: any,
  message: NotificationMessage,
): Promise<void> {
  try {
    const { data: members } = await supabase
      .from('organization_members')
      .select('user_id')
      .eq('organization_id', event.organization_id)
      .limit(MAX_IN_APP_BATCH);

    if (!members?.length) return;

    const userIds = members.map((m: any) => m.user_id);

    const { data: prefs } = await supabase
      .from('user_notification_preferences')
      .select('user_id, muted_event_types, muted_project_ids, in_app_enabled')
      .eq('organization_id', event.organization_id)
      .in('user_id', userIds);

    const prefsMap = new Map<string, any>();
    for (const p of prefs || []) {
      prefsMap.set(p.user_id, p);
    }

    const notifications: any[] = [];

    for (const userId of userIds) {
      const pref = prefsMap.get(userId);

      if (pref?.in_app_enabled === false) continue;
      if (pref?.muted_event_types?.includes(event.event_type)) continue;
      if (event.project_id && pref?.muted_project_ids?.includes(event.project_id)) continue;

      notifications.push({
        user_id: userId,
        organization_id: event.organization_id,
        event_id: event.id,
        event_type: event.event_type,
        title: message.title,
        body: message.body,
        severity: message.severity,
        project_id: event.project_id || null,
        deptex_url: message.deptexUrl,
        read: false,
      });
    }

    if (notifications.length > 0) {
      await supabase.from('user_notifications').insert(notifications);
    }

    notificationLog('info', 'In-app notifications created', {
      eventId: event.id,
      count: notifications.length,
      totalMembers: userIds.length,
    });
  } catch (err: any) {
    notificationLog('error', 'Failed to create in-app notifications', {
      eventId: event.id,
      error: err.message,
    });
  }
}

// ─── OAuth Token Refresh with Redis Mutex ────────────────────────────────────

/**
 * Refresh an OAuth token with a Redis-based distributed mutex to prevent
 * concurrent refreshes (OAuth refresh tokens are typically single-use).
 *
 * Lock key: `token-refresh:{connectionId}`
 * Lock TTL: 30s (auto-release if holder crashes)
 * Wait: up to 5s for lock release, then re-read updated token from DB
 */
async function refreshTokenWithMutex(connection: IntegrationConnection): Promise<void> {
  if (
    connection.token_expires_at &&
    new Date(connection.token_expires_at) > new Date(Date.now() + 60_000)
  ) {
    return;
  }

  const redis = getRedis();
  if (!redis) {
    await refreshOAuthToken(connection);
    return;
  }

  const lockKey = `token-refresh:${connection.id}`;
  const lockValue = crypto.randomUUID();

  const acquired = await redis.set(lockKey, lockValue, { nx: true, px: LOCK_TTL_MS });

  if (!acquired) {
    await waitForLockRelease(redis, lockKey, LOCK_WAIT_MS);

    const { data: updated } = await supabase
      .from('organization_integrations')
      .select('access_token, refresh_token, token_expires_at')
      .eq('id', connection.id)
      .single();

    if (updated) {
      connection.access_token = updated.access_token;
      connection.refresh_token = updated.refresh_token;
      connection.token_expires_at = updated.token_expires_at;
    }
    return;
  }

  try {
    const newTokens = await refreshOAuthToken(connection);

    await supabase
      .from('organization_integrations')
      .update({
        access_token: newTokens.access_token,
        refresh_token: newTokens.refresh_token ?? connection.refresh_token,
        token_expires_at: newTokens.expires_at,
      })
      .eq('id', connection.id);

    connection.access_token = newTokens.access_token;
    if (newTokens.refresh_token) connection.refresh_token = newTokens.refresh_token;
    connection.token_expires_at = newTokens.expires_at;
  } finally {
    const current = await redis.get(lockKey);
    if (current === lockValue) await redis.del(lockKey);
  }
}

async function waitForLockRelease(
  redis: any,
  key: string,
  timeoutMs: number,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const exists = await redis.exists(key);
    if (!exists) return;
    await new Promise((r) => setTimeout(r, 200));
  }
}

/**
 * Perform the actual OAuth token refresh against the provider's token endpoint.
 * Supports Jira, Asana, Slack, Discord, GitLab, and Bitbucket.
 */
async function refreshOAuthToken(connection: IntegrationConnection): Promise<RefreshedTokens> {
  const config = OAUTH_REFRESH_ENDPOINTS[connection.provider];
  if (!config) {
    throw new Error(`No OAuth refresh config for provider: ${connection.provider}`);
  }

  const clientId = process.env[config.clientIdEnv];
  const clientSecret = process.env[config.clientSecretEnv];

  if (!clientId || !clientSecret) {
    throw new Error(`Missing ${config.clientIdEnv} or ${config.clientSecretEnv} for token refresh`);
  }

  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: connection.refresh_token || '',
    client_id: clientId,
    client_secret: clientSecret,
  });

  const response = await fetch(config.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Token refresh failed (${response.status}): ${text.slice(0, 200)}`);
  }

  const data = (await response.json()) as any;
  const expiresIn: number = data.expires_in || 3600;

  return {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_at: new Date(Date.now() + expiresIn * 1000).toISOString(),
  };
}
