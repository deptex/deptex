// Phase 24 (v2.1a): ZAP Automation Framework YAML builder.
//
// Produces a single AF YAML that ZAP runs end-to-end via
// `/zap/zap.sh -cmd -autorun /path/to/automation.yaml`. The same builder
// covers anonymous baseline scans (auth_strategy=undefined, scope=empty,
// runtime=classic) — that's the parity case Task 10's e2e validates.
//
// Job order (per plan §"buildAutomationYaml acceptance"):
//   addOns
//   passiveScan-config
//   replacer        (header rules + jwt/cookie auth)
//   spider | spiderAjax    (spiderAjax for SPA targets)
//   activeScan      (only when scan_profile='full')
//   report
//
// Form-strategy auth lives in `env.contexts[].authentication` (it's not a
// separate job — that's how ZAP's AF schema models it).

import * as yaml from 'js-yaml';

import {
  buildAuthForStrategy,
  CredentialPayload,
  DastAuthStrategy,
} from './auth-config';

export interface ScopeHeaderRule {
  name: string;
  value: string;
  scope: 'all' | 'requests' | 'responses';
}

export interface ScopeConfig {
  includePaths?: string[];
  excludePaths?: string[];
  headerRules?: ScopeHeaderRule[];
}

export type DetectedRuntime = 'unknown' | 'classic' | 'spa';
export type AfScanProfile = 'auto' | 'quick' | 'full';

export interface BuildAutomationYamlOptions {
  targetUrl: string;
  scanProfile: AfScanProfile;
  detectedRuntime: DetectedRuntime;
  // Where ZAP's report job writes the JSON report. Path is relative to
  // /zap/wrk per the AF report job's `reportDir + reportFile` convention.
  reportRelativePath: string;
  scope?: ScopeConfig;
  authStrategy?: DastAuthStrategy;
  authPayload?: CredentialPayload;
  loggedInIndicator?: string;
  loggedOutIndicator?: string;
  scanTimeoutMinutes?: number;
}

const CONTEXT_NAME = 'deptex-dast';

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildHeaderRule(r: ScopeHeaderRule): Record<string, unknown> {
  // matchType reflects whether ZAP rewrites on the request or response side.
  // 'all' uses req_header (the more common case); 'requests' is identical;
  // 'responses' uses resp_header.
  const matchType =
    r.scope === 'responses' ? 'resp_header' : 'req_header';
  return {
    description: `header_rule:${r.name}`,
    url: '',
    matchType,
    matchString: r.name,
    replacementString: r.value,
    tokenProcessing: false,
  };
}

export function buildAutomationYaml(opts: BuildAutomationYamlOptions): string {
  let baseUrl: string;
  try {
    baseUrl = new URL(opts.targetUrl).origin;
  } catch {
    throw new Error(`buildAutomationYaml: invalid targetUrl: ${opts.targetUrl}`);
  }

  // Default include scope: everything under the target's origin. The route
  // already SSRF-checks the URL; we only re-pin the spider's reach here.
  const includePaths =
    opts.scope?.includePaths && opts.scope.includePaths.length > 0
      ? [...opts.scope.includePaths]
      : [`${escapeRegex(baseUrl)}.*`];
  const excludePaths = opts.scope?.excludePaths ?? [];

  const context: Record<string, unknown> = {
    name: CONTEXT_NAME,
    urls: [opts.targetUrl],
    includePaths,
    excludePaths,
  };

  const replacerRules: Array<Record<string, unknown>> = [];
  for (const r of opts.scope?.headerRules ?? []) {
    replacerRules.push(buildHeaderRule(r));
  }

  if (opts.authStrategy && opts.authPayload) {
    const auth = buildAuthForStrategy(
      opts.authStrategy,
      opts.authPayload,
      opts.loggedInIndicator,
      opts.loggedOutIndicator,
    );
    if (auth.contextAuthentication) {
      context.authentication = auth.contextAuthentication;
    }
    if (auth.contextUsers && auth.contextUsers.length > 0) {
      context.users = auth.contextUsers;
    }
    if (auth.replacerRules && auth.replacerRules.length > 0) {
      replacerRules.push(...auth.replacerRules);
    }
  }

  const jobs: Array<Record<string, unknown>> = [];

  // 1. addOns — install just what we need so the AF run doesn't hit a missing
  // job-type at parse time.
  jobs.push({
    type: 'addOns',
    parameters: {
      install: ['ascanrules', 'pscanrules', 'spider', 'spiderAjax', 'replacer'],
    },
  });

  // 2. passiveScan-config — bound rule output so a chatty rule doesn't pollute
  // the report; scan only what's in scope.
  jobs.push({
    type: 'passiveScan-config',
    parameters: {
      maxAlertsPerRule: 10,
      scanOnlyInScope: true,
      enableTags: false,
    },
  });

  // 3. replacer — only emit when there's something to replace (header rules
  // or jwt/cookie auth). An empty replacer job still parses but adds noise.
  if (replacerRules.length > 0) {
    jobs.push({
      type: 'replacer',
      parameters: {},
      rules: replacerRules,
    });
  }

  // 4. spider vs spiderAjax — runtime-driven.
  // 'unknown' AND 'spa' both use spiderAjax (the runtime-shape guard in
  // fly-machines.ts pairs with this — both get the perf-4x machine).
  if (opts.detectedRuntime === 'spa' || opts.detectedRuntime === 'unknown') {
    jobs.push({
      type: 'spiderAjax',
      parameters: {
        context: CONTEXT_NAME,
        // 10-min cap on AJAX crawl; safety net is the outer scan_timeout.
        maxDuration: 10,
        // firefox-headless is the AF default and ships in the ZAP image.
        browserId: 'firefox-headless',
      },
    });
  } else {
    jobs.push({
      type: 'spider',
      parameters: {
        context: CONTEXT_NAME,
        maxDuration: 5,
        maxDepth: 5,
      },
    });
  }

  // 5. activeScan — only on scan_profile='full' (locked decision per plan:
  // 'auto' is passive-only with no auto-escalation).
  if (opts.scanProfile === 'full') {
    jobs.push({
      type: 'activeScan',
      parameters: {
        context: CONTEXT_NAME,
        maxScanDurationInMins: opts.scanTimeoutMinutes ?? 30,
        policy: 'Default Policy',
      },
    });
  }

  // 6. report — JSON traditional report. Path is relative to /zap/wrk per
  // the AF report job's reportDir+reportFile convention.
  jobs.push({
    type: 'report',
    parameters: {
      template: 'traditional-json',
      reportDir: '/zap/wrk',
      reportFile: opts.reportRelativePath,
    },
  });

  const automation = {
    env: {
      contexts: [context],
      parameters: {
        failOnError: false,
        failOnWarning: false,
        progressToStdout: true,
      },
    },
    jobs,
  };

  return yaml.dump(automation, {
    lineWidth: 200,
    noRefs: true,
    noCompatMode: true,
    quotingType: '"',
  });
}
