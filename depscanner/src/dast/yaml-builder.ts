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
// v1.1 (Phase 35): 'api' joins as a first-class scan_profile. Behaves like
// 'full' (active scan emitted) and is the canonical name for spec-driven
// scans even though the openapi: AF job is also engaged on 'full' when the
// target row provides a resolvable spec (row-driven gating).
export type AfScanProfile = 'auto' | 'quick' | 'full' | 'api';

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
  /**
   * v2.1d — login-only mode for the Test-login dry-run job AND for the
   * pre-flight probe inside a real recorded-strategy scan. When true:
   *   - the spider, spiderAjax, activeScan, and traditional-json report jobs
   *     are omitted
   *   - the `requestor` AF job post-auth IS emitted (so loggedInRegex fires)
   *     and the auth-report-json report job IS emitted (so the worker can
   *     parse the structured login verdict)
   *   - the auth context's `failOnError` is set so a verification miss
   *     aborts the autorun cleanly (M0 Spike-5 outcome decides whether this
   *     is via job-level onFail:exit or worker-side gating).
   */
  loginOnly?: boolean;
  /**
   * v2.1d — optional URL the recorded-strategy requestor job hits to drive
   * the verification regex check. When unset, defaults to the credential's
   * `login_page_url` (acceptable but less useful — most fixtures want a
   * post-login URL that contains the loggedIn indicator text). The
   * empirical spike confirmed the requestor MUST run under a `user:` for
   * ZAP to replay the recorded auth method.
   */
  verificationProbeUrl?: string;
  /**
   * v2.1d — absolute directory ZAP's `auth-report-json` report job writes
   * to. Defaults to `/zap/wrk`. The pipeline overrides this with the
   * per-job tempdir so concurrent probes in the same work dir don't collide
   * on a single auth-report.json file.
   */
  authReportDirAbsolute?: string;
  /**
   * v1.1 (Phase 35) — absolute path to a synthesized or fetched OpenAPI
   * spec on disk. When set, an `openapi:` AF job is emitted between the
   * replacer and spider jobs so ZAP seeds its sites tree with the spec's
   * endpoints before crawl + active scan run.
   *
   * Row-driven gating: pipeline decides whether to set this based on the
   * target's `api_spec_source`; scan profile no longer gates the openapi
   * emit. Spider/activeScan still respect `scanProfile`.
   */
  openApiSpecPath?: string;
}

// v2.1d / Phase 36 (v1.1) — auth budget reserved out of scan_timeout_minutes
// for the in-engine auth phase. activeScan.maxScanDurationInMins is reduced
// by this amount for the recorded AND replay strategies so the combined
// (auth + spider + scan) run fits within the outer scan_timeout_minutes
// wall-clock. The constant name was widened from RECORDED_AUTH_BUDGET_MIN
// to AUTH_SETUP_BUDGET_MIN per Patch C strategy-neutrality.
const AUTH_SETUP_BUDGET_MIN = 3;

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

  // 1. addOns — install what we need so the AF run doesn't hit a missing job
  // type at parse time. Includes pscanrulesAlpha + pscanrulesBeta to match
  // zap-baseline.py's coverage (parity check: anonymous AF run must produce
  // findings within +/-10% of zap-baseline.py — `feedback_docker_vs_source_e2e`
  // surfaced the gap when AF emitted ~half the alerts of helper-script).
  //
  // NOTE: `authhelper` is intentionally OMITTED. The v2.1d empirical spike
  // confirmed authhelper is pre-baked into the `ghcr.io/zaproxy/zaproxy:stable`
  // image (ZAP 2.17.0) and listing it in the addOns install list triggers a
  // "addOns job no longer does anything" warning three times per scan. If
  // Deptex ever pins a slimmer ZAP image, document the addOn here and
  // re-introduce.
  jobs.push({
    type: 'addOns',
    parameters: {
      install: [
        'ascanrules',
        'pscanrules',
        'pscanrulesAlpha',
        'pscanrulesBeta',
        'spider',
        'spiderAjax',
        'replacer',
      ],
    },
  });

  // 2. passiveScan-config — scan only what's in scope. We deliberately do NOT
  // cap maxAlertsPerRule: zap-baseline.py has no per-rule cap, and capping
  // dropped Juice Shop CSP coverage from 15 hits to 5 in real-ZAP testing,
  // breaking parity with the helper-script path.
  jobs.push({
    type: 'passiveScan-config',
    parameters: {
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

  // 3.5. requestor — v2.1d: post-auth verification probe.
  //
  // EMPIRICAL FINDING (ZAP 2.17.0): ZAP only triggers the recorded auth
  // method when a job's request is assigned to a user via `parameters.user`.
  // Without that, the requestor fires an anonymous GET and the auth method
  // never runs — `afEnv` echoes the steps back but no replay happens.
  //
  // The verification URL prefers `verificationProbeUrl` (post-login page
  // that contains the loggedIn indicator), falling back to the credential's
  // login_page_url, and finally to the target URL. A login_page_url GET is
  // useful as a smoke test but typically can't drive the loggedIn regex
  // because the login form page doesn't contain the post-login text.
  //
  // M0 Spike-5 outcome decides whether `onFail: exit` reliably halts the
  // autorun on a verification miss. The empirical spike completed the
  // requestor job successfully even on auth failure (the auth verdict
  // lives in the auth-report.json's summaryItems[auth.summary.auth]). We
  // leave `onFail: exit` in place defensively — when ZAP DOES surface a
  // requestor failure, it short-circuits the spider/active-scan work.
  // v2.1d / Phase 36 (v1.1) — post-auth verification probe runs for both
  // browser-driven recorded auth AND replay's script-based auth. The same
  // empirical finding from v2.1d applies: without parameters.user the
  // auth method is never invoked, so the probe fires anonymously and the
  // loggedIn regex never gets a real test.
  if (
    (opts.authStrategy === 'recorded' || opts.authStrategy === 'replay')
    && opts.authPayload
  ) {
    // Recorded carries login_page_url; replay carries origins_observed (the
    // first origin is the canonical post-auth target). Fall back to the
    // target URL for both.
    const recordedLoginPageUrl =
      opts.authStrategy === 'recorded'
        ? (opts.authPayload as { kind: string } & { login_page_url?: string }).login_page_url
        : undefined;
    const verificationUrl =
      opts.verificationProbeUrl
      ?? recordedLoginPageUrl
      ?? opts.targetUrl;
    jobs.push({
      type: 'requestor',
      parameters: {
        // Without `user:` ZAP never invokes the script-based / browser-based
        // auth method (empirical for both strategies — see v2.1d findings).
        user: 'deptex-dast-user',
      },
      requests: [
        {
          url: verificationUrl,
          method: 'GET',
        },
      ],
      onFail: 'exit',
    });
  }

  // 4-7. login-only short-circuit: in login-only mode, omit the spider,
  // active-scan, openapi, and traditional-json report jobs. The autorun YAML
  // is just addOns + passiveScan-config + (replacer if needed) + requestor
  // verification + auth-report-json. The worker reads the auth-report.json
  // file from disk and writes DastLoginTestResult to scan_jobs.error_payload.
  if (!opts.loginOnly) {
    // 3.6. openapi — v1.1 (Phase 35): seeds ZAP's sites tree from a
    // synthesized or URL-fetched OpenAPI spec BEFORE spider+activeScan run,
    // so the crawl picks up spec-discovered endpoints in addition to its
    // own link-following.
    //
    // User-binding convention matches the requestor job at yaml-builder.ts
    // around line 239: `parameters.context` for ALL strategies;
    // `parameters.user` ONLY when authStrategy === 'recorded'. Form/jwt/
    // cookie use context-only — the ZAP context's authenticate-and-replay
    // handles them at request time without needing a per-job user binding.
    if (opts.openApiSpecPath) {
      const openApiJob: Record<string, unknown> = {
        type: 'openapi',
        parameters: {
          apiFile: opts.openApiSpecPath,
          targetUrl: opts.targetUrl,
          context: CONTEXT_NAME,
          // Phase 36 — replay binds the same user; both strategies need
          // the explicit user binding to invoke their auth method.
          ...(opts.authStrategy === 'recorded' || opts.authStrategy === 'replay'
            ? { user: 'deptex-dast-user' }
            : {}),
        },
      };
      jobs.push(openApiJob);
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

    // 5. activeScan — runs on scan_profile='full' and (v1.1) scan_profile=
    // 'api'. 'auto' / 'quick' stay passive-only with no auto-escalation.
    //
    // v2.1d: recorded strategy reserves RECORDED_AUTH_BUDGET_MIN minutes of
    // scan_timeout_minutes for the login replay + verification probe. The
    // pre-flight runs inside the SAME autorun YAML in the same ZAP process,
    // so the auth budget is consumed before the active-scan starts.
    if (opts.scanProfile === 'full' || opts.scanProfile === 'api') {
      const baseTimeout = opts.scanTimeoutMinutes ?? 30;
      // Phase 36 — same auth budget carveout for recorded AND replay
      // (form / jwt / cookie have negligible auth setup time).
      const activeScanDuration =
        opts.authStrategy === 'recorded' || opts.authStrategy === 'replay'
          ? Math.max(1, baseTimeout - AUTH_SETUP_BUDGET_MIN)
          : baseTimeout;
      jobs.push({
        type: 'activeScan',
        parameters: {
          context: CONTEXT_NAME,
          maxScanDurationInMins: activeScanDuration,
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
  }

  // v2.1d — auth-report-json report. ALWAYS emitted for the recorded strategy
  // (login-only AND full scan): the worker reads /zap/wrk/auth-report.json
  // to extract the structured login verdict (summaryItems / failureReasons /
  // afPlanErrors). This is the ONLY signal ZAP exposes for browser-auth
  // success vs failure — empirically confirmed against ZAP 2.17.0 +
  // authhelper v0.39.0. Note: a pre-baked authhelper add-on ships with the
  // `auth-report-json` template; no add-on install needed.
  // v2.1d — auth-report.json is generated ONLY by authhelper's browser-based
  // auth path (recorded strategy). authhelper does NOT emit it for script-
  // based authentication, so replay's verdict signal lives in ZAP exit code
  // + the requestor job's onFail:exit semantics (see pipeline.ts
  // runReplayLoginProbe). Keep this job gated to recorded only.
  if (opts.authStrategy === 'recorded' && opts.authPayload) {
    jobs.push({
      type: 'report',
      parameters: {
        template: 'auth-report-json',
        reportDir: opts.authReportDirAbsolute ?? '/zap/wrk',
        reportFile: 'auth-report.json',
      },
    });
  }

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
