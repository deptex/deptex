// Phase 24 (v2.1a): bridge between the v2.1a credential payload shape (defined
// in `backend/src/types/dast.ts`) and ZAP's Automation Framework auth model.
//
// We mirror the type shape here rather than importing from `backend/src/types`
// because the depscanner package is built independently and must not pull in
// the backend's TS surface. The contract is enforced by the integration test
// in Task 9 (decrypts a credential, hands it to buildAuthForStrategy, asserts
// the YAML round-trips through ZAP without errors).
//
// Strategy → ZAP method mapping:
//   form    → context.authentication{method: form} + context.users[]
//   jwt     → replacer rule (Authorization: Bearer <token>)
//   cookie  → replacer rule (Cookie: name=value; ...)
//   recorded → throws UnsupportedAuthStrategyError; recorded login is v2.1d.

export type DastAuthStrategy = 'form' | 'jwt' | 'cookie' | 'recorded';

export interface FormCredentialPayload {
  kind: 'form';
  login_url: string;
  username_field: string;
  password_field: string;
  username: string;
  password: string;
}

export interface JwtCredentialPayload {
  kind: 'jwt';
  token: string;
}

export interface CookieCredentialPayload {
  kind: 'cookie';
  cookies: Array<{ name: string; value: string; domain?: string; path?: string }>;
}

// v2.1d — recorded login via ZAP's browser-based AF auth method (authhelper
// addon). Mirrors backend/src/types/dast.ts so depscanner can build
// independently. Validator on the backend enforces strict bounds; we re-check
// the goto-position rule here for defense-in-depth at YAML-emit time.

export type RecordedStepAction =
  | 'goto'
  | 'click'
  | 'type_username'
  | 'type_password'
  | 'type_totp'
  | 'type_custom'
  | 'wait'
  | 'return'
  | 'escape';

export interface RecordedStep {
  action: RecordedStepAction;
  selector?: string;
  selector_kind?: 'css' | 'xpath';
  value?: string;
  timeout_ms?: number;
  wait_ms?: number;
}

export interface RecordedCredentialPayload {
  kind: 'recorded';
  login_page_url: string;
  steps: RecordedStep[];
  username: string;
  password: string;
  totp_secret?: string;
  login_page_wait_ms?: number;
  step_delay_ms?: number;
  label?: string;
  sso_origins?: string[];
}

export type CredentialPayload =
  | FormCredentialPayload
  | JwtCredentialPayload
  | CookieCredentialPayload
  | RecordedCredentialPayload;

export interface AuthBuildResult {
  // Becomes context.authentication in the AF YAML.
  contextAuthentication?: Record<string, unknown>;
  // Becomes context.users[] in the AF YAML.
  contextUsers?: Array<Record<string, unknown>>;
  // Pushed onto the replacer job's rules[].
  replacerRules?: Array<Record<string, unknown>>;
}

export class UnsupportedAuthStrategyError extends Error {
  code = 'dast_strategy_not_supported_in_v2_1a';
  constructor(public strategy: string) {
    super(`DAST auth strategy '${strategy}' is not supported in v2.1a`);
    this.name = 'UnsupportedAuthStrategyError';
  }
}

/**
 * Thrown when a credential field contains characters that could inject HTTP
 * headers into every ZAP request (CR/LF/control chars in a cookie name/value,
 * or a JWT token with characters outside the base64url/JWT alphabet). The
 * pipeline maps this to a clean job failure.
 */
export class InvalidCredentialCharacterError extends Error {
  code = 'dast_credential_invalid_characters';
  constructor(message: string) {
    super(message);
    this.name = 'InvalidCredentialCharacterError';
  }
}

// CR, LF, or any C0/C1 control char would let a crafted credential break out
// of the intended header and inject arbitrary headers into ZAP requests.
// eslint-disable-next-line no-control-regex
const CONTROL_OR_CRLF = /[\x00-\x1f\x7f]/;

// A JWT is three base64url segments joined by '.'. Restrict to that alphabet
// so a token can't carry CR/LF/spaces/control chars into the Bearer header.
const JWT_TOKEN_RE = /^[A-Za-z0-9._-]+$/;

function assertNoControlChars(label: string, value: string): void {
  if (CONTROL_OR_CRLF.test(value)) {
    throw new InvalidCredentialCharacterError(
      `DAST ${label} contains a CR, LF, or control character`,
    );
  }
}

export function buildAuthForStrategy(
  strategy: DastAuthStrategy,
  payload: CredentialPayload,
  loggedInIndicator?: string,
  loggedOutIndicator?: string,
): AuthBuildResult {
  if (payload.kind !== strategy) {
    throw new Error(
      `DAST auth payload.kind='${payload.kind}' mismatches strategy='${strategy}'`,
    );
  }

  if (strategy === 'recorded') {
    // v2.1d — delegate to the browser-based auth builder. The yaml-builder
    // also needs the internalIndexToZapIndex[] map, so it should call
    // buildRecordedAuthForZap directly when it needs the mapping. This helper
    // returns the same {contextAuthentication, contextUsers} shape so
    // existing call sites that don't need the index keep working.
    const rec = buildRecordedAuthForZap(
      payload as RecordedCredentialPayload,
      loggedInIndicator,
      loggedOutIndicator,
    );
    return {
      contextAuthentication: rec.contextAuthentication,
      contextUsers: rec.contextUsers,
    };
  }

  if (strategy === 'form') {
    const p = payload as FormCredentialPayload;
    const verification: Record<string, unknown> = { method: 'response' };
    if (loggedInIndicator) verification.loggedInRegex = loggedInIndicator;
    if (loggedOutIndicator) verification.loggedOutRegex = loggedOutIndicator;
    return {
      contextAuthentication: {
        method: 'form',
        parameters: {
          loginPageUrl: p.login_url,
          loginRequestUrl: p.login_url,
          loginRequestBody: `${encodeURIComponent(p.username_field)}={%username%}&${encodeURIComponent(p.password_field)}={%password%}`,
        },
        verification,
      },
      contextUsers: [
        {
          name: 'deptex-dast-user',
          credentials: { username: p.username, password: p.password },
        },
      ],
    };
  }

  if (strategy === 'jwt') {
    const p = payload as JwtCredentialPayload;
    // A JWT placed into `Bearer <token>` must contain only base64url/JWT
    // characters — anything else (whitespace, CR/LF, control chars) could
    // inject headers into every ZAP request.
    if (typeof p.token !== 'string' || !JWT_TOKEN_RE.test(p.token)) {
      throw new InvalidCredentialCharacterError(
        'DAST JWT token contains characters outside the JWT alphabet',
      );
    }
    return {
      replacerRules: [
        {
          description: 'deptex-jwt-bearer',
          url: '',
          matchType: 'req_header',
          matchString: 'Authorization',
          replacementString: `Bearer ${p.token}`,
          tokenProcessing: false,
        },
      ],
    };
  }

  if (strategy === 'cookie') {
    const p = payload as CookieCredentialPayload;
    if (p.cookies.length === 0) {
      throw new Error(`DAST auth cookie payload has no cookies`);
    }
    // A CR/LF/control char in a cookie name or value would let a crafted
    // credential inject arbitrary headers into every ZAP request.
    for (const c of p.cookies) {
      assertNoControlChars('cookie name', c.name);
      assertNoControlChars('cookie value', c.value);
    }
    const cookieHeader = p.cookies
      .map((c) => `${c.name}=${c.value}`)
      .join('; ');
    return {
      replacerRules: [
        {
          description: 'deptex-cookie-auth',
          url: '',
          matchType: 'req_header',
          matchString: 'Cookie',
          replacementString: cookieHeader,
          tokenProcessing: false,
        },
      ],
    };
  }

  // Should be unreachable given the union type, but cover it defensively.
  throw new UnsupportedAuthStrategyError(strategy);
}

// ---------------------------------------------------------------------------
// v2.1c — Nuclei header auth
// ---------------------------------------------------------------------------

/**
 * Flatten a credential payload into the HTTP header map the Nuclei engine
 * injects via `-H @file`. jwt → Authorization, cookie → Cookie. form and
 * recorded auth cannot be reduced to static headers — the caller aborts the
 * run with `auth_failed` rather than silently scanning anonymous (the same
 * never-fall-back-to-anonymous invariant the ZAP path enforces).
 */
export function buildNucleiAuthHeaders(
  strategy: DastAuthStrategy,
  payload: CredentialPayload,
): Record<string, string> {
  if (payload.kind !== strategy) {
    throw new Error(
      `DAST auth payload.kind='${payload.kind}' mismatches strategy='${strategy}'`,
    );
  }
  if (strategy === 'jwt') {
    return { Authorization: `Bearer ${(payload as JwtCredentialPayload).token}` };
  }
  if (strategy === 'cookie') {
    const p = payload as CookieCredentialPayload;
    if (p.cookies.length === 0) throw new Error('DAST auth cookie payload has no cookies');
    return { Cookie: p.cookies.map((c) => `${c.name}=${c.value}`).join('; ') };
  }
  // form / recorded: not expressible as static headers.
  throw new UnsupportedAuthStrategyError(strategy);
}

// ---------------------------------------------------------------------------
// v2.1d — Recorded login via ZAP's `browser` AF auth method (authhelper)
// ---------------------------------------------------------------------------

/**
 * The shape `buildRecordedAuthForZap` returns.
 *
 * `internalIndexToZapIndex` is retained for backward-compat with callers
 * (and tests) that care which UI step collapsed into `loginPageUrl` vs which
 * emitted a real ZAP step. The empirical v2.1d spike against ZAP 2.17.0 +
 * authhelper v0.39.0 confirmed that ZAP does NOT emit per-step
 * success/failure events — the only structured diagnostic signal is the
 * `auth-report-json` REPORT template (summaryItems[] / failureReasons[] /
 * afPlanErrors[]). So the parser no longer uses this mapping to translate
 * ZAP-coordinate failures back into UI coordinates: every failure is
 * `step_index: 0` from ZAP's perspective. The field stays as informational
 * metadata for callers that want to surface "your goto collapsed here".
 */
export interface RecordedAuthBuildResult {
  contextAuthentication: Record<string, unknown>;
  contextUsers: Array<Record<string, unknown>>;
  /**
   * For each UI step index (0..steps.length-1), the corresponding ZAP step
   * index — or -1 if the step was collapsed (only `steps[0]` with action
   * `goto` is collapsed). Length === steps.length.
   */
  internalIndexToZapIndex: number[];
}

const RECORDED_DEFAULT_STEP_TIMEOUT_MS = 1000;
const RECORDED_DEFAULT_LOGIN_PAGE_WAIT_MS = 5000;
const RECORDED_DEFAULT_STEP_DELAY_MS = 0;

const ACTION_TO_ZAP_TYPE: Record<RecordedStepAction, string | null> = {
  goto: null, // collapses into loginPageUrl, never emitted as a step
  click: 'CLICK',
  type_username: 'USERNAME',
  type_password: 'PASSWORD',
  type_totp: 'TOTP_FIELD',
  type_custom: 'CUSTOM_FIELD',
  wait: 'WAIT',
  return: 'RETURN',
  escape: 'ESCAPE',
};

/**
 * v2.1d empirical: ZAP's authhelper step-schema validator REQUIRES a
 * `description: <string>` on every step, otherwise it silently drops the
 * step (the entire steps[] array becomes empty in afEnv → ZAP falls back
 * to AUTO_DETECT). Without this, our explicit-step value-add disappears
 * and recorded login regresses to ~the same coverage as the form strategy.
 * Derive a short human-readable description from the action + selector.
 */
function describeStep(step: RecordedStep, index: number): string {
  switch (step.action) {
    case 'click':
      return step.selector ? `click ${step.selector}` : 'click';
    case 'type_username':
      return 'type username';
    case 'type_password':
      return 'type password';
    case 'type_totp':
      return 'type TOTP code';
    case 'type_custom':
      return step.selector ? `type into ${step.selector}` : 'type custom value';
    case 'wait':
      return typeof step.wait_ms === 'number' ? `wait ${step.wait_ms}ms` : 'wait';
    case 'return':
      return 'press Enter';
    case 'escape':
      return 'press Escape';
    case 'goto':
      // Should never reach the step list (collapsed into loginPageUrl).
      return step.value ? `go to ${step.value}` : `step ${index}`;
    default:
      return `step ${index}`;
  }
}

function recordedSelectorField(step: RecordedStep): Record<string, unknown> {
  // ZAP's browser-auth step accepts `cssSelector` or `xpath`. We default to
  // css when neither selector_kind nor a non-css mode is specified.
  if (!step.selector) return {};
  const isXPath = step.selector_kind === 'xpath';
  return isXPath
    ? { xpath: step.selector }
    : { cssSelector: step.selector };
}

/**
 * Build the AF `browser` auth method block + users[] from a decrypted
 * recorded payload. The yaml-builder calls this directly so it can also use
 * the index mapping. `buildAuthForStrategy` (legacy form-strategy path) also
 * delegates here for the recorded branch but discards the mapping.
 *
 * Spike-1 of M0 verifies the exact `browser` method shape against the ZAP
 * version baked into the depscanner image. Field names that may shift between
 * ZAP versions (camelCase vs snake_case for step selectors) are documented
 * inline; the parser's fixture corpus pins them.
 */
export function buildRecordedAuthForZap(
  payload: RecordedCredentialPayload,
  loggedInIndicator?: string,
  loggedOutIndicator?: string,
): RecordedAuthBuildResult {
  // login_page_url: prefer payload.login_page_url, but if payload.steps[0] is
  // a `goto` with a value, use that (the user-authored entry URL) instead.
  // This matches the validator's goto-only-at-index-0 rule.
  let loginPageUrl = payload.login_page_url;
  const steps = Array.isArray(payload.steps) ? payload.steps : [];
  let gotoCollapsed = false;
  if (steps.length > 0 && steps[0].action === 'goto') {
    if (steps[0].value) {
      loginPageUrl = steps[0].value;
    }
    gotoCollapsed = true;
  }

  // Build the internalIndexToZapIndex[] mapping AND the ZAP step list in one
  // pass. ZAP-step-index is incremented only for actions that emit a step
  // (i.e. NOT `goto`, which collapses).
  const zapSteps: Array<Record<string, unknown>> = [];
  const internalIndexToZapIndex: number[] = [];
  let zapIdx = 0;
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const zapType = ACTION_TO_ZAP_TYPE[step.action];
    if (zapType === null) {
      // goto-only-at-index-0: emit -1 mapping for index 0; reject mid-flow.
      if (i !== 0) {
        // Defense-in-depth — backend validator rejects this. Re-check here so
        // a misbehaving caller can't slip a mid-flow goto past us.
        throw new Error(
          `buildRecordedAuthForZap: step ${i} action 'goto' only valid as steps[0]`,
        );
      }
      internalIndexToZapIndex.push(-1);
      continue;
    }
    // v2.1d empirical: each step REQUIRES a `description:` field, otherwise
    // ZAP's authhelper validator silently drops the entire steps[] array and
    // falls back to AUTO_DETECT (echoing back `steps: []` in afEnv). Use
    // the user-authored description when present (via step.value on action
    // descriptors that don't otherwise consume value), or derive one.
    const description = describeStep(step, i);
    if (step.action === 'wait') {
      // ZAP's WAIT step takes the wait duration via the step's `timeout`
      // (ms). The validator already requires step.wait_ms; we mirror it into
      // the timeout field per ZAP's WAIT convention.
      if (typeof step.wait_ms !== 'number') {
        throw new Error(`buildRecordedAuthForZap: step ${i} wait requires wait_ms`);
      }
      zapSteps.push({ description, type: 'WAIT', timeout: step.wait_ms });
    } else if (step.action === 'return' || step.action === 'escape') {
      // RETURN/ESCAPE need no selector or value; ZAP sends the keystroke.
      zapSteps.push({ description, type: zapType });
    } else if (step.action === 'type_custom') {
      // CUSTOM_FIELD requires a selector + value. The value is a literal
      // string ZAP types into the targeted element (treated as potentially-
      // secret in all log / summary surfaces — the parser redacts it).
      if (!step.selector || typeof step.value !== 'string') {
        throw new Error(`buildRecordedAuthForZap: step ${i} type_custom missing selector or value`);
      }
      zapSteps.push({
        description,
        type: 'CUSTOM_FIELD',
        ...recordedSelectorField(step),
        value: step.value,
        timeout: step.timeout_ms ?? RECORDED_DEFAULT_STEP_TIMEOUT_MS,
      });
    } else if (step.action === 'type_username') {
      // USERNAME requires both selector AND value. Without value: AND
      // description:, ZAP's schema validator drops the step (the array
      // becomes empty in afEnv, AUTO_DETECT runs instead). Thread the
      // decrypted credential into the step so ZAP's schema is satisfied.
      // YAML lives at mode 0600 + unlinked after spawn (same posture as
      // the form strategy).
      if (!step.selector) {
        throw new Error(`buildRecordedAuthForZap: step ${i} type_username requires a selector`);
      }
      zapSteps.push({
        description,
        type: 'USERNAME',
        ...recordedSelectorField(step),
        value: payload.username,
        timeout: step.timeout_ms ?? RECORDED_DEFAULT_STEP_TIMEOUT_MS,
      });
    } else if (step.action === 'type_password') {
      // PASSWORD: same `value:` + `description:` requirement as USERNAME.
      if (!step.selector) {
        throw new Error(`buildRecordedAuthForZap: step ${i} type_password requires a selector`);
      }
      zapSteps.push({
        description,
        type: 'PASSWORD',
        ...recordedSelectorField(step),
        value: payload.password,
        timeout: step.timeout_ms ?? RECORDED_DEFAULT_STEP_TIMEOUT_MS,
      });
    } else {
      // click / type_totp — selector-only. TOTP_FIELD generates the code
      // at scan time from credentials.totp; no `value:` needed on the step.
      if (!step.selector) {
        throw new Error(`buildRecordedAuthForZap: step ${i} ${step.action} requires a selector`);
      }
      zapSteps.push({
        description,
        type: zapType,
        ...recordedSelectorField(step),
        timeout: step.timeout_ms ?? RECORDED_DEFAULT_STEP_TIMEOUT_MS,
      });
    }
    internalIndexToZapIndex.push(zapIdx);
    zapIdx++;
  }

  // Defense in case the user authored zero non-goto steps. ZAP's browser auth
  // needs at least one credential-type step to make the login meaningful.
  if (zapSteps.length === 0) {
    throw new Error('buildRecordedAuthForZap: payload.steps must contain at least one non-goto step');
  }

  const verification: Record<string, unknown> = { method: 'response' };
  if (loggedInIndicator) verification.loggedInRegex = loggedInIndicator;
  if (loggedOutIndicator) verification.loggedOutRegex = loggedOutIndicator;

  // login_page_wait / step_delay are ZAP's `loginPageWait` / `stepDelay`
  // parameters (seconds in the AF schema). The validator stores them as ms;
  // we convert to seconds (rounded to nearest int, since the AF schema is
  // integer-valued in seconds for this addon).
  const loginPageWaitSec = Math.max(
    0,
    Math.round((payload.login_page_wait_ms ?? RECORDED_DEFAULT_LOGIN_PAGE_WAIT_MS) / 1000),
  );
  const stepDelaySec = Math.max(
    0,
    Math.round((payload.step_delay_ms ?? RECORDED_DEFAULT_STEP_DELAY_MS) / 1000),
  );

  const contextAuthentication: Record<string, unknown> = {
    method: 'browser',
    parameters: {
      loginPageUrl,
      loginPageWait: loginPageWaitSec,
      stepDelay: stepDelaySec,
      browserId: 'firefox-headless',
      // NOTE: `diagnostics: true` was emitted in the v2.1d M2 implementation
      // on the assumption it would produce per-step success/failure log
      // events. The empirical spike against ZAP 2.17.0 + authhelper v0.39.0
      // showed the field is a no-op — ZAP emits no per-step events on any
      // channel (stderr / stdout / zap.log). The structured signal lives in
      // the `auth-report-json` report template, which the yaml-builder emits
      // and the runner parses. Field intentionally omitted.
      steps: zapSteps,
    },
    verification,
  };

  // The ZAP user has username + password baked in; the USERNAME / PASSWORD
  // / TOTP_FIELD steps read these. ZAP browser-auth uses the credentials
  // block to substitute the values at step execution time.
  const credentials: Record<string, unknown> = {
    username: payload.username,
    password: payload.password,
  };
  if (payload.totp_secret) {
    // ZAP browser-auth TOTP_FIELD reads credentials.totp (base32 secret) and
    // generates the 6-digit code at scan time using RFC 6238 defaults
    // (period=30, digits=6, alg=SHA1). M0 verifies the exact key name.
    credentials.totp = payload.totp_secret;
  }

  const contextUsers: Array<Record<string, unknown>> = [
    { name: 'deptex-dast-user', credentials },
  ];

  // Marker that 'goto' was collapsed — useful in logs / debug but the parser
  // already gets the mapping array.
  void gotoCollapsed;

  return { contextAuthentication, contextUsers, internalIndexToZapIndex };
}
