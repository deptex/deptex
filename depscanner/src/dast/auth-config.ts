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

export type CredentialPayload =
  | FormCredentialPayload
  | JwtCredentialPayload
  | CookieCredentialPayload;

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

export function buildAuthForStrategy(
  strategy: DastAuthStrategy,
  payload: CredentialPayload,
  loggedInIndicator?: string,
  loggedOutIndicator?: string,
): AuthBuildResult {
  if (strategy === 'recorded' || (payload as { kind: string }).kind === 'recorded') {
    throw new UnsupportedAuthStrategyError('recorded');
  }
  if (payload.kind !== strategy) {
    throw new Error(
      `DAST auth payload.kind='${payload.kind}' mismatches strategy='${strategy}'`,
    );
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
