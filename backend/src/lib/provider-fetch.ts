/**
 * Shared rate-limit + error-classification helpers for the GitHub / GitLab /
 * Bitbucket provider clients. Three things every provider needs:
 *
 *   1. A typed `RateLimitedError` so route handlers can return HTTP 429 with a
 *      generic user-facing message and `Retry-After`, instead of leaking the
 *      raw upstream body to the user.
 *
 *   2. A typed `AuthExpiredError` so each provider's bbFetch/gitlabFetch
 *      wrapper can recognise a 401 and trigger the refresh-token flow.
 *
 *   3. A typed `ProviderError` for everything else, with the upstream status
 *      attached but with the bare 4xx/5xx body stripped from the message that
 *      will eventually reach the user.
 *
 * Routes should NEVER do `res.json({ error: error.message })` for any of
 * these. The route's job is to map error type → user-facing copy.
 */

export type ProviderName = 'github' | 'gitlab' | 'bitbucket';

export class ProviderError extends Error {
  constructor(
    public provider: ProviderName,
    public status: number,
    public path: string,
    cause?: string,
  ) {
    super(`${provider} ${status} on ${path}${cause ? `: ${cause}` : ''}`);
  }
}

export class AuthExpiredError extends ProviderError {
  constructor(provider: ProviderName, path: string, cause?: string) {
    super(provider, 401, path, cause);
  }
}

export class RateLimitedError extends ProviderError {
  constructor(
    provider: ProviderName,
    path: string,
    public retryAfterMs: number,
    cause?: string,
  ) {
    super(provider, 429, path, cause);
  }
}

/**
 * Inspect a response (and its body, already read) and decide if this is a
 * rate-limit case. GitHub returns 429 OR 403 with a body containing
 * "secondary rate limit" / "abuse detection". GitLab/Bitbucket use 429.
 *
 * Returns retry-after in ms (or null if not rate limited).
 */
export function parseRateLimit(response: Response, body: string): number | null {
  if (response.status === 429) {
    const ra = response.headers.get('retry-after');
    if (ra) {
      const seconds = Number(ra);
      if (Number.isFinite(seconds) && seconds > 0) return seconds * 1000;
    }
    return 60_000;
  }

  if (response.status === 403) {
    const reset = response.headers.get('x-ratelimit-reset');
    const remaining = response.headers.get('x-ratelimit-remaining');
    if (remaining === '0' && reset) {
      const resetMs = Number(reset) * 1000 - Date.now();
      if (Number.isFinite(resetMs) && resetMs > 0 && resetMs < 60 * 60 * 1000) {
        return resetMs;
      }
    }
    const bodyLower = body.toLowerCase();
    if (
      bodyLower.includes('secondary rate limit') ||
      bodyLower.includes('abuse detection') ||
      bodyLower.includes('exceeded a rate limit')
    ) {
      const ra = response.headers.get('retry-after');
      if (ra) {
        const seconds = Number(ra);
        if (Number.isFinite(seconds) && seconds > 0) return seconds * 1000;
      }
      return 60_000;
    }
  }

  return null;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, Math.min(ms, 30_000)));
}

/**
 * Run a request once, classify the response, and on rate-limit do one bounded
 * retry honouring Retry-After. On 401, throw `AuthExpiredError` so the
 * caller's refresh-token wrapper can handle it. On any other non-2xx, throw
 * `ProviderError` so the route handler can return a generic user message.
 *
 * Callers pass a `doFetch` closure that performs the actual fetch — this lets
 * the helper retry it cleanly without the caller having to thread auth state
 * back in.
 */
export async function fetchWithRetry(
  provider: ProviderName,
  path: string,
  doFetch: () => Promise<Response>,
): Promise<Response> {
  let response = await doFetch();

  if (response.status >= 400) {
    const body = await response.clone().text();
    if (response.status === 401) {
      throw new AuthExpiredError(provider, path, body.slice(0, 200));
    }

    const retryAfterMs = parseRateLimit(response, body);
    if (retryAfterMs !== null) {
      await sleep(retryAfterMs);
      response = await doFetch();
      if (response.ok) return response;
      const body2 = await response.clone().text();
      const retryAfterMs2 = parseRateLimit(response, body2);
      if (retryAfterMs2 !== null) {
        throw new RateLimitedError(provider, path, retryAfterMs2, 'still rate-limited after retry');
      }
      if (response.status === 401) {
        throw new AuthExpiredError(provider, path, body2.slice(0, 200));
      }
      throw new ProviderError(provider, response.status, path, body2.slice(0, 200));
    }

    throw new ProviderError(provider, response.status, path, body.slice(0, 200));
  }

  return response;
}
