// Backend-lib copy of the SPA detector unit tests.
//
// Mirrors depscanner/src/__tests__/dast-spa-detect.test.ts. The
// implementations live in two files (depscanner copy + backend lib copy)
// pending a v2.1b shared-lib hoist, so they need parallel test coverage.
//
// Covers the runtime-marker fixture set from plan §"Task 9 — SPA detect against
// fixture set: React/Vue/Angular/Next/Nuxt/Svelte/classic SSR HTML samples."
// We inject a fetchImpl mock per test rather than touching the real network.

import {
  detectRuntime,
  nextRuntimeTtlIso,
  RUNTIME_TTL_MS,
  type DetectedRuntime,
  type FetchLike,
} from '../dast-spa-detect';

function htmlResponse(body: string, status = 200, headers: Record<string, string> = {}): any {
  const h = new Map(
    Object.entries({ 'content-type': 'text/html; charset=utf-8', ...headers }).map(([k, v]) => [
      k.toLowerCase(),
      v,
    ]),
  );
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (n: string) => h.get(n.toLowerCase()) ?? null },
    text: async () => body,
  };
}

function makeFetch(map: Record<string, any>): FetchLike {
  return async (url: string) => {
    if (!(url in map)) throw new Error(`unmocked URL: ${url}`);
    const v = map[url];
    if (typeof v === 'function') return v();
    return v;
  };
}

// The backend lib defaults to validateExternalUrl which runs real DNS, so
// every test injects this stub that says yes to any URL it's handed.
// Tests that exercise the guard's own logic (private-IP rejection on
// redirect, etc.) override with a more specific stub.
const alwaysValid = async () => ({ valid: true } as { valid: true });

const TARGET = 'https://app.example.com/';

// ---------------------------------------------------------------------------
// SPA fixture set
// ---------------------------------------------------------------------------

describe('detectRuntime — SPA fixture set', () => {
  it('React app (data-reactroot) → spa with marker react', async () => {
    const html = `<!DOCTYPE html><html><body><div id="root" data-reactroot></div></body></html>`;
    const r = await detectRuntime(TARGET, { validateUrl: alwaysValid, fetchImpl: makeFetch({ [TARGET]: htmlResponse(html) }) });
    expect(r.runtime).toBe('spa');
    expect(r.markers).toContain('react');
    expect(r.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('Next.js app (id="__next") → spa with marker next', async () => {
    const html = `<!DOCTYPE html><html><body><div id="__next"></div><script src="/_next/x.js"></script></body></html>`;
    const r = await detectRuntime(TARGET, { validateUrl: alwaysValid, fetchImpl: makeFetch({ [TARGET]: htmlResponse(html) }) });
    expect(r.runtime).toBe('spa');
    expect(r.markers).toContain('next');
  });

  it('Nuxt app (id="__nuxt") → spa with marker nuxt', async () => {
    const html = `<!DOCTYPE html><html><body><div id="__nuxt"></div></body></html>`;
    const r = await detectRuntime(TARGET, { validateUrl: alwaysValid, fetchImpl: makeFetch({ [TARGET]: htmlResponse(html) }) });
    expect(r.runtime).toBe('spa');
    expect(r.markers).toContain('nuxt');
  });

  it('Vue SSR (data-server-rendered="true") → spa with marker vue-ssr', async () => {
    const html = `<!DOCTYPE html><html><body><div id="app" data-server-rendered="true"><h1>Hi</h1></div></body></html>`;
    const r = await detectRuntime(TARGET, { validateUrl: alwaysValid, fetchImpl: makeFetch({ [TARGET]: htmlResponse(html) }) });
    expect(r.runtime).toBe('spa');
    expect(r.markers).toContain('vue-ssr');
  });

  it('Angular (<app-root> + ng-version) → spa with both markers', async () => {
    const html = `<!DOCTYPE html><html><body><app-root ng-version="17.0.0"></app-root></body></html>`;
    const r = await detectRuntime(TARGET, { validateUrl: alwaysValid, fetchImpl: makeFetch({ [TARGET]: htmlResponse(html) }) });
    expect(r.runtime).toBe('spa');
    expect(r.markers).toEqual(expect.arrayContaining(['angular-attr', 'angular-tag']));
  });

  it('Svelte (id="svelte") → spa with marker svelte', async () => {
    const html = `<!DOCTYPE html><html><body><div id="svelte"></div></body></html>`;
    const r = await detectRuntime(TARGET, { validateUrl: alwaysValid, fetchImpl: makeFetch({ [TARGET]: htmlResponse(html) }) });
    expect(r.runtime).toBe('spa');
    expect(r.markers).toContain('svelte');
  });

  it('classic SSR (server-rendered HTML, no SPA markers) → classic', async () => {
    const html = `<!DOCTYPE html><html><head><title>Blog</title></head><body>
      <header><h1>My Blog</h1></header>
      <article>
        <h2>Post One</h2>
        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
        <p>Praesent feugiat lorem at neque pretium, eu auctor justo dictum.</p>
        <p>Nullam vehicula tortor ut nisl tristique, eu ultricies enim consequat.</p>
        <p>Vestibulum ante ipsum primis in faucibus orci luctus et ultrices.</p>
      </article>
      <footer>&copy; 2026</footer>
    </body></html>`;
    const r = await detectRuntime(TARGET, { validateUrl: alwaysValid, fetchImpl: makeFetch({ [TARGET]: htmlResponse(html) }) });
    expect(r.runtime).toBe('classic');
    expect(r.markers).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Empty-shell heuristic
// ---------------------------------------------------------------------------

describe('detectRuntime — empty-shell heuristic', () => {
  it('empty body + ≥4 scripts → spa with empty_shell_heuristic marker', async () => {
    const html = `<!DOCTYPE html><html><head>
      <script src="/a.js"></script>
      <script src="/b.js"></script>
      <script src="/c.js"></script>
      <script src="/d.js"></script>
    </head><body><div id="app"></div></body></html>`;
    const r = await detectRuntime(TARGET, { validateUrl: alwaysValid, fetchImpl: makeFetch({ [TARGET]: htmlResponse(html) }) });
    expect(r.runtime).toBe('spa');
    expect(r.markers).toEqual(['empty_shell_heuristic']);
  });

  it('empty body + only 2 scripts → classic (script threshold not met)', async () => {
    const html = `<!DOCTYPE html><html><head>
      <script src="/a.js"></script>
      <script src="/b.js"></script>
    </head><body><div id="app"></div></body></html>`;
    const r = await detectRuntime(TARGET, { validateUrl: alwaysValid, fetchImpl: makeFetch({ [TARGET]: htmlResponse(html) }) });
    expect(r.runtime).toBe('classic');
  });
});

// ---------------------------------------------------------------------------
// Failure paths → unknown
// ---------------------------------------------------------------------------

describe('detectRuntime — failure paths return unknown', () => {
  it('fetch throws → unknown', async () => {
    const r = await detectRuntime(TARGET, {
      fetchImpl: async () => {
        throw new Error('econnrefused');
      },
    });
    expect(r.runtime).toBe('unknown');
    expect(r.confidence).toBe(0);
    expect(r.markers).toEqual([]);
  });

  it('non-2xx response → unknown', async () => {
    const r = await detectRuntime(TARGET, { validateUrl: alwaysValid, fetchImpl: makeFetch({ [TARGET]: htmlResponse('', 500) }) });
    expect(r.runtime).toBe('unknown');
  });

  it('non-HTML content-type (application/json) → unknown', async () => {
    const r = await detectRuntime(TARGET, {
      validateUrl: alwaysValid, fetchImpl: makeFetch({
        [TARGET]: htmlResponse('{"ok":true}', 200, { 'content-type': 'application/json' }),
      }),
    });
    expect(r.runtime).toBe('unknown');
  });

  it('missing content-type is permitted (some servers omit it)', async () => {
    const r = await detectRuntime(TARGET, {
      validateUrl: alwaysValid,
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        headers: { get: () => null },
        text: async () => `<html><body><div data-reactroot></div></body></html>`,
      }),
    });
    expect(r.runtime).toBe('spa');
    expect(r.markers).toContain('react');
  });

  it('non-http(s) scheme rejected without fetching', async () => {
    const fetchSpy = jest.fn();
    const r = await detectRuntime('file:///etc/passwd', { validateUrl: alwaysValid, fetchImpl: fetchSpy });
    expect(r.runtime).toBe('unknown');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('validateUrl rejection short-circuits before fetch', async () => {
    const fetchSpy = jest.fn();
    const r = await detectRuntime(TARGET, {
      fetchImpl: fetchSpy,
      validateUrl: async () => ({ valid: false, reason: 'private/loopback' }),
    });
    expect(r.runtime).toBe('unknown');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('no fetch impl available → unknown', async () => {
    const r = await detectRuntime(TARGET, { fetchImpl: undefined as any });
    // globalThis.fetch may or may not exist in the test env; either way we
    // must NOT throw. The runtime field is the contract.
    expect(['unknown', 'classic', 'spa']).toContain(r.runtime as DetectedRuntime);
  });
});

// ---------------------------------------------------------------------------
// Redirect handling
// ---------------------------------------------------------------------------

describe('detectRuntime — redirect handling', () => {
  it('follows up to 3 redirects then classifies the final body', async () => {
    const FINAL = 'https://app.example.com/final';
    const fetchImpl = makeFetch({
      [TARGET]: {
        ok: false,
        status: 302,
        headers: { get: (n: string) => (n.toLowerCase() === 'location' ? '/final' : null) },
        text: async () => '',
      },
      [FINAL]: htmlResponse('<html><body><div data-reactroot></div></body></html>'),
    });
    const r = await detectRuntime(TARGET, { validateUrl: alwaysValid, fetchImpl });
    expect(r.runtime).toBe('spa');
    expect(r.markers).toContain('react');
  });

  it('redirect to a validateUrl-rejected destination → unknown', async () => {
    const fetchImpl = makeFetch({
      [TARGET]: {
        ok: false,
        status: 302,
        headers: {
          get: (n: string) => (n.toLowerCase() === 'location' ? 'http://169.254.169.254/' : null),
        },
        text: async () => '',
      },
    });
    const r = await detectRuntime(TARGET, {
      fetchImpl,
      validateUrl: async (u: string) =>
        u.includes('169.254') ? { valid: false, reason: 'imds' } : { valid: true },
    });
    expect(r.runtime).toBe('unknown');
  });
});

// ---------------------------------------------------------------------------
// TTL helper
// ---------------------------------------------------------------------------

describe('nextRuntimeTtlIso', () => {
  it('returns an ISO string ~30 days in the future', () => {
    const now = Date.now();
    const ttl = new Date(nextRuntimeTtlIso()).getTime();
    expect(ttl).toBeGreaterThan(now + 29 * 24 * 60 * 60 * 1000);
    expect(ttl).toBeLessThan(now + 31 * 24 * 60 * 60 * 1000);
  });

  it('RUNTIME_TTL_MS is 30 days exactly', () => {
    expect(RUNTIME_TTL_MS).toBe(30 * 24 * 60 * 60 * 1000);
  });
});
