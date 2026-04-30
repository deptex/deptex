import { matchRoute, normalizeRoute, isSupportedFramework } from '../dast/route-matcher';

describe('isSupportedFramework', () => {
  it('returns true for the 8 v1 frameworks', () => {
    for (const fw of ['express', 'fastify', 'fastapi', 'spring', 'rails', 'gin', 'sinatra', 'laravel']) {
      expect(isSupportedFramework(fw)).toBe(true);
    }
  });

  it('returns false for unsupported frameworks', () => {
    for (const fw of ['nextjs', 'koa', 'flask', 'django', 'echo', 'nethttp', 'symfony', 'unknown', '']) {
      expect(isSupportedFramework(fw)).toBe(false);
    }
  });
});

describe('matchRoute — Express / Fastify', () => {
  it('matches static routes', () => {
    expect(matchRoute('/api/users', '/api/users', 'express')).toBe(true);
    expect(matchRoute('/api/users', '/api/users', 'fastify')).toBe(true);
  });

  it('matches single param route', () => {
    expect(matchRoute('/users/42', '/users/:id', 'express')).toBe(true);
    expect(matchRoute('/users/abc-123', '/users/:id', 'fastify')).toBe(true);
  });

  it('matches multi-param route', () => {
    expect(matchRoute('/users/42/posts/9', '/users/:userId/posts/:postId', 'express')).toBe(true);
  });

  it('rejects when literal segments differ', () => {
    expect(matchRoute('/users/42/posts', '/users/:id', 'express')).toBe(false);
    expect(matchRoute('/usersextra/42', '/users/:id', 'express')).toBe(false);
    expect(matchRoute('/users', '/users/:id', 'express')).toBe(false);
  });

  it('handles regex-constrained params', () => {
    expect(matchRoute('/files/123', '/files/:id(\\d+)', 'express')).toBe(true);
    expect(matchRoute('/files/abc', '/files/:id(\\d+)', 'express')).toBe(false);
  });

  it('handles wildcard', () => {
    expect(matchRoute('/proxy/anything/here', '/proxy/*', 'express')).toBe(true);
    expect(matchRoute('/proxy/', '/proxy/*', 'express')).toBe(true);
  });

  it('handles trailing slash insensitivity', () => {
    expect(matchRoute('/api/users/', '/api/users', 'express')).toBe(true);
    expect(matchRoute('/api/users', '/api/users/', 'express')).toBe(true);
  });

  it('strips full URL scheme+host', () => {
    expect(matchRoute('https://staging.example.com/users/42', '/users/:id', 'express')).toBe(true);
    expect(matchRoute('http://localhost:3001/users/42?foo=bar', '/users/:id', 'express')).toBe(true);
  });
});

describe('matchRoute — FastAPI / Spring / Laravel (brace syntax)', () => {
  it('matches FastAPI route', () => {
    expect(matchRoute('/items/9', '/items/{item_id}', 'fastapi')).toBe(true);
    expect(matchRoute('/items/9/details', '/items/{item_id}', 'fastapi')).toBe(false);
  });

  it('honors typed FastAPI param', () => {
    // FastAPI type names map to known regex classes — `int` → `[0-9]+`.
    expect(matchRoute('/items/9', '/items/{item_id:int}', 'fastapi')).toBe(true);
    expect(matchRoute('/items/abc', '/items/{item_id:int}', 'fastapi')).toBe(false);
    expect(matchRoute('/items/123e4567-e89b', '/items/{id:uuid}', 'fastapi')).toBe(true);
  });

  it('matches Spring-style brace + regex', () => {
    expect(matchRoute('/api/users/9', '/api/users/{id:[0-9]+}', 'spring')).toBe(true);
    expect(matchRoute('/api/users/abc', '/api/users/{id:[0-9]+}', 'spring')).toBe(false);
  });

  it('matches Laravel optional brace', () => {
    expect(matchRoute('/posts/intro', '/posts/{slug?}', 'laravel')).toBe(true);
  });
});

describe('matchRoute — Rails / Sinatra / Gin', () => {
  it('matches Rails dynamic segments', () => {
    expect(matchRoute('/users/42', '/users/:id', 'rails')).toBe(true);
    expect(matchRoute('/photos/42.json', '/photos/:id.:format', 'rails')).toBe(true);
    expect(matchRoute('/photos/42', '/photos/:id.:format', 'rails')).toBe(false);
  });

  it('matches Rails wildcard splat', () => {
    expect(matchRoute('/files/foo/bar/baz', '/files/*path', 'rails')).toBe(true);
  });

  it('matches Sinatra dynamic segments', () => {
    expect(matchRoute('/posts/hello', '/posts/:slug', 'sinatra')).toBe(true);
  });

  it('matches Gin dynamic segments + wildcard', () => {
    expect(matchRoute('/users/42/posts', '/users/:id/posts', 'gin')).toBe(true);
    expect(matchRoute('/static/foo/bar.js', '/static/*filepath', 'gin')).toBe(true);
  });
});

describe('matchRoute — unsupported frameworks fall back to exact match', () => {
  it('exact-matches without false positives', () => {
    expect(matchRoute('/api/users', '/api/users', 'nextjs')).toBe(true);
    expect(matchRoute('/api/users/42', '/api/users/:id', 'nextjs')).toBe(false);
  });
});

describe('matchRoute — negative corpus', () => {
  it('rejects /usersextra/42 against /users/:id (boundary case)', () => {
    expect(matchRoute('/usersextra/42', '/users/:id', 'express')).toBe(false);
  });

  it('rejects empty path against any param route', () => {
    expect(matchRoute('/', '/users/:id', 'express')).toBe(false);
  });

  it('rejects partial match (no anchoring slip)', () => {
    expect(matchRoute('/users/42/extra', '/users/:id', 'express')).toBe(false);
  });
});

describe('normalizeRoute', () => {
  it('returns RegExp for supported framework', () => {
    const re = normalizeRoute('express', '/users/:id');
    expect(re).toBeInstanceOf(RegExp);
    expect(re!.test('/users/42')).toBe(true);
  });

  it('returns null for unsupported framework', () => {
    expect(normalizeRoute('nextjs', '/api/users/:id')).toBeNull();
  });
});

// 20+ tuple test corpus per plan Task 10 acceptance.
describe('matchRoute — 20-tuple plan acceptance corpus', () => {
  const corpus: Array<[
    /* zapUrl */ string,
    /* pattern */ string,
    /* framework */ string,
    /* expected */ boolean,
    /* note */ string,
  ]> = [
    ['/api/users/42', '/api/users/:id', 'express', true, 'express positive'],
    ['/api/users/42/posts', '/api/users/:id', 'express', false, 'express extra-segment negative'],
    ['/users/42', '/users/:id/posts', 'express', false, 'express missing-segment negative'],
    ['/usersextra/42', '/users/:id', 'express', false, 'express literal-prefix boundary negative'],
    ['/api/v1/items/9', '/api/v1/items/{id}', 'fastapi', true, 'fastapi positive'],
    ['/items/9/extra', '/items/{id}', 'fastapi', false, 'fastapi negative extra segment'],
    ['/api/users/9', '/api/users/{id:[0-9]+}', 'spring', true, 'spring typed positive'],
    ['/api/users/abc', '/api/users/{id:[0-9]+}', 'spring', false, 'spring typed negative'],
    ['/api/posts/hello-world', '/api/posts/:slug', 'rails', true, 'rails positive'],
    ['/photos/42.json', '/photos/:id.:format', 'rails', true, 'rails compound segment positive'],
    ['/files/a/b/c', '/files/*path', 'rails', true, 'rails splat positive'],
    ['/files/a/b/c', '/files/*filepath', 'gin', true, 'gin wildcard positive'],
    ['/users/42/posts', '/users/:id/posts', 'gin', true, 'gin static-after-param positive'],
    ['/posts/hello', '/posts/:slug', 'sinatra', true, 'sinatra positive'],
    ['/api/users/9', '/api/users/:id', 'fastify', true, 'fastify positive'],
    ['/posts/intro', '/posts/{slug?}', 'laravel', true, 'laravel optional positive'],
    ['/files/123', '/files/:id(\\d+)', 'express', true, 'express regex constraint positive'],
    ['/files/abc', '/files/:id(\\d+)', 'express', false, 'express regex constraint negative'],
    ['https://prod.example.com/api/users/42', '/api/users/:id', 'express', true, 'full-URL positive'],
    ['/api/v2/users/42', '/api/v1/users/:id', 'express', false, 'mismatched literal version negative'],
    ['/api/v1/users/42/', '/api/v1/users/:id', 'express', true, 'trailing slash insensitivity'],
    ['/api/users', '/api/users', 'unknown-fw', true, 'unknown framework exact match positive'],
    ['/api/users/42', '/api/users/:id', 'unknown-fw', false, 'unknown framework non-exact rejected'],
  ];

  it.each(corpus)('matchRoute(%s, %s, %s) === %s [%s]', (zapUrl, pattern, fw, expected, _note) => {
    expect(matchRoute(zapUrl, pattern, fw)).toBe(expected);
  });
});
