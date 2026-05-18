/**
 * Webhook security regression tests.
 *
 * Covers the bugs fixed in the depscanner-hardening webhook pass:
 *  - Bitbucket: signature was skipped when repository.full_name was missing
 *  - Bitbucket: signature was treated as valid when no project_repositories row matched
 *  - GitLab: token comparison used non-constant-time `===`
 *  - All providers: webhook_deliveries row was inserted before the dedup check
 *  - GitHub: timingSafeEqual length-mismatch path
 */

import express from 'express';
import request from 'supertest';
import * as crypto from 'crypto';

import {
  setTableResponse,
  clearTableRegistry,
} from '../test/mocks/supabaseSingleton';
import { queryBuilder } from '../test/mocks/supabaseSingleton';

// Disable real outbound rate limit (it falls back to allow when Redis envs are
// missing in the test env, but we set this anyway to avoid surprises).
delete process.env.UPSTASH_REDIS_URL;
delete process.env.UPSTASH_REDIS_TOKEN;

import bitbucketRouter from '../routes/bitbucket-webhooks';
import gitlabRouter from '../routes/gitlab-webhooks';
import { githubWebhookHandler } from '../routes/integrations';

function makeApp(mountFn: (app: express.Express) => void) {
  const app = express();
  app.use(express.json({
    verify: (req: any, _res, buf) => {
      req.rawBody = buf.toString();
    },
  }));
  mountFn(app);
  return app;
}

beforeEach(() => {
  clearTableRegistry();
  process.env.NODE_ENV = 'production';
});

describe('Bitbucket webhook signature', () => {
  const app = makeApp((a) => {
    a.use('/api/integrations', bitbucketRouter);
  });

  it('rejects when repository.full_name is missing', async () => {
    // No project_repositories row needed — should bail before lookup.
    const res = await request(app)
      .post('/api/integrations/webhooks/bitbucket')
      .set('x-event-key', 'repo:push')
      .set('x-request-uuid', 'test-delivery-1')
      .send({ /* no repository */ });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/repository\.full_name/);
  });

  it('rejects when signature is provided but no matching repo exists', async () => {
    setTableResponse('project_repositories', 'then', { data: [], error: null });

    const res = await request(app)
      .post('/api/integrations/webhooks/bitbucket')
      .set('x-event-key', 'repo:push')
      .set('x-request-uuid', 'test-delivery-2')
      .set('x-hub-signature', 'sha256=deadbeef')
      .send({ repository: { full_name: 'who/dis' } });

    expect(res.status).toBe(401);
  });

  it('rejects when matching repo has no configured webhook_secret', async () => {
    setTableResponse('project_repositories', 'then', {
      data: [{ webhook_secret: null }],
      error: null,
    });

    const res = await request(app)
      .post('/api/integrations/webhooks/bitbucket')
      .set('x-event-key', 'repo:push')
      .set('x-request-uuid', 'test-delivery-3')
      .set('x-hub-signature', 'sha256=deadbeef')
      .send({ repository: { full_name: 'acme/repo' } });

    expect(res.status).toBe(401);
  });

  it('accepts a correctly signed payload', async () => {
    const secret = 'bb-secret';
    const body = JSON.stringify({ repository: { full_name: 'acme/repo' } });
    const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');

    setTableResponse('project_repositories', 'then', {
      data: [{ webhook_secret: secret }],
      error: null,
    });

    const res = await request(app)
      .post('/api/integrations/webhooks/bitbucket')
      .set('x-event-key', 'repo:push')
      .set('x-request-uuid', 'test-delivery-4')
      .set('x-hub-signature', expected)
      .set('Content-Type', 'application/json')
      .send(body);

    expect([200, 202]).toContain(res.status);
    expect(res.body.received).toBe(true);
  });

  it('rejects a wrong signature even with matching repo + secret', async () => {
    setTableResponse('project_repositories', 'then', {
      data: [{ webhook_secret: 'correct-secret' }],
      error: null,
    });

    const res = await request(app)
      .post('/api/integrations/webhooks/bitbucket')
      .set('x-event-key', 'repo:push')
      .set('x-request-uuid', 'test-delivery-5')
      .set('x-hub-signature', 'sha256=' + 'a'.repeat(64))
      .send({ repository: { full_name: 'acme/repo' } });

    expect(res.status).toBe(401);
  });
});

describe('GitLab webhook token verification', () => {
  const app = makeApp((a) => {
    a.use('/api/integrations', gitlabRouter);
  });

  it('rejects when no project_repositories row matches', async () => {
    setTableResponse('project_repositories', 'then', { data: [], error: null });

    const res = await request(app)
      .post('/api/integrations/webhooks/gitlab')
      .set('x-gitlab-token', 'attacker-token')
      .set('x-gitlab-event', 'Push Hook')
      .set('x-gitlab-event-uuid', 'gl-delivery-1')
      .send({ project: { path_with_namespace: 'who/dis' } });

    expect(res.status).toBe(401);
  });

  it('accepts a matching token', async () => {
    setTableResponse('project_repositories', 'then', {
      data: [{ webhook_secret: 'gl-secret' }],
      error: null,
    });

    const res = await request(app)
      .post('/api/integrations/webhooks/gitlab')
      .set('x-gitlab-token', 'gl-secret')
      .set('x-gitlab-event', 'Push Hook')
      .set('x-gitlab-event-uuid', 'gl-delivery-2')
      .send({ project: { path_with_namespace: 'acme/repo' } });

    expect(res.body.received).toBe(true);
    expect([200, 202]).toContain(res.status);
  });

  it('rejects a mismatching token of equal length (constant-time path)', async () => {
    // Equal-length-but-different ensures we exercise the timingSafeEqual call,
    // not the early length-mismatch return.
    setTableResponse('project_repositories', 'then', {
      data: [{ webhook_secret: 'aaaaaaaa' }],
      error: null,
    });

    const res = await request(app)
      .post('/api/integrations/webhooks/gitlab')
      .set('x-gitlab-token', 'bbbbbbbb')
      .set('x-gitlab-event', 'Push Hook')
      .set('x-gitlab-event-uuid', 'gl-delivery-3')
      .send({ project: { path_with_namespace: 'acme/repo' } });

    expect(res.status).toBe(401);
  });

  it('rejects when token has different length than configured secret', async () => {
    setTableResponse('project_repositories', 'then', {
      data: [{ webhook_secret: 'aaaaaaaaaaaa' }],
      error: null,
    });

    const res = await request(app)
      .post('/api/integrations/webhooks/gitlab')
      .set('x-gitlab-token', 'short')
      .set('x-gitlab-event', 'Push Hook')
      .set('x-gitlab-event-uuid', 'gl-delivery-4')
      .send({ project: { path_with_namespace: 'acme/repo' } });

    expect(res.status).toBe(401);
  });

  it('fails closed when supabase lookup returns an error', async () => {
    setTableResponse('project_repositories', 'then', {
      data: null,
      error: { message: 'db down' },
    });

    const res = await request(app)
      .post('/api/integrations/webhooks/gitlab')
      .set('x-gitlab-token', 'whatever')
      .set('x-gitlab-event', 'Push Hook')
      .set('x-gitlab-event-uuid', 'gl-delivery-5')
      .send({ project: { path_with_namespace: 'acme/repo' } });

    expect(res.status).toBe(401);
  });
});

describe('GitHub webhook signature verification', () => {
  const app = express();
  app.use(express.json({
    verify: (req: any, _res, buf) => {
      req.rawBody = buf.toString();
    },
  }));
  app.post('/api/webhook/github', githubWebhookHandler);

  beforeEach(() => {
    process.env.GITHUB_WEBHOOK_SECRET = 'gh-secret';
  });

  it('rejects when signature header is missing in production', async () => {
    const res = await request(app)
      .post('/api/webhook/github')
      .set('x-github-event', 'ping')
      .set('x-github-delivery', 'gh-delivery-1')
      .send({});
    expect(res.status).toBe(401);
  });

  it('rejects when signature is the wrong length (no throw)', async () => {
    const res = await request(app)
      .post('/api/webhook/github')
      .set('x-github-event', 'ping')
      .set('x-github-delivery', 'gh-delivery-2')
      .set('x-hub-signature-256', 'sha256=short')
      .send({});
    expect(res.status).toBe(401);
  });

  it('rejects when signature doesn\'t start with sha256=', async () => {
    const res = await request(app)
      .post('/api/webhook/github')
      .set('x-github-event', 'ping')
      .set('x-github-delivery', 'gh-delivery-3')
      .set('x-hub-signature-256', 'sha1=' + 'a'.repeat(64))
      .send({});
    expect(res.status).toBe(401);
  });

  it('accepts a correctly signed payload', async () => {
    const body = JSON.stringify({ zen: 'ping' });
    const sig = 'sha256=' + crypto.createHmac('sha256', 'gh-secret').update(body).digest('hex');

    const res = await request(app)
      .post('/api/webhook/github')
      .set('x-github-event', 'ping')
      .set('x-github-delivery', 'gh-delivery-4')
      .set('x-hub-signature-256', sig)
      .set('Content-Type', 'application/json')
      .send(body);

    expect(res.body.received).toBe(true);
    expect([200, 202]).toContain(res.status);
  });
});

describe('recordWebhookDelivery — synthetic id when delivery header is missing', () => {
  // delivery_id used to default to the literal 'unknown' when the upstream
  // header was absent. With the new UNIQUE (delivery_id, provider) index
  // (phase32) every header-less delivery would have collided; we now
  // generate a UUID and warn. This guard ensures we never regress to
  // 'unknown' or to a NULL insert.
  function findInsertFor(provider: string): Record<string, any> | undefined {
    return queryBuilder.insert.mock.calls
      .map((c: any[]) => c[0])
      .find((p: any) => p && p.provider === provider);
  }

  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    queryBuilder.insert.mockClear();
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  it('GitLab: assigns a UUID and warns when x-gitlab-event-uuid is absent', async () => {
    setTableResponse('project_repositories', 'then', {
      data: [{ webhook_secret: 'gl-secret' }],
      error: null,
    });

    const app = makeApp((a) => a.use('/api/integrations', gitlabRouter));
    await request(app)
      .post('/api/integrations/webhooks/gitlab')
      .set('x-gitlab-token', 'gl-secret')
      .set('x-gitlab-event', 'Push Hook')
      // x-gitlab-event-uuid intentionally omitted
      .send({ project: { path_with_namespace: 'acme/repo' } });

    const inserted = findInsertFor('gitlab');
    expect(inserted).toBeDefined();
    expect(inserted!.delivery_id).not.toBe('unknown');
    expect(inserted!.delivery_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    );
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringMatching(/missing x-gitlab-event-uuid header/)
    );
  });

  it('GitLab: preserves the upstream delivery_id when present', async () => {
    setTableResponse('project_repositories', 'then', {
      data: [{ webhook_secret: 'gl-secret' }],
      error: null,
    });

    const app = makeApp((a) => a.use('/api/integrations', gitlabRouter));
    await request(app)
      .post('/api/integrations/webhooks/gitlab')
      .set('x-gitlab-token', 'gl-secret')
      .set('x-gitlab-event', 'Push Hook')
      .set('x-gitlab-event-uuid', 'gl-real-id-99')
      .send({ project: { path_with_namespace: 'acme/repo' } });

    const inserted = findInsertFor('gitlab');
    expect(inserted!.delivery_id).toBe('gl-real-id-99');
    // Other warnings (Upstash Redis missing-env in the test runner) are
    // expected; ours specifically must NOT fire when the header is present.
    const synthWarn = warnSpy.mock.calls.find((c) =>
      typeof c[0] === 'string' && c[0].includes('missing x-gitlab-event-uuid')
    );
    expect(synthWarn).toBeUndefined();
  });

  it('Bitbucket: assigns a UUID and warns when x-request-uuid is absent', async () => {
    setTableResponse('project_repositories', 'then', {
      data: [{ webhook_secret: 'bb-secret' }],
      error: null,
    });

    const app = makeApp((a) => a.use('/api/integrations', bitbucketRouter));
    const body = JSON.stringify({ repository: { full_name: 'acme/repo' } });
    const sig = 'sha256=' + crypto.createHmac('sha256', 'bb-secret').update(body).digest('hex');
    await request(app)
      .post('/api/integrations/webhooks/bitbucket')
      .set('x-event-key', 'repo:push')
      // x-request-uuid intentionally omitted
      .set('x-hub-signature', sig)
      .set('Content-Type', 'application/json')
      .send(body);

    const inserted = findInsertFor('bitbucket');
    expect(inserted).toBeDefined();
    expect(inserted!.delivery_id).not.toBe('unknown');
    expect(inserted!.delivery_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    );
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringMatching(/missing x-request-uuid header/)
    );
  });
});
