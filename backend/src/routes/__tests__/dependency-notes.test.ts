import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder, setTableResponse, pushTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({ ...require('../../test/mocks/supabaseSingleton'), createUserClient: jest.fn() }));
jest.mock('../../lib/activities', () => ({
  createActivity: jest.fn(),
}));
jest.mock('../../lib/rate-limit', () => ({
  checkRateLimit: jest.fn(async () => ({ allowed: true, remaining: 999 })),
}));

// Cache: keep the pure key builders, stub everything that touches Redis.
jest.mock('../../lib/cache', () => {
  const actual = jest.requireActual('../../lib/cache') as typeof import('../../lib/cache');
  return {
    ...actual,
    getCached: jest.fn(async () => null),
    setCached: jest.fn(async () => undefined),
    registerDependencyNotesCacheKey: jest.fn(async () => undefined),
    invalidateDependencyNotesCache: jest.fn(async () => undefined),
    invalidateLatestSafeVersionCacheByDependencyId: jest.fn(async () => undefined),
    invalidateDependencyVersionsCacheByDependencyId: jest.fn(async () => undefined),
    invalidateAllProjectCachesInOrg: jest.fn(async () => undefined),
  };
});

// Platform AI provider: the analyze-usage tests assert exactly when the LLM fires.
const mockChat = jest.fn();
jest.mock('../../lib/ai/provider', () => ({
  getPlatformProvider: () => ({ chat: mockChat }),
}));

// Billing ledger: assert metering without touching the real deduct path.
jest.mock('../../lib/billing/ledger', () => {
  const actual = jest.requireActual('../../lib/billing/ledger') as typeof import('../../lib/billing/ledger');
  return {
    ...actual,
    recordMeterEvent: jest.fn(async () => ({ deducted: true, newBalanceCents: 100, reason: null })),
  };
});

import { recordMeterEvent } from '../../lib/billing/ledger';

const mockUser = { id: 'user-123', email: 'test@example.com' };
const mockToken = 'valid-token';
const orgId = 'org-1';
const projectId = 'proj-1';
const pdId = 'pd-1';
const notesBase = `/api/organizations/${orgId}/projects/${projectId}/dependencies/${pdId}/notes`;

describe('Dependency notes + analyze-usage (P0 fixes)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    (supabase.auth.admin.listUsers as jest.Mock).mockResolvedValue({ data: { users: [] }, error: null });
    // Org owner with manage permission so checkProjectAccess passes by default.
    setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
    setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: true } }, error: null });
    // checkProjectAccess project↔org bind.
    setTableResponse('projects', 'maybeSingle', { data: { organization_id: orgId }, error: null });
  });

  describe('cross-tenant IDOR guard: projectDependencyId must belong to projectId', () => {
    beforeEach(() => {
      // The forged dependency lives in another org's project → bind lookup misses.
      setTableResponse('project_dependencies', 'maybeSingle', { data: null, error: null });
    });

    it('GET notes returns 404 when the dependency is not in the project', async () => {
      const res = await request(app)
        .get(notesBase)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Dependency not found');
    });

    it('POST notes returns 404 and never inserts', async () => {
      const res = await request(app)
        .post(notesBase)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ content: 'cross-tenant note' });

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Dependency not found');
      expect(queryBuilder.insert).not.toHaveBeenCalled();
    });

    it('DELETE note returns 404 and never deletes', async () => {
      const res = await request(app)
        .delete(`${notesBase}/note-1`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Dependency not found');
      expect(queryBuilder.delete).not.toHaveBeenCalled();
    });

    it('POST reaction returns 404 and never upserts', async () => {
      const res = await request(app)
        .post(`${notesBase}/note-1/reactions`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ emoji: '👍' });

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Dependency not found');
      expect(queryBuilder.upsert).not.toHaveBeenCalled();
    });

    it('DELETE reaction returns 404 and never deletes', async () => {
      const res = await request(app)
        .delete(`${notesBase}/note-1/reactions/reaction-1`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Dependency not found');
      expect(queryBuilder.delete).not.toHaveBeenCalled();
    });
  });

  describe('DELETE reaction binds the full reaction→note→dependency chain', () => {
    it('returns 404 when the noteId does not belong to the dependency', async () => {
      // Dependency itself is in the project…
      setTableResponse('project_dependencies', 'maybeSingle', { data: { id: pdId }, error: null });
      // …but the note is not attached to it (forged noteId from another tenant).
      setTableResponse('dependency_notes', 'maybeSingle', { data: null, error: null });

      const res = await request(app)
        .delete(`${notesBase}/forged-note/reactions/reaction-1`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Note not found');
      expect(queryBuilder.delete).not.toHaveBeenCalled();
    });
  });

  describe('notes happy path still works with the bind in place', () => {
    it('GET notes returns 200 with an empty list', async () => {
      setTableResponse('project_dependencies', 'maybeSingle', { data: { id: pdId }, error: null });
      setTableResponse('dependency_notes', 'then', { data: [], error: null });

      const res = await request(app)
        .get(notesBase)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.notes).toEqual([]);
    });
  });

  describe('POST analyze-usage caching + metering', () => {
    const analyzeUrl = `/api/organizations/${orgId}/projects/${projectId}/dependencies/${pdId}/analyze-usage`;

    function setFreshDependency() {
      setTableResponse('project_dependencies', 'single', {
        data: {
          name: 'lodash',
          version: '4.17.21',
          files_importing_count: 3,
          is_direct: true,
          ai_usage_summary: null,
          ai_usage_analyzed_at: null,
        },
        error: null,
      });
      // 'projects' single queue: getActiveExtractionId, then framework fetch.
      pushTableResponse('projects', { data: { active_extraction_run_id: 'run-1' }, error: null });
      pushTableResponse('projects', { data: { framework: 'react' }, error: null });
      // No connected repo → skip the GitHub snippet fetch.
      setTableResponse('project_repositories', 'maybeSingle', { data: null, error: null });
    }

    it('returns the stored summary without calling the LLM or metering when not refreshing', async () => {
      setTableResponse('project_dependencies', 'single', {
        data: {
          name: 'lodash',
          version: '4.17.21',
          files_importing_count: 3,
          is_direct: true,
          ai_usage_summary: 'Cached summary',
          ai_usage_analyzed_at: '2026-01-01T00:00:00.000Z',
        },
        error: null,
      });

      const res = await request(app)
        .post(analyzeUrl)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.ai_usage_summary).toBe('Cached summary');
      expect(res.body.ai_usage_analyzed_at).toBe('2026-01-01T00:00:00.000Z');
      expect(mockChat).not.toHaveBeenCalled();
      expect(recordMeterEvent).not.toHaveBeenCalled();
    });

    it('runs a fresh analysis and meters the LLM call when no summary exists', async () => {
      setFreshDependency();
      mockChat.mockResolvedValue({
        content: 'Fresh AI summary',
        usage: { inputTokens: 1200, outputTokens: 300 },
        model: 'gemini-2.5-flash',
      });

      const res = await request(app)
        .post(analyzeUrl)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.ai_usage_summary).toBe('Fresh AI summary');
      expect(mockChat).toHaveBeenCalledTimes(1);
      expect(recordMeterEvent).toHaveBeenCalledTimes(1);
      expect(recordMeterEvent).toHaveBeenCalledWith(expect.objectContaining({
        organizationId: orgId,
        projectId,
        eventType: 'ai_tokens',
        provider: 'google',
        feature: 'dependency_usage_analysis',
        quantity: 1200,
        outputQuantity: 300,
        unit: 'mixed_tokens',
        modelId: 'gemini-2.5-flash',
        attribution: { userId: mockUser.id },
        idempotencyKey: expect.stringMatching(new RegExp(`^dep-usage:${pdId}:`)),
      }));
    });

    it('re-runs and meters when refresh=true even though a summary is stored', async () => {
      setTableResponse('project_dependencies', 'single', {
        data: {
          name: 'lodash',
          version: '4.17.21',
          files_importing_count: 3,
          is_direct: true,
          ai_usage_summary: 'Cached summary',
          ai_usage_analyzed_at: '2026-01-01T00:00:00.000Z',
        },
        error: null,
      });
      pushTableResponse('projects', { data: { active_extraction_run_id: 'run-1' }, error: null });
      pushTableResponse('projects', { data: { framework: 'react' }, error: null });
      setTableResponse('project_repositories', 'maybeSingle', { data: null, error: null });
      mockChat.mockResolvedValue({
        content: 'Refreshed AI summary',
        usage: { inputTokens: 800, outputTokens: 150 },
        model: 'gemini-2.5-flash',
      });

      const res = await request(app)
        .post(`${analyzeUrl}?refresh=true`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.ai_usage_summary).toBe('Refreshed AI summary');
      expect(mockChat).toHaveBeenCalledTimes(1);
      expect(recordMeterEvent).toHaveBeenCalledTimes(1);
    });

    it('does not meter when the provider is the zero-usage stub', async () => {
      setFreshDependency();
      mockChat.mockResolvedValue({
        content: 'AI features are temporarily unavailable.',
        usage: { inputTokens: 0, outputTokens: 0 },
        model: 'stub',
      });

      const res = await request(app)
        .post(analyzeUrl)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(recordMeterEvent).not.toHaveBeenCalled();
    });
  });

  describe('DELETE ban-version authorizes before mutating', () => {
    it('org owner can still remove an org-level ban (delete runs after the permission check)', async () => {
      setTableResponse('banned_versions', 'maybeSingle', {
        data: { id: 'ban-1', dependency_id: 'dep-1', banned_version: '1.0.0' },
        error: null,
      });
      const deletedTables: string[] = [];
      queryBuilder.delete.mockImplementation(function (this: any) {
        deletedTables.push(this._table);
        return this;
      });

      const res = await request(app)
        .delete(`/api/organizations/${orgId}/ban-version/ban-1`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Ban removed');
      expect(res.body.id).toBe('ban-1');
      expect(deletedTables).toContain('banned_versions');
    });
  });
});
