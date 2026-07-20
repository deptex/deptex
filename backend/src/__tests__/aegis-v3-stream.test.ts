import express from 'express';
import request from 'supertest';
import { MockLanguageModelV3 } from 'ai/test';
import { simulateReadableStream } from 'ai';

import {
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../test/mocks/supabaseSingleton';

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const USER_ID = '00000000-0000-0000-0000-000000000099';
const THREAD_ID = '00000000-0000-0000-0000-0000000000aa';

jest.mock('../middleware/auth', () => ({
  authenticateUser: (req: any, _res: any, next: any) => {
    req.user = { id: USER_ID };
    next();
  },
}));

jest.mock('../lib/aegis/thread', () => ({
  getOrCreateThread: jest.fn().mockResolvedValue(THREAD_ID),
  loadThreadHistory: jest.fn().mockResolvedValue([]),
}));

jest.mock('../lib/aegis/memory', () => ({
  queryRelevantMemories: jest.fn().mockResolvedValue(''),
}));

jest.mock('../lib/aegis/persistence', () => ({
  saveUserMessage: jest.fn().mockResolvedValue(undefined),
  saveAssistantMessage: jest.fn().mockResolvedValue(undefined),
  saveToolExecution: jest.fn().mockResolvedValue(undefined),
  logChatUsage: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../lib/aegis/title', () => ({
  generateThreadTitle: jest.fn().mockResolvedValue(undefined),
  cleanGeneratedTitle: (raw: string) => raw,
}));

jest.mock('../lib/aegis/errors', () => ({
  classifyChatError: (err: any) => ({ type: 'transient', message: err?.message }),
  writeAegisChatError: jest.fn().mockResolvedValue(undefined),
}));

const mockGetThreadForParticipant = jest.fn();
jest.mock('../lib/aegis/participants', () => ({
  getThreadForParticipant: (threadId: string, userId: string) =>
    mockGetThreadForParticipant(threadId, userId),
}));

const mockGetLanguageModelForOrg = jest.fn();
jest.mock('../lib/aegis/provider', () => ({
  __esModule: true,
  getLanguageModelForOrg: (orgId: string) => mockGetLanguageModelForOrg(orgId),
  getProviderInfoForOrg: jest.fn().mockResolvedValue({
    provider: 'mock',
    model: 'mock-1',
    monthlyCostCap: 100,
  }),
  getEmbeddingModel: jest.fn(),
}));

// Mock the billing ledger so we can drive the prepaid pre-flight gate per-test.
// Default (set in beforeEach) is allow-through (a funded org) so the other tests
// are unaffected; the cost-cap tests override canCharge to deny.
jest.mock('../lib/billing/ledger', () => ({
  canCharge: jest.fn(),
  recordMeterEvent: jest.fn().mockResolvedValue({ deducted: false, newBalanceCents: null }),
}));

import aegisRouter from '../routes/aegis';
import { saveUserMessage, saveAssistantMessage } from '../lib/aegis/persistence';
import { getOrCreateThread } from '../lib/aegis/thread';
import { writeAegisChatError } from '../lib/aegis/errors';
import { canCharge } from '../lib/billing/ledger';

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/aegis', aegisRouter);
  return app;
}

function makeStreamingModel(text: string): MockLanguageModelV3 {
  return new MockLanguageModelV3({
    doStream: async () => ({
      stream: simulateReadableStream({
        chunks: [
          { type: 'stream-start', warnings: [] },
          { type: 'text-start', id: 't1' },
          { type: 'text-delta', id: 't1', delta: text },
          { type: 'text-end', id: 't1' },
          {
            type: 'finish',
            finishReason: 'stop',
            usage: {
              inputTokens: { total: 4, noCache: 4, cacheRead: 0, cacheWrite: 0 },
              outputTokens: { total: 6, text: 6, reasoning: 0 },
            },
          },
        ] as any,
      }),
    }),
  });
}

function setOwnerWithAegisPermission() {
  setTableResponse('organization_members', 'single', {
    data: { role: 'owner' },
    error: null,
  });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { interact_with_aegis: true } },
    error: null,
  });
  setTableResponse('organizations', 'single', {
    data: { name: 'Acme' },
    error: null,
  });
  setTableResponse('aegis_org_settings', 'single', {
    data: { operating_mode: 'propose' },
    error: null,
  });
}

beforeEach(() => {
  clearTableRegistry();
  clearRpcRegistry();
  mockGetLanguageModelForOrg.mockReset();
  mockGetThreadForParticipant.mockReset();
  (saveUserMessage as jest.Mock).mockClear();
  (saveAssistantMessage as jest.Mock).mockClear();
  (getOrCreateThread as jest.Mock).mockClear();
  (writeAegisChatError as jest.Mock).mockClear();
  // Default: balance is fine. Individual tests override to drive the gate.
  (canCharge as jest.Mock).mockReset();
  (canCharge as jest.Mock).mockResolvedValue({ allowed: true, balanceCents: 100_000 });
});

describe('POST /api/aegis/stream', () => {
  it('rejects requests missing organizationId or message', async () => {
    const res = await request(makeApp())
      .post('/api/aegis/stream')
      .send({ organizationId: ORG_ID });
    expect(res.status).toBe(400);
  });

  it('returns 403 when caller lacks interact_with_aegis permission', async () => {
    setTableResponse('organization_members', 'single', { data: { role: 'viewer' }, error: null });
    setTableResponse('organization_roles', 'single', {
      data: { permissions: { interact_with_aegis: false } },
      error: null,
    });

    const res = await request(makeApp())
      .post('/api/aegis/stream')
      .send({ organizationId: ORG_ID, message: 'hi' });
    expect(res.status).toBe(403);
  });

  it('streams the assistant text, sets X-Thread-Id, and persists the message', async () => {
    setOwnerWithAegisPermission();
    mockGetLanguageModelForOrg.mockResolvedValue(makeStreamingModel('Hello from Aegis.'));

    const res = await request(makeApp())
      .post('/api/aegis/stream')
      .send({ organizationId: ORG_ID, message: 'list my projects' });

    expect(res.status).toBe(200);
    expect(res.headers['x-thread-id']).toBe(THREAD_ID);
    expect(res.text).toContain('Hello from Aegis.');

    expect(getOrCreateThread).toHaveBeenCalledWith(
      ORG_ID,
      USER_ID,
      undefined,
      'list my projects',
      undefined,
    );
    expect(saveUserMessage).toHaveBeenCalledWith({
      threadId: THREAD_ID,
      userId: USER_ID,
      content: 'list my projects',
    });
    expect(saveAssistantMessage).toHaveBeenCalledTimes(1);
    const saveCall = (saveAssistantMessage as jest.Mock).mock.calls[0][0];
    expect(saveCall).toMatchObject({
      threadId: THREAD_ID,
      assistantText: 'Hello from Aegis.',
      totalTokens: 10,
    });
    expect(saveCall.parts).toEqual([{ type: 'text', text: 'Hello from Aegis.' }]);
  });

  it('skips the model and persists a cost_cap error when balance is insufficient_credit', async () => {
    setOwnerWithAegisPermission();
    (canCharge as jest.Mock).mockResolvedValue({
      allowed: false,
      balanceCents: 0,
      reason: 'insufficient_credit',
    });
    mockGetLanguageModelForOrg.mockResolvedValue(makeStreamingModel('should not stream'));

    const res = await request(makeApp())
      .post('/api/aegis/stream')
      .send({ organizationId: ORG_ID, message: 'expensive query' });

    expect(res.status).toBe(200);
    // The turn is blocked: a cost_cap error is persisted and the model never runs.
    expect(writeAegisChatError).toHaveBeenCalledWith(
      THREAD_ID,
      expect.objectContaining({ type: 'cost_cap' }),
    );
    expect(mockGetLanguageModelForOrg).not.toHaveBeenCalled();
    expect(res.text).not.toContain('should not stream');
  });

  it('fails OPEN (streams) when canCharge cannot read the balance (db_unavailable)', async () => {
    // A Supabase blip must NOT block a turn — failing closed would brick every
    // org, including well-funded ones, and surface a bogus "top up" CTA.
    setOwnerWithAegisPermission();
    (canCharge as jest.Mock).mockResolvedValue({
      allowed: false,
      balanceCents: 0,
      reason: 'db_unavailable',
    });
    mockGetLanguageModelForOrg.mockResolvedValue(makeStreamingModel('streamed anyway'));

    const res = await request(makeApp())
      .post('/api/aegis/stream')
      .send({ organizationId: ORG_ID, message: 'hi' });

    expect(res.status).toBe(200);
    expect(res.text).toContain('streamed anyway');
    // No cost_cap error written — the block only fires for insufficient_credit.
    const costCapCalls = (writeAegisChatError as jest.Mock).mock.calls.filter(
      ([, payload]) => payload?.type === 'cost_cap',
    );
    expect(costCapCalls).toHaveLength(0);
  });

  it('returns 500 with a generic message when the platform provider loader rejects', async () => {
    setOwnerWithAegisPermission();
    mockGetLanguageModelForOrg.mockRejectedValueOnce(new Error('Platform API key for anthropic is not configured'));

    const res = await request(makeApp())
      .post('/api/aegis/stream')
      .send({ organizationId: ORG_ID, message: 'hi' });

    expect(res.status).toBe(500);
    // Real cause stays in server logs only — the body must never leak provider
    // / DB / supabase error text to the user-facing chat banner.
    expect(res.body.error).toBe('Something went wrong. Please try again.');
    expect(res.body.error).not.toContain('Platform API key');
  });
});

describe('POST /api/aegis/regenerate', () => {
  it('rejects requests without threadId', async () => {
    const res = await request(makeApp()).post('/api/aegis/regenerate').send({});
    expect(res.status).toBe(400);
  });

  it('returns 404 when the caller is not a thread participant', async () => {
    mockGetThreadForParticipant.mockResolvedValueOnce(null);
    const res = await request(makeApp())
      .post('/api/aegis/regenerate')
      .send({ threadId: THREAD_ID });
    expect(res.status).toBe(404);
  });

  it('returns 403 when caller lacks interact_with_aegis', async () => {
    mockGetThreadForParticipant.mockResolvedValueOnce({
      id: THREAD_ID,
      organization_id: ORG_ID,
    });
    setTableResponse('organization_members', 'single', { data: { role: 'viewer' }, error: null });
    setTableResponse('organization_roles', 'single', {
      data: { permissions: { interact_with_aegis: false } },
      error: null,
    });
    const res = await request(makeApp())
      .post('/api/aegis/regenerate')
      .send({ threadId: THREAD_ID });
    expect(res.status).toBe(403);
  });

  it('returns 400 when the thread has no user message to regenerate from', async () => {
    mockGetThreadForParticipant.mockResolvedValueOnce({
      id: THREAD_ID,
      organization_id: ORG_ID,
    });
    setOwnerWithAegisPermission();
    setTableResponse('aegis_chat_messages', 'maybeSingle', { data: null, error: null });
    const res = await request(makeApp())
      .post('/api/aegis/regenerate')
      .send({ threadId: THREAD_ID });
    expect(res.status).toBe(400);
  });

  it('responds with the threadId after deleting trailing assistant rows', async () => {
    mockGetThreadForParticipant.mockResolvedValueOnce({
      id: THREAD_ID,
      organization_id: ORG_ID,
    });
    setOwnerWithAegisPermission();
    setTableResponse('aegis_chat_messages', 'maybeSingle', {
      data: { id: 'msg-user-1', created_at: '2026-01-01T00:00:00Z' },
      error: null,
    });
    setTableResponse('aegis_chat_messages', 'then', { data: null, error: null });

    const res = await request(makeApp())
      .post('/api/aegis/regenerate')
      .send({ threadId: THREAD_ID });

    expect(res.status).toBe(200);
    expect(res.body.threadId).toBe(THREAD_ID);
  });
});
