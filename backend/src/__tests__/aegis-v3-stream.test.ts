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

jest.mock('../lib/aegis-v3/thread', () => ({
  getOrCreateThread: jest.fn().mockResolvedValue(THREAD_ID),
  loadThreadHistory: jest.fn().mockResolvedValue([]),
}));

jest.mock('../lib/aegis-v3/memory', () => ({
  queryRelevantMemories: jest.fn().mockResolvedValue(''),
}));

jest.mock('../lib/aegis-v3/persistence', () => ({
  saveAssistantMessage: jest.fn().mockResolvedValue(undefined),
  saveToolExecution: jest.fn().mockResolvedValue(undefined),
  logChatUsage: jest.fn().mockResolvedValue(undefined),
}));

const mockGetLanguageModelForOrg = jest.fn();
jest.mock('../lib/aegis-v3/provider', () => ({
  __esModule: true,
  getLanguageModelForOrg: (orgId: string) => mockGetLanguageModelForOrg(orgId),
  getProviderInfoForOrg: jest.fn().mockResolvedValue({ provider: 'mock', model: 'mock-1' }),
  getEmbeddingModel: jest.fn(),
}));

import aegisV3Router from '../routes/aegis-v3';
import { saveAssistantMessage } from '../lib/aegis-v3/persistence';
import { getOrCreateThread } from '../lib/aegis-v3/thread';

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/aegis/v3', aegisV3Router);
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
  (saveAssistantMessage as jest.Mock).mockClear();
  (getOrCreateThread as jest.Mock).mockClear();
});

describe('POST /api/aegis/v3/stream', () => {
  it('rejects requests missing organizationId or message', async () => {
    const res = await request(makeApp())
      .post('/api/aegis/v3/stream')
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
      .post('/api/aegis/v3/stream')
      .send({ organizationId: ORG_ID, message: 'hi' });
    expect(res.status).toBe(403);
  });

  it('streams the assistant text, sets X-Thread-Id, and persists the message', async () => {
    setOwnerWithAegisPermission();
    mockGetLanguageModelForOrg.mockResolvedValue(makeStreamingModel('Hello from Aegis.'));

    const res = await request(makeApp())
      .post('/api/aegis/v3/stream')
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
    expect(saveAssistantMessage).toHaveBeenCalledTimes(1);
    const saveCall = (saveAssistantMessage as jest.Mock).mock.calls[0][0];
    expect(saveCall).toMatchObject({
      threadId: THREAD_ID,
      userMessage: 'list my projects',
      assistantText: 'Hello from Aegis.',
      promptTokens: 4,
      completionTokens: 6,
      totalTokens: 10,
    });
  });

  it('returns 500 when the BYOK provider loader rejects', async () => {
    setOwnerWithAegisPermission();
    mockGetLanguageModelForOrg.mockRejectedValueOnce(new Error('No BYOK key configured'));

    const res = await request(makeApp())
      .post('/api/aegis/v3/stream')
      .send({ organizationId: ORG_ID, message: 'hi' });

    expect(res.status).toBe(500);
    expect(res.body.error).toContain('BYOK');
  });
});
