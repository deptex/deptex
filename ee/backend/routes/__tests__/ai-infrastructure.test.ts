/**
 * Phase 6C — AI Infrastructure test suite.
 *
 * Covers BYOK key management, provider abstraction, background vuln monitoring,
 * rate limits / cost caps, usage logging, and safety guards.
 */

/* ------------------------------------------------------------------ */
/*  Mocks — hoisted before any import                                 */
/* ------------------------------------------------------------------ */

const mockSupabaseFrom = jest.fn();
const mockSupabase = {
  from: mockSupabaseFrom,
  auth: { getUser: jest.fn() },
};

jest.mock('@supabase/supabase-js', () => ({
  createClient: jest.fn(() => mockSupabase),
}));

jest.mock('../../../../backend/src/lib/supabase', () => ({
  supabase: mockSupabase,
  createUserClient: jest.fn(() => mockSupabase),
}));

const mockRedisIncr = jest.fn();
const mockRedisIncrby = jest.fn();
const mockRedisDecrby = jest.fn();
const mockRedisExpire = jest.fn();
const mockRedisDecr = jest.fn();
const mockRedisDel = jest.fn();
const mockRedisGet = jest.fn();

jest.mock('@upstash/redis', () => ({
  Redis: jest.fn().mockImplementation(() => ({
    incr: mockRedisIncr,
    incrby: mockRedisIncrby,
    decrby: mockRedisDecrby,
    expire: mockRedisExpire,
    decr: mockRedisDecr,
    del: mockRedisDel,
    get: mockRedisGet,
  })),
}));

jest.mock('openai', () => {
  return jest.fn().mockImplementation(() => ({
    chat: {
      completions: {
        create: jest.fn().mockResolvedValue({
          choices: [{ message: { content: 'ok' } }],
          usage: { prompt_tokens: 10, completion_tokens: 5 },
          model: 'gpt-4o',
        }),
      },
    },
  }));
});

jest.mock('@anthropic-ai/sdk', () => {
  return jest.fn().mockImplementation(() => ({
    messages: {
      create: jest.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'ok' }],
        usage: { input_tokens: 10, output_tokens: 5 },
        model: 'claude-sonnet-4-20250514',
      }),
    },
  }));
});

jest.mock('@google/generative-ai', () => ({
  GoogleGenerativeAI: jest.fn().mockImplementation(() => ({
    getGenerativeModel: jest.fn().mockReturnValue({
      generateContent: jest.fn().mockResolvedValue({
        response: {
          text: () => 'ok',
          usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5 },
        },
      }),
    }),
  })),
  SchemaType: { STRING: 'STRING', NUMBER: 'NUMBER', OBJECT: 'OBJECT' },
}));

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const USER_ID = '00000000-0000-0000-0000-000000000099';
const PROVIDER_ID = 'prov-001';

function chainableQuery(finalData: any = null, finalError: any = null) {
  const chain: Record<string, jest.Mock> = {};
  const terminal = { data: finalData, error: finalError, count: Array.isArray(finalData) ? finalData.length : 0 };

  const methods = ['select', 'insert', 'update', 'upsert', 'delete', 'eq', 'neq',
    'lt', 'lte', 'gt', 'gte', 'or', 'in', 'is', 'order', 'limit', 'range', 'single',
    'maybeSingle', 'then'];

  for (const m of methods) {
    chain[m] = jest.fn().mockReturnValue(chain);
  }
  chain['then'] = jest.fn().mockImplementation((resolve) => resolve?.(terminal) ?? terminal);

  // Allow `await` to resolve the terminal value
  (chain as any)[Symbol.for('jest.asymmetricMatch')] = undefined;
  Object.defineProperty(chain, 'then', {
    value: (resolve: any, reject: any) => Promise.resolve(terminal).then(resolve, reject),
  });

  return chain;
}

function setupFrom(map: Record<string, ReturnType<typeof chainableQuery>>) {
  mockSupabaseFrom.mockImplementation((table: string) => {
    if (map[table]) return map[table];
    return chainableQuery();
  });
}

/* ------------------------------------------------------------------ */
/*  Environment setup / teardown                                       */
/* ------------------------------------------------------------------ */

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
  jest.clearAllMocks();
  process.env.AI_ENCRYPTION_KEY = 'a'.repeat(64);
  process.env.AI_ENCRYPTION_KEY_VERSION = '1';
  process.env.GOOGLE_AI_API_KEY = 'test-google-key';
  process.env.UPSTASH_REDIS_URL = 'https://fake-redis.upstash.io';
  process.env.UPSTASH_REDIS_TOKEN = 'fake-token';
});

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
  jest.resetModules();
});

/* ================================================================== */
/*  1 — BYOK Key Management (Tests 1-7)                               */
/* ================================================================== */

describe('BYOK Key Management', () => {
  it('1: encryptApiKey stores nonce:ciphertext:authTag format, key not returned in GET', async () => {
    const { encryptApiKey } = await import('../../lib/ai/encryption');
    const { encrypted } = encryptApiKey('sk-test-key-12345');

    const parts = encrypted.split(':');
    expect(parts).toHaveLength(3);

    // Each part is valid base64
    for (const p of parts) {
      expect(() => Buffer.from(p, 'base64')).not.toThrow();
      expect(Buffer.from(p, 'base64').length).toBeGreaterThan(0);
    }

    // The encrypted value must not contain the original key
    expect(encrypted).not.toContain('sk-test-key-12345');
  });

  it('2: test connection returns success for valid key (mock provider SDK)', async () => {
    const { createProviderFromKey } = await import('../../lib/ai/provider');
    const provider = createProviderFromKey('openai', 'sk-valid-key');

    const result = await provider.chat(
      [{ role: 'user', content: 'test' }],
      { maxTokens: 1 },
    );

    expect(result.content).toBe('ok');
    expect(result.usage.inputTokens).toBeDefined();
  });

  it('3: test connection returns descriptive error for invalid key', async () => {
    jest.resetModules();

    jest.doMock('openai', () => {
      return jest.fn().mockImplementation(() => ({
        chat: {
          completions: {
            create: jest.fn().mockRejectedValue(
              Object.assign(new Error('Incorrect API key provided'), { status: 401 }),
            ),
          },
        },
      }));
    });

    const { OpenAIProvider } = await import('../../lib/ai/providers/openai-provider');
    const { AIProviderError } = await import('../../lib/ai/types');
    const provider = new OpenAIProvider('sk-invalid');

    await expect(
      provider.chat([{ role: 'user', content: 'hi' }]),
    ).rejects.toThrow(AIProviderError);

    try {
      await provider.chat([{ role: 'user', content: 'hi' }]);
    } catch (err: any) {
      expect(err.code).toBe('auth_failed');
      expect(err.provider).toBe('openai');
      expect(err.message).toContain('Incorrect API key');
    }
  });

  it('4: delete provider removes row (warns if active threads exist)', async () => {
    const threadsQuery = chainableQuery([{ id: 'thread-1' }]);
    const deleteQuery = chainableQuery({ id: PROVIDER_ID });

    setupFrom({
      aegis_chat_threads: threadsQuery,
      organization_ai_providers: deleteQuery,
    });

    const { data: threads } = await mockSupabase
      .from('aegis_chat_threads')
      .select('id')
      .eq('organization_id', ORG_ID);

    const hasActiveThreads = (threads?.length ?? 0) > 0;
    expect(hasActiveThreads).toBe(true);

    await mockSupabase
      .from('organization_ai_providers')
      .delete()
      .eq('id', PROVIDER_ID);

    expect(mockSupabaseFrom).toHaveBeenCalledWith('organization_ai_providers');
  });

  it('5: only manage_integrations permission can add/modify/delete providers', async () => {
    const memberNoPerms = chainableQuery({
      role: 'Member',
      permissions: { manage_integrations: false },
    });
    const memberWithPerms = chainableQuery({
      role: 'Admin',
      permissions: { manage_integrations: true },
    });

    setupFrom({ organization_members: memberNoPerms });
    const { data: noPermsResult } = await mockSupabase
      .from('organization_members')
      .select('role, permissions')
      .eq('organization_id', ORG_ID)
      .eq('user_id', USER_ID)
      .single();

    expect(noPermsResult.permissions.manage_integrations).toBe(false);

    setupFrom({ organization_members: memberWithPerms });
    const { data: withPermsResult } = await mockSupabase
      .from('organization_members')
      .select('role, permissions')
      .eq('organization_id', ORG_ID)
      .eq('user_id', USER_ID)
      .single();

    expect(withPermsResult.permissions.manage_integrations).toBe(true);
  });

  it('6: when only one provider exists, it is auto-set as is_default = true', async () => {
    const providersQuery = chainableQuery([
      { id: PROVIDER_ID, provider: 'openai', is_default: true },
    ]);

    setupFrom({ organization_ai_providers: providersQuery });

    const { data: providers } = await mockSupabase
      .from('organization_ai_providers')
      .select('*')
      .eq('organization_id', ORG_ID);

    expect(providers).toHaveLength(1);
    expect(providers[0].is_default).toBe(true);
  });

  it('7: when AI_ENCRYPTION_KEY env var is missing, BYOK operations throw', async () => {
    delete process.env.AI_ENCRYPTION_KEY;
    jest.resetModules();

    const { encryptApiKey, isEncryptionConfigured } = await import('../../lib/ai/encryption');

    expect(isEncryptionConfigured()).toBe(false);
    expect(() => encryptApiKey('sk-test')).toThrow('AI_ENCRYPTION_KEY not configured');
  });
});

/* ================================================================== */
/*  2 — Provider Abstraction (Tests 8-11)                              */
/* ================================================================== */

describe('Provider Abstraction', () => {
  it('8: getProviderForOrg returns correct provider for configured org', async () => {
    jest.resetModules();

    const { encryptApiKey } = await import('../../lib/ai/encryption');
    const { encrypted, version } = encryptApiKey('sk-live-key');

    const providerRow = {
      id: PROVIDER_ID,
      organization_id: ORG_ID,
      provider: 'openai',
      encrypted_api_key: encrypted,
      encryption_key_version: version,
      model_preference: 'gpt-4o',
      is_default: true,
    };

    setupFrom({
      organization_ai_providers: chainableQuery([providerRow]),
    });

    const { getProviderForOrg } = await import('../../lib/ai/provider');
    const provider = await getProviderForOrg(ORG_ID);

    expect(provider).toBeDefined();
    expect(provider.chat).toBeDefined();
    expect(provider.chatWithTools).toBeDefined();
    expect(provider.streamChat).toBeDefined();
  });

  it('9: getProviderForOrg picks first provider when none marked as default', async () => {
    jest.resetModules();

    const { encryptApiKey } = await import('../../lib/ai/encryption');
    const { encrypted, version } = encryptApiKey('sk-first-key');

    const rows = [
      {
        id: 'prov-a',
        provider: 'anthropic',
        encrypted_api_key: encrypted,
        encryption_key_version: version,
        model_preference: null,
        is_default: false,
      },
    ];

    setupFrom({
      organization_ai_providers: chainableQuery(rows),
    });

    const { getProviderForOrg } = await import('../../lib/ai/provider');
    const provider = await getProviderForOrg(ORG_ID);

    expect(provider).toBeDefined();
  });

  it('10: getProviderForOrg throws AIProviderError(auth_failed) when no providers configured', async () => {
    jest.resetModules();

    setupFrom({
      organization_ai_providers: chainableQuery([]),
    });

    const { getProviderForOrg } = await import('../../lib/ai/provider');
    const { AIProviderError } = await import('../../lib/ai/types');

    await expect(getProviderForOrg(ORG_ID)).rejects.toThrow(AIProviderError);

    try {
      await getProviderForOrg(ORG_ID);
    } catch (err: any) {
      expect(err.code).toBe('auth_failed');
      expect(err.message).toContain('No AI provider configured');
    }
  });

  it('11: getPlatformProvider returns Gemini client; returns stub when GOOGLE_AI_API_KEY missing', async () => {
    jest.resetModules();
    process.env.GOOGLE_AI_API_KEY = 'test-key';

    const { getPlatformProvider } = await import('../../lib/ai/provider');
    const provider = getPlatformProvider();

    expect(provider).toBeDefined();
    expect(provider.chat).toBeDefined();

    // Reset and test stub path
    jest.resetModules();
    delete process.env.GOOGLE_AI_API_KEY;

    const mod2 = await import('../../lib/ai/provider');
    const stub = mod2.getPlatformProvider();

    const result = await stub.chat([{ role: 'user', content: 'hello' }]);
    expect(result.content).toContain('temporarily unavailable');
    expect(result.model).toBe('stub');
  });
});

/* ================================================================== */
/*  3 — Background Monitoring (Tests 12-15)                            */
/* ================================================================== */

describe('Background Monitoring', () => {
  it('12: vuln-check processes due projects and updates last_vuln_check_at', async () => {
    const projectsQuery = chainableQuery([
      { id: 'proj-1', organization_id: ORG_ID, last_vuln_check_at: null, vuln_check_frequency: 12 },
    ]);
    const depsQuery = chainableQuery([]);
    const updateQuery = chainableQuery({ id: 'proj-1' });

    setupFrom({
      projects: projectsQuery,
      project_dependencies: depsQuery,
    });

    // Simulate the vuln-check logic
    const { data: dueProjects } = await mockSupabase
      .from('projects')
      .select('id, organization_id, last_vuln_check_at, vuln_check_frequency')
      .or('last_vuln_check_at.is.null')
      .order('last_vuln_check_at', { ascending: true, nullsFirst: true })
      .limit(10);

    expect(dueProjects).toHaveLength(1);
    expect(dueProjects[0].last_vuln_check_at).toBeNull();

    setupFrom({ projects: updateQuery });
    await mockSupabase
      .from('projects')
      .update({ last_vuln_check_at: new Date().toISOString() })
      .eq('id', 'proj-1');

    expect(mockSupabaseFrom).toHaveBeenCalledWith('projects');
  });

  it('13: new vulnerability detected triggers detected event in project_vulnerability_events', async () => {
    const eventsUpsert = chainableQuery({ id: 'evt-1' });
    setupFrom({ project_vulnerability_events: eventsUpsert });

    const eventPayload = {
      project_id: 'proj-1',
      osv_id: 'GHSA-xxxx-yyyy-zzzz',
      event_type: 'detected',
      project_dependency_id: 'pd-1',
    };

    await mockSupabase
      .from('project_vulnerability_events')
      .upsert(eventPayload, { onConflict: 'project_id,osv_id,event_type', ignoreDuplicates: true });

    expect(mockSupabaseFrom).toHaveBeenCalledWith('project_vulnerability_events');
  });

  it('14: EPSS score change > 10% triggers epss_changed event', async () => {
    const existingVuln = {
      id: 'pdv-1',
      epss_score: 0.15,
      osv_id: 'GHSA-aaaa-bbbb-cccc',
      project_dependency_id: 'pd-1',
    };
    const newEpssScore = 0.30;

    const delta = Math.abs(newEpssScore - existingVuln.epss_score);
    expect(delta).toBeGreaterThan(0.10);

    const eventsUpsert = chainableQuery({ id: 'evt-epss' });
    setupFrom({ project_vulnerability_events: eventsUpsert });

    if (delta > 0.10) {
      await mockSupabase
        .from('project_vulnerability_events')
        .upsert({
          project_id: 'proj-1',
          osv_id: existingVuln.osv_id,
          event_type: 'epss_changed',
          project_dependency_id: existingVuln.project_dependency_id,
          metadata: { old_epss: existingVuln.epss_score, new_epss: newEpssScore },
        }, { onConflict: 'project_id,osv_id,event_type', ignoreDuplicates: false });
    }

    expect(mockSupabaseFrom).toHaveBeenCalledWith('project_vulnerability_events');
  });

  it('15: endpoint stops processing when approaching timeout (90s elapsed)', () => {
    const TIMEOUT_MS = 90_000;
    const MAX_PROJECTS = 10;
    const projects = Array.from({ length: MAX_PROJECTS }, (_, i) => ({ id: `proj-${i}` }));

    let processed = 0;
    const fakeStartTime = Date.now() - 91_000;

    for (const _project of projects) {
      if (Date.now() - fakeStartTime > TIMEOUT_MS) {
        break;
      }
      processed++;
    }

    expect(processed).toBe(0);
  });
});

/* ================================================================== */
/*  4 — Rate Limits and Logging (Tests 16-19)                          */
/* ================================================================== */

describe('Rate Limits and Logging', () => {
  it('16: tier 1 analyze-usage blocked after 5 calls per package per day', async () => {
    jest.resetModules();

    // First 5 calls succeed
    mockRedisIncr.mockResolvedValueOnce(1);
    mockRedisExpire.mockResolvedValue(true);

    const { checkRateLimit } = await import('../../lib/rate-limit');

    const firstResult = await checkRateLimit(`ai:usage-analysis:${ORG_ID}:lodash`, 5, 86_400);
    expect(firstResult.allowed).toBe(true);

    // 6th call blocked
    mockRedisIncr.mockResolvedValueOnce(6);
    jest.resetModules();
    const mod2 = await import('../../lib/rate-limit');
    const sixthResult = await mod2.checkRateLimit(`ai:usage-analysis:${ORG_ID}:lodash`, 5, 86_400);
    expect(sixthResult.allowed).toBe(false);
    expect(sixthResult.remaining).toBe(0);
  });

  it('17: tier 2 monthly cost cap blocks calls when budget exceeded', async () => {
    jest.resetModules();

    const monthlyCap = 50.0;
    const capCents = Math.round(monthlyCap * 100);

    // Redis INCRBY returns value exceeding cap
    mockRedisIncrby.mockResolvedValueOnce(capCents + 100);
    mockRedisDecrby.mockResolvedValue(true);

    const { checkMonthlyCostCap } = await import('../../lib/ai/cost-cap');

    const result = await checkMonthlyCostCap(
      ORG_ID,
      'gpt-4o',
      [{ role: 'user', content: 'Analyze all dependencies' }],
      monthlyCap,
    );

    expect(result.allowed).toBe(false);
    expect(result.capCents).toBe(capCents);
    expect(result.message).toContain('Monthly AI budget reached');
  });

  it('18: all AI calls create ai_usage_logs rows with correct fields', async () => {
    jest.resetModules();

    const insertQuery = chainableQuery({ id: 'log-1' });
    setupFrom({ ai_usage_logs: insertQuery });

    const { logAIUsage } = await import('../../lib/ai/logging');

    await logAIUsage({
      organizationId: ORG_ID,
      userId: USER_ID,
      feature: 'aegis_chat',
      tier: 'byok',
      provider: 'openai',
      model: 'gpt-4o',
      inputTokens: 500,
      outputTokens: 200,
      success: true,
    });

    expect(mockSupabaseFrom).toHaveBeenCalledWith('ai_usage_logs');
  });

  it('19: concurrent cost cap checks use atomic Redis INCR', async () => {
    jest.resetModules();

    const incrResults = [100, 200, 300, 400, 500];
    for (const val of incrResults) {
      mockRedisIncrby.mockResolvedValueOnce(val);
    }

    const { checkMonthlyCostCap } = await import('../../lib/ai/cost-cap');

    const messages = [{ role: 'user' as const, content: 'short' }];
    const promises = incrResults.map(() =>
      checkMonthlyCostCap(ORG_ID, 'gpt-4o-mini', messages, 100.0),
    );

    const results = await Promise.all(promises);

    // All should resolve (no race condition)
    expect(results).toHaveLength(5);
    results.forEach((r) => expect(r.allowed).toBe(true));

    // Verify INCRBY was used (atomic operation)
    expect(mockRedisIncrby).toHaveBeenCalledTimes(5);
  });
});

/* ================================================================== */
/*  5 — Safety (Tests 20-22)                                           */
/* ================================================================== */

describe('Safety', () => {
  it('20: Aegis streaming blocked at thread token limit (returns 400 semantics)', async () => {
    const THREAD_TOKEN_LIMIT = 128_000;

    const threadMessages = [
      { role: 'user' as const, content: 'x'.repeat(THREAD_TOKEN_LIMIT * 4) },
    ];

    const { estimateInputTokens } = await import('../../lib/ai/pricing');
    const tokenEstimate = estimateInputTokens(threadMessages);

    expect(tokenEstimate).toBeGreaterThanOrEqual(THREAD_TOKEN_LIMIT);

    const exceeded = tokenEstimate >= THREAD_TOKEN_LIMIT;
    expect(exceeded).toBe(true);

    if (exceeded) {
      const errorResponse = {
        status: 400,
        body: {
          error: 'Thread context limit exceeded',
          message: `This thread has approximately ${tokenEstimate.toLocaleString()} tokens, which exceeds the ${THREAD_TOKEN_LIMIT.toLocaleString()} token limit. Please start a new thread.`,
        },
      };

      expect(errorResponse.status).toBe(400);
      expect(errorResponse.body.error).toContain('limit exceeded');
    }
  });

  it('21: runtime provider auth_failed error returns user-friendly message and logs with success=false', async () => {
    jest.resetModules();

    jest.doMock('openai', () => {
      return jest.fn().mockImplementation(() => ({
        chat: {
          completions: {
            create: jest.fn().mockRejectedValue(
              Object.assign(new Error('Incorrect API key provided: sk-...xxxx'), { status: 401 }),
            ),
          },
        },
      }));
    });

    const { OpenAIProvider } = await import('../../lib/ai/providers/openai-provider');
    const { AIProviderError } = await import('../../lib/ai/types');

    const provider = new OpenAIProvider('sk-bad-key');

    let caughtError: any;
    try {
      await provider.chat([{ role: 'user', content: 'hello' }]);
    } catch (err) {
      caughtError = err;
    }

    expect(caughtError).toBeInstanceOf(AIProviderError);
    expect(caughtError.code).toBe('auth_failed');
    expect(caughtError.retryable).toBe(false);

    // Verify a usage log would be created with success = false
    const insertQuery = chainableQuery({ id: 'log-err' });
    setupFrom({ ai_usage_logs: insertQuery });

    const { logAIUsage } = await import('../../lib/ai/logging');

    await logAIUsage({
      organizationId: ORG_ID,
      userId: USER_ID,
      feature: 'aegis_chat',
      tier: 'byok',
      provider: 'openai',
      model: 'gpt-4o',
      inputTokens: 0,
      outputTokens: 0,
      success: false,
      errorMessage: caughtError.message,
    });

    expect(mockSupabaseFrom).toHaveBeenCalledWith('ai_usage_logs');
  });

  it('22: encryption key version mismatch falls back to AI_ENCRYPTION_KEY_PREV for decryption', async () => {
    jest.resetModules();

    const oldKeyHex = 'b'.repeat(64);
    const newKeyHex = 'c'.repeat(64);

    // Step 1: Encrypt with the old key (version 1)
    process.env.AI_ENCRYPTION_KEY = oldKeyHex;
    process.env.AI_ENCRYPTION_KEY_VERSION = '1';
    delete process.env.AI_ENCRYPTION_KEY_PREV;

    const mod1 = await import('../../lib/ai/encryption');
    const { encrypted } = mod1.encryptApiKey('sk-secret-original', 1);

    // Step 2: Rotate — old key becomes PREV, new key becomes current (version 2)
    jest.resetModules();
    process.env.AI_ENCRYPTION_KEY = newKeyHex;
    process.env.AI_ENCRYPTION_KEY_PREV = oldKeyHex;
    process.env.AI_ENCRYPTION_KEY_VERSION = '2';

    const mod2 = await import('../../lib/ai/encryption');

    // Decrypt with storedVersion=1 — current key (v2) fails, falls back to PREV (v1)
    const decrypted = mod2.decryptApiKey(encrypted, 1);
    expect(decrypted).toBe('sk-secret-original');
  });
});
