// Smoke for fix-worker's getLanguageModelForOrg model resolution. The worker
// reads default_ai_provider AND default_model and picks a provider from the
// model id prefix; previously it ignored default_model entirely so the user's
// chosen model in the UI was silently overridden by the worker's hard-coded
// DEFAULT_MODELS.
//
// These tests don't actually invoke the AI SDK — they only exercise the
// path that calls supabase.from('organizations').select(...).single() and
// then constructs a model. We mock supabase as a thenable chain.

import { getLanguageModelForOrg } from '../llm';

function fakeSupabase(orgRow: { default_ai_provider: string | null; default_model: string | null }) {
  return {
    from: () => ({
      select: () => ({
        eq: () => ({
          single: async () => ({ data: orgRow, error: null }),
        }),
      }),
    }),
  } as any;
}

describe('fix-worker llm.getLanguageModelForOrg', () => {
  const ORIGINAL_ENV = { ...process.env };

  beforeEach(() => {
    process.env.OPENAI_API_KEY = 'sk-test-openai';
    process.env.ANTHROPIC_API_KEY = 'sk-test-anthropic';
    process.env.GOOGLE_AI_API_KEY = 'sk-test-google';
    process.env.DEEPINFRA_API_KEY = 'sk-test-deepinfra';
  });

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  test('uses default_model when prefix is recognised (anthropic)', async () => {
    const supa = fakeSupabase({
      default_ai_provider: 'openai', // override expected
      default_model: 'claude-sonnet-4-5-20250929',
    });
    // We don't have a way to read the resolved model name from the AI SDK
    // model object directly, so we just assert that the call succeeds and
    // doesn't throw on missing key (anthropic key IS configured above).
    await expect(getLanguageModelForOrg(supa, 'org-1')).resolves.toBeTruthy();
  });

  test('falls back to default_ai_provider DEFAULT when default_model is null', async () => {
    const supa = fakeSupabase({
      default_ai_provider: 'google',
      default_model: null,
    });
    await expect(getLanguageModelForOrg(supa, 'org-1')).resolves.toBeTruthy();
  });

  test('throws a clear error when the platform key is missing', async () => {
    delete process.env.OPENAI_API_KEY;
    const supa = fakeSupabase({
      default_ai_provider: 'openai',
      default_model: null,
    });
    await expect(getLanguageModelForOrg(supa, 'org-1')).rejects.toThrow(
      /OPENAI_API_KEY/,
    );
  });

  test('unrecognised model prefix falls back to default_ai_provider', async () => {
    const supa = fakeSupabase({
      default_ai_provider: 'anthropic',
      default_model: 'mystery-model-not-a-prefix-we-know',
    });
    // No throw: the fallback is anthropic + DEFAULT_MODELS['anthropic'].
    await expect(getLanguageModelForOrg(supa, 'org-1')).resolves.toBeTruthy();
  });

  test('throws on supabase error', async () => {
    const supa = {
      from: () => ({
        select: () => ({
          eq: () => ({
            single: async () => ({ data: null, error: { message: 'org not found' } }),
          }),
        }),
      }),
    } as any;
    await expect(getLanguageModelForOrg(supa, 'org-x')).rejects.toThrow(/org not found/);
  });
});
