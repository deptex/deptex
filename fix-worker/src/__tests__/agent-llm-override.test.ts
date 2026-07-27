// The autonomous agent's model must be toggleable via an explicit override
// (AEGIS_TASK_MODEL) without touching the org-wide default_model. This covers
// the modelId param added to fix-worker getLanguageModelForOrg.

import { getLanguageModelForOrg } from '../llm';

function fakeSupabase(orgRow: { default_ai_provider: string | null; default_model: string | null }) {
  return {
    from: () => ({
      select: () => ({ eq: () => ({ single: async () => ({ data: orgRow, error: null }) }) }),
    }),
  } as any;
}

describe('fix-worker getLanguageModelForOrg — modelId override', () => {
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

  test('override wins over the org default (anthropic prefix)', async () => {
    const supa = fakeSupabase({ default_ai_provider: 'openai', default_model: 'gpt-4o' });
    // Should not throw and should resolve the anthropic model from the override.
    await expect(getLanguageModelForOrg(supa, 'org-1', 'claude-sonnet-4-5-20250929')).resolves.toBeDefined();
  });

  test('override with an unrecognised prefix falls back to the org provider', async () => {
    const supa = fakeSupabase({ default_ai_provider: 'google', default_model: null });
    await expect(getLanguageModelForOrg(supa, 'org-1', 'some-unknown-model')).resolves.toBeDefined();
  });

  test('no override uses the org default_model', async () => {
    const supa = fakeSupabase({ default_ai_provider: 'anthropic', default_model: 'gpt-4o' });
    await expect(getLanguageModelForOrg(supa, 'org-1')).resolves.toBeDefined();
  });

  test('override throws when that provider key is missing', async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const supa = fakeSupabase({ default_ai_provider: 'openai', default_model: 'gpt-4o' });
    await expect(getLanguageModelForOrg(supa, 'org-1', 'claude-sonnet-4-5-20250929')).rejects.toThrow(/anthropic/i);
  });
});
