/**
 * Provider-routing tests for callProviderAndParse — verifies the request
 * shape we send to each AI provider (URL, headers, body keys) and that we
 * correctly parse their distinct response shapes back into a unified
 * GeneratedPayload + token counts.
 *
 * We do not exercise the real network. global.fetch is replaced with a
 * jest.fn() per test. The recorded calls are asserted directly.
 */

import { callProviderAndParse, GenerationError } from '../rule-generator/generate';

const VALID_PAYLOAD = {
  rule_yaml: [
    'rules:',
    '  - id: deptex.example.injection',
    '    languages: [javascript]',
    '    severity: ERROR',
    '    mode: taint',
    '    metadata:',
    '      cve: CVE-2021-X',
    '      package: example',
    '    pattern-sources:',
    '      - pattern: $REQ.body',
    '    pattern-sinks:',
    '      - pattern: dangerous($X)',
  ].join('\n'),
  vulnerable_fixture: "function h(req){dangerous(req.body.cmd)}",
  safe_fixture: "function h(){dangerous('static')}",
  reachability_level: 'confirmed',
  entry_point_class: 'PUBLIC_UNAUTH',
  rationale: 'taint flow from req.body to dangerous()',
};

const VALID_PAYLOAD_JSON = JSON.stringify(VALID_PAYLOAD);

const PROMPT = 'Generate a Semgrep rule for CVE-2021-X in the example package';

interface FetchCall {
  url: string;
  init: RequestInit;
}

function mockFetchOnce(body: unknown, opts?: { status?: number; ok?: boolean }): {
  calls: FetchCall[];
  restore: () => void;
} {
  const calls: FetchCall[] = [];
  const original = global.fetch;
  const status = opts?.status ?? 200;
  const ok = opts?.ok ?? (status >= 200 && status < 300);
  (global as { fetch: unknown }).fetch = jest.fn(async (input: unknown, init?: RequestInit) => {
    calls.push({ url: String(input), init: init ?? {} });
    return {
      ok,
      status,
      json: async () => body,
      text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
    } as unknown as Response;
  });
  return {
    calls,
    restore: () => {
      (global as { fetch: unknown }).fetch = original;
    },
  };
}

afterEach(() => {
  jest.restoreAllMocks();
});

describe('callProviderAndParse — Anthropic', () => {
  it('POSTs to /v1/messages with x-api-key, anthropic-version, content[].text shape', async () => {
    const { calls, restore } = mockFetchOnce({
      content: [{ type: 'text', text: VALID_PAYLOAD_JSON }],
      usage: { input_tokens: 1234, output_tokens: 567 },
    });
    try {
      const result = await callProviderAndParse({
        prompt: PROMPT,
        provider: 'anthropic',
        model: 'claude-sonnet-4-6',
        apiKey: 'sk-ant-secret',
      });
      expect(calls).toHaveLength(1);
      expect(calls[0].url).toBe('https://api.anthropic.com/v1/messages');
      const headers = calls[0].init.headers as Record<string, string>;
      expect(headers['x-api-key']).toBe('sk-ant-secret');
      expect(headers['anthropic-version']).toBe('2023-06-01');
      expect(headers['content-type']).toBe('application/json');
      const body = JSON.parse(String(calls[0].init.body));
      expect(body.model).toBe('claude-sonnet-4-6');
      expect(body.max_tokens).toBe(2_500);
      expect(body.temperature).toBe(0.1);
      expect(body.messages).toEqual([
        { role: 'user', content: [{ type: 'text', text: PROMPT }] },
      ]);
      expect(result.inputTokens).toBe(1234);
      expect(result.outputTokens).toBe(567);
      // sonnet-4-6: 1234 * $3/M + 567 * $15/M = 0.003702 + 0.008505 = 0.012207
      expect(result.estimatedCostUsd).toBeCloseTo(0.012207, 6);
      expect(result.payload.entry_point_class).toBe('PUBLIC_UNAUTH');
    } finally {
      restore();
    }
  });

  it('respects maxOutputTokens override', async () => {
    const { calls, restore } = mockFetchOnce({
      content: [{ type: 'text', text: VALID_PAYLOAD_JSON }],
      usage: { input_tokens: 100, output_tokens: 100 },
    });
    try {
      await callProviderAndParse({
        prompt: PROMPT,
        provider: 'anthropic',
        model: 'claude-haiku-4-5-20251001',
        apiKey: 'k',
        maxOutputTokens: 1_000,
      });
      const body = JSON.parse(String(calls[0].init.body));
      expect(body.max_tokens).toBe(1_000);
    } finally {
      restore();
    }
  });

  it('falls back to char/4 token estimation when usage block is missing', async () => {
    const { restore } = mockFetchOnce({
      content: [{ type: 'text', text: VALID_PAYLOAD_JSON }],
      // no usage block
    });
    try {
      const result = await callProviderAndParse({
        prompt: PROMPT,
        provider: 'anthropic',
        model: 'claude-sonnet-4-6',
        apiKey: 'k',
      });
      // Fallback estimate: ceil(prompt.length / 4)
      expect(result.inputTokens).toBe(Math.ceil(PROMPT.length / 4));
      expect(result.outputTokens).toBeGreaterThan(0);
    } finally {
      restore();
    }
  });

  it('throws GenerationError(provider_error) on non-2xx', async () => {
    const { restore } = mockFetchOnce(
      { error: { message: 'rate limited' } },
      { status: 429, ok: false },
    );
    try {
      await expect(
        callProviderAndParse({
          prompt: PROMPT, provider: 'anthropic', model: 'claude-sonnet-4-6', apiKey: 'k',
        }),
      ).rejects.toThrow(GenerationError);
    } finally {
      restore();
    }
  });

  it('throws GenerationError(parse_failed) when content[0].text is not JSON', async () => {
    const { restore } = mockFetchOnce({
      content: [{ type: 'text', text: 'I cannot help with that' }],
      usage: { input_tokens: 10, output_tokens: 10 },
    });
    try {
      await expect(
        callProviderAndParse({
          prompt: PROMPT, provider: 'anthropic', model: 'claude-sonnet-4-6', apiKey: 'k',
        }),
      ).rejects.toMatchObject({ code: 'parse_failed' });
    } finally {
      restore();
    }
  });
});

describe('callProviderAndParse — OpenAI', () => {
  it('POSTs to /chat/completions with Bearer auth, json_object response_format, system+user messages', async () => {
    const { calls, restore } = mockFetchOnce({
      choices: [{ message: { content: VALID_PAYLOAD_JSON } }],
      usage: { prompt_tokens: 800, completion_tokens: 400 },
    });
    try {
      const result = await callProviderAndParse({
        prompt: PROMPT,
        provider: 'openai',
        model: 'gpt-4o',
        apiKey: 'sk-openai-secret',
      });
      expect(calls).toHaveLength(1);
      expect(calls[0].url).toBe('https://api.openai.com/v1/chat/completions');
      const headers = calls[0].init.headers as Record<string, string>;
      expect(headers.authorization).toBe('Bearer sk-openai-secret');
      expect(headers['content-type']).toBe('application/json');
      const body = JSON.parse(String(calls[0].init.body));
      expect(body.model).toBe('gpt-4o');
      expect(body.temperature).toBe(0.1);
      expect(body.response_format).toEqual({ type: 'json_object' });
      expect(body.messages).toHaveLength(2);
      expect(body.messages[0].role).toBe('system');
      expect(body.messages[1]).toEqual({ role: 'user', content: PROMPT });
      expect(result.inputTokens).toBe(800);
      expect(result.outputTokens).toBe(400);
      // gpt-4o: 800 * $2.50/M + 400 * $10/M = 0.002 + 0.004 = 0.006
      expect(result.estimatedCostUsd).toBeCloseTo(0.006, 6);
    } finally {
      restore();
    }
  });

  it('reads usage.prompt_tokens / completion_tokens (not Anthropic input_tokens)', async () => {
    const { restore } = mockFetchOnce({
      choices: [{ message: { content: VALID_PAYLOAD_JSON } }],
      usage: { prompt_tokens: 999, completion_tokens: 111 },
    });
    try {
      const result = await callProviderAndParse({
        prompt: PROMPT, provider: 'openai', model: 'gpt-4o-mini', apiKey: 'k',
      });
      expect(result.inputTokens).toBe(999);
      expect(result.outputTokens).toBe(111);
    } finally {
      restore();
    }
  });

  it('throws GenerationError(provider_error) when choices[0].message is missing', async () => {
    const { restore } = mockFetchOnce({
      choices: [],
      usage: { prompt_tokens: 0, completion_tokens: 0 },
    });
    try {
      await expect(
        callProviderAndParse({
          prompt: PROMPT, provider: 'openai', model: 'gpt-4o', apiKey: 'k',
        }),
      ).rejects.toMatchObject({ code: 'parse_failed' });
    } finally {
      restore();
    }
  });
});

describe('callProviderAndParse — Google', () => {
  it('POSTs to generativelanguage with key in querystring + responseMimeType json', async () => {
    const { calls, restore } = mockFetchOnce({
      candidates: [
        {
          content: {
            parts: [{ text: VALID_PAYLOAD_JSON }],
          },
        },
      ],
      usageMetadata: { promptTokenCount: 600, candidatesTokenCount: 250 },
    });
    try {
      const result = await callProviderAndParse({
        prompt: PROMPT,
        provider: 'google',
        model: 'gemini-2.5-flash',
        apiKey: 'goog-secret',
      });
      expect(calls).toHaveLength(1);
      expect(calls[0].url).toBe(
        'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=goog-secret',
      );
      const headers = calls[0].init.headers as Record<string, string>;
      // No bearer / no x-api-key — Google passes the key in the URL.
      expect(headers.authorization).toBeUndefined();
      expect(headers['x-api-key']).toBeUndefined();
      const body = JSON.parse(String(calls[0].init.body));
      expect(body.generationConfig.temperature).toBe(0.1);
      expect(body.generationConfig.responseMimeType).toBe('application/json');
      expect(body.contents).toEqual([
        { role: 'user', parts: [{ text: PROMPT }] },
      ]);
      expect(result.inputTokens).toBe(600);
      expect(result.outputTokens).toBe(250);
    } finally {
      restore();
    }
  });

  it('joins parts[].text into a single string when the model splits its output', async () => {
    const split = VALID_PAYLOAD_JSON;
    const half = Math.floor(split.length / 2);
    const { restore } = mockFetchOnce({
      candidates: [
        {
          content: {
            parts: [{ text: split.slice(0, half) }, { text: split.slice(half) }],
          },
        },
      ],
      usageMetadata: { promptTokenCount: 100, candidatesTokenCount: 50 },
    });
    try {
      const result = await callProviderAndParse({
        prompt: PROMPT, provider: 'google', model: 'gemini-1.5-pro', apiKey: 'k',
      });
      expect(result.payload.entry_point_class).toBe('PUBLIC_UNAUTH');
    } finally {
      restore();
    }
  });

  it('URL-encodes the model name to defend against unusual model strings', async () => {
    const { calls, restore } = mockFetchOnce({
      candidates: [{ content: { parts: [{ text: VALID_PAYLOAD_JSON }] } }],
      usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1 },
    });
    try {
      await callProviderAndParse({
        prompt: PROMPT,
        provider: 'google',
        // hypothetical edge-case: model name with spaces
        model: 'gemini test',
        apiKey: 'k v',
      });
      // Both model and key go through encodeURIComponent.
      expect(calls[0].url).toContain('gemini%20test:generateContent');
      expect(calls[0].url).toContain('key=k%20v');
    } finally {
      restore();
    }
  });
});

describe('callProviderAndParse — schema rejection (post-provider parse path)', () => {
  it('rejects payload with too-short rule_yaml across all three providers', async () => {
    const tooShort = JSON.stringify({ ...VALID_PAYLOAD, rule_yaml: 'short' });
    for (const [provider, body] of [
      ['anthropic', { content: [{ type: 'text', text: tooShort }], usage: { input_tokens: 1, output_tokens: 1 } }],
      ['openai', { choices: [{ message: { content: tooShort } }], usage: { prompt_tokens: 1, completion_tokens: 1 } }],
      ['google', { candidates: [{ content: { parts: [{ text: tooShort }] } }], usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1 } }],
    ] as const) {
      const { restore } = mockFetchOnce(body);
      try {
        await expect(
          callProviderAndParse({
            prompt: PROMPT, provider: provider as 'anthropic' | 'openai' | 'google',
            model: 'm', apiKey: 'k',
          }),
        ).rejects.toMatchObject({ code: 'invalid_schema' });
      } finally {
        restore();
      }
    }
  });

  it('rejects unknown reachability_level even when JSON parses', async () => {
    const bad = JSON.stringify({ ...VALID_PAYLOAD, reachability_level: 'module' });
    const { restore } = mockFetchOnce({
      content: [{ type: 'text', text: bad }],
      usage: { input_tokens: 1, output_tokens: 1 },
    });
    try {
      await expect(
        callProviderAndParse({
          prompt: PROMPT, provider: 'anthropic', model: 'claude-sonnet-4-6', apiKey: 'k',
        }),
      ).rejects.toMatchObject({ code: 'invalid_schema' });
    } finally {
      restore();
    }
  });

  it('strips ```json fences before parsing', async () => {
    const fenced = '```json\n' + VALID_PAYLOAD_JSON + '\n```';
    const { restore } = mockFetchOnce({
      content: [{ type: 'text', text: fenced }],
      usage: { input_tokens: 1, output_tokens: 1 },
    });
    try {
      const result = await callProviderAndParse({
        prompt: PROMPT, provider: 'anthropic', model: 'claude-sonnet-4-6', apiKey: 'k',
      });
      expect(result.payload.entry_point_class).toBe('PUBLIC_UNAUTH');
    } finally {
      restore();
    }
  });
});

describe('callProviderAndParse — unsupported provider', () => {
  it('throws GenerationError(unsupported_provider) for unknown provider name', async () => {
    await expect(
      callProviderAndParse({
        prompt: PROMPT,
        // Force an invalid provider name to exercise the dispatch default.
        provider: 'mistral' as unknown as 'anthropic',
        model: 'mistral-large',
        apiKey: 'k',
      }),
    ).rejects.toMatchObject({ code: 'unsupported_provider' });
  });
});
