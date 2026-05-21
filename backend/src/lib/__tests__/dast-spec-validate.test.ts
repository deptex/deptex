// Phase 35 (v1.1) — backend spec-validate lib coverage.

import {
  validateSpecSource,
  validateAndFetchSpecUrl,
  validateOpenApiYaml,
} from '../dast-spec-validate';

jest.mock('../url-guard', () => ({
  validateExternalUrl: jest.fn(),
}));
import { validateExternalUrl } from '../url-guard';
const mockGuard = validateExternalUrl as jest.MockedFunction<typeof validateExternalUrl>;

describe('validateSpecSource', () => {
  it.each(['synthesized', 'url', 'none'])('accepts v1.1 enum: %s', (value) => {
    const out = validateSpecSource(value);
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.value).toBe(value);
  });

  it.each(['upload', 'UPLOAD', 'foo', '', 'Synthesized'])('rejects %p', (value) => {
    const out = validateSpecSource(value);
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error.code).toBe('invalid_spec_source');
  });

  it.each([null, undefined, 42, {}, []])('rejects non-string %p', (value) => {
    const out = validateSpecSource(value);
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error.code).toBe('invalid_spec_source');
  });
});

describe('validateOpenApiYaml', () => {
  it('accepts a minimal valid OpenAPI 3.0 doc', async () => {
    const yaml = `
openapi: 3.0.3
info:
  title: T
  version: "1"
paths:
  /a:
    get:
      responses:
        "200":
          description: ok
`;
    const out = await validateOpenApiYaml(yaml);
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.endpoint_count).toBe(1);
  });

  it('accepts a minimal valid OpenAPI 3.1 doc', async () => {
    const yaml = `
openapi: 3.1.0
info:
  title: T
  version: "1"
paths:
  /a:
    get:
      responses:
        "200":
          description: ok
    post:
      responses:
        default:
          description: ok
`;
    const out = await validateOpenApiYaml(yaml);
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.endpoint_count).toBe(2);
  });

  it('rejects empty body', async () => {
    const out = await validateOpenApiYaml('');
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error.code).toBe('spec_parse_failed');
  });

  it('rejects non-YAML body', async () => {
    const out = await validateOpenApiYaml('<html>not a spec</html>');
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error.code).toBe('spec_parse_failed');
  });

  it('rejects YAML that isnt OpenAPI/Swagger', async () => {
    const yaml = `key: value\nother: 1\n`;
    const out = await validateOpenApiYaml(yaml);
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error.code).toBe('spec_parse_failed');
  });
});

describe('validateAndFetchSpecUrl', () => {
  let origFetch: typeof global.fetch;
  beforeEach(() => {
    origFetch = global.fetch;
    mockGuard.mockReset();
  });
  afterEach(() => {
    global.fetch = origFetch;
  });

  it('soft-fails spec_url_invalid when SSRF guard rejects', async () => {
    mockGuard.mockResolvedValue({ valid: false, reason: 'private address' });
    const out = await validateAndFetchSpecUrl('https://bad.local/spec');
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error.code).toBe('spec_url_invalid');
  });

  it('maps 5xx to spec_url_unreachable', async () => {
    mockGuard.mockResolvedValue({ valid: true, resolved: { host: 'h', addresses: [] } });
    global.fetch = jest.fn().mockResolvedValue(new Response('boom', { status: 502 }));
    const out = await validateAndFetchSpecUrl('https://h/spec');
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error.code).toBe('spec_url_unreachable');
  });

  it('maps fetch-throw to spec_url_unreachable', async () => {
    mockGuard.mockResolvedValue({ valid: true, resolved: { host: 'h', addresses: [] } });
    global.fetch = jest.fn().mockRejectedValue(new Error('ECONNRESET'));
    const out = await validateAndFetchSpecUrl('https://h/spec');
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error.code).toBe('spec_url_unreachable');
  });

  it('maps content-length > MAX to spec_too_large', async () => {
    mockGuard.mockResolvedValue({ valid: true, resolved: { host: 'h', addresses: [] } });
    global.fetch = jest.fn().mockResolvedValue(
      new Response('x', {
        status: 200,
        headers: { 'content-length': String(30 * 1024 * 1024) },
      }),
    );
    const out = await validateAndFetchSpecUrl('https://h/big');
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error.code).toBe('spec_too_large');
  });

  it('maps non-OpenAPI body to spec_parse_failed', async () => {
    mockGuard.mockResolvedValue({ valid: true, resolved: { host: 'h', addresses: [] } });
    global.fetch = jest.fn().mockResolvedValue(new Response('<html>nope</html>', { status: 200 }));
    const out = await validateAndFetchSpecUrl('https://h/index.html');
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error.code).toBe('spec_parse_failed');
  });

  it('happy path: fetches + parses 3.1 spec and returns endpoint_count', async () => {
    mockGuard.mockResolvedValue({ valid: true, resolved: { host: 'h', addresses: [] } });
    const body = `openapi: 3.1.0
info:
  title: T
  version: "1"
paths:
  /x:
    get:
      responses:
        default:
          description: ok
`;
    global.fetch = jest.fn().mockResolvedValue(new Response(body, { status: 200 }));
    const out = await validateAndFetchSpecUrl('https://h/spec.yaml');
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.yaml).toBe(body);
      expect(out.endpoint_count).toBe(1);
    }
  });
});
