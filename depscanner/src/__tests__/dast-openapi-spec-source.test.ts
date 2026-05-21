// Phase 35 (v1.1) — resolveSpecForJob: per-source happy path + soft-fail
// branches. URL fetch is mocked via global.fetch; synthesis runs through
// the real synthesizer (small input).

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
  resolveSpecForJob,
  type SpecResolveStatus,
} from '../dast/openapi-spec-source';
import type { EntryPointRow } from '../dast/cross-link';

// Module-level Jest mock for the url-guard import path. Per-test we reach
// into the mock fn and configure it. Has to live at top level so jest hoists
// it BEFORE the spec-source import runs.
jest.mock('../dast/url-guard', () => ({
  validateExternalUrl: jest.fn(),
}));
import { validateExternalUrl } from '../dast/url-guard';
const mockedValidate = validateExternalUrl as jest.MockedFunction<
  typeof validateExternalUrl
>;

function ep(overrides: Partial<EntryPointRow> = {}): EntryPointRow {
  return {
    framework: 'express',
    http_method: 'GET',
    route_pattern: '/users/:id',
    handler_name: 'getUser',
    file_path: 'src/users.ts',
    line_number: 42,
    entry_point_type: 'http_route',
    classification: 'PUBLIC_UNAUTH',
    ...overrides,
  };
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spec-source-test-'));
  mockedValidate.mockReset();
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('resolveSpecForJob', () => {
  describe('source: none', () => {
    it('returns no spec + status=ok', async () => {
      const out = await resolveSpecForJob({
        source: 'none',
        api_spec_url: null,
        targetUrl: 'https://api.example.com',
        entryPoints: [ep()],
        tmpDir,
      });
      expect(out.specPath).toBeUndefined();
      expect(out.status).toBe<SpecResolveStatus>('ok');
    });
  });

  describe('source: upload (v1.1 defense-in-depth)', () => {
    it('treats upload mode as no-spec in v1.1', async () => {
      const out = await resolveSpecForJob({
        source: 'upload',
        api_spec_url: null,
        targetUrl: 'https://api.example.com',
        entryPoints: [ep()],
        tmpDir,
      });
      expect(out.specPath).toBeUndefined();
      expect(out.status).toBe<SpecResolveStatus>('ok');
    });
  });

  describe('source: synthesized', () => {
    it('writes a YAML spec + sidecar to tmpDir when entry points are present', async () => {
      const out = await resolveSpecForJob({
        source: 'synthesized',
        api_spec_url: null,
        targetUrl: 'https://api.example.com',
        entryPoints: [
          ep({ route_pattern: '/users', http_method: 'GET' }),
          ep({ route_pattern: '/users/:id', http_method: 'PATCH', handler_name: 'updateUser' }),
        ],
        tmpDir,
      });
      expect(out.status).toBe<SpecResolveStatus>('ok');
      expect(out.endpointCount).toBe(2);
      expect(out.specPath).toBeDefined();
      expect(out.sidecarPath).toBeDefined();
      expect(out.sidecar).toBeDefined();
      expect(fs.existsSync(out.specPath!)).toBe(true);
      expect(fs.existsSync(out.sidecarPath!)).toBe(true);
      const yamlBytes = fs.readFileSync(out.specPath!, 'utf-8');
      // js-yaml may emit the version unquoted or quoted depending on parse
      // heuristics; assert presence of both the key and version digits.
      expect(yamlBytes).toMatch(/^openapi:\s*"?3\.1\.0"?/m);
      const sidecar = JSON.parse(fs.readFileSync(out.sidecarPath!, 'utf-8'));
      expect(sidecar['GET /users']).toBeDefined();
      expect(sidecar['PATCH /users/{id}']).toBeDefined();
    });

    it('soft-fails with synth.no_entry_points when no http_route entries', async () => {
      const out = await resolveSpecForJob({
        source: 'synthesized',
        api_spec_url: null,
        targetUrl: 'https://api.example.com',
        entryPoints: [],
        tmpDir,
      });
      expect(out.specPath).toBeUndefined();
      expect(out.status).toBe<SpecResolveStatus>('synth.no_entry_points');
      expect(out.endpointCount).toBe(0);
    });

    it('soft-fails when every entry is filtered out (e.g. all OFFLINE_WORKER)', async () => {
      const out = await resolveSpecForJob({
        source: 'synthesized',
        api_spec_url: null,
        targetUrl: 'https://api.example.com',
        entryPoints: [ep({ classification: 'OFFLINE_WORKER' })],
        tmpDir,
      });
      expect(out.specPath).toBeUndefined();
      expect(out.status).toBe<SpecResolveStatus>('synth.no_entry_points');
    });
  });

  describe('source: url', () => {
    it('soft-fails url.fetch_failed when SSRF guard rejects the URL', async () => {
      mockedValidate.mockResolvedValue({ valid: false, reason: 'private address' });
      const out = await resolveSpecForJob({
        source: 'url',
        api_spec_url: 'https://internal.bad/spec',
        targetUrl: 'https://api.example.com',
        entryPoints: [],
        tmpDir,
      });
      expect(out.specPath).toBeUndefined();
      expect(out.status).toBe<SpecResolveStatus>('url.fetch_failed');
    });

    it('soft-fails url.fetch_failed when api_spec_url is missing', async () => {
      const out = await resolveSpecForJob({
        source: 'url',
        api_spec_url: null,
        targetUrl: 'https://api.example.com',
        entryPoints: [],
        tmpDir,
      });
      expect(out.status).toBe<SpecResolveStatus>('url.fetch_failed');
    });

    it('happy path: fetches and writes YAML to tmpDir', async () => {
      mockedValidate.mockResolvedValue({
        valid: true,
        resolved: { host: 'spec.example.com', addresses: ['93.184.216.34'] },
      });
      const yamlBody = 'openapi: 3.0.3\ninfo:\n  title: T\n  version: "1"\npaths: {}\n';
      const origFetch = global.fetch;
      global.fetch = jest.fn().mockResolvedValue(
        new Response(yamlBody, { status: 200, headers: { 'content-type': 'application/yaml' } }),
      );
      try {
        const out = await resolveSpecForJob({
          source: 'url',
          api_spec_url: 'https://spec.example.com/openapi.yaml',
          targetUrl: 'https://api.example.com',
          entryPoints: [],
          tmpDir,
        });
        expect(out.status).toBe<SpecResolveStatus>('ok');
        expect(out.specPath).toBeDefined();
        expect(fs.readFileSync(out.specPath!, 'utf-8')).toBe(yamlBody);
        // url mode produces no sidecar (we don't know the handlers).
        expect(out.sidecarPath).toBeUndefined();
        expect(out.sidecar).toBeUndefined();
      } finally {
        global.fetch = origFetch;
      }
    });

    it('maps 5xx response to url.fetch_failed', async () => {
      mockedValidate.mockResolvedValue({
        valid: true,
        resolved: { host: 'spec.example.com', addresses: ['93.184.216.34'] },
      });
      const origFetch = global.fetch;
      global.fetch = jest.fn().mockResolvedValue(new Response('boom', { status: 502 }));
      try {
        const out = await resolveSpecForJob({
          source: 'url',
          api_spec_url: 'https://spec.example.com/openapi.yaml',
          targetUrl: 'https://api.example.com',
          entryPoints: [],
          tmpDir,
        });
        expect(out.status).toBe<SpecResolveStatus>('url.fetch_failed');
      } finally {
        global.fetch = origFetch;
      }
    });

    it('maps fetch-throw (network error) to url.fetch_failed', async () => {
      mockedValidate.mockResolvedValue({
        valid: true,
        resolved: { host: 'spec.example.com', addresses: ['93.184.216.34'] },
      });
      const origFetch = global.fetch;
      global.fetch = jest.fn().mockRejectedValue(new Error('ECONNRESET'));
      try {
        const out = await resolveSpecForJob({
          source: 'url',
          api_spec_url: 'https://spec.example.com/openapi.yaml',
          targetUrl: 'https://api.example.com',
          entryPoints: [],
          tmpDir,
        });
        expect(out.status).toBe<SpecResolveStatus>('url.fetch_failed');
      } finally {
        global.fetch = origFetch;
      }
    });

    it('maps non-OpenAPI body to url.parse_failed', async () => {
      mockedValidate.mockResolvedValue({
        valid: true,
        resolved: { host: 'spec.example.com', addresses: ['93.184.216.34'] },
      });
      const origFetch = global.fetch;
      global.fetch = jest.fn().mockResolvedValue(
        new Response('<html>not a spec</html>', { status: 200 }),
      );
      try {
        const out = await resolveSpecForJob({
          source: 'url',
          api_spec_url: 'https://spec.example.com/index.html',
          targetUrl: 'https://api.example.com',
          entryPoints: [],
          tmpDir,
        });
        expect(out.status).toBe<SpecResolveStatus>('url.parse_failed');
      } finally {
        global.fetch = origFetch;
      }
    });

    it('rejects response with declared content-length > MAX_SPEC_BYTES as url.fetch_failed', async () => {
      mockedValidate.mockResolvedValue({
        valid: true,
        resolved: { host: 'spec.example.com', addresses: ['93.184.216.34'] },
      });
      const origFetch = global.fetch;
      const body = 'x'.repeat(100);
      global.fetch = jest.fn().mockResolvedValue(
        new Response(body, {
          status: 200,
          headers: { 'content-length': String(30 * 1024 * 1024) },
        }),
      );
      try {
        const out = await resolveSpecForJob({
          source: 'url',
          api_spec_url: 'https://spec.example.com/big.yaml',
          targetUrl: 'https://api.example.com',
          entryPoints: [],
          tmpDir,
        });
        expect(out.status).toBe<SpecResolveStatus>('url.fetch_failed');
      } finally {
        global.fetch = origFetch;
      }
    });
  });
});
