/**
 * Fly machines orchestrator unit tests
 */

const originalFetch = globalThis.fetch;

const mockFetch = jest.fn();

beforeAll(() => {
  (globalThis as any).fetch = mockFetch;
});

afterAll(() => {
  (globalThis as any).fetch = originalFetch;
});

beforeEach(() => {
  jest.clearAllMocks();
  process.env.FLY_API_TOKEN = 'test-token';
  delete process.env.FLY_EXTRACTION_APP;
  process.env.FLY_DEPSCANNER_APP = 'deptex-depscanner';
  process.env.FLY_MAX_BURST_MACHINES = '5';
});

import { getDastMachineConfig, startDastMachine, startExtractionMachine } from '../fly-machines';

describe('startExtractionMachine', () => {
  it('happy path: list machines → find stopped → start it → return machine ID', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => [
          { id: 'm1', state: 'started', name: 'a', region: 'iad' },
          { id: 'm2', state: 'stopped', name: 'b', region: 'iad' },
        ],
      })
      .mockResolvedValueOnce({ ok: true });

    const result = await startExtractionMachine();

    expect(result).toBe('m2');
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(mockFetch).toHaveBeenNthCalledWith(1, expect.stringContaining('/machines'), expect.any(Object));
    expect(mockFetch).toHaveBeenNthCalledWith(2, expect.stringContaining('/machines/m2/start'), expect.objectContaining({ method: 'POST' }));
  });

  it('all machines busy: creates burst machine (up to FLY_MAX_BURST_MACHINES)', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => [
          { id: 'm1', state: 'started', name: 'a', region: 'iad' },
          { id: 'm2', state: 'started', name: 'b', region: 'iad' },
          { id: 'm3', state: 'started', name: 'c', region: 'iad' },
        ],
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'm4', state: 'created', name: 'burst', region: 'iad' }),
      });

    const result = await startExtractionMachine();

    expect(result).toBe('m4');
    expect(mockFetch).toHaveBeenCalledWith(expect.stringContaining('/machines'), expect.objectContaining({ method: 'POST' }));
  });

  it('all machines busy + at burst limit: logs error, returns null', async () => {
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () =>
        Array.from({ length: 5 }, (_, i) => ({
          id: `m${i + 1}`,
          state: 'started',
          name: `m${i + 1}`,
          region: 'iad',
        })),
    });

    const result = await startExtractionMachine();

    expect(result).toBeNull();
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('burst limit'));
    consoleSpy.mockRestore();
  });

  it('Fly API 5xx: retries 3x with backoff, then returns null', async () => {
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
    const errorSpy = jest.spyOn(console, 'error').mockImplementation();
    mockFetch.mockResolvedValue({ ok: false, status: 503, statusText: 'Service Unavailable' });

    const result = await startExtractionMachine();

    expect(result).toBeNull();
    expect(mockFetch.mock.calls.length).toBeGreaterThanOrEqual(3);
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('All 3 attempts failed'));
    consoleSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it('Fly API 401: logs critical error, returns null', async () => {
    const errorSpy = jest.spyOn(console, 'error').mockImplementation();
    mockFetch.mockResolvedValue({ ok: false, status: 401, statusText: 'Unauthorized' });

    const result = await startExtractionMachine();

    expect(result).toBeNull();
    errorSpy.mockRestore();
  });

  it('no FLY_API_TOKEN: returns null', async () => {
    delete process.env.FLY_API_TOKEN;
    const errorSpy = jest.spyOn(console, 'error').mockImplementation();

    const result = await startExtractionMachine();

    expect(result).toBeNull();
    expect(mockFetch).not.toHaveBeenCalled();
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('FLY_API_TOKEN not configured'));
    process.env.FLY_API_TOKEN = 'test-token';
    errorSpy.mockRestore();
  });

  it('machine start returns error: tries next stopped machine', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => [
          { id: 'm1', state: 'stopped', name: 'a', region: 'iad' },
          { id: 'm2', state: 'stopped', name: 'b', region: 'iad' },
        ],
      })
      .mockResolvedValueOnce({ ok: false, status: 500, text: async () => 'Internal error' })
      .mockResolvedValueOnce({ ok: true });

    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

    const result = await startExtractionMachine();

    expect(result).toBe('m2');
    expect(mockFetch).toHaveBeenCalledTimes(3);
    consoleSpy.mockRestore();
  });

  it('no machines exist at all: creates first burst machine', async () => {
    mockFetch
      .mockResolvedValueOnce({ ok: true, json: async () => [] })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'm-new', state: 'created', name: 'burst', region: 'iad' }),
      });

    const result = await startExtractionMachine();

    expect(result).toBe('m-new');
  });
});

describe('getDastMachineConfig — runtime branching', () => {
  it("'classic' → shared-cpu-4x 8GB", () => {
    const cfg = getDastMachineConfig('classic');
    expect(cfg.guest).toEqual({ cpus: 4, memory_mb: 8192, cpu_kind: 'shared' });
    expect(cfg.app).toBe('deptex-depscanner');
  });

  it("'spa' → performance-4x 16GB", () => {
    const cfg = getDastMachineConfig('spa');
    expect(cfg.guest).toEqual({ cpus: 4, memory_mb: 16384, cpu_kind: 'performance' });
    expect(cfg.app).toBe('deptex-depscanner');
  });

  it("'unknown' → performance-4x 16GB (first scan default)", () => {
    const cfg = getDastMachineConfig('unknown');
    expect(cfg.guest).toEqual({ cpus: 4, memory_mb: 16384, cpu_kind: 'performance' });
  });

  it('app name is identical across runtimes (single Fly app, type-aware dispatch)', () => {
    const classicApp = getDastMachineConfig('classic').app;
    const spaApp = getDastMachineConfig('spa').app;
    const unknownApp = getDastMachineConfig('unknown').app;
    expect(classicApp).toBe(spaApp);
    expect(spaApp).toBe(unknownApp);
  });

  it('honours FLY_DAST_MAX_BURST env var', () => {
    process.env.FLY_DAST_MAX_BURST = '7';
    // Re-require so the constant re-reads the env value.
    jest.resetModules();
    const reloaded = require('../fly-machines') as typeof import('../fly-machines');
    expect(reloaded.getDastMachineConfig('classic').maxBurst).toBe(7);
    expect(reloaded.getDastMachineConfig('spa').maxBurst).toBe(7);
    delete process.env.FLY_DAST_MAX_BURST;
  });
});

describe('startDastMachine — passes runtime-branched config to Fly', () => {
  it("classic target → shared-cpu-4x 8GB shape on burst create", async () => {
    mockFetch
      .mockResolvedValueOnce({ ok: true, json: async () => [] })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'm-classic', state: 'created', name: 'burst', region: 'iad' }),
      });

    const result = await startDastMachine('classic');

    expect(result).toBe('m-classic');
    expect(mockFetch).toHaveBeenCalledTimes(2);
    const createBody = JSON.parse((mockFetch.mock.calls[1][1] as RequestInit).body as string);
    expect(createBody.config.guest).toEqual({ cpus: 4, memory_mb: 8192, cpu_kind: 'shared' });
  });

  it("'spa' target → performance-4x 16GB shape on burst create", async () => {
    mockFetch
      .mockResolvedValueOnce({ ok: true, json: async () => [] })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'm-spa', state: 'created', name: 'burst', region: 'iad' }),
      });

    const result = await startDastMachine('spa');

    expect(result).toBe('m-spa');
    const createBody = JSON.parse((mockFetch.mock.calls[1][1] as RequestInit).body as string);
    expect(createBody.config.guest).toEqual({ cpus: 4, memory_mb: 16384, cpu_kind: 'performance' });
  });

  it("'unknown' (no arg / first scan) defaults to performance-4x 16GB", async () => {
    mockFetch
      .mockResolvedValueOnce({ ok: true, json: async () => [] })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'm-default', state: 'created', name: 'burst', region: 'iad' }),
      });

    const result = await startDastMachine();

    expect(result).toBe('m-default');
    const createBody = JSON.parse((mockFetch.mock.calls[1][1] as RequestInit).body as string);
    expect(createBody.config.guest).toEqual({ cpus: 4, memory_mb: 16384, cpu_kind: 'performance' });
  });
});
