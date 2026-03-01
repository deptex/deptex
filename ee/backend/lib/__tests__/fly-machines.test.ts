/**
 * Phase 2M: Fly machines orchestrator unit tests
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
  process.env.FLY_EXTRACTION_APP = 'deptex-extraction-worker';
  process.env.FLY_MAX_BURST_MACHINES = '5';
});

import { startExtractionMachine } from '../fly-machines';

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
