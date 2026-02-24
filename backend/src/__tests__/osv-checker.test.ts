/**
 * Tests for watchtower-poller osv-checker (fetchLatestNpmVersion).
 * P8: When dist-tags.latest is prerelease (canary/rc), we resolve latest stable from versions + time.
 */

const mockFetch = jest.fn();

beforeEach(() => {
  jest.clearAllMocks();
  global.fetch = mockFetch;
});

afterEach(() => {
  (global as any).fetch = undefined;
});

describe('fetchLatestNpmVersion', () => {
  it('P8: should return latest stable from versions+time when dist-tags.latest is prerelease', async () => {
    const { fetchLatestNpmVersion } = await import('../../watchtower-poller/src/osv-checker');

    mockFetch.mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          'dist-tags': { latest: '4.0.0-canary.0' },
          versions: {
            '4.0.0': {},
            '4.0.0-canary.0': {},
          },
          time: {
            '4.0.0': '2025-01-01T00:00:00.000Z',
            '4.0.0-canary.0': '2025-01-02T00:00:00.000Z',
          },
        }),
    });

    const result = await fetchLatestNpmVersion('some-pkg');

    expect(result.latestVersion).toBe('4.0.0');
    expect(result.publishedAt).toBe('2025-01-01T00:00:00.000Z');
  });

  it('should return dist-tags.latest when it is already stable', async () => {
    const { fetchLatestNpmVersion } = await import('../../watchtower-poller/src/osv-checker');

    mockFetch.mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          'dist-tags': { latest: '4.18.0' },
          versions: { '4.18.0': {} },
          time: { '4.18.0': '2025-06-01T00:00:00.000Z' },
        }),
    });

    const result = await fetchLatestNpmVersion('lodash');

    expect(result.latestVersion).toBe('4.18.0');
    expect(result.publishedAt).toBe('2025-06-01T00:00:00.000Z');
  });

  it('should return null when registry returns 404', async () => {
    const { fetchLatestNpmVersion } = await import('../../watchtower-poller/src/osv-checker');

    mockFetch.mockResolvedValue({ ok: false, status: 404 });

    const result = await fetchLatestNpmVersion('nonexistent-package');

    expect(result.latestVersion).toBe(null);
    expect(result.publishedAt).toBe(null);
  });
});
