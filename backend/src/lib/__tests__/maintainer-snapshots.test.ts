/**
 * Maintainer-snapshot writer / reader unit tests.
 *
 * Covers the M1c historical-baseline contract:
 *   - upsert honors the (package, version, ecosystem, observed_at) natural key
 *   - cold-start (no row predates cutoff) returns null
 *   - ecosystem canonicalization (`pip` -> `pypi`, etc.)
 *   - unknown ecosystem returns null without throwing
 */
import {
  supabase,
  setTableResponse,
  clearTableRegistry,
  queryBuilder,
} from '../../test/mocks/supabaseSingleton';
import {
  writeMaintainerSnapshot,
  getLatestSnapshotBefore,
  getLatestSnapshot,
} from '../malicious/maintainer-snapshots';

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
});

describe('writeMaintainerSnapshot', () => {
  it('upserts on the (package, version, ecosystem, observed_at) natural key and returns the row id', async () => {
    setTableResponse('package_maintainer_snapshots', 'maybeSingle', {
      data: { id: 'snap-1' },
      error: null,
    });

    const id = await writeMaintainerSnapshot(supabase as any, {
      packageName: 'lodash',
      version: '4.17.20',
      ecosystem: 'npm',
      maintainerHandles: ['john', 'jdoe'],
      primaryMaintainerEmail: 'jdoe@example.com',
      signingConfigHash: 'sha-1',
      postinstallHash: null,
      registryMetadataRaw: { version: '4.17.20' },
      observedAt: '2026-05-05T10:00:00.000Z',
    });

    expect(id).toBe('snap-1');
    expect((queryBuilder as any).upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        package_name: 'lodash',
        version: '4.17.20',
        ecosystem: 'npm',
        observed_at: '2026-05-05T10:00:00.000Z',
        maintainer_handles: ['john', 'jdoe'],
        primary_maintainer_email: 'jdoe@example.com',
      }),
      expect.objectContaining({
        onConflict: 'package_name,version,ecosystem,observed_at',
      }),
    );
  });

  it('canonicalizes ecosystem aliases at write time (pip -> pypi)', async () => {
    setTableResponse('package_maintainer_snapshots', 'maybeSingle', {
      data: { id: 'snap-2' },
      error: null,
    });

    await writeMaintainerSnapshot(supabase as any, {
      packageName: 'requests',
      version: '2.31.0',
      ecosystem: 'pip',
      maintainerHandles: ['kennethreitz'],
      primaryMaintainerEmail: null,
      signingConfigHash: null,
      postinstallHash: null,
      registryMetadataRaw: null,
    });

    expect((queryBuilder as any).upsert).toHaveBeenCalledWith(
      expect.objectContaining({ ecosystem: 'pypi' }),
      expect.anything(),
    );
  });

  it('returns null on unknown ecosystem without writing', async () => {
    const id = await writeMaintainerSnapshot(supabase as any, {
      packageName: 'whatever',
      version: '1.0.0',
      ecosystem: 'banana',
      maintainerHandles: [],
      primaryMaintainerEmail: null,
      signingConfigHash: null,
      postinstallHash: null,
      registryMetadataRaw: null,
    });

    expect(id).toBeNull();
  });
});

describe('getLatestSnapshotBefore', () => {
  it('returns the most recent snapshot strictly older than cutoff', async () => {
    setTableResponse('package_maintainer_snapshots', 'maybeSingle', {
      data: {
        id: 'snap-base',
        package_name: 'lodash',
        version: '4.17.20',
        ecosystem: 'npm',
        observed_at: '2026-04-01T00:00:00.000Z',
        maintainer_handles: ['old'],
        primary_maintainer_email: 'old@example.com',
        signing_config_hash: null,
        postinstall_hash: null,
        registry_metadata_raw: null,
      },
      error: null,
    });

    const baseline = await getLatestSnapshotBefore(
      supabase as any,
      'lodash',
      '4.17.20',
      'npm',
      '2026-05-05T00:00:00.000Z',
    );

    expect(baseline).not.toBeNull();
    expect(baseline?.maintainer_handles).toEqual(['old']);
    expect((queryBuilder as any).lt).toHaveBeenCalledWith('observed_at', '2026-05-05T00:00:00.000Z');
    expect((queryBuilder as any).order).toHaveBeenCalledWith('observed_at', { ascending: false });
  });

  it('returns null on cold start (no row predates cutoff)', async () => {
    setTableResponse('package_maintainer_snapshots', 'maybeSingle', { data: null, error: null });

    const baseline = await getLatestSnapshotBefore(
      supabase as any,
      'brand-new-package',
      '0.1.0',
      'npm',
      '2026-05-05T00:00:00.000Z',
    );

    expect(baseline).toBeNull();
  });

  it('returns null on unknown ecosystem without querying', async () => {
    const baseline = await getLatestSnapshotBefore(
      supabase as any,
      'x',
      '1',
      'banana',
      new Date(),
    );
    expect(baseline).toBeNull();
  });
});

describe('getLatestSnapshot', () => {
  it('returns the most recent snapshot regardless of age', async () => {
    setTableResponse('package_maintainer_snapshots', 'maybeSingle', {
      data: {
        id: 'snap-current',
        package_name: 'lodash',
        version: '4.17.20',
        ecosystem: 'npm',
        observed_at: '2026-05-05T00:00:00.000Z',
        maintainer_handles: ['current'],
        primary_maintainer_email: 'current@example.com',
        signing_config_hash: null,
        postinstall_hash: null,
        registry_metadata_raw: null,
      },
      error: null,
    });

    const current = await getLatestSnapshot(
      supabase as any,
      'lodash',
      '4.17.20',
      'npm',
    );

    expect(current).not.toBeNull();
    expect(current?.maintainer_handles).toEqual(['current']);
  });
});
