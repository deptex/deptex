/**
 * End-to-end Shai-Hulud-class detection test.
 *
 * Drives a synthetic npm registry response (fixtures/maintainer-shai-hulud.json)
 * through the full maintainer-signal pipeline:
 *
 *   computeMaintainerSignalsForPackage  →  severityForMaintainerSignal
 *
 * and asserts the package fires a CRITICAL finding under the
 * `maintainer:new_account_with_install_script` rule. This is the smoke test
 * for the Shai-Hulud attack class — a brand-new account publishes a package
 * with an install hook that runs network code on `npm install`. The
 * synthetic fixture has no upstream registry dependency; the fetcher is
 * mocked so the test runs offline + deterministic in CI.
 */
import * as path from 'path';
import * as fs from 'fs';
import {
  supabase,
  setTableResponse,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';
import { computeMaintainerSignalsForPackage } from '../malicious/maintainer-signals';
import { severityForMaintainerSignal } from '../malicious/severity';

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
});

function loadFixture(): any {
  const fixturePath = path.join(__dirname, 'fixtures', 'maintainer-shai-hulud.json');
  const raw = fs.readFileSync(fixturePath, 'utf8');
  return JSON.parse(raw);
}

function fetcherFor(payload: unknown): typeof fetch {
  return async () =>
    ({
      ok: true,
      status: 200,
      statusText: 'OK',
      json: async () => payload,
    } as any);
}

describe('Shai-Hulud-class detection', () => {
  it('fires critical maintainer:new_account_with_install_script on the synthetic fixture', async () => {
    setTableResponse('package_maintainer_snapshots', 'maybeSingle', { data: null, error: null });

    const now = new Date('2026-05-05T00:00:00.000Z');
    // Substitute the recent timestamp so account_age_days < 30.
    const recentTs = new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000).toISOString();
    const fixture = loadFixture();
    fixture.time.created = recentTs;
    fixture.time.modified = recentTs;
    fixture.time['1.0.0'] = recentTs;

    const computed = await computeMaintainerSignalsForPackage(
      supabase as any,
      'evil-supply-chain-pkg',
      '1.0.0',
      'npm',
      { now, fetcher: fetcherFor(fixture) },
    );

    expect(computed).not.toBeNull();
    expect(computed!.signals.account_age_days).toBeLessThan(30);
    expect(computed!.signals.install_script_present).toBe(true);

    const finding = severityForMaintainerSignal(computed!.signals);
    expect(finding).not.toBeNull();
    expect(finding!.severity).toBe('critical');
    expect(finding!.rule_id).toBe('maintainer:new_account_with_install_script');
    // Narrative is injection-clean — message comes from severity.ts, not registry data.
    expect(finding!.message).not.toContain('newuser_2025');
    expect(finding!.message).not.toContain('protonmail');
  });

  it('does NOT fire a finding on an established package without install hooks', async () => {
    setTableResponse('package_maintainer_snapshots', 'maybeSingle', { data: null, error: null });

    const now = new Date('2026-05-05T00:00:00.000Z');
    const benign = {
      name: 'lodash',
      'dist-tags': { latest: '4.17.21' },
      time: { created: '2014-01-01T00:00:00.000Z' },  // ~12 years old
      versions: {
        '4.17.21': {
          maintainers: [{ name: 'jdalton', email: 'jdalton@example.com' }],
          scripts: {},  // no install hooks
          dist: { signatures: [], attestations: null },
        },
      },
    };

    const computed = await computeMaintainerSignalsForPackage(
      supabase as any,
      'lodash',
      '4.17.21',
      'npm',
      { now, fetcher: fetcherFor(benign) },
    );

    expect(computed).not.toBeNull();
    expect(computed!.signals.account_age_days).toBeGreaterThan(30);
    expect(computed!.signals.install_script_present).toBe(false);

    const finding = severityForMaintainerSignal(computed!.signals);
    expect(finding).toBeNull();
  });
});
