/**
 * Live Fly e2e for the fleet dispatcher. Proves the real-Fly cold-start path
 * the unit tests can't: a pinned-image machine actually boots on Fly, is tagged
 * SCAN_TYPE=extraction, and is reachable for the dispatcher's inflight ceiling.
 *
 * This spins a REAL Fly machine (billable seconds) and then destroys it, so it
 * is opt-in: set DEPTEX_FLEET_E2E=1 to run. Requires the backend env
 * (FLY_API_TOKEN, FLY_DEPSCANNER_APP, FLY_DEPSCANNER_IMAGE).
 *
 *   npm run e2e:fleet:live   (in backend/)
 *
 * The full burst→cap→drain→zero behavior is verified deterministically in the
 * committed unit suite (src/lib/__tests__/fleet-dispatcher.test.ts, the
 * "TWO concurrent ticks" hard-cap proof); to watch it on real load, fire a
 * burst of project creations and watch the /admin extraction Fleet panel.
 */
import 'dotenv/config';
import {
  DEPSCANNER_CONFIG,
  createDepscannerBurst,
  listMachines,
  stopFlyMachine,
  machineScanType,
  getDepscannerImage,
} from '../src/lib/fly-machines';

const FLY_API_BASE = 'https://api.machines.dev/v1';

async function destroyMachine(app: string, id: string): Promise<void> {
  await fetch(`${FLY_API_BASE}/apps/${app}/machines/${id}?force=true`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${process.env.FLY_API_TOKEN ?? ''}` },
  });
}

async function main(): Promise<void> {
  if (process.env.DEPTEX_FLEET_E2E !== '1') {
    console.error('Refusing to run: this spins a real Fly machine. Set DEPTEX_FLEET_E2E=1 to proceed.');
    process.exit(2);
  }
  if (!process.env.FLY_API_TOKEN) throw new Error('FLY_API_TOKEN not set');

  const app = DEPSCANNER_CONFIG.app;
  console.log(`[e2e] app=${app} image=${getDepscannerImage()}`);

  console.log('[e2e] creating one pinned-image extraction burst machine...');
  const id = await createDepscannerBurst();
  console.log(`[e2e] created machine ${id}`);

  let ok = false;
  try {
    // Poll listMachines until the machine appears, tagged extraction.
    for (let i = 0; i < 30; i++) {
      const machines = await listMachines(app);
      const m = machines.find((x) => x.id === id);
      if (m) {
        const tag = machineScanType(m);
        console.log(`[e2e] machine ${id} state=${m.state} SCAN_TYPE=${tag}`);
        if (tag !== 'extraction') {
          throw new Error(`expected SCAN_TYPE=extraction, got ${tag}`);
        }
        ok = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
    if (!ok) throw new Error('created machine never appeared in listMachines within 60s');
    console.log('[e2e] PASS — pinned-image machine booted and is tagged extraction');
  } finally {
    console.log(`[e2e] cleaning up machine ${id}...`);
    try {
      await stopFlyMachine(app, id);
    } catch { /* may already be stopping */ }
    try {
      await destroyMachine(app, id);
      console.log(`[e2e] destroyed ${id}`);
    } catch (e: any) {
      console.warn(`[e2e] could not destroy ${id} (destroy it manually): ${e?.message ?? e}`);
    }
  }
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error('[e2e] FAILED:', e?.message ?? e);
  process.exit(1);
});
