const FLY_API_BASE = 'https://api.machines.dev/v1';

export interface FlyMachineConfig {
  app: string;
  image?: string;
  guest: { cpus: number; memory_mb: number; cpu_kind: 'shared' | 'performance' };
  maxBurst: number;
  region?: string;
}

// Phase 23: extraction-worker → depscanner. The new Fly app name is `deptex-depscanner`.
// During the rollover window we still read FLY_EXTRACTION_APP so existing deployments
// keep pointing at the old app until Henry creates the new one and flips the env var.
//
// Single Fly app hosts every scan_jobs.type. Per-type machine size differs at start —
// extraction needs the perf-8x for tree-sitter + atom + dep-scan; DAST needs less.
// Same `app` value, different `guest` shape passed to the Machines API at create time.
function depscannerApp(): string {
  return (
    process.env.FLY_DEPSCANNER_APP ||
    process.env.FLY_EXTRACTION_APP ||
    'deptex-depscanner'
  );
}

export const DEPSCANNER_CONFIG: FlyMachineConfig = {
  app: depscannerApp(),
  guest: { cpus: 8, memory_mb: 65536, cpu_kind: 'performance' },
  maxBurst: parseInt(process.env.FLY_MAX_BURST_MACHINES || '5', 10),
};

// Phase 23b: DAST scans run on the same depscanner Fly app but on a smaller
// machine shape. ZAP doesn't need 65GB; 8GB shared-cpu-4x is plenty.
//
// Phase 24 (v2.1a): SPA scans run ZAP browserBased + headless Chromium and
// need ~16GB to keep the AJAX spider alive on real apps. Classic scans stay
// on the cheaper shared-cpu-4x 8GB shape. The route resolves the target's
// `detected_runtime` before queueing and passes it to `startDastMachine` so
// the right guest shape is provisioned at machine-start time.
//
// `unknown` is treated as SPA so the very first scan (before runtime is
// classified) gets enough memory; once the worker classifies the target as
// `classic` the next scan downsizes automatically.
export type DetectedRuntime = 'unknown' | 'classic' | 'spa';

const DAST_MAX_BURST = parseInt(process.env.FLY_DAST_MAX_BURST || '3', 10);

export function getDastMachineConfig(detectedRuntime: DetectedRuntime): FlyMachineConfig {
  if (detectedRuntime === 'classic') {
    return {
      app: depscannerApp(),
      guest: { cpus: 4, memory_mb: 8192, cpu_kind: 'shared' },
      maxBurst: DAST_MAX_BURST,
    };
  }
  // 'unknown' or 'spa' → performance-4x 16GB.
  return {
    app: depscannerApp(),
    guest: { cpus: 4, memory_mb: 16384, cpu_kind: 'performance' },
    maxBurst: DAST_MAX_BURST,
  };
}

// Back-compat: kept for `recovery.ts`, which only reads `.app`. The app name
// is identical across runtimes (single Fly app, type-aware dispatch), so the
// classic shape works as the recovery fallback.
export const DAST_CONFIG: FlyMachineConfig = getDastMachineConfig('classic');

export const FIX_CONFIG: FlyMachineConfig = {
  app: process.env.FLY_FIX_APP || 'deptex-fix-worker',
  guest: { cpus: 4, memory_mb: 8192, cpu_kind: 'shared' },
  maxBurst: parseInt(process.env.FLY_FIX_MAX_BURST || '3', 10),
};

interface FlyMachine {
  id: string;
  name: string;
  state: string;
  region: string;
  config?: Record<string, unknown>;
}

function getToken(): string {
  return process.env.FLY_API_TOKEN ?? '';
}

async function flyFetch(app: string, path: string, options: RequestInit = {}): Promise<Response> {
  const url = `${FLY_API_BASE}/apps/${app}${path}`;
  return fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${getToken()}`,
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });
}

async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function listMachines(app: string): Promise<FlyMachine[]> {
  const res = await flyFetch(app, '/machines');
  if (!res.ok) {
    throw new Error(`Failed to list machines: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<FlyMachine[]>;
}

async function startMachine(app: string, machineId: string): Promise<void> {
  const res = await flyFetch(app, `/machines/${machineId}/start`, { method: 'POST' });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Failed to start machine ${machineId}: ${res.status} ${text}`);
  }
}

export async function stopFlyMachine(app: string, machineId: string): Promise<void> {
  const res = await flyFetch(app, `/machines/${machineId}/stop`, { method: 'POST' });
  if (!res.ok) {
    const text = await res.text();
    console.warn(`[FLY] Failed to stop machine ${machineId}: ${res.status} ${text}`);
  }
}

/** Extract the image reference from an existing machine's config. */
function getImageFromMachine(machine: FlyMachine): string | null {
  const cfg = machine.config as Record<string, unknown> | undefined;
  if (!cfg) return null;
  if (typeof cfg.image === 'string' && cfg.image) return cfg.image;
  return null;
}

async function createBurstMachine(config: FlyMachineConfig, imageOverride?: string): Promise<string> {
  const image = imageOverride || config.image || `registry.fly.io/${config.app}:latest`;
  const region = config.region || 'iad';

  const res = await flyFetch(config.app, '/machines', {
    method: 'POST',
    body: JSON.stringify({
      name: `${config.app}-burst-${Date.now()}`,
      region,
      config: {
        auto_destroy: true,
        restart: { policy: 'no' },
        image,
        guest: config.guest,
      },
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Failed to create burst machine: ${res.status} ${text}`);
  }

  const machine = (await res.json()) as FlyMachine;
  return machine.id;
}

/**
 * Start a Fly machine from the pool, or create a burst machine if all are busy.
 * Returns the machine ID on success, or null if unable to start any machine.
 * Failures are logged but never throw — the job stays queued for recovery.
 */
export async function startFlyMachine(config: FlyMachineConfig): Promise<string | null> {
  const token = getToken();

  if (!token) {
    console.error(`[FLY] FLY_API_TOKEN not configured — cannot start ${config.app} machines`);
    return null;
  }

  const MAX_RETRIES = 3;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const machines = await listMachines(config.app);
      const stopped = machines.filter((m) => m.state === 'stopped');

      // Resolve the image from an existing machine so burst machines use the
      // same deployed image instead of guessing `:latest` (which may not exist).
      let resolvedImage: string | null = null;
      for (const m of machines) {
        resolvedImage = getImageFromMachine(m);
        if (resolvedImage) break;
      }
      if (resolvedImage) {
        console.log(`[FLY] Resolved image from existing machine: ${resolvedImage}`);
      }

      if (stopped.length > 0) {
        for (const machine of stopped) {
          try {
            await startMachine(config.app, machine.id);
            console.log(`[FLY] Started ${config.app} machine ${machine.id} (pool)`);
            return machine.id;
          } catch (e: any) {
            console.warn(`[FLY] Failed to start machine ${machine.id}, trying next: ${e.message}`);
          }
        }
      }

      if (machines.length < config.maxBurst) {
        try {
          const machineId = await createBurstMachine(config, resolvedImage ?? undefined);
          console.log(`[FLY] Created ${config.app} burst machine ${machineId} (total: ${machines.length + 1}/${config.maxBurst})`);
          return machineId;
        } catch (e: any) {
          console.error(`[FLY] Failed to create burst machine: ${e.message}`);
        }
      } else {
        console.warn(`[FLY] All ${machines.length} ${config.app} machines busy and at burst limit (${config.maxBurst})`);
      }

      return null;
    } catch (e: any) {
      const isRateLimited = e.message?.includes('429');
      const retryAfter = isRateLimited ? 2000 : 1000 * Math.pow(2, attempt - 1);

      if (attempt < MAX_RETRIES) {
        console.warn(`[FLY] Attempt ${attempt}/${MAX_RETRIES} failed: ${e.message}. Retrying in ${retryAfter}ms`);
        await sleep(retryAfter);
      } else {
        console.error(`[FLY] All ${MAX_RETRIES} attempts failed: ${e.message}. Job stays queued for recovery.`);
        return null;
      }
    }
  }

  return null;
}

export const startDepscannerMachine = () => startFlyMachine(DEPSCANNER_CONFIG);
// Back-compat alias — extraction is one of several scan types depscanner runs.
export const startExtractionMachine = startDepscannerMachine;
export const startDastMachine = (detectedRuntime: DetectedRuntime = 'unknown') =>
  startFlyMachine(getDastMachineConfig(detectedRuntime));
export const startFixMachine = () => startFlyMachine(FIX_CONFIG);
