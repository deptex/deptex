const FLY_API_BASE = 'https://api.machines.dev/v1';

export interface FlyMachineConfig {
  app: string;
  image?: string;
  guest: { cpus: number; memory_mb: number; cpu_kind: 'shared' | 'performance' };
  maxBurst: number;
  region?: string;
}

export const EXTRACTION_CONFIG: FlyMachineConfig = {
  app: process.env.FLY_EXTRACTION_APP || 'deptex-extraction-worker',
  guest: { cpus: 8, memory_mb: 65536, cpu_kind: 'performance' },
  maxBurst: parseInt(process.env.FLY_MAX_BURST_MACHINES || '5', 10),
};

export const AIDER_CONFIG: FlyMachineConfig = {
  app: process.env.FLY_AIDER_APP || 'deptex-aider-worker',
  guest: { cpus: 4, memory_mb: 8192, cpu_kind: 'shared' },
  maxBurst: parseInt(process.env.FLY_AIDER_MAX_BURST || '3', 10),
};

export const WATCHTOWER_CONFIG: FlyMachineConfig = {
  app: process.env.FLY_WATCHTOWER_APP || 'deptex-watchtower-worker',
  guest: { cpus: 1, memory_mb: 1024, cpu_kind: 'shared' },
  maxBurst: 1,
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

export const startExtractionMachine = () => startFlyMachine(EXTRACTION_CONFIG);
export const startAiderMachine = () => startFlyMachine(AIDER_CONFIG);
export const startWatchtowerMachine = () => startFlyMachine(WATCHTOWER_CONFIG);
