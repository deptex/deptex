const FLY_API_BASE = 'https://api.machines.dev/v1';

function getConfig() {
  return {
    token: process.env.FLY_API_TOKEN ?? '',
    app: process.env.FLY_EXTRACTION_APP ?? 'deptex-extraction-worker',
    maxBurstMachines: parseInt(process.env.FLY_MAX_BURST_MACHINES ?? '5', 10),
  };
}

interface FlyMachine {
  id: string;
  name: string;
  state: string;
  region: string;
  config?: Record<string, unknown>;
}

async function flyFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const { token, app } = getConfig();
  const url = `${FLY_API_BASE}/apps/${app}${path}`;
  return fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });
}

async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function listMachines(): Promise<FlyMachine[]> {
  const res = await flyFetch('/machines');
  if (!res.ok) {
    throw new Error(`Failed to list machines: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<FlyMachine[]>;
}

async function startMachine(machineId: string): Promise<void> {
  const res = await flyFetch(`/machines/${machineId}/start`, { method: 'POST' });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Failed to start machine ${machineId}: ${res.status} ${text}`);
  }
}

async function createBurstMachine(): Promise<string> {
  const { app } = getConfig();
  const res = await flyFetch('/machines', {
    method: 'POST',
    body: JSON.stringify({
      name: `${app}-burst-${Date.now()}`,
      region: 'iad',
      config: {
        auto_destroy: true,
        restart: { policy: 'no' },
        image: `registry.fly.io/${app}:latest`,
        guest: {
          cpu_kind: 'performance',
          cpus: 8,
          memory_mb: 65536,
        },
        stop_config: { timeout: '4h' },
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
 * Start an extraction machine from the pool, or create a burst machine if all are busy.
 * Returns the machine ID on success, or null if unable to start any machine.
 * Failures are logged but never throw — the job stays queued in Supabase for recovery.
 */
export async function startExtractionMachine(): Promise<string | null> {
  const { token, maxBurstMachines } = getConfig();

  if (!token) {
    console.error('[FLY] FLY_API_TOKEN not configured — cannot start extraction machines');
    return null;
  }

  const MAX_RETRIES = 3;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const machines = await listMachines();
      const stopped = machines.filter((m) => m.state === 'stopped');

      if (stopped.length > 0) {
        for (const machine of stopped) {
          try {
            await startMachine(machine.id);
            console.log(`[FLY] Started machine ${machine.id} (pool)`);
            return machine.id;
          } catch (e: any) {
            console.warn(`[FLY] Failed to start machine ${machine.id}, trying next: ${e.message}`);
          }
        }
      }

      if (machines.length < maxBurstMachines) {
        try {
          const machineId = await createBurstMachine();
          console.log(`[FLY] Created burst machine ${machineId} (total: ${machines.length + 1}/${maxBurstMachines})`);
          return machineId;
        } catch (e: any) {
          console.error(`[FLY] Failed to create burst machine: ${e.message}`);
        }
      } else {
        console.warn(`[FLY] All ${machines.length} machines busy and at burst limit (${maxBurstMachines})`);
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
