const FLY_API_BASE = 'https://api.machines.dev/v1';

export interface FlyMachineConfig {
  app: string;
  image?: string;
  guest: { cpus: number; memory_mb: number; cpu_kind: 'shared' | 'performance' };
  maxBurst: number;
  region?: string;
  /**
   * Machine kind, stamped onto each created machine as the `SCAN_TYPE` env var.
   * The worker intersects its supported job types with `SCAN_TYPE` so an
   * extraction-shaped (64GB) machine never claims a small dast job and a
   * dast-shaped (16GB) machine never claims a 64GB extraction job (OOM). It
   * also lets the fleet dispatcher count only extraction machines on the
   * shared `deptex-depscanner` app, and lets the legacy `startFlyMachine`
   * burst check count only its own kind. See the scalable-extraction-infra plan.
   */
  scanType: 'extraction' | 'dast' | 'fix';
}

/** A Fly machine create-error caused by API rate limiting (HTTP 429). */
export class FlyRateLimitError extends Error {
  constructor(message: string) {
    super(`429 ${message}`);
    this.name = 'FlyRateLimitError';
  }
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
  scanType: 'extraction',
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
      scanType: 'dast',
    };
  }
  // 'unknown' or 'spa' → performance-4x 16GB.
  return {
    app: depscannerApp(),
    guest: { cpus: 4, memory_mb: 16384, cpu_kind: 'performance' },
    maxBurst: DAST_MAX_BURST,
    scanType: 'dast',
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
  scanType: 'fix',
};

export interface FlyMachine {
  id: string;
  name: string;
  state: string;
  region: string;
  created_at?: string;
  config?: Record<string, unknown>;
}

/** Fly machine states that consume resources / count as "exists and running". */
export const ACTIVE_MACHINE_STATES = ['created', 'starting', 'started', 'replacing'];

/**
 * Read the `SCAN_TYPE` env stamped on a machine at create time. Returns null for
 * untagged machines (legacy / test fixtures created before SCAN_TYPE tagging).
 */
export function machineScanType(m: FlyMachine): string | null {
  const env = (m.config as { env?: Record<string, unknown> } | undefined)?.env;
  const t = env?.SCAN_TYPE;
  return typeof t === 'string' && t ? t : null;
}

/**
 * Whether a machine belongs to a given scan kind. Untagged machines match any
 * kind (back-compat: pre-tagging machines + unit-test fixtures). Real machines
 * created after this change are always tagged, so kinds are fully separated in
 * practice.
 */
export function machineMatchesScanType(m: FlyMachine, scanType: string): boolean {
  const t = machineScanType(m);
  return t === null || t === scanType;
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

export async function listMachines(app: string): Promise<FlyMachine[]> {
  const res = await flyFetch(app, '/machines');
  if (!res.ok) {
    throw new Error(`Failed to list machines: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<FlyMachine[]>;
}

export async function startMachine(app: string, machineId: string): Promise<void> {
  const res = await flyFetch(app, `/machines/${machineId}/start`, { method: 'POST' });
  if (!res.ok) {
    const text = await res.text();
    if (res.status === 429) throw new FlyRateLimitError(`start ${machineId}: ${text}`);
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
        // Stamp the machine kind so the worker only claims matching job types
        // and the dispatcher / legacy burst-count only count their own kind.
        env: { SCAN_TYPE: config.scanType },
      },
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    if (res.status === 429) throw new FlyRateLimitError(`create burst machine: ${text}`);
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
      const allMachines = await listMachines(config.app);
      // Only count/reuse machines of THIS kind. Extraction and dast share the
      // `deptex-depscanner` app; without this filter a busy extraction fleet
      // would make dast see "at burst limit" and starve, and vice-versa.
      const machines = allMachines.filter((m) => machineMatchesScanType(m, config.scanType));
      const stopped = machines.filter((m) => m.state === 'stopped');

      // Resolve the image from ANY existing machine on the app — extraction and
      // dast share one Fly app and one deployed release, so the digest is
      // identical across kinds. Scanning only the kind-filtered list would let a
      // dast burst (usually 0 dast machines on an extraction-flooded app) fall
      // back to `:latest`, which may not exist. Kind filtering stays for the
      // burst COUNT + stopped-pool reuse below, not image resolution.
      let resolvedImage: string | null = null;
      for (const m of allMachines) {
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
// Still used by recovery.ts as a redundant provision fallback; the primary
// extraction provisioning path is now the fleet dispatcher (createDepscannerBurst).
export const startExtractionMachine = startDepscannerMachine;
export const startDastMachine = (detectedRuntime: DetectedRuntime = 'unknown') =>
  startFlyMachine(getDastMachineConfig(detectedRuntime));
export const startFixMachine = () => startFlyMachine(FIX_CONFIG);

/**
 * Resolve the image a depscanner burst machine should boot. Resolution order:
 *   1. FLY_DEPSCANNER_IMAGE env — an EXPLICIT pin. Set this only to force a
 *      specific image (e.g. a deliberate worker rollback). Leave it UNSET for
 *      normal operation — a stale pin would boot stale code on every burst.
 *   2. The image of any existing machine on the app (running OR stopped). The
 *      app's persistent machine carries the current deployed release after every
 *      `flyctl deploy`, so this tracks deploys automatically — no manual re-pin.
 *   3. Throw — a true cold start with nothing deployed and no pin. Deploy the
 *      depscanner worker first so we never gamble on a possibly-absent `:latest`.
 *
 * Pass `machines` (e.g. the dispatcher's per-tick `listMachines` result) to skip
 * a redundant API round-trip; omit it and we fetch the list ourselves.
 */
export async function resolveDepscannerImage(machines?: FlyMachine[]): Promise<string> {
  const pinned = process.env.FLY_DEPSCANNER_IMAGE?.trim();
  if (pinned) return pinned;

  const list = machines ?? (await listMachines(DEPSCANNER_CONFIG.app));
  for (const m of list) {
    const img = getImageFromMachine(m);
    if (img) return img;
  }

  throw new Error(
    `Cannot resolve a depscanner image: FLY_DEPSCANNER_IMAGE is unset and no machine on ` +
      `${DEPSCANNER_CONFIG.app} carries an image. Deploy the depscanner worker first ` +
      `(flyctl deploy -a ${DEPSCANNER_CONFIG.app}), or set FLY_DEPSCANNER_IMAGE to a release digest.`,
  );
}

/**
 * Create ONE extraction burst machine for the dispatcher: `SCAN_TYPE=extraction`,
 * `auto_destroy`. The image is auto-resolved from the live deployment (see
 * resolveDepscannerImage) unless `imageOverride` is passed — the dispatcher
 * resolves it once per tick and passes it here to avoid re-listing per machine.
 * Throws FlyRateLimitError on 429 (the dispatcher stops the tick); retries once
 * on other transient errors. The dispatcher owns the MAX_FLEET accounting, so
 * this does not consult the pool count — the caller decides how many to create.
 */
export async function createDepscannerBurst(imageOverride?: string): Promise<string> {
  const image = imageOverride ?? (await resolveDepscannerImage());
  let lastErr: unknown;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      return await createBurstMachine(DEPSCANNER_CONFIG, image);
    } catch (e) {
      if (e instanceof FlyRateLimitError) throw e; // do not retry a 429
      lastErr = e;
      if (attempt < 2) await sleep(1000);
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}
