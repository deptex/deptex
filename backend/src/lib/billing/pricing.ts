// Fly.io machine pricing (USD per second). Source: https://fly.io/docs/about/pricing/
// Verified 2026-05-22. Refresh when adding new machine sizes or when Fly updates pricing.
//
// Note: rates are per-second, derived from Fly's published per-second pricing.
// shared-cpu-1x  = $0.0000022 / sec  (~$0.0067/hr)
// shared-cpu-2x  = $0.0000044 / sec
// shared-cpu-4x  = $0.0000087 / sec
// shared-cpu-8x  = $0.0000174 / sec
// performance-1x = $0.0000087 / sec
// performance-2x = $0.0000174 / sec
// performance-4x = $0.0000348 / sec
// performance-8x = $0.0000695 / sec
//
// All include RAM cost embedded; Fly's pricing page breaks them out but we
// charge a single rate per machine size for simplicity.

const MACHINE_RATE_USD_PER_SECOND: Record<string, number> = {
  'shared-cpu-1x':  0.0000022,
  'shared-cpu-2x':  0.0000044,
  'shared-cpu-4x':  0.0000087,
  'shared-cpu-8x':  0.0000174,
  'performance-1x': 0.0000087,
  'performance-2x': 0.0000174,
  'performance-4x': 0.0000348,
  'performance-8x': 0.0000695,
  'perf-2x':        0.0000174,  // legacy alias
  'perf-4x':        0.0000348,
  'perf-8x':        0.0000695,
};

const DEFAULT_RATE_USD_PER_SECOND = 0.0000087; // performance-1x

const MARKUP_FACTOR = 2;

export interface WorkerCost {
  cogCents: number;
  chargedCents: number;
}

export function chargedCentsForWorker(machineSize: string, seconds: number): WorkerCost {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return { cogCents: 0, chargedCents: 0 };
  }
  const rate = MACHINE_RATE_USD_PER_SECOND[machineSize] ?? DEFAULT_RATE_USD_PER_SECOND;
  const cogDollars = rate * seconds;
  const cogCents = cogDollars * 100;
  const chargedCents = cogCents * MARKUP_FACTOR;
  return { cogCents, chargedCents };
}

export function getMachineRateUsdPerSecond(machineSize: string): number {
  return MACHINE_RATE_USD_PER_SECOND[machineSize] ?? DEFAULT_RATE_USD_PER_SECOND;
}
