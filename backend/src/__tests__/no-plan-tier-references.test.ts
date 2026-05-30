// CI grep guard against legacy 4-tier subscription identifiers.
//
// The prepaid billing rewrite retired the 4-tier plan model: per-plan limits,
// the `organization_plans` table, the Stripe subscription layer, and the Redis
// AI cost cap are all gone. This guard fails CI if any of those identifiers
// reappear in src/ — they are hard regressions.
//
// Historical note: while the removal was in flight these were split into an
// always-enforced list plus a SKIP_TIER_CLEANUP_GUARD-gated "cleanup pending"
// list. The cleanup has landed, so everything below is now always enforced and
// the env-var gate is gone.

import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '../../..');
const BACKEND_SRC = path.resolve(__dirname, '..');
const FRONTEND_SRC = path.resolve(REPO_ROOT, 'frontend/src');

// Identifiers that must NEVER appear in src/. Any hit is a regression.
const FORBIDDEN: string[] = [
  // Tables / SQL functions retired with the prepaid rewrite
  'organization_plans',
  'increment_sync_usage',
  'decrement_sync_usage',
  'stripe_webhook_events',
  // 4-tier plan-limit lib (deleted)
  'PLAN_LIMITS',
  'PLAN_FEATURES',
  'TIER_MAP',
  'TIER_DISPLAY_NAMES',
  'checkPlanLimit',
  'checkPlanFeature',
  'checkDowngradeAllowed',
  'requirePlanLimit',
  'requirePlanFeature',
  'getOrgPlan',
  'getUsageSummary',
  'getFeatureAccess',
  'invalidatePlanCache',
  'checkBillingPermission',
  // Legacy Redis AI cost cap (deleted; the prepaid ledger replaced it)
  'recordActualCost',
  'checkMonthlyCostCap',
  // Frontend 4-tier shims (deleted)
  'usePlanGate',
  'usePlanLimit',
  'planTiers',
  'TIER_DISPLAY',
  'FEATURE_REQUIRED_TIER',
  // Stripe subscription price IDs (the prepaid model has no tiers)
  'STRIPE_PRO_MONTHLY_PRICE_ID',
  'STRIPE_PRO_ANNUAL_PRICE_ID',
  'STRIPE_TEAM_MONTHLY_PRICE_ID',
  'STRIPE_TEAM_ANNUAL_PRICE_ID',
  'VITE_STRIPE_PRO_MONTHLY_PRICE_ID',
  'VITE_STRIPE_PRO_ANNUAL_PRICE_ID',
  'VITE_STRIPE_TEAM_MONTHLY_PRICE_ID',
  'VITE_STRIPE_TEAM_ANNUAL_PRICE_ID',
];

// Only this guard file may legitimately contain the identifiers (as the string
// literals above).
const EXCLUDED_FILES = new Set<string>([
  path.resolve(__dirname, 'no-plan-tier-references.test.ts'),
]);

function isExcluded(file: string): boolean {
  if (EXCLUDED_FILES.has(file)) return true;
  if (file.includes('node_modules')) return true;
  if (file.endsWith('.d.ts')) return true;
  return false;
}

function walk(dir: string, out: string[] = []): string[] {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (entry.isFile() && (full.endsWith('.ts') || full.endsWith('.tsx'))) {
      if (!isExcluded(full)) out.push(full);
    }
  }
  return out;
}

function findMatches(identifiers: string[], roots: string[]): Record<string, string[]> {
  const matches: Record<string, string[]> = {};
  const files = roots.flatMap((r) => walk(r));
  for (const id of identifiers) {
    const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`\\b${escaped}\\b`);
    const hits: string[] = [];
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf-8');
      if (re.test(content)) hits.push(path.relative(REPO_ROOT, file));
    }
    if (hits.length > 0) matches[id] = hits;
  }
  return matches;
}

describe('no plan-tier references (CI grep guard)', () => {
  test('legacy 4-tier identifiers never appear in src/', () => {
    const hits = findMatches(FORBIDDEN, [BACKEND_SRC, FRONTEND_SRC]);
    if (Object.keys(hits).length > 0) {
      const formatted = Object.entries(hits)
        .map(([id, files]) => `  ${id}: ${files.length} file(s)\n${files.map((f) => `    - ${f}`).join('\n')}`)
        .join('\n');
      throw new Error(`Forbidden plan-tier identifiers leaked into src/:\n${formatted}`);
    }
  });
});
