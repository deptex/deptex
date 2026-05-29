// CI grep guard against legacy 4-tier subscription identifiers.
//
// After M7 + M10 finish deleting the old tier-gating code, this test
// enforces that none of the listed identifiers reappear in src/. Until
// then, the cleanup-pending identifiers are gated behind
// SKIP_TIER_CLEANUP_GUARD so the partial cleanup doesn't break CI.
//
// To run the full guard locally: unset SKIP_TIER_CLEANUP_GUARD; jest.
// Once the worktree branch lands, drop the SKIP_TIER_CLEANUP_GUARD branch
// from .github/workflows/test.yml.

import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '../../..');
const BACKEND_SRC = path.resolve(__dirname, '..');
const FRONTEND_SRC = path.resolve(REPO_ROOT, 'frontend/src');

// Always-forbidden — these identifiers must NEVER appear in src/ after the
// billing PR lands. Anything in this list is a hard regression. Kept small
// so a fresh contributor reading a leaked identifier here knows it's a bug.
const ALWAYS_FORBIDDEN: string[] = [
  // Webhook events table retired in phase37 (no in-progress callsites at
  // M6; will catch any future reintroduction).
  'stripe_webhook_events',
  'decrement_sync_usage',
];

// Cleanup-pending — listed for the eventual grep guard; not enforced yet
// because the routes/libs that reference these die in M7 (Aegis + cost-cap)
// and M10 (tier-gating UI). Track these here so we have one obvious place
// to flip the guard on.
const CLEANUP_PENDING: string[] = [
  // Tables / SQL functions retired in phase37 — runtime broken until M7+M10
  'organization_plans',
  'increment_sync_usage',
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
  'recordActualCost',
  'checkMonthlyCostCap',
  'usePlanGate',
  'usePlanLimit',
  'planTiers',
  'TIER_DISPLAY',
  'FEATURE_REQUIRED_TIER',
  'STRIPE_PRO_MONTHLY_PRICE_ID',
  'STRIPE_PRO_ANNUAL_PRICE_ID',
  'STRIPE_TEAM_MONTHLY_PRICE_ID',
  'STRIPE_TEAM_ANNUAL_PRICE_ID',
  'VITE_STRIPE_PRO_MONTHLY_PRICE_ID',
  'VITE_STRIPE_PRO_ANNUAL_PRICE_ID',
  'VITE_STRIPE_TEAM_MONTHLY_PRICE_ID',
  'VITE_STRIPE_TEAM_ANNUAL_PRICE_ID',
];

// Files where these identifiers MAY legitimately appear during the
// cleanup window: the cleanup target itself, plus the guard test.
const EXCLUDED_FILES = new Set<string>([
  path.resolve(__dirname, 'no-plan-tier-references.test.ts'),
  path.resolve(BACKEND_SRC, 'lib/plan-limits.ts'),
  path.resolve(BACKEND_SRC, 'lib/stripe.ts'),
  path.resolve(BACKEND_SRC, 'lib/ai/cost-cap.ts'),
  path.resolve(BACKEND_SRC, 'lib/taint-engine/cost-cap.ts'),
]);

function isExcluded(file: string): boolean {
  if (EXCLUDED_FILES.has(file)) return true;
  if (file.includes('node_modules')) return true;
  if (file.includes('__tests__')) return false;
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
  test('always-forbidden identifiers never appear in src/', () => {
    const hits = findMatches(ALWAYS_FORBIDDEN, [BACKEND_SRC, FRONTEND_SRC]);
    if (Object.keys(hits).length > 0) {
      const formatted = Object.entries(hits)
        .map(([id, files]) => `  ${id}: ${files.length} file(s)\n${files.map((f) => `    - ${f}`).join('\n')}`)
        .join('\n');
      throw new Error(`Forbidden plan-tier identifiers leaked into src/:\n${formatted}`);
    }
  });

  const runCleanupGuard = !process.env.SKIP_TIER_CLEANUP_GUARD;
  (runCleanupGuard ? test : test.skip)(
    'cleanup-pending identifiers (enabled after M7 + M10)',
    () => {
      const hits = findMatches(CLEANUP_PENDING, [BACKEND_SRC, FRONTEND_SRC]);
      if (Object.keys(hits).length > 0) {
        const formatted = Object.entries(hits)
          .map(([id, files]) => `  ${id}: ${files.length} file(s)\n${files.map((f) => `    - ${f}`).join('\n')}`)
          .join('\n');
        throw new Error(`Tier-cleanup identifiers still present (M7/M10 incomplete):\n${formatted}`);
      }
    },
  );
});
