/**
 * Pin the default cost-cap constants to the values the migration installs as
 * column DEFAULTs. If the migration default changes (next phase) and the
 * constant doesn't, orgs without a settings row would silently see the old
 * fallback. This test fails loudly at that mismatch.
 *
 * The frontend mirror in `frontend/src/lib/taint-engine-defaults.ts` must
 * stay in sync with these values too — checked by `frontend-defaults-match`
 * which reads the frontend file as text (no build step in jest config).
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  DEFAULT_MONTHLY_AI_COST_CAP_USD,
  DEFAULT_GENERATOR_MONTHLY_BUDGET_USD,
  ALL_VULN_CLASSES,
} from '../lib/taint-engine-defaults';
import { ALL_VULN_CLASSES as ENGINE_VULN_CLASSES } from '../../depscanner/src/taint-engine/spec';

describe('taint-engine defaults', () => {
  test('DEFAULT_MONTHLY_AI_COST_CAP_USD matches phase27a migration DEFAULT (75)', () => {
    expect(DEFAULT_MONTHLY_AI_COST_CAP_USD).toBe(75);
    const sql = fs.readFileSync(
      path.resolve(__dirname, '../../database/phase27a_cve_targeted_taint.sql'),
      'utf8',
    );
    expect(sql).toMatch(/monthly_ai_cost_cap_usd\s+SET\s+DEFAULT\s+75\.00/);
  });

  test('DEFAULT_GENERATOR_MONTHLY_BUDGET_USD matches phase27a migration DEFAULT (30)', () => {
    expect(DEFAULT_GENERATOR_MONTHLY_BUDGET_USD).toBe(30);
    const sql = fs.readFileSync(
      path.resolve(__dirname, '../../database/phase27a_cve_targeted_taint.sql'),
      'utf8',
    );
    expect(sql).toMatch(/monthly_budget_usd\s+SET\s+DEFAULT\s+30\.00/);
  });

  test('frontend mirror has identical constant values', () => {
    const frontendSrc = fs.readFileSync(
      path.resolve(__dirname, '../../../frontend/src/lib/taint-engine-defaults.ts'),
      'utf8',
    );
    const capMatch = frontendSrc.match(/DEFAULT_MONTHLY_AI_COST_CAP_USD\s*=\s*(\d+)/);
    const budgetMatch = frontendSrc.match(/DEFAULT_GENERATOR_MONTHLY_BUDGET_USD\s*=\s*(\d+)/);
    expect(capMatch).not.toBeNull();
    expect(budgetMatch).not.toBeNull();
    expect(Number(capMatch![1])).toBe(DEFAULT_MONTHLY_AI_COST_CAP_USD);
    expect(Number(budgetMatch![1])).toBe(DEFAULT_GENERATOR_MONTHLY_BUDGET_USD);
  });

  test('ALL_VULN_CLASSES mirrors the engine constant byte-for-byte', () => {
    expect([...ALL_VULN_CLASSES]).toEqual([...ENGINE_VULN_CLASSES]);
  });

  test('frontend ALL_VULN_CLASSES mirror has identical entries in identical order', () => {
    const frontendSrc = fs.readFileSync(
      path.resolve(__dirname, '../../../frontend/src/lib/taint-engine-defaults.ts'),
      'utf8',
    );
    const arrayMatch = frontendSrc.match(/ALL_VULN_CLASSES[^=]*=\s*\[([\s\S]*?)\]/);
    expect(arrayMatch).not.toBeNull();
    const literalEntries = Array.from(arrayMatch![1].matchAll(/'([a-z_]+)'/g)).map((m) => m[1]);
    expect(literalEntries).toEqual([...ALL_VULN_CLASSES]);
  });

  test('phase26 migration vuln_classes_enabled CHECK list matches ALL_VULN_CLASSES', () => {
    // The taint_engine_settings.vuln_classes_enabled column was introduced
    // in phase26 with a CHECK that the array contains only the enum values.
    // Surface the migration text so a future expansion of the engine taxonomy
    // fails this test loudly.
    const sql = fs.readFileSync(
      path.resolve(__dirname, '../../database/phase26_taint_engine.sql'),
      'utf8',
    );
    for (const cls of ALL_VULN_CLASSES) {
      expect(sql).toContain(cls);
    }
  });
});
