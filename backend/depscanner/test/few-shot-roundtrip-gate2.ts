/**
 * Canonical Gate 2 round-trip test for the Phase 6.5 few-shot library
 * (PDA-4 / plan task 7).
 *
 * Iterates `FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES` and runs the Phase 6 cross-
 * file taint engine against each entry's vulnerable_fixture and safe_fixture.
 * Pass iff the spec emits ≥1 flow on vulnerable and 0 on safe. Exit code 1
 * on any failure so CI can gate the build.
 *
 * Why a tsx script and not jest: the per-language propagators load tree-
 * sitter WASM via dynamic `import()`, which jest's vm-isolate sandbox
 * refuses without --experimental-vm-modules. A tsx-driven script side-steps
 * the jest sandbox entirely. The jest test at
 * `backend/src/__tests__/few-shot-roundtrip.test.ts` covers Gate 1 (zod +
 * osv_id rejection) for every entry plus Gate 2 for the JS subset (TS
 * Compiler API path); this script is the all-language Gate 2.
 *
 * Run: cd backend/depscanner && npm run test:few-shot-gate2
 */

import { FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES } from '../src/rule-generator/few-shot-examples';
import { validateRule, makeRuleGenWorkdir } from '../src/rule-generator/validate';

async function main() {
  const workDir = makeRuleGenWorkdir();
  let passed = 0;
  let failed = 0;
  for (const ex of FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES) {
    const result = await validateRule({
      payload: ex.payload,
      cveId: ex.cveId,
      ecosystem: ex.ecosystem,
      workDir,
      runPatchValidation: false,
    });
    const log = result.log;
    const verdict = result.status === 'validated' ? 'PASS' : 'FAIL';
    console.log(
      `${verdict}  ${ex.cveId.padEnd(18)} ${ex.packageName.padEnd(22)} ${ex.ecosystem.padEnd(10)} pre=${log.fixture_pre_matches} post=${log.fixture_post_matches} took=${log.took_ms}ms`,
    );
    if (result.status !== 'validated') {
      console.log(`     errors: ${log.errors.join(' | ')}`);
      failed++;
    } else {
      passed++;
    }
  }
  console.log(`\n${passed}/${passed + failed} few-shot examples round-tripped`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
