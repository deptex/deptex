/**
 * Unit tests for detector-flows.ts — the Flow-coercion layer that maps the
 * three non-taint detector regimes (sanitizer-absence / insecure-default /
 * regex-literal) into single-hop `Flow` records so they round-trip through the
 * same `project_reachable_flows` storage + FP-filter as taint flows.
 *
 * Asserts, per coercion:
 *   - the deterministic id (sha1(`tag|file:line:col|pattern`).slice(0,16))
 *   - the fixed sub-threshold engine_confidence (0.65)
 *   - the single-hop shape (entry == sink, one 'sink' flow node, flow_length 1)
 *   - vuln_class / taint_kind / osv_id passthrough + precedence
 *
 * Run: npx tsx test/taint-engine-detector-flows.test.ts
 */

import { createHash } from 'crypto';
import {
  sanitizerAbsenceToFlow,
  insecureDefaultToFlow,
  regexLiteralToFlow,
} from '../src/taint-engine/detector-flows';
import type { NonTaintFinding } from '../src/taint-engine/non-taint-detector';
import type { InsecureDefaultFinding } from '../src/taint-engine/insecure-default-detector';
import type { RegexLiteralFinding } from '../src/taint-engine/regex-literal-detector';

let failures = 0;
let passes = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
    passes++;
  }
}

/** Mirror of detector-flows.ts#hashFlowId — the test recomputes it
 *  independently so a change to the id derivation is caught, not masked. */
function expectedId(tag: string, filePath: string, line: number, column: number, pattern: string): string {
  return createHash('sha1')
    .update(`${tag}|${filePath}:${line}:${column}|${pattern}`)
    .digest('hex')
    .slice(0, 16);
}

const DETECTOR_CONFIDENCE = 0.65;

/** Assert the invariants every detector Flow must satisfy: single-hop shape,
 *  sub-threshold confidence, entry == sink, exactly one 'sink' flow node. */
function assertSingleHopShape(flow: ReturnType<typeof regexLiteralToFlow>, label: string): void {
  assert(flow.flow_length === 1, `${label}: flow_length === 1 (got ${flow.flow_length})`);
  assert(flow.flow_nodes.length === 1, `${label}: exactly one flow node (got ${flow.flow_nodes.length})`);
  assert(flow.flow_nodes[0]?.kind === 'sink', `${label}: the single node is a 'sink' node`);
  assert(flow.engine_confidence === DETECTOR_CONFIDENCE, `${label}: engine_confidence === ${DETECTOR_CONFIDENCE} (got ${flow.engine_confidence})`);
  assert(flow.taint_kind === 'http_input', `${label}: taint_kind placeholder is 'http_input'`);
  assert(flow.sink_is_external === false, `${label}: sink_is_external === false`);
  assert(
    flow.entry_point_file === flow.sink_file && flow.entry_point_line === flow.sink_line,
    `${label}: entry point collapses onto the sink location`,
  );
  assert(
    flow.flow_nodes[0]?.filePath === flow.sink_file && flow.flow_nodes[0]?.line === flow.sink_line,
    `${label}: the flow node sits at the sink coordinates`,
  );
}

// ---------- A. sanitizerAbsenceToFlow (Phase F4) ----------
console.log('\n[A] sanitizerAbsenceToFlow');

const sanFinding: NonTaintFinding = {
  id: 'ntd_abc',
  vuln_class: 'auth_bypass',
  sink_file: 'src/auth.ts',
  sink_line: 42,
  sink_column: 7,
  sink_method: 'jwt.verify',
  sink_pattern: 'jwt.verify(*)',
  trigger: { argument_name: 'algorithms', match_mode: 'required' },
  engine_confidence: 0.85,
  description: 'jwt.verify without an explicit algorithms allowlist',
};

const sanFlow = sanitizerAbsenceToFlow(sanFinding, 'jsonwebtoken', undefined);
assert(
  sanFlow.id === expectedId('san', 'src/auth.ts', 42, 7, 'jwt.verify(*)'),
  `id is sha1('san|file:line:col|pattern').slice(0,16) (got ${sanFlow.id})`,
);
assert(sanFlow.vuln_class === 'auth_bypass', 'vuln_class copied from finding');
assert(sanFlow.sink_method === 'jwt.verify', 'sink_method copied from finding');
assert(
  sanFlow.source_description.includes('jsonwebtoken') && sanFlow.source_description.includes('algorithms'),
  'source_description names the framework + the missing argument',
);
assert(sanFlow.sink_description === sanFinding.description, 'sink_description copied from finding');
assertSingleHopShape(sanFlow, 'sanitizerAbsence');

// osv_id precedence: explicit osvId wins; otherwise falls back to finding.osv_id.
assert(sanitizerAbsenceToFlow(sanFinding, 'jsonwebtoken', 'CVE-2022-23539').osv_id === 'CVE-2022-23539', 'explicit osvId wins');
assert(
  sanitizerAbsenceToFlow({ ...sanFinding, osv_id: 'CVE-FROM-FINDING' }, 'jsonwebtoken', undefined).osv_id === 'CVE-FROM-FINDING',
  'falls back to finding.osv_id when osvId arg is undefined',
);
assert(sanFlow.osv_id === undefined, 'osv_id undefined when neither source provides one');

// determinism + location-sensitivity of the id.
assert(
  sanitizerAbsenceToFlow(sanFinding, 'jsonwebtoken', undefined).id === sanFlow.id,
  'id is deterministic for identical inputs',
);
assert(
  sanitizerAbsenceToFlow({ ...sanFinding, sink_line: 43 }, 'jsonwebtoken', undefined).id !== sanFlow.id,
  'id changes when the sink line changes',
);

// ---------- B. insecureDefaultToFlow (Phase 3.3) ----------
console.log('\n[B] insecureDefaultToFlow');

const iddFinding: InsecureDefaultFinding = {
  id: 'idd_abc',
  framework: 'flask',
  vuln_class: 'weak_crypto',
  sink_file: 'app/views.py',
  sink_line: 10,
  sink_column: 4,
  sink_method: 'response.set_cookie',
  sink_pattern: 'response.set_cookie(*)',
  trigger: { argument_name: 'secure', observed_literal: 'False', reason: 'forbidden_value' },
  engine_confidence: 0.85,
  description: 'Flask response.set_cookie without secure=True',
};

const iddFlow = insecureDefaultToFlow(iddFinding, undefined);
assert(
  iddFlow.id === expectedId('idd', 'app/views.py', 10, 4, 'response.set_cookie(*)'),
  `id uses the 'idd' tag (got ${iddFlow.id})`,
);
assert(iddFlow.vuln_class === 'weak_crypto', 'vuln_class copied from finding');
assert(
  iddFlow.source_description.includes('flask') &&
    iddFlow.source_description.includes('forbidden_value') &&
    iddFlow.source_description.includes('secure') &&
    iddFlow.source_description.includes('False'),
  'source_description carries framework + reason + arg name + observed literal',
);
assertSingleHopShape(iddFlow, 'insecureDefault');
assert(insecureDefaultToFlow(iddFinding, 'CVE-2023-30861').osv_id === 'CVE-2023-30861', 'osvId threaded through');

// argLabel fallback: positional (no name) → `arg[N]`; neither → `arg`.
const iddPositional = insecureDefaultToFlow(
  { ...iddFinding, trigger: { argument_position: 3, reason: 'absent' } },
  undefined,
);
assert(iddPositional.source_description.includes('arg[3]'), 'positional-only trigger renders arg[3]');
const iddBare = insecureDefaultToFlow(
  { ...iddFinding, trigger: { reason: 'absent' } },
  undefined,
);
assert(/\barg\b/.test(iddBare.source_description), 'no name/position renders a bare "arg" label');

// ---------- C. regexLiteralToFlow (Phase 3.2) ----------
console.log('\n[C] regexLiteralToFlow');

const rgxFinding: RegexLiteralFinding = {
  filePath: 'node_modules/debug/src/index.js',
  line: 17,
  regex: '%[oOdisfc%]',
  description: 'debug coloring-format regex with catastrophic backtracking',
  framework: 'debug',
};

const rgxFlow = regexLiteralToFlow(rgxFinding, 'CVE-2017-16137');
assert(
  rgxFlow.id === expectedId('rgx', 'node_modules/debug/src/index.js', 17, 0, '%[oOdisfc%]'),
  `id uses the 'rgx' tag, column 0, and the regex as pattern (got ${rgxFlow.id})`,
);
assert(rgxFlow.vuln_class === 'redos', 'regex-literal flow is always redos');
assert(rgxFlow.sink_method === '%[oOdisfc%]', 'sink_method is the matched regex literal');
assert(rgxFlow.flow_nodes[0]?.column === 0, 'column is 0 (unavailable from the substring scan)');
assert(rgxFlow.osv_id === 'CVE-2017-16137', 'osvId threaded through');
assert(rgxFlow.source_description.includes('debug'), 'source_description names the framework');
assertSingleHopShape(rgxFlow, 'regexLiteral');

console.log(`\n=== ${passes} passed, ${failures} failed ===`);
if (failures > 0) process.exit(1);
