/**
 * Build a "stacked" variant by composing the prompt mods of multiple winners.
 *
 * The naive approach (textually merging multiple prompt-builders) is brittle;
 * instead we do composition at the runtime level:
 *
 *   1. Start with v_base's output.
 *   2. For each named overlay, apply a known mod to the prompt string.
 *      - 'meta'     : reframe option (a) around metavars (mirrors v_meta)
 *      - 'grammar'  : append the Semgrep pattern grammar block (mirrors v_grammar)
 *      - 'audit'    : insert sink_metavar_audit JSON field directive
 *      - 'cot'      : prepend structured-CoT planning fields directive
 *      - 'negfew'   : insert the safe_fixture trap example
 *      - 'instance' : append factory/aliasing constraint
 *      - 'quote'    : (post-processor — applied at validate time, not prompt)
 *
 *   3. Optionally export postProcessPayload that runs the quote-fixer.
 *
 * Each overlay is a self-contained string-edit. Order matters — later
 * overlays see earlier overlays' output.
 *
 * Usage from CLI:
 *   npm run iterate -- --variant=stack --stack-overlays=meta,grammar,quote
 *
 * stack.ts uses an env-var override (DEPTEX_STACK_OVERLAYS) to pick overlays
 * because the variant interface doesn't accept extra args. cli.ts and
 * tournament.ts can set the env before importing this module.
 */

import { buildGenerationPrompt as base } from '../../../src/rule-generator/prompt-builder';
import type { BuildPromptArgs } from '../../../src/rule-generator/prompt-builder';
import type { GeneratedPayload } from '../../../src/rule-generator/generate';
import { postProcessPayload as quotePostProcess } from './v_quote';

// Re-stating the overlay text inline keeps stack.ts self-contained — no
// regex-fragile string-pattern matching against the production prompt.
// If a v_X variant's strategy gets revised, we mirror the change here.

const META_REFRAME = `

# CRITICAL — metavar-aware safe_fixture pinning
Your safe_fixture must be safe for the SEMGREP TAINT ENGINE, not just for a human reader. Walk through your sink pattern and write down EVERY \`$VAR\` metavariable. For EACH ONE, the corresponding expression in your safe_fixture MUST be a static literal (string, number, hard-coded const, or a value derived only from constants — NOT anything traceable to \`req.*\` / \`process.*\` / \`process.env\`).
Concrete: if your sink is \`minimatch($PATH, $PATTERN, ...)\`, the safe_fixture MUST hard-code BOTH \`$PATH\` AND \`$PATTERN\`. Pinning only \`$PATTERN\` is NOT safe — \`$PATH\` will still bind to \`req.body.path\` and the rule will fire on what you thought was a safe fixture. This is the #1 reason generated rules fail validation.`;

const GRAMMAR_BLOCK = `

# Semgrep pattern grammar (most common cause of accepted-YAML-but-broken-rule)
Semgrep has its own pattern syntax that goes beyond YAML. Three illegal patterns to avoid:

1) \`focus-metavariable\` MUST be a sibling of the patterns it focuses on, inside the same \`patterns:\` block. NEVER place it as a sibling of \`pattern-either\`.
\`\`\`yaml
# WRONG
pattern-sinks:
  - pattern-either:
      - pattern: 'nanoid($SIZE)'
  - focus-metavariable: $SIZE      # WRONG: sibling of pattern-either

# RIGHT
pattern-sinks:
  - patterns:
      - pattern-either:
          - pattern: 'nanoid($SIZE)'
      - focus-metavariable: $SIZE
\`\`\`

2) \`pattern-not\` takes ONE pattern, not a list. Wrap alternatives in \`pattern-either\` first:
\`\`\`yaml
# WRONG
- pattern-not:
    - pattern: foo($A)
    - pattern: bar($A)

# RIGHT
- pattern-not:
    pattern-either:
      - pattern: foo($A)
      - pattern: bar($A)
\`\`\`

3) Option-bag attribute syntax DOES NOT EXIST. To assert that an options object has a key set, use \`metavariable-pattern\` against the option metavar, not a fictional \`'$OPTIONS.attr: true'\` string:
\`\`\`yaml
# WRONG (no such Semgrep syntax)
- pattern: '$OPTIONS.allowInvalidAsymmetricKeyTypes: true'

# RIGHT
- patterns:
    - pattern: jwt.verify($T, $K, $OPTS)
    - metavariable-pattern:
        metavariable: $OPTS
        pattern: '{ ..., allowInvalidAsymmetricKeyTypes: true, ... }'
\`\`\`

Fields that do NOT exist: \`pattern-include\`, \`pattern-not-include\`, list-valued \`pattern-not\`, list-valued \`pattern-not-inside\`. Do not invent them.`;

const AUDIT_DIRECTIVE = `

# Sink metavar audit (REQUIRED before writing rule_yaml + safe_fixture)
Add a \`sink_metavar_audit\` field as the FIRST field of your output JSON. Enumerate every \`$VAR\` that appears in your \`pattern-sinks\` and state what it binds to in your safe_fixture. EVERY entry must have \`is_static_literal: true\`. If you can't make a metavar bind to a literal, your rule design is wrong — narrow the sink shape or split into multiple rules.
\`\`\`
{
  "sink_metavar_audit": [
    {"metavar": "$URL", "binds_in_safe_fixture_to": "the literal 'https://example.com/static'", "is_static_literal": true},
    {"metavar": "$HEADERS", "binds_in_safe_fixture_to": "STATIC_HEADERS const literal", "is_static_literal": true}
  ],
  "rule_yaml": "...",
  ...
}
\`\`\``;

const COT_PREFACE = `

# Structured analysis BEFORE rule authoring
Add the following planning fields as the FIRST entries of your output JSON. They force you to commit to a sink shape, source set, and sanitization strategy before authoring — dramatically reduces "rule doesn't match its own fixture" errors:
\`\`\`
{
  "patch_analysis": "<2-3 sentences: what behavior is the upstream patch fixing? Where in the source-to-sink data flow is the fix?>",
  "sink_shape": "<the EXACT call shape Semgrep should match>",
  "source_shape": "<what untrusted input must reach the sink>",
  "sanitization_strategy": "<'static_literal' (preferred) | 'named_sanitizer' (only when literal impossible)>",
  "vulnerable_fixture_plan": "<2 sentences: name the variables that hold tainted source, name the line where source flows into sink>",
  "safe_fixture_plan": "<2 sentences: name what each sink metavar binds to in your safe fixture; confirm none binds to req.*>",
  "rule_yaml": "...",
  "vulnerable_fixture": "...",
  "safe_fixture": "...",
  ...
}
\`\`\``;

const NEGFEW_TRAP = `

# Common safe_fixture TRAP (study this — #1 reason rules fail validation)
Below is a safe_fixture that LOOKS correct but actually triggers the rule.

Rule:
\`\`\`yaml
rules:
  - id: deptex.minimatch.redos
    languages: [javascript]
    severity: ERROR
    message: minimatch ReDoS via untrusted pattern
    mode: taint
    pattern-sources:
      - pattern: $REQ.body
      - pattern: $REQ.query
    pattern-sinks:
      - pattern: 'minimatch($PATH, $PATTERN, ...)'
\`\`\`

Looks-safe-but-fires fixture:
\`\`\`js
const filePath = req.body.path;       // tainted
const pattern = '*.js';                // literal — pinned, looks safe
minimatch(filePath, pattern);          // BOOM: $PATH binds to req.body.path
\`\`\`

Why it fails: Semgrep taint mode binds the source to ANY metavar in the sink. Pinning \`$PATTERN\` to a literal does not save you when \`$PATH\` still binds to taint.

Correct version:
\`\`\`js
const filePath = 'src/main.js';        // literal
const pattern = '*.js';                 // literal
minimatch(filePath, pattern);           // does NOT fire
\`\`\``;

const INSTANCE_BLOCK = `

# Factory / instance aliasing
When the package exposes a factory (\`axios.create\`, \`new Client(...)\`, \`pg.Pool(...)\`, \`redis.createClient\`, \`mongoose.createConnection\`, \`nodemailer.createTransport\`), your \`pattern-sinks\` MUST include BOTH the direct form AND the \`$INSTANCE.method(...)\` form. Real apps almost always alias.
\`\`\`yaml
pattern-sinks:
  - pattern: 'axios.get($URL, ...)'
  - pattern: 'axios.$METHOD($URL, ...)'
  - pattern: '$INSTANCE.get($URL, ...)'
  - pattern: '$INSTANCE.$METHOD($URL, ...)'
\`\`\`

When using \`...\` after a comma to match remaining args, ALSO include the no-trailing-args form:
\`\`\`yaml
pattern-either:
  - pattern: 'axios.get($URL)'
  - pattern: 'axios.get($URL, ...)'
\`\`\``;

type OverlayKey = 'meta' | 'grammar' | 'audit' | 'cot' | 'negfew' | 'instance' | 'quote';

function appendOverlay(prompt: string, key: OverlayKey): string {
  switch (key) {
    case 'meta': return prompt + META_REFRAME;
    case 'grammar': return prompt + GRAMMAR_BLOCK;
    case 'audit': return prompt + AUDIT_DIRECTIVE;
    case 'cot': return prompt + COT_PREFACE;
    case 'negfew': return prompt + NEGFEW_TRAP;
    case 'instance': return prompt + INSTANCE_BLOCK;
    case 'quote': return prompt; // post-processor only
  }
}

export const NAME = 'stack';
export const VERSION = `stack-${(process.env.DEPTEX_STACK_OVERLAYS ?? 'meta+grammar').replace(/,/g, '+')}`;

export function buildGenerationPrompt(args: BuildPromptArgs): string {
  const overlays = (process.env.DEPTEX_STACK_OVERLAYS ?? 'meta,grammar')
    .split(',').map((s) => s.trim()).filter(Boolean) as OverlayKey[];
  let prompt = base(args);
  for (const k of overlays) prompt = appendOverlay(prompt, k);
  return prompt;
}

export function postProcessPayload(payload: GeneratedPayload): GeneratedPayload {
  const overlays = (process.env.DEPTEX_STACK_OVERLAYS ?? '').split(',').map((s) => s.trim());
  if (overlays.includes('quote')) return quotePostProcess(payload);
  return payload;
}
