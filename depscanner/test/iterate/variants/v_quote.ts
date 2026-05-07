/**
 * Deterministic post-processor variant: same prompt as v_base, but after the
 * AI returns its rule_yaml, walk every `pattern:` line and force single-quote
 * around the value if it contains any of `{}[]:,&*?!|>` or the Semgrep
 * ellipsis `...`. Fixes the dominant deepseek/gemini schema-fail pattern
 * (unquoted YAML flow-mapping in a pattern scalar) deterministically — no
 * prompt-following required.
 *
 * Scope: only `pattern:` keys are rewritten. `message:` and other scalars are
 * left alone (they're rarer pain points and YAML's folded/literal styles are
 * trickier to preserve safely).
 */

import { buildGenerationPrompt as base } from '../../../src/rule-generator/prompt-builder';
import type { BuildPromptArgs } from '../../../src/rule-generator/prompt-builder';
import type { GeneratedPayload } from '../../../src/rule-generator/generate';

export const NAME = 'v_quote';
export const VERSION = 'quote-v1';

export function buildGenerationPrompt(args: BuildPromptArgs): string {
  return base(args);
}

const NEEDS_QUOTING = /[\{\}\[\]:,&*?!|>]|\.\.\./;

function quotePatternValue(raw: string): string {
  const trimmed = raw.trimEnd();
  if (trimmed.length === 0) return raw;
  // Already quoted (single or double) — leave alone.
  const first = trimmed[0];
  const last = trimmed[trimmed.length - 1];
  if ((first === "'" && last === "'") || (first === '"' && last === '"')) return raw;
  if (!NEEDS_QUOTING.test(trimmed)) return raw;
  // Single-quote it. Inner single quotes are escaped as '' in YAML single-quoted scalars.
  const inner = trimmed.replace(/'/g, "''");
  // Preserve original trailing whitespace (rare but happens).
  const trailingWs = raw.slice(trimmed.length);
  return `'${inner}'${trailingWs}`;
}

/**
 * Walk YAML text line-by-line. For every line matching `^(\s*)(- )?pattern:\s+(value)$`
 * where value isn't a block-scalar marker (|, >, |-, >-, etc.) and isn't
 * already quoted and contains characters YAML treats specially — single-quote
 * the value. Multi-line block scalars are left alone (they're already valid).
 */
function quotePatternsInYaml(yamlText: string): string {
  const lines = yamlText.split(/\r?\n/);
  const out: string[] = [];
  // Match inline scalar form. Block scalar lines (next line is the body) end
  // in `|` or `>` and are skipped — leaving them alone is safer than trying
  // to reformat the indented body.
  const re = /^(\s*-?\s*pattern\s*:\s+)([^\r\n]*)$/;
  for (const line of lines) {
    const m = line.match(re);
    if (!m) { out.push(line); continue; }
    const head = m[1];
    let value = m[2];
    // Skip empty / block-scalar markers; leave the line as-is.
    const t = value.trim();
    if (t === '' || t === '|' || t === '>' || t === '|-' || t === '>-' || t === '|+' || t === '>+') {
      out.push(line);
      continue;
    }
    // Strip a trailing inline comment (e.g. `pattern: foo  # note`) before
    // quoting; preserve it after the quoted value.
    let comment = '';
    const ci = findInlineCommentStart(value);
    if (ci >= 0) {
      comment = value.slice(ci);
      value = value.slice(0, ci).trimEnd();
    }
    const quoted = quotePatternValue(value);
    out.push(`${head}${quoted}${comment ? '  ' + comment : ''}`);
  }
  return out.join('\n');
}

function findInlineCommentStart(s: string): number {
  // Honor quote state — `#` inside a quoted scalar isn't a comment.
  let inS = false, inD = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "'" && !inD) inS = !inS;
    else if (ch === '"' && !inS) inD = !inD;
    else if (ch === '#' && !inS && !inD) {
      // Comment starts only if preceded by whitespace (or at start).
      if (i === 0 || /\s/.test(s[i - 1])) return i;
    }
  }
  return -1;
}

export function postProcessPayload(payload: GeneratedPayload): GeneratedPayload {
  return {
    ...payload,
    rule_yaml: quotePatternsInYaml(payload.rule_yaml),
  };
}
