/**
 * Load and validate a FrameworkSpec from YAML.
 *
 * Hand-rolled validator instead of zod / ajv to avoid pulling a new dep into
 * extraction-worker. Errors are thrown with a single readable message that
 * names the file path + the offending field — sufficient for spec-author
 * debugging during M3 (hand-written models) and M6 (AI-inferred models).
 */

import * as fs from 'fs';
import * as yaml from 'js-yaml';
import {
  ALL_VULN_CLASSES,
  type FrameworkSanitizer,
  type FrameworkSink,
  type FrameworkSource,
  type FrameworkSpec,
  type TaintKind,
  type VulnClass,
} from './spec';

export class SpecValidationError extends Error {
  constructor(message: string, public readonly fieldPath: string, public readonly source?: string) {
    super(`${message}${source ? ` (${source})` : ''} at ${fieldPath}`);
    this.name = 'SpecValidationError';
  }
}

const TAINT_KINDS: readonly TaintKind[] = ['http_input', 'env', 'file', 'cli', 'rpc'];
const VULN_CLASS_SET = new Set<string>(ALL_VULN_CLASSES);
const TAINT_KIND_SET = new Set<string>(TAINT_KINDS);

export function loadSpec(yamlPath: string): FrameworkSpec {
  let raw: string;
  try {
    raw = fs.readFileSync(yamlPath, 'utf8');
  } catch (err) {
    throw new SpecValidationError(`failed to read spec file: ${(err as Error).message}`, '<file>', yamlPath);
  }
  let parsed: unknown;
  try {
    parsed = yaml.load(raw);
  } catch (err) {
    throw new SpecValidationError(`YAML parse error: ${(err as Error).message}`, '<root>', yamlPath);
  }
  return validateSpec(parsed, yamlPath);
}

/**
 * Phase 6.5 — load a FrameworkSpec from an already-parsed JSON object (the
 * `framework_spec` JSONB column of `organization_generated_rules`). Reuses
 * the same hand-rolled validator as the YAML path so cve-targeted specs
 * pass the same shape checks as bundled framework models. The optional
 * `source` label appears in error messages so a malformed CVE-row points
 * at the offending CVE id rather than `<root>`.
 */
export function loadSpecFromJson(json: unknown, source?: string): FrameworkSpec {
  return validateSpec(json, source);
}

export function validateSpec(input: unknown, source?: string): FrameworkSpec {
  if (!isObject(input)) {
    throw new SpecValidationError('spec root must be an object', '$', source);
  }
  const framework = expectString(input, 'framework', '$.framework', source);
  const version = expectString(input, 'version', '$.version', source);
  const rawLanguage = (input as Record<string, unknown>).language;
  let language: FrameworkSpec['language'];
  if (rawLanguage !== undefined) {
    if (
      typeof rawLanguage !== 'string' ||
      !['js', 'python', 'java', 'go', 'ruby', 'php', 'rust', 'csharp'].includes(rawLanguage)
    ) {
      throw new SpecValidationError(
        `language must be one of js|python|java|go|ruby|php|rust|csharp, got ${JSON.stringify(rawLanguage)}`,
        '$.language',
        source,
      );
    }
    language = rawLanguage as FrameworkSpec['language'];
  }
  const sources = expectArray(input, 'sources', '$.sources', source).map((s, i) =>
    validateSource(s, `$.sources[${i}]`, source),
  );
  const sinks = expectArray(input, 'sinks', '$.sinks', source).map((s, i) =>
    validateSink(s, `$.sinks[${i}]`, source),
  );
  const sanitizers = expectArray(input, 'sanitizers', '$.sanitizers', source).map((s, i) =>
    validateSanitizer(s, `$.sanitizers[${i}]`, source),
  );
  return { framework, version, language, sources, sinks, sanitizers };
}

function validateSource(input: unknown, fieldPath: string, source?: string): FrameworkSource {
  if (!isObject(input)) throw new SpecValidationError('source must be an object', fieldPath, source);
  const pattern = expectString(input, 'pattern', `${fieldPath}.pattern`, source);
  const taint_kind = expectString(input, 'taint_kind', `${fieldPath}.taint_kind`, source);
  if (!TAINT_KIND_SET.has(taint_kind)) {
    throw new SpecValidationError(
      `taint_kind must be one of ${TAINT_KINDS.join('|')}, got "${taint_kind}"`,
      `${fieldPath}.taint_kind`,
      source,
    );
  }
  const description = expectString(input, 'description', `${fieldPath}.description`, source);
  return { pattern, taint_kind: taint_kind as TaintKind, description };
}

function validateSink(input: unknown, fieldPath: string, source?: string): FrameworkSink {
  if (!isObject(input)) throw new SpecValidationError('sink must be an object', fieldPath, source);
  const pattern = expectString(input, 'pattern', `${fieldPath}.pattern`, source);
  const vuln_class = expectString(input, 'vuln_class', `${fieldPath}.vuln_class`, source);
  if (!VULN_CLASS_SET.has(vuln_class)) {
    throw new SpecValidationError(
      `vuln_class must be one of ${ALL_VULN_CLASSES.join('|')}, got "${vuln_class}"`,
      `${fieldPath}.vuln_class`,
      source,
    );
  }
  const description = expectString(input, 'description', `${fieldPath}.description`, source);
  const argRaw = (input as Record<string, unknown>).argument_indices;
  let argument_indices: number[] = [];
  if (argRaw !== undefined) {
    if (!Array.isArray(argRaw)) {
      throw new SpecValidationError('argument_indices must be an integer array', `${fieldPath}.argument_indices`, source);
    }
    argument_indices = argRaw.map((v, i) => {
      if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
        throw new SpecValidationError(
          `argument_indices[${i}] must be a non-negative integer, got ${JSON.stringify(v)}`,
          `${fieldPath}.argument_indices[${i}]`,
          source,
        );
      }
      return v;
    });
  }
  // Phase 6.5: CVE-targeted FrameworkSpec rows carry osv_id on every sink
  // (server-side substituted in rule-generation-step.ts; never trusted from
  // model output). Hand-written framework-models/*.yaml leave it absent.
  const osvIdRaw = (input as Record<string, unknown>).osv_id;
  let osv_id: string | undefined;
  if (osvIdRaw !== undefined) {
    if (typeof osvIdRaw !== 'string' || osvIdRaw.length === 0) {
      throw new SpecValidationError(
        `osv_id must be a non-empty string when present, got ${JSON.stringify(osvIdRaw)}`,
        `${fieldPath}.osv_id`,
        source,
      );
    }
    osv_id = osvIdRaw;
  }
  return { pattern, vuln_class: vuln_class as VulnClass, argument_indices, description, osv_id };
}

function validateSanitizer(input: unknown, fieldPath: string, source?: string): FrameworkSanitizer {
  if (!isObject(input)) throw new SpecValidationError('sanitizer must be an object', fieldPath, source);
  const pattern = expectString(input, 'pattern', `${fieldPath}.pattern`, source);
  const description = expectString(input, 'description', `${fieldPath}.description`, source);
  const classesRaw = expectArray(input, 'vuln_classes', `${fieldPath}.vuln_classes`, source);
  const vuln_classes = classesRaw.map((v, i) => {
    if (typeof v !== 'string' || !VULN_CLASS_SET.has(v)) {
      throw new SpecValidationError(
        `vuln_classes[${i}] must be one of ${ALL_VULN_CLASSES.join('|')}, got ${JSON.stringify(v)}`,
        `${fieldPath}.vuln_classes[${i}]`,
        source,
      );
    }
    return v as VulnClass;
  });
  return { pattern, vuln_classes, description };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function expectString(obj: Record<string, unknown>, key: string, fieldPath: string, source?: string): string {
  const v = obj[key];
  if (typeof v !== 'string' || v.length === 0) {
    throw new SpecValidationError(`expected non-empty string for "${key}", got ${JSON.stringify(v)}`, fieldPath, source);
  }
  return v;
}

function expectArray(obj: Record<string, unknown>, key: string, fieldPath: string, source?: string): unknown[] {
  const v = obj[key];
  if (!Array.isArray(v)) {
    throw new SpecValidationError(`expected array for "${key}", got ${typeof v}`, fieldPath, source);
  }
  return v;
}
