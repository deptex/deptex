/**
 * Zod-strict schema for the cross-file CVE-targeted taint generator's
 * `framework_spec` output (Phase 6.5 / M2).
 *
 * The generator is asked to emit a single JSON object describing one CVE-
 * scoped FrameworkSpec snippet that the Phase 6 cross-file taint engine can
 * load alongside the framework models. The shape mirrors `FrameworkSpec` in
 * `taint-engine/spec.ts`, with two intentional differences:
 *
 *   1. `osv_id` is NOT in the model output. The generator runs per-CVE; the
 *      server substitutes `osv_id = cve_id` on every sink AFTER parsing
 *      (Patch 5 / E1). The DB-side `framework_spec_osv_match_chk` constraint
 *      (M1 / phase27a) enforces this server-side as defense-in-depth.
 *      Emitting `osv_id` in the model output is a security event — the
 *      generator's Gate-1 hardening logs it as `prompt_injection_suspect`
 *      and rejects the row.
 *
 *   2. `.strict()` mode rejects any unrecognised key. Prevents prompt-
 *      injection-driven schema-shape attacks where the model is coerced into
 *      emitting extra fields that downstream consumers might trust.
 *
 * `vuln_class` is imported from `taint-engine/spec.ts` as the single source
 * of truth (Patch 5 / PDA-5) — adding a new vuln class to the engine keeps
 * the generator schema in sync automatically.
 *
 * Schema version (`framework-spec-v1`) is recorded on every generated row so
 * a future shape revision can selectively re-validate older rows.
 */

import { z } from 'zod';
import { ALL_VULN_CLASSES } from '../taint-engine/spec';

const TAINT_KINDS = ['http_input', 'env', 'file', 'cli', 'rpc'] as const;

const LANGUAGES = ['js', 'python', 'java', 'go', 'ruby', 'php', 'rust', 'csharp'] as const;

const VULN_CLASSES = ALL_VULN_CLASSES as readonly [string, ...string[]];

export const FrameworkSourceSchema = z.object({
  pattern: z.string().min(1),
  taint_kind: z.enum(TAINT_KINDS),
  description: z.string().min(1),
}).strict();

/**
 * Sink schema — model output (no osv_id; substituted server-side).
 *
 * `argument_indices` is required by the engine's `validateSink` but accepts
 * an empty array to mean "any tainted argument triggers". We require the
 * model to emit it explicitly (zod default would let the model omit it
 * silently, which is harder to debug when the model meant `[0]` but typed
 * nothing).
 */
export const FrameworkSinkSchema = z.object({
  pattern: z.string().min(1),
  vuln_class: z.enum(VULN_CLASSES),
  argument_indices: z.array(z.number().int().nonnegative()),
  description: z.string().min(1),
}).strict();

export const FrameworkSanitizerSchema = z.object({
  pattern: z.string().min(1),
  vuln_classes: z.array(z.enum(VULN_CLASSES)).min(1),
  description: z.string().min(1),
}).strict();

/**
 * The model-emitted FrameworkSpec. Sinks are osv_id-LESS at this layer; the
 * persistence step (`rule-generation-step.ts`) walks `sinks[]` and injects
 * `osv_id = cve_id` before writing to the DB.
 */
export const FrameworkSpecJsonSchema = z.object({
  framework: z.string().min(1),
  version: z.string().min(1),
  language: z.enum(LANGUAGES),
  sources: z.array(FrameworkSourceSchema),
  sinks: z.array(FrameworkSinkSchema).min(1, 'framework_spec.sinks must have at least one entry — a CVE-targeted spec with no sinks emits no flows'),
  sanitizers: z.array(FrameworkSanitizerSchema),
}).strict();

export type FrameworkSpecJson = z.infer<typeof FrameworkSpecJsonSchema>;
export type FrameworkSinkJson = z.infer<typeof FrameworkSinkSchema>;
export type FrameworkSourceJson = z.infer<typeof FrameworkSourceSchema>;
export type FrameworkSanitizerJson = z.infer<typeof FrameworkSanitizerSchema>;

/**
 * Same shape as FrameworkSinkSchema but with osv_id present (post-substitution).
 * This is what hits the DB. Exposed for tests + the persistence step.
 */
export const PersistedFrameworkSinkSchema = FrameworkSinkSchema.extend({
  osv_id: z.string().min(1),
}).strict();

export const PersistedFrameworkSpecSchema = FrameworkSpecJsonSchema.extend({
  sinks: z.array(PersistedFrameworkSinkSchema).min(1),
}).strict();

export type PersistedFrameworkSpec = z.infer<typeof PersistedFrameworkSpecSchema>;
export type PersistedFrameworkSink = z.infer<typeof PersistedFrameworkSinkSchema>;

/**
 * The complete generator output schema — what `parseAndValidate` enforces.
 * Mirrors the model-output spec in `prompt-builder.ts`. Removed from the
 * Phase 5 schema: `rule_yaml`. Added: `framework_spec`. Kept (still useful
 * downstream): `vulnerable_fixture`, `safe_fixture`, `reachability_level`,
 * `entry_point_class`, `rationale`.
 */
const REACHABILITY_LEVELS = ['confirmed', 'function'] as const;
const ENTRY_POINT_CLASSES = ['PUBLIC_UNAUTH', 'AUTH_INTERNAL', 'OFFLINE_WORKER'] as const;

export const GeneratedFrameworkSpecPayloadSchema = z.object({
  framework_spec: FrameworkSpecJsonSchema,
  vulnerable_fixture: z.string().min(10, 'vulnerable_fixture too short'),
  safe_fixture: z.string().min(10, 'safe_fixture too short'),
  reachability_level: z.enum(REACHABILITY_LEVELS),
  entry_point_class: z.enum(ENTRY_POINT_CLASSES),
  rationale: z.string().optional().default(''),
}).strict();

export type GeneratedFrameworkSpecPayload = z.infer<typeof GeneratedFrameworkSpecPayloadSchema>;

/**
 * Walk `sinks[]` and reject any sink that contains an osv_id field. The
 * generator's Gate 1 calls this AFTER zod's schema check (zod's `.strict()`
 * already rejects extras, but `osv_id` rejection deserves its own labelled
 * error path so it can be logged as `prompt_injection_suspect`).
 *
 * Returns the index of the offending sink, or null if all are clean.
 */
export function findRogueOsvIdInSinks(input: unknown): number | null {
  if (!input || typeof input !== 'object') return null;
  const spec = input as { sinks?: unknown };
  if (!Array.isArray(spec.sinks)) return null;
  for (let i = 0; i < spec.sinks.length; i++) {
    const sink = spec.sinks[i];
    if (sink && typeof sink === 'object' && 'osv_id' in (sink as Record<string, unknown>)) {
      return i;
    }
  }
  return null;
}

/**
 * Server-side osv_id substitution. Walks `sinks[]` and injects `osv_id =
 * cve_id` on every sink. Pure — returns a new object; never mutates input.
 *
 * The persistence step is the SINGLE canonical assignment site for osv_id.
 * No other code path is allowed to set this field.
 */
export function withOsvIdsSubstituted(spec: FrameworkSpecJson, cveId: string): PersistedFrameworkSpec {
  return {
    ...spec,
    sinks: spec.sinks.map((sink) => ({ ...sink, osv_id: cveId })),
  };
}

/** Bumped from `rulegen-v10` (Phase 5 final) → `framework-spec-v1` (Phase 6.5). */
export const FRAMEWORK_SPEC_PROMPT_VERSION = 'framework-spec-v1';
