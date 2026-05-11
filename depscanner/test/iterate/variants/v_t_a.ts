/**
 * Tournament 2026-05-10 variant A — source-shape expansion.
 * Thin wrapper around the canonical prompt-variant module under
 * depscanner/src/cve-generation/prompt-variants/ so the iterate harness can
 * load it.
 */
export { NAME, VERSION, buildGenerationPrompt } from '../../../src/cve-generation/prompt-variants/v_a_source_expansion';
