import type { SupportedLanguageId } from '../tree-sitter-extractor/languages/types';
import type { FrameworkDetector } from './types';
import { expressDetector } from './detectors/express';

/**
 * All registered framework detectors. Adding a new framework is a two-step
 * change: (1) create `detectors/<name>.ts` exporting a `FrameworkDetector`,
 * (2) add it to this list. Detectors self-declare their target language and
 * trigger imports, so the registry stays flat.
 */
const ALL_DETECTORS: readonly FrameworkDetector[] = [
  expressDetector,
];

/** Detectors that might apply to files of the given language. */
export function getDetectorsForLanguage(lang: SupportedLanguageId): FrameworkDetector[] {
  return ALL_DETECTORS.filter((d) => d.language === lang);
}

export function allDetectors(): readonly FrameworkDetector[] {
  return ALL_DETECTORS;
}
