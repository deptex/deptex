import { Language, Parser } from 'web-tree-sitter';
import * as path from 'path';
import type { SupportedLanguageId } from './languages/types';

let parserInitPromise: Promise<void> | null = null;
const languageCache = new Map<string, Language>();

async function ensureParserInitialized(): Promise<void> {
  if (!parserInitPromise) {
    parserInitPromise = Parser.init();
  }
  return parserInitPromise;
}

/**
 * Resolve a grammar .wasm file from the `@repomix/tree-sitter-wasms` package.
 * All 8 MVP languages ship there as `tree-sitter-<name>.wasm` (compiled
 * against a current-ABI tree-sitter that produces the `dylink.0` custom
 * section web-tree-sitter 0.22+ requires).
 *
 * Resolution uses `require.resolve` so the path works whether depscanner
 * is run from source (tsx), compiled (dist/), or inside the Docker image.
 */
function resolveWasmPath(wasmFile: string): string {
  const pkgRoot = path.dirname(require.resolve('@repomix/tree-sitter-wasms/package.json'));
  return path.join(pkgRoot, 'out', wasmFile);
}

export async function loadLanguage(wasmFile: string): Promise<Language> {
  await ensureParserInitialized();
  const cached = languageCache.get(wasmFile);
  if (cached) return cached;
  const lang = await Language.load(resolveWasmPath(wasmFile));
  languageCache.set(wasmFile, lang);
  return lang;
}

export async function makeParser(language: Language): Promise<Parser> {
  await ensureParserInitialized();
  const parser = new Parser();
  parser.setLanguage(language);
  return parser;
}

export function clearLanguageCache(): void {
  languageCache.clear();
}

export const _languageCacheSize = (): number => languageCache.size;
// ^ used by tests; not part of the public API
