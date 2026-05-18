import { Language, Parser, type Tree } from 'web-tree-sitter';
import * as path from 'path';

let parserInitPromise: Promise<void> | null = null;
const languageCache = new Map<string, Language>();
const parserCache = new Map<string, Parser>();
/** wasm files whose grammar failed to load — logged once, never retried noisily. */
const failedGrammars = new Set<string>();

/** Files larger than this are skipped before parsing (minified/generated blobs hang the parser). */
const MAX_PARSE_BYTES = 1_000_000;
/** Wall-clock budget for a single parse; a pathological file aborts to an empty result. */
const MAX_PARSE_MS = 10_000;

/** Thrown when a language grammar (.wasm) fails to load — distinct from a per-file parse error. */
export class LanguageLoadError extends Error {
  constructor(public readonly wasmFile: string, cause: unknown) {
    super(`Failed to load tree-sitter grammar ${wasmFile}: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = 'LanguageLoadError';
  }
}

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
  let lang: Language;
  try {
    lang = await Language.load(resolveWasmPath(wasmFile));
  } catch (err) {
    if (!failedGrammars.has(wasmFile)) {
      failedGrammars.add(wasmFile);
      console.error(`[tree-sitter] Grammar load failed for ${wasmFile}; all files of this language will be skipped.`, err);
    }
    throw new LanguageLoadError(wasmFile, err);
  }
  languageCache.set(wasmFile, lang);
  return lang;
}

/** One reusable parser per language per run. Reused parsers avoid leaking a WASM Parser per file. */
async function getParser(wasmFile: string): Promise<Parser> {
  const cached = parserCache.get(wasmFile);
  if (cached) return cached;
  const language = await loadLanguage(wasmFile);
  await ensureParserInitialized();
  const parser = new Parser();
  parser.setLanguage(language);
  parserCache.set(wasmFile, parser);
  return parser;
}

export async function makeParser(language: Language): Promise<Parser> {
  await ensureParserInitialized();
  const parser = new Parser();
  parser.setLanguage(language);
  return parser;
}

/**
 * Parse a source file with a cached per-language parser, a byte-size guard,
 * and a wall-clock timeout. Returns null if the file is too large or parsing
 * was aborted. Grammar-load failures propagate as `LanguageLoadError`.
 *
 * The caller MUST call `tree.delete()` on the returned tree once done — the
 * web-tree-sitter Tree holds un-GC'able WASM heap.
 */
export async function parseSource(wasmFile: string, source: string): Promise<Tree | null> {
  if (Buffer.byteLength(source, 'utf8') > MAX_PARSE_BYTES) return null;
  const parser = await getParser(wasmFile);
  const deadline = Date.now() + MAX_PARSE_MS;
  // web-tree-sitter aborts the parse when progressCallback returns true; the
  // published d.ts types the return as void, so cast just the callback.
  const progressCallback = ((): boolean => Date.now() > deadline) as () => void;
  return parser.parse(source, null, { progressCallback });
}

export function clearLanguageCache(): void {
  languageCache.clear();
  for (const parser of parserCache.values()) {
    try { parser.delete(); } catch { /* already freed */ }
  }
  parserCache.clear();
  failedGrammars.clear();
}

export const _languageCacheSize = (): number => languageCache.size;
// ^ used by tests; not part of the public API
