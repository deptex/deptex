import type {
  ExtractedFile,
  KnownDep,
  LanguageModule,
} from '../../tree-sitter-extractor/languages/types';
import type { EntryPoint } from '../types';

/**
 * Run a language module over an inline source string and return the parsed
 * `ExtractedFile`. Used by framework-detector tests to exercise the full
 * tree-sitter → detector path without staging a temp workspace.
 */
export async function extractInline(
  mod: LanguageModule,
  source: string,
  virtualPath: string,
  deps: KnownDep[] = [],
): Promise<ExtractedFile> {
  return mod.extractFile(source, virtualPath, { deps, workspaceRoot: '/tmp' });
}

export function entryPointsFor(file: ExtractedFile, framework: string): EntryPoint[] {
  return (file.entryPoints ?? []).filter((ep) => ep.framework === framework);
}

export const dep = (name: string, namespace: string | null = null): KnownDep => ({
  name,
  namespace,
});
