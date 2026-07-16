import type {
  ExtractedFile,
  KnownDep,
  LanguageModule,
} from '../tree-sitter-extractor/languages/types';
import type { CtxOnlyRouteRecord, EntryPoint } from './types';
import { runPostProcess } from './build-auth-map';

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

/**
 * Extract a multi-file workspace and run the cross-file `postProcess` pass over
 * it (entry-point auth classification, T9). Returns the extracted files plus the
 * ctx-only route records postProcess re-homed — the same shape
 * `buildEntryPointAuthMap` consumes at runtime. Used by the Rails/Django
 * cross-file detector tests.
 */
export async function extractWorkspace(
  mod: LanguageModule,
  files: ReadonlyArray<{ path: string; source: string }>,
  deps: KnownDep[] = [],
): Promise<{ files: ExtractedFile[]; postProcessRecords: CtxOnlyRouteRecord[] }> {
  const extracted: ExtractedFile[] = [];
  for (const f of files) {
    extracted.push(await mod.extractFile(f.source, f.path, { deps, workspaceRoot: '/tmp' }));
  }
  const postProcessRecords = await runPostProcess(extracted, '/tmp');
  return { files: extracted, postProcessRecords };
}
