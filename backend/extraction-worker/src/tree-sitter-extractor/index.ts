import * as fs from 'fs';
import type { ExtractedFile, LanguageModule, SupportedEcosystem } from './languages/types';
import { javascriptModule } from './languages/javascript';
import { pythonModule } from './languages/python';
import { resolveImportToDep } from './import-mapping';
import { walkSourceFiles } from './walk';

export type { ExtractedFile, UsageSlice, ImportBinding, SupportedEcosystem, SupportedLanguageId } from './languages/types';
export { resolveImportToDep } from './import-mapping';

export interface ExtractUsageOptions {
  workspaceRoot: string;
  ecosystem: SupportedEcosystem;
  /** Dep names from the SBOM. Used to gate import resolution — an import that doesn't resolve to any known dep is dropped. */
  depNames?: readonly string[];
  /** Optional cap on files processed (for perf tests and truly huge monorepos). */
  maxFiles?: number;
  /** Per-file exceptions are swallowed and reported here. */
  onFileError?: (filePath: string, error: Error) => void;
}

export interface ExtractUsageResult {
  files: ExtractedFile[];
  /** Map from dep name → number of distinct files that imported it. */
  filesImportingByDep: Record<string, number>;
}

/** Language modules registered for M2. M3 adds java + go; M4 adds the rest. */
const LANGUAGE_MODULES: LanguageModule[] = [javascriptModule, pythonModule];

/**
 * Universal usage extractor built on web-tree-sitter.
 *
 * Walks every source file under `workspaceRoot`, dispatches by extension to a
 * language module, and returns per-file imports + call-sites plus the
 * per-dep file-count aggregate used to populate
 * `project_dependencies.files_importing_count`.
 */
export async function extractUsage(options: ExtractUsageOptions): Promise<ExtractUsageResult> {
  const { workspaceRoot, depNames = [], maxFiles, onFileError } = options;

  const supports = (p: string): boolean => LANGUAGE_MODULES.some((m) => m.supportsFile(p));
  const allFiles = walkSourceFiles(workspaceRoot, supports);
  const files = maxFiles != null ? allFiles.slice(0, maxFiles) : allFiles;

  const extracted: ExtractedFile[] = [];
  const filesByDep = new Map<string, Set<string>>();

  for (const file of files) {
    const mod = LANGUAGE_MODULES.find((m) => m.supportsFile(file));
    if (!mod) continue;
    let source: string;
    try {
      source = fs.readFileSync(file, 'utf8');
    } catch (err) {
      onFileError?.(file, err as Error);
      continue;
    }
    let result: ExtractedFile;
    try {
      result = await mod.extractFile(source, file, depNames);
    } catch (err) {
      onFileError?.(file, err as Error);
      continue;
    }
    extracted.push(result);

    for (const imp of result.imports) {
      const dep = resolveImportToDep(imp.source, options.ecosystem, depNames);
      if (!dep) continue;
      if (!filesByDep.has(dep)) filesByDep.set(dep, new Set());
      filesByDep.get(dep)!.add(file);
    }
  }

  const filesImportingByDep: Record<string, number> = {};
  for (const [dep, set] of filesByDep) filesImportingByDep[dep] = set.size;

  return { files: extracted, filesImportingByDep };
}
