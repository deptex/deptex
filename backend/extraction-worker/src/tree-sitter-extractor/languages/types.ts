export type SupportedEcosystem =
  | 'npm'
  | 'pypi'
  | 'maven'
  | 'go'
  | 'rubygems'
  | 'composer'
  | 'cargo'
  | 'nuget';

export type SupportedLanguageId =
  | 'javascript'
  | 'python'
  | 'java'
  | 'go'
  | 'ruby'
  | 'php'
  | 'rust'
  | 'csharp';

export interface ImportBinding {
  /** The local name bound in the file (e.g. `_` for `import _ from 'lodash'`). */
  localName: string;
  /** The name imported from the source module (e.g. `template` for `import { template } from 'lodash'`). Null for default/namespace/side-effect imports. */
  importedName: string | null;
  /** The module specifier as written (e.g. `'lodash/template'`). */
  source: string;
  /** 0-based line number. */
  line: number;
  kind: 'default' | 'named' | 'namespace' | 'side-effect' | 'cjs-require';
}

export interface UsageSlice {
  filePath: string;
  /** 0-based line number. */
  lineNumber: number;
  containingMethod: string | null;
  targetName: string;
  targetType: 'call' | 'member' | 'constructor' | 'tag' | 'new';
  resolvedMethod: string | null;
  usageLabel: string | null;
  /** The dep the usage resolved to, or null if first-party / stdlib / unknown. Populated by the extractor after alias resolution. */
  depName: string | null;
}

export interface ExtractedFile {
  filePath: string;
  language: SupportedLanguageId;
  imports: ImportBinding[];
  usages: UsageSlice[];
}

export interface KnownDep {
  name: string;
  /** Maven groupId / NuGet parent namespace / null for flat ecosystems. */
  namespace: string | null;
}

export interface LanguageContext {
  deps: readonly KnownDep[];
  /** Absolute path to the workspace root — some modules (go) read co-located manifest files. */
  workspaceRoot: string;
}

export interface LanguageModule {
  id: SupportedLanguageId;
  supportsFile(filePath: string): boolean;
  extractFile(
    source: string,
    filePath: string,
    ctx: LanguageContext
  ): Promise<ExtractedFile>;
}
