import type { Tree } from 'web-tree-sitter';
import type { ExtractedFile, SupportedLanguageId } from '../tree-sitter-extractor/languages/types';
import type { RequestParam } from '../param-harvest/types';

export type EntryPointType =
  | 'http_route'
  | 'graphql_resolver'
  | 'websocket'
  | 'message_handler'
  | 'cli_command'
  | 'cron_job'
  | 'background_job'
  | 'event_listener'
  | 'rpc_method'
  | 'serverless_handler';

export type EntryPointClassification =
  | 'PUBLIC_UNAUTH'
  | 'AUTH_INTERNAL'
  | 'OFFLINE_WORKER'
  | 'UNKNOWN';

export type HttpMethod =
  | 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

export interface EntryPoint {
  filePath: string;
  /** 1-based line number — matches how the DB stores it. */
  lineNumber: number;
  framework: string;
  handlerName: string | null;
  httpMethod: HttpMethod | null;
  routePattern: string | null;
  entryPointType: EntryPointType;
  classification: EntryPointClassification;
  authenticated: boolean | null;
  authMechanism: string | null;
  middlewareChain: string[] | null;
  metadata: Record<string, unknown> | null;
  /**
   * Deterministically-harvested request parameters (query/header/cookie) the
   * handler reads — drives the DAST OpenAPI synthesizer's `query` parameters.
   * Populated by the per-framework param harvest during detection; null when
   * none recovered (or the handler isn't an inline function). Canonicalized
   * (deduped + sorted) — see param-harvest/types.ts.
   */
  requestParams?: RequestParam[] | null;
}

/**
 * Context passed to each detector — includes the parsed AST (for detectors
 * that need AST walking beyond what the extractor's `UsageSlice`s provide)
 * plus the already-extracted file metadata.
 */
export interface DetectorContext {
  source: string;
  /**
   * Language-specific AST tree from web-tree-sitter. Opaque to the registry;
   * each detector knows how to walk the tree shape for its own language.
   */
  tree: Tree;
  /** The file's extractor output — imports, usages, path. */
  file: ExtractedFile;
  /** Absolute path to the workspace root — detectors derive workspace-relative paths from it. */
  workspaceRoot: string;
  /** Dependency names from the SBOM — detectors gate on the framework's own package being present. */
  depNames: readonly string[];
}

export interface FrameworkDetector {
  /** Stable identifier stored in `project_entry_points.framework`. */
  name: string;
  /** User-facing name — shown in UI. */
  displayName: string;
  language: SupportedLanguageId;
  /**
   * Import names that activate this detector. If none of these are imported
   * in the file, the detector skips without walking the tree. At least one
   * must match for the detector to run.
   */
  triggerImports: readonly string[];
  /**
   * Walk the file and return any entry points found. Empty array if none
   * (e.g. the file imports express but doesn't actually register a route).
   */
  detect(ctx: DetectorContext): EntryPoint[];
}
