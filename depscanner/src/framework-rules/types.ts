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

/** 1-based, inclusive-both-ends line span of a handler (entry-point auth join, Sem 6). */
export interface HandlerSpan {
  startLine: number;
  endLine: number;
}

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
  /**
   * Span of this route's terminal handler (entry-point auth join, Sem 6). A
   * taint flow demotes only when its source line falls inside an authed,
   * demotion-eligible span. null for mount / wrapped / member / cross-file
   * handlers (those never demote). Absent on rows that predate span capture.
   */
  handlerSpan?: HandlerSpan | null;
  /**
   * false when the handler could be re-mounted / called from code we can't see
   * (exported or referenced elsewhere in the file) — its route still classifies
   * but never demotes a flow. Absent = treated as eligible only when a span is
   * present.
   */
  demotionEligible?: boolean;
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

/**
 * A route's auth facts carried in `ctx.entryPointAuth` and consumed by the
 * flow→route join (`matchFlowToRoutes`). Built per-route pre-dedupe at usage
 * extraction; NEVER persisted (the coarse `project_entry_points` row is).
 * `postProcess` detectors (Rails/Django) return these to re-home per-action
 * classifications onto controller/view files without touching `file.entryPoints`.
 */
export interface CtxOnlyRouteRecord {
  /** Project-relative POSIX path the record is keyed under (the handler's file). */
  filePath: string;
  classification: EntryPointClassification;
  handlerSpan: HandlerSpan | null;
  demotionEligible: boolean;
  routePattern: string | null;
  middlewareChain: string[] | null;
  authMechanism: string | null;
}

/**
 * Per-action auth facts a cross-file detector banks onto a controller/view
 * `ExtractedFile` during `detect` (entry-point auth classification, T9). The
 * detector's `postProcess` re-homes these into ctx-only route records keyed on
 * the same file. `filePath` is the file's original (possibly absolute) path —
 * `buildEntryPointAuthMap` normalizes it to the project-relative join key.
 */
export interface FileAuthFacts {
  framework: string;
  filePath: string;
  actions: Array<{
    /** Action / view name (for adjudication + logs). */
    name: string;
    /** The action method / view body span (Sem 6). */
    handlerSpan: HandlerSpan;
    classification: EntryPointClassification;
    demotionEligible: boolean;
    routePattern: string | null;
    middlewareChain: string[] | null;
    authMechanism: string | null;
  }>;
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
  /**
   * Optional cross-file pass (Rails/Django), run once after all files are
   * extracted (alongside `resolveMountPrefixes`). Consumes banked `authFacts`
   * to resolve routes→controller/view files and RETURNS ctx-only route records
   * (re-homed onto the handler file); it must NEVER append to `file.entryPoints`
   * (that would leak into `storeEntryPoints` + `httpEntryPointCount`). Wrapped
   * per-detector so a throw degrades that framework to route-local evidence.
   */
  postProcess?(files: readonly ExtractedFile[], opts: { workspaceRoot: string }): CtxOnlyRouteRecord[];
}
