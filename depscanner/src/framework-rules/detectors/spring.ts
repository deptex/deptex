import * as fs from 'fs';
import * as path from 'path';
import type { Node } from 'web-tree-sitter';
import type {
  DetectorContext,
  EntryPoint,
  EntryPointClassification,
  FrameworkDetector,
  HttpMethod,
} from '../types';
import {
  SPRING_VERB_ANNOTATIONS,
  annotationsOn,
  detectJavaAuthMechanism,
  javaAuthEvidenceFromAnnotations,
  joinRoute,
  lineOf,
  mergeJavaAuthEvidence,
  textOf,
  walkTree,
  workspaceHasFullSecurityChain,
} from '../util/java';
import { classifyRoute, spanOfNode } from '../util/auth-evidence';

// Spring MVC / WebFlux routes:
//   @RestController @RequestMapping("/api/users")
//   public class UserController {
//     @GetMapping("/{id}") ...
//     @PostMapping ...
//     @RequestMapping(value="/search", method=RequestMethod.GET) ...
//   }

const CONTROLLER_ANNOTATIONS = new Set(['RestController', 'Controller']);

function isControllerClass(decl: Node, source: string): boolean {
  return annotationsOn(decl, source).some((a) => CONTROLLER_ANNOTATIONS.has(a.name));
}

function classPrefix(decl: Node, source: string): string | null {
  const req = annotationsOn(decl, source).find((a) => a.name === 'RequestMapping');
  return req?.firstStringArg ?? null;
}

function methodFromRequestMapping(namedValues: Map<string, Node>, source: string): HttpMethod | null {
  const methodNode = namedValues.get('method');
  if (!methodNode) return null;
  const text = textOf(methodNode, source);
  // `RequestMethod.GET` — take the rightmost segment.
  const m = text.split('.').pop()?.toUpperCase() ?? '';
  if (['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(m)) return m as HttpMethod;
  return null;
}

// ---------------------------------------------------------------------------
// Spring Boot Actuator endpoint enumeration
// ---------------------------------------------------------------------------
//
// Actuator endpoints are framework-provided HTTP routes: no `@Controller`
// declares them, so the AST walk above never sees them. Yet a project that sets
// `management.endpoints.web.exposure.include` exposes real, request-reachable
// HTTP routes — several of which parse an attacker-supplied JSON body through
// jackson-core's blocking parser (`POST /actuator/loggers/{name}`). Enumerating
// them here (a) records them as genuine entry points for DAST + auditing and
// (b) is the deployed-web-app signal that lets the reachability classifier
// recover the jackson-core blocking-parser silence-FN.

interface ActuatorRoute {
  method: HttpMethod;
  /** Path suffix appended to the actuator base path. */
  suffix: string;
  /** The operation accepts a JSON request body (parsed by jackson-core). */
  jsonBody?: boolean;
}

interface ActuatorEndpoint {
  /** Endpoint id — the token used in `exposure.include` / `exclude`. */
  id: string;
  routes: ActuatorRoute[];
  /**
   * Disabled by default even under `include=*`; only enumerated when its
   * per-endpoint enable flag is set (e.g. `management.endpoint.shutdown.enabled`).
   */
  requiresEnableFlag?: string;
}

/**
 * The standard Spring Boot Actuator web endpoints. Kept intentionally to the
 * well-known set that registers HTTP routes under the actuator base path; the
 * JSON-body write operations (loggers POST, caches DELETE) are flagged so the
 * classifier + DAST can reason about the request-body parser surface.
 */
const ACTUATOR_ENDPOINTS: readonly ActuatorEndpoint[] = [
  { id: 'health', routes: [{ method: 'GET', suffix: '/health' }, { method: 'GET', suffix: '/health/{component}' }] },
  { id: 'info', routes: [{ method: 'GET', suffix: '/info' }] },
  {
    id: 'loggers',
    routes: [
      { method: 'GET', suffix: '/loggers' },
      { method: 'GET', suffix: '/loggers/{name}' },
      // Sets a log level via {"configuredLevel":"DEBUG"} — attacker JSON body
      // hits jackson-core's blocking parser. The key silence-FN surface.
      { method: 'POST', suffix: '/loggers/{name}', jsonBody: true },
    ],
  },
  { id: 'metrics', routes: [{ method: 'GET', suffix: '/metrics' }, { method: 'GET', suffix: '/metrics/{requiredMetricName}' }] },
  { id: 'env', routes: [{ method: 'GET', suffix: '/env' }, { method: 'GET', suffix: '/env/{toMatch}' }] },
  { id: 'beans', routes: [{ method: 'GET', suffix: '/beans' }] },
  { id: 'mappings', routes: [{ method: 'GET', suffix: '/mappings' }] },
  { id: 'configprops', routes: [{ method: 'GET', suffix: '/configprops' }] },
  { id: 'conditions', routes: [{ method: 'GET', suffix: '/conditions' }] },
  { id: 'scheduledtasks', routes: [{ method: 'GET', suffix: '/scheduledtasks' }] },
  { id: 'threaddump', routes: [{ method: 'GET', suffix: '/threaddump' }] },
  { id: 'heapdump', routes: [{ method: 'GET', suffix: '/heapdump' }] },
  { id: 'httpexchanges', routes: [{ method: 'GET', suffix: '/httpexchanges' }] },
  {
    id: 'caches',
    routes: [
      { method: 'GET', suffix: '/caches' },
      { method: 'GET', suffix: '/caches/{cache}' },
      { method: 'DELETE', suffix: '/caches' },
      { method: 'DELETE', suffix: '/caches/{cache}' },
    ],
  },
  // Off unless management.endpoint.shutdown.enabled=true, even under include=*.
  { id: 'shutdown', requiresEnableFlag: 'shutdown', routes: [{ method: 'POST', suffix: '/shutdown', jsonBody: true }] },
];

const DEFAULT_ACTUATOR_BASE_PATH = '/actuator';

export interface ActuatorExposure {
  /** Raw value of `management.endpoints.web.exposure.include`. */
  include: string;
  /** Raw value of `management.endpoints.web.exposure.exclude` (or null). */
  exclude: string | null;
  /** `management.endpoints.web.base-path` (defaults to `/actuator`). */
  basePath: string;
  /** Set of endpoint ids whose per-endpoint enable flag is on (e.g. shutdown). */
  enabledFlags: Set<string>;
  /** Absolute path of the config file the exposure was read from. */
  configFilePath: string;
  /** 1-based line of the `include` directive (for the entry-point line number). */
  configLine: number;
}

/** Parse a comma/space list of endpoint ids, lowercased. */
function parseIdList(raw: string | null | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(/[,\s]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * Resolve the actual set of exposed actuator routes from an exposure config.
 * Pure — unit-tested directly.
 *   - `include=*` exposes every catalog endpoint (minus enable-flag-gated ones
 *     that aren't enabled), then `exclude` removes any named ids.
 *   - an explicit `include` list exposes only the named ids (still respecting
 *     `exclude` + enable flags).
 */
export function resolveActuatorRoutes(exposure: {
  include: string;
  exclude?: string | null;
  enabledFlags?: Set<string>;
}): Array<{ id: string; method: HttpMethod; routeSuffix: string; jsonBody: boolean }> {
  const include = parseIdList(exposure.include);
  const exclude = new Set(parseIdList(exposure.exclude ?? null));
  const enabled = exposure.enabledFlags ?? new Set<string>();
  const includeAll = include.includes('*');
  const out: Array<{ id: string; method: HttpMethod; routeSuffix: string; jsonBody: boolean }> = [];
  for (const ep of ACTUATOR_ENDPOINTS) {
    const named = includeAll || include.includes(ep.id);
    if (!named) continue;
    if (exclude.has(ep.id)) continue;
    if (ep.requiresEnableFlag && !enabled.has(ep.requiresEnableFlag)) continue;
    for (const r of ep.routes) {
      out.push({ id: ep.id, method: r.method, routeSuffix: r.suffix, jsonBody: !!r.jsonBody });
    }
  }
  return out;
}

/**
 * Build `http_route` entry points for the exposed actuator endpoints. Pure.
 * Each row is attached to the config file (stable file/line) with a unique
 * handler name per route, so identical rows emitted while scanning multiple
 * controller files collapse under the entry-point storage dedup key
 * (project, run, file_path, line, framework, handler_name).
 */
export function enumerateActuatorEntryPoints(opts: {
  exposure: ActuatorExposure;
  springSecurityPresent: boolean;
}): EntryPoint[] {
  const { exposure, springSecurityPresent } = opts;
  const base = (exposure.basePath || DEFAULT_ACTUATOR_BASE_PATH).replace(/\/+$/, '') || '';
  const routes = resolveActuatorRoutes({
    include: exposure.include,
    exclude: exposure.exclude,
    enabledFlags: exposure.enabledFlags,
  });
  // Unauthenticated unless the project ships Spring Security (which may protect
  // the actuator). Conservative honest default; the reachability promotion gate
  // keys on exposure, not on this classification.
  const classification: EntryPointClassification = springSecurityPresent ? 'AUTH_INTERNAL' : 'PUBLIC_UNAUTH';
  const authMechanism = springSecurityPresent ? 'spring_security' : null;
  return routes.map((r) => {
    const routePattern = `${base}${r.routeSuffix}` || '/';
    return {
      filePath: exposure.configFilePath,
      lineNumber: exposure.configLine,
      framework: 'spring',
      handlerName: `actuator ${r.method} ${routePattern}`,
      httpMethod: r.method,
      routePattern,
      entryPointType: 'http_route',
      classification,
      authenticated: springSecurityPresent ? true : false,
      authMechanism,
      middlewareChain: null,
      metadata: {
        actuator: true,
        endpoint_id: r.id,
        json_body: r.jsonBody,
        exposed_via: exposure.include,
      },
      requestParams: null,
    };
  });
}

const ACTUATOR_CONFIG_CANDIDATES = [
  'src/main/resources/application.properties',
  'src/main/resources/application.yml',
  'src/main/resources/application.yaml',
  'application.properties',
  'application.yml',
  'application.yaml',
  'config/application.properties',
  'config/application.yml',
  'config/application.yaml',
];

/** Read a config value (`key = value` / `key: value`) + its 1-based line. */
function readConfigValue(text: string, key: string): { value: string; line: number } | null {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`^\\s*${escaped}\\s*[=:]\\s*(.+?)\\s*$`, 'im');
  const m = text.match(re);
  if (!m || m.index === undefined) return null;
  const value = m[1].replace(/^["']|["']$/g, '').trim();
  const line = text.slice(0, m.index).split(/\r?\n/).length;
  return { value, line };
}

/**
 * Discover the actuator web-exposure config from the workspace. Best-effort —
 * returns null when no `management.endpoints.web.exposure.include` directive is
 * found (actuator not exposed / non-standard config). Never throws.
 */
export function readActuatorExposure(workspaceRoot: string | undefined): ActuatorExposure | null {
  if (!workspaceRoot) return null;
  for (const rel of ACTUATOR_CONFIG_CANDIDATES) {
    const abs = path.join(workspaceRoot, rel);
    let text: string;
    try {
      const stat = fs.statSync(abs);
      if (!stat.isFile() || stat.size > 2 * 1024 * 1024) continue;
      text = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    const inc = readConfigValue(text, 'management.endpoints.web.exposure.include');
    if (!inc || !inc.value || inc.value.toLowerCase() === 'none') continue;
    const exc = readConfigValue(text, 'management.endpoints.web.exposure.exclude');
    const bp = readConfigValue(text, 'management.endpoints.web.base-path');
    const enabledFlags = new Set<string>();
    // Per-endpoint enable flags (only shutdown matters in the catalog today).
    const shutdown = readConfigValue(text, 'management.endpoint.shutdown.enabled');
    if (shutdown && /^true$/i.test(shutdown.value)) enabledFlags.add('shutdown');
    return {
      include: inc.value,
      exclude: exc?.value ?? null,
      basePath: bp?.value || DEFAULT_ACTUATOR_BASE_PATH,
      enabledFlags,
      configFilePath: abs,
      configLine: inc.line,
    };
  }
  return null;
}

export const springDetector: FrameworkDetector = {
  name: 'spring',
  displayName: 'Spring MVC',
  language: 'java',
  triggerImports: [
    'org.springframework.web.bind.annotation',
    'org.springframework.stereotype',
  ],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    // Import hint only — classification comes from annotation evidence.
    const authMechanismHint = detectJavaAuthMechanism(file.imports);
    // Centralized Spring Security (Sem 3 zero-carve-out rule): a filter chain
    // that positively covers every request with no permitAll/anonymous/ignoring
    // carve-outs authenticates ALL MVC routes (belt still guards belt routes).
    const chainCovers = workspaceHasFullSecurityChain(ctx.workspaceRoot);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'class_declaration') return;
      if (!isControllerClass(node, source)) return;

      const prefix = classPrefix(node, source);
      const nameNode = node.childForFieldName('name');
      const className = nameNode ? textOf(nameNode, source) : null;
      const classEvidence = javaAuthEvidenceFromAnnotations(annotationsOn(node, source), source);

      const body = node.childForFieldName('body');
      if (!body) return;
      for (let i = 0; i < body.namedChildCount; i++) {
        const member = body.namedChild(i)!;
        if (member.type !== 'method_declaration') continue;
        const methodName = member.childForFieldName('name');
        const handlerName = methodName ? textOf(methodName, source) : null;

        const methodEvidence = javaAuthEvidenceFromAnnotations(annotationsOn(member, source), source);
        const merged = mergeJavaAuthEvidence(classEvidence, methodEvidence);

        const classifyFor = (routePattern: string | null) => {
          const routeLocal = merged.vettedAuthTokens.length > 0;
          const vetted = routeLocal
            ? merged.vettedAuthTokens
            : chainCovers ? ['SecurityFilterChain'] : [];
          return classifyRoute({
            vettedAuthTokens: vetted,
            publicOverrides: merged.publicOverrides,
            routePattern,
            centralizedOnly: !routeLocal,
          });
        };

        const pushRoute = (
          httpMethod: EntryPoint['httpMethod'],
          subRoute: string,
          annotationName: string,
        ): void => {
          const routePattern = joinRoute(prefix, subRoute);
          const result = classifyFor(routePattern);
          entryPoints.push({
            filePath: file.filePath,
            lineNumber: lineOf(member),
            framework: 'spring',
            handlerName,
            httpMethod,
            routePattern,
            entryPointType: 'http_route',
            classification: result.classification,
            authenticated: result.authenticated,
            authMechanism: authMechanismHint,
            middlewareChain: merged.vettedAuthTokens.length ? merged.vettedAuthTokens : null,
            // Declaration-bound family (Sem 6): evidence travels with the
            // method declaration → span always demotion-eligible.
            handlerSpan: spanOfNode(member),
            demotionEligible: true,
            metadata: { controller: className, annotation: annotationName },
          });
        };

        for (const ann of annotationsOn(member, source)) {
          const httpMethod = SPRING_VERB_ANNOTATIONS[ann.name];
          if (httpMethod) {
            pushRoute(httpMethod, ann.firstStringArg ?? '', ann.name);
          } else if (ann.name === 'RequestMapping') {
            pushRoute(methodFromRequestMapping(ann.namedValues, source), ann.firstStringArg ?? '', 'RequestMapping');
          }
        }
      }
    });

    // Framework-provided actuator endpoints (config-driven, no @Controller).
    // Best-effort: never let an actuator read fail controller detection. Emitted
    // from every spring-triggered file and deduped downstream by the stable
    // (config-file, line, handler-name) key in storeEntryPoints.
    try {
      const exposure = readActuatorExposure(ctx.workspaceRoot);
      if (exposure) {
        const springSecurityPresent = ctx.depNames.some((d) =>
          /spring-security|starter-security/i.test(d),
        );
        entryPoints.push(...enumerateActuatorEntryPoints({ exposure, springSecurityPresent }));
      }
    } catch {
      /* actuator enumeration is best-effort */
    }

    return entryPoints;
  },
};
