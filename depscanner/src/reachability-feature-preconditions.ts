/**
 * Per-CVE FEATURE-PRECONDITION GATE (reachability noise reduction).
 *
 * The reachability classifier stamps a transitive framework dependency at
 * `module` with `verdict = "callgraph_reached_transitive"` whenever the taint
 * callgraph traced a single edge into the framework starter. That coarse
 * signal is WRONG for *feature-gated* CVEs: a CVE that lives in a framework
 * feature the application never enables (WebSocket, AJP, HTTP/2, WebDAV,
 * Digest auth, a TLS cipher connector, a Spring Security filter chain,
 * script-template views, a Realm, the CloudFoundry actuator) is provably
 * unreachable even though the servlet container / framework runtime is on the
 * request path. Keeping it at `module` is pure noise.
 *
 * This module is the generalizable, data-driven half of the fix:
 *
 *   1. `FEATURE_PRECONDITIONS` — a declarative table mapping an advisory to a
 *      required framework feature via robust keyword patterns on the advisory
 *      SUMMARY (the summaries name the feature explicitly — "WebSocket",
 *      "AJP", "HTTP/2", "WebDAV", "DIGEST authentication", "cipher", "security
 *      constraints", "Script Template", "Cloud Foundry"). Each entry also
 *      declares the *owning* dependency (so a jackson/postgres CVE that merely
 *      happens to mention "cipher" is never mistaken for the tomcat TLS CVE)
 *      and a `detect()` that reads real project signals. Adding a new entry is
 *      one table row.
 *
 *   2. A project-feature detector (`gatherSpringFeatureSignals` +
 *      `SpringFeatureSignals`) that decides whether the scanned project enables
 *      each feature from manifest (`pom.xml` starters/deps), config
 *      (`application*.properties|yml`, `web.xml`) and code (registered beans /
 *      annotations under `src/main`).
 *
 *   3. `evaluateFeaturePreconditionDemotion` — the pure decision function the
 *      classifier calls per finding.
 *
 * SAFETY (non-negotiable — a wrongful demotion silences a real vuln, the worst
 * possible outcome, far worse than leaving noise):
 *   - We DEMOTE to `unreachable` ONLY when the required feature is *provably
 *     absent* — the detector read the project AND found no enabling signal in
 *     the manifest, config, or code.
 *   - Any ambiguity is `unknown`, never `absent`: unreadable workspace, an
 *     unrecognized project (no pom.xml parsed), or a code scan that hit its
 *     byte cap all leave the finding at `module`.
 *   - The detector is LIBERAL about "present": when in doubt it reports the
 *     feature enabled (which blocks demotion). It is only ever confident about
 *     absence.
 *   - Java/Spring only for now (the table + detector are Maven-scoped). Other
 *     ecosystems return no signals → nothing is demoted. The shape generalizes
 *     to other frameworks by adding table rows + detector branches.
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Project-feature signals
// ---------------------------------------------------------------------------

export interface SpringFeatureSignals {
  /**
   * True once at least one `pom.xml` was parsed — i.e. this is a Maven project
   * we can reason about. When false the detector cannot prove any feature
   * absent, so `evaluate…` refuses every demotion.
   */
  recognized: boolean;
  /**
   * True when the `.java` scan hit its file/byte cap before finishing. A code
   * signal we didn't get to read might exist, so features whose absence relies
   * on scanning code return `unknown` (never `absent`) when this is set.
   */
  truncated: boolean;
  /** Lowercased Maven artifactIds across every parsed `pom.xml`. */
  pomArtifacts: Set<string>;
  /** Lowercased concat of `application*.{properties,yml,yaml}` + `web.xml`. */
  configText: string;
  /** Lowercased concat of `src/main/**\/*.java`. */
  codeText: string;
  /** A repo-root `manifest.yml`/`manifest.yaml` with an `applications:` block. */
  hasCloudFoundryManifest: boolean;
}

export type FeaturePresence = 'present' | 'absent' | 'unknown';

/** Empty (nothing recognized) signals — the "cannot reason" sentinel. */
export function emptySpringFeatureSignals(): SpringFeatureSignals {
  return {
    recognized: false,
    truncated: false,
    pomArtifacts: new Set(),
    configText: '',
    codeText: '',
    hasCloudFoundryManifest: false,
  };
}

// ---------------------------------------------------------------------------
// Feature-precondition table (declarative)
// ---------------------------------------------------------------------------

interface FeaturePrecondition {
  /** Stable feature id, surfaced in `reachability_details.reason`. */
  feature: string;
  /**
   * Demote only when the finding's dependency NAME includes one of these
   * lowercased tokens. Anchors each feature to the package that actually
   * owns the vulnerable surface (tomcat → the servlet container, spring-web →
   * spring-webmvc, …) so an unrelated CVE that merely mentions the keyword is
   * never demoted.
   */
  owners: string[];
  /** Demote only when the advisory SUMMARY matches one of these. */
  summary: RegExp[];
  /** Is the feature enabled in the scanned project? */
  detect: (s: SpringFeatureSignals) => FeaturePresence;
}

/** Any of `subs` is a substring of a parsed pom artifactId. */
function depIncludes(s: SpringFeatureSignals, subs: string[]): boolean {
  for (const a of s.pomArtifacts) {
    for (const sub of subs) if (a.includes(sub)) return true;
  }
  return false;
}

/** Any of `subs` occurs in the concatenated `.java` source. */
function codeIncludes(s: SpringFeatureSignals, subs: string[]): boolean {
  return subs.some((x) => s.codeText.includes(x));
}

/** Any of `subs` occurs in code OR config text. */
function anyTextIncludes(s: SpringFeatureSignals, subs: string[]): boolean {
  return subs.some((x) => s.codeText.includes(x) || s.configText.includes(x));
}

/** Any regex matches the config text. */
function configMatches(s: SpringFeatureSignals, res: RegExp[]): boolean {
  return res.some((r) => r.test(s.configText));
}

/**
 * Resolve a boolean "present" signal into a `FeaturePresence`. When the signal
 * is absent AND the code scan was truncated (a code signal may have been
 * missed), we return `unknown` — never `absent` — so a demotion is refused.
 */
function resolve(present: boolean, s: SpringFeatureSignals): FeaturePresence {
  if (present) return 'present';
  if (s.truncated) return 'unknown';
  return 'absent';
}

// ---------------------------------------------------------------------------
// Spring web-app / Jackson / actuator signal helpers
// (shared by the FRAMEWORK_MEDIATED table below and the jackson-core
// blocking-parser ALWAYS_ON_RUNTIME row further down)
// ---------------------------------------------------------------------------

/**
 * Spring web-application artifacts. Substring match (via `depIncludes`) so the
 * modern module-split names (`spring-boot-starter-webmvc`,
 * `spring-boot-starter-webflux`) and the classic `spring-boot-starter-web` /
 * `spring-webmvc` all resolve — `spring-boot-starter-web` is a prefix of the
 * `-webmvc` / `-webflux` variants.
 */
const SPRING_WEB_ARTIFACTS = [
  'spring-boot-starter-web',
  'spring-webmvc',
  'spring-webflux',
  'spring-web',
];

/** The project ships a Spring MVC / WebFlux web layer. */
function springWebAppPresent(s: SpringFeatureSignals): boolean {
  return depIncludes(s, SPRING_WEB_ARTIFACTS);
}

/**
 * The app declares a Jackson-backed message-converter surface — a
 * `@RestController` / `@ResponseBody` (JSON responses) or `@RequestBody` (JSON
 * request bodies). Substring tokens catch the `@`-prefixed annotations in the
 * lowercased code text. Liberal by design: a false "present" only floors
 * Jackson at `module` (still hidden, just honest), it never surfaces noise.
 */
function jacksonMessageConvertersPresent(s: SpringFeatureSignals): boolean {
  return codeIncludes(s, ['restcontroller', 'responsebody', 'requestbody']);
}

/**
 * Raw value of `management.endpoints.web.exposure.include` (properties form, or
 * a best-effort yaml `exposure:`→`include:`), trimmed & unquoted; null when
 * unset. `configText` is already lowercased by the detector.
 */
function actuatorIncludeValue(s: SpringFeatureSignals): string | null {
  const clean = (v: string) => v.trim().replace(/^["']|["']$/g, '').trim();
  const flat = s.configText.match(
    /management\.endpoints\.web\.exposure\.include\s*[=:]\s*([^\r\n#]+)/,
  );
  if (flat) return clean(flat[1]);
  // yaml nested form — only trust an `include:` when an `exposure:` key is also
  // present (avoids matching an unrelated `include:` elsewhere in config).
  if (s.configText.includes('exposure')) {
    const y = s.configText.match(/\binclude\s*:\s*([^\r\n#]+)/);
    if (y) return clean(y[1]);
  }
  return null;
}

/** Actuator web endpoints are exposed at all (`include` names something). */
function actuatorExposed(s: SpringFeatureSignals): boolean {
  const v = actuatorIncludeValue(s);
  return !!v && v.length > 0 && v !== 'none';
}

/**
 * An actuator endpoint that accepts a JSON request BODY is exposed —
 * `POST /actuator/loggers/{name}` sets a log level via `{"configuredLevel":…}`,
 * parsed by jackson-core's BLOCKING parser. True when `include` is `*` or names
 * `loggers` explicitly. Gates the jackson-core blocking-parser promotion so a
 * project with no exposed JSON-body actuator endpoint never earns it.
 */
export function actuatorWriteJsonEndpointExposed(s: SpringFeatureSignals): boolean {
  const v = actuatorIncludeValue(s);
  if (!v) return false;
  return v.includes('*') || /\bloggers\b/.test(v);
}

// ---------------------------------------------------------------------------
// FRAMEWORK-MEDIATED DEPENDENCY table (silence-FN recovery)
// ---------------------------------------------------------------------------

interface FrameworkMediatedDep {
  /** Stable id, surfaced in `reachability_details`. */
  id: string;
  /** Match when the dependency NAME includes one of these lowercased tokens. */
  owners: string[];
  /** The framework-dispatch mechanism that exercises this dep is present. */
  mediated: (s: SpringFeatureSignals) => boolean;
}

/**
 * Dependencies a framework exercises via DISPATCH — the app never `import`s
 * them, yet they run on the request path. The import-absence heuristic in the
 * classifier would wrongly declare these orphan `unreachable`; this table lets
 * the classifier floor them at `module` instead.
 *
 * SAFETY: this only ever moves a verdict unreachable→module (still hidden, just
 * HONEST) — the conservative direction. Each row anchors to the owning package
 * (jackson) AND requires the framework's dispatch mechanism to be present, so an
 * unrelated transitive is never floored. Generalizes by adding a row (e.g. a
 * JAX-RS `MessageBodyReader` provider, gson under a spring web app).
 */
const FRAMEWORK_MEDIATED: FrameworkMediatedDep[] = [
  {
    // Jackson is Spring's default JSON (de)serializer: MappingJackson2Http-
    // MessageConverter is auto-configured in any spring-boot web app, and the
    // actuator endpoints render/parse JSON through it. No app file imports
    // com.fasterxml.jackson — it is reached purely via framework dispatch.
    id: 'spring-jackson-message-converter',
    owners: ['jackson'],
    mediated: (s) =>
      springWebAppPresent(s) &&
      (jacksonMessageConvertersPresent(s) || actuatorExposed(s)),
  },
];

export interface FrameworkMediatedResult {
  mediated: boolean;
  id?: string;
}

/**
 * Decide whether a dependency with no first-party import is nonetheless
 * exercised via framework dispatch. Pure — unit-tested directly.
 *
 * Fail-safe: unrecognized signals (non-Maven / unreadable project) or a missing
 * dependency name → `{ mediated: false }`, so the classifier keeps its prior
 * verdict (no false floor).
 */
export function evaluateFrameworkMediatedUsage(input: {
  depName: string | null | undefined;
  signals: SpringFeatureSignals | null | undefined;
}): FrameworkMediatedResult {
  const { depName, signals } = input;
  if (!signals || !signals.recognized) return { mediated: false };
  if (!depName) return { mediated: false };
  const dep = depName.toLowerCase();
  for (const row of FRAMEWORK_MEDIATED) {
    if (!row.owners.some((o) => dep.includes(o))) continue;
    if (row.mediated(signals)) return { mediated: true, id: row.id };
  }
  return { mediated: false };
}

/**
 * The table. Each row is cheap to add. Owners + summary patterns keep the gate
 * anchored to genuinely feature-specific advisories; generic request-path CVEs
 * (a servlet-container request-smuggling CVE, a spring-webmvc data-binding CVE)
 * do NOT name a feature in their summary and so never match — that is the
 * property that makes demotion safe.
 *
 * NOTE — deliberately EXCLUDED (safety):
 *   - Thymeleaf / template-engine SSTI: its precondition is a request→template
 *     expression taint flow, not a config toggle; the template engine renders
 *     every page, so it stays on the request path. Proving "no SSTI flow" is
 *     the taint engine's job, not this gate's — we never demote it.
 *   - Actuator health-group / security-bypass: the bypass only matters when
 *     Spring Security is present, but the actuator endpoints themselves are on
 *     the request path when exposed; we leave these at `module`.
 *   - Server-Sent Events (SseEmitter): left at `module` here out of caution;
 *     enable by adding the row below once its advisory-id space is disambiguated
 *     from the generic spring-webmvc dispatch CVEs.
 */
export const FEATURE_PRECONDITIONS: FeaturePrecondition[] = [
  // --- Embedded Tomcat feature CVEs (owner: the servlet container) ---
  {
    feature: 'tomcat-websocket',
    owners: ['tomcat'],
    summary: [/web[\s-]?socket/i],
    detect: (s) =>
      resolve(
        depIncludes(s, ['websocket']) ||
          codeIncludes(s, [
            'serverendpoint',
            'enablewebsocket',
            'websockethandler',
            'websocketconfigurer',
            'websockethandlerregistry',
            'stompendpoint',
          ]),
        s,
      ),
  },
  {
    feature: 'tomcat-ajp-connector',
    owners: ['tomcat'],
    summary: [/\bajp\b/i],
    // AJP is never on by default in embedded Tomcat; any mention (an AJP
    // Connector bean or an `ajp` property) marks it present.
    detect: (s) => resolve(anyTextIncludes(s, ['ajp']), s),
  },
  {
    feature: 'tomcat-http2',
    owners: ['tomcat'],
    summary: [/http\/2/i, /\bhttp2\b/i],
    // `http2` is unambiguous — the `h2` in-memory DB does not contain it.
    detect: (s) => resolve(anyTextIncludes(s, ['http2']), s),
  },
  {
    feature: 'tomcat-webdav',
    owners: ['tomcat'],
    summary: [/web[\s-]?dav/i],
    detect: (s) => resolve(anyTextIncludes(s, ['webdav']), s),
  },
  {
    feature: 'tomcat-digest-auth',
    owners: ['tomcat'],
    // Require the DIGEST *authentication* context so a "message digest" hash
    // CVE never trips it.
    summary: [/digest.{0,40}auth/i, /auth.{0,40}digest/i, /digestauthenticator/i],
    detect: (s) => resolve(anyTextIncludes(s, ['digest']), s),
  },
  {
    feature: 'tomcat-tls-cipher',
    owners: ['tomcat'],
    summary: [/\bcipher/i],
    // Server-side TLS connector only (`server.ssl.*` / a `ssl:`+enabled yaml
    // block / an explicit cipher list). Deliberately does NOT match a JDBC
    // `?ssl=true` datasource URL — that is client TLS, unrelated to the
    // container's cipher ordering.
    detect: (s) =>
      resolve(
        s.configText.includes('server.ssl') ||
          configMatches(s, [/ssl:\s*[\r\n]+\s*(enabled:\s*true|key-?store|certificate)/]) ||
          anyTextIncludes(s, ['ciphers', 'setciphers', 'sslhostconfig']),
        s,
      ),
  },
  {
    feature: 'tomcat-security-constraints',
    owners: ['tomcat'],
    summary: [/security constraint/i],
    detect: (s) =>
      resolve(
        depIncludes(s, ['spring-security', 'spring-boot-starter-security']) ||
          codeIncludes(s, [
            '@servletsecurity',
            'securityfilterchain',
            'enablewebsecurity',
            'httpsecurity',
          ]) ||
          anyTextIncludes(s, ['security-constraint']),
        s,
      ),
  },
  {
    feature: 'tomcat-realm',
    owners: ['tomcat'],
    summary: [/\brealm\b/i, /lockoutrealm/i],
    detect: (s) =>
      resolve(
        depIncludes(s, ['spring-security', 'spring-boot-starter-security']) ||
          codeIncludes(s, ['realm', 'enablewebsecurity', 'securityfilterchain', 'logincontext']),
        s,
      ),
  },

  // --- Spring MVC feature CVEs (owner: spring-web / spring-webmvc) ---
  {
    feature: 'spring-script-template-views',
    owners: ['spring-web'],
    summary: [/script\s?(view\s?)?template/i, /scripttemplate/i],
    detect: (s) =>
      resolve(
        codeIncludes(s, ['scripttemplate', 'scripttemplateconfigurer', 'scripttemplateview']) ||
          depIncludes(s, ['nashorn', 'graal']),
        s,
      ),
  },

  // --- Spring Boot default security filter chain (owner: spring-boot) ---
  {
    feature: 'spring-security-filter-chain',
    owners: ['spring-boot'],
    // Specific to the "default security filter chain" advisory; a generic
    // spring-boot autoconfiguration CVE will not name a filter chain.
    summary: [/security filter chain/i, /default security filter/i],
    detect: (s) =>
      resolve(
        depIncludes(s, ['spring-security', 'spring-boot-starter-security']) ||
          codeIncludes(s, [
            'enablewebsecurity',
            'securityfilterchain',
            'websecurityconfigureradapter',
            '@enablemethodsecurity',
          ]),
        s,
      ),
  },

  // --- Actuator CloudFoundry endpoint (owner: actuator / spring-boot) ---
  {
    feature: 'actuator-cloudfoundry',
    owners: ['actuator', 'spring-boot'],
    summary: [/cloud\s?foundry/i],
    detect: (s) =>
      resolve(
        s.hasCloudFoundryManifest ||
          depIncludes(s, ['spring-cloud']) ||
          anyTextIncludes(s, ['cloudfoundry', 'vcap_services', 'vcap_application']),
        s,
      ),
  },
];

// ---------------------------------------------------------------------------
// The decision function (pure — unit-tested directly)
// ---------------------------------------------------------------------------

export interface FeatureDemotionResult {
  demote: boolean;
  feature?: string;
  matchedPattern?: string;
}

/**
 * Decide whether a `module` / `callgraph_reached_transitive` finding should be
 * demoted to `unreachable` because the framework feature its CVE requires is
 * PROVABLY ABSENT.
 *
 * Returns `{ demote: false }` unless:
 *   - signals are recognized (a real Maven project we read), AND
 *   - the finding has both a dependency name and an advisory summary, AND
 *   - at least one table row's owner matches the dep AND summary matches, AND
 *   - EVERY matching row's feature is provably `absent` (any `present`/`unknown`
 *     row aborts the demotion).
 */
export function evaluateFeaturePreconditionDemotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  signals: SpringFeatureSignals | null | undefined;
}): FeatureDemotionResult {
  const { depName, summary, signals } = input;
  if (!signals || !signals.recognized) return { demote: false };
  if (!depName || !summary) return { demote: false };

  const dep = depName.toLowerCase();
  const applicable = FEATURE_PRECONDITIONS.filter(
    (fp) => fp.owners.some((o) => dep.includes(o)) && fp.summary.some((re) => re.test(summary)),
  );
  if (applicable.length === 0) return { demote: false };

  // Conservative: a single non-absent match blocks the demotion entirely.
  let chosen: FeaturePrecondition | undefined;
  for (const fp of applicable) {
    if (fp.detect(signals) !== 'absent') return { demote: false };
    if (!chosen) chosen = fp;
  }
  const matched = chosen!.summary.find((re) => re.test(summary));
  return { demote: true, feature: chosen!.feature, matchedPattern: matched?.source };
}

// ---------------------------------------------------------------------------
// Always-on framework-runtime PROMOTION table (declarative)
// ---------------------------------------------------------------------------

/**
 * The mirror image of the feature-precondition DEMOTION gate above. Some
 * framework CVEs live in code that is *unconditionally* on the request path of
 * any deployed web app — an embedded servlet container's request parser /
 * default servlet, Spring MVC's always-registered static-resource handler — or
 * that executes at every web-app *startup* (a predictable temp dir created
 * during boot). The classifier otherwise buries such a CVE at `module`
 * (depscore weight 0.5, effectively hidden behind the reachable findings) even
 * though it is genuinely exploitable on ordinary traffic. That is a silence
 * FALSE-NEGATIVE — a real, reachable vuln the engine hides.
 *
 * Surfaced by the M4 reachability corpus on spring-petclinic (a real Spring
 * app, 17 HTTP entry points): tomcat-embed-core's request-parser + default-
 * servlet CVEs land at `module` because petclinic never `import`s
 * `org.apache.catalina`, so the "transitive + not first-party-imported"
 * heuristic (and the embedded-runtime floor) can only reach `module` — yet the
 * servlet container processes EVERY request.
 *
 * This table PROMOTES such a `module` finding to a visible tier when ALL hold:
 *   - the finding's dependency NAME matches an `owners` token (anchors the row
 *     to the package that actually owns the always-on surface — the servlet
 *     container's connector, spring-web's ResourceHttpRequestHandler,
 *     spring-boot's startup), AND
 *   - the advisory SUMMARY matches one of `summary` (names the always-on
 *     class: "request smuggling"/"HTTP/1.1"/request-line parsing, "open
 *     redirect"/URL-normalization/default-servlet, "static resource"/
 *     "ResourceHttpRequestHandler"/"cache poisoning", "temporary directory" at
 *     startup), AND
 *   - the per-row `requires(signals)` precondition holds (an extension point;
 *     the current always-on rows are unconditional — the runtime truly is
 *     always on), AND
 *   - (checked by the CALLER, not here) the project is a DEPLOYED WEB APP —
 *     >= 1 HTTP-route entry point was detected for this run.
 *
 * SAFETY (this is the RISKY direction — over-promotion manufactures NOISE, the
 * opposite failure to a wrongful demotion):
 *   - Only well-defined always-on classes named by owner+summary are listed. A
 *     generic framework CVE that names no always-on surface matches no row and
 *     stays `module`. When in doubt we LEAVE it at module.
 *   - The owner+summary anchoring is disjoint BY CONSTRUCTION from the
 *     DEMOTION table's feature-gated summaries (WebSocket, AJP, HTTP/2, WebDAV,
 *     cipher, DIGEST auth, security constraint, realm, …): an always-on summary
 *     never names a gated feature, so a feature-gated CVE can never match a
 *     promotion row. The classifier additionally REFUSES to promote any finding
 *     the demotion gate would silence (belt-and-suspenders — see
 *     reachability.ts), which also covers the "feature-present ⇒ genuinely
 *     reachable ⇒ promote" case correctly.
 *   - `promoteTo` is capped at `data_flow` — never `confirmed` (that tier is
 *     reserved for a proven taint flow). Servlet-container request-parser +
 *     MVC resource-handler CVEs promote to `data_flow`; startup-only CVEs to
 *     `function`.
 *   - `threatTag` records an exploit precondition the bare request path does
 *     NOT satisfy (a fronting proxy for request smuggling, a local co-tenant
 *     for the predictable-temp-dir race) so depscore can stay honest about
 *     findings that need more than a single ordinary HTTP request.
 *   - Java/Spring owners first; the shape generalizes by adding rows.
 */
export interface AlwaysOnRuntime {
  /** Stable sink id, surfaced in `reachability_details.reason`. */
  sink: string;
  /** Promote only when the dependency NAME includes one of these lowercased tokens. */
  owners: string[];
  /** Promote only when the advisory SUMMARY matches one of these. */
  summary: RegExp[];
  /** The tier to promote to. Never `confirmed` (that needs a proven flow). */
  promoteTo: 'function' | 'data_flow';
  /**
   * Extra per-row precondition on the project signals. The current always-on
   * rows are unconditional (`() => true`) — the runtime truly is always on —
   * but the hook lets a future row require a signal without widening the table
   * shape. Receives an empty (unrecognized) signals object when none were
   * gathered (non-Maven), so a predicate MUST treat "no signal" as its safe
   * default.
   */
  requires: (s: SpringFeatureSignals) => boolean;
  /**
   * An exploit precondition the bare request path does not satisfy (surfaced as
   * `reachability_details.threat_tag`). Present ⇒ depscore should discount the
   * finding; absent ⇒ directly exploitable on ordinary traffic.
   */
  threatTag?: string;
}

export const ALWAYS_ON_RUNTIME: AlwaysOnRuntime[] = [
  // --- Embedded servlet container: HTTP/1.1 request smuggling / desync ---
  // The connector parses every request; a smuggling/desync bug is only
  // exploitable behind a fronting proxy / LB that disagrees with the origin on
  // message framing, hence the threat tag.
  {
    sink: 'servlet-container-request-smuggling',
    owners: ['tomcat', 'jetty', 'undertow'],
    summary: [
      /request\s+smuggl/i,
      /http[\s/]?1\.1/i,
      /transfer[- ]?encoding/i,
      /\bchunked\b/i,
      /\bdesync/i,
    ],
    promoteTo: 'data_flow',
    requires: () => true,
    threatTag: 'requires_fronting_proxy',
  },
  // --- Embedded servlet container: generic connector / request parsing ---
  // Request-line / header / URI parsing in the connector is on every request
  // and directly reachable (no proxy precondition).
  {
    sink: 'servlet-container-request-parser',
    owners: ['tomcat', 'jetty', 'undertow'],
    summary: [
      /request\s+(line|header|uri|target|parsing|processing)/i,
      /http\s+connector/i,
      /servlet\s+container/i,
      /\bcoyote\b/i,
    ],
    promoteTo: 'data_flow',
    requires: () => true,
  },
  // --- Embedded servlet container: default servlet URL normalization ---
  // The default servlet normalizes every static-path URL; a normalization bug
  // yields open redirect / path confusion on the ordinary request path.
  {
    sink: 'servlet-default-servlet-url-normalization',
    owners: ['tomcat', 'jetty', 'undertow'],
    summary: [/open[\s-]?redirect/i, /url\s+normaliz/i, /path\s+normaliz/i, /default\s+servlet/i],
    promoteTo: 'data_flow',
    requires: () => true,
  },
  // --- Spring MVC static-resource handler (registered by default) ---
  // ResourceHttpRequestHandler serves /static, /public and webjars on
  // (nearly) every layout render; on by default in any Spring MVC / Boot web
  // app. Anchored to resource-serving terms so a websocket/etc. spring-web CVE
  // never matches.
  {
    sink: 'spring-mvc-resource-handler',
    owners: ['spring-web'],
    summary: [
      /static\s+resource/i,
      /resourcehttprequesthandler/i,
      /resource\s*handler/i,
      /cache\s*poison/i,
      /\bwebjar/i,
    ],
    promoteTo: 'data_flow',
    requires: () => true,
  },
  // --- Spring Boot web-app startup (predictable temp dir at boot) ---
  // Executes once at every web-app startup. Promote only to `function` (it is
  // not per-request) and tag the local co-tenant precondition the temp-dir race
  // needs.
  {
    sink: 'spring-boot-startup-tempdir',
    owners: ['spring-boot'],
    summary: [
      /temp(orary)?\s*(dir|directory|file)/i,
      /predictable\s+(temp|directory|file|location)/i,
      /temp[\s-]?dir/i,
    ],
    promoteTo: 'function',
    requires: () => true,
    threatTag: 'requires_local_cotenant',
  },
  // --- jackson-core BLOCKING parser reached via an exposed actuator JSON-body
  //     write endpoint (POST /actuator/loggers/{name} takes an attacker JSON
  //     body → JsonFactory.createParser(InputStream) → the blocking parser) ---
  // Deliberately NARROW so it recovers exactly one silence-FN without dragging
  // the sibling jackson CVEs along:
  //   - owner `jackson-core` — NOT `jackson-databind` (its deserialization CVEs
  //     need an untrusted `@RequestBody` polymorphic bind this app never does),
  //   - summary must name the BLOCKING parser / document-length constraint —
  //     jackson-core CVE-2026-29062 names `UTF8DataInputJsonParser` (DataInput)
  //     and GHSA-72hv names the Async parser; neither says "blocking", so
  //     neither matches,
  //   - `requires` gates on an actuator JSON-body endpoint actually being
  //     exposed (see actuatorWriteJsonEndpointExposed) — no exposed loggers
  //     endpoint ⇒ no promotion.
  // Capped at `function` (not data_flow): the vulnerable class is on a specific
  // exposed endpoint rather than on *every* request, and there is no proven
  // taint flow — but it is clearly above the hidden `module` tier.
  {
    sink: 'jackson-core-blocking-parser-actuator',
    owners: ['jackson-core'],
    summary: [
      /document[\s-]?length[\s\S]{0,40}blocking/i,
      /blocking[\s\S]{0,40}pars/i,
    ],
    promoteTo: 'function',
    requires: (s) => actuatorWriteJsonEndpointExposed(s),
  },
];

export interface AlwaysOnPromotionResult {
  promote: boolean;
  sink?: string;
  promoteTo?: 'function' | 'data_flow';
  matchedPattern?: string;
  threatTag?: string;
}

/**
 * Decide whether a `module` finding should be PROMOTED to a visible tier
 * because its CVE lives in always-on framework-runtime code AND the project is
 * a deployed web app. Pure — unit-tested directly.
 *
 * Returns `{ promote: false }` unless:
 *   - `hasHttpRouteEntryPoint` is true (the project is a deployed web app — a
 *     library repo with no HTTP route never earns a promotion), AND
 *   - the finding has both a dependency name and an advisory summary, AND
 *   - some `ALWAYS_ON_RUNTIME` row's owner matches the dep AND its summary
 *     matches AND its `requires(signals)` precondition holds.
 *
 * COMPOSITION NOTE: refusing to promote a finding the feature-precondition
 * DEMOTION gate would silence is the CALLER's responsibility — the classifier
 * evaluates the demotion FIRST and only offers still-`module` findings here.
 * This function models the promotion itself and nothing else.
 */
export function evaluateAlwaysOnRuntimePromotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  hasHttpRouteEntryPoint: boolean;
  signals?: SpringFeatureSignals | null;
}): AlwaysOnPromotionResult {
  const { depName, summary, hasHttpRouteEntryPoint } = input;
  // Web-app gate: no HTTP-route entry point ⇒ nothing is on a request path;
  // a library / CLI repo must never earn a promotion.
  if (!hasHttpRouteEntryPoint) return { promote: false };
  if (!depName || !summary) return { promote: false };
  const dep = depName.toLowerCase();
  // A missing signals object (non-Maven, or tests) resolves to the empty
  // "cannot reason" sentinel; the current rows' `requires` ignore it.
  const signals = input.signals ?? emptySpringFeatureSignals();
  for (const row of ALWAYS_ON_RUNTIME) {
    if (!row.owners.some((o) => dep.includes(o))) continue;
    const matched = row.summary.find((re) => re.test(summary));
    if (!matched) continue;
    if (!row.requires(signals)) continue;
    return {
      promote: true,
      sink: row.sink,
      promoteTo: row.promoteTo,
      matchedPattern: matched.source,
      threatTag: row.threatTag,
    };
  }
  return { promote: false };
}

// ---------------------------------------------------------------------------
// Project-feature detector (reads the workspace)
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'target', 'build', 'dist', '.gradle', 'out', 'bin',
  'vendor', '.idea', '.mvn', 'coverage',
]);

// Bounds so a huge monorepo can't blow the step budget. Petclinic-scale
// projects finish far under these; a project that exceeds them yields
// `truncated = true`, which downgrades code-signal absences to `unknown`
// (no demotion) rather than risking a false absence.
const MAX_DIR_DEPTH = 12;
const MAX_JAVA_FILES = 6000;
const MAX_JAVA_BYTES = 40 * 1024 * 1024;
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;

function safeRead(file: string, limitBytes: number): string | null {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > limitBytes) return null;
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Walk `root` (bounded) gathering the pom / config / java / CF-manifest
 * signals the feature detectors read. Never throws — an unreadable tree yields
 * empty (unrecognized) signals, which refuses every demotion.
 */
export function gatherSpringFeatureSignals(root: string | undefined): SpringFeatureSignals {
  const signals = emptySpringFeatureSignals();
  if (!root) return signals;
  try {
    if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) return signals;
  } catch {
    return signals;
  }

  const pomArtifacts = new Set<string>();
  const configParts: string[] = [];
  const codeParts: string[] = [];
  let javaFileCount = 0;
  let javaBytes = 0;
  let configBytes = 0;
  let truncated = false;

  // CloudFoundry deploy manifest at the repo root.
  for (const mf of ['manifest.yml', 'manifest.yaml']) {
    const c = safeRead(path.join(root, mf), MAX_CONFIG_BYTES);
    if (c && /^\s*applications\s*:/m.test(c)) signals.hasCloudFoundryManifest = true;
  }

  const artifactRe = /<artifactId>\s*([^<\s][^<]*?)\s*<\/artifactId>/gi;

  const walk = (dir: string, depth: number): void => {
    if (depth > MAX_DIR_DEPTH) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        walk(full, depth + 1);
        continue;
      }
      if (!ent.isFile()) continue;
      const lower = ent.name.toLowerCase();
      const fullLower = full.toLowerCase().replace(/\\/g, '/');

      if (lower === 'pom.xml') {
        const c = safeRead(full, MAX_CONFIG_BYTES);
        if (c) {
          let m: RegExpExecArray | null;
          artifactRe.lastIndex = 0;
          while ((m = artifactRe.exec(c)) !== null) {
            pomArtifacts.add(m[1].trim().toLowerCase());
          }
        }
        continue;
      }

      if (
        lower === 'web.xml' ||
        (/^application.*\.(properties|ya?ml)$/.test(lower))
      ) {
        if (configBytes < MAX_CONFIG_BYTES) {
          const c = safeRead(full, MAX_CONFIG_BYTES);
          if (c) {
            configParts.push(c.toLowerCase());
            configBytes += c.length;
          }
        }
        continue;
      }

      if (lower.endsWith('.java')) {
        // Skip test sources — a feature exercised only by tests is not on the
        // production request path (and counting it as "present" would just
        // block a demotion anyway, the safe direction).
        if (fullLower.includes('/src/test/') || fullLower.includes('/test/java/')) continue;
        if (javaFileCount >= MAX_JAVA_FILES || javaBytes >= MAX_JAVA_BYTES) {
          truncated = true;
          continue;
        }
        const c = safeRead(full, MAX_JAVA_BYTES);
        if (c) {
          codeParts.push(c.toLowerCase());
          javaFileCount += 1;
          javaBytes += c.length;
        }
      }
    }
  };

  walk(root, 0);

  signals.pomArtifacts = pomArtifacts;
  signals.configText = configParts.join('\n');
  signals.codeText = codeParts.join('\n');
  signals.truncated = truncated;
  signals.recognized = pomArtifacts.size > 0;
  return signals;
}
