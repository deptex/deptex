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
