/**
 * PHP / Symfony framework-mediated reachability model — the composer-ecosystem
 * MIRROR of `reachability-feature-preconditions.ts` (Java / Spring / Maven).
 *
 * The reachability classifier caps a transitive framework dependency at
 * `module` with `verdict = "callgraph_reached_transitive"` whenever the taint
 * callgraph traced an edge into the framework. For a Symfony app the coarse PHP
 * callgraph reaches nearly every component, so ALL of a Symfony project's
 * dependency-CVEs land at `module` (hidden-but-unsure) — the exact blindness the
 * Java model fixed for Spring, recurring identically in PHP:
 *
 *   - Framework code UNCONDITIONALLY on the request path of any Symfony app that
 *     has routes (http-foundation's Request parsing → an authorization-bypass
 *     CVE; the security firewall's login path when a firewall + form_login are
 *     configured) is UNDER-REACHED (buried at `module` when it should be VISIBLE).
 *   - CVEs gated behind a feature symfony never enables (the Twig SANDBOX / SSTI
 *     cluster, untrusted-YAML parsing, an x509 firewall, the `unanimous` decision
 *     strategy) or living in a package that is DEV-ONLY (never shipped to prod —
 *     symfony/process pulled only by php-cs-fixer, dom-crawler by browser-kit)
 *     are OVER-KEPT at `module` when they are provably `unreachable`.
 *
 * This module is the generalizable, data-driven fix, structured exactly like the
 * Java one:
 *
 *   1. `FEATURE_PRECONDITIONS` — declarative advisory→required-feature table
 *      (owner-anchored + summary-anchored) that DEMOTES `module`→`unreachable`
 *      when the feature is provably absent.
 *   2. `ALWAYS_ON_RUNTIME` — declarative always-on-request-path table that
 *      PROMOTES `module`→visible for a deployed web app (>= 1 HTTP route).
 *   3. A DEV-ONLY package demotion (`evaluateSymfonyDevOnlyDemotion`) that reads
 *      `composer.lock`'s `packages-dev` authoritatively — the strongest lever,
 *      needing no summary match. (The classifier's existing dev-scope check
 *      misses these because the coarse PHP callgraph re-stamps them
 *      `callgraph_reached_transitive`, overriding the SBOM scope, and composer's
 *      TRANSITIVE dev-ness — process via php-cs-fixer — isn't always propagated
 *      into the SBOM scope. `composer.lock` is the ground truth.)
 *   4. `gatherSymfonyFeatureSignals` — reads the workspace (composer.json/.lock,
 *      config/**, security.yaml, src/**, templates/**, public/index.php).
 *
 * SAFETY (identical doctrine to the Java model — a wrongful DEMOTION silences a
 * real vuln, the worst outcome):
 *   - DEMOTE only when the required feature is *provably absent* (the detector
 *     read the project AND found no enabling signal). Any ambiguity → `unknown`,
 *     never `absent`: an unrecognized project (composer.json not parsed / not a
 *     Symfony app), or a code scan that hit its byte cap, refuses every demotion.
 *   - The detector is LIBERAL about "present" (when in doubt it reports the
 *     feature enabled, which BLOCKS demotion); confident only about absence.
 *   - PROMOTE is the risky direction (over-promotion manufactures noise): only
 *     well-defined always-on classes named by owner+summary are promoted, capped
 *     at `data_flow`, and only for a deployed web app (checked by the CALLER via
 *     the HTTP-route-entry-point signal).
 *   - Composer / Symfony only. Other ecosystems get no signals → nothing moves.
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Project-feature signals
// ---------------------------------------------------------------------------

export interface SymfonyFeatureSignals {
  /**
   * True once composer.json was parsed AND this is recognizably a Symfony app
   * (`symfony/framework-bundle` present in composer.json require or the lock).
   * When false the detector cannot prove any feature absent, so every demotion
   * / promotion is refused — the "cannot reason" sentinel.
   */
  recognized: boolean;
  /**
   * True when the `.php` / `.twig` scan hit its file/byte cap. A code signal we
   * didn't read might exist, so features whose absence relies on scanning code
   * resolve to `unknown` (never `absent`) when this is set.
   */
  truncated: boolean;
  /** Lowercased `composer.lock` → `packages[].name` (production tree). */
  lockProd: Set<string>;
  /** Lowercased `composer.lock` → `packages-dev[].name` (never shipped to prod). */
  lockDev: Set<string>;
  /** Lowercased concat of `config/**\/*.{yaml,yml}` + `.env` + `config/bundles.php`. */
  configText: string;
  /** Lowercased `config/packages/security.yaml` (+ any `security.yaml`). */
  securityYamlText: string;
  /** Lowercased concat of `src/**\/*.php` + `templates/**\/*.twig` + `public/index.php`. */
  codeText: string;
}

export type FeaturePresence = 'present' | 'absent' | 'unknown';

/** Empty (nothing recognized) signals — the "cannot reason" sentinel. */
export function emptySymfonyFeatureSignals(): SymfonyFeatureSignals {
  return {
    recognized: false,
    truncated: false,
    lockProd: new Set(),
    lockDev: new Set(),
    configText: '',
    securityYamlText: '',
    codeText: '',
  };
}

// ---------------------------------------------------------------------------
// Feature-detect helpers (LIBERAL about "present", confident only about absence)
// ---------------------------------------------------------------------------

function textIncludes(hay: string, subs: string[]): boolean {
  return subs.some((x) => hay.includes(x));
}

/**
 * Resolve a boolean "present" signal into a `FeaturePresence`. When absent AND
 * the code scan was truncated (a signal may have been missed), return `unknown`
 * — never `absent` — so a demotion is refused.
 */
function resolve(present: boolean, s: SymfonyFeatureSignals): FeaturePresence {
  if (present) return 'present';
  if (s.truncated) return 'unknown';
  return 'absent';
}

/** The Twig SANDBOX (SecurityPolicy) is wired up somewhere in the app. */
function twigSandboxEnabled(s: SymfonyFeatureSignals): boolean {
  return (
    textIncludes(s.codeText, [
      'sandboxextension',
      'securitypolicy',
      '\\twig\\sandbox',
      'twig\\extension\\sandboxextension',
    ]) ||
    /\{%\s*sandbox/.test(s.codeText) ||
    // a `twig: sandbox:` config block, or a `sandboxed_environment` service
    textIncludes(s.configText, ['sandboxed_environment']) ||
    /sandbox\s*:/.test(s.configText)
  );
}

/** A security firewall is configured (any non-`security: false` firewall). */
function firewallConfigured(s: SymfonyFeatureSignals): boolean {
  return /firewalls\s*:/.test(s.securityYamlText) || textIncludes(s.securityYamlText, ['form_login', 'access_control']);
}

/** The firewall uses form_login (the interactive login path). */
function formLoginConfigured(s: SymfonyFeatureSignals): boolean {
  return s.securityYamlText.includes('form_login');
}

/** `access_control:` rules exist (the firewall guards protected routes). */
function accessControlConfigured(s: SymfonyFeatureSignals): boolean {
  return s.securityYamlText.includes('access_control');
}

/** An x509 authenticator is configured on a firewall. */
function x509Configured(s: SymfonyFeatureSignals): boolean {
  return /\bx509\b/.test(s.securityYamlText) || /\bx\.509\b/.test(s.securityYamlText);
}

/** The `unanimous` access-decision strategy is configured. */
function unanimousStrategyConfigured(s: SymfonyFeatureSignals): boolean {
  return s.securityYamlText.includes('unanimous') || s.configText.includes('unanimous');
}

/**
 * The app parses UNTRUSTED YAML at runtime. Symfony parses its own trusted
 * config through the framework, never via a `Yaml::parse` on request data, so
 * the presence of an explicit parse call in first-party code is the signal.
 * Liberal: ANY parse call blocks the demotion (safe direction).
 */
function yamlParsesUntrusted(s: SymfonyFeatureSignals): boolean {
  return textIncludes(s.codeText, [
    'yaml::parse(',
    'yaml_parse(',
    '->parsefile(',
    'yaml::parsefile(',
    'new parser(',
  ]);
}

/** The Symfony HTTP reverse-proxy cache wraps the kernel. */
function httpCacheKernelEnabled(s: SymfonyFeatureSignals): boolean {
  return (
    textIncludes(s.codeText, ['new httpcache(', 'httpcache($kernel', 'extends httpcache']) ||
    s.lockProd.has('symfony/http-cache')
  );
}

/** A PDO-backed cache adapter/pool is configured. */
function pdoCacheAdapterConfigured(s: SymfonyFeatureSignals): boolean {
  return (
    textIncludes(s.configText, ['cache.adapter.pdo', 'pdoadapter']) ||
    textIncludes(s.codeText, ['pdoadapter', 'doctrinedbaladapter'])
  );
}

/** The app composes email via symfony/mailer or symfony/mime `Email`. */
function symfonyMailerPresent(s: SymfonyFeatureSignals): boolean {
  return (
    s.lockProd.has('symfony/mailer') ||
    textIncludes(s.codeText, [
      'symfony\\component\\mime\\email',
      'symfony\\component\\mime\\message',
      'mailerinterface',
      '->send(new email',
      'new email(',
    ])
  );
}

/**
 * The WebProfilerBundle is enabled in the PRODUCTION environment. The profiler
 * (and its Twig HtmlDumper / CodeExtension debug filters) only render when the
 * bundle runs in prod; `config/bundles.php` gates it. Symfony's standard layout
 * ships it as `['dev' => true, 'test' => true]` — dev/test only. Present iff the
 * bundle's env array names `prod` or `all`; absent when it lists only dev/test
 * (or the bundle isn't registered at all). Read from `config/bundles.php` (which
 * the detector folds into `configText`).
 */
function profilerEnabledInProd(s: SymfonyFeatureSignals): boolean {
  const m = s.configText.match(/webprofilerbundle::class\s*=>\s*\[([^\]]*)\]/);
  if (!m) return false; // not registered → not in prod
  const envs = m[1];
  return /['"]prod['"]/.test(envs) || /['"]all['"]/.test(envs);
}

/**
 * The app renders a Twig template whose NAME is user/variable-controlled (the
 * precondition for the template-name-injection / load-outside-dir / `{% use %}`
 * code-injection CVEs). LIBERAL about "present" — any dynamic-render hint blocks
 * the demotion (the safe direction; a missed dynamic name would be a silence-FN).
 * Symfony/demo renders only string-literal names (`->render('blog/index.twig')`),
 * so this is absent for it.
 */
function userControlledTemplateName(s: SymfonyFeatureSignals): boolean {
  const c = s.codeText;
  return (
    // a render whose FIRST argument is a bare variable — `->render($t)`.
    /->render(view|block)?\s*\(\s*\$/.test(c) ||
    // a render whose template name is a string CONCATENATED with something
    // (a variable / expression) — `->render('blog/index.'.$_format.'.twig')`.
    // symfony/demo does exactly this with the request `_format`, which makes
    // the template path request-influenced (correctly blocks the demotion).
    /->render(view|block)?\s*\(\s*['"][^'"\n]*['"]\s*\.\s*[^,)\n]*\$/.test(c) ||
    /->createtemplate\s*\(/.test(c) ||
    // a Twig-SPECIFIC loader/render with a variable — NOT the generic `->load(`
    // which also matches Symfony's config/routing loaders (`$loader->load(
    // $confDir…)` in every Kernel.php) and would falsely block every Symfony app.
    /->loadtemplate\s*\(\s*\$/.test(c) ||
    /\$twig\s*->\s*(render|load)\s*\(\s*\$/.test(c) ||
    // a render whose first argument is not a string literal (a constant /
    // `self::TEMPLATE` / method call) — conservative catch-all for a computed
    // name. Requires a letter/`\` right after `(` (a string literal starts with
    // a quote, so `->render('x')` never trips this).
    /->render(view|block)?\s*\(\s*[a-z_\\]/.test(c)
  );
}

// ---------------------------------------------------------------------------
// FEATURE-PRECONDITION table (DEMOTE module → unreachable when provably absent)
// ---------------------------------------------------------------------------

interface FeaturePrecondition {
  feature: string;
  /** Demote only when the finding's dependency NAME includes one of these. */
  owners: string[];
  /** Demote only when the advisory SUMMARY matches one of these. */
  summary: RegExp[];
  /** Is the feature enabled in the scanned project? */
  detect: (s: SymfonyFeatureSignals) => FeaturePresence;
}

export const FEATURE_PRECONDITIONS: FeaturePrecondition[] = [
  // --- Twig sandbox / SSTI cluster (owner: twig). The sandbox is an opt-in
  //     SecurityPolicy; symfony/demo never enables it, so every "sandbox
  //     bypass" CVE is provably unreachable. ---
  {
    feature: 'twig-sandbox',
    owners: ['twig'],
    summary: [/sandbox/i],
    detect: (s) => resolve(twigSandboxEnabled(s), s),
  },
  // --- Untrusted-YAML parsing (owner: symfony/yaml). Every yaml-component CVE
  //     (Billion-Laughs, parser ReDoS, hardened untrusted parse) requires
  //     feeding attacker-controlled YAML to the parser. Symfony parses only its
  //     own trusted config; a first-party `Yaml::parse` call is the signal.
  //     Owner-anchored to the yaml component + gated on the untrusted-parse
  //     precondition, so summary phrasing (which rarely says "yaml") is broad. ---
  {
    feature: 'symfony-yaml-untrusted-parse',
    owners: ['yaml'],
    summary: [
      /yaml/i,
      /parse/i,
      /resource consumption/i,
      /billion laughs/i,
      /\bredos\b/i,
      /denial of service/i,
      /untrusted/i,
      /entity expansion/i,
      /nested/i,
    ],
    detect: (s) => resolve(yamlParsesUntrusted(s), s),
  },
  // --- x509 firewall authenticator (owner: security-*). ---
  {
    feature: 'symfony-security-x509',
    owners: ['security-http', 'security-core', 'security-bundle', 'security'],
    summary: [/x509/i, /x\.509/i],
    detect: (s) => resolve(x509Configured(s), s),
  },
  // --- `unanimous` access-decision strategy (owner: security-*). ---
  {
    feature: 'symfony-security-unanimous',
    owners: ['security-http', 'security-core', 'security-bundle', 'security'],
    summary: [/unanimous/i],
    detect: (s) => resolve(unanimousStrategyConfigured(s), s),
  },
  // --- HttpCache reverse proxy (owner: http-kernel). The cookie-in-cache CVE
  //     only bites when the kernel is wrapped in Symfony's HttpCache. ---
  {
    feature: 'symfony-httpcache',
    owners: ['http-kernel'],
    summary: [/httpcache/i, /http\s*cache/i, /reverse proxy/i, /cache poison/i],
    detect: (s) => resolve(httpCacheKernelEnabled(s), s),
  },
  // --- PDO cache adapter (owner: cache). SQLi in PdoAdapter::doClear needs a
  //     PDO-backed cache pool; the default filesystem adapter is unaffected. ---
  {
    feature: 'symfony-cache-pdo-adapter',
    owners: ['cache'],
    summary: [/pdoadapter/i, /pdo adapter/i, /sql injection/i, /doclear/i],
    detect: (s) => resolve(pdoCacheAdapterConfigured(s), s),
  },
  // --- symfony/mime email header injection (owner: mime). The vulnerable path
  //     is email COMPOSITION via symfony/mailer + Mime\Email; an app that sends
  //     mail some other way (SwiftMailer) never reaches it. Lower-confidence
  //     (prod-tree dep, rests on a usage signal not dev-tree provenance) — the
  //     LIBERAL `symfonyMailerPresent` keeps it at module on any doubt. ---
  {
    feature: 'symfony-mime-mailer',
    owners: ['mime'],
    summary: [/email header/i, /header injection/i, /smtp command/i, /crlf/i, /address/i],
    detect: (s) => resolve(symfonyMailerPresent(s), s),
  },
  // --- Twig profiler / debug filters (owners: twig, twig-bridge). The profiler
  //     HtmlDumper XSS + the twig-bridge CodeExtension XSS only render when the
  //     WebProfilerBundle runs in prod; symfony ships it dev/test-only. ---
  {
    feature: 'twig-profiler',
    owners: ['twig', 'twig-bridge'],
    summary: [/profiler/i, /htmldumper/i, /codeextension/i],
    detect: (s) => resolve(profilerEnabledInProd(s), s),
  },
  // --- Twig user-controlled template NAME (owner: twig). The load-outside-dir,
  //     `_self` / `{% use %}` code-injection CVEs need an attacker-controlled
  //     template name; an app that renders only static names is unaffected. ---
  {
    feature: 'twig-user-controlled-template-name',
    owners: ['twig'],
    summary: [
      /template\s+(name|outside|directory|loader|path)/i,
      /\{%\s*use/i,
      /_self/i,
      /code injection/i,
      /arbitrary (code|template)/i,
    ],
    detect: (s) => resolve(userControlledTemplateName(s), s),
  },
  // --- monolog-bridge `server:log` CLI listener (owner: monolog-bridge). The
  //     unauthenticated-deserialization sink lives in the `bin/console
  //     server:log` command — a local dev tool never on any HTTP request path,
  //     so it is structurally unreachable for a production scan. ---
  {
    feature: 'symfony-monolog-serverlog',
    owners: ['monolog-bridge'],
    summary: [/server:?log/i, /serverlog/i, /console.*(listen|log)/i],
    detect: () => 'absent',
  },
];

export interface FeatureDemotionResult {
  demote: boolean;
  feature?: string;
  matchedPattern?: string;
}

/**
 * Decide whether a `module` / `callgraph_reached_transitive` composer finding
 * should be demoted to `unreachable` because the Symfony feature its CVE
 * requires is PROVABLY ABSENT. Pure — unit-tested directly.
 *
 * Returns `{ demote: false }` unless signals are recognized, the finding has a
 * dep name + summary, at least one owner+summary row matches, AND EVERY matching
 * row's feature is provably `absent` (a single `present`/`unknown` aborts).
 */
export function evaluateSymfonyFeaturePreconditionDemotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  signals: SymfonyFeatureSignals | null | undefined;
}): FeatureDemotionResult {
  const { depName, summary, signals } = input;
  if (!signals || !signals.recognized) return { demote: false };
  if (!depName || !summary) return { demote: false };

  const dep = depName.toLowerCase();
  const applicable = FEATURE_PRECONDITIONS.filter(
    (fp) => fp.owners.some((o) => dep.includes(o)) && fp.summary.some((re) => re.test(summary)),
  );
  if (applicable.length === 0) return { demote: false };

  let chosen: FeaturePrecondition | undefined;
  for (const fp of applicable) {
    if (fp.detect(signals) !== 'absent') return { demote: false };
    if (!chosen) chosen = fp;
  }
  const matched = chosen!.summary.find((re) => re.test(summary));
  return { demote: true, feature: chosen!.feature, matchedPattern: matched?.source };
}

// ---------------------------------------------------------------------------
// DEV-ONLY package demotion (composer.lock packages-dev) — the strongest lever
// ---------------------------------------------------------------------------

export interface DevOnlyDemotionResult {
  demote: boolean;
  package?: string;
}

/**
 * Demote to `unreachable` when the finding's package is provably DEV-ONLY — it
 * appears in `composer.lock`'s `packages-dev` and NOT in `packages`, so it is
 * never installed in a production deployment (`composer install --no-dev`).
 * Needs no summary match — the composer analog of the Java "dev/test scope"
 * demotion, but read from the lockfile because the coarse PHP callgraph
 * overrides the SBOM scope for these transitive dev deps.
 *
 * `packageName` is the full `vendor/name` (e.g. `symfony/process`). Falls back
 * to a trailing-segment match so a short `depName` still resolves.
 */
export function evaluateSymfonyDevOnlyDemotion(input: {
  packageName: string | null | undefined;
  signals: SymfonyFeatureSignals | null | undefined;
}): DevOnlyDemotionResult {
  const { packageName, signals } = input;
  if (!signals || !signals.recognized) return { demote: false };
  if (!packageName) return { demote: false };
  const pkg = packageName.toLowerCase();

  const inSet = (set: Set<string>): boolean => {
    if (set.has(pkg)) return true;
    // trailing-segment fallback: match `symfony/process` when given `process`.
    for (const e of set) if (e === pkg || e.endsWith('/' + pkg)) return true;
    return false;
  };

  if (inSet(signals.lockDev) && !inSet(signals.lockProd)) {
    return { demote: true, package: pkg };
  }
  return { demote: false };
}

// ---------------------------------------------------------------------------
// ALWAYS-ON framework-runtime PROMOTION table (module → visible)
// ---------------------------------------------------------------------------

export interface AlwaysOnRuntime {
  sink: string;
  owners: string[];
  summary: RegExp[];
  promoteTo: 'function' | 'data_flow';
  /** Extra per-row precondition on the project signals. */
  requires: (s: SymfonyFeatureSignals) => boolean;
  /** Exploit precondition the bare request path does not satisfy (depscore hint). */
  threatTag?: string;
}

export const ALWAYS_ON_RUNTIME: AlwaysOnRuntime[] = [
  // --- http-foundation Request parsing: on EVERY request for any Symfony app
  //     that has routes. An authorization-bypass / PATH_INFO parsing CVE here
  //     directly weakens the access_control the firewall enforces. ---
  {
    sink: 'symfony-http-foundation-request-parser',
    owners: ['http-foundation'],
    summary: [
      /path_?info/i,
      /authorization bypass/i,
      /access control/i,
      /request\s+(parsing|pars|line|header|uri|target|processing)/i,
    ],
    promoteTo: 'data_flow',
    requires: () => true,
    threatTag: 'requires_protected_route',
  },
  // --- Security firewall login path: exercised on every authentication when a
  //     firewall + form_login (or access_control) is configured. Session-
  //     fixation of the CSRF token, user-enumeration, and firewall-bypass CVEs
  //     all live on this always-on path. Promote only to `function` (a specific
  //     auth path, not literally every request) and only when the firewall is
  //     actually configured. ---
  {
    sink: 'symfony-security-firewall-login',
    owners: ['security-bundle', 'security-core', 'security-guard', 'security-http', 'security'],
    summary: [
      /session fixation/i,
      /\bcsrf\b/i,
      /user enumeration/i,
      /failure_forward/i,
      /firewall bypass/i,
      /authentication bypass/i,
    ],
    promoteTo: 'function',
    requires: (s) => firewallConfigured(s) && (formLoginConfigured(s) || accessControlConfigured(s)),
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
 * Decide whether a `module` composer finding should be PROMOTED to a visible
 * tier because its CVE lives in always-on Symfony-runtime code AND the project
 * is a deployed web app. Pure — unit-tested directly.
 *
 * COMPOSITION: refusing to promote a finding the DEMOTION gates would silence is
 * the CALLER's responsibility (it runs the demotions first and only offers
 * still-`module` findings here). This models the promotion itself.
 */
export function evaluateSymfonyAlwaysOnRuntimePromotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  hasHttpRouteEntryPoint: boolean;
  signals?: SymfonyFeatureSignals | null;
}): AlwaysOnPromotionResult {
  const { depName, summary, hasHttpRouteEntryPoint } = input;
  if (!hasHttpRouteEntryPoint) return { promote: false };
  if (!depName || !summary) return { promote: false };
  const dep = depName.toLowerCase();
  const signals = input.signals ?? emptySymfonyFeatureSignals();
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
  'node_modules', '.git', 'vendor', 'var', 'build', 'dist', 'out', 'bin',
  '.idea', 'coverage', 'public/build', '.github',
]);

const MAX_DIR_DEPTH = 12;
const MAX_CODE_FILES = 8000;
const MAX_CODE_BYTES = 40 * 1024 * 1024;
const MAX_CONFIG_BYTES = 6 * 1024 * 1024;

function safeRead(file: string, limitBytes: number): string | null {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > limitBytes) return null;
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

/** Parse `composer.lock` → prod + dev package-name sets (lowercased). */
function parseComposerLock(root: string): { prod: Set<string>; dev: Set<string> } | null {
  const raw = safeRead(path.join(root, 'composer.lock'), MAX_CONFIG_BYTES);
  if (!raw) return null;
  try {
    const json = JSON.parse(raw);
    const prod = new Set<string>();
    const dev = new Set<string>();
    for (const p of Array.isArray(json.packages) ? json.packages : []) {
      if (p && typeof p.name === 'string') prod.add(p.name.toLowerCase());
    }
    for (const p of Array.isArray(json['packages-dev']) ? json['packages-dev'] : []) {
      if (p && typeof p.name === 'string') dev.add(p.name.toLowerCase());
    }
    return { prod, dev };
  } catch {
    return null;
  }
}

/** True when composer.json declares a require on `symfony/framework-bundle`. */
function composerRequiresFrameworkBundle(root: string): boolean {
  const raw = safeRead(path.join(root, 'composer.json'), MAX_CONFIG_BYTES);
  if (!raw) return false;
  try {
    const json = JSON.parse(raw);
    const req = { ...(json.require ?? {}), ...(json['require-dev'] ?? {}) };
    return Object.keys(req).some((k) => k.toLowerCase() === 'symfony/framework-bundle');
  } catch {
    // fall back to a substring probe (a malformed composer.json still tells us
    // whether this is a Symfony app).
    return raw.toLowerCase().includes('symfony/framework-bundle');
  }
}

/**
 * Walk `root` (bounded) gathering the composer / config / php / twig signals the
 * feature detectors read. Never throws — an unreadable tree yields empty
 * (unrecognized) signals, which refuses every demotion / promotion.
 */
export function gatherSymfonyFeatureSignals(root: string | undefined): SymfonyFeatureSignals {
  const signals = emptySymfonyFeatureSignals();
  if (!root) return signals;
  try {
    if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) return signals;
  } catch {
    return signals;
  }

  const lock = parseComposerLock(root);
  if (lock) {
    signals.lockProd = lock.prod;
    signals.lockDev = lock.dev;
  }
  const hasFrameworkBundle =
    composerRequiresFrameworkBundle(root) ||
    signals.lockProd.has('symfony/framework-bundle');

  const configParts: string[] = [];
  const securityParts: string[] = [];
  const codeParts: string[] = [];
  let codeFileCount = 0;
  let codeBytes = 0;
  let configBytes = 0;
  let truncated = false;

  // Root-level .env is config.
  const env = safeRead(path.join(root, '.env'), MAX_CONFIG_BYTES);
  if (env) configParts.push(env.toLowerCase());

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

      // config: yaml/yml under config/, plus bundles.php.
      const isConfigYaml =
        (lower.endsWith('.yaml') || lower.endsWith('.yml')) && fullLower.includes('/config/');
      const isBundles = lower === 'bundles.php';
      if (isConfigYaml || isBundles) {
        if (configBytes < MAX_CONFIG_BYTES) {
          const c = safeRead(full, MAX_CONFIG_BYTES);
          if (c) {
            const lc = c.toLowerCase();
            configParts.push(lc);
            configBytes += c.length;
            if (lower === 'security.yaml' || lower === 'security.yml') securityParts.push(lc);
          }
        }
        continue;
      }

      // code: first-party php under src/, twig templates, public/index.php.
      const isSrcPhp = lower.endsWith('.php') && (fullLower.includes('/src/') || lower === 'index.php');
      const isTwig = lower.endsWith('.twig');
      if (isSrcPhp || isTwig) {
        // Skip tests — a feature exercised only by tests is not on the prod path.
        if (fullLower.includes('/tests/') || fullLower.includes('/test/')) continue;
        if (codeFileCount >= MAX_CODE_FILES || codeBytes >= MAX_CODE_BYTES) {
          truncated = true;
          continue;
        }
        const c = safeRead(full, MAX_CODE_BYTES);
        if (c) {
          codeParts.push(c.toLowerCase());
          codeFileCount += 1;
          codeBytes += c.length;
        }
      }
    }
  };

  walk(root, 0);

  signals.configText = configParts.join('\n');
  signals.securityYamlText = securityParts.join('\n');
  signals.codeText = codeParts.join('\n');
  signals.truncated = truncated;
  // Recognized only for a real Symfony app (framework-bundle present) that we
  // could read a lockfile for — otherwise the model is a no-op.
  signals.recognized = hasFrameworkBundle && (signals.lockProd.size > 0 || signals.lockDev.size > 0);
  return signals;
}
