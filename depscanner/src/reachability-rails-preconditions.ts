/**
 * Ruby / Rails framework-mediated reachability model — the RubyGems-ecosystem
 * MIRROR of `reachability-feature-preconditions.ts` (Java/Spring/Maven) and
 * `reachability-symfony-preconditions.ts` (PHP/Symfony/Composer).
 *
 * The reachability classifier caps a transitive framework dependency at `module`
 * with `verdict = "callgraph_reached_transitive"` (or `transitive_of_reachable`)
 * whenever the coarse Ruby callgraph traced an edge into the gem. For a Rails app
 * the callgraph reaches nearly the whole Rails stack, so ALL of a Rails project's
 * dependency-CVEs land at `module` (hidden-but-unsure) — the exact blindness the
 * Java model fixed for Spring and the PHP model fixed for Symfony, recurring
 * identically in Ruby (measured on Discourse 2.5.0: 157/157 findings at `module`,
 * 0 shown, 0 confidently hidden):
 *
 *   - Gem code UNCONDITIONALLY on the request path of any deployed Rails app —
 *     the app server (Puma) HTTP parser, the Rack middleware stack's body/query/
 *     header parsing, ActionDispatch request handling, the HTML sanitizer Rails
 *     runs on user content (rails-html-sanitizer / loofah / sanitize / nokogiri),
 *     the JSON encoder/decoder (Oj) — is UNDER-REACHED (buried at `module` when it
 *     should be VISIBLE). Hiding a reachable stored-XSS / request-smuggling / DoS
 *     is a silence false-negative, the worst error class.
 *   - CVEs gated behind a gem FEATURE the app never uses (Rack::Static / Directory
 *     LFI when the app mounts neither; Nokogiri XSLT/Schema/XInclude when the app
 *     calls none; the Oj::Parser/Doc streaming APIs the Rails integration never
 *     touches; a Windows-only bug on a Linux deploy) or living in a gem that is
 *     DEV/TEST-ONLY (Gemfile `group :development`) are OVER-KEPT at `module` when
 *     they are provably `unreachable`.
 *
 * Structured exactly like the Java / PHP models:
 *   1. `FEATURE_PRECONDITIONS` — advisory→required-feature table (owner + summary)
 *      that DEMOTES `module`→`unreachable` when the feature is provably absent.
 *   2. `ALWAYS_ON_RUNTIME` — always-on-request-path table that PROMOTES
 *      `module`→visible for a deployed web app (>= 1 HTTP route). Each row carries
 *      an `exclude` guard so a gem that SPLITS (Rack request-parser CVEs promote,
 *      Rack::Static CVEs do not) never promotes its feature-gated siblings.
 *   3. `evaluateRailsDevOnlyDemotion` — reads the Gemfile's `:development`/`:test`/
 *      `:assets` GROUP declarations (the Ruby analog of composer.lock packages-dev
 *      / the Java dev-scope). Reads DIRECT declarations only, NOT transitive: a gem
 *      pulled transitively by a dev tool (rexml via rubocop) but ALSO required at
 *      runtime must NOT be demoted — reading only direct group membership is the
 *      safe design.
 *   4. `gatherRailsFeatureSignals` — reads Gemfile, Gemfile.lock, config/**, app/**,
 *      lib/**.
 *
 * SAFETY (identical doctrine to the Java / PHP models — a wrongful DEMOTION
 * silences a real vuln):
 *   - DEMOTE only when the required feature is *provably absent* (the detector read
 *     the project AND found no enabling signal). Any ambiguity → `unknown`, never
 *     `absent`: an unrecognized project (no Gemfile / not a Rails app) or a code
 *     scan that hit its byte cap refuses every demotion.
 *   - The detectors are LIBERAL about "present" (when in doubt they report the
 *     feature enabled, which BLOCKS demotion); confident only about absence.
 *   - PROMOTE is the risky direction (over-promotion manufactures noise): only
 *     well-defined always-on classes named by owner+summary are promoted, the
 *     `exclude` guard vetoes feature-gated siblings, and promotion only fires for a
 *     deployed web app (checked by the CALLER via the HTTP-route-entry-point
 *     signal).
 *   - RubyGems only. Other ecosystems get no signals → nothing moves.
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Project-feature signals
// ---------------------------------------------------------------------------

export interface RailsFeatureSignals {
  /**
   * True once a Gemfile / Gemfile.lock was parsed AND this is recognizably a
   * Rails app (`rails` / `railties` / `actionpack` in the gem set, or a
   * `Rails::Application` in config/application.rb). When false the detector
   * cannot prove any feature absent, so every demotion / promotion is refused —
   * the "cannot reason" sentinel.
   */
  recognized: boolean;
  /**
   * True when the `.rb` scan hit its file/byte cap. A code signal we didn't read
   * might exist, so features whose absence relies on scanning code resolve to
   * `unknown` (never `absent`) when this is set.
   */
  truncated: boolean;
  /**
   * Gem names declared DIRECTLY inside a Gemfile `:development` / `:test` /
   * `:assets` group AND nowhere at prod scope (lowercased). The dev-only lever.
   */
  devGems: Set<string>;
  /** Every gem name in Gemfile.lock (lowercased) — for feature-presence checks. */
  lockGems: Set<string>;
  /**
   * Lowercased concat of `config/**` (`*.rb` + `*.yml`) — production.rb,
   * application.rb, initializers, routes.rb, puma.rb, environments.
   */
  configText: string;
  /** Lowercased concat of first-party `app/**` + `lib/**` `*.rb`. */
  codeText: string;
  /** True when the deploy targets JRuby (Gemfile `platform: :jruby`, `.ruby-version` jruby). */
  jruby: boolean;
}

export type FeaturePresence = 'present' | 'absent' | 'unknown';

/** Empty (nothing recognized) signals — the "cannot reason" sentinel. */
export function emptyRailsFeatureSignals(): RailsFeatureSignals {
  return {
    recognized: false,
    truncated: false,
    devGems: new Set(),
    lockGems: new Set(),
    configText: '',
    codeText: '',
    jruby: false,
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
function resolve(present: boolean, s: RailsFeatureSignals): FeaturePresence {
  if (present) return 'present';
  if (s.truncated) return 'unknown';
  return 'absent';
}

/** The app calls a Nokogiri XSLT / Schema / XInclude / C14N API (feature-gated). */
function nokogiriAdvancedApiUsed(s: RailsFeatureSignals): boolean {
  return textIncludes(s.codeText, [
    'nokogiri::xslt',
    '.xslt(',
    'xslt.parse',
    'xml::schema',
    'relaxng',
    'xml::relaxng',
    'schema.from',
    'xinclude',
    'do_xinclude',
    'canonicalize',
    'c14n',
  ]);
}

/**
 * The `Rack::Static` middleware is mounted. NOTE: this is specifically
 * `Rack::Static` (the CVE's component) — NOT Rails' `public_file_server` /
 * `ActionDispatch::Static`, which is a different middleware (Rack::Files-based)
 * that the Rack::Static CVEs do not touch. Keying on the explicit mount string
 * avoids a false "present" from a dev/test env enabling public_file_server.
 */
function rackStaticMounted(s: RailsFeatureSignals): boolean {
  return textIncludes(s.configText.concat(s.codeText), ['rack::static']);
}

/** Rack::Directory (directory-listing middleware) is mounted. */
function rackDirectoryMounted(s: RailsFeatureSignals): boolean {
  return textIncludes(s.configText, ['rack::directory']) || textIncludes(s.codeText, ['rack::directory']);
}

/** Rack::CommonLogger / Rack::Lint is in the middleware stack. */
function rackCommonLoggerMounted(s: RailsFeatureSignals): boolean {
  return textIncludes(s.configText.concat(s.codeText), ['rack::commonlogger', 'rack::lint']);
}

/** The app uses the explicit Oj::Parser (SAJ) / Oj::Doc streaming APIs. */
function ojStreamingApiUsed(s: RailsFeatureSignals): boolean {
  return textIncludes(s.codeText, ['oj::parser', 'oj::doc', 'oj.saj', 'oj::saj', 'oj::scanner']);
}

/** rails-ujs / jquery_ujs client script ships with the app. */
function railsUjsPresent(s: RailsFeatureSignals): boolean {
  return textIncludes(s.configText.concat(s.codeText), [
    'rails-ujs',
    'rails_ujs',
    'jquery_ujs',
    'jquery-ujs',
    '@rails/ujs',
    'actionview/helpers/javascript', // remote: true form helpers
  ]);
}

/** The aws-sdk-s3 client-side Encryption Client is present. */
function awsS3EncryptionPresent(s: RailsFeatureSignals): boolean {
  return (
    s.lockGems.has('aws-sdk-s3-encryption') ||
    textIncludes(s.codeText, ['encryptionv2::client', 's3::encryption', 'encryptionv2client', 'aws::s3::encryption'])
  );
}

/**
 * Puma is DECLARED but never LOADED: the Gemfile pins it `require: false` and
 * nothing explicitly `require`s it (a unicorn-served app like Discourse 2.5.0
 * keeps puma as a dev-convenience dependency). Bundler.require skips
 * require-false gems, so puma's HTTP parser never runs — promoting its CVEs on
 * such an app manufactures noise (caught by the Discourse ground-truth labels,
 * 2026-07-02: 7 puma CVEs labelled unreachable under unicorn).
 */
function pumaDeclaredButNotLoaded(s: RailsFeatureSignals): boolean {
  const requireFalse = /gem\s+['"]puma['"][^\n]*require:\s*false/.test(s.configText);
  if (!requireFalse) return false;
  const explicitlyRequired = /require\s+['"]puma['"]/.test(s.configText) || /require\s+['"]puma['"]/.test(s.codeText);
  return !explicitlyRequired;
}

/** MessageBus::Diagnostics is explicitly enabled (the CVE-2021-43840 precondition). */
function messageBusDiagnosticsEnabled(s: RailsFeatureSignals): boolean {
  return textIncludes(s.configText.concat(s.codeText), ['enable_diagnostics', 'messagebus::diagnostics', 'message_bus/diagnostics']);
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
  detect: (s: RailsFeatureSignals) => FeaturePresence;
}

export const FEATURE_PRECONDITIONS: FeaturePrecondition[] = [
  // --- Nokogiri advanced XML APIs (owner: nokogiri). XSLT transforms, XML::Schema
  //     validation, XInclude, C14N canonicalization — Rails' HTML sanitizer path
  //     uses none of these; an app that never calls them is unaffected. ---
  {
    feature: 'nokogiri-advanced-xml-api',
    // `(?<!lib)xslt` matches the XSLT transform API (`Nokogiri::XSLT`, "XSLT
    // transform") but NOT the bundled `libxslt` C library — a "libxml2/libxslt"
    // memory-safety CVE is reached through the always-on HTML/XML parser, not the
    // opt-in transform API, so it must NOT be demoted (that was a silence-FN on
    // CVE-2021-30560). Same guard on the promotion exclude below.
    owners: ['nokogiri'],
    summary: [/(?<!lib)xslt/i, /schema/i, /xinclude/i, /c14n/i, /canonical/i, /xerces/i, /relaxng/i],
    detect: (s) => resolve(nokogiriAdvancedApiUsed(s), s),
  },
  // --- Nokogiri JRuby-only CVEs (owner: nokogiri). Several advisories only bite
  //     the JRuby/Xerces backend; an MRI deploy never runs that code. ---
  {
    feature: 'nokogiri-jruby-backend',
    owners: ['nokogiri'],
    summary: [/jruby/i, /xerces/i, /nonet/i],
    detect: (s) => (s.jruby ? 'present' : s.truncated ? 'unknown' : 'absent'),
  },
  // --- Rack::Static LFI / path-prefix bypass (owner: rack). Rails never mounts
  //     Rack::Static; the app is only affected if it adds it or enables
  //     public_file_server in prod. ---
  {
    feature: 'rack-static-middleware',
    owners: ['rack'],
    summary: [/rack::static/i, /rack:: static/i, /static\b.*(prefix|file inclusion|header_rules)/i, /local file inclusion in rack::static/i],
    detect: (s) => resolve(rackStaticMounted(s), s),
  },
  // --- Rack::Directory listing middleware (owner: rack). Rails never mounts it. ---
  {
    feature: 'rack-directory-middleware',
    owners: ['rack'],
    summary: [/rack::directory/i, /rack:: directory/i, /directory (traversal|disclosure|index)/i, /root directory disclosure/i],
    detect: (s) => resolve(rackDirectoryMounted(s), s),
  },
  // --- Rack::CommonLogger / Rack::Lint log & escape injection (owner: rack).
  //     Rails logs via Rails::Rack::Logger, not Rack::CommonLogger. The summary
  //     must NAME the CommonLogger/Lint component — a bare "log injection" /
  //     "escape sequence injection" does NOT prove the CVE lives in CommonLogger
  //     (Rack::Sendfile's X-Accel escape-injection CVE-2025-27111 says only
  //     "Escape Sequence Injection ... Possible Log Injection" and is genuinely
  //     reachable when Sendfile is active — demoting it via this rule was a
  //     silence-FN caught by the mastodon ground truth, 2026-07-02). Fail-safe:
  //     an unnamed log-injection summary falls through to `module`, not
  //     `unreachable`. The real CommonLogger CVE (CVE-2025-25184) names
  //     "Rack::CommonLogger" and still demotes correctly. ---
  {
    feature: 'rack-commonlogger-middleware',
    owners: ['rack'],
    summary: [/commonlogger/i, /common logger/i, /rack::lint/i],
    detect: (s) => resolve(rackCommonLoggerMounted(s), s),
  },
  // --- Oj::Parser (SAJ) / Oj::Doc streaming APIs (owner: oj). The Rails
  //     integration uses only Oj.load / Oj.dump (compat mode); the explicit
  //     streaming parsers are opt-in and rarely used. ---
  {
    feature: 'oj-streaming-parser',
    owners: ['oj'],
    summary: [/oj::parser/i, /oj::doc/i, /\bsaj\b/i, /create_id/i, /array_class|hash_class/i, /each_child/i, /reentrant close/i, /symbol key cache/i],
    detect: (s) => resolve(ojStreamingApiUsed(s), s),
  },
  // --- actionpack-dev-error-pages row REMOVED (2026-07-02). Its premise —
  //     that prod's `consider_all_requests_local = false` disables the
  //     actionable-exceptions / pending-migration endpoints — is FALSE for the
  //     affected Rails versions: CVE-2020-8185's whole point is that the
  //     ActionableExceptions middleware sat in the DEFAULT PROD stack and
  //     handled unauthenticated POST /rails/actions regardless of that setting
  //     (fixed in 6.0.3.2 by gating it). Ground-truth on Discourse 2.5.0
  //     (Rails 6.0.3.1) labels it data_flow; demoting it was a wrongful
  //     silence. Those summaries now fall through to `module` (honest). ---
  // --- ActionView rails-ujs DOM XSS (owner: actionview). The vulnerable code is
  //     the @rails/ujs client script; an app whose frontend never ships rails-ujs
  //     (e.g. a React/Ember SPA) never loads it. ---
  {
    feature: 'actionview-rails-ujs',
    owners: ['actionview'],
    summary: [/rails-ujs/i, /rails_ujs/i, /\bujs\b/i, /contenteditable/i],
    detect: (s) => resolve(railsUjsPresent(s), s),
  },
  // --- aws-sdk-s3 client-side Encryption Client (owner: aws-sdk-s3). The
  //     key-commitment issue is in the S3 Encryption Client; plain uploads never
  //     load it (the aws-sdk-s3-encryption gem isn't even installed). ---
  {
    feature: 'aws-s3-encryption-client',
    owners: ['aws-sdk-s3'],
    summary: [/encryption client/i, /key commitment/i, /client[- ]side encryption/i],
    detect: (s) => resolve(awsS3EncryptionPresent(s), s),
  },
  // --- Windows-only gem CVE (owner: diffy + any). A double-quote command
  //     injection that only affects a Windows environment is structurally absent
  //     on Deptex's Linux/container scans. ---
  {
    feature: 'windows-only',
    owners: ['diffy'],
    summary: [/windows/i],
    detect: () => 'absent',
  },
  // --- Puma declared but NOT loaded (owner: puma). A Gemfile `require: false`
  //     puma on a unicorn-served app (Discourse 2.5.0) never boots, so NONE of
  //     puma's CVEs are on any call path — demote every puma CVE to unreachable.
  //     The promotion above already refuses to promote in this state; this row
  //     is what takes the remaining puma `module` findings to `unreachable`
  //     (Discourse ground truth: 7 puma CVEs labelled unreachable under unicorn,
  //     2026-07-02). Fail-safe: `pumaDeclaredButNotLoaded` only returns true when
  //     it POSITIVELY finds `require: false` + no explicit `require 'puma'`;
  //     when it can't tell, it returns false → `present` → no demotion. ---
  {
    feature: 'puma-not-loaded',
    owners: ['puma'],
    summary: [/./],
    detect: (s) => (pumaDeclaredButNotLoaded(s) ? 'absent' : 'present'),
  },
];

export interface FeatureDemotionResult {
  demote: boolean;
  feature?: string;
  matchedPattern?: string;
}

/**
 * Decide whether a `module` gem finding should be demoted to `unreachable`
 * because the Rails feature its CVE requires is PROVABLY ABSENT. Pure —
 * unit-tested directly.
 *
 * Returns `{ demote: false }` unless signals are recognized, the finding has a
 * dep name + summary, at least one owner+summary row matches, AND EVERY matching
 * row's feature is provably `absent` (a single `present`/`unknown` aborts).
 */
export function evaluateRailsFeaturePreconditionDemotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  signals: RailsFeatureSignals | null | undefined;
}): FeatureDemotionResult {
  const { depName, summary, signals } = input;
  if (!signals || !signals.recognized) return { demote: false };
  if (!depName || !summary) return { demote: false };

  const dep = depName.toLowerCase();
  const applicable = FEATURE_PRECONDITIONS.filter(
    (fp) => fp.owners.some((o) => dep === o || dep.includes(o)) && fp.summary.some((re) => re.test(summary)),
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
// DEV-ONLY gem demotion (Gemfile :development/:test/:assets groups)
// ---------------------------------------------------------------------------

export interface DevOnlyDemotionResult {
  demote: boolean;
  gem?: string;
}

/**
 * Demote to `unreachable` when the finding's gem is provably DEV-ONLY — declared
 * DIRECTLY inside a Gemfile `:development` / `:test` / `:assets` group and nowhere
 * at prod scope, so it is never loaded in production (`bundle install --without
 * development test`). The Ruby analog of the composer packages-dev / Java
 * dev-scope demotion. Needs no summary match.
 *
 * Reads DIRECT Gemfile group membership only — NOT transitive — so a gem pulled
 * transitively by a dev tool (rexml via rubocop) that is ALSO required at runtime
 * is never wrongly demoted.
 */
export function evaluateRailsDevOnlyDemotion(input: {
  depName: string | null | undefined;
  signals: RailsFeatureSignals | null | undefined;
}): DevOnlyDemotionResult {
  const { depName, signals } = input;
  if (!signals || !signals.recognized) return { demote: false };
  if (!depName) return { demote: false };
  const gem = depName.toLowerCase();
  if (signals.devGems.has(gem)) return { demote: true, gem };
  return { demote: false };
}

// ---------------------------------------------------------------------------
// ALWAYS-ON framework-runtime PROMOTION table (module → visible)
// ---------------------------------------------------------------------------

export interface AlwaysOnRuntime {
  sink: string;
  owners: string[];
  summary: RegExp[];
  /** Veto: a summary matching any of these is a feature-gated sibling — never promote. */
  exclude?: RegExp[];
  promoteTo: 'function' | 'data_flow';
  /** Extra per-row precondition on the project signals. */
  requires: (s: RailsFeatureSignals) => boolean;
  /** Exploit precondition the bare request path does not satisfy (depscore hint). */
  threatTag?: string;
}

export const ALWAYS_ON_RUNTIME: AlwaysOnRuntime[] = [
  // --- Puma app server: parses 100% of inbound HTTP before any Rack middleware.
  //     Request-smuggling / keepalive-DoS / header-normalization / info-exposure
  //     CVEs are all on the always-on request path of a deployed Rails app —
  //     PROVIDED puma actually loads. A Gemfile `require: false` puma on a
  //     unicorn-served app (Discourse 2.5.0) never boots; promoting there is
  //     noise (Discourse ground-truth labels, 2026-07-02). ---
  {
    sink: 'rails-puma-http-server',
    owners: ['puma'],
    summary: [/./],
    // EXCLUDE the PROXY-protocol CVEs: puma's PROXY-protocol v1 parser only runs
    // when the app opts in via `set_remote_address proxy_protocol: :v1` — off by
    // default, so these are not on the always-on request path (mastodon ground
    // truth labels CVE-2026-47736/47737 unreachable, 2026-07-02).
    exclude: [/proxy protocol/i],
    promoteTo: 'data_flow',
    requires: (s) => !pumaDeclaredButNotLoaded(s),
    threatTag: 'requires_untrusted_request',
  },
  // --- Rack request parsing (owner: rack): Rack::Request / Multipart / QueryParser
  //     / Utils parse the body, query string, cookies, headers and Accept-Encoding
  //     of every request. EXCLUDE the feature-gated middleware (Static / Directory
  //     / CommonLogger / Lint / Sendfile / Files / Session) whose demotions run
  //     first — the exclude guard is belt-and-suspenders against a project where
  //     that middleware's absence could not be proven. ---
  {
    sink: 'rails-rack-request-parser',
    owners: ['rack'],
    summary: [
      /multipart/i,
      /query\s*parser|queryparser|query string|params_limit|unbounded[- ]parameter/i,
      /header parsing|parsing.*header/i,
      /content[- ]?type parsing/i,
      /content[- ]disposition/i,
      /percent[- ]encoded cookie|cookie.*(overwrite|prefix)/i,
      /accept[- ]encoding|select_best_encoding/i,
      /url[- ]encoded/i,
      /range header|byte range/i,
      /rack::request|rack::utils|rack::multipart|rack::queryparser/i,
    ],
    exclude: [/rack::static/i, /rack::directory/i, /commonlogger/i, /rack::lint/i, /rack::sendfile/i, /rack::files/i, /rack::session|session (gets restored|restored)/i, /information disclosure/i],
    promoteTo: 'data_flow',
    requires: () => true,
    threatTag: 'requires_untrusted_request',
  },
  // --- ActionDispatch request handling (owner: actionpack): header/route ReDoS,
  //     request-object DoS, cross-request response exposure, param-filter ReDoS —
  //     on every request, no app-specific code required. EXCLUDE the app-pattern
  //     CVEs (open-redirect / host-auth / XSS-via-redirect / token-auth / CSP /
  //     dev pages) that need a specific first-party usage. ---
  {
    sink: 'rails-actiondispatch-request',
    owners: ['actionpack'],
    summary: [
      /action dispatch/i,
      /exposure of information in action pack/i,
      /query parameter filtering/i,
      /param.*filter.*redos|redos.*param/i,
    ],
    exclude: [
      /open redirect/i,
      /host authorization/i,
      /cross-site scripting|xss/i,
      /token authentication/i,
      /content security policy/i,
      /method execution/i,
      /actionable/i,
      /pending migration/i,
    ],
    promoteTo: 'data_flow',
    requires: () => true,
    threatTag: 'requires_untrusted_request',
  },
  // --- Oj JSON encoder/decoder (owner: oj): Oj.load / Oj.dump run on every JSON
  //     API request+response Rails serializes in compat mode. EXCLUDE the explicit
  //     Oj::Parser (SAJ) / Oj::Doc streaming APIs (their demotion runs first). ---
  {
    sink: 'rails-oj-json-codec',
    owners: ['oj'],
    summary: [/oj\.dump/i, /oj\.load/i, /oj dump|oj load/i, /intern\.c|form_attr/i, /exception serialization/i, /2gb string/i],
    // EXCLUDE the large-`:indent` overflow CVEs: the buffer overflows in Oj.dump
    // via a large indent require the app to pass a big `:indent` dump option,
    // which the Rails/compat integration never does — off by default (mastodon
    // ground truth labels CVE-2026-54502/54896 unreachable, 2026-07-02).
    exclude: [/oj::parser/i, /oj::doc/i, /\bsaj\b/i, /each_child/i, /create_id/i, /array_class|hash_class/i, /reentrant close/i, /symbol key cache/i, /\bindent\b/i],
    promoteTo: 'data_flow',
    requires: () => true,
    threatTag: 'requires_untrusted_json',
  },
  // --- Nokogiri libxml2 HTML/XML parser (owner: nokogiri): exercised whenever
  //     Rails sanitizes user posts / oneboxed remote HTML via Loofah/Sanitize.
  //     Parser + memory-safety + CSS + zlib CVEs are on the content path. EXCLUDE
  //     the XSLT/Schema/XInclude/C14N/JRuby feature-gated siblings. ---
  {
    sink: 'rails-nokogiri-html-parser',
    owners: ['nokogiri'],
    summary: [
      /libxml/i,
      /libxslt/i,
      /html.*(parse|parser)|parse.*html/i,
      /use-after-free/i,
      /out-of-bounds/i,
      /out of bounds/i,
      /null pointer/i,
      /integer overflow/i,
      /memory leak/i,
      /css selector/i,
      /zlib/i,
      /denial of service|dos\b|regular expression/i,
      /nokogiri/i,
    ],
    exclude: [/(?<!lib)xslt/i, /schema/i, /xinclude/i, /c14n/i, /canonical/i, /jruby/i, /xerces/i, /nonet/i, /relaxng/i],
    promoteTo: 'data_flow',
    requires: () => true,
    threatTag: 'requires_untrusted_html',
  },
  // --- Rails HTML sanitizer stack (owners: rails-html-sanitizer, loofah, sanitize):
  //     runs on user-generated content (posts, oneboxed remote HTML). XSS / ReDoS /
  //     uncontrolled-recursion here silences reachable stored-XSS — the worst class.
  //     EXCLUDE the CONFIG-GATED XSS CVEs whose exploit needs a specific sanitizer
  //     ALLOWLIST the app must opt into (data-URI allowed, `certain configurations`
  //     permitting math/svg+style or select+style, `noscript` allowed): these fire
  //     only under a non-default allowlist, so the always-on sanitizer path does
  //     NOT reach them (mastodon+discourse ground truth label CVE-2022-23515/23518/
  //     23519/23520 + Sanitize CVE-2023-23627 unreachable, 2026-07-02). The genuine
  //     always-on sanitizer ReDoS / data-URI-independent CVEs still promote. ---
  {
    sink: 'rails-html-sanitizer',
    owners: ['rails-html-sanitizer', 'loofah', 'sanitize'],
    summary: [/./],
    exclude: [/data uri/i, /data-uri/i, /certain configurations/i, /\bnoscript\b/i],
    promoteTo: 'data_flow',
    requires: () => true,
    threatTag: 'requires_untrusted_html',
  },
  // --- ActionView render helpers (owner: actionview): translate / tag helpers emit
  //     into HTML responses. XSS here is on the render path. EXCLUDE the rails-ujs
  //     client-script CVE (its demotion runs first). ---
  {
    sink: 'rails-actionview-render',
    owners: ['actionview'],
    summary: [/xss/i, /cross-site scripting/i, /tag helper/i, /translate/i, /action view/i],
    exclude: [/rails-ujs/i, /rails_ujs/i, /\bujs\b/i, /contenteditable/i],
    promoteTo: 'function',
    requires: () => true,
    threatTag: 'requires_reflected_content',
  },
  // --- ActiveSupport SafeBuffer render path (owner: activesupport): SafeBuffer
  //     backs every html_safe string + i18n interpolation Rails emits, so an
  //     XSS in SafeBuffer#% / #bytesplice is on the render path. EXCLUDE the
  //     number-helper / underscore ReDoS + EncryptedFile disclosure (CORRECT_MODULE). ---
  {
    sink: 'rails-activesupport-safebuffer',
    owners: ['activesupport'],
    summary: [/safebuffer/i, /safe buffer/i, /bytesplice/i, /xss/i, /cross-site scripting/i],
    exclude: [/number/i, /underscore/i, /encrypted/i, /redos/i, /denial of service/i],
    promoteTo: 'function',
    requires: () => true,
    threatTag: 'requires_reflected_content',
  },
  // --- MessageBus path traversal (owner: message_bus): reachable ONLY when
  //     MessageBus::Diagnostics is enabled AND the MessageBus middleware is on the
  //     stack. Feature-PRESENCE-gated promotion — promote only when the app
  //     provably enables Diagnostics (else it stays hidden-but-unsure). ---
  {
    sink: 'rails-messagebus-diagnostics',
    owners: ['message_bus'],
    summary: [/path traversal/i, /diagnostics/i],
    promoteTo: 'function',
    requires: (s) => messageBusDiagnosticsEnabled(s),
    threatTag: 'requires_diagnostics_enabled',
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
 * Decide whether a `module` gem finding should be PROMOTED to a visible tier
 * because its CVE lives in always-on Rails-runtime code AND the project is a
 * deployed web app. Pure — unit-tested directly.
 *
 * COMPOSITION: refusing to promote a finding the DEMOTION gates would silence is
 * the CALLER's responsibility (it runs the demotions first and only offers
 * still-`module` findings here). The `exclude` guard is a second line of defence:
 * it vetoes a feature-gated sibling summary even if its demotion could not fire.
 */
export function evaluateRailsAlwaysOnRuntimePromotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  hasHttpRouteEntryPoint: boolean;
  signals?: RailsFeatureSignals | null;
}): AlwaysOnPromotionResult {
  const { depName, summary, hasHttpRouteEntryPoint } = input;
  if (!hasHttpRouteEntryPoint) return { promote: false };
  if (!depName || !summary) return { promote: false };
  const dep = depName.toLowerCase();
  const signals = input.signals ?? emptyRailsFeatureSignals();
  for (const row of ALWAYS_ON_RUNTIME) {
    if (!row.owners.some((o) => dep === o || dep.includes(o))) continue;
    if (row.exclude && row.exclude.some((re) => re.test(summary))) continue;
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
  'node_modules', '.git', 'vendor', 'tmp', 'build', 'dist', 'out',
  '.idea', 'coverage', 'public', '.github', 'log', 'spec', 'test',
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

/**
 * Parse the Gemfile → the set of gems declared DIRECTLY inside a
 * `:development` / `:test` / `:assets` group and NOT at prod scope.
 *
 * Handles both block groups (`group :development do ... gem 'x' ... end`) and
 * inline group kwargs (`gem 'x', group: :development` / `groups: [:test]`). A gem
 * declared anywhere at prod scope (top-level, or a non-dev group) is removed from
 * the dev set — the safe direction.
 */
function parseGemfileDevGems(root: string): Set<string> {
  const raw = safeRead(path.join(root, 'Gemfile'), MAX_CONFIG_BYTES);
  const devGems = new Set<string>();
  const prodGems = new Set<string>();
  if (!raw) return devGems;
  const DEV_GROUPS = new Set(['development', 'test', 'assets']);
  const lines = raw.split(/\r?\n/);
  // Track a stack of active block-group scopes.
  const groupStack: Array<Set<string>> = [];
  const gemRe = /^\s*gem\s+['"]([^'"]+)['"](.*)$/;
  const groupOpenRe = /^\s*group\s+(.+?)\s+do\s*$/;
  const endRe = /^\s*end\s*$/;

  const currentGroups = (): Set<string> => {
    const acc = new Set<string>();
    for (const g of groupStack) for (const x of g) acc.add(x);
    return acc;
  };

  for (const line of lines) {
    const go = line.match(groupOpenRe);
    if (go) {
      const names = new Set<string>();
      for (const m of go[1].matchAll(/:([a-z_]+)/gi)) names.add(m[1].toLowerCase());
      groupStack.push(names);
      continue;
    }
    if (endRe.test(line) && groupStack.length > 0) {
      groupStack.pop();
      continue;
    }
    const gm = line.match(gemRe);
    if (!gm) continue;
    const name = gm[1].toLowerCase();
    const rest = gm[2] || '';
    // Inline group kwargs on this gem line.
    const inlineGroups = new Set<string>();
    for (const m of rest.matchAll(/group[s]?\s*:\s*\[?\s*([^\]\n]+)/gi)) {
      for (const g of m[1].matchAll(/:([a-z_]+)/gi)) inlineGroups.add(g[1].toLowerCase());
    }
    const groups = new Set<string>([...currentGroups(), ...inlineGroups]);
    if (groups.size > 0 && [...groups].every((g) => DEV_GROUPS.has(g))) {
      devGems.add(name);
    } else {
      prodGems.add(name);
    }
  }
  // A gem seen at prod scope anywhere wins (never demote it).
  for (const g of prodGems) devGems.delete(g);
  return devGems;
}

/** Parse Gemfile.lock → the set of every gem name (lowercased). */
function parseGemfileLock(root: string): Set<string> {
  const raw = safeRead(path.join(root, 'Gemfile.lock'), MAX_CONFIG_BYTES);
  const gems = new Set<string>();
  if (!raw) return gems;
  // In the `specs:` section each gem is `    name (version)` (4-space indent);
  // its runtime deps are `      dep (req)` (6-space). Capture both — we just want
  // the name universe for presence checks.
  for (const m of raw.matchAll(/^\s{4,6}([a-zA-Z0-9._-]+)\s*\(/gm)) {
    gems.add(m[1].toLowerCase());
  }
  return gems;
}

/** Detect a JRuby deploy from Gemfile platform kwargs / .ruby-version. */
function detectJRuby(root: string, gemfile: string | null): boolean {
  if (gemfile && /platform[s]?\s*:\s*\[?[^)\n]*:jruby/i.test(gemfile)) {
    // A `platform: :jruby` kwarg only scopes THOSE gems; it doesn't make the
    // whole app JRuby. Treat an explicit `ruby engine: 'jruby'` / .ruby-version
    // as authoritative instead.
  }
  const rv = safeRead(path.join(root, '.ruby-version'), 4096);
  if (rv && /jruby/i.test(rv)) return true;
  if (gemfile && /ruby\s+['"][^'"]*['"]\s*,\s*engine\s*:\s*['"]jruby['"]/i.test(gemfile)) return true;
  return false;
}

/**
 * Walk `root` (bounded) gathering the Gemfile / config / ruby-code signals the
 * feature detectors read. Never throws — an unreadable tree yields empty
 * (unrecognized) signals, which refuses every demotion / promotion.
 */
export function gatherRailsFeatureSignals(root: string | undefined): RailsFeatureSignals {
  const signals = emptyRailsFeatureSignals();
  if (!root) return signals;
  try {
    if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) return signals;
  } catch {
    return signals;
  }

  const gemfileRaw = safeRead(path.join(root, 'Gemfile'), MAX_CONFIG_BYTES);
  signals.devGems = parseGemfileDevGems(root);
  signals.lockGems = parseGemfileLock(root);
  signals.jruby = detectJRuby(root, gemfileRaw);

  const isRailsApp =
    signals.lockGems.has('rails') ||
    signals.lockGems.has('railties') ||
    signals.lockGems.has('actionpack') ||
    (gemfileRaw ? /gem\s+['"]rails['"]/.test(gemfileRaw) : false) ||
    fs.existsSync(path.join(root, 'config', 'application.rb'));

  const configParts: string[] = [];
  const codeParts: string[] = [];
  let codeFileCount = 0;
  let codeBytes = 0;
  let configBytes = 0;
  let truncated = false;

  if (gemfileRaw) configParts.push(gemfileRaw.toLowerCase());

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

      // config: *.rb + *.yml under config/, plus root config.ru.
      const isConfig =
        ((lower.endsWith('.rb') || lower.endsWith('.yml') || lower.endsWith('.yaml')) && fullLower.includes('/config/')) ||
        lower === 'config.ru';
      if (isConfig) {
        if (configBytes < MAX_CONFIG_BYTES) {
          const c = safeRead(full, MAX_CONFIG_BYTES);
          if (c) {
            configParts.push(c.toLowerCase());
            configBytes += c.length;
          }
        }
        continue;
      }

      // code: first-party ruby under app/ or lib/.
      const isAppCode = lower.endsWith('.rb') && (fullLower.includes('/app/') || fullLower.includes('/lib/'));
      if (isAppCode) {
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
  signals.codeText = codeParts.join('\n');
  signals.truncated = truncated;
  signals.recognized = isRailsApp && (signals.lockGems.size > 0 || !!gemfileRaw);
  return signals;
}
