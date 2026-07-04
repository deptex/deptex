/**
 * Ruby / Rails framework-mediated reachability model — the RubyGems mirror of
 * the Java / PHP feature-precondition + always-on-runtime gates. Verdicts are
 * grounded in the Discourse 2.5.0 triage.
 *
 * Covers:
 *   1. the pure decision functions with injected signals (no filesystem):
 *      - `evaluateRailsAlwaysOnRuntimePromotion` (Puma / Rack request parser /
 *        ActionDispatch / Oj codec / Nokogiri parser / sanitizer stack → visible;
 *        the `exclude` guard vetoes Rack::Static / Nokogiri-XSLT / Oj::Parser /
 *        rails-ujs siblings; message_bus gated on Diagnostics; fail-safes),
 *      - `evaluateRailsFeaturePreconditionDemotion` (Rack::Static/Directory,
 *        Nokogiri XSLT/Schema/JRuby, Oj streaming, rails-ujs, S3 encryption,
 *        Windows-only → unreachable when absent; blocked when present),
 *      - `evaluateRailsDevOnlyDemotion` (Gemfile :development/:test group gem).
 *   2. end-to-end through `updateReachabilityLevels` with `ecosystem: 'gem'`.
 */

import { updateReachabilityLevels } from '../reachability';
import type { Storage } from '../storage';
import {
  evaluateRailsAlwaysOnRuntimePromotion,
  evaluateRailsFeaturePreconditionDemotion,
  evaluateRailsDevOnlyDemotion,
  emptyRailsFeatureSignals,
  type RailsFeatureSignals,
} from '../reachability-rails-preconditions';

// ---------------------------------------------------------------------------
// Representative advisory summaries (real Discourse CVE phrasings)
// ---------------------------------------------------------------------------

const RACK_MULTIPART_DOS = 'Rack has possible DoS Vulnerability in Multipart MIME parsing';
const RACK_QUERYPARSER_DOS = 'Rack has an Unbounded-Parameter DoS in Rack::QueryParser';
const RACK_STATIC_LFI = 'Local File Inclusion in Rack::Static';
const RACK_DIRECTORY_TRAVERSAL = 'Rack has a Directory Traversal via Rack:Directory';
const RACK_COMMONLOGGER_INJECTION = 'Possible Log Injection in Rack::CommonLogger';
const PUMA_SMUGGLING = 'Puma HTTP Request/Response Smuggling vulnerability';
const ACTIONDISPATCH_REDOS = 'ReDoS based DoS vulnerability in Action Dispatch';
const ACTIONPACK_OPEN_REDIRECT = 'actionpack Open Redirect in Host Authorization Middleware';
const ACTIONPACK_DEV_MIGRATION = 'Untrusted users can run pending migrations in production in Rails';
const OJ_LOAD_OVERFLOW = 'Oj: Integer Overflow in Oj.load 2GB String Handling';
const OJ_PARSER_UAF = 'Oj: Use-After-Free in Oj::Parser Symbol Key Cache Toggle';
const NOKOGIRI_LIBXML_OOB = 'Nokogiri contains libxml Out-of-bounds Write vulnerability';
const NOKOGIRI_LIBXSLT_DEP = 'Nokogiri has vulnerable dependencies on libxml2 and libxslt';
const NOKOGIRI_XSLT_LEAK = 'Nokogiri XSLT transform has a memory leak';
const NOKOGIRI_JRUBY_SCHEMA = 'Nokogiri: XML::Schema on JRuby allows network requests when NONET is set';
const RAILS_HTML_SANITIZER_XSS = 'Possible XSS vulnerability with certain configurations of rails-html-sanitizer';
const LOOFAH_DATA_URI_XSS = 'Improper neutralization of data URIs may allow XSS in Loofah';
const ACTIONVIEW_TAG_XSS = 'XSS Vulnerability in Action View tag helpers';
const ACTIONVIEW_UJS_XSS = 'rails-ujs vulnerable to DOM Based Cross-site Scripting contenteditable';
const ACTIVESUPPORT_SAFEBUFFER_XSS = 'ActiveSupport SafeBuffer#bytesplice XSS vulnerability';
const AWS_S3_ENCRYPTION = "AWS SDK for Ruby's S3 Encryption Client has a Key Commitment Issue";
const DIFFY_WINDOWS = 'Improper handling of double quotes in file name in Diffy in Windows environments';
const MESSAGEBUS_TRAVERSAL = 'Path traversal when MessageBus::Diagnostics is enabled';
const BETTER_ERRORS_CSRF = 'Older releases of better_errors open to Cross-Site Request Forgery attack';

/**
 * A recognized Discourse-shaped Rails project: Rails on Puma, Oj JSON, MRI, no
 * Rack::Static/Directory, no Nokogiri XSLT/Schema, no Oj streaming, no rails-ujs
 * (Ember SPA), no S3 encryption; MessageBus::Diagnostics enabled. Dev gems:
 * better_errors.
 */
function railsSignals(over: Partial<RailsFeatureSignals> = {}): RailsFeatureSignals {
  return {
    ...emptyRailsFeatureSignals(),
    recognized: true,
    devGems: new Set(['better_errors', 'rspec', 'byebug']),
    lockGems: new Set(['rails', 'railties', 'actionpack', 'rack', 'puma', 'oj', 'nokogiri', 'aws-sdk-s3']),
    configText:
      "consider_all_requests_local = false\nconfig.public_file_server.enabled = false\nmessagebus.enable_diagnostics\noj::rails.set_encoder\n",
    codeText: "class postscontroller; def index; render json: post; end; end\n",
    jruby: false,
    ...over,
  };
}

// ---------------------------------------------------------------------------
// 1. Pure decision functions — PROMOTION
// ---------------------------------------------------------------------------

describe('evaluateRailsAlwaysOnRuntimePromotion', () => {
  const P = (depName: string, summary: string, over: Partial<RailsFeatureSignals> = {}) =>
    evaluateRailsAlwaysOnRuntimePromotion({ depName, summary, hasHttpRouteEntryPoint: true, signals: railsSignals(over) });

  it('promotes a Rack multipart-parsing DoS to data_flow', () => {
    const r = P('rack', RACK_MULTIPART_DOS);
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('data_flow');
    expect(r.sink).toBe('rails-rack-request-parser');
  });

  it('promotes a Rack QueryParser DoS to data_flow', () => {
    expect(P('rack', RACK_QUERYPARSER_DOS).promote).toBe(true);
  });

  it('promotes Puma request smuggling to data_flow', () => {
    const r = P('puma', PUMA_SMUGGLING);
    expect(r.promote).toBe(true);
    expect(r.sink).toBe('rails-puma-http-server');
  });

  it('refuses the Puma promotion when puma is declared require:false and never required (unicorn-served Discourse shape)', () => {
    // Bundler.require skips require-false gems — puma's parser never boots on
    // a unicorn deploy. Promoting there is noise (Discourse 2.5.0 ground truth:
    // 7 puma CVEs labelled unreachable under unicorn).
    const discourseShaped = {
      configText:
        railsSignals().configText + "gem 'puma', require: false\nworker_processes 4 # unicorn.conf.rb\n",
    };
    expect(P('puma', PUMA_SMUGGLING, discourseShaped).promote).toBe(false);
  });

  it('still promotes Puma when require:false but the app explicitly requires puma', () => {
    const explicitlyRequired = {
      configText: railsSignals().configText + "gem 'puma', require: false\n",
      codeText: railsSignals().codeText + "require 'puma'\n",
    };
    expect(P('puma', PUMA_SMUGGLING, explicitlyRequired).promote).toBe(true);
  });

  it('does NOT promote the Puma PROXY-protocol CVE (opt-in, off by default)', () => {
    // PROXY-protocol v1 parsing runs only under `set_remote_address proxy_protocol:`
    // — not the always-on path (mastodon ground truth: CVE-2026-47736/47737 unreachable).
    expect(P('puma', 'Puma PROXY Protocol v1 Parser Allows Remote Memory Exhaustion').promote).toBe(false);
  });

  it('does NOT promote the Oj large-`:indent` overflow (opt-in dump option)', () => {
    // The Rails/compat Oj integration never passes a large `:indent`; the buffer
    // overflow needs it (mastodon ground truth: CVE-2026-54502/54896 unreachable).
    expect(P('oj', 'Oj: Stack Buffer Overflow in Oj.dump via Large Indent').promote).toBe(false);
    expect(P('oj', 'Oj: Heap Buffer Overflow in Oj.dump Exception Serialization via Large Indent').promote).toBe(false);
  });

  it('does NOT promote the XInclude-gated nokogiri UAF CVEs by id (coarse summary hides the gate)', () => {
    // CVE-2021-30560 / CVE-2021-3518 read as "use-after-free"/"libxml2 and libxslt"
    // but are XInclude-gated (non-default parse option); discourse ground truth
    // labels both unreachable. The id is the only signal.
    const nokoUAF = 'Nokogiri Implements libxml2 version vulnerable to use-after-free';
    expect(evaluateRailsAlwaysOnRuntimePromotion({ depName: 'nokogiri', summary: nokoUAF, hasHttpRouteEntryPoint: true, signals: railsSignals(), osvIds: ['CVE-2021-3518'] }).promote).toBe(false);
    expect(evaluateRailsAlwaysOnRuntimePromotion({ depName: 'nokogiri', summary: 'Nokogiri has vulnerable dependencies on libxml2 and libxslt', hasHttpRouteEntryPoint: true, signals: railsSignals(), osvIds: ['CVE-2021-30560'] }).promote).toBe(false);
    // A genuine always-on libxml2 parser UAF with a DIFFERENT id still promotes.
    expect(evaluateRailsAlwaysOnRuntimePromotion({ depName: 'nokogiri', summary: nokoUAF, hasHttpRouteEntryPoint: true, signals: railsSignals(), osvIds: ['CVE-2099-0001'] }).promote).toBe(true);
  });

  it('does NOT promote the zlib DEFLATE (compression) OOB CVE by id', () => {
    // CVE-2018-25032: a zlib deflate/COMPRESSION out-of-bounds write. Nokogiri
    // only uses zlib INFLATE (decompressing gzipped content) on the parse path —
    // it never deflates untrusted input — so this compression bug is NOT on the
    // untrusted-HTML content path. Its summary matches the generic /zlib/ +
    // /out-of-bounds/ promoters, so the id is the only signal (discourse ground
    // truth labels it module).
    const zlibOob = "Nokogiri affected by zlib's Out-of-bounds Write vulnerability";
    expect(evaluateRailsAlwaysOnRuntimePromotion({ depName: 'nokogiri', summary: zlibOob, hasHttpRouteEntryPoint: true, signals: railsSignals(), osvIds: ['CVE-2018-25032'] }).promote).toBe(false);
    // A genuine inflate-path libxml2 OOB with a different id still promotes.
    expect(evaluateRailsAlwaysOnRuntimePromotion({ depName: 'nokogiri', summary: 'libxml2 out-of-bounds read while parsing HTML', hasHttpRouteEntryPoint: true, signals: railsSignals(), osvIds: ['CVE-2099-0002'] }).promote).toBe(true);
  });

  it('does NOT promote non-parse-path nokogiri advisory classes (DOM-API misuse / type-confusion / CSS-selector / zlib)', () => {
    // Reachable only when the app's OWN code calls a specific low-level Nokogiri
    // mutator with bad input — off the always-on Loofah/Sanitize parse path on ANY
    // Rails app (discourse + mastodon ground truth: all module/unreachable). These
    // slip the /nokogiri/ + memory-safety promoters; the (b)-(d) excludes veto them.
    const nonParsePath = [
      'Nokogiri Improperly Handles Unexpected Data Type',                                                   // CVE-2022-29181 type-confusion
      'Nokogiri: Possible Use-After-Free when `Nokogiri::XML::Document#encoding=` raises an exception',      // GHSA-5v8h
      'Nokogiri: Possible Use-After-Free when directly using `Nokogiri::XML::XPathContext` beyond document lifetime', // GHSA-p67v
      'Nokogiri: Null Pointer Dereference calling methods on uninitialized wrapper classes',                 // GHSA-9cv2
      'Nokogiri: Possible Use-After-Free when setting `Document#root=` to an invalid node type',             // GHSA-wjv4
      'Nokogiri: Possible Use-After-Free when setting an attribute value via `Nokogiri::XML::Attr#value=` or `#content=`', // GHSA-phwj
      'Nokogiri: Possible Out-of-Bounds Read in `Nokogiri::XML::NodeSet#[]`',                                // GHSA-5prr
      'Nokogiri CSS selector tokenizer has regular expression backtracking',                                 // GHSA-c4rq
      'Out-of-bounds Write in zlib affects Nokogiri',                                                        // GHSA-v6gp (generalizes the CVE-2018-25032 id-veto)
    ];
    for (const summary of nonParsePath) {
      expect(P('nokogiri', summary).promote).toBe(false);
    }
  });

  it('STILL promotes the genuine libxml2 parse-path nokogiri memory-safety + vendored-rollup CVEs', () => {
    // Guard against over-correction: the excludes must not demote the reachable set
    // (discourse+mastodon ground truth: these are data_flow).
    const parsePath = [
      'Nokogiri contains libxml Out-of-bounds Write vulnerability',              // CVE-2021-3517
      'Nokogiri Implements libxml2 version vulnerable to null pointer dereferencing', // CVE-2021-3537
      'Nokogiri Inefficient Regular Expression Complexity',                     // CVE-2022-24836 (parse ReDoS)
      'Nokogiri patches vendored libxml2 to resolve multiple CVEs',             // GHSA-353f rollup
      'Integer Overflow or Wraparound in libxml2 affects Nokogiri',             // GHSA-cgx6
    ];
    for (const summary of parsePath) {
      const r = P('nokogiri', summary);
      expect(r.promote).toBe(true);
      expect(r.sink).toBe('rails-nokogiri-html-parser');
    }
  });

  it('does NOT promote the Ruby-version-gated SafeBuffer#bytesplice XSS by id', () => {
    // CVE-2023-28120: bytesplice only exists on Ruby ≥3.2; mastodon pins <3.1
    // (mastodon ground truth: unreachable). Excluded by id → not promoted.
    expect(evaluateRailsAlwaysOnRuntimePromotion({ depName: 'activesupport', summary: 'Possible XSS Security Vulnerability in SafeBuffer#bytesplice', hasHttpRouteEntryPoint: true, signals: railsSignals(), osvIds: ['CVE-2023-28120'] }).promote).toBe(false);
  });

  it('promotes an ActionDispatch ReDoS to data_flow', () => {
    const r = P('actionpack', ACTIONDISPATCH_REDOS);
    expect(r.promote).toBe(true);
    expect(r.sink).toBe('rails-actiondispatch-request');
  });

  it('promotes an Oj.load overflow to data_flow', () => {
    const r = P('oj', OJ_LOAD_OVERFLOW);
    expect(r.promote).toBe(true);
    expect(r.sink).toBe('rails-oj-json-codec');
  });

  it('promotes a Nokogiri libxml OOB write to data_flow', () => {
    const r = P('nokogiri', NOKOGIRI_LIBXML_OOB);
    expect(r.promote).toBe(true);
    expect(r.sink).toBe('rails-nokogiri-html-parser');
  });

  it('does NOT promote a config-gated rails-html-sanitizer XSS ("certain configurations")', () => {
    // These XSS need a specific non-default sanitizer allowlist (math/svg+style,
    // select+style) — not on the always-on sanitizer path. mastodon+discourse
    // ground truth label CVE-2022-23519/23520 unreachable; excluding drops them
    // from data_flow to the honest module tier.
    expect(P('rails-html-sanitizer', RAILS_HTML_SANITIZER_XSS).promote).toBe(false);
  });

  it('does NOT promote a loofah/sanitizer data-URI XSS (needs sanitized-HTML render, config-gated)', () => {
    // The data-URI XSS fires only when the app RENDERS sanitizer output as HTML
    // (not strip_tags-to-plain-text); mastodon ground truth labels CVE-2022-23515
    // unreachable. Excluded → module (honest), not the over-claimed data_flow.
    expect(P('loofah', LOOFAH_DATA_URI_XSS).promote).toBe(false);
  });

  it('still promotes a genuine always-on sanitizer ReDoS (not config-gated)', () => {
    // A ReDoS in the sanitizer regex is on the always-on user-content path and
    // must still promote — the exclude is scoped to data-URI/config/noscript.
    const r = P('rails-html-sanitizer', 'Inefficient Regular Expression Complexity in rails-html-sanitizer');
    expect(r.promote).toBe(true);
    expect(r.sink).toBe('rails-html-sanitizer');
  });

  it('promotes an ActionView tag-helper XSS to function', () => {
    const r = P('actionview', ACTIONVIEW_TAG_XSS);
    expect(r.promote).toBe(true);
    expect(r.promoteTo).toBe('function');
    expect(r.sink).toBe('rails-actionview-render');
  });

  it('promotes an ActiveSupport SafeBuffer XSS to function', () => {
    const r = P('activesupport', ACTIVESUPPORT_SAFEBUFFER_XSS);
    expect(r.promote).toBe(true);
    expect(r.sink).toBe('rails-activesupport-safebuffer');
  });

  it('promotes message_bus path traversal WHEN Diagnostics is enabled', () => {
    const r = P('message_bus', MESSAGEBUS_TRAVERSAL);
    expect(r.promote).toBe(true);
    expect(r.sink).toBe('rails-messagebus-diagnostics');
  });

  it('does NOT promote message_bus when Diagnostics is not enabled', () => {
    const r = P('message_bus', MESSAGEBUS_TRAVERSAL, { configText: 'nothing here' });
    expect(r.promote).toBe(false);
  });

  // --- exclude guard: feature-gated siblings are NEVER promoted ---
  it('does NOT promote Rack::Static LFI (feature-gated sibling excluded)', () => {
    expect(P('rack', RACK_STATIC_LFI).promote).toBe(false);
  });

  it('does NOT promote Rack::Directory traversal (feature-gated sibling excluded)', () => {
    expect(P('rack', RACK_DIRECTORY_TRAVERSAL).promote).toBe(false);
  });

  it('does NOT promote a Nokogiri XSLT CVE (feature-gated sibling excluded)', () => {
    expect(P('nokogiri', NOKOGIRI_XSLT_LEAK).promote).toBe(false);
  });

  it('DOES promote a "libxml2 and libxslt" dependency CVE (libxslt lib ≠ XSLT API — was a silence-FN)', () => {
    // CVE-2021-30560: the vendored libxml2/libxslt libraries are on the always-on
    // parser path; the `(?<!lib)xslt` guard means "libxslt" must NOT trip the
    // XSLT-transform-API exclude.
    const r = P('nokogiri', NOKOGIRI_LIBXSLT_DEP);
    expect(r.promote).toBe(true);
    expect(r.sink).toBe('rails-nokogiri-html-parser');
  });

  it('does NOT promote an Oj::Parser UAF (streaming sibling excluded)', () => {
    expect(P('oj', OJ_PARSER_UAF).promote).toBe(false);
  });

  it('does NOT promote an ActionView rails-ujs XSS (client-script sibling excluded)', () => {
    expect(P('actionview', ACTIONVIEW_UJS_XSS).promote).toBe(false);
  });

  it('does NOT promote an actionpack open-redirect app-pattern CVE (excluded)', () => {
    expect(P('actionpack', ACTIONPACK_OPEN_REDIRECT).promote).toBe(false);
  });

  it('does NOT promote on a library/CLI repo (0 HTTP routes)', () => {
    const r = evaluateRailsAlwaysOnRuntimePromotion({
      depName: 'rack',
      summary: RACK_MULTIPART_DOS,
      hasHttpRouteEntryPoint: false,
      signals: railsSignals(),
    });
    expect(r.promote).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 1b. Pure decision functions — FEATURE-PRECONDITION DEMOTION
// ---------------------------------------------------------------------------

describe('evaluateRailsFeaturePreconditionDemotion', () => {
  const D = (depName: string, summary: string, over: Partial<RailsFeatureSignals> = {}) =>
    evaluateRailsFeaturePreconditionDemotion({ depName, summary, signals: railsSignals(over) });

  it('demotes Rack::Static LFI when Rack::Static is not mounted', () => {
    const r = D('rack', RACK_STATIC_LFI);
    expect(r.demote).toBe(true);
    expect(r.feature).toBe('rack-static-middleware');
  });

  it('demotes ALL puma CVEs to unreachable when puma is require:false and not loaded (Discourse under unicorn)', () => {
    // 7 discourse puma CVEs are labelled unreachable (require:false + unicorn).
    const notLoaded = {
      configText: railsSignals().configText + "gem 'puma', require: false\nworker_processes 4 # unicorn.conf.rb\n",
    };
    expect(D('puma', PUMA_SMUGGLING, notLoaded).feature).toBe('puma-not-loaded');
    expect(D('puma', "Puma's Keepalive Connections Causing Denial Of Service", notLoaded).demote).toBe(true);
  });

  it('does NOT demote puma when it is genuinely loaded (default — fail-safe present)', () => {
    // The base railsSignals has puma in lockGems without require:false → loaded.
    expect(D('puma', PUMA_SMUGGLING).demote).toBe(false);
  });

  it('does NOT demote Rack::Static when the app explicitly mounts Rack::Static', () => {
    const r = D('rack', RACK_STATIC_LFI, { configText: 'use rack::static, urls: ["/media"]' });
    expect(r.demote).toBe(false);
  });

  it('demotes Rack::Static even when a dev env enables public_file_server (Rack::Static ≠ ActionDispatch::Static)', () => {
    // A dev/test env `public_file_server.enabled = true` must NOT block the
    // demotion — the CVE is in Rack::Static, a different middleware than Rails'
    // public_file_server (ActionDispatch::Static / Rack::Files).
    const r = D('rack', RACK_STATIC_LFI, { configText: 'config.public_file_server.enabled = true' });
    expect(r.demote).toBe(true);
  });

  it('demotes Rack::Directory traversal when Rack::Directory is not mounted', () => {
    expect(D('rack', RACK_DIRECTORY_TRAVERSAL).feature).toBe('rack-directory-middleware');
  });

  it('demotes Rack::CommonLogger log injection when not in the middleware stack', () => {
    expect(D('rack', RACK_COMMONLOGGER_INJECTION).feature).toBe('rack-commonlogger-middleware');
  });

  it('does NOT demote a component-less log-injection CVE as CommonLogger (Rack::Sendfile CVE-2025-27111 silence-FN)', () => {
    // "Escape Sequence Injection ... Possible Log Injection" names no component;
    // it is actually a Rack::Sendfile CVE, genuinely reachable when Sendfile is
    // active. The bare /log injection/i pattern used to demote it to
    // unreachable — a Gate-3 silence-FN caught by the mastodon ground truth.
    const r = D('rack', 'Escape Sequence Injection vulnerability in Rack lead to Possible Log Injection');
    expect(r.demote).toBe(false);
  });

  it('demotes a Nokogiri XSLT CVE when the app calls no XSLT/Schema API', () => {
    expect(D('nokogiri', NOKOGIRI_XSLT_LEAK).feature).toBe('nokogiri-advanced-xml-api');
  });

  it('does NOT demote the Nokogiri XSLT CVE when the app calls Nokogiri::XSLT', () => {
    const r = D('nokogiri', NOKOGIRI_XSLT_LEAK, { codeText: 'nokogiri::xslt.parse(sheet)' });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote a "libxml2 and libxslt" dependency CVE (libxslt lib ≠ XSLT transform API)', () => {
    // The bundled libxslt library sits on the parser path; only the explicit XSLT
    // transform API is feature-gated. Demoting this would be a silence-FN.
    expect(D('nokogiri', NOKOGIRI_LIBXSLT_DEP).demote).toBe(false);
  });

  it('demotes a Nokogiri JRuby-only CVE on an MRI deploy', () => {
    const r = D('nokogiri', NOKOGIRI_JRUBY_SCHEMA);
    expect(r.demote).toBe(true);
  });

  it('does NOT demote the Nokogiri JRuby CVE on a JRuby deploy', () => {
    const r = D('nokogiri', NOKOGIRI_JRUBY_SCHEMA, { jruby: true });
    expect(r.demote).toBe(false);
  });

  it('demotes an Oj::Parser streaming CVE when the app never calls the streaming API', () => {
    expect(D('oj', OJ_PARSER_UAF).feature).toBe('oj-streaming-parser');
  });

  it('does NOT demote the Oj::Parser CVE when the app uses Oj::Parser', () => {
    const r = D('oj', OJ_PARSER_UAF, { codeText: 'p = oj::parser.new(:saj)' });
    expect(r.demote).toBe(false);
  });

  it('demotes an ActionView rails-ujs CVE when rails-ujs never ships', () => {
    expect(D('actionview', ACTIONVIEW_UJS_XSS).feature).toBe('actionview-rails-ujs');
  });

  it('does NOT demote the rails-ujs CVE when rails-ujs is present', () => {
    const r = D('actionview', ACTIONVIEW_UJS_XSS, { codeText: '//= require rails-ujs' });
    expect(r.demote).toBe(false);
  });

  it('does NOT demote the actionpack pending-migration CVE (row removed — CVE-2020-8185 ran in the default PROD stack on affected versions)', () => {
    // Discourse 2.5.0 (Rails 6.0.3.1) ground truth: unauthenticated POST
    // /rails/actions ran pending migrations in prod REGARDLESS of
    // consider_all_requests_local — demoting it was a wrongful silence.
    expect(D('actionpack', ACTIONPACK_DEV_MIGRATION).demote).toBe(false);
    const withLocal = D('actionpack', ACTIONPACK_DEV_MIGRATION, { configText: 'consider_all_requests_local = true' });
    expect(withLocal.demote).toBe(false);
  });

  it('demotes the aws-sdk-s3 encryption-client CVE when the encryption gem is absent', () => {
    expect(D('aws-sdk-s3', AWS_S3_ENCRYPTION).feature).toBe('aws-s3-encryption-client');
  });

  it('does NOT demote the S3 encryption CVE when aws-sdk-s3-encryption is installed', () => {
    const r = D('aws-sdk-s3', AWS_S3_ENCRYPTION, { lockGems: new Set(['aws-sdk-s3', 'aws-sdk-s3-encryption']) });
    expect(r.demote).toBe(false);
  });

  it('demotes a Windows-only diffy CVE on a Linux scan', () => {
    expect(D('diffy', DIFFY_WINDOWS).feature).toBe('windows-only');
  });

  it('does NOT demote when the summary names no gated feature', () => {
    expect(D('rack', 'Rack had a minor performance regression.').demote).toBe(false);
  });

  it('refuses to demote for an unrecognized project', () => {
    const r = evaluateRailsFeaturePreconditionDemotion({
      depName: 'rack',
      summary: RACK_STATIC_LFI,
      signals: emptyRailsFeatureSignals(),
    });
    expect(r.demote).toBe(false);
  });

  it('refuses to demote (→ unknown) a code-signal feature when the scan was truncated', () => {
    const r = D('nokogiri', NOKOGIRI_XSLT_LEAK, { truncated: true });
    expect(r.demote).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 1c. Pure decision functions — DEV-ONLY DEMOTION
// ---------------------------------------------------------------------------

describe('evaluateRailsDevOnlyDemotion', () => {
  it('demotes a gem declared in the Gemfile :development group', () => {
    const r = evaluateRailsDevOnlyDemotion({ depName: 'better_errors', signals: railsSignals() });
    expect(r.demote).toBe(true);
    expect(r.gem).toBe('better_errors');
  });

  it('does NOT demote a production gem', () => {
    expect(evaluateRailsDevOnlyDemotion({ depName: 'rack', signals: railsSignals() }).demote).toBe(false);
  });

  it('does NOT demote a runtime gem that only LOOKS dev-transitive (rexml via rubocop)', () => {
    // rexml is pulled transitively by rubocop but ALSO required at runtime; it is
    // NOT a DIRECT Gemfile dev-group declaration, so devGems never contains it.
    expect(evaluateRailsDevOnlyDemotion({ depName: 'rexml', signals: railsSignals() }).demote).toBe(false);
  });

  it('refuses to demote for an unrecognized project', () => {
    expect(evaluateRailsDevOnlyDemotion({ depName: 'better_errors', signals: emptyRailsFeatureSignals() }).demote).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. End-to-end through updateReachabilityLevels (ecosystem: 'gem')
// ---------------------------------------------------------------------------

interface TableState { rows: any[] }

class FakeStorage {
  tables: Record<string, TableState> = {};
  updates: Array<{ table: string; filter: Record<string, unknown>; values: any }> = [];

  set(table: string, rows: any[]) {
    this.tables[table] = { rows };
  }

  from(table: string): any {
    const state = this.tables[table] ?? { rows: [] };
    const filters: Array<{ col: string; val: unknown }> = [];
    const filterRows = () => {
      let rows = state.rows;
      for (const f of filters) rows = rows.filter((r) => r[f.col] === f.val);
      return rows;
    };
    const builder: any = {
      select() { return builder; },
      eq(col: string, val: unknown) { filters.push({ col, val }); return builder; },
      in() { return builder; },
      maybeSingle() { return Promise.resolve({ data: filterRows()[0] ?? null, error: null }); },
      single() {
        const rows = filterRows();
        return Promise.resolve({
          data: rows[0] ?? null,
          error: rows.length === 0 ? { code: 'PGRST116', message: 'not found' } : null,
        });
      },
      insert: () => Promise.resolve({ data: null, error: null }),
      upsert: (rows: any) => {
        const arr = Array.isArray(rows) ? rows : [rows];
        for (const r of arr) this.updates.push({ table, filter: { id: r.id }, values: r });
        return Promise.resolve({ data: null, error: null });
      },
      then(onFulfilled: any) {
        return Promise.resolve({ data: filterRows(), error: null }).then(onFulfilled);
      },
    };
    return builder;
  }
}

const log = {
  info: jest.fn().mockResolvedValue(undefined),
  success: jest.fn().mockResolvedValue(undefined),
  warn: jest.fn().mockResolvedValue(undefined),
  error: jest.fn().mockResolvedValue(undefined),
};

const PROJECT_ID = 'proj-1';
const RUN_ID = 'run-1';

/** Seed one gem transitive dep (namespace null, bare gem name) that lands at `module`. */
function seedGemDep(
  fsk: FakeStorage,
  opts: { name: string; osvId: string; summary: string; filesImporting?: number },
) {
  fsk.set('project_dependency_vulnerabilities', [
    {
      id: 'pdv-1',
      project_dependency_id: 'pd-1',
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      osv_id: opts.osvId,
      aliases: [],
      summary: opts.summary,
    },
  ]);
  fsk.set('project_dependencies', [
    {
      id: 'pd-1',
      project_id: PROJECT_ID,
      last_seen_extraction_run_id: RUN_ID,
      dependency_id: 'dep-1',
      dependency_version_id: 'dv-1',
      is_direct: false,
      files_importing_count: opts.filesImporting ?? 1,
      environment: null,
      name: opts.name,
      namespace: null,
    },
  ]);
  fsk.set('project_reachable_flows', []);
  fsk.set('project_reachable_flow_suppressions', []);
  fsk.set('dependency_version_edges', []);
  // Generic first-party usage slice that does NOT contain any dependency name —
  // so the classifier's function-tier name-match heuristic never fires and the
  // dep lands at `module` via the coarse-callgraph branch, exactly as a real
  // Rails scan does.
  fsk.set('project_usage_slices', [
    {
      project_id: PROJECT_ID,
      extraction_run_id: RUN_ID,
      file_path: 'app/controllers/posts_controller.rb',
      line_number: 1,
      target_name: 'app.controller.index',
      target_type: 'app.controller.index',
      resolved_method: 'app.controller.index',
    },
  ]);
}

function verdictOf(fsk: FakeStorage, pdvId: string): { level?: string; details?: any } {
  const u = fsk.updates.find(
    (x) => x.table === 'project_dependency_vulnerabilities' && x.filter.id === pdvId && 'reachability_level' in x.values,
  );
  return { level: u?.values.reachability_level, details: u?.values.reachability_details };
}

beforeEach(() => jest.clearAllMocks());

describe('updateReachabilityLevels — Rails framework-mediated model', () => {
  it('PROMOTES a Rack multipart-parsing DoS module finding to data_flow on a deployed web app', async () => {
    const fsk = new FakeStorage();
    seedGemDep(fsk, { name: 'rack', osvId: 'CVE-2023-27530', summary: RACK_MULTIPART_DOS });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'gem',
      usedTransitives: new Set(['rack']),
      railsFeatureSignals: railsSignals(),
      httpEntryPointCount: 75,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('data_flow');
    expect(details?.verdict).toBe('always_on_framework_runtime');
    expect(details?.sink).toBe('rails-rack-request-parser');
  });

  it('DEV-ONLY DEMOTE: better_errors (Gemfile :development) module → unreachable', async () => {
    const fsk = new FakeStorage();
    seedGemDep(fsk, { name: 'better_errors', osvId: 'CVE-2021-39197', summary: BETTER_ERRORS_CSRF, filesImporting: 0 });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'gem',
      usedTransitives: new Set(['better_errors']),
      railsFeatureSignals: railsSignals(),
      httpEntryPointCount: 75,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('dev_only_dependency');
    expect(details?.package).toBe('better_errors');
  });

  it('FEATURE DEMOTE: a Rack::Static LFI module → unreachable (Rack::Static not mounted)', async () => {
    const fsk = new FakeStorage();
    seedGemDep(fsk, { name: 'rack', osvId: 'CVE-2025-27610', summary: RACK_STATIC_LFI });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'gem',
      usedTransitives: new Set(['rack']),
      railsFeatureSignals: railsSignals(),
      httpEntryPointCount: 75,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.verdict).toBe('feature_precondition_absent');
    expect(details?.feature).toBe('rack-static-middleware');
  });

  it('DEMOTE applies even on a non-web-app (0 routes): a Nokogiri XSLT CVE → unreachable', async () => {
    const fsk = new FakeStorage();
    seedGemDep(fsk, { name: 'nokogiri', osvId: 'GHSA-v2fc-qm4h-8hqv', summary: NOKOGIRI_XSLT_LEAK });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'gem',
      usedTransitives: new Set(['nokogiri']),
      railsFeatureSignals: railsSignals(),
      httpEntryPointCount: 0,
    });
    const { level, details } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('unreachable');
    expect(details?.feature).toBe('nokogiri-advanced-xml-api');
  });

  it('STAYS module: a Rack request-parser CVE on a library repo (0 routes → no promotion)', async () => {
    const fsk = new FakeStorage();
    seedGemDep(fsk, { name: 'rack', osvId: 'CVE-2023-27530', summary: RACK_MULTIPART_DOS });
    await updateReachabilityLevels(PROJECT_ID, RUN_ID, fsk as unknown as Storage, log, undefined, {
      ecosystem: 'gem',
      usedTransitives: new Set(['rack']),
      railsFeatureSignals: railsSignals(),
      httpEntryPointCount: 0,
    });
    const { level } = verdictOf(fsk, 'pdv-1');
    expect(level).toBe('module');
  });
});
