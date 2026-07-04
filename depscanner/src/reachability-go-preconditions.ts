/**
 * Go / net-http framework-mediated reachability model — the Go-module-ecosystem
 * MIRROR of `reachability-feature-preconditions.ts` (Java/Spring/Maven),
 * `reachability-symfony-preconditions.ts` (PHP/Symfony/Composer) and
 * `reachability-rails-preconditions.ts` (Ruby/Rails/RubyGems).
 *
 * Go is DIFFERENT from the dynamic-framework ecosystems, and better: its import
 * graph is precise at the SUBPACKAGE level. `golang.org/x/net` is one module but
 * a grab-bag of independently-imported packages (`http2`, `html`, `idna`,
 * `proxy`, `websocket`, …); `golang.org/x/crypto` likewise (`ssh`, `acme`,
 * `bcrypt`, `openpgp`, …). The `go build` toolchain only compiles the packages a
 * program actually imports, so a CVE scoped to a subpackage the repo never
 * imports is PROVABLY not in the binary — the strongest reachability evidence we
 * have, and one the coarse callgraph models can't match.
 *
 * The reachability classifier floors every direct/imported Go module at `module`
 * (`golang` is not in EXPLICIT_IMPORT_ECOSYSTEMS — its tree-sitter resolution is
 * per-module, not per-subpackage, so `files_importing_count` counts imports of
 * ANY subpackage). That collapses the two facts above: caddy imports
 * `golang.org/x/net/http2` (serves HTTP/2) but NOT `golang.org/x/net/html`, yet
 * both the http2 DoS CVEs and the html-parser CVEs land at `module` (hidden).
 * Measured on caddy 2.x: 48/48 dependency-CVEs at `module`, 0 shown, and the
 * always-on HTTP/2 rapid-reset / stream-cancel / CONTINUATION-flood DoS CVEs —
 * genuinely reachable on every request of a deployed web server — silenced. That
 * is a silence false-negative, the worst error class.
 *
 * This model splits the `module` bucket using the subpackage import set:
 *   1. `SUBPACKAGE_GATES` — DEMOTES `module`→`unreachable` when the CVE's affected
 *      subpackage (inferred from the advisory summary) is PROVABLY not imported by
 *      any first-party source file (x/crypto/ssh CVEs on a server that runs no SSH;
 *      x/net/html parser CVEs on a server that parses no HTML).
 *   2. `ALWAYS_ON_RUNTIME` — PROMOTES `module`→visible for a deployed Go HTTP
 *      server when the CVE lives in an always-on request-path subpackage the repo
 *      DOES import (x/net/http2 on a server that serves HTTP/2).
 *   3. `gatherGoImportSignals` — walks `.go` files to collect the first-party
 *      import set + the deployed-HTTP-server signal (a `main` package that serves).
 *
 * SAFETY (identical doctrine to the Java / PHP / Ruby models — a wrongful DEMOTION
 * silences a real vuln):
 *   - DEMOTE only when the affected subpackage is *provably not imported* AND the
 *     import scan was complete. Any ambiguity → refuse: an unrecognized project
 *     (no go.mod), a truncated scan (import set incomplete), or a summary that
 *     names no gated subpackage all leave the finding at `module`.
 *   - The subpackage import check treats a DESCENDANT import as "imported" (a repo
 *     that imports `ssh/agent` pulls `ssh`), so a CVE on a parent package is never
 *     demoted when a child is used — the conservative direction.
 *   - PROMOTE is the risky direction (over-promotion manufactures noise): only the
 *     well-defined always-on HTTP-server stack, gated on the affected subpackage
 *     being imported AND the project being a deployed HTTP server, is promoted.
 *   - Go modules only. Other ecosystems get no signals → nothing moves.
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Project-import signals
// ---------------------------------------------------------------------------

export interface GoImportSignals {
  /**
   * True once a `go.mod` was found + parsed. When false the detector cannot
   * reason about the import graph, so every demotion / promotion is refused —
   * the "cannot reason" sentinel.
   */
  recognized: boolean;
  /**
   * True when the `.go` scan hit its file/byte cap. The import set may be
   * incomplete, so a subpackage that looks un-imported might actually be used —
   * every DEMOTION is refused when this is set (a demotion relies on proving
   * absence). Promotion still runs (it relies on a positive import + the server
   * signal, both of which a truncated scan can only UNDER-report → fail-safe).
   */
  truncated: boolean;
  /**
   * True when this is a deployed Go HTTP server: a `package main` executable that
   * serves HTTP (`http.Serve` / `ListenAndServe` / `http2.Serve` /
   * `http2.ConfigureServer`, or a `h2c` handler). Gates the always-on promotion,
   * standing in for the http-route-entry-point signal the framework detectors
   * can't produce for a server (caddy) that routes via its own module system
   * rather than code-registered `http.HandleFunc` / mux handlers.
   */
  isDeployedHttpServer: boolean;
  /**
   * Every first-party imported package path (full, including subpackage —
   * `golang.org/x/net/http2`, `golang.org/x/crypto/ssh/agent`). Stdlib paths
   * (no dot in the first segment) are excluded to bound the set.
   */
  importedPackages: Set<string>;
  /**
   * Arc 2 (dependency-source import graphs): the toolchain-computed transitive
   * COMPILE SET — `go list -deps ./...` output, unioned across every module in
   * the workspace. Contains every package compiled into the build, first-party
   * AND dependency-internal, so it is ground truth for "is this subpackage in
   * the binary?". Populated by the reachability classifier's signals merge
   * (from `options.transitiveImports`), never by `gatherGoImportSignals`.
   * Undefined = the oracle didn't run. Consulted ONLY by the demotion gate —
   * a transitive import is NEVER promotion evidence (the promotion's
   * `requiredSubpackage` reads `importedPackages` alone).
   */
  transitiveImportedPackages?: Set<string>;
  /**
   * True only when the compile set is COMPLETE: `go list -deps` succeeded for
   * the single root module, or for EVERY module of a multi-module workspace
   * (union). The precondition for any transitive ABSENCE claim
   * (`requiresTransitiveProof` rules). A positive membership answer in
   * `transitiveImportedPackages` is valid regardless — it only ever refuses.
   */
  transitiveComplete?: boolean;
}

/** Empty (nothing recognized) signals — the "cannot reason" sentinel. */
export function emptyGoImportSignals(): GoImportSignals {
  return {
    recognized: false,
    truncated: false,
    isDeployedHttpServer: false,
    importedPackages: new Set(),
  };
}

/**
 * Does the project import `pkg` — exactly, or via any DESCENDANT package
 * (`ssh/agent` counts as importing `ssh`, since the child compilation unit pulls
 * the parent)? An ANCESTOR import does NOT count (importing `ssh` does not
 * compile `ssh/agent`), which is exactly the Go-accurate build semantics: only
 * imported packages are compiled.
 */
function importsSubpackage(signals: GoImportSignals, pkg: string): boolean {
  const prefix = pkg + '/';
  for (const p of signals.importedPackages) {
    if (p === pkg || p.startsWith(prefix)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// SUBPACKAGE-IMPORT GATE (DEMOTE module → unreachable when the affected
// subpackage is provably not imported)
// ---------------------------------------------------------------------------

interface SubpackageRule {
  /** The affected import path. Demote when the repo imports neither it nor a descendant. */
  subpackage: string;
  /**
   * The advisory summary indicates this subpackage. Rules with
   * `requiresTransitiveProof` may only carry patterns that NAME the affected
   * subpackage (`/protojson/i`, `/\bidna\b/i`) — a generic term (`/json/i`)
   * would let a future CVE in a DIFFERENT subpackage of the same module ride a
   * transitive absence proof it doesn't deserve.
   */
  patterns: RegExp[];
  /**
   * Arc 2: first-party import absence is KNOWN-UNSOUND for this subpackage —
   * common dependency chains compile it in transitively (idna via certmagic /
   * any x/net h2 consumer; protojson via cel-go). Demote ONLY when the
   * toolchain-computed compile set is complete AND the subpackage is absent
   * from it. Without the flag a rule keeps today's first-party-only behavior
   * when no compile set is available.
   */
  requiresTransitiveProof?: boolean;
}

interface ModuleSubpackageGate {
  /** Exact dependency (module) name the CVE is attributed to. */
  module: string;
  /** Ordered MOST-SPECIFIC-FIRST (agent/knownhosts before the generic ssh row). */
  rules: SubpackageRule[];
}

export const SUBPACKAGE_GATES: ModuleSubpackageGate[] = [
  // --- golang.org/x/crypto — a grab-bag of independent crypto subpackages. A
  //     web server typically imports only bcrypt / scrypt (password hashing);
  //     the ssh / agent / knownhosts / acme / openpgp subpackages are separate
  //     compilation units a non-SSH, non-ACME-client server never pulls. ---
  {
    module: 'golang.org/x/crypto',
    rules: [
      // ssh/agent — the SSH agent protocol (most-specific first).
      {
        subpackage: 'golang.org/x/crypto/ssh/agent',
        patterns: [/ssh\/agent/i, /ssh agent/i],
      },
      // ssh/knownhosts — known_hosts host-key checking.
      {
        subpackage: 'golang.org/x/crypto/ssh/knownhosts',
        patterns: [/knownhosts/i, /known[_ ]hosts/i],
      },
      // ssh — the SSH transport/server. Terrapin (CVE-2023-48795) is an
      // Encrypt-then-MAC / ChaCha20-Poly1305 prefix-truncation attack on the SSH
      // transport; PublicKeyCallback / key-exchange DoS are the ServerConfig path.
      {
        subpackage: 'golang.org/x/crypto/ssh',
        patterns: [
          /\bssh\b/i,
          /terrapin/i,
          /encrypt-then-mac/i,
          /publickeycallback/i,
          /serverconfig/i,
          /key exchange/i,
        ],
      },
      // acme / autocert — the built-in ACME client + on-disk cert cache.
      {
        subpackage: 'golang.org/x/crypto/acme',
        patterns: [/\bacme\b/i, /autocert/i],
      },
      // openpgp — the (deprecated) OpenPGP implementation.
      {
        subpackage: 'golang.org/x/crypto/openpgp',
        patterns: [/openpgp/i],
      },
    ],
  },
  // --- golang.org/x/net — a grab-bag of independent networking subpackages. A
  //     server serving HTTP/2 imports `http2` (see the promotion below) but not
  //     necessarily the `html` tokenizer or the `idna` label encoder, which are
  //     separate compilation units. ---
  {
    module: 'golang.org/x/net',
    rules: [
      // html — the HTML tokenizer/parser. XSS, text-node rendering, DOCTYPE /
      // foreign-content handling, non-linear parse DoS all live here. A server
      // that never parses HTML with x/net/html never runs this code.
      {
        subpackage: 'golang.org/x/net/html',
        patterns: [
          /\bhtml\b/i,
          /text node/i,
          /cross-site scripting/i,
          /\bxss\b/i,
          /doctype/i,
          /foreign content/i,
          /character reference/i,
        ],
      },
      // idna — RESTORED (Arc 2) behind a transitive proof. History: removed
      // 2026-07-02 because first-party import absence was proven unsound on
      // BOTH validated apps (`go mod why` traces gitea → certmagic →
      // golang.org/x/net/idna; caddy's h2 client transport executes
      // idna.ToASCII on every proxied request). With `requiresTransitiveProof`
      // the rule demotes ONLY when the toolchain-computed compile set is
      // complete and idna is absent from it — on gitea and caddy the compile
      // set CONTAINS idna, so this rule refuses there (labels: `module` both).
      {
        subpackage: 'golang.org/x/net/idna',
        patterns: [/\bidna\b/i, /punycode/i],
        requiresTransitiveProof: true,
      },
    ],
  },
  // --- google.golang.org/protobuf — the protojson encoder is a separate
  //     compilation unit most protobuf consumers never pull (the wire format
  //     lives in proto/; protojson is opt-in JSON transcoding). First-party
  //     absence proves nothing (caddy: cel-go's object.go calls protojson from
  //     the celmatcher eval path — a labelled transitive chain), so the rule
  //     requires the transitive compile-set proof. Two-directional corpus
  //     ground truth: caddy CVE-2024-24786 `module` (cel-go compiles protojson
  //     in → refuse), gitea same CVE `unreachable` (nothing on gitea's prod
  //     path compiles protojson → demote). ---
  {
    module: 'google.golang.org/protobuf',
    rules: [
      {
        subpackage: 'google.golang.org/protobuf/encoding/protojson',
        // Subpackage-naming pattern ONLY — /json/i was reviewed and rejected:
        // it would let a future core-protobuf CVE whose summary merely mentions
        // JSON ride this rule's absence proof.
        patterns: [/protojson/i],
        requiresTransitiveProof: true,
      },
    ],
  },
];

/**
 * Arc 2 trigger guard: the gated module names — the dep-import-graph step
 * only pays for `go list` when one of these is actually a dependency.
 */
export function goSubpackageGateModules(): Set<string> {
  return new Set(SUBPACKAGE_GATES.map((g) => g.module.toLowerCase()));
}

export interface GoDemotionResult {
  demote: boolean;
  subpackage?: string;
  matchedPattern?: string;
  /**
   * Which absence standard backed the demotion: 'first_party' (today's
   * import-scan proof) or 'prod_path' (Arc 2: the complete toolchain compile
   * set — first-party AND every dependency on the production path). Drives
   * the verdict stamp; legacy rules always stamp 'first_party' so their
   * verdict strings stay byte-stable.
   */
  proofStandard?: 'first_party' | 'prod_path';
}

/**
 * Is `pkg` (or a descendant) in the transitive COMPILE SET? Ground truth from
 * the Go toolchain — a positive answer refuses a demotion regardless of
 * completeness (`go list -deps` closures are exact: if ssh is compiled it is
 * listed, so exact membership suffices; the descendant check is harmless
 * belt-and-suspenders in the refusal direction).
 */
function transitivelyCompiled(signals: GoImportSignals, pkg: string): boolean {
  const set = signals.transitiveImportedPackages;
  if (!set) return false;
  const prefix = pkg + '/';
  for (const p of set) {
    if (p === pkg || p.startsWith(prefix)) return true;
  }
  return false;
}

/**
 * Decide whether a `module` Go finding should be demoted to `unreachable` because
 * the CVE's affected subpackage is PROVABLY not imported by the project. Pure —
 * unit-tested directly.
 *
 * Returns `{ demote: false }` unless signals are recognized + complete (not
 * truncated), the finding has a dep name + summary, its module has a subpackage
 * gate, a rule's pattern matches the summary, AND the matched subpackage (nor any
 * descendant) is imported.
 */
export function evaluateGoSubpackageDemotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  signals: GoImportSignals | null | undefined;
}): GoDemotionResult {
  const { depName, summary, signals } = input;
  if (!signals || !signals.recognized) return { demote: false };
  // A demotion proves absence; an incomplete import scan can't. Refuse.
  if (signals.truncated) return { demote: false };
  if (!depName || !summary) return { demote: false };

  const dep = depName.toLowerCase();
  const gate = SUBPACKAGE_GATES.find((g) => g.module.toLowerCase() === dep);
  if (!gate) return { demote: false };

  for (const rule of gate.rules) {
    const matched = rule.patterns.find((re) => re.test(summary));
    if (!matched) continue;
    // First matching rule wins (most-specific-first). Demote only when the
    // affected subpackage is provably not imported.
    if (importsSubpackage(signals, rule.subpackage)) return { demote: false };
    // Arc 2 veto: the toolchain compile set is ground truth — a subpackage
    // compiled in via ANY dependency chain (certmagic→idna, cel-go→protojson)
    // refutes first-party absence. Positive evidence is valid regardless of
    // completeness; it only ever refuses.
    if (transitivelyCompiled(signals, rule.subpackage)) return { demote: false };
    if (rule.requiresTransitiveProof) {
      // First-party absence is KNOWN-unsound for this subpackage: demote only
      // on a complete transitive absence proof. Anything less = unknown = refuse.
      if (signals.transitiveComplete !== true) return { demote: false };
      return {
        demote: true,
        subpackage: rule.subpackage,
        matchedPattern: matched.source,
        proofStandard: 'prod_path',
      };
    }
    return {
      demote: true,
      subpackage: rule.subpackage,
      matchedPattern: matched.source,
      proofStandard: 'first_party',
    };
  }
  return { demote: false };
}

// ---------------------------------------------------------------------------
// ALWAYS-ON HTTP-server-stack PROMOTION (module → visible)
// ---------------------------------------------------------------------------

interface GoAlwaysOnRule {
  sink: string;
  /** Exact dependency (module) name. */
  module: string;
  /** The affected subpackage must be imported for the promotion to fire. */
  requiredSubpackage: string;
  patterns: RegExp[];
  /** Veto: a summary matching any of these is a feature-gated sibling — never promote. */
  exclude?: RegExp[];
  promoteTo: 'function' | 'data_flow';
  threatTag?: string;
}

export const ALWAYS_ON_RUNTIME: GoAlwaysOnRule[] = [
  // --- golang.org/x/net/http2 — the HTTP/2 server protocol handler. On a
  //     deployed Go HTTP server that imports http2/h2c, the protocol-level DoS
  //     CVEs (rapid reset, stream cancellation, CONTINUATION flood, HPACK /
  //     header memory growth) are first-party wired. Tier is `function`, NOT
  //     data_flow (corrected 2026-07-02 by caddy ground-truth verification):
  //     a server's DEFAULT inbound HTTP/2 is Go's STDLIB h2 bundle — the x/net
  //     module's server code typically runs via opt-in h2c wiring (caddy:
  //     AllowH2C, default off) and its client code via an h2 upstream
  //     transport, so "unconditionally on the inbound request path" overclaims
  //     for the module's copy. EXCLUDE the html/idna siblings. ---
  {
    sink: 'go-http2-server',
    module: 'golang.org/x/net',
    requiredSubpackage: 'golang.org/x/net/http2',
    patterns: [
      /http2/i,
      /http\/2/i,
      /rapid reset/i,
      /stream cancellation/i,
      /\bhpack\b/i,
      /settings_max_frame/i,
      /continuation/i,
      /too many headers/i,
    ],
    exclude: [
      /\bhtml\b/i,
      /text node/i,
      /cross-site scripting/i,
      /\bxss\b/i,
      /doctype/i,
      /foreign content/i,
      /\bidna\b/i,
      /punycode/i,
    ],
    promoteTo: 'function',
    threatTag: 'requires_untrusted_request',
  },
  // --- golang.org/x/net/html — the HTML tokenizer/parser. This package exists
  //     to parse UNTRUSTED HTML from the web, so a deployed Go HTTP server that
  //     imports it is (overwhelmingly) feeding attacker-influenced content
  //     through html.Parse — gitea renders every user markdown/comment/README
  //     through it and serves the output to other users (stored-XSS shape for
  //     the XSS CVEs, remote DoS for the parser CVEs). The parser/tokenizer
  //     CVEs (text-node rendering, DOCTYPE/character-reference handling,
  //     foreign-content, duplicate-attribute XSS, non-linear/infinite parse
  //     loops) are on that content path. PROMOTE to data_flow (ground truth:
  //     gitea labels all 8 data_flow). Unlike http2 (where the STDLIB serves
  //     default h2, so the x/net copy isn't the inbound path), there is no
  //     stdlib-does-it-instead caveat for html — importing x/net/html means you
  //     USE x/net/html. The `requiredSubpackage` import-gate is the safety: a
  //     server that never imports x/net/html (caddy) never promotes — its html
  //     CVEs stay demoted-unreachable via SUBPACKAGE_GATES. EXCLUDE the
  //     http2/idna siblings belt-and-suspenders. ---
  {
    sink: 'go-net-html-parser',
    module: 'golang.org/x/net',
    requiredSubpackage: 'golang.org/x/net/html',
    patterns: [
      /net\/html/i,
      /net html parser/i,
      /html parser/i,
      /text node/i,
      /cross-site scripting/i,
      /\bxss\b/i,
      /doctype/i,
      /character reference/i,
      /foreign content/i,
      /namespaced element/i,
      /duplicate attribute/i,
      /(?:infinite|non-linear).{0,20}pars/i,
      /parsing loop/i,
    ],
    exclude: [/http2/i, /http\/2/i, /rapid reset/i, /\bhpack\b/i, /continuation/i, /\bidna\b/i, /punycode/i],
    promoteTo: 'data_flow',
    threatTag: 'requires_untrusted_html',
  },
  // --- golang.org/x/text/language — the language-tag matcher. Its
  //     `ParseAcceptLanguage` is called on the client-supplied `Accept-Language`
  //     request header by every i18n locale middleware, so the ReDoS in that
  //     parser (CVE-2022-32149) fires on ordinary request traffic when the
  //     server imports x/text/language for i18n (gitea's locale middleware
  //     calls `language.ParseAcceptLanguage(req.Header.Get("Accept-Language"))`
  //     on every request — ground truth labels it data_flow). Import-gated on
  //     x/text/language + isDeployedHttpServer: a server that never imports it
  //     (caddy) has the CVE demoted-unreachable already and never promotes.
  //     Summary is specific to the Accept-Language parser so a different x/text
  //     CVE (collation, transform, unicode tables) never matches. ---
  {
    sink: 'go-text-accept-language',
    module: 'golang.org/x/text',
    requiredSubpackage: 'golang.org/x/text/language',
    patterns: [/accept-language/i, /accept language/i, /x\/text\/language/i, /parseacceptlanguage/i],
    promoteTo: 'data_flow',
    threatTag: 'requires_untrusted_request',
  },
];

export interface GoPromotionResult {
  promote: boolean;
  sink?: string;
  promoteTo?: 'function' | 'data_flow';
  matchedPattern?: string;
  threatTag?: string;
}

/**
 * Decide whether a `module` Go finding should be PROMOTED to a visible tier
 * because its CVE lives in an always-on HTTP-server subpackage the project both
 * imports AND deploys as a server. Pure — unit-tested directly.
 */
export function evaluateGoAlwaysOnRuntimePromotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  signals: GoImportSignals | null | undefined;
}): GoPromotionResult {
  const { depName, summary, signals } = input;
  if (!signals || !signals.isDeployedHttpServer) return { promote: false };
  if (!depName || !summary) return { promote: false };
  const dep = depName.toLowerCase();
  for (const row of ALWAYS_ON_RUNTIME) {
    if (row.module.toLowerCase() !== dep) continue;
    if (row.exclude && row.exclude.some((re) => re.test(summary))) continue;
    const matched = row.patterns.find((re) => re.test(summary));
    if (!matched) continue;
    if (!importsSubpackage(signals, row.requiredSubpackage)) continue;
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
// Project-import detector (reads the workspace)
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'vendor', 'testdata', 'tmp', 'build', 'dist', 'out',
  '.idea', 'coverage', '.github', 'examples', 'docs',
]);

const MAX_DIR_DEPTH = 12;
const MAX_CODE_FILES = 12000;
const MAX_CODE_BYTES = 48 * 1024 * 1024;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

// A deployed HTTP server: an http/http2 listen-and-serve call. `ConfigureServer`
// / `h2c.NewHandler` configure the HTTP/2 side of a server specifically.
const SERVE_RE =
  /\b(?:http|http2)\.(?:ListenAndServe|ListenAndServeTLS|Serve|ServeTLS|ConfigureServer)\b|\bh2c\.NewHandler\b/;

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
 * Extract the imported package paths from a Go source file. Handles both the
 * factored `import ( … )` block (one path per line, optionally aliased / `_` /
 * `.`) and the single `import "path"` form. Only non-stdlib paths (a dot in the
 * first segment) are returned, to bound the set.
 *
 * Comments are stripped FIRST: the factored-block match is non-greedy on `)`, so
 * a `)` inside a comment WITHIN an import block (e.g. gitea's GPG file has
 * `// OpenPGP (RFC 4880) armored signatures` above the `golang.org/x/crypto/openpgp`
 * import) would otherwise close the block early and drop every import after it —
 * a silence-FN (the openpgp CVE would look un-imported and get wrongly demoted).
 * Import paths never contain line- or block-comment delimiters, so stripping
 * comments is safe for path extraction even though it may mangle unrelated
 * string literals elsewhere in the file.
 */
function extractGoImports(source: string): string[] {
  const out: string[] = [];
  const addPath = (raw: string): void => {
    const p = raw.trim();
    if (!p) return;
    const first = p.split('/')[0];
    if (!first.includes('.')) return; // stdlib
    out.push(p);
  };

  const src = source
    .replace(/\/\*[\s\S]*?\*\//g, ' ') // block comments (may span lines / contain parens)
    .replace(/\/\/[^\n]*/g, ''); // line comments

  // Factored import blocks: import ( … ).
  const blockRe = /\bimport\s*\(([\s\S]*?)\)/g;
  let m: RegExpExecArray | null;
  while ((m = blockRe.exec(src)) !== null) {
    for (const q of m[1].matchAll(/"([^"]+)"/g)) addPath(q[1]);
  }
  // Single-line imports: import "path" or import alias "path".
  const singleRe = /\bimport\s+(?:[A-Za-z0-9_.]+\s+)?"([^"]+)"/g;
  while ((m = singleRe.exec(src)) !== null) addPath(m[1]);

  return out;
}

/**
 * Walk `root` (bounded) gathering the first-party Go import set + the deployed-
 * HTTP-server signal. Never throws — an unreadable tree or a non-Go workspace
 * yields empty (unrecognized) signals, which refuses every demotion / promotion.
 */
export function gatherGoImportSignals(root: string | undefined): GoImportSignals {
  const signals = emptyGoImportSignals();
  if (!root) return signals;
  try {
    if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) return signals;
  } catch {
    return signals;
  }
  // A Go module is recognized by its go.mod at the workspace root.
  if (!fs.existsSync(path.join(root, 'go.mod'))) return signals;

  let hasMainPackage = false;
  let servesHttp = false;
  let codeFileCount = 0;
  let codeBytes = 0;
  let truncated = false;

  const walk = (dir: string, depth: number): void => {
    if (depth > MAX_DIR_DEPTH) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        walk(path.join(dir, ent.name), depth + 1);
        continue;
      }
      if (!ent.isFile()) continue;
      const lower = ent.name.toLowerCase();
      // First-party Go source only; skip generated tests.
      if (!lower.endsWith('.go') || lower.endsWith('_test.go')) continue;
      if (codeFileCount >= MAX_CODE_FILES || codeBytes >= MAX_CODE_BYTES) {
        truncated = true;
        continue;
      }
      const src = safeRead(path.join(dir, ent.name), MAX_FILE_BYTES);
      if (!src) continue;
      codeFileCount += 1;
      codeBytes += src.length;
      for (const p of extractGoImports(src)) signals.importedPackages.add(p);
      if (!hasMainPackage && /^\s*package\s+main\b/m.test(src)) hasMainPackage = true;
      if (!servesHttp && SERVE_RE.test(src)) servesHttp = true;
    }
  };

  walk(root, 0);

  signals.truncated = truncated;
  signals.recognized = true;
  signals.isDeployedHttpServer = hasMainPackage && servesHttp;
  return signals;
}
