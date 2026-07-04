/**
 * Python / Django framework-mediated reachability model — the pypi-ecosystem
 * MIRROR of `reachability-feature-preconditions.ts` (Java/Spring/Maven),
 * `reachability-symfony-preconditions.ts` (PHP/Symfony/Composer),
 * `reachability-rails-preconditions.ts` (Ruby/Rails/RubyGems) and
 * `reachability-go-preconditions.ts` (Go/net-http).
 *
 * pypi IS an EXPLICIT_IMPORT_ECOSYSTEM, so the base classifier already demotes
 * a package no first-party file imports. What survives at `module` is the
 * IMPORTED-but-unproven middle — and Python shares Go's shape there: a package
 * is imported at MODULE granularity (`from PIL import Image` keeps ALL of
 * pillow at `module`) while its CVEs are scoped to SUBMODULES the app may never
 * touch (`PIL.ImageFont`, `PIL.PdfParser`, `cryptography...pkcs7`). Measured on
 * saleor 3.14 (68 module dependency-CVEs, hand-triaged): 5 genuinely-reachable
 * request-path CVEs buried (django's uri_to_iri / response-logging /
 * Email+URLValidator run on ordinary request traffic; pillow's WebP decoder
 * runs on every uploaded image), ~25 provably-absent-feature CVEs over-kept,
 * and the rest an honest undecidable middle.
 *
 * This model splits that `module` bucket:
 *   1. `FEATURE_PRECONDITIONS` — advisory→required-feature table (owner +
 *      summary) that DEMOTES `module`→`unreachable` when the feature is
 *      provably absent: a pillow submodule / cryptography serialization API the
 *      first-party import set + code text never touch, `django.contrib.humanize`
 *      never referenced, a Windows-only bug on a container/Linux deploy, the
 *      h11 fallback parser shadowed by httptools, setuptools' PackageIndex
 *      (build-time tooling no web app invokes at runtime).
 *   2. `evaluateDjangoDevOnlyDemotion` — manifest dev-group demotion (poetry
 *      dev/test groups, Pipfile [dev-packages], requirements-dev.txt): a dev
 *      tool imported only by test code sits at `module` (its own test files
 *      import it) yet never loads in production.
 *   3. `ALWAYS_ON_RUNTIME` — always-on-request-path table that PROMOTES
 *      `module`→visible for a deployed Django app: django's uri_to_iri /
 *      log-response / validator ReDoS CVEs, pillow's WebP decode on an app
 *      with an image-upload surface. Rows may also match by advisory ID
 *      (`ids`) — PYSEC-2023-175's summary is the literal string "Summary", so
 *      summary patterns alone cannot see it.
 *   4. `gatherDjangoFeatureSignals` — reads manifests (pyproject.toml, Pipfile,
 *      requirements*.txt) + walks first-party `.py`/`.html` collecting the
 *      dotted import set and liberal code-text signals.
 *
 * SAFETY (identical doctrine to the four sibling models — a wrongful DEMOTION
 * silences a real vuln):
 *   - DEMOTE only when the required feature is *provably absent*. Any ambiguity
 *     → `unknown`, never `absent`: an unrecognized project (no Django dep / no
 *     project marker) or a truncated code scan refuses every demotion.
 *   - Detectors are LIBERAL about "present" (a bare substring mention of
 *     `imagefont` anywhere in first-party code blocks the ImageFont demotion);
 *     confident only about absence. Known transitive consumers (a captcha lib
 *     pulling ImageFont, paramiko pulling cryptography's SSH loaders) are
 *     modelled as `unlessDeps` — their presence also blocks the demotion.
 *   - PROMOTE is the risky direction (over-promotion manufactures noise): only
 *     the well-defined always-on Django request path + the upload-gated WebP
 *     decoder are promoted, and only for a deployed web app.
 *   - pypi only. Other ecosystems get no signals → nothing moves.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  pep503Normalize,
  transitiveConsumerVeto,
  type TransitiveImportIndex,
  type TransitiveQuestion,
} from './transitive-imports';

// ---------------------------------------------------------------------------
// Project-feature signals
// ---------------------------------------------------------------------------

export interface DjangoFeatureSignals {
  /**
   * True once a dependency manifest was parsed AND this is recognizably a
   * Django project (`django` in the dependency universe plus a project marker:
   * manage.py / wsgi.py / asgi.py / an INSTALLED_APPS setting). When false the
   * detector cannot prove any feature absent, so every demotion / promotion is
   * refused — the "cannot reason" sentinel.
   */
  recognized: boolean;
  /**
   * True when the `.py` scan hit its file/byte cap. A code signal we didn't
   * read might exist, so features whose absence relies on scanning code resolve
   * to `unknown` (never `absent`) when this is set.
   */
  truncated: boolean;
  /**
   * Package names (normalized: lowercased, `_`→`-`, extras stripped) declared
   * in a dev-only manifest scope — poetry dev/test/lint/docs groups, Pipfile
   * `[dev-packages]`, requirements-dev/test/lint files — AND nowhere at prod
   * scope. The dev-only lever.
   */
  devDeps: Set<string>;
  /** Every normalized package name seen in any manifest — for presence checks. */
  depUniverse: Set<string>;
  /**
   * Every first-party dotted import path, lowercased: `import PIL.Image` →
   * `pil.image`; `from PIL import ImageFont, ImageDraw` → `pil`,
   * `pil.imagefont`, `pil.imagedraw`. Relative imports (leading `.`) are
   * first-party and skipped.
   */
  importedModules: Set<string>;
  /**
   * Lowercased concat of first-party `.py` + `.html` sources — the liberal
   * substring surface (a template's `{% load humanize %}` lives here, as does
   * any settings-file INSTALLED_APPS entry).
   */
  codeText: string;
  /**
   * True when this is a deployable Django web app: a wsgi.py / asgi.py module
   * exists, or the settings declare WSGI_APPLICATION / ASGI_APPLICATION /
   * ROOT_URLCONF. Gates the always-on promotion (the pypi stand-in for the
   * HTTP-route-entry-point signal, which framework detection may or may not
   * emit for a GraphQL-only Django app).
   */
  isDeployedWebApp: boolean;
  /**
   * True when the app has an image-upload/decode surface: an ImageField (or a
   * subclass — VersatileImageField matches by substring) or a first-party
   * `Image.open(` call. Gates the pillow WebP-decode promotion.
   */
  usesImageUploads: boolean;
  /**
   * Arc 2 (dependency-source import graphs): per-dist imports + question-token
   * hits extracted from the installed prod dists' wheels. Populated by the
   * reachability classifier's signals merge (from
   * `options.transitiveImports`), never by `gatherDjangoFeatureSignals`.
   * v1 is VETO-ONLY: a non-owner dist importing/mentioning a row's question
   * refuses that demotion; absence proves nothing here (hard lists survive).
   * Undefined = the oracle didn't run.
   */
  transitiveImports?: TransitiveImportIndex;
}

export type FeaturePresence = 'present' | 'absent' | 'unknown';

/** Empty (nothing recognized) signals — the "cannot reason" sentinel. */
export function emptyDjangoFeatureSignals(): DjangoFeatureSignals {
  return {
    recognized: false,
    truncated: false,
    devDeps: new Set(),
    depUniverse: new Set(),
    importedModules: new Set(),
    codeText: '',
    isDeployedWebApp: false,
    usesImageUploads: false,
  };
}

/** Normalize a pypi package name: lowercase, `_`→`-`, strip extras (`x[y]`). */
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/\[.*$/, '').replace(/_/g, '-').trim();
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
function resolve(present: boolean, s: DjangoFeatureSignals): FeaturePresence {
  if (present) return 'present';
  if (s.truncated) return 'unknown';
  return 'absent';
}

/**
 * Does the first-party import set contain `mod` — exactly, or via any
 * DESCENDANT path (`pil.imagefont.core` counts as importing `pil.imagefont`)?
 * The Python analog of the Go subpackage check. An ANCESTOR import does NOT
 * count (`import PIL` does not load `PIL.ImageFont` — submodules load only
 * when imported), which is Python-accurate module semantics.
 */
function moduleImported(s: DjangoFeatureSignals, mod: string): boolean {
  const prefix = mod + '.';
  for (const p of s.importedModules) {
    if (p === mod || p.startsWith(prefix)) return true;
  }
  return false;
}

/**
 * Any of `names` present at PROD scope. A proven-dev-only dependency is not
 * evidence about production reachability, in either direction: a dev-scoped
 * django-debug-toolbar can't feed sqlparse in prod (so it must not BLOCK that
 * demotion), and a dev-scoped httptools doesn't shadow h11 in prod (so it must
 * not ENABLE that one).
 */
function hasAnyProdDep(s: DjangoFeatureSignals, names: string[]): boolean {
  return names.some((n) => s.depUniverse.has(n) && !s.devDeps.has(n));
}

/** A pillow submodule is touched: imported, or its name appears in code. */
function pillowSubmoduleUsed(s: DjangoFeatureSignals, sub: string, extraText: string[] = []): boolean {
  return (
    moduleImported(s, `pil.${sub}`) ||
    textIncludes(s.codeText, [sub, ...extraText])
  );
}

// ---------------------------------------------------------------------------
// FEATURE-PRECONDITION table (DEMOTE module → unreachable when provably absent)
// ---------------------------------------------------------------------------

interface FeaturePrecondition {
  feature: string;
  /** Demote only when the finding's dependency NAME equals one of these (normalized). */
  owners: string[];
  /** Demote only when the advisory SUMMARY matches one of these. */
  summary: RegExp[];
  /** Is the feature enabled in the scanned project? */
  detect: (s: DjangoFeatureSignals) => FeaturePresence;
  /**
   * True when this row's absence proof is IMPORT-GATED on the specific vulnerable
   * SUBMODULE / API (not a broad config/platform feature). The vulnerable code is
   * then provably unreachable REGARDLESS of the package's own reachability tier —
   * so the caller may apply this demotion to a `function`-level finding too (the
   * usage classifier stamps `function` when the package's TOP-LEVEL API is called,
   * e.g. `tqdm(...)` / `FileLock(...)`, even though the vulnerable submodule
   * `tqdm.cli` / `SoftFileLock` is never touched). Left `false`/undefined for the
   * broad feature/platform rows (humanize, windows-only, brotli-via-Scrapy, the
   * h11 shadow) which stay `module`-only out of caution.
   */
  functionSafe?: boolean;
  /**
   * Arc 2: this row's TRANSITIVE consumer question — which module imports /
   * liberal substring tokens in a NON-OWNER prod dist's sources indicate the
   * vulnerable submodule may load. A hit VETOES the demotion (v1 is veto-only;
   * absence never bypasses the hard list — see the arc plan §8). Set ONLY on
   * submodule-load rows: consumer-SEMANTICS rows (sqlparse: "does something
   * feed sqlparse ATTACKER sql?", brotli-via-Scrapy, the h11 shadow) must NOT
   * carry one — Django itself imports sqlparse for trusted sqlmigrate SQL, so
   * a raw import veto would reverse paperless's two labelled-unreachable wins.
   */
  question?: TransitiveQuestion;
}

export const FEATURE_PRECONDITIONS: FeaturePrecondition[] = [
  // --- django.contrib.humanize (owner: django). The intcomma-filter DoS only
  //     runs if the humanize app is installed/loaded; the string "humanize"
  //     appearing NOWHERE in settings, code or templates proves it out. ---
  {
    feature: 'django-contrib-humanize',
    owners: ['django'],
    summary: [/intcomma/i, /humanize/i],
    detect: (s) => resolve(textIncludes(s.codeText, ['humanize']), s),
  },
  // --- Windows-only Django CVE (owner: django). NFKC-normalization slowness
  //     (UsernameField DoS) only bites Windows; structurally absent on the
  //     Linux/container deploys Deptex scans — the same doctrine as the Rails
  //     model's windows-only row. Keyed narrowly on "on Windows" in the summary. ---
  {
    feature: 'django-windows-only',
    owners: ['django'],
    summary: [/\bon windows\b/i],
    detect: () => 'absent',
  },
  // --- PIL.ImageFont (owner: pillow). Font-processing CVEs live in the
  //     ImageFont submodule, loaded only when imported. A captcha lib renders
  //     text via ImageFont transitively → its presence blocks the demotion. ---
  {
    feature: 'pillow-imagefont',
    functionSafe: true,
    owners: ['pillow'],
    summary: [/imagefont/i, /\bfont/i],
    question: { modules: ['pil.imagefont'], tokens: ['imagefont', 'truetype('] },
    detect: (s) =>
      resolve(
        pillowSubmoduleUsed(s, 'imagefont', ['truetype(']) ||
          hasAnyProdDep(s, ['django-simple-captcha', 'captcha', 'pilkit', 'easy-thumbnails']),
        s,
      ),
  },
  // --- PIL.PdfParser (owner: pillow). The PDF trailer-parsing loop only runs
  //     when pillow READS/appends an existing PDF (PdfParser). Detect keys on
  //     the submodule itself, not a generic ".pdf" mention — an app generating
  //     PDFs via weasyprint never touches PIL.PdfParser. ---
  {
    feature: 'pillow-pdfparser',
    functionSafe: true,
    owners: ['pillow'],
    summary: [/pdfparser/i, /pdf pars/i, /\bpdf\b/i],
    detect: (s) => resolve(pillowSubmoduleUsed(s, 'pdfparser', ['append_images']), s),
  },
  // --- PIL.ImageMath (owner: pillow). ImageMath.eval code-execution requires
  //     the app to call the opt-in eval API on attacker input. ---
  {
    feature: 'pillow-imagemath',
    functionSafe: true,
    owners: ['pillow'],
    summary: [/imagemath/i, /arbitrary code execution/i],
    detect: (s) => resolve(pillowSubmoduleUsed(s, 'imagemath'), s),
  },
  // --- cryptography PKCS7 loaders (owner: cryptography). load_pem_pkcs7 /
  //     load_der_pkcs7 are opt-in serialization APIs; an ACME client (acme /
  //     josepy) is the common transitive consumer. ---
  {
    feature: 'cryptography-pkcs7',
    functionSafe: true,
    owners: ['cryptography'],
    summary: [/pkcs7/i, /pkcs\s*#?\s*7/i],
    question: { tokens: ['pkcs7'] },
    detect: (s) =>
      resolve(textIncludes(s.codeText, ['pkcs7']) || hasAnyProdDep(s, ['acme', 'josepy']), s),
  },
  // --- cryptography PKCS12 parsing (owner: cryptography). ---
  {
    feature: 'cryptography-pkcs12',
    functionSafe: true,
    owners: ['cryptography'],
    summary: [/pkcs12/i, /pkcs\s*#?\s*12/i],
    question: { tokens: ['pkcs12'] },
    detect: (s) =>
      resolve(textIncludes(s.codeText, ['pkcs12']) || hasAnyProdDep(s, ['requests-pkcs12']), s),
  },
  // --- cryptography SSH-certificate loaders (owner: cryptography). The
  //     load_ssh_* serialization APIs; SSH client libs are the transitive
  //     consumers. Keyed on "SSH certificate" (not bare "ssh") to avoid
  //     over-matching unrelated summaries. ---
  {
    feature: 'cryptography-ssh-certificates',
    functionSafe: true,
    owners: ['cryptography'],
    summary: [/ssh certificate/i, /\bssh\b/i],
    question: { tokens: ['load_ssh', 'ssh_certificate', 'sshcertificate'] },
    detect: (s) =>
      resolve(
        textIncludes(s.codeText, ['load_ssh', 'ssh_certificate', 'sshcertificate']) ||
          hasAnyProdDep(s, ['paramiko', 'asyncssh', 'fabric', 'sshtunnel']),
        s,
      ),
  },
  // --- Brotli-via-Scrapy (owner: brotli). CVE-2025-6176's vulnerable path is
  //     Scrapy's brotli decompression; without Scrapy the finding describes a
  //     consumer the project doesn't ship. ---
  {
    feature: 'brotli-scrapy-consumer',
    owners: ['brotli', 'brotlicffi'],
    summary: [/scrapy/i],
    detect: (s) => resolve(hasAnyProdDep(s, ['scrapy']), s),
  },
  // --- h11 fallback parser shadowed (owner: h11). uvicorn prefers httptools
  //     for HTTP parsing when installed; h11's malformed-chunked-encoding bug
  //     never sees traffic. hypercorn always uses h11, and an explicit `h11`
  //     mention in code/config (e.g. uvicorn http="h11") re-activates it —
  //     both block the demotion. ---
  {
    feature: 'h11-parser-shadowed-by-httptools',
    owners: ['h11'],
    summary: [/chunked/i, /malformed/i],
    detect: (s) =>
      resolve(
        !hasAnyProdDep(s, ['httptools']) ||
          hasAnyProdDep(s, ['hypercorn']) ||
          textIncludes(s.codeText, ['h11']),
        s,
      ),
  },
  // --- sqlparse fed untrusted SQL (owner: sqlparse). Django uses sqlparse only
  //     for dev-time SQL splitting (sqlmigrate) and debug tooling; the DoS
  //     needs attacker-controlled SQL text reaching sqlparse. Absent unless
  //     first-party code imports it (or debug-toolbar, which pretty-prints
  //     queries through it, ships at prod scope). ---
  {
    feature: 'sqlparse-untrusted-sql',
    owners: ['sqlparse'],
    summary: [/denial of service/i, /nested list/i, /formatting/i],
    detect: (s) =>
      resolve(moduleImported(s, 'sqlparse') || hasAnyProdDep(s, ['django-debug-toolbar']), s),
  },
  // --- fontTools XXE (owner: fonttools). The XXE vector is fontTools' XML/TTX
  //     font handling — it requires the app to feed attacker fonts through the
  //     fontTools API directly. weasyprint's font subsetting of app-bundled
  //     CSS fonts never parses attacker TTX. ---
  {
    feature: 'fonttools-untrusted-fonts',
    owners: ['fonttools'],
    summary: [/xxe/i, /external entity/i],
    question: { modules: ['fonttools'], tokens: ['fonttools', 'ttlib'] },
    detect: (s) =>
      resolve(moduleImported(s, 'fonttools') || textIncludes(s.codeText, ['fonttools', 'ttlib']), s),
  },
  // --- setuptools PackageIndex / easy_install (owner: setuptools). Build-time
  //     package-fetch tooling (command injection via package URL, path
  //     traversal in PackageIndex.download) that no deployed web app invokes at
  //     runtime — absent unless first-party code drives it. ---
  {
    feature: 'setuptools-packageindex',
    owners: ['setuptools'],
    summary: [/package.?index/i, /easy_install/i, /package url/i],
    question: { tokens: ['package_index', 'easy_install'] },
    detect: (s) => resolve(textIncludes(s.codeText, ['package_index', 'easy_install']), s),
  },
  // --- tqdm CLI argument injection (owner: tqdm). CVE-2024-34062 lives in tqdm's
  //     COMMAND-LINE entrypoint (`tqdm.cli` / `python -m tqdm`), reached only when
  //     untrusted data is piped through the tqdm CLI with attacker-controlled args.
  //     A web app that imports the tqdm LIBRARY (`from tqdm import tqdm`, as
  //     paperless does in its mgmt commands / Celery tasks) never loads `tqdm.cli`
  //     — so the CVE is unreachable even though the usage classifier stamps tqdm
  //     `function` for the library call. functionSafe: the CLI submodule is
  //     import-gated. ---
  {
    feature: 'tqdm-cli-injection',
    functionSafe: true,
    owners: ['tqdm'],
    summary: [/\bcli\b/i, /command.?line/i, /\bargument/i],
    question: { modules: ['tqdm.cli'], tokens: ['tqdm.cli', 'tqdm.__main__'] },
    detect: (s) =>
      resolve(
        moduleImported(s, 'tqdm.cli') ||
          textIncludes(s.codeText, ['tqdm.cli', 'python -m tqdm', 'tqdm.__main__']),
        s,
      ),
  },
  // --- filelock SoftFileLock TOCTOU (owner: filelock). CVE-2026-22701 is in the
  //     `SoftFileLock` class — the soft-lock fallback for filesystems without
  //     hard-link support. Apps use the DEFAULT `FileLock` (hard-link based); the
  //     vulnerable SoftFileLock is opt-in and absent unless referenced by name
  //     (paperless uses `from filelock import FileLock` exclusively — the usage
  //     classifier stamps filelock `function` for that call). functionSafe: the
  //     SoftFileLock class is import-gated. ---
  {
    feature: 'filelock-softfilelock',
    functionSafe: true,
    owners: ['filelock'],
    summary: [/softfilelock/i, /soft.?file.?lock/i],
    question: { tokens: ['softfilelock'] },
    detect: (s) => resolve(textIncludes(s.codeText, ['softfilelock']), s),
  },
];

export interface FeatureDemotionResult {
  demote: boolean;
  feature?: string;
  matchedPattern?: string;
  /**
   * True only when EVERY matched row is `functionSafe` (import-gated on the
   * specific vulnerable submodule/API). The caller may then apply this demotion
   * to a `function`-level finding. If any matched row is a broad feature/platform
   * rule, this is false → the demotion stays `module`-only.
   */
  functionSafe?: boolean;
}

/**
 * Decide whether a `module` pypi finding should be demoted to `unreachable`
 * because the feature its CVE requires is PROVABLY ABSENT. Pure — unit-tested
 * directly.
 *
 * Returns `{ demote: false }` unless signals are recognized, the finding has a
 * dep name + summary, at least one owner+summary row matches, AND EVERY
 * matching row's feature is provably `absent` (a single `present`/`unknown`
 * aborts).
 */
export function evaluateDjangoFeaturePreconditionDemotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  signals: DjangoFeatureSignals | null | undefined;
}): FeatureDemotionResult {
  const { depName, summary, signals } = input;
  if (!signals || !signals.recognized) return { demote: false };
  if (!depName || !summary) return { demote: false };

  const dep = normalizePypiName(depName);
  const applicable = FEATURE_PRECONDITIONS.filter(
    (fp) => fp.owners.includes(dep) && fp.summary.some((re) => re.test(summary)),
  );
  if (applicable.length === 0) return { demote: false };

  // Arc 2 veto: owner exclusion keeps the vulnerable package's own
  // self-imports/self-mentions from counting as consumer evidence.
  const vetoOwners = [pep503Normalize(depName)];
  let chosen: FeaturePrecondition | undefined;
  for (const fp of applicable) {
    if (fp.detect(signals) !== 'absent') return { demote: false };
    // A NON-OWNER prod dist imports / mentions this row's question — a
    // transitive consumer may load the vulnerable submodule. Refuse.
    if (
      fp.question &&
      transitiveConsumerVeto(signals.transitiveImports, fp.question, vetoOwners)
    ) {
      return { demote: false };
    }
    if (!chosen) chosen = fp;
  }
  const matched = chosen!.summary.find((re) => re.test(summary));
  // Function-safe only when EVERY matched row is import-gated on its specific
  // vulnerable submodule/API — a single broad feature/platform row keeps the
  // whole demotion module-only.
  const functionSafe = applicable.every((fp) => fp.functionSafe === true);
  return { demote: true, feature: chosen!.feature, matchedPattern: matched?.source, functionSafe };
}

/**
 * Arc 2 — the transitive-question registry, DERIVED from the row table (never
 * hand-synced): every module prefix + token the dep-import-graph pipeline step
 * must scan dependency sources for, and the owner names whose findings make
 * the pypi leg worth running at all (the trigger guard). The extractor version
 * hash incorporates this registry, so editing a row's `question` invalidates
 * cached summaries automatically.
 */
export function djangoTransitiveQuestionRegistry(): {
  modules: string[];
  tokens: string[];
  owners: string[];
} {
  const modules = new Set<string>();
  const tokens = new Set<string>();
  const owners = new Set<string>();
  for (const fp of FEATURE_PRECONDITIONS) {
    if (!fp.question) continue;
    for (const m of fp.question.modules ?? []) modules.add(m);
    for (const t of fp.question.tokens ?? []) tokens.add(t);
    for (const o of fp.owners) owners.add(o);
  }
  return {
    modules: [...modules].sort(),
    tokens: [...tokens].sort(),
    owners: [...owners].sort(),
  };
}

// ---------------------------------------------------------------------------
// DEV-ONLY demotion (manifest dev groups)
// ---------------------------------------------------------------------------

export interface DevOnlyDemotionResult {
  demote: boolean;
  package?: string;
}

/**
 * Demote to `unreachable` when the finding's package is provably DEV-ONLY —
 * declared in a dev-scope manifest group (poetry dev/test groups, Pipfile
 * `[dev-packages]`, requirements-dev.txt) and nowhere at prod scope, so it
 * never loads in production. The pypi analog of the Gemfile-group / composer
 * packages-dev demotion. Needs no summary match.
 *
 * This matters even though pypi is an EXPLICIT_IMPORT_ECOSYSTEM: a dev tool's
 * own test files import it (`import pytest`), so `files_importing_count > 0`
 * keeps it at `module` — the manifest group is the only prod/dev truth.
 */
export function evaluateDjangoDevOnlyDemotion(input: {
  depName: string | null | undefined;
  signals: DjangoFeatureSignals | null | undefined;
}): DevOnlyDemotionResult {
  const { depName, signals } = input;
  if (!signals || !signals.recognized) return { demote: false };
  if (!depName) return { demote: false };
  const pkg = normalizePypiName(depName);
  if (signals.devDeps.has(pkg)) return { demote: true, package: pkg };
  return { demote: false };
}

// ---------------------------------------------------------------------------
// ALWAYS-ON framework-runtime PROMOTION table (module → visible)
// ---------------------------------------------------------------------------

export interface AlwaysOnRuntime {
  sink: string;
  owners: string[];
  summary: RegExp[];
  /**
   * Advisory IDs (osv_id or alias, uppercased CVE/PYSEC) that match this row
   * even when the summary doesn't — PYSEC-2023-175's summary is the literal
   * string "Summary", invisible to patterns.
   */
  ids?: string[];
  /** Veto: a summary matching any of these is a feature-gated sibling — never promote. */
  exclude?: RegExp[];
  promoteTo: 'function' | 'data_flow';
  /** Extra per-row precondition on the project signals. */
  requires: (s: DjangoFeatureSignals) => boolean;
  /** Exploit precondition the bare request path does not satisfy (depscore hint). */
  threatTag?: string;
}

export const ALWAYS_ON_RUNTIME: AlwaysOnRuntime[] = [
  // --- django.utils.encoding.uri_to_iri (owner: django). Runs on redirect /
  //     i18n URL processing of ordinary request traffic — a crafted request
  //     path triggers the quadratic decode with no app-specific code. ---
  {
    sink: 'django-uri-to-iri',
    owners: ['django'],
    summary: [/uri_to_iri/i],
    exclude: [/\bon windows\b/i],
    promoteTo: 'data_flow',
    requires: () => true,
    threatTag: 'requires_untrusted_request',
  },
  // --- django response logging (owner: django). Every unhandled 4xx/5xx logs
  //     the raw request.path (log_response) — attacker-controlled bytes reach
  //     the log stream on the always-on request path. ---
  {
    sink: 'django-log-response-injection',
    owners: ['django'],
    summary: [/output neutralization for logs/i, /log injection/i, /log_response/i],
    exclude: [/\bon windows\b/i],
    promoteTo: 'data_flow',
    requires: () => true,
    threatTag: 'requires_untrusted_request',
  },
  // --- django Email/URLValidator ReDoS (owner: django). Fires wherever a form
  //     / serializer validates an attacker-supplied email or URL — near-
  //     universal on any Django app with an auth or account surface. Gated on
  //     a positive validator-surface signal. ---
  {
    sink: 'django-validator-redos',
    owners: ['django'],
    summary: [/emailvalidator/i, /urlvalidator/i, /email\s*validator/i, /url\s*validator/i],
    exclude: [/\bon windows\b/i],
    promoteTo: 'function',
    requires: (s) =>
      textIncludes(s.codeText, [
        'emailfield',
        'urlfield',
        'emailvalidator',
        'urlvalidator',
        'django.contrib.auth',
      ]),
    threatTag: 'requires_untrusted_request',
  },
  // --- pillow WebP decode (owner: pillow). The bundled-libwebp OOB write
  //     (CVE-2023-4863) executes when pillow DECODES an attacker image — on any
  //     app with an image-upload surface that's ordinary user traffic. Matched
  //     by ID too: PYSEC-2023-175 is the same bug with a useless summary.
  //     EXCLUDE the font/pdf/imagemath siblings (their demotions run first). ---
  {
    sink: 'pillow-webp-decode',
    owners: ['pillow'],
    summary: [/libwebp/i, /webp/i, /buildhuffmantable/i],
    ids: ['CVE-2023-4863', 'PYSEC-2023-175'],
    exclude: [/\bfont/i, /\bpdf\b/i, /imagemath/i],
    promoteTo: 'function',
    requires: (s) => s.usesImageUploads,
    threatTag: 'requires_untrusted_upload',
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
 * Decide whether a `module` pypi finding should be PROMOTED to a visible tier
 * because its CVE lives in always-on Django-runtime code AND the project is a
 * deployed web app. Pure — unit-tested directly.
 *
 * COMPOSITION: the caller runs the demotions first and only offers
 * still-`module` findings here; the `exclude` guard is a second line of
 * defence against feature-gated siblings.
 */
export function evaluateDjangoAlwaysOnRuntimePromotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  /** osv_id + aliases of the finding, for `ids`-matched rows. */
  osvIds?: string[] | null;
  /** Deployed-web-app gate: HTTP-route entry points OR the signals' own marker. */
  deployedWebApp: boolean;
  signals: DjangoFeatureSignals | null | undefined;
}): AlwaysOnPromotionResult {
  const { depName, summary, osvIds, deployedWebApp, signals } = input;
  if (!signals || !signals.recognized) return { promote: false };
  if (!deployedWebApp) return { promote: false };
  if (!depName) return { promote: false };
  const dep = normalizePypiName(depName);
  const idSet = new Set((osvIds ?? []).map((x) => String(x).toUpperCase()));
  for (const row of ALWAYS_ON_RUNTIME) {
    if (!row.owners.includes(dep)) continue;
    if (summary && row.exclude && row.exclude.some((re) => re.test(summary))) continue;
    const idMatched = row.ids ? row.ids.find((id) => idSet.has(id.toUpperCase())) : undefined;
    const matched = summary ? row.summary.find((re) => re.test(summary)) : undefined;
    if (!idMatched && !matched) continue;
    if (!row.requires(signals)) continue;
    return {
      promote: true,
      sink: row.sink,
      promoteTo: row.promoteTo,
      matchedPattern: matched?.source ?? (idMatched ? `id:${idMatched}` : undefined),
      threatTag: row.threatTag,
    };
  }
  return { promote: false };
}

// ---------------------------------------------------------------------------
// Manifest parsing (prod/dev scopes)
// ---------------------------------------------------------------------------

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

/** Poetry group names treated as dev scope. Unknown group names stay PROD (safe). */
const DEV_GROUP_NAMES = new Set(['dev', 'test', 'tests', 'lint', 'docs', 'typing', 'ci', 'local', 'development']);

/**
 * Parse pyproject.toml dependency scopes with a section-based line scan (no
 * TOML dependency). PEP 621 `[project] dependencies` arrays and poetry
 * `[tool.poetry.dependencies]` tables are prod; poetry dev-named groups +
 * legacy `[tool.poetry.dev-dependencies]` are dev. `[project.optional-
 * dependencies]` extras are treated as PROD (an extra may ship to production —
 * treating it prod only ever BLOCKS a demotion).
 */
export function parsePyprojectToml(raw: string, prod: Set<string>, dev: Set<string>): void {
  let section = '';
  let arrayDepth = 0; // > 0 while inside [project] dependencies = [ ... ]
  for (const line of raw.split(/\r?\n/)) {
    const sec = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (sec) {
      section = sec[1].trim().toLowerCase();
      arrayDepth = 0;
      continue;
    }
    const s = section;
    // PEP 621: [project] dependencies = ["pkg>=1.0", ...] (possibly multi-line).
    // Bracket-DEPTH tracking, not a bare `]` test — an extras spec like
    // "uvicorn[standard]>=0.20" carries balanced brackets inside the string.
    if (s === 'project') {
      const opener = arrayDepth === 0 && /^\s*dependencies\s*=\s*\[/.test(line);
      if (opener || arrayDepth > 0) {
        for (const m of line.matchAll(/["']([A-Za-z0-9_.-]+)/g)) prod.add(normalizePypiName(m[1]));
        const opens = (line.match(/\[/g) ?? []).length;
        const closes = (line.match(/\]/g) ?? []).length;
        arrayDepth += opens - closes;
        if (arrayDepth < 0) arrayDepth = 0;
      }
      continue;
    }
    if (s === 'project.optional-dependencies') {
      for (const m of line.matchAll(/["']([A-Za-z0-9_.-]+)/g)) prod.add(normalizePypiName(m[1]));
      continue;
    }
    // Poetry tables: one `name = version-spec` per line.
    const keyed = line.match(/^\s*([A-Za-z0-9_.-]+)\s*=/);
    if (!keyed) continue;
    const name = normalizePypiName(keyed[1]);
    if (name === 'python') continue;
    if (s === 'tool.poetry.dependencies') {
      prod.add(name);
    } else if (s === 'tool.poetry.dev-dependencies') {
      dev.add(name);
    } else {
      const grp = s.match(/^tool\.poetry\.group\.([^.]+)\.dependencies$/);
      if (grp) {
        if (DEV_GROUP_NAMES.has(grp[1])) dev.add(name);
        else prod.add(name); // unknown group → prod (blocks demotion — safe)
      }
    }
  }
}

/** Parse Pipfile: [packages] → prod, [dev-packages] → dev. */
export function parsePipfile(raw: string, prod: Set<string>, dev: Set<string>): void {
  let section = '';
  for (const line of raw.split(/\r?\n/)) {
    const sec = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (sec) {
      section = sec[1].trim().toLowerCase();
      continue;
    }
    const keyed = line.match(/^\s*"?([A-Za-z0-9_.-]+)"?\s*=/);
    if (!keyed) continue;
    const name = normalizePypiName(keyed[1]);
    if (section === 'packages') prod.add(name);
    else if (section === 'dev-packages') dev.add(name);
  }
}

/** Parse a requirements .txt body into the given scope set. */
export function parseRequirementsTxt(raw: string, into: Set<string>): void {
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith('-')) continue; // skip flags (-r/-e/--hash)
    const m = t.match(/^([A-Za-z0-9_.-]+)/);
    if (m) into.add(normalizePypiName(m[1]));
  }
}

export const DEV_REQUIREMENTS_RE = /(dev|test|lint|docs|local|ci)/i;

// ---------------------------------------------------------------------------
// Python import extraction
// ---------------------------------------------------------------------------

/**
 * Extract first-party dotted import paths from a Python source. Handles
 * `import a.b, c as d`, `from a.b import c, d as e`, and the parenthesized
 * multi-line form `from a import (b, c)`. Relative imports (leading `.`) are
 * first-party and skipped.
 *
 * Comments are stripped FIRST and backslash line-continuations collapsed —
 * the parenthesized-form match is non-greedy on `)`, so a `)` inside a comment
 * within the import list would otherwise close it early and drop names (the
 * exact silence-FN shape the Go model's gitea validation caught).
 */
export function extractPythonImports(source: string): string[] {
  const out: string[] = [];
  const add = (mod: string): void => {
    const m = mod.trim().toLowerCase();
    if (!m || m.startsWith('.')) return;
    out.push(m);
  };

  const src = source.replace(/#[^\n]*/g, '').replace(/\\\r?\n/g, ' ');

  // from X import (a, b, c) — parenthesized, possibly multi-line.
  const fromParenRe = /^[ \t]*from[ \t]+([A-Za-z0-9_.]+)[ \t]+import[ \t]+\(([\s\S]*?)\)/gm;
  let m: RegExpExecArray | null;
  const fromTargets: Array<[string, string]> = [];
  while ((m = fromParenRe.exec(src)) !== null) fromTargets.push([m[1], m[2]]);
  // from X import a, b as c — single-line.
  const fromPlainRe = /^[ \t]*from[ \t]+([A-Za-z0-9_.]+)[ \t]+import[ \t]+([^\n(]+)/gm;
  while ((m = fromPlainRe.exec(src)) !== null) fromTargets.push([m[1], m[2]]);
  for (const [base, names] of fromTargets) {
    add(base);
    for (const part of names.split(',')) {
      const name = part.trim().split(/[ \t]/)[0];
      if (!name || name === '*' || !/^[A-Za-z0-9_]+$/.test(name)) continue;
      add(`${base}.${name}`);
    }
  }
  // import a.b, c as d
  const importRe = /^[ \t]*import[ \t]+([^\n]+)/gm;
  while ((m = importRe.exec(src)) !== null) {
    for (const part of m[1].split(',')) {
      const name = part.trim().split(/[ \t]/)[0];
      if (name && /^[A-Za-z0-9_.]+$/.test(name)) add(name);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Project-feature detector (reads the workspace)
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.venv', 'venv', 'env', '__pycache__', 'site-packages',
  'dist', 'build', 'out', '.idea', 'coverage', '.tox', '.mypy_cache',
  '.pytest_cache', '.github', 'docs', 'static', 'media', 'locale',
]);

const MAX_DIR_DEPTH = 12;
const MAX_CODE_FILES = 12000;
const MAX_CODE_BYTES = 48 * 1024 * 1024;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

/**
 * Walk `root` (bounded) gathering the manifest scopes + first-party import set
 * + liberal code-text signals. Never throws — an unreadable tree or a
 * non-Django workspace yields empty (unrecognized) signals, which refuses
 * every demotion / promotion.
 */
export function gatherDjangoFeatureSignals(root: string | undefined): DjangoFeatureSignals {
  const signals = emptyDjangoFeatureSignals();
  if (!root) return signals;
  try {
    if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) return signals;
  } catch {
    return signals;
  }

  const prod = new Set<string>();
  const dev = new Set<string>();

  const pyproject = safeRead(path.join(root, 'pyproject.toml'), MAX_CONFIG_BYTES);
  if (pyproject) parsePyprojectToml(pyproject, prod, dev);
  const pipfile = safeRead(path.join(root, 'Pipfile'), MAX_CONFIG_BYTES);
  if (pipfile) parsePipfile(pipfile, prod, dev);
  // requirements*.txt at root + requirements/ dir.
  const reqCandidates: string[] = [];
  try {
    for (const ent of fs.readdirSync(root, { withFileTypes: true })) {
      if (ent.isFile() && /^requirements.*\.txt$/i.test(ent.name)) reqCandidates.push(path.join(root, ent.name));
      if (ent.isDirectory() && ent.name.toLowerCase() === 'requirements') {
        try {
          for (const sub of fs.readdirSync(path.join(root, ent.name), { withFileTypes: true })) {
            if (sub.isFile() && /\.txt$/i.test(sub.name)) reqCandidates.push(path.join(root, ent.name, sub.name));
          }
        } catch { /* unreadable requirements dir — skip */ }
      }
    }
  } catch { /* unreadable root — manifest sets stay as parsed so far */ }
  for (const file of reqCandidates) {
    const raw = safeRead(file, MAX_CONFIG_BYTES);
    if (!raw) continue;
    const isDev = DEV_REQUIREMENTS_RE.test(path.basename(file));
    parseRequirementsTxt(raw, isDev ? dev : prod);
  }

  // Prod scope wins: a package seen at prod scope anywhere is never dev-only.
  for (const p of prod) dev.delete(p);
  signals.devDeps = dev;
  signals.depUniverse = new Set([...prod, ...dev]);

  const codeParts: string[] = [];
  let hasWsgiOrAsgi = false;
  let hasManagePy = false;
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
      if (lower === 'wsgi.py' || lower === 'asgi.py') hasWsgiOrAsgi = true;
      if (lower === 'manage.py') hasManagePy = true;
      const isPy = lower.endsWith('.py');
      const isTemplate = lower.endsWith('.html');
      if (!isPy && !isTemplate) continue;
      if (codeFileCount >= MAX_CODE_FILES || codeBytes >= MAX_CODE_BYTES) {
        truncated = true;
        continue;
      }
      const src = safeRead(path.join(dir, ent.name), MAX_FILE_BYTES);
      if (!src) continue;
      codeFileCount += 1;
      codeBytes += src.length;
      codeParts.push(src.toLowerCase());
      if (isPy) for (const p of extractPythonImports(src)) signals.importedModules.add(p);
    }
  };

  walk(root, 0);

  signals.codeText = codeParts.join('\n');
  signals.truncated = truncated;

  const djangoInDeps = signals.depUniverse.has('django') || moduleImported(signals, 'django');
  const projectMarker =
    hasManagePy || hasWsgiOrAsgi || signals.codeText.includes('installed_apps');
  signals.recognized = djangoInDeps && projectMarker;

  signals.isDeployedWebApp =
    hasWsgiOrAsgi ||
    textIncludes(signals.codeText, ['wsgi_application', 'asgi_application', 'root_urlconf']);
  signals.usesImageUploads = textIncludes(signals.codeText, ['imagefield', 'image.open(', 'imagefile']);
  return signals;
}
