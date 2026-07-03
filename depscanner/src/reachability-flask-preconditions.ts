/**
 * Flask / FastAPI reachability preconditions (pypi) — the 7th framework model.
 *
 * Flask and FastAPI are the two dominant non-Django Python web stacks, and they
 * have OPPOSITE shapes: Flask is a server-rendered WSGI app (Jinja2 templates,
 * Werkzeug request/form parsing, WTForms), FastAPI is an ASGI JSON API (Starlette
 * request stack, Pydantic request-body validation, Uvicorn, usually PyJWT auth).
 * A single model handles both because the levers are the same shape as the other
 * framework models:
 *
 *   1. `FEATURE_PRECONDITIONS` — advisory→required-feature table (owner + summary
 *      pattern). DEMOTES a `module`/`function` finding to `unreachable` when the
 *      vulnerable feature is PROVABLY absent from the workspace (e.g. a Starlette
 *      multipart-parser DoS on a pure-JSON FastAPI API that has no form/upload
 *      endpoints; a StaticFiles CVE on an app that mounts no StaticFiles; a
 *      PyJWKClient CVE on an app that uses a static HS256 secret).
 *   2. `evaluateFlaskDevOnlyDemotion` — poetry dev-group / Pipfile dev-packages /
 *      requirements-dev demotion (prod scope wins). Reuses the shared pypi
 *      manifest parsers.
 *   3. `ALWAYS_ON_RUNTIME` — PROMOTES a `module` finding to a visible tier when
 *      its CVE lives in always-on request-path framework code AND the per-row
 *      project-signal precondition holds (Werkzeug/Starlette form parser when the
 *      app HAS form/upload endpoints; Pydantic validator ReDoS when the app
 *      validates request emails; PyJWT decode CVEs when the app decodes
 *      attacker-supplied JWTs). Feature-gated, never blunt — the same row demotes
 *      on the opposite-shape app and promotes on the matching one.
 *   4. `gatherFlaskFeatureSignals` — reads the workspace (manifests + first-party
 *      imports + liberal code-text) into a `FlaskFeatureSignals`. When it can't
 *      recognize a Flask/FastAPI app it returns the empty sentinel and every
 *      demotion / promotion is refused ("cannot reason").
 *
 * DOCTRINE: liberal about "feature present" (blocks a demotion — safe), confident
 * only about provable absence. `recognized: false` and `truncated: true` both
 * force `unknown`, never `absent`. Shares the pypi manifest/import parsers with
 * the Django model (same ecosystem) to avoid drift.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  normalizePypiName,
  extractPythonImports,
  parsePyprojectToml,
  parsePipfile,
  parseRequirementsTxt,
  DEV_REQUIREMENTS_RE,
} from './reachability-django-preconditions';

export interface FlaskFeatureSignals {
  /**
   * True once a manifest was parsed AND this is a recognizable Flask or FastAPI
   * app (`flask`/`fastapi`/`starlette` in the dependency universe plus a project
   * marker: a wsgi.py/asgi.py module or a `Flask(`/`FastAPI(` app instantiation).
   * When false the detector cannot prove anything, so every demotion/promotion is
   * refused.
   */
  recognized: boolean;
  /** Which stack — for context/logging. A repo depending on both resolves 'both'. */
  framework: 'flask' | 'fastapi' | 'both' | null;
  /** True when the code scan hit its cap — absence-of-code signals become `unknown`. */
  truncated: boolean;
  /** Package names (normalized) declared ONLY at a dev manifest scope. The dev-only lever. */
  devDeps: Set<string>;
  /** Every normalized package name seen in any manifest. */
  depUniverse: Set<string>;
  /** Every first-party dotted import path, lowercased (`from starlette import x` → `starlette`, `starlette.x`). */
  importedModules: Set<string>;
  /** Lowercased concat of first-party `.py` + `.html` sources — the liberal substring surface. */
  codeText: string;
  /** Deployable web app: wsgi.py/asgi.py exists OR a `Flask(`/`FastAPI(` app is instantiated. Gates promotion. */
  isDeployedWebApp: boolean;
  /**
   * The app has a form / multipart / file-upload surface — Flask `request.files`
   * / `request.form` / WTForms FileField, or FastAPI `Form(` / `File(` /
   * `UploadFile`. Gates the multipart-parser rows (Werkzeug/Starlette/
   * python-multipart DoS is unreachable on a pure-JSON API).
   */
  usesForms: boolean;
  /** Decodes attacker-supplied JWTs on the request path (auth). Gates the PyJWT decode rows. */
  usesJwtAuth: boolean;
  /** Validates an email/URL from request input (Pydantic `EmailStr` / WTForms EmailField / email-validator). */
  usesEmailValidation: boolean;
  /**
   * Uvicorn is a prod dependency AND httptools is NOT installed, so uvicorn falls
   * back to the pure-Python `h11` HTTP/1.1 parser that parses every request. Gates
   * the h11 request-parser rows.
   */
  usesH11: boolean;
}

export type FeaturePresence = 'present' | 'absent' | 'unknown';

/** Empty (nothing recognized) signals — the "cannot reason" sentinel. */
export function emptyFlaskFeatureSignals(): FlaskFeatureSignals {
  return {
    recognized: false,
    framework: null,
    truncated: false,
    devDeps: new Set(),
    depUniverse: new Set(),
    importedModules: new Set(),
    codeText: '',
    isDeployedWebApp: false,
    usesForms: false,
    usesJwtAuth: false,
    usesEmailValidation: false,
    usesH11: false,
  };
}

// ---------------------------------------------------------------------------
// Feature-detect helpers (LIBERAL about "present", confident only about absence)
// ---------------------------------------------------------------------------

function textIncludes(hay: string, subs: string[]): boolean {
  return subs.some((x) => hay.includes(x));
}

/** Resolve a boolean "present" signal into a `FeaturePresence`; truncated + absent → `unknown`. */
function resolve(present: boolean, s: FlaskFeatureSignals): FeaturePresence {
  if (present) return 'present';
  if (s.truncated) return 'unknown';
  return 'absent';
}

/** Does the first-party import set contain `mod`, exactly or via any descendant path? */
function moduleImported(s: FlaskFeatureSignals, mod: string): boolean {
  const prefix = mod + '.';
  for (const p of s.importedModules) {
    if (p === mod || p.startsWith(prefix)) return true;
  }
  return false;
}

/** Any of `names` present at PROD scope (a proven dev-only dep is not prod evidence). */
function hasAnyProdDep(s: FlaskFeatureSignals, names: string[]): boolean {
  return names.some((n) => s.depUniverse.has(n) && !s.devDeps.has(n));
}

// ---------------------------------------------------------------------------
// FEATURE-PRECONDITION table (DEMOTE module/function → unreachable when absent)
// ---------------------------------------------------------------------------

interface FeaturePrecondition {
  feature: string;
  /** Demote only when the finding's dependency NAME equals one of these (normalized). */
  owners: string[];
  /** Demote only when the advisory summary matches one of these. */
  summary: RegExp[];
  /** Advisory IDs (osv_id/alias, uppercased) that also match even when the summary doesn't. */
  ids?: string[];
  /** Returns the REQUIRED feature's presence; demote fires only on `absent`. */
  detect: (s: FlaskFeatureSignals) => FeaturePresence;
  /**
   * True when the required feature is a specific import-gated submodule/API, so
   * the absence is level-independent and the demotion may apply at `function`
   * too (the usage classifier stamps `function` for a top-level package call
   * even when the vulnerable submodule is never touched).
   */
  functionSafe?: boolean;
}

/**
 * Rows grounded in the blind-triage + adversarial-verify ground truth for FlaskBB
 * (has Flask-WTF forms) and fastapi-realworld (pure-JSON, no forms).
 */
export const FEATURE_PRECONDITIONS: FeaturePrecondition[] = [
  // Multipart/form parser (Werkzeug / Starlette / python-multipart / the fastapi
  // python-multipart Content-Type ReDoS) is UNREACHABLE on an app with no form /
  // upload endpoints — a pure-JSON FastAPI API never invokes it. functionSafe:
  // the usage classifier stamps `function` for a top-level fastapi/starlette call
  // even though the multipart submodule is never entered (fastapi CVE-2024-24762
  // whose advisory summary is just the package blurb → matched by ID).
  {
    feature: 'form/multipart parsing',
    owners: ['fastapi', 'starlette', 'python-multipart', 'werkzeug'],
    summary: [/multipart/i, /form data/i, /form-data/i, /too many fields/i, /parsing file/i, /resource exhaustion/i],
    ids: ['CVE-2024-24762'],
    detect: (s) => resolve(s.usesForms, s),
    functionSafe: true,
  },
];

export interface FeatureDemotionResult {
  demote: boolean;
  feature?: string;
  matchedPattern?: string;
  /** True only when EVERY matched row is `functionSafe`. */
  functionSafe?: boolean;
}

/**
 * Decide whether a `module`/`function` pypi finding should be DEMOTED to
 * `unreachable` because a required feature is provably absent. Pure.
 */
export function evaluateFlaskFeaturePreconditionDemotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  osvIds?: string[] | null;
  signals: FlaskFeatureSignals | null | undefined;
}): FeatureDemotionResult {
  const { depName, summary, osvIds, signals } = input;
  if (!signals || !signals.recognized) return { demote: false };
  if (!depName) return { demote: false };
  const dep = normalizePypiName(depName);
  const idSet = new Set((osvIds ?? []).map((x) => String(x).toUpperCase()));
  const applicable = FEATURE_PRECONDITIONS.filter((fp) => {
    if (!fp.owners.includes(dep)) return false;
    const idMatch = fp.ids ? fp.ids.some((id) => idSet.has(id.toUpperCase())) : false;
    const sumMatch = summary ? fp.summary.some((re) => re.test(summary)) : false;
    if (!idMatch && !sumMatch) return false;
    return fp.detect(signals) === 'absent';
  });
  if (applicable.length === 0) return { demote: false };
  const chosen = applicable[0];
  const matched = summary ? chosen.summary.find((re) => re.test(summary)) : undefined;
  const functionSafe = applicable.every((fp) => fp.functionSafe === true);
  return { demote: true, feature: chosen.feature, matchedPattern: matched?.source, functionSafe };
}

// ---------------------------------------------------------------------------
// ALWAYS-ON-RUNTIME table (PROMOTE module → function/data_flow when present)
// ---------------------------------------------------------------------------

export interface AlwaysOnRuntime {
  sink: string;
  owners: string[];
  summary: RegExp[];
  ids?: string[];
  /** Veto: a summary matching any of these is a feature-gated sibling — never promote. */
  exclude?: RegExp[];
  promoteTo: 'function' | 'data_flow';
  /** Per-row precondition on the project signals. */
  requires: (s: FlaskFeatureSignals) => boolean;
  /** Exploit precondition the bare request path does not satisfy (depscore hint). */
  threatTag?: string;
  /**
   * When true, this promotion may override the `orphan_transitive_unreachable`
   * heuristic floor (a direct dep declared-but-not-imported). Set ONLY on rows
   * where the `requires` signal PROVABLY implies THIS exact orphan dep is
   * transitively reached — i.e. the signal's consumer is a FIXED transitive
   * consumer of this dep (idna is only ever reached via requests/email-validator's
   * idna.encode). NOT set where the signal could be satisfied by an ALTERNATIVE
   * library (usesJwtAuth = PyJWT OR python-jose; usesEmailValidation = pydantic OR
   * WTForms) — otherwise an unused orphan dep would be promoted on the strength of
   * a different library's usage (a cross-dependency false positive).
   */
  overridesOrphanFloor?: boolean;
}

/** Rows grounded in the FlaskBB + fastapi-realworld verified ground truth. */
export const ALWAYS_ON_RUNTIME: AlwaysOnRuntime[] = [
  // NOTE: the Werkzeug nameless-cookie __Host- confusion (CVE-2023-23934) is
  // deliberately NOT promoted. Adversarial review found `data_flow` over-claims a
  // LOW-severity parser-CONFUSION bug whose exploitability needs the app to rely
  // on __Host-/cookie-prefix trust (unprovable by the engine), and the "always-on"
  // claim only holds for a default cookie-session Flask app, not raw Werkzeug. It
  // stays `module` — the honest conservative silence.
  //
  // Werkzeug multipart-form parser DoS — reachable when the app has form/upload
  // endpoints; an attacker forces the multipart parser by POSTing a multipart
  // Content-Type to any Flask-WTF form endpoint (login/register).
  {
    sink: 'werkzeug-form-parser',
    owners: ['werkzeug'],
    summary: [/multipart/i, /parsing file/i, /resource exhaustion/i],
    promoteTo: 'data_flow',
    requires: (s) => s.usesForms,
    threatTag: 'requires_untrusted_request',
  },
  // Starlette / python-multipart form parser DoS — same shape on the FastAPI side
  // (fires only on a FastAPI app that actually declares form/upload endpoints).
  {
    sink: 'starlette-form-parser',
    owners: ['starlette', 'python-multipart'],
    summary: [/multipart/i, /form data/i, /too many fields/i, /form.*limits/i],
    promoteTo: 'data_flow',
    requires: (s) => s.usesForms,
    threatTag: 'requires_untrusted_request',
  },
  // h11 HTTP/1.1 request parser — uvicorn without httptools parses every request
  // through h11, so a malformed chunked-encoding body reaches it on the request path.
  {
    sink: 'h11-request-parser',
    owners: ['h11'],
    summary: [/chunked/i, /malformed/i, /request line/i, /request smuggling/i],
    promoteTo: 'data_flow',
    requires: (s) => s.usesH11,
    threatTag: 'requires_untrusted_request',
  },
  // Pydantic email validator ReDoS — the request-email validator runs pydantic's
  // email regex on untrusted input wherever the app validates a request email
  // (EmailStr / WTForms Email()).
  {
    sink: 'pydantic-email-redos',
    owners: ['pydantic'],
    // Bare /email/i dropped (adversarial review): it would over-promote any future
    // non-ReDoS pydantic "email" advisory. The ReDoS class is captured by the two
    // specific patterns (CVE-2024-3772's summary is "regular expression denial of service").
    summary: [/regular expression denial/i, /redos/i],
    promoteTo: 'data_flow',
    requires: (s) => s.usesEmailValidation,
    threatTag: 'requires_untrusted_request',
  },
  // idna encode — email-validator calls idna.encode() on the untrusted email
  // domain, so the IDNA DoS/confusion is reached wherever request emails validate.
  {
    sink: 'idna-encode',
    owners: ['idna'],
    summary: [/internationalized domain/i, /\bidna\b/i],
    promoteTo: 'data_flow',
    requires: (s) => s.usesEmailValidation,
    threatTag: 'requires_untrusted_request',
    // idna is a FIXED transitive consumer of request-email validation
    // (email-validator → idna.encode on the untrusted domain), so validation
    // provably reaches it even when idna is a direct-but-unimported (orphan) pin.
    // The one rule permitted to override the orphan_transitive_unreachable floor.
    overridesOrphanFloor: true,
  },
  // PyJWT crit-header parsing — an app that decodes attacker-supplied bearer JWTs
  // runs the vulnerable crit-header parse on every authenticated request. EXCLUDE
  // the PyJWKClient/JWKS siblings (feature-gated on remote-key fetching a static
  // HS256 secret never does).
  {
    sink: 'pyjwt-crit-decode',
    owners: ['pyjwt'],
    summary: [/\bcrit\b/i, /crit header/i, /crit.{0,4}extension/i],
    exclude: [/pyjwkclient/i, /jwks/i, /jwk.*endpoint/i],
    promoteTo: 'data_flow',
    requires: (s) => s.usesJwtAuth,
    threatTag: 'requires_untrusted_request',
  },
];

export interface AlwaysOnPromotionResult {
  promote: boolean;
  sink?: string;
  promoteTo?: 'function' | 'data_flow';
  matchedPattern?: string;
  threatTag?: string;
  /** True when the matched row may override the orphan_transitive_unreachable floor. */
  overridesOrphanFloor?: boolean;
}

/**
 * Decide whether a `module` pypi finding should be PROMOTED because its CVE lives
 * in always-on Flask/FastAPI request-path code AND the per-row precondition holds
 * AND the project is a deployed web app. Pure.
 */
export function evaluateFlaskAlwaysOnRuntimePromotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  osvIds?: string[] | null;
  deployedWebApp: boolean;
  signals: FlaskFeatureSignals | null | undefined;
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
      overridesOrphanFloor: row.overridesOrphanFloor === true,
    };
  }
  return { promote: false };
}

// ---------------------------------------------------------------------------
// Dev-only demotion (poetry dev groups / Pipfile dev-packages / requirements-dev)
// ---------------------------------------------------------------------------

export interface DevOnlyDemotionResult {
  demote: boolean;
  package?: string;
}

/** Demote a finding whose dependency is declared ONLY at a dev manifest scope. */
export function evaluateFlaskDevOnlyDemotion(input: {
  depName: string | null | undefined;
  signals: FlaskFeatureSignals | null | undefined;
}): DevOnlyDemotionResult {
  const { depName, signals } = input;
  if (!signals || !signals.recognized) return { demote: false };
  if (!depName) return { demote: false };
  const dep = normalizePypiName(depName);
  if (signals.devDeps.has(dep) && !hasAnyProdDep(signals, [dep])) {
    return { demote: true, package: dep };
  }
  return { demote: false };
}

// ---------------------------------------------------------------------------
// Project-feature detector (reads the workspace)
// ---------------------------------------------------------------------------

const MAX_CONFIG_BYTES = 6 * 1024 * 1024;
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.venv', 'venv', 'env', '__pycache__', 'site-packages',
  'dist', 'build', 'out', '.idea', 'coverage', '.tox', '.mypy_cache',
  '.pytest_cache', '.github', 'docs', 'static', 'media', 'locale',
]);
const MAX_DIR_DEPTH = 12;
const MAX_CODE_FILES = 12000;
const MAX_CODE_BYTES = 48 * 1024 * 1024;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

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
 * Walk `root` (bounded) gathering manifest scopes + first-party imports + liberal
 * code-text signals. Never throws — an unreadable tree or a non-Flask/FastAPI
 * workspace yields empty (unrecognized) signals, refusing every demotion/promotion.
 */
export function gatherFlaskFeatureSignals(root: string | undefined): FlaskFeatureSignals {
  const signals = emptyFlaskFeatureSignals();
  if (!root) return signals;
  try {
    if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) return signals;
  } catch {
    return signals;
  }

  const prod = new Set<string>();
  const dev = new Set<string>();
  // Raw PROD manifest text, retained so signals that depend on an EXTRA spec
  // (e.g. `uvicorn[standard]`, which pulls httptools transitively) can be detected
  // even though extras are stripped from the normalized depUniverse.
  const manifestParts: string[] = [];

  const pyproject = safeRead(path.join(root, 'pyproject.toml'), MAX_CONFIG_BYTES);
  if (pyproject) { parsePyprojectToml(pyproject, prod, dev); manifestParts.push(pyproject); }
  const pipfile = safeRead(path.join(root, 'Pipfile'), MAX_CONFIG_BYTES);
  if (pipfile) { parsePipfile(pipfile, prod, dev); manifestParts.push(pipfile); }
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
  } catch { /* unreadable root */ }
  for (const file of reqCandidates) {
    const raw = safeRead(file, MAX_CONFIG_BYTES);
    if (!raw) continue;
    const isDev = DEV_REQUIREMENTS_RE.test(path.basename(file));
    parseRequirementsTxt(raw, isDev ? dev : prod);
    if (!isDev) manifestParts.push(raw);
  }
  const manifestText = manifestParts.join('\n');

  // Prod scope wins.
  for (const p of prod) dev.delete(p);
  signals.devDeps = dev;
  signals.depUniverse = new Set([...prod, ...dev]);

  const codeParts: string[] = [];
  let hasWsgiOrAsgi = false;
  let codeFileCount = 0;
  let codeBytes = 0;
  let truncated = false;

  const walk = (dir: string, depth: number): void => {
    // Content below the depth cap goes unscanned — mark truncated so a signal that
    // would have lived there resolves to `unknown` (demotion refused), not `absent`.
    if (depth > MAX_DIR_DEPTH) { truncated = true; return; }
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
      const isPy = lower.endsWith('.py');
      const isTemplate = lower.endsWith('.html');
      if (!isPy && !isTemplate) continue;
      if (codeFileCount >= MAX_CODE_FILES || codeBytes >= MAX_CODE_BYTES) {
        truncated = true;
        continue;
      }
      const src = safeRead(path.join(dir, ent.name), MAX_FILE_BYTES);
      // Oversize (> MAX_FILE_BYTES) or unreadable → content unscanned: mark
      // truncated so a missed marker becomes `unknown`, not `absent` (fail-safe).
      if (!src) { truncated = true; continue; }
      codeFileCount += 1;
      codeBytes += src.length;
      codeParts.push(src.toLowerCase());
      if (isPy) for (const p of extractPythonImports(src)) signals.importedModules.add(p);
    }
  };
  walk(root, 0);

  signals.codeText = codeParts.join('\n');
  signals.truncated = truncated;

  const code = signals.codeText;
  // Quart is the ASGI reimplementation of the Flask API (same Werkzeug/Jinja2 +
  // request.files/request.form surface), so it counts as the 'flask' stack.
  const flaskInDeps =
    signals.depUniverse.has('flask') ||
    signals.depUniverse.has('quart') ||
    moduleImported(signals, 'flask') ||
    moduleImported(signals, 'quart');
  const fastapiInDeps =
    signals.depUniverse.has('fastapi') ||
    signals.depUniverse.has('starlette') ||
    moduleImported(signals, 'fastapi') ||
    moduleImported(signals, 'starlette');
  signals.framework =
    flaskInDeps && fastapiInDeps ? 'both' : flaskInDeps ? 'flask' : fastapiInDeps ? 'fastapi' : null;

  // App-instantiation marker: `Flask(` / `FastAPI(` / `Starlette(` / `Quart(`
  // (lowercased in codeText), or a WSGI/ASGI module. Distinguishes a deployed app
  // from a library that merely lists flask/starlette as a dependency. `starlette(`
  // covers pure-Starlette ASGI apps that instantiate `Starlette(routes=...)` with
  // no asgi.py and no FastAPI wrapper.
  const appMarker = hasWsgiOrAsgi || textIncludes(code, ['flask(', 'fastapi(', 'starlette(', 'quart(', 'wsgi_app', 'asgi_app']);
  signals.recognized = signals.framework != null && appMarker;
  signals.isDeployedWebApp = signals.recognized;

  // --- feature signals (liberal about presence) ---
  // Form/multipart surface. python-multipart is only pulled when a FastAPI app
  // declares Form()/File()/UploadFile endpoints, so its prod presence is a strong
  // signal; Flask-WTF markers (flaskform/validate_on_submit/wtforms) cover Flask.
  // An attacker can force Werkzeug/Starlette's multipart parser by POSTing a
  // multipart Content-Type to ANY form-accepting endpoint.
  signals.usesForms =
    hasAnyProdDep(signals, ['python-multipart']) ||
    textIncludes(code, [
      // Werkzeug form parse is triggered by ANY of these access paths — request.form
      // and request.values (CombinedMultiDict) and get_data(parse_form_data=True)
      // all invoke it; Flask-RESTful reqparse location='form'|'files' does too.
      'request.files', 'request.form', 'request.values', 'parse_form_data', 'get_data(',
      'filefield', 'filestorage', 'multipartform', 'multipart/form-data',
      'enctype=multipart', 'enctype="multipart', "enctype='multipart",
      'uploadfile', 'flaskform', 'flask_wtf', 'validate_on_submit', 'wtforms',
      'reqparse', 'requestparser', "location='form'", 'location="form"',
      "location='files'", 'location="files"',
    ]);
  signals.usesJwtAuth =
    textIncludes(code, ['jwt.decode', 'jwt.get_unverified', 'decode_token', 'jwtbearer', 'oauth2passwordbearer']) ||
    (hasAnyProdDep(signals, ['pyjwt', 'python-jose', 'jose']) && textIncludes(code, ['.decode(', 'jwt']));
  // email-validator is pulled only by pydantic[email]/WTForms Email() → its prod
  // presence implies request-email validation, which calls idna.encode on the
  // untrusted domain + runs pydantic's email regex.
  signals.usesEmailValidation =
    hasAnyProdDep(signals, ['email-validator']) ||
    textIncludes(code, ['emailstr', 'emailfield', 'email_validator', 'emailvalidator', 'validate_email']);
  // uvicorn without the [standard] extra ships no httptools, so it uses the
  // pure-Python h11 parser for every request. httptools arrives TRANSITIVELY via
  // the `uvicorn[standard]` extra — extras are stripped from the normalized
  // depUniverse, so a direct-dep check alone is a dead guard. Also scan the raw
  // manifest text for the `uvicorn[standard]` extra spec (or a direct httptools
  // pin): when httptools is present it, not h11, is the active request parser.
  const hasHttptools =
    hasAnyProdDep(signals, ['httptools']) || /uvicorn\s*\[[^\]]*\bstandard\b[^\]]*\]/i.test(manifestText);
  signals.usesH11 = hasAnyProdDep(signals, ['uvicorn']) && !hasHttptools;

  return signals;
}
