/**
 * Laravel framework-mediated reachability model — the composer-ecosystem sibling
 * of the Symfony model, for apps built on `laravel/framework` (which are NOT
 * recognized as Symfony: they carry no `symfony/framework-bundle`). Laravel
 * ships a large monolithic framework whose request-path behaviour is FEATURE-
 * GATED, so — unlike a blunt "promote every laravel/framework request CVE" table
 * — each row is gated on a feature the scanned app provably uses (or provably
 * does not).
 *
 * The model exposes:
 *   1. `ALWAYS_ON_RUNTIME` — declarative table that PROMOTES `module`→visible
 *      for a laravel/framework CVE when the app is a deployed web app AND the
 *      required feature is present (signed URLs in use; file-upload validation
 *      in use).
 *   2. `FEATURE_PRECONDITIONS` — table that DEMOTES `module`→`unreachable` when
 *      the CVE's required feature is PROVABLY ABSENT (no signed-URL API anywhere).
 *   3. `gatherLaravelFeatureSignals` — reads the workspace (composer.lock for
 *      recognition + scope; `app/**` + `routes/**` PHP for the feature signals).
 *
 * TWO-APP CALIBRATION (the reason every row is feature-gated, not always-on):
 *   - monica (Blade MVC CRM) USES signed URLs (temporarySignedRoute in an
 *     invitation notification) → GHSA-crmm (Temporary Signed URL Path Confusion)
 *     is data_flow there.
 *   - koel (API-first + Vue SPA) uses NO signed URLs (no ValidateSignature /
 *     temporarySignedRoute anywhere) → GHSA-crmm is UNREACHABLE there.
 *   A naive always-on promotion would wrongly SHOW GHSA-crmm on koel; the
 *   signed-URL gate demotes it instead. Both apps DO validate file uploads
 *   (`mimes` rules), so the file-validation CVE promotes on both.
 *
 * DELIBERATELY NOT MODELLED (yet): mail / markdown feature-ABSENCE demotions.
 * Heuristic code-scan detectors cannot reliably PROVE those features absent —
 * monica reaches symfony/mime + league/commonmark (its own ground truth labels
 * them function) via Notification / helper paths a grep for `Mail::` / `->notify`
 * / `Str::markdown` misses (they return zero hits on monica too). A demotion
 * built on that would be a Gate-3 false-negative (hide a reachable vuln). Only
 * the signed-URL feature — reachable via the SPECIFIC, only Laravel signed-URL
 * APIs — is safe to prove absent.
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

export interface LaravelFeatureSignals {
  /**
   * True once `composer.lock` was parsed AND this is recognizably a Laravel app
   * (`laravel/framework` in the production packages). When false the model is a
   * no-op — every demotion / promotion is refused (fail-safe).
   */
  recognized: boolean;
  /**
   * True when the `app/**` + `routes/**` scan hit its file/byte cap. A feature
   * signal we didn't read might exist, so a feature's absence resolves to
   * `unknown` (never `absent`) when this is set — a demotion is refused.
   */
  truncated: boolean;
  /** Lowercased `composer.lock` → `packages[].name` (production tree). */
  lockProd: Set<string>;
  /** Lowercased `composer.lock` → `packages-dev[].name`. */
  lockDev: Set<string>;
  /** Lowercased concat of first-party `app/**` + `routes/**` PHP. */
  codeText: string;
}

export type FeaturePresence = 'present' | 'absent' | 'unknown';

/** Empty (nothing recognized) signals — the "cannot reason" sentinel. */
export function emptyLaravelFeatureSignals(): LaravelFeatureSignals {
  return {
    recognized: false,
    truncated: false,
    lockProd: new Set(),
    lockDev: new Set(),
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
 * — never `absent` — so a demotion is refused (fail-safe).
 */
function resolve(present: boolean, s: LaravelFeatureSignals): FeaturePresence {
  if (present) return 'present';
  if (s.truncated) return 'unknown';
  return 'absent';
}

/**
 * The app uses Laravel SIGNED URLs — the only ways to generate or validate one
 * are these framework APIs, so their total absence is a strong proof the feature
 * is unused (and the signed-URL CVE unreachable). LIBERAL: any single hit marks
 * the feature present (the safe direction — blocks the demotion).
 */
export function usesSignedUrls(s: LaravelFeatureSignals): boolean {
  return textIncludes(s.codeText, [
    'temporarysignedroute',
    'signedroute',
    'hasvalidsignature',
    'hasvalidrelativesignature',
    'validatesignature',
    '->signed(',
    'url::signedroute',
  ]);
}

/**
 * The app validates FILE UPLOADS — it declares a `file` / `mimes` / `image`
 * validation rule or handles an `UploadedFile`. The file-validation-bypass CVE
 * lives in the framework validator, so it is reachable on any app that runs
 * those rules on user uploads. LIBERAL about "present".
 */
export function hasFileUploadValidation(s: LaravelFeatureSignals): boolean {
  const c = s.codeText;
  return (
    // Upload-handling APIs + the file-validation rule keywords. `mimes:` /
    // `mimetypes:` are the canonical Laravel file-validation rules (they always
    // carry the `:` + an extension list, so they're specific to file validation
    // and match inside a pipe-string rule like `'required|image|mimes:jpg,png'`).
    textIncludes(c, ['uploadedfile', '->hasfile(', '->file(', 'storeas(', 'mimes:', 'mimetypes:']) ||
    // array/key form of a `file` or `image` rule — `'file' => …`, `'image' => …`.
    /['"](file|image)['"]\s*=>/.test(c)
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
  detect: (s: LaravelFeatureSignals) => FeaturePresence;
}

export const FEATURE_PRECONDITIONS: FeaturePrecondition[] = [
  // --- Signed-URL path confusion (GHSA-crmm "Temporary Signed URL Path
  //     Confusion"). Reachable only if the app actually generates/validates a
  //     signed URL. koel uses none → provably unreachable; monica uses them (a
  //     temporarySignedRoute invitation) → present → demotion refused, and the
  //     always-on row below promotes it instead. ---
  {
    feature: 'laravel-signed-url',
    owners: ['laravel/framework', 'framework'],
    summary: [/signed url/i, /signed-url/i, /signature/i],
    detect: (s) => resolve(usesSignedUrls(s), s),
  },
];

export interface FeatureDemotionResult {
  demote: boolean;
  feature?: string;
  matchedPattern?: string;
}

/**
 * Decide whether a `module` laravel/framework finding should be demoted to
 * `unreachable` because the Laravel feature its CVE requires is PROVABLY ABSENT.
 * Pure — unit-tested directly. Fail-safe: refused unless signals are recognized,
 * the finding has a dep name + summary, an owner+summary row matches, and EVERY
 * matching row's feature is provably `absent` (a single present/unknown aborts).
 */
export function evaluateLaravelFeaturePreconditionDemotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  signals: LaravelFeatureSignals | null | undefined;
}): FeatureDemotionResult {
  const { depName, summary, signals } = input;
  if (!signals || !signals.recognized) return { demote: false };
  if (!depName || !summary) return { demote: false };

  const dep = depName.toLowerCase();
  const applicable = FEATURE_PRECONDITIONS.filter(
    (fp) => fp.owners.some((o) => dep.includes(o)) && fp.summary.some((re) => re.test(summary)),
  );
  if (applicable.length === 0) return { demote: false };
  // EVERY applicable row must be provably absent.
  for (const fp of applicable) {
    if (fp.detect(signals) !== 'absent') return { demote: false };
  }
  const matched = applicable[0];
  return {
    demote: true,
    feature: matched.feature,
    matchedPattern: matched.summary.find((re) => re.test(summary))?.source,
  };
}

// ---------------------------------------------------------------------------
// ALWAYS-ON framework-runtime PROMOTION table (module → visible)
// ---------------------------------------------------------------------------

export interface AlwaysOnRuntime {
  sink: string;
  owners: string[];
  summary: RegExp[];
  promoteTo: 'function' | 'data_flow';
  /** Extra per-row precondition on the project signals (the feature gate). */
  requires: (s: LaravelFeatureSignals) => boolean;
  /** Exploit precondition the bare request path does not satisfy (depscore hint). */
  threatTag?: string;
}

export const ALWAYS_ON_RUNTIME: AlwaysOnRuntime[] = [
  // --- Signed-URL path confusion (GHSA-crmm). When the app DOES use signed URLs
  //     (monica), the confusion is on the signed-route validation path an
  //     attacker hits directly → data_flow. Gated on the feature being present so
  //     it never fires on an app that has no signed URLs (koel). ---
  {
    sink: 'laravel-signed-url-validation',
    owners: ['laravel/framework', 'framework'],
    summary: [/signed url/i, /signed-url/i, /signature/i],
    promoteTo: 'data_flow',
    requires: (s) => usesSignedUrls(s),
    threatTag: 'requires_signed_route',
  },
  // --- File-validation bypass (CVE-2025-27515). The bug is in the framework's
  //     `file`/`mimes` validator; reachable on any app that validates user file
  //     uploads. Promote to `function` (a specific upload path, not every
  //     request). Both monica and koel validate uploads. ---
  {
    sink: 'laravel-file-validation',
    owners: ['laravel/framework', 'framework'],
    summary: [/file validation/i, /validation bypass/i],
    promoteTo: 'function',
    requires: (s) => hasFileUploadValidation(s),
    threatTag: 'requires_file_upload',
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
 * Decide whether a `module` laravel/framework finding should be PROMOTED to a
 * visible tier because its CVE lives on an always-on Laravel request path AND
 * the app is a deployed web app AND the required feature is present. Pure.
 *
 * COMPOSITION: the caller runs the demotions first and only offers still-`module`
 * findings here (a demoted finding's `unreachable` is respected).
 */
export function evaluateLaravelAlwaysOnRuntimePromotion(input: {
  depName: string | null | undefined;
  summary: string | null | undefined;
  hasHttpRouteEntryPoint: boolean;
  signals?: LaravelFeatureSignals | null;
}): AlwaysOnPromotionResult {
  const { depName, summary, hasHttpRouteEntryPoint } = input;
  if (!hasHttpRouteEntryPoint) return { promote: false };
  if (!depName || !summary) return { promote: false };
  const dep = depName.toLowerCase();
  const signals = input.signals ?? emptyLaravelFeatureSignals();
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
  'node_modules', '.git', 'vendor', 'storage', 'bootstrap', 'build', 'dist',
  'public', '.idea', 'coverage', '.github', 'database',
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

/**
 * Read a Laravel workspace into feature signals. Scans `app/**` + `routes/**`
 * PHP (Laravel's first-party code lives there, NOT Symfony's `src/`). Returns
 * empty (unrecognized) signals when the root is unreadable / not a Laravel app,
 * which refuses every demotion / promotion.
 */
export function gatherLaravelFeatureSignals(root: string | undefined): LaravelFeatureSignals {
  const signals = emptyLaravelFeatureSignals();
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
  const hasLaravel = signals.lockProd.has('laravel/framework');

  const codeParts: string[] = [];
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
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        walk(full, depth + 1);
        continue;
      }
      if (!ent.isFile()) continue;
      const lower = ent.name.toLowerCase();
      if (!lower.endsWith('.php')) continue;
      const fullLower = full.toLowerCase().replace(/\\/g, '/');
      // First-party Laravel code: app/** + routes/**. Skip tests — a feature
      // exercised only by tests is not on the production path.
      if (!/\/app\/|\/routes\//.test(fullLower)) continue;
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
  };

  walk(root, 0);

  signals.codeText = codeParts.join('\n');
  signals.truncated = truncated;
  // Recognized only for a real Laravel app whose lockfile we could read.
  signals.recognized = hasLaravel && (signals.lockProd.size > 0 || signals.lockDev.size > 0);
  return signals;
}
