/**
 * GuardDog invocation.
 *
 * GuardDog ships with both Semgrep rules and per-ecosystem metadata
 * heuristics. We run it against a previously-unpacked tarball directory
 * (so the binary has no network exposure during the scan) and parse its
 * sarif-ish JSON output into our own raw-finding shape.
 *
 * `--no-exec` is mandatory: it tells GuardDog NOT to run any package
 * postinstall hooks while introspecting metadata. That + tarball-cache's
 * `--ignore-scripts` are the only execution barriers.
 */
import { execFile, execFileSync } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { canonicalizeEcosystem, guarddogCliVerb, type CanonicalEcosystem } from './ecosystem';

const execFileAsync = promisify(execFile);

export const GUARDDOG_VERSION = 'guarddog@2.9.0';
const GUARDDOG_BIN = '/opt/guarddog-venv/bin/guarddog';
const PER_PACKAGE_TIMEOUT_MS = 60_000;

export interface GuardDogRule {
  rule_id: string;
  severity: 'ERROR' | 'WARNING' | 'INFO' | string;
  message: string;
  evidence: { file_path: string; lines: [number, number]; snippet: string }[];
}

/**
 * GuardDog source heuristics that are too low-precision to stand alone as a
 * "this package is malicious" finding. Each fires on a structural pattern that
 * the vast majority of legitimate packages contain, with no judgement of
 * intent:
 *   - `api-obfuscation`   — any dynamic / minified API access (dynamic
 *     `require`, bracket access on `process`). Flagged `express@4.18.2` and
 *     `on-finished@2.4.1`.
 *   - `npm-install-script` — merely "package.json declares a pre/post-install
 *     hook." Flagged `esbuild` and `@types/node`. It detects the *presence* of
 *     a hook, not a malicious one — a genuinely malicious install hook also
 *     trips the behavioral rules below.
 *   - `shady-links`       — a URL whose domain "looks" suspicious by shape.
 *     Flagged `is-number`, `micromatch`, `proxy-from-env` — three of the most-
 *     downloaded packages on npm.
 * Real malware that does any of these ALSO trips higher-signal behavioral rules
 * (exfiltration, silent process execution, outbound network) which we keep, so
 * dropping these standalone structural flags loses no real detection while
 * killing a large source of false positives. Matched by rule-id suffix so it
 * covers every ecosystem prefix (npm-/pypi-/go-/…).
 */
export const GUARDDOG_LOW_PRECISION_RULE_SUFFIXES = [
  'api-obfuscation',
  'npm-install-script',
  'shady-links',
] as const;

/**
 * Canonicalize a GuardDog rule id for suffix matching: lowercase and fold `_`
 * to `-`. GuardDog 2.9.0 emits hyphenated ids (`npm-api-obfuscation`), but
 * folding underscores makes the suffix lists robust to a separator change in a
 * future GuardDog without re-validating against live output. A no-op for the
 * hyphenated ids we see today.
 */
function normalizeGuardDogRuleId(ruleId: string): string {
  return (ruleId ?? '').toLowerCase().replace(/_/g, '-');
}

export function isLowPrecisionGuardDogRule(ruleId: string): boolean {
  const id = normalizeGuardDogRuleId(ruleId);
  return GUARDDOG_LOW_PRECISION_RULE_SUFFIXES.some((s) => id.endsWith(s));
}

/**
 * Broad GuardDog METADATA heuristics that fire standalone on well-vetted
 * packages and are too weak to stand alone as a "this package is malicious"
 * verdict. Unlike GUARDDOG_LOW_PRECISION_RULE_SUFFIXES (dropped unconditionally
 * because real malware ALWAYS also trips a behavioral rule), these are kept when
 * something corroborates them but suppressed when they are the SOLE signal:
 *   - `empty-information`            — no description/readme; ~every internal pkg.
 *   - `release-zero`                 — version 0.0.x / pre-1.0; nearly universal.
 *   - `single-python-file`           — one .py module; tons of legit utilities.
 *   - `bundled-binary`               — ships a compiled artifact; common + legit
 *                                      (esbuild, sharp, prebuilt addons).
 *   - `deceptive-author` /           — author/metadata shape heuristics that
 *     `metadata-mismatch` /            mis-fire on monorepo + re-published pkgs.
 *     `repository-integrity-mismatch`
 *   - `direct-url-dependency`        — a git/url dep; legitimate in many lockfiles.
 *
 * Deliberately EXCLUDES the genuinely-high-signal standalone heuristics —
 * `typosquatting` and the `*-email-domain` account-takeover rules — which can be
 * the ONLY indicator of real malware and are therefore always kept. The
 * corroboration gate lives in malicious-scan.ts; this list is its policy.
 */
export const GUARDDOG_CORROBORATION_RULE_SUFFIXES = [
  'empty-information',
  'release-zero',
  'single-python-file',
  'bundled-binary',
  'deceptive-author',
  'metadata-mismatch',
  'repository-integrity-mismatch',
  'direct-url-dependency',
] as const;

/**
 * True for a broad metadata heuristic that should only surface when corroborated
 * by another signal on the same package (a high-signal GuardDog rule or a feed
 * hit). See GUARDDOG_CORROBORATION_RULE_SUFFIXES.
 */
export function requiresCorroboration(ruleId: string): boolean {
  const id = normalizeGuardDogRuleId(ruleId);
  return GUARDDOG_CORROBORATION_RULE_SUFFIXES.some((s) => id.endsWith(s));
}

/**
 * True for a GuardDog rule that, on its own, is strong enough to corroborate a
 * package's other (weaker) findings: i.e. NOT an unconditionally-dropped
 * low-precision structural flag and NOT a corroboration-requiring metadata
 * heuristic. These are the behavioral / source-code rules (exfiltration, silent
 * process execution, obfuscated code, …) plus the high-signal standalone
 * metadata heuristics (typosquatting, compromised-email-domain).
 */
export function isCorroboratingGuardDogRule(ruleId: string): boolean {
  return !isLowPrecisionGuardDogRule(ruleId) && !requiresCorroboration(ruleId);
}

export function isGuardDogAvailable(): boolean {
  try {
    if (!fs.existsSync(GUARDDOG_BIN)) return false;
    execFileSync(GUARDDOG_BIN, ['--version'], { stdio: 'ignore', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

export interface GuardDogResult {
  rules: GuardDogRule[];
  errored: boolean;
}

/**
 * Run GuardDog over an unpacked package directory. Returns the raw rule
 * hits (already filtered by GuardDog's own severity rules) for the
 * insertion path to map onto Deptex severity.
 */
export async function runGuardDog(
  unpackedDir: string,
  ecosystem: string,
  packageName: string,
): Promise<GuardDogResult> {
  const canonical = canonicalizeEcosystem(ecosystem);
  if (!canonical) return { rules: [], errored: false };

  const verb = guarddogCliVerb(canonical);
  if (!verb) return { rules: [], errored: false };

  let stdout: string;
  try {
    // Async exec — runGuardDog is called under a concurrency gate, and a
    // synchronous execFileSync would block the event loop and serialize
    // every "parallel" slot onto one GuardDog subprocess at a time.
    const res = await execFileAsync(
      GUARDDOG_BIN,
      [verb, 'scan', unpackedDir, '--output-format', 'json', '--exit-non-zero-on-finding'],
      {
        timeout: PER_PACKAGE_TIMEOUT_MS,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    stdout = res.stdout;
  } catch (err: any) {
    // GuardDog exits non-zero ON finding. The stdout is still the json
    // result. Distinguish "exit because findings" from "exit because
    // crashed" via the presence of valid JSON in stdout.
    stdout = err?.stdout?.toString() ?? '';
    if (!stdout.trim()) {
      return { rules: [], errored: true };
    }
  }

  return parseGuardDogJson(stdout, packageName, canonical);
}

export function parseGuardDogJson(
  raw: string,
  packageName: string,
  ecosystem: CanonicalEcosystem,
): GuardDogResult {
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { rules: [], errored: true };
  }

  // GuardDog 2.9.0 (npm/pypi) shape:
  //   { "package": "<dir>", "issues": N, "errors": {}, "results": {
  //       "<rule_id>": {}                       — rule ran, no findings
  //       "<rule_id>": [ <match>, ... ]         — rule ran, fired
  //       "<rule_id>": { "<file>": [ <match>, ... ] }   — metadata rules
  //   }}
  // Each <match> has { location: "file:line", code, message } for source rules
  // and a flat object for metadata rules.
  //
  // We also tolerate two older / future shapes for robustness:
  //   { "results": [ { "rule_name": ..., "details": ... }, ... ] }
  //   { "<rule_id>": { ... } }
  const rules: GuardDogRule[] = [];
  const root = parsed?.results ?? parsed;
  if (!root || typeof root !== 'object') return { rules, errored: false };

  const entries: Array<[string, any]> = Array.isArray(root)
    ? root.map((r: any) => [String(r?.rule_name ?? r?.rule_id ?? 'unknown'), r])
    : Object.entries(root);

  for (const [ruleId, body] of entries) {
    if (body === null || body === undefined) continue;

    // Skip empty objects — GuardDog emits `{}` for every rule that ran
    // without firing; treating those as findings would create one
    // bogus WARNING row per package per supported rule.
    if (
      typeof body === 'object' &&
      !Array.isArray(body) &&
      Object.keys(body).length === 0
    ) {
      continue;
    }

    // Collect raw match objects from whichever shape the rule used.
    const rawMatches: any[] = [];
    if (Array.isArray(body)) {
      // Source rules: rule_id maps directly to an array of matches.
      for (const m of body) rawMatches.push(m);
    } else if (typeof body === 'object') {
      if (Array.isArray((body as any).matches)) {
        // Older / alternate shape with explicit matches array.
        for (const m of (body as any).matches) rawMatches.push(m);
      } else if ((body as any).location || (body as any).message || (body as any).code) {
        // Single-object match.
        rawMatches.push(body);
      } else {
        // Metadata rules sometimes nest by file:
        //   { "<file>": [ <match>, ... ] }
        // Treat each value-array as additional matches.
        for (const v of Object.values(body)) {
          if (Array.isArray(v)) {
            for (const m of v) rawMatches.push(m);
          } else if (v && typeof v === 'object') {
            rawMatches.push(v);
          }
        }
      }
    }

    if (rawMatches.length === 0) {
      // No concrete matches → no evidence. A rule body carrying only a
      // stray `message`/`severity` field but zero matches must NOT become
      // a no-evidence WARNING finding. Skip rather than fabricate one.
      continue;
    }

    const severityRaw =
      (body as any).severity ??
      (body as any).metadata?.severity ??
      (rawMatches.length > 0 ? 'ERROR' : 'WARNING');
    const severity = String(severityRaw).toUpperCase();
    const messageBase =
      (body as any).description ?? (body as any).message ?? rawMatches[0]?.message ?? null;
    const message = String(messageBase ?? `${packageName}/${ecosystem}: ${ruleId}`);

    const evidence: GuardDogRule['evidence'] = [];
    for (const m of rawMatches) {
      // GuardDog's `location` is usually "file:line[-endline]"; sometimes
      // an object with file/line/end fields. Handle both.
      let filePath = m?.file ?? m?.path ?? '';
      let startLine = 0;
      let endLine = 0;
      const loc = m?.location;
      if (typeof loc === 'string') {
        const colon = loc.lastIndexOf(':');
        if (colon > 0) {
          filePath = loc.slice(0, colon);
          const lineSpec = loc.slice(colon + 1);
          const dash = lineSpec.indexOf('-');
          if (dash > 0) {
            startLine = parseInt(lineSpec.slice(0, dash), 10) || 0;
            endLine = parseInt(lineSpec.slice(dash + 1), 10) || startLine;
          } else {
            startLine = parseInt(lineSpec, 10) || 0;
            endLine = startLine;
          }
        } else {
          filePath = loc;
        }
      } else if (loc && typeof loc === 'object') {
        filePath = loc.file ?? filePath;
        startLine = Number(m?.line ?? loc?.line?.start ?? 0) || 0;
        endLine = Number(loc?.line?.end ?? startLine) || startLine;
      } else {
        startLine = Number(m?.line ?? 0) || 0;
        endLine = startLine;
      }
      const snippet = String(m?.code ?? m?.snippet ?? '').slice(0, 1024);
      // GuardDog 2.9.0 emits paths already relative to the scanned
      // directory (e.g. "perf/perf.js"). Strip a leading slash if a
      // future version starts emitting absolute paths so the cache row
      // stays free of org-derived prefix data per multi-tenant
      // invariant #2.
      const stripped = typeof filePath === 'string' ? filePath.replace(/^\/+/, '') : '';
      evidence.push({
        file_path: stripped,
        lines: [startLine, endLine],
        snippet,
      });
    }

    rules.push({ rule_id: String(ruleId), severity, message, evidence });
  }

  return { rules, errored: false };
}
