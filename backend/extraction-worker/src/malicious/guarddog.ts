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
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { canonicalizeEcosystem, guarddogCliVerb, type CanonicalEcosystem } from './ecosystem';

export const GUARDDOG_VERSION = 'guarddog@2.9.0';
const GUARDDOG_BIN = '/opt/guarddog-venv/bin/guarddog';
const PER_PACKAGE_TIMEOUT_MS = 60_000;

export interface GuardDogRule {
  rule_id: string;
  severity: 'ERROR' | 'WARNING' | 'INFO' | string;
  message: string;
  evidence: { file_path: string; lines: [number, number]; snippet: string }[];
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
export function runGuardDog(
  unpackedDir: string,
  ecosystem: string,
  packageName: string,
): GuardDogResult {
  const canonical = canonicalizeEcosystem(ecosystem);
  if (!canonical) return { rules: [], errored: false };

  const verb = guarddogCliVerb(canonical);
  if (!verb) return { rules: [], errored: false };

  let stdout: string;
  try {
    stdout = execFileSync(
      GUARDDOG_BIN,
      [verb, 'scan', unpackedDir, '--output-format', 'json', '--exit-non-zero-on-finding'],
      {
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: PER_PACKAGE_TIMEOUT_MS,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
      },
    );
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

  // GuardDog's JSON shape varies by ecosystem; we accept either:
  //   { "results": { "rule_id": { ... }, "rule_id": { ... } } }
  //   { "results": [ { "rule_name": ..., "details": ... }, ... ] }
  //   { "<rule_id>": { ... } }                              (older shape)
  const rules: GuardDogRule[] = [];
  const root = parsed?.results ?? parsed;
  if (!root || typeof root !== 'object') return { rules, errored: false };

  const entries: Array<[string, any]> = Array.isArray(root)
    ? root.map((r: any) => [String(r?.rule_name ?? r?.rule_id ?? 'unknown'), r])
    : Object.entries(root);

  for (const [ruleId, body] of entries) {
    if (!body || typeof body !== 'object') continue;
    const severityRaw =
      body.severity ??
      body.metadata?.severity ??
      (typeof body.matches !== 'undefined' && body.matches?.length > 0 ? 'ERROR' : 'WARNING');
    const severity = String(severityRaw).toUpperCase();
    const message = String(body.description ?? body.message ?? `${packageName}/${ecosystem}: ${ruleId}`);
    const evidence: GuardDogRule['evidence'] = [];

    const matches = Array.isArray(body.matches) ? body.matches : [];
    for (const m of matches) {
      const filePath = m?.file ?? m?.path ?? m?.location?.file ?? '';
      const startLine = m?.line ?? m?.location?.line?.start ?? 0;
      const endLine = m?.location?.line?.end ?? startLine;
      const snippet = String(m?.code ?? m?.snippet ?? '').slice(0, 1024);
      // file_path is intentionally tarball-relative so the cache stays
      // free of org-derived data per multi-tenant invariant #2.
      const rel = filePath ? path.relative('/', filePath) : '';
      evidence.push({
        file_path: rel || filePath || '',
        lines: [Number(startLine) || 0, Number(endLine) || 0],
        snippet,
      });
    }

    rules.push({ rule_id: String(ruleId), severity, message, evidence });
  }

  return { rules, errored: false };
}
