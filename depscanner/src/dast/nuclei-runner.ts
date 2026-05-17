// v2.1c: Nuclei (ProjectDiscovery) DAST engine runner.
//
// Nuclei is the second user-triggerable DAST engine alongside ZAP. It runs the
// pinned `nuclei` binary (baked into the depscanner image) against a single
// target URL, streams JSONL results, and maps each result into the engine-
// agnostic `DastFindingRaw` shape so the rest of the pipeline (cross-link,
// insert, commit) is unchanged.
//
// Credentials: form/jwt/cookie auth is reduced to a flat header map and written
// to an ephemeral 0600 file in a per-run mkdtemp dir, passed to nuclei as
// `-H @<file>`. The dir is removed in a finally block on BOTH the resolve and
// reject paths so plaintext auth headers never linger. `sweepStaleDastTmpDirs`
// runs at worker startup to clear dirs orphaned by a hard crash.

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  spawnExternal,
  type AbortReason,
} from './control-plane';
import {
  owaspRefForCwe,
  redactCredentials,
  type DastFindingRaw,
} from './runner';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default overall scan budget — same 30 min ceiling as the ZAP path. */
export const NUCLEI_DEFAULT_TIMEOUT_MS = 30 * 60_000;

/** mkdtemp prefix for per-run credential dirs; sweepStaleDastTmpDirs keys on it. */
const NUCLEI_TMP_PREFIX = 'dast-nuclei-';

// ---------------------------------------------------------------------------
// Nuclei JSONL result shape (only the fields we consume)
// ---------------------------------------------------------------------------

interface NucleiClassification {
  'cve-id'?: string[] | null;
  'cwe-id'?: string[] | null;
  'epss-score'?: number | null;
  'epss-percentile'?: number | null;
  cpe?: string | null;
}

interface NucleiInfo {
  name?: string;
  severity?: string;
  description?: string;
  tags?: string[] | string;
  classification?: NucleiClassification | null;
}

interface NucleiResult {
  'template-id'?: string;
  'template-path'?: string;
  info?: NucleiInfo;
  type?: string;
  host?: string;
  'matched-at'?: string;
  'matched-line'?: string;
  request?: string;
  response?: string;
  'extracted-results'?: string[];
  'matcher-status'?: boolean;
}

const NUCLEI_SEVERITY_MAP: Record<string, DastFindingRaw['severity']> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  unknown: 'info',
};

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

/** Extract the HTTP method from a raw request blob; default GET. */
function methodFromRequest(request: string | undefined, type: string | undefined): string {
  if (type && type !== 'http') return 'GET';
  if (!request) return 'GET';
  const firstLine = request.split(/\r?\n/, 1)[0] ?? '';
  const verb = firstLine.trim().split(/\s+/, 1)[0] ?? '';
  return /^[A-Z]+$/.test(verb) ? verb : 'GET';
}

function asTagArray(tags: string[] | string | undefined): string[] {
  if (Array.isArray(tags)) return tags;
  if (typeof tags === 'string') return tags.split(',').map((t) => t.trim()).filter(Boolean);
  return [];
}

/**
 * Map one parsed Nuclei result object into a `DastFindingRaw`. Returns null
 * when the object is missing the fields a finding cannot exist without
 * (a template id and any addressable location).
 */
export function mapNucleiResult(obj: NucleiResult): DastFindingRaw | null {
  const templateId = typeof obj['template-id'] === 'string' ? obj['template-id'] : null;
  const endpoint = obj['matched-at'] || obj.host || '';
  if (!templateId || !endpoint) return null;

  const info = obj.info ?? {};
  const classification = info.classification ?? {};
  const tags = asTagArray(info.tags);

  const severity = NUCLEI_SEVERITY_MAP[(info.severity ?? 'info').toLowerCase()] ?? 'info';

  const cweRaw = Array.isArray(classification['cwe-id']) ? classification['cwe-id'][0] : null;
  const cweId = cweRaw ? cweRaw.replace(/^CWE-/i, '') : null;

  const cveIds = (Array.isArray(classification['cve-id']) ? classification['cve-id'] : [])
    .filter((c): c is string => typeof c === 'string' && c.length > 0);

  const extracted = (Array.isArray(obj['extracted-results']) ? obj['extracted-results'] : [])
    .filter((v): v is string => typeof v === 'string')
    .map((v) => redactCredentials(v))
    .filter((v): v is string => v != null);

  return {
    endpoint_url: endpoint,
    http_method: methodFromRequest(obj.request, obj.type),
    vulnerability_type: info.name || templateId,
    severity,
    cwe_id: cweId,
    owasp_top10_ref: owaspRefForCwe(cweId),
    rule_id: templateId,
    message: info.description || info.name || null,
    payload_redacted: redactCredentials(obj.request ?? null),
    response_evidence_redacted: redactCredentials(obj.response ?? null),
    // A Nuclei matcher hit is a deterministic runtime detection.
    confidence: 'high',
    engine: 'nuclei',
    template_id: templateId,
    kev: tags.some((t) => t.toLowerCase() === 'kev'),
    cve_ids: cveIds,
    epss_score: typeof classification['epss-score'] === 'number' ? classification['epss-score'] : null,
    cpe: typeof classification.cpe === 'string' ? classification.cpe : null,
    extracted_values: extracted.length > 0 ? extracted : null,
  };
}

/**
 * Parse Nuclei's `-jsonl` stdout. Robust to a truncated final line (process
 * killed mid-write), blank lines, non-JSON noise, and duplicate lines (the
 * same template can match twice on identical input — dedupe on the raw line).
 */
export function parseNucleiJsonl(stdout: string): DastFindingRaw[] {
  const out: DastFindingRaw[] = [];
  const seenLines = new Set<string>();
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line[0] !== '{') continue;
    if (seenLines.has(line)) continue;
    seenLines.add(line);
    let obj: NucleiResult;
    try {
      obj = JSON.parse(line) as NucleiResult;
    } catch {
      // Truncated last line or non-JSON noise — skip, never crash the parse.
      continue;
    }
    const finding = mapNucleiResult(obj);
    if (finding) out.push(finding);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Ephemeral credential file
// ---------------------------------------------------------------------------

/**
 * Write `authHeaders` to a 0600 file inside a fresh mkdtemp dir. Returns the
 * dir + file path; the caller MUST remove the dir in a finally block.
 */
function writeHeaderFile(authHeaders: Record<string, string>): { dir: string; file: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), NUCLEI_TMP_PREFIX));
  const file = path.join(dir, 'headers.txt');
  const body = Object.entries(authHeaders)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
  fs.writeFileSync(file, body + '\n', { mode: 0o600 });
  return { dir, file };
}

/**
 * Worker-startup sweep: remove `dast-nuclei-*` dirs left in os.tmpdir() by a
 * hard crash that skipped the finally cleanup. Best-effort; never throws.
 */
export function sweepStaleDastTmpDirs(): void {
  let entries: string[];
  try {
    entries = fs.readdirSync(os.tmpdir());
  } catch {
    return;
  }
  for (const name of entries) {
    if (!name.startsWith(NUCLEI_TMP_PREFIX)) continue;
    try {
      fs.rmSync(path.join(os.tmpdir(), name), { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  }
}

// ---------------------------------------------------------------------------
// runNuclei
// ---------------------------------------------------------------------------

export interface RunNucleiInputs {
  targetUrl: string;
  /** Templates corpus dir — defaults to $NUCLEI_TEMPLATES_DIR. */
  templatesDir?: string;
  scanTimeoutMinutes: number;
  /** Flattened auth headers; written to an ephemeral 0600 file when present. */
  authHeaders?: Record<string, string>;
  /** Test seam — substitute the spawn implementation. */
  spawnImpl?: typeof spawn;
}

export interface RunNucleiControl {
  /** Heartbeat tick called from the cancellation-poll loop. */
  onHeartbeat: () => Promise<void>;
  /** Returns true to abort the scan (user cancellation). */
  isCancelled: () => Promise<boolean>;
  /** Polling cadence for cancellation + heartbeat. */
  pollIntervalMs: number;
}

export interface NucleiRunOutputs {
  findings: DastFindingRaw[];
  durationMs: number;
  exitCode: number | null;
  aborted: boolean;
  abortReason: AbortReason | null;
}

/**
 * Run a Nuclei scan against a single target. Spawns the pinned `nuclei` binary
 * via the shared control-plane (group-kill, SIGTERM→SIGKILL escalation, hard
 * timeout), polls for cancellation, and parses the JSONL result stream.
 */
export async function runNuclei(
  inputs: RunNucleiInputs,
  control: RunNucleiControl,
): Promise<NucleiRunOutputs> {
  const templatesDir = inputs.templatesDir ?? process.env.NUCLEI_TEMPLATES_DIR ?? '/opt/nuclei-templates';
  const timeoutMs = inputs.scanTimeoutMinutes * 60_000;

  let credDir: string | null = null;
  let credFile: string | null = null;
  if (inputs.authHeaders && Object.keys(inputs.authHeaders).length > 0) {
    const written = writeHeaderFile(inputs.authHeaders);
    credDir = written.dir;
    credFile = written.file;
  }

  // `-silent` keeps stdout to JSONL result lines only; `-jsonl` selects the
  // line-delimited format; `-disable-update-check` blocks any network fetch
  // of the templates corpus (we use the SHA-pinned baked copy).
  const args = [
    '-target', inputs.targetUrl,
    '-templates', templatesDir,
    '-jsonl',
    '-silent',
    '-no-color',
    '-disable-update-check',
  ];
  if (credFile) {
    args.push('-H', `@${credFile}`);
  }

  try {
    const handle = spawnExternal({
      command: 'nuclei',
      args,
      timeoutMs,
      spawnImpl: inputs.spawnImpl,
      onStderr: (chunk) => {
        process.stderr.write(`[nuclei] ${redactCredentials(chunk)}`);
      },
    });

    // Cancellation + heartbeat poll, mirroring the ZAP control loop.
    let pollDone = false;
    let pollTimer: NodeJS.Timeout | null = null;
    async function pollOnce(): Promise<void> {
      if (pollDone) return;
      try {
        await control.onHeartbeat();
      } catch {
        /* non-fatal */
      }
      if (pollDone) return;
      let cancelled = false;
      try {
        cancelled = await control.isCancelled();
      } catch {
        cancelled = false;
      }
      if (pollDone) return;
      if (cancelled) {
        handle.abort('cancellation_requested');
        return;
      }
      pollTimer = setTimeout(pollOnce, control.pollIntervalMs);
      pollTimer.unref?.();
    }
    pollTimer = setTimeout(pollOnce, control.pollIntervalMs);
    pollTimer.unref?.();

    let result;
    try {
      result = await handle.done;
    } finally {
      pollDone = true;
      if (pollTimer) clearTimeout(pollTimer);
    }

    return {
      findings: parseNucleiJsonl(result.stdout),
      durationMs: result.durationMs,
      exitCode: result.exitCode,
      aborted: result.aborted,
      abortReason: result.abortReason,
    };
  } finally {
    // Drop the plaintext header file on BOTH the resolve and reject paths.
    if (credDir) {
      try {
        fs.rmSync(credDir, { recursive: true, force: true });
      } catch {
        /* best-effort — sweepStaleDastTmpDirs is the backstop */
      }
    }
  }
}
