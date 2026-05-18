/**
 * NDJSON writer for the diagnostic drop records emitted by the propagator
 * (Phase 1.2 of the reachability-90-percent plan).
 *
 * Plumbed by callers that want a flushed-on-process-exit on-disk transcript
 * of "why didn't this taint propagate?" — the iterate harness, the
 * cve-targeted-fixture runner, or any test that wants to consume drop
 * records offline. Stays out of the engine core so production code paths
 * pay zero fs overhead unless they opt in.
 *
 * One line per `DropRecord` (JSON.stringify, no pretty-printing). Append-only.
 * The caller is responsible for picking the path and calling close() at the
 * end; the writer doesn't auto-flush on process exit (deterministic > magic).
 */

import * as fs from 'fs';
import * as path from 'path';
import type { DiagSink, DropRecord } from './flow';

export interface DiagNdjsonWriter {
  /** Pass as `RunWorklistOptions.diagSink`. */
  sink: DiagSink;
  /** Records emitted so far (in-memory mirror, useful for tests + summary lines). */
  records(): DropRecord[];
  /** Flush + close the file handle. Safe to call multiple times. */
  close(): void;
}

/**
 * Open an NDJSON file at `filePath` and return a sink that appends one JSON
 * record per call. Creates any missing parent directories.
 */
export function createNdjsonDiagWriter(filePath: string): DiagNdjsonWriter {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const fd = fs.openSync(filePath, 'a');
  const captured: DropRecord[] = [];
  let closed = false;
  return {
    sink: (record: DropRecord): void => {
      if (closed) return;
      captured.push(record);
      fs.writeSync(fd, JSON.stringify(record) + '\n');
    },
    records: (): DropRecord[] => captured.slice(),
    close: (): void => {
      if (closed) return;
      try {
        fs.closeSync(fd);
      } catch {
        /* non-fatal */
      }
      closed = true;
    },
  };
}

/**
 * Convenience: read back the NDJSON file as an array of DropRecords. Used by
 * the iterate-harness diag analysis step in Phase 4.0 reclassification.
 * Silently ignores malformed lines so a partial dump (process killed mid-write)
 * doesn't crash readers.
 */
export function readNdjsonDiagFile(filePath: string): DropRecord[] {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, 'utf8');
  const out: DropRecord[] = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed) as DropRecord);
    } catch {
      /* skip malformed */
    }
  }
  return out;
}

/**
 * Inspect the environment for the canonical Phase 1.2 dump path. Returns a
 * configured NDJSON writer when both env vars are set; returns null
 * otherwise so callers can write `const w = diagFromEnv(cveId); opts.diagSink = w?.sink;`
 * with no branching elsewhere.
 *
 * Required env:
 *   - `DEBUG_TRACE=1` (must be exactly "1")
 *   - `DEBUG_TRACE_DIR=<absolute path to bench-iterate/<variant>/<ts>/diag/>`
 *
 * The caller passes `cveId` (or any short correlation tag); the file lands
 * at `<DEBUG_TRACE_DIR>/<cveId>.ndjson`.
 */
export function diagFromEnv(cveId: string): DiagNdjsonWriter | null {
  if (process.env.DEBUG_TRACE !== '1') return null;
  const dir = process.env.DEBUG_TRACE_DIR;
  if (!dir) return null;
  return createNdjsonDiagWriter(path.join(dir, `${cveId}.ndjson`));
}
