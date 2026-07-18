/**
 * Build the per-file route-auth map carried on `ctx.entryPointAuth` (entry-point
 * auth classification, T2). The map is the dataset `matchFlowToRoutes` joins each
 * taint flow against; it is in-memory only (never persisted — the coarse
 * `project_entry_points` row is the persisted form).
 *
 * Keys are project-relative POSIX paths produced by the SAME `toProjectRelative`
 * the entry-point writer uses, so a map key is byte-identical to a flow's
 * `entry_point_file` (both workspace-relative POSIX) — the join can never miss on
 * a path-shape mismatch.
 *
 * Two record sources:
 *   - every detected `EntryPoint` (per-route, pre-dedupe) with its captured
 *     handler span + demotion-eligibility;
 *   - `CtxOnlyRouteRecord`s returned by cross-file `postProcess` detectors
 *     (Rails/Django), which re-home per-action classifications onto the
 *     controller/view file WITHOUT ever touching `file.entryPoints` (so
 *     `storeEntryPoints` + `httpEntryPointCount` are untouched).
 */
import type { ExtractedFile } from '../tree-sitter-extractor/languages/types';
import type { CtxOnlyRouteRecord, EntryPoint, FrameworkDetector } from './types';
import type { RouteAuthRecord } from './util/auth-evidence';
import { toProjectRelative } from './storage';
import { allDetectors } from './registry';
import { recordDetectorError } from '../tree-sitter-extractor/detector-errors';

/** Same shape as `EntryPointAuthMap` (taint-engine/match-flow-to-routes). */
export type EntryPointAuthMap = Map<string, RouteAuthRecord[]>;

/**
 * Run every detector's optional cross-file `postProcess` pass and collect the
 * re-homed ctx-only records. Each detector is isolated in its own try/catch so a
 * throw degrades that one framework to route-local evidence (its per-route
 * `EntryPoint`s already landed during extraction) without losing the others.
 * Yields to the event loop between detectors so a heavy cross-file walk on a big
 * repo can't starve the heartbeat.
 *
 * `detectors` is injectable for tests; production passes the real registry.
 */
export async function runPostProcess(
  files: readonly ExtractedFile[],
  workspaceRoot: string,
  detectors: readonly FrameworkDetector[] = allDetectors(),
): Promise<CtxOnlyRouteRecord[]> {
  const out: CtxOnlyRouteRecord[] = [];
  for (const d of detectors) {
    if (!d.postProcess) continue;
    try {
      const recs = d.postProcess(files, { workspaceRoot });
      if (Array.isArray(recs)) out.push(...recs);
    } catch (err) {
      recordDetectorError(d.name, err);
    }
    // Cooperative yield (wpa2-f4) — one per detector that actually ran.
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  return out;
}

function recordFromEntryPoint(ep: EntryPoint): RouteAuthRecord {
  return {
    classification: ep.classification,
    handlerSpan: ep.handlerSpan ?? null,
    // Absent flag ⇒ eligible only when a span was captured (the documented
    // default on `EntryPoint.demotionEligible`). A null span never matches a
    // flow anyway, so this is fail-safe either way.
    demotionEligible: ep.demotionEligible ?? (ep.handlerSpan != null),
    routePattern: ep.routePattern,
    middlewareChain: ep.middlewareChain,
    authMechanism: ep.authMechanism,
  };
}

/**
 * Assemble the route-auth map from the detected entry points plus any
 * `postProcess`-returned ctx-only records. Pure + synchronous.
 */
export function buildEntryPointAuthMap(
  files: readonly ExtractedFile[],
  extraRecords: readonly CtxOnlyRouteRecord[],
  workspaceRoot: string | undefined,
): EntryPointAuthMap {
  const map: EntryPointAuthMap = new Map();
  const add = (key: string, rec: RouteAuthRecord): void => {
    const arr = map.get(key);
    if (arr) arr.push(rec);
    else map.set(key, [rec]);
  };

  for (const file of files) {
    for (const ep of file.entryPoints ?? []) {
      add(toProjectRelative(workspaceRoot, ep.filePath), recordFromEntryPoint(ep));
    }
  }
  // Re-homed cross-file records. `filePath` is contract-documented as
  // project-relative POSIX, but normalize defensively so an absolute path from a
  // detector can never silently break the join.
  for (const rec of extraRecords) {
    add(toProjectRelative(workspaceRoot, rec.filePath), {
      classification: rec.classification,
      handlerSpan: rec.handlerSpan,
      demotionEligible: rec.demotionEligible,
      routePattern: rec.routePattern,
      middlewareChain: rec.middlewareChain,
      authMechanism: rec.authMechanism,
    });
  }
  return map;
}

/**
 * Attack-surface tally for the T2 log line. Counted over the PERSISTED entry
 * points only (`file.entryPoints`) — re-homed ctx-only records are deliberately
 * excluded so the number matches what `project_entry_points` holds.
 */
export function summarizeAttackSurface(files: readonly ExtractedFile[]): {
  public: number;
  authenticated: number;
  background: number;
} {
  let pub = 0;
  let authed = 0;
  let background = 0;
  for (const file of files) {
    for (const ep of file.entryPoints ?? []) {
      switch (ep.classification) {
        case 'AUTH_INTERNAL':
          authed++;
          break;
        case 'OFFLINE_WORKER':
          background++;
          break;
        default:
          // PUBLIC_UNAUTH + UNKNOWN both read as externally reachable surface.
          pub++;
      }
    }
  }
  return { public: pub, authenticated: authed, background };
}
