/**
 * Flow → route join (entry-point auth classification, Core Semantics 6/7).
 *
 * THE single source of truth for matching a taint flow to the detected routes
 * in its source file, imported by BOTH consumers so they can never diverge:
 *   - T3 tag stamping (`pipeline-steps/taint-engine.ts` → `storage.ts writeFlows`)
 *   - T5 fp-filter route-context injection (`taint-engine/fp-filter.ts`)
 * The fp-filter runs inside `runEngine` on the main thread BEFORE the pipeline
 * step's `writeFlows`, so both sites must call this one helper.
 *
 * A flow demotes only when its source line falls inside an authed,
 * demotion-eligible handler span. Everything else stamps `unmatched` (PUBLIC
 * weight, no merge vote) — the structural fail-safe that makes every
 * wrongful-demotion shape from the review rounds impossible.
 */
import type { EntryPointClassification } from '../framework-rules/types';
import { spanContains, type RouteAuthRecord } from '../framework-rules/util/auth-evidence';

export type { RouteAuthRecord };

/** The per-file, per-route auth map carried on the pipeline ctx (built at usage extraction). */
export type EntryPointAuthMap = Map<string, RouteAuthRecord[]>;

export const TAG_UNMATCHED = 'framework-input:unmatched';
/** Legacy constant the engine wrote before this feature; parses to PUBLIC weight, never votes. */
export const TAG_LEGACY_PUBLIC = 'framework-input:PUBLIC_UNAUTH';

/** Evidence tag for a matched, evaluated route. Lowercase class token. */
export function tagForClass(cls: EntryPointClassification): string {
  return `framework-route:${cls.toLowerCase()}`;
}

/** Higher = more exposed. Used to pick the worst-case (most-exposed) among candidates. */
const EXPOSURE_RANK: Record<EntryPointClassification, number> = {
  PUBLIC_UNAUTH: 3,
  AUTH_INTERNAL: 2,
  OFFLINE_WORKER: 1,
  UNKNOWN: 0,
};

export interface FlowRouteMatch {
  /** Routes whose handler span contains the flow's source line. */
  candidates: RouteAuthRecord[];
  /** The tag to stamp on the flow (Sem 6 stamping rule). */
  stampTag: string;
  /** The single route to feed the Qwen prompt (T5) — narrowest containing span, or null. */
  contextRoute: RouteAuthRecord | null;
}

/**
 * Match a taint flow to the routes in its source file (Core Semantics 6).
 *
 * @param authMap  ctx.entryPointAuth — per-file route records (project-relative POSIX keys)
 * @param file     the flow's `entry_point_file` (already project-relative POSIX)
 * @param line     the flow's `entry_point_line` (1-based)
 */
export function matchFlowToRoutes(authMap: EntryPointAuthMap, file: string, line: number): FlowRouteMatch {
  const routes = authMap.get(file) ?? [];
  const candidates = routes.filter((r) => spanContains(r.handlerSpan, line));

  // Context route (T5): narrowest containing span = innermost handler.
  let contextRoute: RouteAuthRecord | null = null;
  let narrowest = Infinity;
  for (const c of candidates) {
    if (!c.handlerSpan) continue;
    const width = c.handlerSpan.endLine - c.handlerSpan.startLine;
    if (width < narrowest) { narrowest = width; contextRoute = c; }
  }

  if (candidates.length === 0) {
    return { candidates, stampTag: TAG_UNMATCHED, contextRoute };
  }

  // Worst-case across candidates (Sem 6 stamping):
  //  - any evidence-PUBLIC candidate → the flow is publicly reachable here.
  //  - any UNKNOWN, or any authed-but-INELIGIBLE candidate → we cannot safely
  //    demote (ignorance / re-mountable handler) → unmatched (no vote).
  //  - else all candidates authed/internal AND eligible → worst-case class.
  if (candidates.some((c) => c.classification === 'PUBLIC_UNAUTH')) {
    return { candidates, stampTag: tagForClass('PUBLIC_UNAUTH'), contextRoute };
  }
  if (candidates.some((c) => c.classification === 'UNKNOWN' || !c.demotionEligible)) {
    return { candidates, stampTag: TAG_UNMATCHED, contextRoute };
  }
  // All are AUTH_INTERNAL / OFFLINE_WORKER and eligible → most-exposed wins.
  let worst: EntryPointClassification = 'OFFLINE_WORKER';
  for (const c of candidates) {
    if (EXPOSURE_RANK[c.classification] > EXPOSURE_RANK[worst]) worst = c.classification;
  }
  return { candidates, stampTag: tagForClass(worst), contextRoute };
}

/**
 * Parse an `entry_point_tag` back to a merge contribution (Core Semantics 7).
 * `votes` distinguishes matched evidence (participates in the PDV worst-case)
 * from unmatched/legacy tags (weight only, no vote). Shared by T3/T4 and
 * byte-duplicated backend-side (no shared package — scrub.ts convention).
 */
export function parseEntryPointTag(tag: string | null | undefined): {
  cls: EntryPointClassification;
  votes: boolean;
} {
  if (typeof tag === 'string' && tag.startsWith('framework-route:')) {
    const token = tag.slice('framework-route:'.length).toUpperCase();
    if (token === 'AUTH_INTERNAL' || token === 'OFFLINE_WORKER' || token === 'PUBLIC_UNAUTH') {
      return { cls: token as EntryPointClassification, votes: true };
    }
  }
  // unmatched, legacy PUBLIC_UNAUTH constant, or anything unrecognized → PUBLIC
  // weight, no vote (the AI verdict alone decides those flows).
  return { cls: 'PUBLIC_UNAUTH', votes: false };
}
