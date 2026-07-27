/**
 * Backend copy of the depscanner's `entry_point_tag` parser (entry-point auth
 * classification, T11). Byte-identical logic to
 * `depscanner/src/taint-engine/match-flow-to-routes.ts` `parseEntryPointTag` —
 * there is no shared package between the worker and the backend, so this follows
 * the `scrub.ts` convention: a duplicated helper kept in sync by a parity test
 * (`entry-point-tag.test.ts`). If you change one, change both.
 *
 * `votes` distinguishes matched `framework-route:` evidence (participates in the
 * merge / carries a real class) from unmatched / legacy tags (no signal). The
 * DTO builder shows a badge only for voting tags.
 */

export type EntryPointClassification = 'PUBLIC_UNAUTH' | 'AUTH_INTERNAL' | 'OFFLINE_WORKER' | 'UNKNOWN';

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

/**
 * The entry-point class to surface on a per-flow DTO / badge: the matched
 * evidence class, or null for unmatched / legacy tags (no badge — matches the
 * frontend's no-signal rendering).
 */
export function entryPointClassForDto(tag: string | null | undefined): EntryPointClassification | null {
  const { cls, votes } = parseEntryPointTag(tag);
  return votes ? cls : null;
}
