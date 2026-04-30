import type { KnownDep } from '../languages/types';

/**
 * Maven import → artifact resolution.
 *
 * Strict groupId-prefix matching is the common case
 * (`org.apache.commons.text.StringSubstitutor` → groupId `org.apache.commons`).
 * But several popular ecosystems (Jackson, Spring) publish artifacts whose
 * groupId is NOT a prefix of the package path — jackson-databind's groupId
 * is `com.fasterxml.jackson.core` but the class lives in
 * `com.fasterxml.jackson.databind.ObjectMapper`. We handle that by scoring
 * each dep against the import using "longest common dotted prefix" and
 * preferring higher scores.
 *
 * A single groupId can host multiple artifacts (log4j-core, log4j-api in
 * `org.apache.logging.log4j`). When the import alone doesn't disambiguate
 * we tiebreak with heuristic hints (`.core.` → -core, `.databind.` →
 * -databind, etc.), a `-core` > `-api` preference for the Log4Shell case,
 * and shortest-name last.
 */
export function resolveMavenImport(
  importName: string,
  deps: readonly KnownDep[] = []
): string | null {
  if (!importName) return null;

  const importSegs = importName.split('.');
  let bestScore = 0;
  const bestCandidates: KnownDep[] = [];

  for (const dep of deps) {
    if (!dep.namespace) continue;
    const groupSegs = dep.namespace.split('.');
    let matching = 0;
    for (let i = 0; i < Math.min(importSegs.length, groupSegs.length); i++) {
      if (importSegs[i] === groupSegs[i]) matching++;
      else break;
    }
    // Require at least 3 matching segments to avoid false matches on
    // shared TLDs like `com.*` / `org.*`.
    if (matching < 3) continue;
    if (matching > bestScore) {
      bestScore = matching;
      bestCandidates.length = 0;
      bestCandidates.push(dep);
    } else if (matching === bestScore) {
      bestCandidates.push(dep);
    }
  }

  if (bestCandidates.length === 0) return null;
  if (bestCandidates.length === 1) return bestCandidates[0].name;

  const lower = importName.toLowerCase();
  const HINTS: Array<[RegExp, string]> = [
    [/\.core\./, '-core'],
    [/\.core$/, '-core'],
    [/\.api\./, '-api'],
    [/\.api$/, '-api'],
    [/\.impl\./, '-impl'],
    [/\.impl$/, '-impl'],
    [/\.annotation(s)?\b/, 'annotation'],
    [/\.databind\./, 'databind'],
    [/\.databind$/, 'databind'],
  ];
  for (const [pattern, marker] of HINTS) {
    if (!pattern.test(lower)) continue;
    const hinted = bestCandidates.find((d) => d.name.toLowerCase().includes(marker));
    if (hinted) return hinted.name;
  }

  // -core wins over -api when both are present. Reachability generally cares
  // about the implementation artifact (Log4Shell lives in log4j-core, not
  // log4j-api), so this matches real-world use.
  const core = bestCandidates.find((d) => d.name.toLowerCase().includes('-core') || d.name.toLowerCase().endsWith('core'));
  if (core) return core.name;

  let shortest = bestCandidates[0];
  for (const d of bestCandidates) {
    if (d.name.length < shortest.name.length) shortest = d;
  }
  return shortest.name;
}
