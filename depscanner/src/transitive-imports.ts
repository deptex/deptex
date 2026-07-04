/**
 * Transitive dependency-source import index — Arc 2 (dependency-source import
 * graphs). Answers "is module/submodule X imported by any package on the
 * production dependency path?" for the reachability precondition models, which
 * today can only prove absence against FIRST-PARTY imports.
 *
 * Two legs build this index (see pipeline-steps/dep-import-graph.ts):
 *   - golang: `go list -deps ./...` — the toolchain's exact compile set, a
 *     ROOTED closure from first-party packages. A package appears iff it is
 *     genuinely compiled into the build, so membership needs no owner
 *     exclusion.
 *   - pypi: per-dist wheel import extraction — an UNROOTED union over every
 *     installed prod dist (a conservative superset of the rooted closure).
 *     Sound for vetoes on every dist EXCEPT the finding's OWNER package, whose
 *     own sources always mention its own submodules (PIL's ImageFont.py
 *     contains "imagefont"; cryptography's pkcs7.py contains "pkcs7"; sqlparse
 *     self-imports absolutely). Owner exclusion restores the actual question —
 *     "does anything ELSE load this?" — and matches the existing first-party
 *     textIncludes standard.
 *
 * THREE-VALUED SAFETY (the arc's core rule):
 *   - POSITIVE answers (imported / token hit) are valid on ANY status — they
 *     only ever REFUSE a demotion, the conservative direction.
 *   - ABSENCE claims require `status === 'complete'` — only the Go leg can
 *     reach it in v1 (the pypi leg is veto-only; see the arc plan §8).
 *   - `unavailable`, or absence asked of a `partial` index, means `unknown`:
 *     the caller must refuse the demotion, exactly like a truncated
 *     first-party scan.
 *
 * This module is PURE and dependency-free (both the models and the pipeline
 * step import it; it imports neither). All package keys and owner names are
 * expected pre-normalized by the caller (PEP-503 for pypi, exact module path
 * for golang).
 */

export interface PackageImportSummary {
  /**
   * Modules this package imports — lowercased dotted paths for pypi
   * (`pil.imagefont`), full import paths for golang
   * (`golang.org/x/net/idna`).
   */
  modules: Set<string>;
  /**
   * Question-token substring hits found anywhere in this package's sources
   * (pypi only) — the liberal belt-and-suspenders that catches
   * `importlib.import_module("PIL.ImageFont")`-style dynamic loading the
   * import parser can't see.
   */
  tokenHits: Set<string>;
}

export interface TransitiveImportIndex {
  ecosystem: 'golang' | 'pypi';
  /**
   * complete    — every enumerated package extracted; absence answers valid.
   * partial     — some packages failed / capped / had no wheel; only POSITIVE
   *               answers are valid (veto-only).
   * unavailable — nothing usable; callers behave exactly as if no index exists.
   */
  status: 'complete' | 'partial' | 'unavailable';
  /** Per-package summaries, keyed by normalized package name. */
  perPackage: Map<string, PackageImportSummary>;
  /** Names successfully extracted (a set, not a count — supports cross-checks). */
  extractedPackages: Set<string>;
  /** Names enumerated but not extracted (fetch/unpack/cap failures). */
  failedPackages: string[];
}

/** The "nothing usable" sentinel — callers treat it identically to no index. */
export function emptyTransitiveImportIndex(
  ecosystem: TransitiveImportIndex['ecosystem'],
): TransitiveImportIndex {
  return {
    ecosystem,
    status: 'unavailable',
    perPackage: new Map(),
    extractedPackages: new Set(),
    failedPackages: [],
  };
}

/** Path separator for descendant semantics: pypi dots, golang slashes. */
function separatorFor(ecosystem: TransitiveImportIndex['ecosystem']): string {
  return ecosystem === 'golang' ? '/' : '.';
}

/**
 * Union of every package's imported modules — the flat membership set the Go
 * evaluator consumes (rooted closure ⇒ no owner exclusion needed).
 */
export function unionImportedModules(idx: TransitiveImportIndex): Set<string> {
  const out = new Set<string>();
  for (const summary of idx.perPackage.values()) {
    for (const m of summary.modules) out.add(m);
  }
  return out;
}

/**
 * Is `mod` imported by any package OTHER than the excluded owners — exactly,
 * or via a DESCENDANT path (`pil.imagefont.core` counts as importing
 * `pil.imagefont`; an ANCESTOR does not — same semantics as the first-party
 * `moduleImported` / `importsSubpackage` checks)?
 *
 * A positive answer is valid on ANY index status (it only ever refuses a
 * demotion). Callers asking about ABSENCE must separately require
 * `status === 'complete'`.
 */
export function transitiveModuleImported(
  idx: TransitiveImportIndex,
  mod: string,
  excludeOwners: ReadonlySet<string>,
): boolean {
  const prefix = mod + separatorFor(idx.ecosystem);
  for (const [pkg, summary] of idx.perPackage) {
    if (excludeOwners.has(pkg)) continue;
    for (const m of summary.modules) {
      if (m === mod || m.startsWith(prefix)) return true;
    }
  }
  return false;
}

/**
 * Did any package OTHER than the excluded owners hit one of `tokens` (liberal
 * substring evidence, pypi only)? Positive-only evidence, valid on any status.
 */
export function transitiveTokenHit(
  idx: TransitiveImportIndex,
  tokens: readonly string[],
  excludeOwners: ReadonlySet<string>,
): boolean {
  if (tokens.length === 0) return false;
  for (const [pkg, summary] of idx.perPackage) {
    if (excludeOwners.has(pkg)) continue;
    for (const t of tokens) {
      if (summary.tokenHits.has(t)) return true;
    }
  }
  return false;
}

/** A precondition row's transitive question: which modules/tokens indicate a consumer. */
export interface TransitiveQuestion {
  /** Module prefixes whose (descendant) import by a non-owner dist is a veto. */
  modules?: readonly string[];
  /** Liberal substring tokens whose presence in a non-owner dist is a veto. */
  tokens?: readonly string[];
}

/**
 * The single veto entry point for the pypi precondition rows: does any
 * NON-OWNER prod-path package import one of the question's modules or mention
 * one of its tokens? True ⇒ a transitive consumer may load the vulnerable
 * submodule ⇒ the demotion must be refused. False proves nothing by itself
 * (v1 is veto-only): the caller's existing first-party + hard-list logic
 * still decides.
 *
 * Null/undefined index or `unavailable` status ⇒ false (no evidence either
 * way — today's behavior).
 */
export function transitiveConsumerVeto(
  idx: TransitiveImportIndex | null | undefined,
  question: TransitiveQuestion,
  excludeOwners: readonly string[],
): boolean {
  if (!idx || idx.status === 'unavailable') return false;
  const owners = new Set(excludeOwners);
  if (question.modules) {
    for (const mod of question.modules) {
      if (transitiveModuleImported(idx, mod, owners)) return true;
    }
  }
  if (question.tokens && transitiveTokenHit(idx, question.tokens, owners)) return true;
  return false;
}
