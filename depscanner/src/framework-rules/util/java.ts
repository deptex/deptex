import * as fs from 'fs';
import * as path from 'path';
import type { Node, Tree } from 'web-tree-sitter';
import type { ImportBinding } from '../../tree-sitter-extractor/languages/types';
import type { EntryPointClassification, HttpMethod } from '../types';

export function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

export function javaStringLiteral(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type !== 'string_literal') return null;
  // string_literal wraps string_fragment nodes between double-quotes.
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'string_fragment') return textOf(c, source);
  }
  const raw = textOf(node, source);
  const match = raw.match(/^"(.*)"$/s);
  return match ? match[1] : null;
}

/** 1-based line number — matches how the DB stores it. */
export function lineOf(node: Node): number {
  return node.startPosition.row + 1;
}

export function walkTree(tree: Tree, visit: (node: Node) => void): void {
  const walk = (node: Node): void => {
    visit(node);
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(tree.rootNode);
}

export interface ParsedAnnotation {
  node: Node;
  /** e.g. "RestController", "GetMapping", "Path" — the simple name. */
  name: string;
  /** Annotations with no parens: `@GET`, `@PostMapping`. */
  isMarker: boolean;
  /** First positional argument as a string literal, if present. */
  firstStringArg: string | null;
  /** Named values — `@RequestMapping(value = "/p", method = RequestMethod.GET)`. */
  namedValues: Map<string, Node>;
}

export function parseAnnotation(node: Node, source: string): ParsedAnnotation | null {
  if (node.type !== 'annotation' && node.type !== 'marker_annotation') return null;
  const nameNode = node.childForFieldName('name') ?? node.namedChild(0);
  if (!nameNode) return null;
  const name = textOf(nameNode, source);

  if (node.type === 'marker_annotation') {
    return { node, name, isMarker: true, firstStringArg: null, namedValues: new Map() };
  }

  const args = node.childForFieldName('arguments') ?? null;
  let firstStringArg: string | null = null;
  const namedValues = new Map<string, Node>();

  if (args) {
    for (let i = 0; i < args.namedChildCount; i++) {
      const arg = args.namedChild(i)!;
      if (arg.type === 'string_literal' && firstStringArg === null) {
        firstStringArg = javaStringLiteral(arg, source);
      } else if (arg.type === 'element_value_pair') {
        const key = arg.childForFieldName('key') ?? arg.namedChild(0);
        const value = arg.childForFieldName('value') ?? arg.namedChild(1);
        if (key && value) {
          namedValues.set(textOf(key, source), value);
          if ((textOf(key, source) === 'value' || textOf(key, source) === 'path') &&
              value.type === 'string_literal' && firstStringArg === null) {
            firstStringArg = javaStringLiteral(value, source);
          }
        }
      }
    }
  }

  return { node, name, isMarker: false, firstStringArg, namedValues };
}

/** Extract annotations from a class_declaration or method_declaration's modifiers. */
export function annotationsOn(declNode: Node, source: string): ParsedAnnotation[] {
  const modifiers = declNode.namedChild(0);
  if (!modifiers || modifiers.type !== 'modifiers') return [];
  const out: ParsedAnnotation[] = [];
  for (let i = 0; i < modifiers.namedChildCount; i++) {
    const c = modifiers.namedChild(i)!;
    if (c.type === 'annotation' || c.type === 'marker_annotation') {
      const parsed = parseAnnotation(c, source);
      if (parsed) out.push(parsed);
    }
  }
  return out;
}

/** Java auth-flavored package roots. */
export const JAVA_AUTH_PACKAGES: ReadonlyArray<{ prefix: string; mechanism: string }> = [
  { prefix: 'org.springframework.security', mechanism: 'spring_security' },
  { prefix: 'javax.annotation.security', mechanism: 'jee_security' },
  { prefix: 'jakarta.annotation.security', mechanism: 'jee_security' },
  { prefix: 'io.jsonwebtoken', mechanism: 'bearer_jwt' },
  { prefix: 'com.auth0.jwt', mechanism: 'bearer_jwt' },
  { prefix: 'com.nimbusds.jwt', mechanism: 'bearer_jwt' },
];

export function detectJavaAuthMechanism(imports: readonly ImportBinding[]): string | null {
  for (const imp of imports) {
    const hit = JAVA_AUTH_PACKAGES.find((p) => imp.source === p.prefix || imp.source.startsWith(`${p.prefix}.`));
    if (hit) return hit.mechanism;
  }
  return null;
}

export function classifyFromAuth(auth: string | null): EntryPointClassification {
  return auth ? 'AUTH_INTERNAL' : 'PUBLIC_UNAUTH';
}

export function joinRoute(prefix: string | null, sub: string | null): string | null {
  if (!prefix && !sub) return null;
  const p = prefix ? (prefix.startsWith('/') ? prefix : `/${prefix}`).replace(/\/$/, '') : '';
  const s = sub ? (sub.startsWith('/') ? sub : `/${sub}`) : '';
  const joined = `${p}${s}` || '/';
  return joined.replace(/\/+/g, '/');
}

/** Map a Spring verb-annotation name to HTTP method, or null if not a verb. */
export const SPRING_VERB_ANNOTATIONS: Record<string, HttpMethod> = {
  GetMapping: 'GET',
  PostMapping: 'POST',
  PutMapping: 'PUT',
  PatchMapping: 'PATCH',
  DeleteMapping: 'DELETE',
  HeadMapping: 'HEAD',
  OptionsMapping: 'OPTIONS',
};

export const JAXRS_VERB_ANNOTATIONS: Record<string, HttpMethod> = {
  GET: 'GET', POST: 'POST', PUT: 'PUT', PATCH: 'PATCH',
  DELETE: 'DELETE', HEAD: 'HEAD', OPTIONS: 'OPTIONS',
};

export const MICRONAUT_VERB_ANNOTATIONS: Record<string, HttpMethod> = {
  Get: 'GET', Post: 'POST', Put: 'PUT', Patch: 'PATCH',
  Delete: 'DELETE', Head: 'HEAD', Options: 'OPTIONS',
};

// ---------------------------------------------------------------------------
// Java annotation → route-auth evidence (entry-point auth classification, T7a).
// Annotation semantics are EXACT (unlike JS middleware names), so this helper
// decides auth-vs-public directly and hands classifyRoute pre-vetted tokens.
// ---------------------------------------------------------------------------

export interface JavaAuthEvidence {
  /** Pre-vetted auth tokens (exact annotation semantics — bypass name matching). */
  vettedAuthTokens: string[];
  /** Explicit-public annotations (`@PermitAll`, public `@PreAuthorize` SpEL, …). */
  publicOverrides: string[];
  /** True when the list carried ANY auth-relevant security annotation (drives JEE method-replaces-class). */
  hasSecurityAnnotation: boolean;
}

/** Sem 2 — SpEL expressions that make a `@PreAuthorize` route public. */
const PUBLIC_SPEL_RE = /\b(permitAll|isAnonymous|true)\b/i;
/** Micronaut `@Secured` public rules (string or SecurityRule constant). */
const MICRONAUT_ANONYMOUS_RE = /is_?anonymous/i;

/**
 * Reduce a declaration's annotations to route-auth evidence (Sem 1/2 for the
 * Java annotation families — Spring Security, JEE/Jakarta security, Quarkus,
 * Micronaut). Unresolvable expressions (non-literal SpEL constant refs) are NOT
 * evidence (fail-safe → public).
 */
export function javaAuthEvidenceFromAnnotations(
  anns: readonly ParsedAnnotation[],
  source: string,
): JavaAuthEvidence {
  const vettedAuthTokens: string[] = [];
  const publicOverrides: string[] = [];
  let hasSecurityAnnotation = false;

  for (const ann of anns) {
    switch (ann.name) {
      case 'PermitAll':
        hasSecurityAnnotation = true;
        publicOverrides.push('PermitAll');
        break;
      case 'AllowAnonymous':
        hasSecurityAnnotation = true;
        publicOverrides.push('AllowAnonymous');
        break;
      case 'DenyAll':
        // Not publicly reachable at all — AUTH_INTERNAL is the closest honest
        // class (definitely not public attack surface).
        hasSecurityAnnotation = true;
        vettedAuthTokens.push('DenyAll');
        break;
      case 'RolesAllowed':
        hasSecurityAnnotation = true;
        vettedAuthTokens.push(`RolesAllowed(${annotationArgsText(ann, source)})`);
        break;
      case 'Authenticated': // io.quarkus.security.Authenticated
        hasSecurityAnnotation = true;
        vettedAuthTokens.push('Authenticated');
        break;
      case 'Secured': {
        // Spring @Secured("ROLE_X") / Micronaut @Secured(SecurityRule.IS_AUTHENTICATED
        // | "isAnonymous()"). An anonymous rule is an explicit-public marker.
        hasSecurityAnnotation = true;
        const argsText = annotationArgsText(ann, source);
        if (MICRONAUT_ANONYMOUS_RE.test(argsText)) publicOverrides.push(`Secured(${argsText})`);
        else vettedAuthTokens.push(`Secured(${argsText})`);
        break;
      }
      case 'PreAuthorize':
      case 'PostAuthorize': {
        hasSecurityAnnotation = true;
        const spel = ann.firstStringArg;
        if (spel === null) {
          // Constant-ref / unresolvable SpEL — could be permitAll behind a
          // constant, so it is NOT auth evidence (Sem 1 fail-safe).
          break;
        }
        if (PUBLIC_SPEL_RE.test(spel)) publicOverrides.push(`${ann.name}(${spel})`);
        else vettedAuthTokens.push(`${ann.name}(${spel})`);
        break;
      }
      default:
        break;
    }
  }
  return { vettedAuthTokens, publicOverrides, hasSecurityAnnotation };
}

/** Raw text of an annotation's argument list (for display tokens). */
function annotationArgsText(ann: ParsedAnnotation, source: string): string {
  const args = ann.node.childForFieldName('arguments');
  if (!args) return '';
  return textOf(args, source).replace(/^\(|\)$/g, '').trim();
}

/**
 * JEE/Spring merge rule (Sem 2): method-level security annotations REPLACE
 * class-level ones; a method with none inherits the class's. Method-level
 * public thereby beats class-level auth.
 */
export function mergeJavaAuthEvidence(
  classEv: JavaAuthEvidence,
  methodEv: JavaAuthEvidence,
): { vettedAuthTokens: string[]; publicOverrides: string[] } {
  const eff = methodEv.hasSecurityAnnotation ? methodEv : classEv;
  return { vettedAuthTokens: eff.vettedAuthTokens, publicOverrides: eff.publicOverrides };
}

// ---------------------------------------------------------------------------
// Centralized Spring Security coverage (Sem 3 zero-carve-out rule).
// ---------------------------------------------------------------------------

/** Memo per workspaceRoot — one bounded scan per extraction. */
const securityChainMemo = new Map<string, boolean>();

/** Exposed for tests. */
export function resetSecurityChainMemo(): void {
  securityChainMemo.clear();
}

const SKIP_DIRS = new Set(['.git', 'node_modules', 'target', 'build', 'out', 'dist', 'vendor', '.gradle', '.idea']);
const MAX_SCAN_ENTRIES = 20_000;
const MAX_CANDIDATE_BYTES = 512 * 1024;

/**
 * Does the workspace declare a Spring Security filter chain that positively
 * covers EVERY request with zero carve-outs (Sem 3)? True only when a
 * security-config-shaped file contains `SecurityFilterChain` (or the legacy
 * `WebSecurityConfigurerAdapter`) AND `anyRequest().authenticated()`-style
 * full coverage AND no `permitAll(` / `anonymous(` / `web.ignoring` anywhere in
 * any chain-bearing file. Any carve-out in any chain file kills coverage
 * entirely — we cannot resolve which routes the carve-outs exempt.
 *
 * Pure text scan over `*security*.java` basenames (bounded walk, memoized per
 * workspace). Best-effort: any error → false (no coverage claimed).
 */
export function workspaceHasFullSecurityChain(workspaceRoot: string | undefined): boolean {
  if (!workspaceRoot) return false;
  const memo = securityChainMemo.get(workspaceRoot);
  if (memo !== undefined) return memo;

  let sawFullCoverage = false;
  let sawCarveOut = false;
  let visited = 0;
  try {
    const stack = [workspaceRoot];
    while (stack.length > 0 && visited < MAX_SCAN_ENTRIES && !sawCarveOut) {
      const dir = stack.pop()!;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const e of entries) {
        if (++visited > MAX_SCAN_ENTRIES) break;
        if (e.isDirectory()) {
          if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) stack.push(path.join(dir, e.name));
          continue;
        }
        if (!e.isFile()) continue;
        if (!/security/i.test(e.name) || !e.name.endsWith('.java')) continue;
        const abs = path.join(dir, e.name);
        let text: string;
        try {
          if (fs.statSync(abs).size > MAX_CANDIDATE_BYTES) continue;
          text = fs.readFileSync(abs, 'utf8');
        } catch {
          continue;
        }
        if (!/SecurityFilterChain|WebSecurityConfigurerAdapter/.test(text)) continue;
        if (/permitAll\s*\(|\banonymous\s*\(|web\s*\.\s*ignoring|webIgnoring/i.test(text)) {
          sawCarveOut = true;
          break;
        }
        if (/anyRequest\s*\(\s*\)\s*\.\s*(authenticated|fullyAuthenticated|hasRole|hasAuthority|hasAnyRole|hasAnyAuthority)\s*\(/.test(text)) {
          sawFullCoverage = true;
        }
      }
    }
  } catch {
    /* best-effort — claim nothing */
  }
  const result = sawFullCoverage && !sawCarveOut;
  securityChainMemo.set(workspaceRoot, result);
  return result;
}
