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
