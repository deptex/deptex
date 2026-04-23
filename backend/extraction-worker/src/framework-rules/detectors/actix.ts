import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';

function textOf(n: Node | null, src: string): string {
  return n ? src.slice(n.startIndex, n.endIndex) : '';
}

function rustStringLiteral(node: Node | null, source: string): string | null {
  if (!node || node.type !== 'string_literal') return null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'string_content') return textOf(c, source);
  }
  const raw = textOf(node, source);
  const m = raw.match(/^"(.*)"$/s);
  return m ? m[1] : null;
}

// Actix-web attribute macros on async fn:
//   #[get("/users")]
//   async fn list_users() -> impl Responder { ... }
//   #[post("/users")]
//   async fn create_user() -> impl Responder { ... }

const VERB_MACROS: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
};

export const actixDetector: FrameworkDetector = {
  name: 'actix',
  displayName: 'Actix',
  language: 'rust',
  triggerImports: ['actix-web', 'actix_web'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const entryPoints: EntryPoint[] = [];

    const walk = (node: Node): void => {
      if (node.type === 'function_item') {
        const attrs = collectPrecedingAttributes(node, source);
        for (const attr of attrs) {
          const verb = VERB_MACROS[attr.name];
          if (!verb) continue;
          if (attr.firstStringArg === null) continue;
          const name = node.childForFieldName('name');
          entryPoints.push({
            filePath: file.filePath,
            lineNumber: node.startPosition.row + 1,
            framework: 'actix',
            handlerName: name ? textOf(name, source) : null,
            httpMethod: verb,
            routePattern: attr.firstStringArg,
            entryPointType: 'http_route',
            classification: 'PUBLIC_UNAUTH',
            authenticated: null,
            authMechanism: null,
            middlewareChain: null,
            metadata: { macro: attr.name },
          });
        }
      }
      for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
    };
    walk(tree.rootNode);
    return entryPoints;
  },
};

export interface RustAttribute {
  name: string;
  firstStringArg: string | null;
  node: Node;
}

export function collectPrecedingAttributes(fnNode: Node, source: string): RustAttribute[] {
  const parent = fnNode.parent;
  if (!parent) return [];
  const out: RustAttribute[] = [];
  const fnStart = fnNode.startIndex;
  for (let i = 0; i < parent.namedChildCount; i++) {
    const c = parent.namedChild(i)!;
    // Compare by startIndex — web-tree-sitter may return a new Node wrapper
    // each call to namedChild, so `===` identity isn't reliable.
    if (c.startIndex === fnStart && c.endIndex === fnNode.endIndex) break;
    if (c.type === 'attribute_item') {
      const attr = c.namedChild(0);
      if (attr?.type !== 'attribute') continue;
      // attribute > path (identifier) + arguments? (delim_token_tree)
      const pathNode = attr.childForFieldName('path') ?? attr.namedChild(0);
      if (!pathNode) continue;
      const name = textOf(pathNode, source);
      const args = attr.childForFieldName('arguments');
      let firstStringArg: string | null = null;
      if (args) {
        // Walk inside the token tree for the first string_literal.
        const findStr = (n: Node): string | null => {
          if (n.type === 'string_literal') return rustStringLiteral(n, source);
          for (let j = 0; j < n.namedChildCount; j++) {
            const r = findStr(n.namedChild(j)!);
            if (r !== null) return r;
          }
          return null;
        };
        firstStringArg = findStr(args);
      }
      out.push({ name, firstStringArg, node: c });
    } else if (c.type === 'function_item') {
      out.length = 0; // reset between functions
    }
  }
  return out;
}
