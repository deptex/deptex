import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';
import { collectPrecedingAttributes } from './actix';

function textOf(n: Node | null, src: string): string {
  return n ? src.slice(n.startIndex, n.endIndex) : '';
}

// Rocket's attribute macros mirror Actix but live under the `rocket` crate:
//   #[get("/users")]
//   #[post("/users", data = "<user>")]
const VERB_MACROS: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
};

export const rocketDetector: FrameworkDetector = {
  name: 'rocket',
  displayName: 'Rocket',
  language: 'rust',
  triggerImports: ['rocket'],
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
            framework: 'rocket',
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
