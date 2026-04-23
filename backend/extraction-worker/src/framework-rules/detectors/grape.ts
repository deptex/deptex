import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  RUBY_HTTP_METHODS,
  classifyFromAuth,
  detectRubyAuthMechanism,
  lineOf,
  rubyStringLiteral,
  textOf,
  walkTree,
} from '../util/ruby';

// Grape DSL lives inside a class < Grape::API:
//   class MyAPI < Grape::API
//     prefix '/api'
//     resource :users do
//       get do ... end
//       post '/create' do ... end
//     end
//   end
// We emit one entry per verb call inside a Grape::API-subclassing class.

export const grapeDetector: FrameworkDetector = {
  name: 'grape',
  displayName: 'Grape',
  language: 'ruby',
  triggerImports: ['grape'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectRubyAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'class') return;
      const superclass = node.childForFieldName('superclass');
      if (!superclass) return;
      const superText = textOf(superclass, source);
      if (!/Grape::API/.test(superText)) return;

      // Inside the class, walk every descendant `call` node with a verb
      // method and no receiver.
      const body = node.childForFieldName('body');
      if (!body) return;
      const stack: Node[] = [body];
      while (stack.length > 0) {
        const cur = stack.pop()!;
        if (cur.type === 'call') {
          const receiver = cur.childForFieldName('receiver');
          if (!receiver) {
            const method = cur.childForFieldName('method');
            if (method?.type === 'identifier') {
              const methodName = textOf(method, source).toLowerCase();
              const httpMethod = RUBY_HTTP_METHODS[methodName];
              if (httpMethod) {
                const args = cur.childForFieldName('arguments');
                const first = args?.namedChild(0);
                const routePattern = first ? (rubyStringLiteral(first, source) ?? '/') : '/';
                entryPoints.push({
                  filePath: file.filePath,
                  lineNumber: lineOf(cur),
                  framework: 'grape',
                  handlerName: null,
                  httpMethod,
                  routePattern,
                  entryPointType: 'http_route',
                  classification,
                  authenticated: !!authMechanism,
                  authMechanism,
                  middlewareChain: null,
                  metadata: null,
                });
              }
            }
          }
        }
        for (let i = 0; i < cur.namedChildCount; i++) stack.push(cur.namedChild(i)!);
      }
    });
    return entryPoints;
  },
};
