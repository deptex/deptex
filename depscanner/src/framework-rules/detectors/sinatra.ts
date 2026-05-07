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

// Sinatra: top-level DSL calls with a string literal and do-block:
//   get '/users' do ... end
//   post '/login' do ... end
//   delete '/items/:id' do ... end
// Also handles the block-less form `get '/users', &handler`.

export const sinatraDetector: FrameworkDetector = {
  name: 'sinatra',
  displayName: 'Sinatra',
  language: 'ruby',
  triggerImports: ['sinatra'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectRubyAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'call') return;
      // Receiver must be absent — Sinatra's DSL uses bare top-level calls.
      const receiver = node.childForFieldName('receiver');
      if (receiver) return;
      const method = node.childForFieldName('method');
      if (method?.type !== 'identifier') return;
      const methodName = textOf(method, source).toLowerCase();
      const httpMethod = RUBY_HTTP_METHODS[methodName];
      if (!httpMethod) return;
      const args = node.childForFieldName('arguments');
      const first = args?.namedChild(0);
      const routePattern = rubyStringLiteral(first ?? null, source);
      if (!routePattern) return;

      // Avoid matching Rails `get '/users', to: 'users#index'` inside the
      // `routes.draw do ... end` block — the outer draw call is the tell.
      if (isInsideRoutesDraw(node, source)) return;

      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(node),
        framework: 'sinatra',
        handlerName: null,
        httpMethod,
        routePattern,
        entryPointType: 'http_route',
        classification,
        authenticated: !!authMechanism,
        authMechanism,
        middlewareChain: null,
        metadata: { style: 'dsl' },
      });
    });
    return entryPoints;
  },
};

function isInsideRoutesDraw(node: Node, source: string): boolean {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (cur.type === 'do_block' || cur.type === 'block') {
      const parent = cur.parent;
      if (parent?.type === 'call') {
        const method = parent.childForFieldName('method');
        if (method && textOf(method, source) === 'draw') return true;
      }
    }
  }
  return false;
}
