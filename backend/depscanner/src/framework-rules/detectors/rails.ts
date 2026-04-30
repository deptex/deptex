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

// Rails config/routes.rb:
//   Rails.application.routes.draw do
//     get '/users', to: 'users#index'
//     post '/users', to: 'users#create'
//     resources :items
//     namespace :api do ... end
//   end
// We only capture the verb + path entries; `resources` expands to the full
// RESTful set but we don't enumerate them here (left for a future pass).

export const railsDetector: FrameworkDetector = {
  name: 'rails',
  displayName: 'Rails',
  language: 'ruby',
  // Empty trigger: Rails routes.rb doesn't require an explicit `require` at
  // the top — Rails auto-loads. Scan every file; the draw block IS the gate.
  triggerImports: [],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectRubyAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    const drawBlocks = findRoutesDrawBlocks(tree.rootNode, source);
    if (drawBlocks.length === 0) return [];

    for (const block of drawBlocks) {
      walkBlock(block, source, (node) => {
        if (node.type !== 'call') return;
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

        const handlerName = extractToKwarg(args ?? null, source);
        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(node),
          framework: 'rails',
          handlerName,
          httpMethod,
          routePattern,
          entryPointType: 'http_route',
          classification,
          authenticated: !!authMechanism,
          authMechanism,
          middlewareChain: null,
          metadata: null,
        });
      });
    }
    return entryPoints;
  },
};

function findRoutesDrawBlocks(root: Node, source: string): Node[] {
  const out: Node[] = [];
  const walk = (node: Node): void => {
    if (node.type === 'call') {
      const method = node.childForFieldName('method');
      if (method && textOf(method, source) === 'draw') {
        const block = node.childForFieldName('block');
        if (block) out.push(block);
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(root);
  return out;
}

function walkBlock(block: Node, _source: string, visit: (n: Node) => void): void {
  const walk = (node: Node): void => {
    visit(node);
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(block);
}

function extractToKwarg(args: Node | null, source: string): string | null {
  if (!args) return null;
  for (let i = 0; i < args.namedChildCount; i++) {
    const arg = args.namedChild(i)!;
    if (arg.type === 'pair') {
      const key = arg.childForFieldName('key');
      const value = arg.childForFieldName('value');
      if (key && value && textOf(key, source) === 'to:') {
        if (value.type === 'string') return rubyStringLiteral(value, source);
      }
    }
  }
  return null;
}
