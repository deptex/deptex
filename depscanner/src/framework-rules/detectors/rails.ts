import type { Node } from 'web-tree-sitter';
import type { CtxOnlyRouteRecord, DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import type { ExtractedFile } from '../../tree-sitter-extractor/languages/types';
import {
  RUBY_HTTP_METHODS,
  analyzeRailsController,
  classifyFromAuth,
  detectRubyAuthMechanism,
  isRailsController,
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

    // Bank per-action auth facts from any controller class in this file (the
    // cross-file leg, T9). The taint sources fire inside controller actions, so
    // classifying them here + re-homing via postProcess demotes those flows —
    // no routes.rb resolution needed (covers resources-routed controllers too).
    bankControllerAuthFacts(tree.rootNode, source, file);

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
  /**
   * Cross-file pass (T9): flatten every file's banked Rails controller
   * auth facts into ctx-only route records keyed on the controller file. The
   * records are added to `ctx.entryPointAuth` only — never persisted — so a
   * flow whose source falls inside an authed action span demotes.
   */
  postProcess(files: readonly ExtractedFile[]): CtxOnlyRouteRecord[] {
    const out: CtxOnlyRouteRecord[] = [];
    for (const file of files) {
      const facts = file.authFacts;
      if (!facts || facts.framework !== 'rails') continue;
      for (const action of facts.actions) {
        // Only re-home the actions that carry a demotion (AUTH_INTERNAL/OFFLINE);
        // public actions add no signal and public is the default fallback.
        if (action.classification === 'PUBLIC_UNAUTH' || action.classification === 'UNKNOWN') continue;
        out.push({
          filePath: facts.filePath,
          classification: action.classification,
          handlerSpan: action.handlerSpan,
          demotionEligible: action.demotionEligible,
          routePattern: action.routePattern,
          middlewareChain: action.middlewareChain,
          authMechanism: action.authMechanism,
        });
      }
    }
    return out;
  },
};

/** Bank per-action auth facts from every controller class in the file. */
function bankControllerAuthFacts(root: Node, source: string, file: ExtractedFile): void {
  const actions: import('../types').FileAuthFacts['actions'] = [];
  const walk = (node: Node): void => {
    if (node.type === 'class' && isRailsController(node, source)) {
      for (const a of analyzeRailsController(node, source)) {
        actions.push({
          name: a.name,
          handlerSpan: a.handlerSpan,
          classification: a.classification,
          demotionEligible: a.demotionEligible,
          routePattern: null,
          middlewareChain: a.middlewareChain,
          authMechanism: a.middlewareChain?.[0] ?? null,
        });
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(root);
  if (actions.length > 0) {
    file.authFacts = { framework: 'rails', filePath: file.filePath, actions };
  }
}

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
