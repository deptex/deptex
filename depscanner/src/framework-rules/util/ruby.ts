import type { Node, Tree } from 'web-tree-sitter';
import type { ImportBinding } from '../../tree-sitter-extractor/languages/types';
import type { EntryPointClassification, HttpMethod } from '../types';

export function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

export function rubyStringLiteral(node: Node | null, source: string): string | null {
  if (!node || node.type !== 'string') return null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'string_content') return textOf(c, source);
  }
  const raw = textOf(node, source);
  const m = raw.match(/^['"](.*)['"]$/s);
  return m ? m[1] : null;
}

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

export const RUBY_HTTP_METHODS: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
};

export const RUBY_AUTH_GEMS: ReadonlyArray<{ gem: string; mechanism: string }> = [
  { gem: 'devise', mechanism: 'devise' },
  { gem: 'pundit', mechanism: 'pundit' },
  { gem: 'cancancan', mechanism: 'cancan' },
  { gem: 'warden', mechanism: 'warden' },
  { gem: 'jwt', mechanism: 'bearer_jwt' },
];

export function detectRubyAuthMechanism(imports: readonly ImportBinding[]): string | null {
  for (const imp of imports) {
    const head = imp.source.split('/')[0];
    const hit = RUBY_AUTH_GEMS.find((a) => a.gem === head);
    if (hit) return hit.mechanism;
  }
  return null;
}

export function classifyFromAuth(auth: string | null): EntryPointClassification {
  return auth ? 'AUTH_INTERNAL' : 'PUBLIC_UNAUTH';
}

// ---------------------------------------------------------------------------
// Rails controller auth analysis (entry-point auth classification, T9).
//
// The auth evidence (before_action) lives in the controller, and so do the
// taint sources (`params[:x]` in an action). We classify each action from the
// controller's before_action/skip_before_action rules and bank per-action
// facts; postProcess re-homes them (the routes file is not needed — this covers
// resources-routed controllers too).
// ---------------------------------------------------------------------------

import type { HandlerSpan } from '../types';
import { matchesAuthName } from './auth-evidence';

/**
 * Callbacks known to HALT the request when auth fails (Sem 4). A callback is
 * auth evidence iff it matches an auth-name pattern AND is halting: bang-suffix
 * convention (`authenticate_user!`) OR a member of this allowlist. Bare
 * `authenticate` (non-halting filter) is NOT evidence.
 */
const RUBY_HALTING_ALLOWLIST = new Set([
  'require_login', 'require_user', 'require_admin', 'authorize', 'authorize!',
  'authenticate_request', 'login_required', 'ensure_logged_in',
]);

/**
 * App-idiom halting auth gates the shared auth-name patterns miss: the
 * `require_logged_in[_role]` family (lobsters + many real Rails apps) and
 * `require_authentication` / `ensure_authenticated`. These redirect
 * unauthenticated requests, so they halt. Ruby-local by design — kept out of the
 * shared `matchesAuthName` so it can't demote a same-named token in another
 * language (`login`-substring false matches are a cardinal-sin risk elsewhere).
 */
const RUBY_HALTING_AUTH_NAME = /^(require_logged_in(_[a-z]+)?|require_authentication|ensure_authenticated)$/;

function isHaltingAuthCallback(sym: string): boolean {
  const bare = sym.replace(/^:/, '');
  if (RUBY_HALTING_AUTH_NAME.test(bare)) return true;
  if (!matchesAuthName(bare)) return false;
  return bare.endsWith('!') || RUBY_HALTING_ALLOWLIST.has(bare);
}

interface BeforeActionRule {
  kind: 'before' | 'skip';
  callback: string;
  isAuth: boolean;
  /** Actions named in `only:` (resolved), else null. */
  only: string[] | null;
  /** True when ANY non-`only:` kwarg is present (except/if/unless/…) → conditional. */
  conditional: boolean;
}

/** Symbol / string arg text of a call's first positional argument. */
function firstSymbolArg(callNode: Node, source: string): string | null {
  const args = callNode.childForFieldName('arguments');
  if (!args) return null;
  for (let i = 0; i < args.namedChildCount; i++) {
    const a = args.namedChild(i)!;
    if (a.type === 'simple_symbol') return textOf(a, source).replace(/^:/, '');
    if (a.type === 'string') return rubyStringLiteral(a, source);
    if (a.type === 'pair') break; // kwargs start — no positional symbol
  }
  return null;
}

/** Parse a before_action/skip_before_action call's kwargs. */
function parseCallbackKwargs(callNode: Node, source: string): { only: string[] | null; conditional: boolean } {
  const args = callNode.childForFieldName('arguments');
  let only: string[] | null = null;
  let conditional = false;
  if (!args) return { only, conditional };
  for (let i = 0; i < args.namedChildCount; i++) {
    const a = args.namedChild(i)!;
    if (a.type !== 'pair') continue;
    const key = a.childForFieldName('key');
    const keyName = key ? textOf(key, source).replace(/:$/, '').replace(/^:/, '') : '';
    const value = a.childForFieldName('value');
    if (keyName === 'only') {
      only = value ? symbolListOf(value, source) : [];
    } else {
      // except:/if:/unless:/any other kwarg → conditional carve-out (Sem 3).
      conditional = true;
    }
  }
  return { only, conditional };
}

/** Symbols in `[:a, :b]` or a bare `:a`. */
function symbolListOf(node: Node, source: string): string[] {
  const out: string[] = [];
  const collect = (n: Node): void => {
    if (n.type === 'simple_symbol') { out.push(textOf(n, source).replace(/^:/, '')); return; }
    for (let i = 0; i < n.namedChildCount; i++) collect(n.namedChild(i)!);
  };
  collect(node);
  return out;
}

/** Does a controller-level rule cover `action`? */
function ruleCoversAction(rule: BeforeActionRule, action: string): boolean {
  if (rule.conditional) return false; // any non-only kwarg → not covering (Sem 3)
  if (rule.only === null) return true; // no only: → covers all
  return rule.only.includes(action);
}

export interface RailsActionFact {
  name: string;
  handlerSpan: HandlerSpan;
  classification: EntryPointClassification;
  demotionEligible: boolean;
  middlewareChain: string[] | null;
}

/**
 * Analyze one Rails controller class node → per-action auth classification.
 * An action is AUTH_INTERNAL iff some before_action covers it with a halting
 * auth callback AND no skip_before_action removes that coverage.
 */
export function analyzeRailsController(classNode: Node, source: string): RailsActionFact[] {
  const body = classNode.childForFieldName('body');
  if (!body) return [];

  const rules: BeforeActionRule[] = [];
  const actions: Array<{ name: string; span: HandlerSpan }> = [];

  const scan = (n: Node): void => {
    if (n.type === 'call' && !n.childForFieldName('receiver')) {
      const method = n.childForFieldName('method');
      const methodName = method ? textOf(method, source) : '';
      if (methodName === 'before_action' || methodName === 'append_before_action' || methodName === 'prepend_before_action'
        || methodName === 'skip_before_action') {
        const callback = firstSymbolArg(n, source);
        if (callback) {
          const { only, conditional } = parseCallbackKwargs(n, source);
          rules.push({
            kind: methodName === 'skip_before_action' ? 'skip' : 'before',
            callback,
            isAuth: isHaltingAuthCallback(callback),
            only,
            conditional,
          });
        }
      }
    }
    // `def action` — only direct methods of the class body (not nested).
    for (let i = 0; i < n.namedChildCount; i++) {
      const c = n.namedChild(i)!;
      if (c.type === 'method') {
        const nm = c.childForFieldName('name');
        if (nm) actions.push({ name: textOf(nm, source), span: { startLine: c.startPosition.row + 1, endLine: c.endPosition.row + 1 } });
      } else {
        scan(c);
      }
    }
  };
  // Walk the class body: collect rules everywhere, but actions only at the
  // top level of the body (methods nested in blocks are not Rails actions).
  for (let i = 0; i < body.namedChildCount; i++) {
    const c = body.namedChild(i)!;
    if (c.type === 'method') {
      const nm = c.childForFieldName('name');
      if (nm) actions.push({ name: textOf(nm, source), span: { startLine: c.startPosition.row + 1, endLine: c.endPosition.row + 1 } });
    } else if (c.type === 'call' && !c.childForFieldName('receiver')) {
      const method = c.childForFieldName('method');
      const methodName = method ? textOf(method, source) : '';
      if (['before_action', 'append_before_action', 'prepend_before_action', 'skip_before_action'].includes(methodName)) {
        const callback = firstSymbolArg(c, source);
        if (callback) {
          const { only, conditional } = parseCallbackKwargs(c, source);
          rules.push({
            kind: methodName === 'skip_before_action' ? 'skip' : 'before',
            callback, isAuth: isHaltingAuthCallback(callback), only, conditional,
          });
        }
      }
    }
  }

  const out: RailsActionFact[] = [];
  for (const action of actions) {
    let authed = false;
    let mechanism: string | null = null;
    for (const r of rules) {
      if (!r.isAuth) continue;
      if (r.kind === 'before' && ruleCoversAction(r, action.name)) { authed = true; mechanism = r.callback; }
      // A skip removes coverage only when it is UNCONDITIONAL-only-resolved for
      // this action (fail-safe: a conditional skip doesn't reliably remove, but
      // reinstating auth on an ambiguous skip could wrongly demote — so a
      // covering skip of the SAME callback, only: or unconditional, clears it).
      if (r.kind === 'skip' && ruleCoversAction(r, action.name)) authed = false;
    }
    out.push({
      name: action.name,
      handlerSpan: action.span,
      classification: authed ? 'AUTH_INTERNAL' : 'PUBLIC_UNAUTH',
      // Declaration-bound: the before_action travels with the controller class.
      demotionEligible: true,
      middlewareChain: mechanism ? [mechanism] : null,
    });
  }
  return out;
}

/** True when a class node is (or looks like) a Rails controller. */
export function isRailsController(classNode: Node, source: string): boolean {
  const nameNode = classNode.childForFieldName('name');
  const name = nameNode ? textOf(nameNode, source) : '';
  if (/Controller$/.test(name)) return true;
  const superclass = classNode.childForFieldName('superclass');
  if (superclass) {
    const superText = textOf(superclass, source);
    if (/Controller/.test(superText)) return true;
  }
  return false;
}
