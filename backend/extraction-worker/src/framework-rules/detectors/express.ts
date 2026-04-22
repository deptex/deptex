import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';

const HTTP_METHOD_NAMES: Record<string, HttpMethod> = {
  get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH',
  delete: 'DELETE', head: 'HEAD', options: 'OPTIONS',
};

// Additional route-registering methods that don't directly name an HTTP verb
// but still introduce a handler (all verbs + middleware mount).
const ROUTE_METHOD_NAMES = new Set([
  ...Object.keys(HTTP_METHOD_NAMES),
  'all',     // matches every method
  'use',     // middleware — registers a handler but not a single-verb route
]);

// Auth middleware packages — presence in the file elevates classification
// from PUBLIC_UNAUTH to AUTH_INTERNAL. The mechanism string is stored so
// downstream UI can tell users what the auth check is.
const AUTH_MIDDLEWARE: Array<{ pkg: string; mechanism: string }> = [
  { pkg: 'passport', mechanism: 'passport' },
  { pkg: 'express-jwt', mechanism: 'bearer_jwt' },
  { pkg: 'jsonwebtoken', mechanism: 'bearer_jwt' },
  { pkg: 'express-session', mechanism: 'session_cookie' },
  { pkg: 'cookie-session', mechanism: 'session_cookie' },
  { pkg: 'helmet', mechanism: 'helmet' },
];

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

function stringLiteralValue(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type !== 'string') return null;
  const frag = node.namedChild(0);
  if (frag && frag.type === 'string_fragment') return textOf(frag, source);
  const raw = textOf(node, source);
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    return raw.slice(1, -1);
  }
  return null;
}

function handlerDescriptor(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type === 'identifier') return textOf(node, source);
  if (node.type === 'function_expression' || node.type === 'function_declaration') {
    const name = node.childForFieldName('name');
    return name ? textOf(name, source) : '(anonymous)';
  }
  if (node.type === 'arrow_function') return '(anonymous)';
  if (node.type === 'member_expression') return textOf(node, source);
  return null;
}

/**
 * Walk the tree collecting local-variable bindings that came from calling
 * the imported `express` function or `express.Router()`. These are the
 * identifiers we treat as route registrars.
 */
function collectExpressInstances(
  root: Node,
  source: string,
  expressLocalName: string
): Set<string> {
  const instances = new Set<string>();

  const valueLooksLikeExpressCall = (value: Node | null): boolean => {
    if (!value) return false;
    if (value.type !== 'call_expression') return false;
    const fn = value.childForFieldName('function');
    if (!fn) return false;
    if (fn.type === 'identifier') {
      return textOf(fn, source) === expressLocalName;
    }
    if (fn.type === 'member_expression') {
      const object = fn.childForFieldName('object');
      const property = fn.childForFieldName('property');
      if (object?.type === 'identifier' && property) {
        return textOf(object, source) === expressLocalName && textOf(property, source) === 'Router';
      }
    }
    return false;
  };

  const walk = (node: Node): void => {
    if (node.type === 'variable_declarator') {
      const name = node.childForFieldName('name');
      const value = node.childForFieldName('value');
      if (name?.type === 'identifier' && valueLooksLikeExpressCall(value)) {
        instances.add(textOf(name, source));
      }
    } else if (node.type === 'assignment_expression') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      if (left?.type === 'identifier' && valueLooksLikeExpressCall(right)) {
        instances.add(textOf(left, source));
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };

  walk(root);
  return instances;
}

/** Extract the middleware chain args that appear BEFORE the handler argument. */
function collectMiddlewareChain(args: Node | null, source: string): string[] {
  if (!args) return [];
  const chain: string[] = [];
  const argNodes: Node[] = [];
  for (let i = 0; i < args.namedChildCount; i++) argNodes.push(args.namedChild(i)!);
  // Drop the trailing function/arrow — that's the handler, not middleware.
  const mwNodes = argNodes.slice(0, -1);
  // And drop the leading string literal (route pattern).
  const startIdx = mwNodes.length > 0 && mwNodes[0].type === 'string' ? 1 : 0;
  for (let i = startIdx; i < mwNodes.length; i++) {
    const n = mwNodes[i];
    if (n.type === 'identifier') chain.push(textOf(n, source));
    else if (n.type === 'call_expression') {
      const fn = n.childForFieldName('function');
      if (fn) chain.push(textOf(fn, source));
    }
    else if (n.type === 'member_expression') chain.push(textOf(n, source));
  }
  return chain;
}

export const expressDetector: FrameworkDetector = {
  name: 'express',
  displayName: 'Express.js',
  language: 'javascript',
  triggerImports: ['express'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;

    const expressImport = file.imports.find((imp) => imp.source === 'express');
    if (!expressImport || !expressImport.localName) return [];

    const instances = collectExpressInstances(tree.rootNode, source, expressImport.localName);
    if (instances.size === 0) return [];

    // Detect auth middleware presence (file-level). Classification flips from
    // PUBLIC_UNAUTH → AUTH_INTERNAL if we see any.
    const importedAuthMechanism = (() => {
      for (const imp of file.imports) {
        const hit = AUTH_MIDDLEWARE.find((m) => imp.source === m.pkg || imp.source.startsWith(`${m.pkg}/`));
        if (hit) return hit.mechanism;
      }
      return null;
    })();

    const entryPoints: EntryPoint[] = [];

    const walk = (node: Node): void => {
      if (node.type === 'call_expression') {
        const fn = node.childForFieldName('function');
        if (fn?.type === 'member_expression') {
          const object = fn.childForFieldName('object');
          const property = fn.childForFieldName('property');
          if (object?.type === 'identifier' && property?.type === 'property_identifier') {
            const instanceName = textOf(object, source);
            const methodName = textOf(property, source);
            if (instances.has(instanceName) && ROUTE_METHOD_NAMES.has(methodName)) {
              const args = node.childForFieldName('arguments');
              const routeArg = args?.namedChild(0) ?? null;
              const routePattern = stringLiteralValue(routeArg, source);
              // `.use(handler)` without a route string — middleware mount. We
              // skip these at the entry-point layer to avoid pattern=null
              // noise; only register route-pattern calls.
              if (!routePattern) {
                for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
                return;
              }

              const lastArg = args ? args.namedChild(args.namedChildCount - 1) : null;
              const handlerName = handlerDescriptor(lastArg, source);
              const middlewareChain = collectMiddlewareChain(args, source);

              const httpMethod = HTTP_METHOD_NAMES[methodName] ?? null;
              const classification: EntryPoint['classification'] = importedAuthMechanism
                ? 'AUTH_INTERNAL'
                : 'PUBLIC_UNAUTH';

              entryPoints.push({
                filePath: file.filePath,
                lineNumber: node.startPosition.row + 1,
                framework: 'express',
                handlerName,
                httpMethod,
                routePattern,
                entryPointType: 'http_route',
                classification,
                authenticated: !!importedAuthMechanism,
                authMechanism: importedAuthMechanism,
                middlewareChain: middlewareChain.length ? middlewareChain : null,
                metadata: {
                  instance: instanceName,
                  call: `${instanceName}.${methodName}`,
                },
              });
            }
          }
        }
      }
      for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
    };

    walk(tree.rootNode);
    return entryPoints;
  },
};
