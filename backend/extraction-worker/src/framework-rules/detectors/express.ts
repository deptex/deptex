import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  HTTP_METHOD_NAMES,
  classifyFromAuth,
  detectAuthMechanism,
  findInstancesOfImport,
  handlerDescriptor,
  lineOf,
  stringLiteralValue,
  textOf,
  walkTree,
} from '../util/javascript';

const ROUTE_METHOD_NAMES = new Set([...Object.keys(HTTP_METHOD_NAMES), 'all', 'use']);

function collectMiddlewareChain(args: Node | null, source: string): string[] {
  if (!args) return [];
  const argNodes: Node[] = [];
  for (let i = 0; i < args.namedChildCount; i++) argNodes.push(args.namedChild(i)!);
  const mwNodes = argNodes.slice(0, -1);
  const startIdx = mwNodes.length > 0 && mwNodes[0].type === 'string' ? 1 : 0;
  const chain: string[] = [];
  for (let i = startIdx; i < mwNodes.length; i++) {
    const n = mwNodes[i];
    if (n.type === 'identifier') chain.push(textOf(n, source));
    else if (n.type === 'call_expression') {
      const fn = n.childForFieldName('function');
      if (fn) chain.push(textOf(fn, source));
    } else if (n.type === 'member_expression') chain.push(textOf(n, source));
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
    if (!expressImport?.localName) return [];

    const instances = findInstancesOfImport(tree.rootNode, source, expressImport.localName, {
      extraMethods: ['Router'],
    });
    if (instances.size === 0) return [];

    const authMechanism = detectAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'call_expression') return;
      const fn = node.childForFieldName('function');
      if (fn?.type !== 'member_expression') return;
      const object = fn.childForFieldName('object');
      const property = fn.childForFieldName('property');
      if (object?.type !== 'identifier' || property?.type !== 'property_identifier') return;
      const instanceName = textOf(object, source);
      const methodName = textOf(property, source);
      if (!instances.has(instanceName) || !ROUTE_METHOD_NAMES.has(methodName)) return;

      const args = node.childForFieldName('arguments');
      const routeArg = args?.namedChild(0) ?? null;
      const routePattern = stringLiteralValue(routeArg, source);
      if (!routePattern) return;

      const lastArg = args ? args.namedChild(args.namedChildCount - 1) : null;
      const handlerName = handlerDescriptor(lastArg, source);
      const middlewareChain = collectMiddlewareChain(args, source);

      entryPoints.push({
        filePath: file.filePath,
        lineNumber: lineOf(node),
        framework: 'express',
        handlerName,
        httpMethod: HTTP_METHOD_NAMES[methodName] ?? null,
        routePattern,
        entryPointType: 'http_route',
        classification,
        authenticated: !!authMechanism,
        authMechanism,
        middlewareChain: middlewareChain.length ? middlewareChain : null,
        metadata: { instance: instanceName, call: `${instanceName}.${methodName}` },
      });
    });

    return entryPoints;
  },
};
