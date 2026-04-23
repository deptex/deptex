import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';

function textOf(n: Node | null, src: string): string {
  return n ? src.slice(n.startIndex, n.endIndex) : '';
}

function csStringLiteral(node: Node | null, source: string): string | null {
  if (!node || node.type !== 'string_literal') return null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'string_literal_content' || c.type === 'string_content') return textOf(c, source);
  }
  const raw = textOf(node, source);
  const m = raw.match(/^"(.*)"$/s);
  return m ? m[1] : null;
}

// ASP.NET Core Minimal APIs:
//   var app = WebApplication.Create();
//   app.MapGet("/users", () => "hi");
//   app.MapPost("/users", CreateUser);
//   app.MapPut("/users/{id}", handler);

const MAP_METHODS: Record<string, HttpMethod> = {
  MapGet: 'GET', MapPost: 'POST', MapPut: 'PUT', MapPatch: 'PATCH',
  MapDelete: 'DELETE', MapHead: 'HEAD', MapOptions: 'OPTIONS',
};

export const minimalApisDetector: FrameworkDetector = {
  name: 'minimal-apis',
  displayName: 'ASP.NET Core Minimal APIs',
  language: 'csharp',
  // Minimal API projects don't always import Mvc — scan every file, the
  // `app.MapGet(...)` idiom is the gate.
  triggerImports: [],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const entryPoints: EntryPoint[] = [];

    const walk = (node: Node): void => {
      if (node.type === 'invocation_expression') {
        const expr = node.childForFieldName('function') ?? node.namedChild(0);
        if (expr?.type === 'member_access_expression') {
          const name = expr.childForFieldName('name') ?? expr.namedChild(1);
          if (name) {
            const methodName = textOf(name, source);
            const verb = MAP_METHODS[methodName];
            if (verb) {
              const args = node.childForFieldName('arguments') ?? node.namedChild(1);
              const first = args?.namedChild(0);
              const firstInner = first?.type === 'argument' ? first.namedChild(0) : first ?? null;
              const routePattern = csStringLiteral(firstInner ?? null, source);
              if (routePattern) {
                const last = args ? args.namedChild(args.namedChildCount - 1) : null;
                const lastInner = last?.type === 'argument' ? last.namedChild(0) : last;
                let handlerName: string | null = null;
                if (lastInner) {
                  if (lastInner.type === 'identifier') handlerName = textOf(lastInner, source);
                  else if (lastInner.type === 'lambda_expression') handlerName = '(lambda)';
                  else handlerName = textOf(lastInner, source).slice(0, 40);
                }
                entryPoints.push({
                  filePath: file.filePath,
                  lineNumber: node.startPosition.row + 1,
                  framework: 'minimal-apis',
                  handlerName,
                  httpMethod: verb,
                  routePattern,
                  entryPointType: 'http_route',
                  classification: 'PUBLIC_UNAUTH',
                  authenticated: null,
                  authMechanism: null,
                  middlewareChain: null,
                  metadata: { method: methodName },
                });
              }
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
