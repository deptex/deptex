import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';
import { HTTP_METHOD_NAMES, classifyFromAuth, detectAuthMechanism, lineOf, stringLiteralValue, textOf, walkTree } from '../util/javascript';

// NestJS is decorator-driven:
//   @Controller('/users')
//   export class UsersController {
//     @Get(':id')
//     findOne(@Param('id') id: string) { ... }
//   }
// Decorators are only legal in TS/TSX files — JS Nest projects exist but are
// rare enough we don't chase them here.

const METHOD_DECORATOR_NAMES: Record<string, HttpMethod> = {
  Get: 'GET', Post: 'POST', Put: 'PUT', Patch: 'PATCH',
  Delete: 'DELETE', Head: 'HEAD', Options: 'OPTIONS',
};

function decoratorInvocation(dec: Node): Node | null {
  // decorator > call_expression | member_expression | identifier
  const inner = dec.namedChild(0);
  return inner ?? null;
}

function decoratorName(dec: Node, source: string): string | null {
  const inner = decoratorInvocation(dec);
  if (!inner) return null;
  if (inner.type === 'call_expression') {
    const fn = inner.childForFieldName('function');
    if (fn?.type === 'identifier') return textOf(fn, source);
    if (fn?.type === 'member_expression') {
      const property = fn.childForFieldName('property');
      return property ? textOf(property, source) : null;
    }
  }
  if (inner.type === 'identifier') return textOf(inner, source);
  return null;
}

function decoratorFirstStringArg(dec: Node, source: string): string | null {
  const inner = decoratorInvocation(dec);
  if (inner?.type !== 'call_expression') return null;
  const args = inner.childForFieldName('arguments');
  const first = args?.namedChild(0);
  return stringLiteralValue(first ?? null, source);
}

function joinRoute(prefix: string | null, sub: string | null): string | null {
  if (!prefix && !sub) return null;
  const p = prefix ? (prefix.startsWith('/') ? prefix : `/${prefix}`).replace(/\/$/, '') : '';
  const s = sub ? (sub.startsWith('/') ? sub : `/${sub}`) : '';
  const joined = `${p}${s}` || '/';
  return joined.replace(/\/+/g, '/');
}

export const nestjsDetector: FrameworkDetector = {
  name: 'nestjs',
  displayName: 'NestJS',
  language: 'javascript',
  triggerImports: ['@nestjs/common', '@nestjs/core', '@nestjs/platform-express', '@nestjs/platform-fastify'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;

    const authMechanism = detectAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'class_declaration' && node.type !== 'class') return;

      // Controller decorators sit on the class; method decorators sit on each
      // method. Decorators in TS/TSX appear as children before the class/method
      // node (decorator type).
      // tree-sitter-typescript grammar puts decorators as siblings of the
      // class_declaration / method_definition, typically as preceding named
      // children on the parent. Grammar-specifically: class declarations may
      // have a `decorators` field, or the decorators appear in
      // `export_statement > decorator + class_declaration`.
      // Simplest path: walk up to the containing node and look for sibling
      // decorator nodes.

      // tree-sitter-typescript nests decorators inside class_declaration
      // (before the class body), while export_statement wraps exported classes
      // so decorators may also sit as preceding siblings under the parent.
      // Check both locations. Node-wrapper identity is unreliable in
      // web-tree-sitter, so compare startIndex positions.
      let controllerPrefix: string | null = null;
      let isController = false;
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i)!;
        if (child.type !== 'decorator') break;
        const name = decoratorName(child, source);
        if (name === 'Controller') {
          isController = true;
          controllerPrefix = decoratorFirstStringArg(child, source);
        }
      }
      if (!isController) {
        const classParent = node.parent;
        if (classParent) {
          for (let i = 0; i < classParent.namedChildCount; i++) {
            const sib = classParent.namedChild(i)!;
            if (sib.startIndex >= node.startIndex) break;
            if (sib.type === 'decorator') {
              const name = decoratorName(sib, source);
              if (name === 'Controller') {
                isController = true;
                controllerPrefix = decoratorFirstStringArg(sib, source);
              }
            }
          }
        }
      }
      if (!isController) return;

      // Find class body and walk methods.
      const body = node.childForFieldName('body');
      if (!body) return;
      for (let i = 0; i < body.namedChildCount; i++) {
        const member = body.namedChild(i)!;
        if (member.type !== 'method_definition') continue;

        // Collect decorators preceding this method within the body.
        const decorators: Node[] = [];
        for (let j = 0; j < i; j++) {
          const prev = body.namedChild(j)!;
          if (prev.type === 'decorator') decorators.push(prev);
          else if (prev.type === 'method_definition') decorators.length = 0;
        }

        for (const dec of decorators) {
          const name = decoratorName(dec, source);
          if (!name) continue;
          const httpMethod = METHOD_DECORATOR_NAMES[name];
          if (!httpMethod) continue;
          const subRoute = decoratorFirstStringArg(dec, source);
          const route = joinRoute(controllerPrefix, subRoute ?? '');
          const methodName = member.childForFieldName('name');
          entryPoints.push({
            filePath: file.filePath,
            lineNumber: lineOf(member),
            framework: 'nestjs',
            handlerName: methodName ? textOf(methodName, source) : null,
            httpMethod,
            routePattern: route,
            entryPointType: 'http_route',
            classification,
            authenticated: !!authMechanism,
            authMechanism,
            middlewareChain: null,
            metadata: { decorator: name },
          });
        }
      }
    });

    return entryPoints;
  },
};
