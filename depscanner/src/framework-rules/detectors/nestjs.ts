import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';
import { HTTP_METHOD_NAMES, detectAuthMechanism, lineOf, stringLiteralValue, textOf, walkTree } from '../util/javascript';
import { classifyRoute, matchesPublicOverride, spanOfNode } from '../util/auth-evidence';

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

/**
 * All string-shaped argument tokens of a decorator invocation:
 * `@UseGuards(JwtAuthGuard, RolesGuard)` → ['JwtAuthGuard', 'RolesGuard'];
 * `@UseGuards(AuthGuard('jwt'))` → ["AuthGuard('jwt')"] (arg text kept so the
 * optional/anonymous vetoes see strategy names).
 */
function decoratorArgTokens(dec: Node, source: string): string[] {
  const inner = decoratorInvocation(dec);
  if (inner?.type !== 'call_expression') return [];
  const args = inner.childForFieldName('arguments');
  if (!args) return [];
  const out: string[] = [];
  for (let i = 0; i < args.namedChildCount; i++) {
    const t = textOf(args.namedChild(i)!, source).trim();
    if (t) out.push(t);
  }
  return out;
}

/**
 * Split a decorator list into route-auth evidence: `@UseGuards(...)` argument
 * tokens (auth iff they match the shared auth-name patterns — `*AuthGuard`
 * matches, ThrottlerGuard stays neutral) and explicit-public override
 * decorators (`@Public()`, `@SkipAuth()`, `@AllowAnonymous()`).
 */
function gatherDecoratorEvidence(
  decorators: readonly Node[],
  source: string,
): { guardTokens: string[]; publicOverrides: string[] } {
  const guardTokens: string[] = [];
  const publicOverrides: string[] = [];
  for (const dec of decorators) {
    const name = decoratorName(dec, source);
    if (!name) continue;
    if (name === 'UseGuards') {
      guardTokens.push(...decoratorArgTokens(dec, source));
    } else if (matchesPublicOverride(name)) {
      publicOverrides.push(name);
    }
  }
  return { guardTokens, publicOverrides };
}

export const nestjsDetector: FrameworkDetector = {
  name: 'nestjs',
  displayName: 'NestJS',
  language: 'javascript',
  triggerImports: ['@nestjs/common', '@nestjs/core', '@nestjs/platform-express', '@nestjs/platform-fastify'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;

    // Import hint only — classification comes from guard/override decorators.
    const authMechanismHint = detectAuthMechanism(file.imports);
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
      // Collect the class's decorators from BOTH grammar locations (inline
      // children before the body, and preceding siblings under an
      // export_statement wrapper), then read Controller + auth evidence off the
      // combined list.
      const classDecorators: Node[] = [];
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i)!;
        if (child.type !== 'decorator') break;
        classDecorators.push(child);
      }
      if (classDecorators.length === 0) {
        const classParent = node.parent;
        if (classParent) {
          for (let i = 0; i < classParent.namedChildCount; i++) {
            const sib = classParent.namedChild(i)!;
            if (sib.startIndex >= node.startIndex) break;
            if (sib.type === 'decorator') classDecorators.push(sib);
          }
        }
      }
      let controllerPrefix: string | null = null;
      let isController = false;
      for (const dec of classDecorators) {
        if (decoratorName(dec, source) === 'Controller') {
          isController = true;
          controllerPrefix = decoratorFirstStringArg(dec, source);
        }
      }
      if (!isController) return;

      // Class-level guards cover every method; a method-level @Public()
      // override still wins (Sem 2: method-level public beats class auth).
      const classEvidence = gatherDecoratorEvidence(classDecorators, source);

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

        // Method-level guard/override evidence, merged with the class's.
        const methodEvidence = gatherDecoratorEvidence(decorators, source);

        for (const dec of decorators) {
          const name = decoratorName(dec, source);
          if (!name) continue;
          const httpMethod = METHOD_DECORATOR_NAMES[name];
          if (!httpMethod) continue;
          const subRoute = decoratorFirstStringArg(dec, source);
          const route = joinRoute(controllerPrefix, subRoute ?? '');
          const methodName = member.childForFieldName('name');

          const guardTokens = [...classEvidence.guardTokens, ...methodEvidence.guardTokens];
          const result = classifyRoute({
            // classifyRoute's auth-name matching decides which guard tokens are
            // real auth evidence (`*AuthGuard` matches; ThrottlerGuard neutral;
            // Optional*/anonymous-strategy guards vetoed).
            authTokens: guardTokens,
            publicOverrides: [...classEvidence.publicOverrides, ...methodEvidence.publicOverrides],
            routePattern: route,
            // Decorator evidence is declaration-local, never a centralized
            // idiom — the belt does not apply (Sem 10).
            centralizedOnly: false,
          });

          entryPoints.push({
            filePath: file.filePath,
            lineNumber: lineOf(member),
            framework: 'nestjs',
            handlerName: methodName ? textOf(methodName, source) : null,
            httpMethod,
            routePattern: route,
            entryPointType: 'http_route',
            classification: result.classification,
            authenticated: result.authenticated,
            authMechanism: authMechanismHint,
            middlewareChain: guardTokens.length ? guardTokens : null,
            // Declaration-bound family (Sem 6 guard table): the auth evidence
            // travels with the method wherever it's referenced, so the span is
            // always demotion-eligible.
            handlerSpan: spanOfNode(member),
            demotionEligible: true,
            metadata: { decorator: name },
          });
        }
      }
    });

    return entryPoints;
  },
};
