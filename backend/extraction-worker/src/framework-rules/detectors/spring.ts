import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';
import {
  SPRING_VERB_ANNOTATIONS,
  annotationsOn,
  classifyFromAuth,
  detectJavaAuthMechanism,
  joinRoute,
  lineOf,
  textOf,
  walkTree,
} from '../util/java';

// Spring MVC / WebFlux routes:
//   @RestController @RequestMapping("/api/users")
//   public class UserController {
//     @GetMapping("/{id}") ...
//     @PostMapping ...
//     @RequestMapping(value="/search", method=RequestMethod.GET) ...
//   }

const CONTROLLER_ANNOTATIONS = new Set(['RestController', 'Controller']);

function isControllerClass(decl: Node, source: string): boolean {
  return annotationsOn(decl, source).some((a) => CONTROLLER_ANNOTATIONS.has(a.name));
}

function classPrefix(decl: Node, source: string): string | null {
  const req = annotationsOn(decl, source).find((a) => a.name === 'RequestMapping');
  return req?.firstStringArg ?? null;
}

function methodFromRequestMapping(namedValues: Map<string, Node>, source: string): HttpMethod | null {
  const methodNode = namedValues.get('method');
  if (!methodNode) return null;
  const text = textOf(methodNode, source);
  // `RequestMethod.GET` — take the rightmost segment.
  const m = text.split('.').pop()?.toUpperCase() ?? '';
  if (['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(m)) return m as HttpMethod;
  return null;
}

export const springDetector: FrameworkDetector = {
  name: 'spring',
  displayName: 'Spring MVC',
  language: 'java',
  triggerImports: [
    'org.springframework.web.bind.annotation',
    'org.springframework.stereotype',
  ],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectJavaAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'class_declaration') return;
      if (!isControllerClass(node, source)) return;

      const prefix = classPrefix(node, source);
      const nameNode = node.childForFieldName('name');
      const className = nameNode ? textOf(nameNode, source) : null;

      const body = node.childForFieldName('body');
      if (!body) return;
      for (let i = 0; i < body.namedChildCount; i++) {
        const member = body.namedChild(i)!;
        if (member.type !== 'method_declaration') continue;
        const methodName = member.childForFieldName('name');
        const handlerName = methodName ? textOf(methodName, source) : null;

        for (const ann of annotationsOn(member, source)) {
          const httpMethod = SPRING_VERB_ANNOTATIONS[ann.name];
          if (httpMethod) {
            const subRoute = ann.firstStringArg ?? '';
            entryPoints.push({
              filePath: file.filePath,
              lineNumber: lineOf(member),
              framework: 'spring',
              handlerName,
              httpMethod,
              routePattern: joinRoute(prefix, subRoute),
              entryPointType: 'http_route',
              classification,
              authenticated: !!authMechanism,
              authMechanism,
              middlewareChain: null,
              metadata: { controller: className, annotation: ann.name },
            });
          } else if (ann.name === 'RequestMapping') {
            const rmMethod = methodFromRequestMapping(ann.namedValues, source);
            const subRoute = ann.firstStringArg ?? '';
            entryPoints.push({
              filePath: file.filePath,
              lineNumber: lineOf(member),
              framework: 'spring',
              handlerName,
              httpMethod: rmMethod,
              routePattern: joinRoute(prefix, subRoute),
              entryPointType: 'http_route',
              classification,
              authenticated: !!authMechanism,
              authMechanism,
              middlewareChain: null,
              metadata: { controller: className, annotation: 'RequestMapping' },
            });
          }
        }
      }
    });
    return entryPoints;
  },
};
