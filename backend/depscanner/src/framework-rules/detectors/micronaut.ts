import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  MICRONAUT_VERB_ANNOTATIONS,
  annotationsOn,
  classifyFromAuth,
  detectJavaAuthMechanism,
  joinRoute,
  lineOf,
  textOf,
  walkTree,
} from '../util/java';

// Micronaut routes:
//   @Controller("/api/users")
//   public class UserController {
//     @Get("/{id}")  public String get(...) { ... }
//     @Post          public String create() { ... }
//   }

export const micronautDetector: FrameworkDetector = {
  name: 'micronaut',
  displayName: 'Micronaut',
  language: 'java',
  triggerImports: ['io.micronaut.http.annotation', 'io.micronaut.core'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectJavaAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'class_declaration') return;
      const classAnns = annotationsOn(node, source);
      const controllerAnn = classAnns.find((a) => a.name === 'Controller');
      if (!controllerAnn) return;
      const classPrefix = controllerAnn.firstStringArg ?? null;
      const className = node.childForFieldName('name');

      const body = node.childForFieldName('body');
      if (!body) return;
      for (let i = 0; i < body.namedChildCount; i++) {
        const member = body.namedChild(i)!;
        if (member.type !== 'method_declaration') continue;
        const methodAnns = annotationsOn(member, source);
        for (const ann of methodAnns) {
          const verb = MICRONAUT_VERB_ANNOTATIONS[ann.name];
          if (!verb) continue;
          const subRoute = ann.firstStringArg ?? '';
          const methodName = member.childForFieldName('name');
          entryPoints.push({
            filePath: file.filePath,
            lineNumber: lineOf(member),
            framework: 'micronaut',
            handlerName: methodName ? textOf(methodName, source) : null,
            httpMethod: verb,
            routePattern: joinRoute(classPrefix, subRoute),
            entryPointType: 'http_route',
            classification,
            authenticated: !!authMechanism,
            authMechanism,
            middlewareChain: null,
            metadata: { controller: className ? textOf(className, source) : null, annotation: ann.name },
          });
        }
      }
    });
    return entryPoints;
  },
};
