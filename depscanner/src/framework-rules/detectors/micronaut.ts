import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  MICRONAUT_VERB_ANNOTATIONS,
  annotationsOn,
  detectJavaAuthMechanism,
  javaAuthEvidenceFromAnnotations,
  joinRoute,
  lineOf,
  mergeJavaAuthEvidence,
  textOf,
  walkTree,
} from '../util/java';
import { classifyRoute, spanOfNode } from '../util/auth-evidence';

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
    // Import hint only — classification comes from @Secured annotation evidence
    // (IS_AUTHENTICATED / roles → auth; IS_ANONYMOUS → explicit public).
    const authMechanismHint = detectJavaAuthMechanism(file.imports);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'class_declaration') return;
      const classAnns = annotationsOn(node, source);
      const controllerAnn = classAnns.find((a) => a.name === 'Controller');
      if (!controllerAnn) return;
      const classPrefix = controllerAnn.firstStringArg ?? null;
      const className = node.childForFieldName('name');
      const classEvidence = javaAuthEvidenceFromAnnotations(classAnns, source);

      const body = node.childForFieldName('body');
      if (!body) return;
      for (let i = 0; i < body.namedChildCount; i++) {
        const member = body.namedChild(i)!;
        if (member.type !== 'method_declaration') continue;
        const methodAnns = annotationsOn(member, source);
        const merged = mergeJavaAuthEvidence(
          classEvidence,
          javaAuthEvidenceFromAnnotations(methodAnns, source),
        );
        for (const ann of methodAnns) {
          const verb = MICRONAUT_VERB_ANNOTATIONS[ann.name];
          if (!verb) continue;
          const subRoute = ann.firstStringArg ?? '';
          const routePattern = joinRoute(classPrefix, subRoute);
          const methodName = member.childForFieldName('name');
          const result = classifyRoute({
            vettedAuthTokens: merged.vettedAuthTokens,
            publicOverrides: merged.publicOverrides,
            routePattern,
            centralizedOnly: false,
          });
          entryPoints.push({
            filePath: file.filePath,
            lineNumber: lineOf(member),
            framework: 'micronaut',
            handlerName: methodName ? textOf(methodName, source) : null,
            httpMethod: verb,
            routePattern,
            entryPointType: 'http_route',
            classification: result.classification,
            authenticated: result.authenticated,
            authMechanism: authMechanismHint,
            middlewareChain: merged.vettedAuthTokens.length ? merged.vettedAuthTokens : null,
            // Declaration-bound family — span always demotion-eligible (Sem 6).
            handlerSpan: spanOfNode(member),
            demotionEligible: true,
            metadata: { controller: className ? textOf(className, source) : null, annotation: ann.name },
          });
        }
      }
    });
    return entryPoints;
  },
};
