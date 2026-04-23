import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  JAXRS_VERB_ANNOTATIONS,
  annotationsOn,
  classifyFromAuth,
  detectJavaAuthMechanism,
  joinRoute,
  lineOf,
  textOf,
  walkTree,
} from '../util/java';

// Quarkus resource classes are JAX-RS based with a distinct framework
// signature — `io.quarkus.*` imports tag them so the EntryPoint.framework
// field reads 'quarkus' (useful for UI grouping). Otherwise identical to JAX-RS.

export const quarkusDetector: FrameworkDetector = {
  name: 'quarkus',
  displayName: 'Quarkus',
  language: 'java',
  triggerImports: ['io.quarkus'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const authMechanism = detectJavaAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'class_declaration') return;
      const classAnns = annotationsOn(node, source);
      const pathAnn = classAnns.find((a) => a.name === 'Path');
      if (!pathAnn) return;
      const classPrefix = pathAnn.firstStringArg ?? null;
      const className = node.childForFieldName('name');

      const body = node.childForFieldName('body');
      if (!body) return;
      for (let i = 0; i < body.namedChildCount; i++) {
        const member = body.namedChild(i)!;
        if (member.type !== 'method_declaration') continue;
        const methodAnns = annotationsOn(member, source);
        const verbAnn = methodAnns.find((a) => JAXRS_VERB_ANNOTATIONS[a.name]);
        if (!verbAnn) continue;
        const subPathAnn = methodAnns.find((a) => a.name === 'Path');
        const subRoute = subPathAnn?.firstStringArg ?? '';
        const methodName = member.childForFieldName('name');

        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(member),
          framework: 'quarkus',
          handlerName: methodName ? textOf(methodName, source) : null,
          httpMethod: JAXRS_VERB_ANNOTATIONS[verbAnn.name],
          routePattern: joinRoute(classPrefix, subRoute),
          entryPointType: 'http_route',
          classification,
          authenticated: !!authMechanism,
          authMechanism,
          middlewareChain: null,
          metadata: { resource: className ? textOf(className, source) : null, annotation: verbAnn.name },
        });
      }
    });
    return entryPoints;
  },
};
