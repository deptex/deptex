import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import {
  JAXRS_VERB_ANNOTATIONS,
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
    // Import hint only — classification comes from annotation evidence
    // (@Authenticated / @RolesAllowed / @PermitAll are the Quarkus idioms).
    const authMechanismHint = detectJavaAuthMechanism(file.imports);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'class_declaration') return;
      const classAnns = annotationsOn(node, source);
      const pathAnn = classAnns.find((a) => a.name === 'Path');
      if (!pathAnn) return;
      const classPrefix = pathAnn.firstStringArg ?? null;
      const className = node.childForFieldName('name');
      const classEvidence = javaAuthEvidenceFromAnnotations(classAnns, source);

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
        const routePattern = joinRoute(classPrefix, subRoute);
        const methodName = member.childForFieldName('name');

        const merged = mergeJavaAuthEvidence(
          classEvidence,
          javaAuthEvidenceFromAnnotations(methodAnns, source),
        );
        const result = classifyRoute({
          vettedAuthTokens: merged.vettedAuthTokens,
          publicOverrides: merged.publicOverrides,
          routePattern,
          centralizedOnly: false,
        });

        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(member),
          framework: 'quarkus',
          handlerName: methodName ? textOf(methodName, source) : null,
          httpMethod: JAXRS_VERB_ANNOTATIONS[verbAnn.name],
          routePattern,
          entryPointType: 'http_route',
          classification: result.classification,
          authenticated: result.authenticated,
          authMechanism: authMechanismHint,
          middlewareChain: merged.vettedAuthTokens.length ? merged.vettedAuthTokens : null,
          // Declaration-bound family — span always demotion-eligible (Sem 6).
          handlerSpan: spanOfNode(member),
          demotionEligible: true,
          metadata: { resource: className ? textOf(className, source) : null, annotation: verbAnn.name },
        });
      }
    });
    return entryPoints;
  },
};
