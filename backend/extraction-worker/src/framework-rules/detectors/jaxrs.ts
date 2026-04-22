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

// JAX-RS / Jakarta RESTful routes (used standalone + by Quarkus + Jersey):
//   @Path("/items")
//   public class ItemResource {
//     @GET @Path("/{id}") public String get(...) { ... }
//     @POST public String create() { ... }
//   }

export const jaxrsDetector: FrameworkDetector = {
  name: 'jaxrs',
  displayName: 'JAX-RS / Jakarta REST',
  language: 'java',
  triggerImports: [
    'javax.ws.rs',
    'jakarta.ws.rs',
  ],
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
      const nameNode = node.childForFieldName('name');
      const className = nameNode ? textOf(nameNode, source) : null;

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

        const methodNameNode = member.childForFieldName('name');
        entryPoints.push({
          filePath: file.filePath,
          lineNumber: lineOf(member),
          framework: 'jaxrs',
          handlerName: methodNameNode ? textOf(methodNameNode, source) : null,
          httpMethod: JAXRS_VERB_ANNOTATIONS[verbAnn.name],
          routePattern: joinRoute(classPrefix, subRoute),
          entryPointType: 'http_route',
          classification,
          authenticated: !!authMechanism,
          authMechanism,
          middlewareChain: null,
          metadata: { resource: className, annotation: verbAnn.name },
        });
      }
    });
    return entryPoints;
  },
};
