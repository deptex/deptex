import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';
import {
  HTTP_METHOD_NAMES,
  classifyFromAuth,
  decoratorsOf,
  detectPyAuthMechanism,
  findClassInstances,
  lineOf,
  parseDecorator,
  pythonStringLiteral,
  textOf,
  walkTree,
} from '../util/python';
import { harvestFlaskParams } from '../../param-harvest/flask-harvest';

// Flask route patterns:
//   app = Flask(__name__)
//   @app.route('/users', methods=['GET', 'POST']) → GET + POST
//   @app.get('/users')   (Flask ≥ 2.0)            → GET
//   @app.post('/users')                            → POST
//   Same for put/delete/patch.

export const flaskDetector: FrameworkDetector = {
  name: 'flask',
  displayName: 'Flask',
  language: 'python',
  triggerImports: ['flask'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;

    // Allow either `from flask import Flask` OR `import flask` then `flask.Flask()`.
    // We look for instances bound from calling `Flask` directly.
    const instances = findClassInstances(tree.rootNode, source, ['Flask', 'Blueprint']);
    if (instances.size === 0) return [];

    const authMechanism = detectPyAuthMechanism(file.imports);
    const classification = classifyFromAuth(authMechanism);
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      if (node.type !== 'function_definition') return;
      const decorators = decoratorsOf(node);
      if (decorators.length === 0) return;
      const funcName = node.childForFieldName('name');
      const handlerName = funcName ? textOf(funcName, source) : null;
      // Harvest once per view function — shared across all its HTTP methods.
      const requestParams = harvestFlaskParams(node, source);

      for (const dec of decorators) {
        const parsed = parseDecorator(dec, source);
        if (!parsed.object || !instances.has(parsed.object)) continue;
        if (!parsed.call || !parsed.attr) continue;

        const args = parsed.call.childForFieldName('arguments');
        const routeArg = args?.namedChild(0);
        const routePattern = pythonStringLiteral(routeArg ?? null, source);
        if (!routePattern) continue;

        let methods: HttpMethod[] = [];
        const verb = HTTP_METHOD_NAMES[parsed.attr];
        if (verb) methods = [verb];
        else if (parsed.attr === 'route') {
          methods = extractMethodsKwarg(args, source);
          if (methods.length === 0) methods = ['GET']; // Flask default
        } else continue;

        for (const m of methods) {
          entryPoints.push({
            filePath: file.filePath,
            lineNumber: lineOf(node),
            framework: 'flask',
            handlerName,
            httpMethod: m,
            routePattern,
            entryPointType: 'http_route',
            classification,
            authenticated: !!authMechanism,
            authMechanism,
            middlewareChain: null,
            metadata: { instance: parsed.object, decorator: parsed.attr },
            requestParams,
          });
        }
      }
    });

    return entryPoints;
  },
};

function extractMethodsKwarg(args: Node | null, source: string): HttpMethod[] {
  if (!args) return [];
  const out: HttpMethod[] = [];
  for (let i = 0; i < args.namedChildCount; i++) {
    const c = args.namedChild(i)!;
    if (c.type !== 'keyword_argument') continue;
    const name = c.childForFieldName('name');
    if (!name || textOf(name, source) !== 'methods') continue;
    const value = c.childForFieldName('value');
    if (value?.type !== 'list') continue;
    for (let j = 0; j < value.namedChildCount; j++) {
      const el = value.namedChild(j)!;
      if (el.type === 'string') {
        const raw = pythonStringLiteral(el, source);
        if (raw) {
          const upper = raw.toUpperCase() as HttpMethod;
          if (['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(upper)) {
            out.push(upper);
          }
        }
      }
    }
  }
  return out;
}
