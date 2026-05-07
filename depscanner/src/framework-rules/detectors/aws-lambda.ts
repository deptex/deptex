import type { DetectorContext, EntryPoint, FrameworkDetector } from '../types';
import { lineOf, textOf, walkTree } from '../util/javascript';

// AWS Lambda handler conventions:
//   exports.handler = async (event, context) => { ... }
//   export const handler = async (event) => { ... }
//   export async function handler(event) { ... }
// The 'handler' name itself is convention (matches the default configured in
// serverless.yml / SAM / CDK). Users can override — we can't detect that
// without the config file, so we match the common name.
//
// Classified as OFFLINE_WORKER by default because Lambdas aren't necessarily
// public-HTTP (SQS triggers, S3 events, EventBridge, etc.) — callers that
// know their trigger is API Gateway can override via metadata later.

const HANDLER_NAMES = new Set(['handler', 'handlers', 'lambdaHandler', 'main']);

export const awsLambdaDetector: FrameworkDetector = {
  name: 'aws-lambda',
  displayName: 'AWS Lambda',
  language: 'javascript',
  // Lambda projects don't always import an SDK — the `exports.handler` /
  // `export const handler` convention IS the signal. Empty triggerImports
  // tells the JS module to run this detector on every file.
  triggerImports: [],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const entryPoints: EntryPoint[] = [];

    walkTree(tree, (node) => {
      // Pattern 1: exports.X = ...
      if (node.type === 'assignment_expression') {
        const left = node.childForFieldName('left');
        if (left?.type !== 'member_expression') return;
        const object = left.childForFieldName('object');
        const property = left.childForFieldName('property');
        if (object?.type !== 'identifier' || property?.type !== 'property_identifier') return;
        if (textOf(object, source) !== 'exports' && textOf(object, source) !== 'module') return;
        const propName = textOf(property, source);
        if (!HANDLER_NAMES.has(propName)) return;
        entryPoints.push(makeEntry(node, file.filePath, propName));
        return;
      }

      // Pattern 2: export const X = ... / export async function X() {...}
      if (node.type === 'export_statement') {
        for (let i = 0; i < node.namedChildCount; i++) {
          const child = node.namedChild(i)!;
          let name: string | null = null;
          if (child.type === 'lexical_declaration') {
            const decl = child.namedChild(0);
            if (decl?.type === 'variable_declarator') {
              const n = decl.childForFieldName('name');
              if (n?.type === 'identifier') name = textOf(n, source);
            }
          } else if (child.type === 'function_declaration') {
            const n = child.childForFieldName('name');
            if (n?.type === 'identifier') name = textOf(n, source);
          }
          if (name && HANDLER_NAMES.has(name)) {
            entryPoints.push(makeEntry(node, file.filePath, name));
          }
        }
      }
    });

    return entryPoints;
  },
};

function makeEntry(node: import('web-tree-sitter').Node, filePath: string, handlerName: string): EntryPoint {
  return {
    filePath,
    lineNumber: lineOf(node),
    framework: 'aws-lambda',
    handlerName,
    httpMethod: null,
    routePattern: null,
    entryPointType: 'serverless_handler',
    classification: 'OFFLINE_WORKER',
    authenticated: null,
    authMechanism: null,
    middlewareChain: null,
    metadata: { export_name: handlerName },
  };
}
