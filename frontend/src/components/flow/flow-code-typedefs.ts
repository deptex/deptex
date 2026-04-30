/**
 * Build runtime `.d.ts` strings to feed Monaco's TS extra-lib so the FlowCode
 * editor gets autocomplete + hover docs for every event type and node contract.
 *
 * No codegen step, no checked-in artifact — typedefs are reassembled on the fly
 * from `EVENT_SCHEMAS` (the schema source of truth) plus the contract registry
 * mirror. Drift impossible by construction: change a schema field, the editor
 * picks it up on next mount.
 */

import { EVENT_SCHEMAS, type EventField } from '../../lib/flow-event-schemas';

/**
 * Mirror of `backend/src/lib/flow-code/contracts.ts` — frontend doesn't import
 * across the backend boundary, so the contract metadata it needs for the editor
 * signature lives here too. Kept lean: only the fields used to render the
 * pinned function header.
 */
export interface NodeContractSpec {
  functionName: string;
  paramName: string;
  returnTypeTs: string;
}

export const NODE_CODE_CONTRACTS: Record<string, NodeContractSpec> = {
  condition: {
    functionName: 'evaluate',
    paramName: 'context',
    returnTypeTs: 'boolean',
  },
};

const RESERVED_WORDS = new Set([
  'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default',
  'delete', 'do', 'else', 'enum', 'export', 'extends', 'false', 'finally', 'for',
  'function', 'if', 'import', 'in', 'instanceof', 'new', 'null', 'return',
  'super', 'switch', 'this', 'throw', 'true', 'try', 'typeof', 'var', 'void',
  'while', 'with', 'yield', 'let', 'static', 'implements', 'interface',
  'package', 'private', 'protected', 'public',
]);

interface DtsNode {
  // Either a leaf (concrete TS type) or a branch (nested object).
  kind: 'leaf' | 'branch';
  type?: string;          // when kind === 'leaf'
  children?: Map<string, DtsNode>; // when kind === 'branch'
}

/**
 * Build a TS interface body for a single event type. Reassembles dot-paths
 * (`vulnerability.severity`) into nested interface declarations.
 *
 * Throws if:
 *   - Two paths collide such that one is a leaf and the other a branch
 *     (e.g. `foo` and `foo.bar` both declared).
 *   - Any path segment is a JS reserved word (would generate invalid TS).
 */
export function buildEventDts(eventType: string): string {
  const schema = EVENT_SCHEMAS[eventType];
  if (!schema) {
    return `interface ${pascalCase(eventType)}Context {}`;
  }

  // Build nested tree from dot paths.
  const root: DtsNode = { kind: 'branch', children: new Map() };
  for (const f of schema.fields) {
    insertField(root, f.path, fieldToTsType(f), eventType);
  }

  const interfaceName = `${pascalCase(eventType)}Context`;
  if (!root.children || root.children.size === 0) {
    return `interface ${interfaceName} {}`;
  }
  return `interface ${interfaceName} ${renderBranch(root, '')}`;
}

function insertField(root: DtsNode, path: string, leafType: string, eventType: string): void {
  const segments = path.split('.');
  let node = root;
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (RESERVED_WORDS.has(seg)) {
      throw new Error(`Schema for '${eventType}' uses reserved word '${seg}' in path '${path}'`);
    }
    const isLast = i === segments.length - 1;
    if (node.kind !== 'branch') {
      throw new Error(`Schema collision in '${eventType}': '${path}' steps into a leaf`);
    }
    const children = node.children!;
    let next = children.get(seg);
    if (!next) {
      next = isLast ? { kind: 'leaf', type: leafType } : { kind: 'branch', children: new Map() };
      children.set(seg, next);
    } else {
      if (isLast && next.kind !== 'leaf') {
        throw new Error(`Schema collision in '${eventType}': '${path}' is both leaf and object`);
      }
      if (!isLast && next.kind !== 'branch') {
        throw new Error(`Schema collision in '${eventType}': '${path}' is both leaf and object`);
      }
    }
    node = next;
  }
}

function renderBranch(node: DtsNode, indent: string): string {
  if (node.kind !== 'branch' || !node.children || node.children.size === 0) {
    return '{}';
  }
  const lines: string[] = ['{'];
  const inner = indent + '  ';
  for (const [name, child] of node.children) {
    if (child.kind === 'leaf') {
      lines.push(`${inner}${name}?: ${child.type};`);
    } else {
      lines.push(`${inner}${name}?: ${renderBranch(child, inner)};`);
    }
  }
  lines.push(`${indent}}`);
  return lines.join('\n');
}

function fieldToTsType(f: EventField): string {
  if (f.type === 'enum' && f.enumValues && f.enumValues.length > 0) {
    return f.enumValues.map((v) => `'${v.replace(/'/g, "\\'")}'`).join(' | ');
  }
  if (f.type === 'string') return 'string';
  if (f.type === 'number') return 'number';
  if (f.type === 'boolean') return 'boolean';
  return 'unknown';
}

/**
 * Emit the editor signature line for a node contract:
 *   `function evaluate(context: VulnerabilityDiscoveredContext): boolean`
 */
export function buildContractSignature(nodeType: string, eventType: string): string {
  const c = NODE_CODE_CONTRACTS[nodeType];
  if (!c) return `function evaluate(context: unknown): unknown`;
  const ctxType = `${pascalCase(eventType)}Context`;
  return `function ${c.functionName}(${c.paramName}: ${ctxType}): ${c.returnTypeTs}`;
}

/**
 * Combine the event interface + the helper declarations + the contract
 * signature into one `.d.ts` string ready for `addExtraLib`.
 */
export function buildFlowCodeDts(nodeType: string, eventType: string): string {
  const eventInterface = buildEventDts(eventType);
  const contract = NODE_CODE_CONTRACTS[nodeType];
  const ctxName = `${pascalCase(eventType)}Context`;

  // Helpers exposed at runtime — match the host references in `policy-engine.ts`.
  const helpers = `
declare function isLicenseAllowed(license: string | null, allowList: string[]): boolean;
declare function isLicenseBanned(license: string | null, banList: string[]): boolean;
declare function semverGt(a: string, b: string): boolean;
declare function semverLt(a: string, b: string): boolean;
declare function daysSince(isoDate: string): number;
declare function fetch(url: string): Promise<{ ok: boolean; status: number; json(): Promise<unknown>; text(): Promise<string> }>;
`;

  if (!contract) {
    return `${eventInterface}\n${helpers}\ndeclare const ${'context'}: ${ctxName};\n`;
  }

  return `${eventInterface}\n${helpers}\ndeclare const ${contract.paramName}: ${ctxName};\n`;
}

function pascalCase(s: string): string {
  return s
    .split(/[_\-\s]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join('');
}
