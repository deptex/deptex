/**
 * Per-node return contracts for code-mode flow nodes.
 *
 * Each contract describes what user-written code for a node type must return
 * and how its body is wrapped into a function declaration. Today only the
 * `condition` node has a contract; filter/switch/transform contracts get added
 * when those nodes acquire a UI (YAGNI per the locked plan).
 *
 * Source of truth: backend. The frontend's Monaco TS extra-lib reads a mirror
 * of `functionName` / `paramName` / `returnTypeTs` to build the editor signature.
 */

export type FlowNodeType = 'condition';

export interface FlowCodeContract {
  /** Function declaration name the user's code must export (e.g. `evaluate`). */
  functionName: string;
  /** Parameter name shown in the editor signature. Cosmetic — runtime uses positional. */
  paramName: string;
  /** TS type of the return value, used for the Monaco signature line. */
  returnTypeTs: string;
  /**
   * Validate the runtime return value. Returns `true` on pass, or a human
   * error string on fail. Stays synchronous so the sandbox wrapper can log
   * `returnShape` errors without an extra async hop.
   */
  returnTypeCheck: (val: unknown) => true | string;
  /** Body inserted when the user switches a fresh node to code mode. */
  defaultBody: string;
  /** One-click templates surfaced in the editor's "Examples" collapsible. */
  exampleBodies?: Array<{ label: string; body: string }>;
}

export const NODE_CODE_CONTRACTS: Record<FlowNodeType, FlowCodeContract> = {
  condition: {
    functionName: 'evaluate',
    paramName: 'context',
    returnTypeTs: 'boolean',
    returnTypeCheck: (val) =>
      typeof val === 'boolean'
        ? true
        : `Condition must return boolean, got ${val === null ? 'null' : typeof val}`,
    defaultBody: `  // Return true to continue down this branch, false to stop.
  return true;`,
    exampleBodies: [
      {
        label: 'Critical or high severity only',
        body: `  const sev = context.vulnerability?.severity;
  return sev === 'critical' || sev === 'high';`,
      },
      {
        label: 'Reachable + score >= 70',
        body: `  const v = context.vulnerability;
  return Boolean(v?.isReachable) && (v?.depscore ?? 0) >= 70;`,
      },
      {
        label: 'Production tier projects',
        body: `  return context.project?.tier === 'Production';`,
      },
      {
        label: 'Direct dependencies only',
        body: `  return context.dependency?.isDirect === true;`,
      },
    ],
  },
};

export function getContract(nodeType: string): FlowCodeContract | null {
  return (NODE_CODE_CONTRACTS as Record<string, FlowCodeContract>)[nodeType] ?? null;
}
