/**
 * Per-function IR lowerer for Python (tree-sitter).
 *
 * Emits the same `Step[]` shape that the TS lowerer (../ir.ts) emits:
 *   - source: `target = <pattern matching a FrameworkSource>` (property/index access)
 *   - assign: `target = source` — copy taint between locals
 *   - call:   `[target =] callee(args)` — args carry taint, returns may flow back
 *   - return: `return [expr]`
 *
 * Like the TS lowerer, this is intentionally over-approximating (branches are
 * flattened, no alias analysis, no field-level taint). Non-Identifier args
 * synthesize a temp var so taint flows through f-strings, attribute access in
 * args, nested calls, string concatenation/formatting, etc. — mirrors the
 * "M3.0 fix" behavior in the TS lowerer.
 *
 * Known v1 limitations:
 *   - Tuple unpacking `a, b = expr` taints both `a` and `b` from `expr`'s
 *     taint; field-level destructuring is not modeled.
 *   - List/dict comprehensions over a tainted iterable taint the result var.
 *   - `with` blocks: body is walked; the context-manager's __enter__ value
 *     is treated as a regular assignment from the call.
 *   - `global`/`nonlocal` declarations are ignored.
 *   - `try/except` exception bindings (`except E as e`) bind `e` to the
 *     captured exception and are not taint-tracked.
 */

import type { Node } from 'web-tree-sitter';
import type {
  CalleeRef,
  IrFunction,
  LocalVar,
  SourceLocation,
  Step,
} from '../ir';
import type { FunctionId } from '../types';
import { resolvePythonCallee } from './callgraph';
import type { PythonFileContext } from './callgraph';

export interface LowerPythonOptions {
  /** Workspace-relative file path. */
  filePath: string;
  /** Per-file context: tree, source, imports, functions. */
  fileContext: PythonFileContext;
  /** All file contexts in the workspace, used by callee resolution. */
  allFiles: Map<string, PythonFileContext>;
}

/**
 * Lower a Python `function_definition` (or the file root for the synthetic
 * module initializer) into the engine's IR.
 *
 * `funcNode` must either be a tree-sitter `function_definition` node or the
 * file's root (`module`) node.
 */
export function lowerPythonFunction(
  funcId: FunctionId,
  funcNode: Node,
  opts: LowerPythonOptions,
): IrFunction {
  const params: LocalVar[] = [];
  let body: Node | null = null;
  let isModule = false;

  if (funcNode.type === 'function_definition') {
    const paramsNode = funcNode.childForFieldName('parameters');
    if (paramsNode) {
      for (let i = 0; i < paramsNode.namedChildCount; i++) {
        const p = paramsNode.namedChild(i);
        if (!p) continue;
        const name = paramNameOf(p, opts.fileContext.source);
        params.push(name ?? `<param@${i}>`);
      }
    }
    body = funcNode.childForFieldName('body');
  } else if (funcNode.type === 'module') {
    isModule = true;
    body = funcNode;
  } else {
    // Defensive: unknown caller — treat as module.
    isModule = true;
    body = funcNode;
  }

  const steps: Step[] = [];
  const enclosingClass = enclosingClassOf(funcNode, opts.fileContext.source);

  if (body) {
    const ctx: WalkCtx = {
      opts,
      enclosingClass,
      isModule,
    };
    walkBlock(body, steps, ctx);
  }

  return { id: funcId, params, steps };
}

interface WalkCtx {
  opts: LowerPythonOptions;
  enclosingClass: string | null;
  isModule: boolean;
}

function enclosingClassOf(node: Node, source: string): string | null {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (cur.type === 'class_definition') {
      const nameNode = cur.childForFieldName('name');
      return textOf(nameNode, source) || null;
    }
  }
  return null;
}

function paramNameOf(p: Node, source: string): string | null {
  // Common parameter shapes:
  //   identifier            → `x`
  //   typed_parameter       → `x: int`
  //   default_parameter     → `x = 1`
  //   typed_default_parameter → `x: int = 1`
  //   list_splat_pattern    → `*args` (rare in field, usually identifier)
  //   dictionary_splat_pattern → `**kwargs`
  if (p.type === 'identifier') return textOf(p, source);
  if (p.type === 'typed_parameter') {
    const inner = p.namedChild(0);
    if (inner) return textOf(inner, source);
  }
  if (p.type === 'default_parameter' || p.type === 'typed_default_parameter') {
    const nameNode = p.childForFieldName('name');
    return textOf(nameNode, source) || null;
  }
  if (p.type === 'list_splat_pattern' || p.type === 'dictionary_splat_pattern') {
    const inner = p.namedChild(0);
    if (inner) return textOf(inner, source);
  }
  return null;
}

function locOf(node: Node, ctx: WalkCtx): SourceLocation {
  return {
    filePath: ctx.opts.filePath,
    line: node.startPosition.row + 1,
    column: node.startPosition.column + 1,
  };
}

function textOf(node: Node | null | undefined, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

/**
 * Walk a block (function body, module root, or any statement-list-ish node)
 * and emit Steps in syntactic order. Recurses into nested blocks (for/if/try/
 * with/while). Skips nested function/class definitions — the caller analyzes
 * those as separate IrFunctions.
 */
function walkBlock(node: Node, steps: Step[], ctx: WalkCtx): void {
  for (let i = 0; i < node.namedChildCount; i++) {
    const stmt = node.namedChild(i);
    if (!stmt) continue;
    walkStatement(stmt, steps, ctx);
  }
}

function walkStatement(stmt: Node, steps: Step[], ctx: WalkCtx): void {
  switch (stmt.type) {
    case 'expression_statement': {
      // Could be `expr` or `target = expr` (assignment is parsed as expression here).
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const inner = stmt.namedChild(i);
        if (inner) walkExpressionAsAssign(inner, null, steps, ctx);
      }
      return;
    }
    case 'assignment': {
      handleAssignment(stmt, steps, ctx);
      return;
    }
    case 'augmented_assignment': {
      // `x += foo` — treat as both reading x and combining with foo into x.
      const left = stmt.childForFieldName('left');
      const right = stmt.childForFieldName('right');
      const leftName = left && left.type === 'identifier' ? textOf(left, ctx.opts.fileContext.source) : null;
      if (right) walkExpressionAsAssign(right, leftName, steps, ctx);
      return;
    }
    case 'return_statement': {
      // The grammar exposes the expression as a child (named child after the keyword).
      let exprChild: Node | null = null;
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (c) {
          exprChild = c;
          break;
        }
      }
      if (exprChild) {
        emitReturnFromExpression(exprChild, steps, ctx);
      } else {
        steps.push({ kind: 'return', from: null, loc: locOf(stmt, ctx) });
      }
      return;
    }
    case 'if_statement': {
      const cond = stmt.childForFieldName('condition');
      if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
      const consequence = stmt.childForFieldName('consequence');
      if (consequence) walkBlock(consequence, steps, ctx);
      // elif / else
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'elif_clause') {
          const ec = c.childForFieldName('condition');
          if (ec) walkExpressionAsAssign(ec, null, steps, ctx);
          const cb = c.childForFieldName('consequence');
          if (cb) walkBlock(cb, steps, ctx);
        } else if (c.type === 'else_clause') {
          const body = c.childForFieldName('body');
          if (body) walkBlock(body, steps, ctx);
        }
      }
      return;
    }
    case 'for_statement': {
      // `for X in iter: body` — taint of iter flows to X (best-effort).
      const target = stmt.childForFieldName('left');
      const iter = stmt.childForFieldName('right');
      const targetName = target && target.type === 'identifier' ? textOf(target, ctx.opts.fileContext.source) : null;
      if (iter) walkExpressionAsAssign(iter, targetName, steps, ctx);
      const body = stmt.childForFieldName('body');
      if (body) walkBlock(body, steps, ctx);
      return;
    }
    case 'while_statement': {
      const cond = stmt.childForFieldName('condition');
      if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
      const body = stmt.childForFieldName('body');
      if (body) walkBlock(body, steps, ctx);
      return;
    }
    case 'try_statement': {
      const body = stmt.childForFieldName('body');
      if (body) walkBlock(body, steps, ctx);
      // except / else / finally clauses
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'except_clause') {
          // Body is a block; walk it.
          for (let j = 0; j < c.namedChildCount; j++) {
            const cc = c.namedChild(j);
            if (cc && cc.type === 'block') walkBlock(cc, steps, ctx);
          }
        } else if (c.type === 'finally_clause' || c.type === 'else_clause') {
          for (let j = 0; j < c.namedChildCount; j++) {
            const cc = c.namedChild(j);
            if (cc && cc.type === 'block') walkBlock(cc, steps, ctx);
          }
        }
      }
      return;
    }
    case 'with_statement': {
      // `with expr as alias: body` — the alias takes taint from expr.
      // Each "with item" is `(expr, alias?)`.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'with_clause') {
          for (let j = 0; j < c.namedChildCount; j++) {
            const item = c.namedChild(j);
            if (item && item.type === 'with_item') {
              const expr = item.childForFieldName('value') ?? item.namedChild(0);
              const alias = item.childForFieldName('alias');
              const aliasName = alias && alias.type === 'identifier' ? textOf(alias, ctx.opts.fileContext.source) : null;
              if (expr) walkExpressionAsAssign(expr, aliasName, steps, ctx);
            }
          }
        } else if (c.type === 'block') {
          walkBlock(c, steps, ctx);
        }
      }
      return;
    }
    case 'block': {
      walkBlock(stmt, steps, ctx);
      return;
    }
    case 'function_definition':
    case 'class_definition':
    case 'decorated_definition':
      // Skip nested defs — they're analyzed as their own IrFunctions.
      return;
    case 'import_statement':
    case 'import_from_statement':
    case 'global_statement':
    case 'nonlocal_statement':
    case 'pass_statement':
    case 'break_statement':
    case 'continue_statement':
    case 'comment':
    case 'raise_statement':
      return;
    default:
      // Unknown statement: walk its children defensively.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (c) walkStatement(c, steps, ctx);
      }
      return;
  }
}

function handleAssignment(stmt: Node, steps: Step[], ctx: WalkCtx): void {
  const left = stmt.childForFieldName('left');
  const right = stmt.childForFieldName('right');
  if (!right) return;
  if (!left) {
    walkExpressionAsAssign(right, null, steps, ctx);
    return;
  }
  // Single identifier target.
  if (left.type === 'identifier') {
    const target = textOf(left, ctx.opts.fileContext.source);
    walkExpressionAsAssign(right, target, steps, ctx);
    return;
  }
  // Tuple unpacking: emit one assign per element from the same right expression.
  if (left.type === 'pattern_list' || left.type === 'tuple_pattern') {
    // First materialize the right to a temp, then assign the temp to each.
    const tmp = `<unpack@${steps.length}>`;
    walkExpressionAsAssign(right, tmp, steps, ctx);
    for (let i = 0; i < left.namedChildCount; i++) {
      const elem = left.namedChild(i);
      if (!elem) continue;
      if (elem.type === 'identifier') {
        steps.push({
          kind: 'assign',
          target: textOf(elem, ctx.opts.fileContext.source),
          from: tmp,
          loc: locOf(elem, ctx),
        });
      }
    }
    return;
  }
  // Subscript / attribute target: walk RHS for side effects without an l-value.
  walkExpressionAsAssign(right, null, steps, ctx);
}

/**
 * Lower an expression that's being assigned to `target` (or evaluated for
 * side effects when target=null). Emits source/assign/call steps.
 */
function walkExpressionAsAssign(
  expr: Node,
  target: LocalVar | null,
  steps: Step[],
  ctx: WalkCtx,
): void {
  switch (expr.type) {
    case 'parenthesized_expression':
    case 'expression_list': {
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'await': {
      const inner = expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'assignment': {
      // `x = foo()` as expression — treat as a statement-like assignment.
      handleAssignment(expr, steps, ctx);
      return;
    }
    case 'call': {
      const fn = expr.childForFieldName('function');
      const argList = expr.childForFieldName('arguments');
      const calleeText = textOf(fn, ctx.opts.fileContext.source);
      const callee = resolveCallee(calleeText, ctx);
      const args: (LocalVar | null)[] = [];
      const argTexts: string[] = [];
      if (argList) {
        for (let i = 0; i < argList.namedChildCount; i++) {
          const a = argList.namedChild(i);
          if (!a) continue;
          if (a.type === 'comment') continue;
          // keyword_argument: name=value — track value's taint via temp.
          let valueNode: Node = a;
          if (a.type === 'keyword_argument') {
            const v = a.childForFieldName('value');
            if (v) valueNode = v;
          }
          argTexts.push(textOf(valueNode, ctx.opts.fileContext.source));
          const direct = extractVarFromArg(valueNode, ctx.opts.fileContext.source);
          if (direct) {
            args.push(direct);
            continue;
          }
          const tmp = `<arg${args.length}@${steps.length}>`;
          walkExpressionAsAssign(valueNode, tmp, steps, ctx);
          args.push(tmp);
        }
      }
      steps.push({
        kind: 'call',
        target,
        callee,
        args,
        argTexts,
        loc: locOf(expr, ctx),
      });
      return;
    }
    case 'attribute':
    case 'subscript': {
      // Property / index access — text becomes a source-pattern key.
      if (target) {
        steps.push({
          kind: 'source',
          target,
          sourceText: textOf(expr, ctx.opts.fileContext.source),
          loc: locOf(expr, ctx),
        });
      }
      return;
    }
    case 'identifier': {
      if (target) {
        steps.push({
          kind: 'assign',
          target,
          from: textOf(expr, ctx.opts.fileContext.source),
          loc: locOf(expr, ctx),
        });
      }
      return;
    }
    case 'string': {
      // Plain string: inert. f-strings are 'string' too — inspect for interpolations.
      // tree-sitter-python emits `interpolation` named children inside f-strings.
      let foundInterp = false;
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (!c) continue;
        if (c.type === 'interpolation') {
          foundInterp = true;
          // The interpolated expression is the named child of `interpolation`.
          for (let j = 0; j < c.namedChildCount; j++) {
            const inner = c.namedChild(j);
            if (!inner) continue;
            if (inner.type === 'format_specifier' || inner.type === 'type_conversion') continue;
            walkExpressionAsAssign(inner, target, steps, ctx);
          }
        }
      }
      if (!foundInterp) {
        // Plain string. No taint contribution.
      }
      return;
    }
    case 'concatenated_string': {
      // Adjacent string literals or f-string parts.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'binary_operator':
    case 'boolean_operator': {
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      if (left) walkExpressionAsAssign(left, target, steps, ctx);
      if (right) walkExpressionAsAssign(right, target, steps, ctx);
      return;
    }
    case 'comparison_operator': {
      // Walk all operands for side effects without target taint.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, null, steps, ctx);
      }
      return;
    }
    case 'unary_operator':
    case 'not_operator': {
      const inner = expr.childForFieldName('argument') ?? expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'conditional_expression': {
      // a if cond else b — both branches may flow to target.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'list':
    case 'tuple':
    case 'set': {
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'dictionary': {
      for (let i = 0; i < expr.namedChildCount; i++) {
        const pair = expr.namedChild(i);
        if (!pair) continue;
        if (pair.type === 'pair') {
          const value = pair.childForFieldName('value');
          if (value) walkExpressionAsAssign(value, target, steps, ctx);
        }
      }
      return;
    }
    case 'list_comprehension':
    case 'set_comprehension':
    case 'generator_expression':
    case 'dictionary_comprehension': {
      // Walk the body expression(s); over-approximate by tainting target if any
      // sub-expression is tainted.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'lambda': {
      // Inert at call site (the lambda body is its own function — we don't
      // analyze it here).
      return;
    }
    case 'string_content':
    case 'integer':
    case 'float':
    case 'true':
    case 'false':
    case 'none':
    case 'ellipsis':
      return;
    default:
      // Defensive: walk children.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
  }
}

function emitReturnFromExpression(expr: Node, steps: Step[], ctx: WalkCtx): void {
  if (expr.type === 'identifier') {
    steps.push({
      kind: 'return',
      from: textOf(expr, ctx.opts.fileContext.source),
      loc: locOf(expr, ctx),
    });
    return;
  }
  const synthetic = `<retval@${steps.length}>`;
  walkExpressionAsAssign(expr, synthetic, steps, ctx);
  steps.push({ kind: 'return', from: synthetic, loc: locOf(expr, ctx) });
}

function extractVarFromArg(arg: Node, source: string): LocalVar | null {
  if (arg.type === 'identifier') return source.slice(arg.startIndex, arg.endIndex);
  if (arg.type === 'parenthesized_expression') {
    const inner = arg.namedChild(0);
    if (inner) return extractVarFromArg(inner, source);
  }
  return null;
}

function resolveCallee(calleeText: string, ctx: WalkCtx): CalleeRef {
  // Look up via Python callgraph resolution — if internal, return functionId.
  // Build the file map needed.
  const fileFunctions = new Map<string, typeof ctx.opts.fileContext.functions>();
  const fileImports = new Map<string, typeof ctx.opts.fileContext.imports>();
  for (const [fp, fctx] of ctx.opts.allFiles.entries()) {
    fileFunctions.set(fp, fctx.functions);
    fileImports.set(fp, fctx.imports);
  }
  const { calleeId, kind } = resolvePythonCallee(
    calleeText,
    ctx.opts.filePath,
    fileFunctions,
    fileImports,
    ctx.enclosingClass,
  );
  if (calleeId && kind === 'static') {
    return { kind: 'internal', functionId: calleeId, calleeText };
  }
  if (kind === 'static') {
    return { kind: 'external', calleeText };
  }
  return { kind: 'unresolved', calleeText };
}
