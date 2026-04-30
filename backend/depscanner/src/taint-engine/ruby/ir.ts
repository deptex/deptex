/**
 * Per-function IR lowerer for Ruby (tree-sitter).
 *
 * Emits the same `Step[]` shape that the TS / Python lowerers emit:
 *   - source: `target = <pattern matching a FrameworkSource>` (property/index access)
 *   - assign: `target = source` — copy taint between locals
 *   - call:   `[target =] callee(args)` — args carry taint, returns may flow back
 *   - return: `return [expr]`
 *
 * Like the other lowerers, this is intentionally over-approximating
 * (branches are flattened, no alias analysis, no field-level taint).
 * Non-Identifier args synthesize a temp var so taint flows through string
 * interpolation, attribute access in args, nested calls, etc.
 *
 * Implicit returns: Ruby methods return the value of their last expression.
 * We emit a synthesized return Step for the last expression of a method
 * body when no explicit `return` was emitted along that path.
 *
 * Known v1 limitations:
 *   - Multi-assign / array destructuring (`a, b = expr`) taints both `a`
 *     and `b` from `expr`'s taint; field-level destructuring is not modeled.
 *   - Block params (`do |x|` / `{ |x| }`) over a tainted iterable taint the
 *     block param best-effort, but yields are not flowed across the block
 *     boundary.
 *   - `begin / rescue / ensure` exception bindings are not taint-tracked.
 *   - Heredocs render as a `string` node and follow the same interpolation
 *     handling as ordinary strings.
 *   - `method_missing`, `define_method`, and `Module#include` are not
 *     resolved.
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
import { resolveRubyCallee } from './callgraph';
import type { RubyFileContext } from './callgraph';

export interface LowerRubyOptions {
  /** Workspace-relative file path. */
  filePath: string;
  /** Per-file context: tree, source, imports, functions. */
  fileContext: RubyFileContext;
  /** All file contexts in the workspace, used by callee resolution. */
  allFiles: Map<string, RubyFileContext>;
}

/**
 * Lower a Ruby `method` / `singleton_method` (or the file root for the
 * synthetic module initializer) into the engine's IR.
 */
export function lowerRubyMethod(
  funcId: FunctionId,
  funcNode: Node,
  opts: LowerRubyOptions,
): IrFunction {
  const params: LocalVar[] = [];
  let body: Node | null = null;
  let isModule = false;

  if (funcNode.type === 'method' || funcNode.type === 'singleton_method') {
    const paramsNode =
      funcNode.childForFieldName('parameters') ?? findChildOfType(funcNode, 'method_parameters');
    if (paramsNode) {
      for (let i = 0; i < paramsNode.namedChildCount; i++) {
        const p = paramsNode.namedChild(i);
        if (!p) continue;
        const name = paramNameOf(p, opts.fileContext.source);
        params.push(name ?? `<param@${i}>`);
      }
    }
    body = funcNode.childForFieldName('body') ?? findChildOfType(funcNode, 'body_statement');
    // Some grammar variants don't expose `body` as a field; fall back to
    // walking direct children for a body_statement.
    if (!body) {
      for (let i = 0; i < funcNode.namedChildCount; i++) {
        const c = funcNode.namedChild(i);
        if (c && c.type === 'body_statement') {
          body = c;
          break;
        }
      }
    }
  } else if (funcNode.type === 'program') {
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
    walkBlock(body, steps, ctx, /*isMethodBody*/ !isModule);
  }

  return { id: funcId, params, steps };
}

interface WalkCtx {
  opts: LowerRubyOptions;
  enclosingClass: string | null;
  isModule: boolean;
}

function enclosingClassOf(node: Node, source: string): string | null {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (cur.type === 'class' || cur.type === 'module') {
      const nameNode = cur.childForFieldName('name');
      if (nameNode) {
        const text = source.slice(nameNode.startIndex, nameNode.endIndex);
        const last = text.split('::').pop()!.trim();
        if (last) return last;
      }
    }
  }
  return null;
}

function paramNameOf(p: Node, source: string): string | null {
  // Common param shapes in tree-sitter-ruby:
  //   identifier              → `x`
  //   optional_parameter      → `x = 1`  (has `name` field)
  //   keyword_parameter       → `x:` / `x: default`
  //   splat_parameter         → `*args`
  //   hash_splat_parameter    → `**kwargs`
  //   block_parameter         → `&blk`
  //   destructured_parameter  → `(a, b)`
  if (p.type === 'identifier') return textOf(p, source);
  if (
    p.type === 'optional_parameter' ||
    p.type === 'keyword_parameter' ||
    p.type === 'block_parameter'
  ) {
    const nameNode = p.childForFieldName('name');
    if (nameNode) return textOf(nameNode, source);
  }
  if (p.type === 'splat_parameter' || p.type === 'hash_splat_parameter') {
    const inner = p.namedChild(0);
    if (inner) return textOf(inner, source);
    // `*` / `**` with no name.
    return null;
  }
  if (p.type === 'destructured_parameter') {
    // Use the textual form as a synthetic param name.
    return textOf(p, source);
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

function findChildOfType(node: Node, type: string): Node | null {
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child && child.type === type) return child;
  }
  return null;
}

/**
 * Walk a block (method body, program root, do/end/{} block, body_statement)
 * and emit Steps in syntactic order. Recurses into nested blocks (if/unless/
 * while/until/for/case/begin). Skips nested method/class definitions — the
 * caller analyzes those as separate IrFunctions.
 *
 * If `isMethodBody` is true, the LAST top-level statement is also emitted
 * as an implicit `return` (Ruby semantics).
 */
function walkBlock(node: Node, steps: Step[], ctx: WalkCtx, isMethodBody = false): void {
  const stmts: Node[] = [];
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (c) stmts.push(c);
  }
  for (let i = 0; i < stmts.length; i++) {
    const stmt = stmts[i];
    const isLast = isMethodBody && i === stmts.length - 1;
    walkStatement(stmt, steps, ctx, isLast);
  }
}

function walkStatement(stmt: Node, steps: Step[], ctx: WalkCtx, isImplicitReturn = false): void {
  switch (stmt.type) {
    case 'method':
    case 'singleton_method':
    case 'class':
    case 'module':
      // Skip nested defs — analyzed as their own IrFunctions.
      return;
    case 'comment':
      return;
    case 'assignment':
    case 'operator_assignment': {
      handleAssignment(stmt, steps, ctx);
      return;
    }
    case 'multiple_assignment': {
      handleMultipleAssignment(stmt, steps, ctx);
      return;
    }
    case 'return': {
      // `return [expr]`
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
    case 'if':
    case 'unless': {
      const cond = stmt.childForFieldName('condition');
      if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
      const consequence = stmt.childForFieldName('consequence');
      if (consequence) walkStatement(consequence, steps, ctx);
      // Walk alternative children (elsif / else)
      const alt = stmt.childForFieldName('alternative');
      if (alt) walkStatement(alt, steps, ctx);
      // Some grammars expose then/else as separate clauses; handle them.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'elsif' || c.type === 'else') {
          walkStatement(c, steps, ctx);
        } else if (c.type === 'then') {
          walkStatement(c, steps, ctx);
        }
      }
      return;
    }
    case 'elsif': {
      const cond = stmt.childForFieldName('condition');
      if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
      const consequence = stmt.childForFieldName('consequence');
      if (consequence) walkStatement(consequence, steps, ctx);
      const alt = stmt.childForFieldName('alternative');
      if (alt) walkStatement(alt, steps, ctx);
      return;
    }
    case 'else':
    case 'then':
    case 'do': {
      // Body is the named children.
      walkBlock(stmt, steps, ctx);
      return;
    }
    case 'while':
    case 'until':
    case 'while_modifier':
    case 'until_modifier': {
      const cond = stmt.childForFieldName('condition');
      if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
      const body = stmt.childForFieldName('body');
      if (body) walkStatement(body, steps, ctx);
      return;
    }
    case 'for': {
      const target = stmt.childForFieldName('pattern') ?? stmt.childForFieldName('left');
      const iter = stmt.childForFieldName('value') ?? stmt.childForFieldName('right');
      const targetName =
        target && target.type === 'identifier' ? textOf(target, ctx.opts.fileContext.source) : null;
      if (iter) walkExpressionAsAssign(iter, targetName, steps, ctx);
      const body = stmt.childForFieldName('body');
      if (body) walkStatement(body, steps, ctx);
      return;
    }
    case 'case':
    case 'case_match': {
      const value = stmt.childForFieldName('value');
      if (value) walkExpressionAsAssign(value, null, steps, ctx);
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'when' || c.type === 'in_clause' || c.type === 'else') {
          walkStatement(c, steps, ctx);
        }
      }
      return;
    }
    case 'when':
    case 'in_clause': {
      // Walk the body; pattern expressions are inert for taint.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'then') {
          walkStatement(c, steps, ctx);
        } else if (c.type === 'pattern' || c.type === 'binary' || c.type === 'array') {
          // pattern — walk for source side effects only.
          walkExpressionAsAssign(c, null, steps, ctx);
        } else {
          walkStatement(c, steps, ctx);
        }
      }
      return;
    }
    case 'begin': {
      // begin / rescue / ensure / else
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'body_statement' || c.type === 'rescue' || c.type === 'ensure' || c.type === 'else') {
          walkStatement(c, steps, ctx);
        }
      }
      return;
    }
    case 'rescue':
    case 'ensure': {
      const body = stmt.childForFieldName('body');
      if (body) walkStatement(body, steps, ctx);
      // Some grammar variants expose body as direct named children.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'body_statement') walkStatement(c, steps, ctx);
      }
      return;
    }
    case 'body_statement':
    case 'block_body':
    case 'program': {
      walkBlock(stmt, steps, ctx);
      return;
    }
    case 'break':
    case 'next':
    case 'redo':
    case 'retry':
      return;
    default:
      // Treat unknown statements as expressions — implicit return if last.
      if (isImplicitReturn) {
        emitReturnFromExpression(stmt, steps, ctx);
      } else {
        walkExpressionAsAssign(stmt, null, steps, ctx);
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
  // Simple identifier / instance variable / class variable / global variable.
  if (
    left.type === 'identifier' ||
    left.type === 'instance_variable' ||
    left.type === 'class_variable' ||
    left.type === 'global_variable'
  ) {
    const target = textOf(left, ctx.opts.fileContext.source);
    walkExpressionAsAssign(right, target, steps, ctx);
    return;
  }
  // Constant assignment `Foo = bar`.
  if (left.type === 'constant') {
    const target = textOf(left, ctx.opts.fileContext.source);
    walkExpressionAsAssign(right, target, steps, ctx);
    return;
  }
  // Subscript / element-ref / call (setter): walk RHS for side effects.
  walkExpressionAsAssign(right, null, steps, ctx);
}

function handleMultipleAssignment(stmt: Node, steps: Step[], ctx: WalkCtx): void {
  const left = stmt.childForFieldName('left');
  const right = stmt.childForFieldName('right');
  if (!right || !left) return;
  // Materialize the RHS to a temp, then copy to each LHS element.
  const tmp = `<unpack@${steps.length}>`;
  walkExpressionAsAssign(right, tmp, steps, ctx);
  const elems: Node[] = [];
  for (let i = 0; i < left.namedChildCount; i++) {
    const c = left.namedChild(i);
    if (c) elems.push(c);
  }
  for (const elem of elems) {
    if (elem.type === 'identifier' || elem.type === 'instance_variable') {
      steps.push({
        kind: 'assign',
        target: textOf(elem, ctx.opts.fileContext.source),
        from: tmp,
        loc: locOf(elem, ctx),
      });
    }
  }
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
    case 'parenthesized_statements':
    case 'parenthesized_expression': {
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'assignment':
    case 'operator_assignment': {
      handleAssignment(expr, steps, ctx);
      return;
    }
    case 'multiple_assignment': {
      handleMultipleAssignment(expr, steps, ctx);
      return;
    }
    case 'call':
    case 'method_call': {
      handleCall(expr, target, steps, ctx);
      return;
    }
    case 'element_reference': {
      // `obj[key]` — model as a property/source access. Use the textual
      // form so YAML patterns like `params[*]` / `params.*` can match.
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
    case 'scope_resolution': {
      // `Foo::Bar` — treat as an inert constant reference.
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
    case 'identifier':
    case 'instance_variable':
    case 'class_variable':
    case 'global_variable':
    case 'constant': {
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
    case 'string':
    case 'heredoc_beginning':
    case 'heredoc_body':
    case 'string_array':
    case 'symbol_array':
    case 'chained_string': {
      // Plain string or interpolated string. Look for `interpolation`
      // children — each contributes its expression's taint to target.
      let foundInterp = false;
      const visit = (n: Node): void => {
        for (let i = 0; i < n.namedChildCount; i++) {
          const c = n.namedChild(i);
          if (!c) continue;
          if (c.type === 'interpolation') {
            foundInterp = true;
            for (let j = 0; j < c.namedChildCount; j++) {
              const inner = c.namedChild(j);
              if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
            }
          } else if (c.type === 'string') {
            visit(c);
          }
        }
      };
      visit(expr);
      if (!foundInterp) {
        // Plain string. No taint contribution.
      }
      return;
    }
    case 'binary':
    case 'unary': {
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      const operand = expr.childForFieldName('operand');
      if (left) walkExpressionAsAssign(left, target, steps, ctx);
      if (right) walkExpressionAsAssign(right, target, steps, ctx);
      if (operand) walkExpressionAsAssign(operand, target, steps, ctx);
      return;
    }
    case 'conditional':
    case 'ternary': {
      // `cond ? a : b` — both branches may flow to target.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'if':
    case 'unless':
    case 'case':
    case 'case_match': {
      // Expression-position if/unless/case — walk for side effects.
      walkStatement(expr, steps, ctx);
      return;
    }
    case 'array':
    case 'hash': {
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (!c) continue;
        if (c.type === 'pair') {
          const value = c.childForFieldName('value');
          if (value) walkExpressionAsAssign(value, target, steps, ctx);
        } else {
          walkExpressionAsAssign(c, target, steps, ctx);
        }
      }
      return;
    }
    case 'block':
    case 'do_block':
    case 'lambda':
    case 'proc': {
      // The block body is its own logical scope — walk it for side
      // effects (calls / sources fire) but don't propagate its return
      // value back to target.
      const body = expr.childForFieldName('body');
      if (body) walkStatement(body, steps, ctx);
      return;
    }
    case 'integer':
    case 'float':
    case 'rational':
    case 'imaginary':
    case 'true':
    case 'false':
    case 'nil':
    case 'self':
    case 'simple_symbol':
    case 'bare_symbol':
    case 'regex':
    case 'character':
      return;
    case 'range': {
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'splat_argument':
    case 'hash_splat_argument':
    case 'block_argument': {
      const inner = expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'pair': {
      const value = expr.childForFieldName('value');
      if (value) walkExpressionAsAssign(value, target, steps, ctx);
      return;
    }
    default:
      // Defensive: walk children.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
  }
}

function handleCall(
  expr: Node,
  target: LocalVar | null,
  steps: Step[],
  ctx: WalkCtx,
): void {
  const methodNode = expr.childForFieldName('method');
  const recvNode = expr.childForFieldName('receiver');
  const argList = expr.childForFieldName('arguments');
  const blockNode = expr.childForFieldName('block');

  let calleeText: string;
  if (recvNode) {
    const recvText = textOf(recvNode, ctx.opts.fileContext.source);
    const methodText = textOf(methodNode, ctx.opts.fileContext.source);
    // Normalize `Foo::bar` to `Foo.bar` so spec patterns can match either form.
    const recvPlain = recvText.replace(/::/g, '.');
    calleeText = methodText ? `${recvPlain}.${methodText}` : recvPlain;
  } else {
    calleeText = textOf(methodNode, ctx.opts.fileContext.source);
  }

  const callee = resolveCallee(calleeText, ctx);
  const args: (LocalVar | null)[] = [];
  const argTexts: string[] = [];
  if (argList) {
    for (let i = 0; i < argList.namedChildCount; i++) {
      const a = argList.namedChild(i);
      if (!a) continue;
      if (a.type === 'comment') continue;
      // `pair` (keyword arg) — track the value's taint.
      let valueNode: Node = a;
      if (a.type === 'pair') {
        const v = a.childForFieldName('value');
        if (v) valueNode = v;
      } else if (a.type === 'splat_argument' || a.type === 'hash_splat_argument' || a.type === 'block_argument') {
        const inner = a.namedChild(0);
        if (inner) valueNode = inner;
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

  // Walk the trailing block (do...end / { ... }) for side effects only.
  if (blockNode) {
    walkStatement(blockNode, steps, ctx);
  }
}

function emitReturnFromExpression(expr: Node, steps: Step[], ctx: WalkCtx): void {
  if (
    expr.type === 'identifier' ||
    expr.type === 'instance_variable' ||
    expr.type === 'class_variable' ||
    expr.type === 'global_variable' ||
    expr.type === 'constant'
  ) {
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
  if (
    arg.type === 'identifier' ||
    arg.type === 'instance_variable' ||
    arg.type === 'class_variable' ||
    arg.type === 'global_variable'
  ) {
    return source.slice(arg.startIndex, arg.endIndex);
  }
  if (arg.type === 'parenthesized_expression' || arg.type === 'parenthesized_statements') {
    const inner = arg.namedChild(0);
    if (inner) return extractVarFromArg(inner, source);
  }
  return null;
}

function resolveCallee(calleeText: string, ctx: WalkCtx): CalleeRef {
  // Look up via Ruby callgraph resolution — if internal, return functionId.
  const fileFunctions = new Map<string, typeof ctx.opts.fileContext.functions>();
  const fileImports = new Map<string, typeof ctx.opts.fileContext.imports>();
  for (const [fp, fctx] of ctx.opts.allFiles.entries()) {
    fileFunctions.set(fp, fctx.functions);
    fileImports.set(fp, fctx.imports);
  }
  const { calleeId, kind } = resolveRubyCallee(
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
