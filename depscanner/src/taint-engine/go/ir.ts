/**
 * Go IR lowerer for the cross-file taint engine.
 *
 * Walks tree-sitter Go AST and emits the same `Step[]` shape the TS lowerer
 * uses, so the propagator's worklist can interpret Go functions identically.
 *
 * Mapping:
 *   - `var x = expr`, `x := expr`, `x = expr` (single-LHS) → assign-shaped
 *     Steps. Multi-value forms `x, err := f()` and `x, err = f()` are split:
 *     each LHS receives a copy of the call's tainted return (over-
 *     approximate, sound).
 *   - `expr` statements → walked for embedded calls (sinks fire).
 *   - call_expression → Call step. Method calls (`receiver.Method(args)`)
 *     are emitted with calleeText `receiver.Method` (used by sink/source
 *     pattern matching, including the wildcard receiver `*.Query`).
 *     The selector_expression's `field` becomes the suffix; the `operand`
 *     is captured as-is in the calleeText.
 *   - return_statement → Return step. If the expression list has multiple
 *     returns, we emit a Return for each (worst-case taint propagation).
 *   - selector_expression as a value (not call) → Source step (e.g.
 *     `c.Body` when read as data, though Go doesn't surface request data
 *     this way often — most input arrives via method calls; matched by
 *     the call-source `(*)` pattern).
 *   - Composite literals, struct literals, `make(...)`, `new(...)` are
 *     treated as call-shaped (they can carry taint into the constructed
 *     value).
 *   - Non-Identifier call args get a synth temp (mirrors TS lowerer M3.0
 *     fix) so taint flows through `db.Query(fmt.Sprintf("...%s", x))`.
 */

import type { Node } from 'web-tree-sitter';
import type { CalleeRef, IrFunction, LocalVar, SourceLocation, Step } from '../ir';
import type { FunctionId } from '../types';

/** Context the lowerer needs to resolve internal calls. */
export interface GoLowerContext {
  filePath: string;
  /** The function (or source_file for module-init) being lowered. */
  funcId: FunctionId;
  /** Map AST node id → resolved internal FunctionId. */
  callExprToFuncId: Map<number, FunctionId>;
  /** External / unresolved-vs-internal classifier. */
  isExternalCall: (node: Node) => boolean;
}

export function lowerGoFunction(
  funcNode: Node,
  ctx: GoLowerContext,
): IrFunction {
  const params: LocalVar[] = [];
  let body: Node | null = null;

  if (funcNode.type === 'function_declaration' || funcNode.type === 'method_declaration') {
    const paramList = funcNode.childForFieldName('parameters');
    if (paramList) {
      for (let i = 0; i < paramList.namedChildCount; i++) {
        const param = paramList.namedChild(i);
        if (!param || param.type !== 'parameter_declaration') continue;
        // Multiple-name form: `x, y int` → 2 params share the type. Walk all
        // identifier-typed children before the type field.
        for (let j = 0; j < param.namedChildCount; j++) {
          const c = param.namedChild(j);
          if (c && c.type === 'identifier') params.push(c.text);
        }
      }
    }
    body = funcNode.childForFieldName('body');
  } else if (funcNode.type === 'source_file') {
    body = funcNode;
  }

  const steps: Step[] = [];
  if (body) walkBody(body, steps, ctx);
  return { id: ctx.funcId, params, steps };
}

function walkBody(body: Node, steps: Step[], ctx: GoLowerContext): void {
  if (body.type === 'source_file') {
    // Top-level: walk var/const/short decls + init() bodies (which are emitted
    // as separate functions, so we don't recurse into function bodies here).
    for (let i = 0; i < body.namedChildCount; i++) {
      const stmt = body.namedChild(i);
      if (!stmt) continue;
      if (stmt.type === 'function_declaration' || stmt.type === 'method_declaration') continue;
      walkStatement(stmt, steps, ctx);
    }
    return;
  }
  if (body.type === 'block') {
    for (let i = 0; i < body.namedChildCount; i++) {
      const c = body.namedChild(i);
      if (!c) continue;
      if (c.type === 'statement_list') {
        for (let j = 0; j < c.namedChildCount; j++) {
          const s = c.namedChild(j);
          if (s) walkStatement(s, steps, ctx);
        }
      } else {
        walkStatement(c, steps, ctx);
      }
    }
    return;
  }
  walkStatement(body, steps, ctx);
}

function walkStatement(stmt: Node, steps: Step[], ctx: GoLowerContext): void {
  switch (stmt.type) {
    case 'block':
    case 'statement_list':
      walkBody(stmt, steps, ctx);
      return;

    case 'short_var_declaration':
    case 'assignment_statement': {
      lowerAssign(stmt, steps, ctx);
      return;
    }

    case 'var_declaration': {
      // var x = expr; can hold multiple specs.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const spec = stmt.namedChild(i);
        if (!spec || spec.type !== 'var_spec') continue;
        lowerVarSpec(spec, steps, ctx);
      }
      return;
    }

    case 'const_declaration': {
      // Constants can't be tainted in practice but the literal init may
      // hold a call; walk for side effects.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const spec = stmt.namedChild(i);
        if (!spec || spec.type !== 'const_spec') continue;
        const value = spec.childForFieldName('value');
        if (value) walkExpressionList(value, null, steps, ctx);
      }
      return;
    }

    case 'expression_statement': {
      // `f(args)` or `obj.Method(args)`
      const expr = stmt.namedChild(0);
      if (expr) walkExpressionAsAssign(expr, null, steps, ctx);
      return;
    }

    case 'return_statement': {
      const exprList = stmt.namedChild(0); // expression_list
      if (!exprList || exprList.type !== 'expression_list') {
        steps.push({ kind: 'return', from: null, loc: locOf(stmt, ctx) });
        return;
      }
      // Emit a Return for each return value (we don't model multi-value
      // returns precisely; over-approximate by treating any return as the
      // function's potentially-tainted output).
      for (let i = 0; i < exprList.namedChildCount; i++) {
        const expr = exprList.namedChild(i);
        if (!expr) continue;
        emitReturnFromExpression(expr, steps, ctx);
      }
      if (exprList.namedChildCount === 0) {
        steps.push({ kind: 'return', from: null, loc: locOf(stmt, ctx) });
      }
      return;
    }

    case 'if_statement': {
      const cond = stmt.childForFieldName('condition');
      if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
      const init = stmt.childForFieldName('initializer');
      if (init) walkStatement(init, steps, ctx);
      const cons = stmt.childForFieldName('consequence');
      if (cons) walkStatement(cons, steps, ctx);
      const alt = stmt.childForFieldName('alternative');
      if (alt) walkStatement(alt, steps, ctx);
      return;
    }

    case 'for_statement': {
      // Walk init + condition + body. `range` form has range_clause.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'for_clause') {
          // for_clause has initializer, condition, update fields
          const init = c.childForFieldName('initializer');
          if (init) walkStatement(init, steps, ctx);
          const cond = c.childForFieldName('condition');
          if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
          const upd = c.childForFieldName('update');
          if (upd) walkStatement(upd, steps, ctx);
        } else if (c.type === 'range_clause') {
          // range_clause: left fields → expression-list. Treat like assign
          // from the iterable to each bound var.
          const left = c.childForFieldName('left');
          const right = c.childForFieldName('right');
          const rightVar = right ? extractVarFromArg(right) : null;
          if (left && left.type === 'expression_list' && right) {
            for (let j = 0; j < left.namedChildCount; j++) {
              const lhs = left.namedChild(j);
              if (lhs && lhs.type === 'identifier') {
                steps.push({
                  kind: 'assign',
                  target: lhs.text,
                  from: rightVar,
                  loc: locOf(lhs, ctx),
                });
              }
            }
          }
        } else if (c.type === 'block') {
          walkStatement(c, steps, ctx);
        }
      }
      return;
    }

    case 'expression_switch_statement': {
      const value = stmt.childForFieldName('value');
      if (value) walkExpressionAsAssign(value, null, steps, ctx);
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c || c.type !== 'expression_case' && c.type !== 'default_case') continue;
        for (let j = 0; j < c.namedChildCount; j++) {
          const inner = c.namedChild(j);
          if (!inner) continue;
          if (inner.type === 'expression_list') {
            // case values — no taint relevance, but walk for nested calls
            for (let k = 0; k < inner.namedChildCount; k++) {
              const e = inner.namedChild(k);
              if (e) walkExpressionAsAssign(e, null, steps, ctx);
            }
          } else if (inner.type === 'statement_list') {
            for (let k = 0; k < inner.namedChildCount; k++) {
              const s = inner.namedChild(k);
              if (s) walkStatement(s, steps, ctx);
            }
          }
        }
      }
      return;
    }

    case 'type_switch_statement': {
      // Walk the alias clause + each case body.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'type_case' || c.type === 'default_case') {
          for (let j = 0; j < c.namedChildCount; j++) {
            const inner = c.namedChild(j);
            if (inner && inner.type === 'statement_list') {
              for (let k = 0; k < inner.namedChildCount; k++) {
                const s = inner.namedChild(k);
                if (s) walkStatement(s, steps, ctx);
              }
            }
          }
        }
      }
      return;
    }

    case 'defer_statement':
    case 'go_statement': {
      const inner = stmt.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, null, steps, ctx);
      return;
    }

    case 'labeled_statement': {
      // skip label, walk the inner stmt
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (c && c.type !== 'label_name') walkStatement(c, steps, ctx);
      }
      return;
    }

    case 'select_statement': {
      // walk each case body
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'communication_case' || c.type === 'default_case') {
          for (let j = 0; j < c.namedChildCount; j++) {
            const inner = c.namedChild(j);
            if (inner && inner.type === 'statement_list') {
              for (let k = 0; k < inner.namedChildCount; k++) {
                const s = inner.namedChild(k);
                if (s) walkStatement(s, steps, ctx);
              }
            }
          }
        }
      }
      return;
    }

    case 'inc_statement':
    case 'dec_statement':
    case 'break_statement':
    case 'continue_statement':
    case 'goto_statement':
    case 'fallthrough_statement':
    case 'empty_statement':
      return;

    default:
      // Try descending: unknown stmt may wrap an inner expression we want
      // to walk for sink detection.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (isExpressionType(c.type)) {
          walkExpressionAsAssign(c, null, steps, ctx);
        }
      }
      return;
  }
}

function isExpressionType(t: string): boolean {
  return (
    t === 'call_expression' ||
    t === 'selector_expression' ||
    t === 'identifier' ||
    t === 'binary_expression' ||
    t === 'unary_expression' ||
    t === 'parenthesized_expression' ||
    t === 'type_assertion_expression' ||
    t === 'index_expression' ||
    t === 'composite_literal'
  );
}

/** Lower a `var spec` (var x [type] = expr | var x, y = a, b). */
function lowerVarSpec(spec: Node, steps: Step[], ctx: GoLowerContext): void {
  // var_spec has `name` (identifier) — possibly multiple names — and `value`
  // (expression_list) optional.
  const value = spec.childForFieldName('value');
  const names: Node[] = [];
  for (let i = 0; i < spec.namedChildCount; i++) {
    const c = spec.namedChild(i);
    if (c && c.type === 'identifier') names.push(c);
  }
  if (!value) return; // no init
  // value is an expression_list
  if (value.type !== 'expression_list') return;
  const exprs: Node[] = [];
  for (let i = 0; i < value.namedChildCount; i++) {
    const e = value.namedChild(i);
    if (e) exprs.push(e);
  }
  lowerMultiAssign(names.map((n) => n.text), exprs, steps, ctx, spec);
}

/** Lower `x := expr`, `x = expr`, including multi-LHS forms. */
function lowerAssign(stmt: Node, steps: Step[], ctx: GoLowerContext): void {
  const left = stmt.childForFieldName('left');
  const right = stmt.childForFieldName('right');
  if (!left || !right) return;

  const lhsNames: (string | null)[] = [];
  if (left.type === 'expression_list') {
    for (let i = 0; i < left.namedChildCount; i++) {
      const e = left.namedChild(i);
      if (!e) {
        lhsNames.push(null);
        continue;
      }
      if (e.type === 'identifier') {
        const name = e.text;
        if (name === '_') lhsNames.push(null);
        else lhsNames.push(name);
      } else {
        // selector / index / etc — we don't model field-write taint.
        lhsNames.push(null);
      }
    }
  }

  const rhsExprs: Node[] = [];
  if (right.type === 'expression_list') {
    for (let i = 0; i < right.namedChildCount; i++) {
      const e = right.namedChild(i);
      if (e) rhsExprs.push(e);
    }
  } else {
    rhsExprs.push(right);
  }

  lowerMultiAssign(lhsNames, rhsExprs, steps, ctx, stmt);
}

function lowerMultiAssign(
  lhsNames: (string | null)[],
  rhsExprs: Node[],
  steps: Step[],
  ctx: GoLowerContext,
  origin: Node,
): void {
  // Three cases:
  //   a) 1:1 — `x = expr`, `x, y = a, b`: pair up.
  //   b) N:1 — `x, err := f()` (N LHS, 1 RHS that returns N values): every
  //      LHS receives the same call's taint (over-approximate).
  //   c) 1:N — uncommon, not standard Go. Treat as 1:1 over min().
  if (rhsExprs.length === 1 && lhsNames.length > 1) {
    // N:1 — synthesize a temp for the call, then each LHS = temp.
    const tmp = `<call@${steps.length}>`;
    walkExpressionAsAssign(rhsExprs[0], tmp, steps, ctx);
    for (const name of lhsNames) {
      if (!name) continue;
      steps.push({
        kind: 'assign',
        target: name,
        from: tmp,
        loc: locOf(origin, ctx),
      });
    }
    return;
  }
  // 1:1 (or truncated)
  const n = Math.min(lhsNames.length, rhsExprs.length);
  for (let i = 0; i < n; i++) {
    const name = lhsNames[i];
    const expr = rhsExprs[i];
    if (!expr) continue;
    if (!name) {
      // walk for side effects only
      walkExpressionAsAssign(expr, null, steps, ctx);
      continue;
    }
    walkExpressionAsAssign(expr, name, steps, ctx);
  }
}

function walkExpressionList(
  exprList: Node,
  target: LocalVar | null,
  steps: Step[],
  ctx: GoLowerContext,
): void {
  if (exprList.type !== 'expression_list') {
    walkExpressionAsAssign(exprList, target, steps, ctx);
    return;
  }
  for (let i = 0; i < exprList.namedChildCount; i++) {
    const e = exprList.namedChild(i);
    if (e) walkExpressionAsAssign(e, target, steps, ctx);
  }
}

function walkExpressionAsAssign(
  expr: Node,
  target: LocalVar | null,
  steps: Step[],
  ctx: GoLowerContext,
): void {
  switch (expr.type) {
    case 'parenthesized_expression':
    case 'type_assertion_expression': {
      const inner = expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'unary_expression': {
      const operand = expr.childForFieldName('operand') ?? expr.namedChild(0);
      if (operand) walkExpressionAsAssign(operand, target, steps, ctx);
      return;
    }
    case 'call_expression': {
      lowerCall(expr, target, steps, ctx);
      return;
    }
    case 'selector_expression': {
      // Property access — emit Source step (the source pattern matcher
      // looks for `<receiver>.<field>` text).
      if (target) {
        steps.push({
          kind: 'source',
          target,
          sourceText: expr.text,
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
          from: expr.text,
          loc: locOf(expr, ctx),
        });
      }
      return;
    }
    case 'index_expression': {
      // arr[i] — treat as source-shaped read (so `req.params[\"x\"]`
      // matches `req.params.*`-style patterns).
      if (target) {
        steps.push({
          kind: 'source',
          target,
          sourceText: expr.text,
          loc: locOf(expr, ctx),
        });
      }
      return;
    }
    case 'binary_expression': {
      // taint flows from either side
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      if (left) walkExpressionAsAssign(left, target, steps, ctx);
      if (right) walkExpressionAsAssign(right, target, steps, ctx);
      return;
    }
    case 'composite_literal': {
      // struct{f: tainted} — taints whole literal
      const body = expr.childForFieldName('body');
      if (body) {
        for (let i = 0; i < body.namedChildCount; i++) {
          const elem = body.namedChild(i);
          if (!elem) continue;
          if (elem.type === 'keyed_element' || elem.type === 'literal_element') {
            for (let j = 0; j < elem.namedChildCount; j++) {
              const e = elem.namedChild(j);
              if (e) walkExpressionAsAssign(e, target, steps, ctx);
            }
          } else {
            walkExpressionAsAssign(elem, target, steps, ctx);
          }
        }
      }
      return;
    }
    case 'func_literal': {
      // closure — its body would be its own function in M3 semantics; for
      // M2 we don't recurse into nested functions during lowering (their
      // calls fire when the closure is invoked elsewhere).
      return;
    }
    case 'expression_list': {
      for (let i = 0; i < expr.namedChildCount; i++) {
        const e = expr.namedChild(i);
        if (e) walkExpressionAsAssign(e, target, steps, ctx);
      }
      return;
    }
    case 'interpreted_string_literal':
    case 'raw_string_literal':
    case 'int_literal':
    case 'float_literal':
    case 'rune_literal':
    case 'true':
    case 'false':
    case 'nil':
      return;
    default:
      // Unknown expr — try descending.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
  }
}

function lowerCall(
  expr: Node,
  target: LocalVar | null,
  steps: Step[],
  ctx: GoLowerContext,
): void {
  const fnNode = expr.childForFieldName('function');
  const argList = expr.childForFieldName('arguments');
  const calleeText = fnNode ? fnNode.text : '<unknown>';

  // Method-chain calls (`exec.Command(...).Run()`): the inner call is buried
  // in the outer fnNode's selector_expression operand. Lower it FIRST so its
  // sink/source effects fire — otherwise `exec.Command(userInput).Run()`
  // never sees the inner call as a sink.
  if (fnNode && fnNode.type === 'selector_expression') {
    const operand = fnNode.childForFieldName('operand');
    if (operand && operand.type === 'call_expression') {
      const tmp = `<recvCall@${steps.length}>`;
      lowerCall(operand, tmp, steps, ctx);
    }
  }

  const args: (LocalVar | null)[] = [];
  const argTexts: string[] = [];
  if (argList) {
    for (let i = 0; i < argList.namedChildCount; i++) {
      const a = argList.namedChild(i);
      if (!a) {
        args.push(null);
        argTexts.push('');
        continue;
      }
      argTexts.push(a.text);
      const direct = extractVarFromArg(a);
      if (direct) {
        args.push(direct);
        continue;
      }
      // Synth a temp so taint flows through fmt.Sprintf/string-concat args.
      const tmp = `<arg${i}@${steps.length}>`;
      walkExpressionAsAssign(a, tmp, steps, ctx);
      args.push(tmp);
    }
  }

  let callee: CalleeRef;
  const internalId = ctx.callExprToFuncId.get(expr.id);
  if (internalId) {
    callee = { kind: 'internal', functionId: internalId, calleeText };
  } else if (fnNode && ctx.isExternalCall(fnNode)) {
    callee = { kind: 'external', calleeText };
  } else {
    callee = { kind: 'unresolved', calleeText };
  }

  steps.push({
    kind: 'call',
    target,
    callee,
    args,
    argTexts,
    loc: locOf(expr, ctx),
  });
}

function emitReturnFromExpression(
  expr: Node,
  steps: Step[],
  ctx: GoLowerContext,
): void {
  if (expr.type === 'identifier') {
    steps.push({ kind: 'return', from: expr.text, loc: locOf(expr, ctx) });
    return;
  }
  const synth = `<retval@${steps.length}>`;
  walkExpressionAsAssign(expr, synth, steps, ctx);
  steps.push({ kind: 'return', from: synth, loc: locOf(expr, ctx) });
}

function extractVarFromArg(arg: Node): LocalVar | null {
  if (arg.type === 'identifier') return arg.text;
  if (arg.type === 'parenthesized_expression') {
    const inner = arg.namedChild(0);
    if (inner) return extractVarFromArg(inner);
  }
  if (arg.type === 'type_assertion_expression') {
    const inner = arg.namedChild(0);
    if (inner) return extractVarFromArg(inner);
  }
  return null;
}

function locOf(node: Node, ctx: GoLowerContext): SourceLocation {
  return {
    filePath: ctx.filePath,
    line: node.startPosition.row + 1,
    column: node.startPosition.column + 1,
  };
}
