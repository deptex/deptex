/**
 * Per-function IR lowerer for Rust (tree-sitter).
 *
 * Emits the same `Step[]` shape that the TS / Python / Go lowerers emit:
 *   - source: `target = <pattern matching a FrameworkSource>` (field/index access)
 *   - assign: `target = source` — copy taint between locals
 *   - call:   `[target =] callee(args)` — args carry taint, returns may flow back
 *   - return: `return [expr]` (or trailing-expression return)
 *
 * Like the other lowerers, this is intentionally over-approximating
 * (branches flatten, no alias analysis, no field-level taint). Non-Identifier
 * args synthesize a temp var so taint flows through `format!(...)`,
 * field access, nested calls, string concat, etc.
 *
 * Rust-specific shapes:
 *   - `function_item`        — declaration entry
 *   - `let_declaration`      — `let x = expr;` (with optional pattern destructuring)
 *   - `assignment_expression` — `x = expr` (statement-position)
 *   - `call_expression`      — function call
 *   - `method_call_expression` — `x.foo(...)` becomes calleeText `x.foo`
 *   - `field_expression`     — `x.field` becomes a source-shape read
 *   - `block`                — last expression is implicit return value
 *   - `return_expression`    — `return expr;`
 *   - `if_expression` / `match_expression` — branches walked separately
 *   - `match_arm`            — body lowered, pattern's bindings ignored
 *   - `for_expression` / `loop_expression` / `while_expression`
 *   - `try_expression`       — `x?` propagates taint of x
 *   - `await_expression`     — `expr.await` is pass-through
 *   - `tuple_expression` / `struct_expression` / `array_expression`
 *   - `string_literal` / `raw_string_literal` — inert
 *   - `closure_expression`   — body skipped (analyzed as own fn if registered)
 *   - `macro_invocation`     — emitted as call-shape with calleeText `name!`
 *
 * Known v1 limitations:
 *   - Lifetimes / `&` / `*` / `mut` are stripped from variable text — we
 *     never track ownership / borrow state.
 *   - `?`-style error propagation is treated as identity for the value
 *     channel; we don't model the error path at all.
 *   - Pattern-destructuring in `let` only binds the leading identifier in
 *     a `tuple_pattern` element-by-element from the same RHS temp; struct
 *     patterns / refutable patterns get one temp-share assignment per
 *     bound identifier.
 *   - `match` arms all fan in; no per-arm narrowing.
 *   - Macros (`format!`, `println!`, `vec!`, `log::info!`) are emitted as
 *     calls with `calleeText = "<name>!"`; their arguments are walked so
 *     taint flows through interpolation.
 *   - Closures aren't analyzed inline — their bodies are walked only if
 *     the callgraph registered them as separate functions (which our
 *     callgraph collector does NOT do for closures in M2).
 *   - Generic resolution / trait dispatch are not modeled.
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
import { resolveRustCallee } from './callgraph';
import type { RustFileContext } from './callgraph';

export interface LowerRustOptions {
  /** Workspace-relative file path. */
  filePath: string;
  /** Per-file context: tree, source, imports, functions. */
  fileContext: RustFileContext;
  /** All file contexts in the workspace, used by callee resolution. */
  allFiles: Map<string, RustFileContext>;
}

/**
 * Lower a Rust `function_item` (or the file root for the synthetic module
 * initializer) into the engine's IR.
 */
export function lowerRustFunction(
  funcId: FunctionId,
  funcNode: Node,
  opts: LowerRustOptions,
): IrFunction {
  const params: LocalVar[] = [];
  let body: Node | null = null;
  let isModule = false;

  if (funcNode.type === 'function_item') {
    const paramsNode = funcNode.childForFieldName('parameters');
    if (paramsNode) {
      for (let i = 0; i < paramsNode.namedChildCount; i++) {
        const p = paramsNode.namedChild(i);
        if (!p) continue;
        const name = paramNameOf(p, opts.fileContext.source);
        if (name) params.push(name);
        else params.push(`<param@${i}>`);
      }
    }
    body = funcNode.childForFieldName('body');
  } else if (funcNode.type === 'source_file') {
    isModule = true;
    body = funcNode;
  } else {
    isModule = true;
    body = funcNode;
  }

  const steps: Step[] = [];
  const enclosingType = enclosingImplType(funcNode, opts.fileContext.source);

  if (body) {
    const ctx: WalkCtx = { opts, enclosingType, isModule };
    if (body.type === 'block') {
      walkBlockBody(body, steps, ctx, /* asReturn= */ funcNode.type === 'function_item');
    } else if (body.type === 'source_file') {
      walkSourceFile(body, steps, ctx);
    } else {
      walkStatement(body, steps, ctx);
    }
  }

  return { id: funcId, params, steps };
}

interface WalkCtx {
  opts: LowerRustOptions;
  enclosingType: string | null;
  isModule: boolean;
}

function enclosingImplType(node: Node, source: string): string | null {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (cur.type === 'impl_item') {
      const typeNode = cur.childForFieldName('type');
      return typeNode ? textOf(typeNode, source) : null;
    }
  }
  return null;
}

function paramNameOf(p: Node, source: string): string | null {
  // Common parameter shapes:
  //   self_parameter           → `self` / `&self` / `&mut self`
  //   parameter                → `x: T`
  //   variadic_parameter       → `args: ...`
  if (p.type === 'self_parameter') return 'self';
  if (p.type === 'parameter') {
    const patternNode = p.childForFieldName('pattern');
    if (patternNode) return identifierFromPattern(patternNode, source);
    // Fallback: first identifier child.
    for (let i = 0; i < p.namedChildCount; i++) {
      const c = p.namedChild(i);
      if (c && c.type === 'identifier') return textOf(c, source);
    }
  }
  return null;
}

function identifierFromPattern(p: Node, source: string): string | null {
  if (p.type === 'identifier') return textOf(p, source);
  if (p.type === 'mut_pattern') {
    const inner = p.namedChild(0);
    if (inner) return identifierFromPattern(inner, source);
  }
  if (p.type === 'reference_pattern') {
    const inner = p.namedChild(0);
    if (inner) return identifierFromPattern(inner, source);
  }
  if (p.type === 'tuple_pattern' || p.type === 'tuple_struct_pattern') {
    // First identifier we find. Multi-binding is handled at the let-stmt
    // level via lowerLetWithPattern.
    for (let i = 0; i < p.namedChildCount; i++) {
      const c = p.namedChild(i);
      if (c) {
        const name = identifierFromPattern(c, source);
        if (name) return name;
      }
    }
  }
  if (p.type === 'struct_pattern') {
    // Bind the first field's value identifier.
    for (let i = 0; i < p.namedChildCount; i++) {
      const c = p.namedChild(i);
      if (!c) continue;
      if (c.type === 'field_pattern') {
        const valueNode = c.childForFieldName('value') ?? c.childForFieldName('name');
        if (valueNode) {
          const n = identifierFromPattern(valueNode, source);
          if (n) return n;
        }
      } else if (c.type === 'shorthand_field_identifier') {
        return textOf(c, source);
      }
    }
  }
  if (p.type === 'identifier') return textOf(p, source);
  return null;
}

/** Collect every leaf identifier bound by a pattern (for tuple/struct unpack). */
function collectPatternBindings(p: Node, source: string, out: string[]): void {
  if (!p) return;
  if (p.type === 'identifier') {
    out.push(textOf(p, source));
    return;
  }
  if (p.type === 'mut_pattern' || p.type === 'reference_pattern') {
    const inner = p.namedChild(0);
    if (inner) collectPatternBindings(inner, source, out);
    return;
  }
  if (
    p.type === 'tuple_pattern' ||
    p.type === 'tuple_struct_pattern' ||
    p.type === 'slice_pattern' ||
    p.type === 'or_pattern'
  ) {
    for (let i = 0; i < p.namedChildCount; i++) {
      const c = p.namedChild(i);
      if (c) collectPatternBindings(c, source, out);
    }
    return;
  }
  if (p.type === 'struct_pattern') {
    for (let i = 0; i < p.namedChildCount; i++) {
      const c = p.namedChild(i);
      if (!c) continue;
      if (c.type === 'field_pattern') {
        const valueNode = c.childForFieldName('value') ?? c.childForFieldName('name');
        if (valueNode) collectPatternBindings(valueNode, source, out);
      } else if (c.type === 'shorthand_field_identifier') {
        out.push(textOf(c, source));
      }
    }
    return;
  }
  // Literal / wildcard / ranges — no bindings.
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
 * Strip `&`, `&mut`, `*` operators from a variable-textual reference so the
 * propagator's local map sees the bare name. Mirrors the documented v1
 * decision: "Treat `&`/`*`/`mut` as no-ops at the IR layer".
 */
function stripRefMut(text: string): string {
  let t = text.trim();
  // Repeatedly peel leading `&`, `&mut `, `*`.
  for (;;) {
    if (t.startsWith('&mut ')) {
      t = t.slice(5).trim();
      continue;
    }
    if (t.startsWith('&')) {
      t = t.slice(1).trim();
      continue;
    }
    if (t.startsWith('*')) {
      t = t.slice(1).trim();
      continue;
    }
    break;
  }
  return t;
}

/**
 * Walk a `block` node — possibly emitting a return Step from its trailing
 * expression if `asReturn` is true (function bodies, match arm tails).
 */
function walkBlockBody(block: Node, steps: Step[], ctx: WalkCtx, asReturn: boolean): void {
  // tree-sitter-rust block: zero-or-more statements + optional trailing
  // expression. The last named child is the trailing expr if it isn't a
  // statement node-type.
  const children: Node[] = [];
  for (let i = 0; i < block.namedChildCount; i++) {
    const c = block.namedChild(i);
    if (c) children.push(c);
  }
  if (children.length === 0) return;

  const last = children[children.length - 1];
  const stmts = isStatement(last) ? children : children.slice(0, -1);
  const trailing = isStatement(last) ? null : last;

  for (const stmt of stmts) {
    walkStatement(stmt, steps, ctx);
  }
  if (trailing) {
    if (asReturn) {
      emitReturnFromExpression(trailing, steps, ctx);
    } else {
      walkExpressionAsAssign(trailing, null, steps, ctx);
    }
  }
}

function isStatement(node: Node): boolean {
  switch (node.type) {
    case 'expression_statement':
    case 'let_declaration':
    case 'function_item':
    case 'impl_item':
    case 'mod_item':
    case 'struct_item':
    case 'enum_item':
    case 'use_declaration':
    case 'trait_item':
    case 'type_item':
    case 'const_item':
    case 'static_item':
    case 'attribute_item':
    case 'inner_attribute_item':
    case 'macro_definition':
    case 'macro_rules_definition':
    case 'extern_crate_declaration':
    case 'foreign_mod_item':
    case 'empty_statement':
      return true;
    default:
      return false;
  }
}

/** Walk the source_file root for the synthetic module initializer. */
function walkSourceFile(root: Node, steps: Step[], ctx: WalkCtx): void {
  for (let i = 0; i < root.namedChildCount; i++) {
    const stmt = root.namedChild(i);
    if (!stmt) continue;
    walkStatement(stmt, steps, ctx);
  }
}

function walkStatement(stmt: Node, steps: Step[], ctx: WalkCtx): void {
  switch (stmt.type) {
    case 'expression_statement': {
      // A single expression child, sometimes wrapping a control-flow expr.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const inner = stmt.namedChild(i);
        if (inner) walkExpressionAsAssign(inner, null, steps, ctx);
      }
      return;
    }
    case 'let_declaration': {
      lowerLet(stmt, steps, ctx);
      return;
    }
    case 'function_item':
    case 'impl_item':
    case 'mod_item':
    case 'struct_item':
    case 'enum_item':
    case 'trait_item':
    case 'type_item':
    case 'const_item':
    case 'static_item':
    case 'use_declaration':
    case 'extern_crate_declaration':
    case 'foreign_mod_item':
    case 'macro_definition':
    case 'macro_rules_definition':
    case 'attribute_item':
    case 'inner_attribute_item':
    case 'empty_statement':
      // Nested defs are analyzed as their own IrFunctions; declarations are
      // inert for taint.
      return;
    default:
      // Fall back: treat as an expression for side effects.
      walkExpressionAsAssign(stmt, null, steps, ctx);
      return;
  }
}

function lowerLet(stmt: Node, steps: Step[], ctx: WalkCtx): void {
  const patternNode = stmt.childForFieldName('pattern');
  const valueNode = stmt.childForFieldName('value');
  if (!valueNode) {
    // `let x;` — no init.
    return;
  }
  if (!patternNode) {
    walkExpressionAsAssign(valueNode, null, steps, ctx);
    return;
  }
  // Single-identifier or simple ref/mut pattern: assign directly to that name.
  const single = identifierFromPattern(patternNode, ctx.opts.fileContext.source);
  const bindings: string[] = [];
  collectPatternBindings(patternNode, ctx.opts.fileContext.source, bindings);

  if (single && bindings.length <= 1) {
    walkExpressionAsAssign(valueNode, single, steps, ctx);
    return;
  }
  // Multi-binding pattern: lower the value to a temp, then assign every
  // bound identifier from the temp (over-approximate).
  const tmp = `<unpack@${steps.length}>`;
  walkExpressionAsAssign(valueNode, tmp, steps, ctx);
  for (const name of bindings) {
    if (!name) continue;
    steps.push({
      kind: 'assign',
      target: name,
      from: tmp,
      loc: locOf(patternNode, ctx),
    });
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
    case 'parenthesized_expression': {
      const inner = expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'reference_expression':
    case 'unary_expression': {
      // Take the inner expression, ignore the operator (`&`, `&mut`, `-`,
      // `!`, `*`).
      const inner = expr.childForFieldName('value') ?? expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'try_expression': {
      // `expr?` — taint of expr flows to target.
      const inner = expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'await_expression': {
      const inner = expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'type_cast_expression': {
      const inner = expr.childForFieldName('value') ?? expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'assignment_expression': {
      // `lhs = rhs`
      const lhs = expr.childForFieldName('left');
      const rhs = expr.childForFieldName('right');
      if (rhs) {
        const lhsName =
          lhs && (lhs.type === 'identifier' ? textOf(lhs, ctx.opts.fileContext.source) : null);
        walkExpressionAsAssign(rhs, lhsName ?? null, steps, ctx);
      }
      return;
    }
    case 'compound_assignment_expr': {
      // `x += rhs` — treat as combining rhs into x.
      const lhs = expr.childForFieldName('left');
      const rhs = expr.childForFieldName('right');
      const lhsName =
        lhs && (lhs.type === 'identifier' ? textOf(lhs, ctx.opts.fileContext.source) : null);
      if (rhs) walkExpressionAsAssign(rhs, lhsName ?? null, steps, ctx);
      return;
    }
    case 'call_expression': {
      lowerCall(expr, target, steps, ctx);
      return;
    }
    case 'method_call_expression': {
      lowerMethodCall(expr, target, steps, ctx);
      return;
    }
    case 'macro_invocation': {
      lowerMacroInvocation(expr, target, steps, ctx);
      return;
    }
    case 'field_expression': {
      // `x.field` — emit as source-shape read using full text.
      if (target) {
        steps.push({
          kind: 'source',
          target,
          sourceText: stripRefMut(textOf(expr, ctx.opts.fileContext.source)),
          loc: locOf(expr, ctx),
        });
      }
      return;
    }
    case 'index_expression': {
      // `x[i]` — also source-shape (over-approximate).
      if (target) {
        steps.push({
          kind: 'source',
          target,
          sourceText: stripRefMut(textOf(expr, ctx.opts.fileContext.source)),
          loc: locOf(expr, ctx),
        });
      }
      return;
    }
    case 'identifier': {
      if (target) {
        const name = stripRefMut(textOf(expr, ctx.opts.fileContext.source));
        steps.push({
          kind: 'assign',
          target,
          from: name,
          loc: locOf(expr, ctx),
        });
      }
      return;
    }
    case 'self': {
      if (target) {
        steps.push({
          kind: 'assign',
          target,
          from: 'self',
          loc: locOf(expr, ctx),
        });
      }
      return;
    }
    case 'block': {
      // Block-as-expression: walk statements, treat trailing expr as the
      // value flowing into target.
      walkBlockAsExpr(expr, target, steps, ctx);
      return;
    }
    case 'if_expression': {
      // Walk condition for side effects, then both branches taint target.
      const cond = expr.childForFieldName('condition');
      if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
      const cons = expr.childForFieldName('consequence');
      if (cons) walkExpressionAsAssign(cons, target, steps, ctx);
      const alt = expr.childForFieldName('alternative');
      if (alt) walkExpressionAsAssign(alt, target, steps, ctx);
      return;
    }
    case 'else_clause': {
      // Wraps a block or further `if`.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'if_let_expression': {
      // `if let pat = scrutinee { ... } else { ... }` — taint scrutinee
      // flows into bound identifiers; both branches flow to target.
      const scrutinee = expr.childForFieldName('value') ?? expr.childForFieldName('scrutinee');
      if (scrutinee) walkExpressionAsAssign(scrutinee, null, steps, ctx);
      const cons = expr.childForFieldName('consequence');
      if (cons) walkExpressionAsAssign(cons, target, steps, ctx);
      const alt = expr.childForFieldName('alternative');
      if (alt) walkExpressionAsAssign(alt, target, steps, ctx);
      return;
    }
    case 'match_expression': {
      // Walk scrutinee for side effects, then walk each arm body.
      const scrutinee = expr.childForFieldName('value') ?? expr.namedChild(0);
      if (scrutinee) walkExpressionAsAssign(scrutinee, null, steps, ctx);
      const body = expr.childForFieldName('body');
      if (body) {
        for (let i = 0; i < body.namedChildCount; i++) {
          const arm = body.namedChild(i);
          if (!arm) continue;
          if (arm.type === 'match_arm') {
            const armBody = arm.childForFieldName('value');
            if (armBody) walkExpressionAsAssign(armBody, target, steps, ctx);
          }
        }
      }
      return;
    }
    case 'for_expression': {
      // `for pat in iter { ... }` — iter taint flows to bound identifier(s).
      const patternNode = expr.childForFieldName('pattern');
      const value = expr.childForFieldName('value');
      const body = expr.childForFieldName('body');
      if (value && patternNode) {
        const single = identifierFromPattern(patternNode, ctx.opts.fileContext.source);
        if (single) {
          walkExpressionAsAssign(value, single, steps, ctx);
        } else {
          // Multi-binding pattern: synth temp.
          const tmp = `<for@${steps.length}>`;
          walkExpressionAsAssign(value, tmp, steps, ctx);
          const names: string[] = [];
          collectPatternBindings(patternNode, ctx.opts.fileContext.source, names);
          for (const n of names) {
            steps.push({
              kind: 'assign',
              target: n,
              from: tmp,
              loc: locOf(patternNode, ctx),
            });
          }
        }
      } else if (value) {
        walkExpressionAsAssign(value, null, steps, ctx);
      }
      if (body) walkExpressionAsAssign(body, null, steps, ctx);
      return;
    }
    case 'while_expression': {
      const cond = expr.childForFieldName('condition');
      if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
      const body = expr.childForFieldName('body');
      if (body) walkExpressionAsAssign(body, null, steps, ctx);
      return;
    }
    case 'while_let_expression': {
      const scrut = expr.childForFieldName('value') ?? expr.childForFieldName('scrutinee');
      if (scrut) walkExpressionAsAssign(scrut, null, steps, ctx);
      const body = expr.childForFieldName('body');
      if (body) walkExpressionAsAssign(body, null, steps, ctx);
      return;
    }
    case 'loop_expression': {
      const body = expr.childForFieldName('body');
      if (body) walkExpressionAsAssign(body, null, steps, ctx);
      return;
    }
    case 'return_expression': {
      // `return expr` — emit a Return Step. The trailing expression of a
      // function body is handled separately in walkBlockBody.
      const inner = expr.namedChild(0);
      if (inner) {
        emitReturnFromExpression(inner, steps, ctx);
      } else {
        steps.push({ kind: 'return', from: null, loc: locOf(expr, ctx) });
      }
      return;
    }
    case 'break_expression': {
      const inner = expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'continue_expression':
      return;
    case 'tuple_expression': {
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'array_expression': {
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'struct_expression': {
      // body has field_initializer children; walk each value.
      const body = expr.childForFieldName('body');
      if (body) {
        for (let i = 0; i < body.namedChildCount; i++) {
          const fi = body.namedChild(i);
          if (!fi) continue;
          if (fi.type === 'field_initializer') {
            const v = fi.childForFieldName('value');
            if (v) walkExpressionAsAssign(v, target, steps, ctx);
          } else if (fi.type === 'shorthand_field_initializer') {
            const inner = fi.namedChild(0);
            if (inner && target) {
              steps.push({
                kind: 'assign',
                target,
                from: textOf(inner, ctx.opts.fileContext.source),
                loc: locOf(fi, ctx),
              });
            }
          } else if (fi.type === 'base_field_initializer') {
            const inner = fi.namedChild(0);
            if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
          }
        }
      }
      return;
    }
    case 'binary_expression': {
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      if (left) walkExpressionAsAssign(left, target, steps, ctx);
      if (right) walkExpressionAsAssign(right, target, steps, ctx);
      return;
    }
    case 'range_expression': {
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
    }
    case 'closure_expression':
      // Body skipped — closures are analyzed separately if registered.
      return;
    case 'unsafe_block': {
      const inner = expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'async_block': {
      const inner = expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }
    case 'string_literal':
    case 'raw_string_literal':
    case 'integer_literal':
    case 'float_literal':
    case 'char_literal':
    case 'boolean_literal':
    case 'unit_expression':
      // Inert.
      return;
    case 'scoped_identifier': {
      // A path like `Foo::Bar` used as a value (e.g. enum constructor). Emit
      // as an assign from its text — usually unmatched, harmless.
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
    default:
      // Defensive: walk children, none of which we recognise.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (c) walkExpressionAsAssign(c, target, steps, ctx);
      }
      return;
  }
}

function walkBlockAsExpr(
  block: Node,
  target: LocalVar | null,
  steps: Step[],
  ctx: WalkCtx,
): void {
  // Walk all statements; the trailing expression (if any) flows to target.
  const children: Node[] = [];
  for (let i = 0; i < block.namedChildCount; i++) {
    const c = block.namedChild(i);
    if (c) children.push(c);
  }
  if (children.length === 0) return;
  const last = children[children.length - 1];
  const stmts = isStatement(last) ? children : children.slice(0, -1);
  const trailing = isStatement(last) ? null : last;
  for (const s of stmts) walkStatement(s, steps, ctx);
  if (trailing) walkExpressionAsAssign(trailing, target, steps, ctx);
}

function lowerCall(
  expr: Node,
  target: LocalVar | null,
  steps: Step[],
  ctx: WalkCtx,
): void {
  const fnNode = expr.childForFieldName('function');

  // tree-sitter-rust represents `recv.method(args)` as a call_expression
  // whose function child is a field_expression. Reroute that case to the
  // method-call lowerer so the receiver chain is recursively walked, sink
  // patterns like `*.arg(*)` match, and inner calls like `sqlx::query(...)`
  // emit their own steps. (There is no `method_call_expression` node type
  // in tree-sitter-rust 0.20+.)
  if (fnNode && fnNode.type === 'field_expression') {
    lowerMethodCallFromCallExpr(expr, fnNode, target, steps, ctx);
    return;
  }

  const argList = expr.childForFieldName('arguments');
  const calleeText = stripRefMut(fnNode ? textOf(fnNode, ctx.opts.fileContext.source) : '<unknown>');
  const callee = resolveCallee(calleeText, ctx);

  const args: (LocalVar | null)[] = [];
  const argTexts: string[] = [];
  if (argList) {
    for (let i = 0; i < argList.namedChildCount; i++) {
      const a = argList.namedChild(i);
      if (!a) continue;
      argTexts.push(textOf(a, ctx.opts.fileContext.source));
      const direct = extractVarFromArg(a, ctx.opts.fileContext.source);
      if (direct) {
        args.push(direct);
        continue;
      }
      const tmp = `<arg${args.length}@${steps.length}>`;
      walkExpressionAsAssign(a, tmp, steps, ctx);
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
}

/**
 * tree-sitter-rust shape: a method call `recv.method(args)` is parsed as a
 * `call_expression` whose function field is a `field_expression`. The
 * field_expression contains the receiver + method identifier; the
 * call_expression's `arguments` field has the method's args.
 *
 * Lower it like a method call: pre-walk the receiver chain (so nested calls
 * emit their own sink steps), build calleeText as `receiver_root.method`,
 * and treat the receiver as the implicit first argument so receiver-tainting
 * patterns like `*.arg(*)` (Command builders) match.
 */
function lowerMethodCallFromCallExpr(
  callExpr: Node,
  fieldExpr: Node,
  target: LocalVar | null,
  steps: Step[],
  ctx: WalkCtx,
): void {
  const receiver = fieldExpr.childForFieldName('value') ?? fieldExpr.namedChild(0);
  const methodNode = fieldExpr.childForFieldName('field') ?? fieldExpr.namedChild(1);
  const argList = callExpr.childForFieldName('arguments');
  const methodName = methodNode ? textOf(methodNode, ctx.opts.fileContext.source) : '';

  let receiverText = '';
  let receiverVar: LocalVar | null = null;

  if (receiver) {
    if (receiver.type === 'call_expression' || receiver.type === 'method_call_expression') {
      const tmp = `<recvCall@${steps.length}>`;
      walkExpressionAsAssign(receiver, tmp, steps, ctx);
      receiverVar = tmp;
      receiverText = stripRefMut(receiverRootText(receiver, ctx));
    } else if (receiver.type === 'identifier') {
      receiverText = stripRefMut(textOf(receiver, ctx.opts.fileContext.source));
      receiverVar = receiverText;
    } else if (receiver.type === 'self') {
      receiverText = 'self';
      receiverVar = 'self';
    } else if (receiver.type === 'await_expression' || receiver.type === 'try_expression') {
      // Unwrap and recurse — `x.await.method(...)` is a method call on the
      // value of `x.await`, which is itself a method-call shape.
      const tmp = `<recvAwait@${steps.length}>`;
      walkExpressionAsAssign(receiver, tmp, steps, ctx);
      receiverVar = tmp;
      receiverText = stripRefMut(receiverRootText(receiver, ctx));
    } else if (
      receiver.type === 'field_expression' ||
      receiver.type === 'scoped_identifier'
    ) {
      const tmp = `<recv@${steps.length}>`;
      walkExpressionAsAssign(receiver, tmp, steps, ctx);
      receiverVar = tmp;
      receiverText = stripRefMut(textOf(receiver, ctx.opts.fileContext.source));
    } else {
      const tmp = `<recv@${steps.length}>`;
      walkExpressionAsAssign(receiver, tmp, steps, ctx);
      receiverVar = tmp;
      receiverText = stripRefMut(textOf(receiver, ctx.opts.fileContext.source));
    }
  }

  const calleeText = receiverText ? `${receiverText}.${methodName}` : methodName;
  const callee = resolveCallee(calleeText, ctx);

  const args: (LocalVar | null)[] = [];
  const argTexts: string[] = [];
  if (receiverVar) {
    args.push(receiverVar);
    argTexts.push(receiverText);
  }
  if (argList) {
    for (let i = 0; i < argList.namedChildCount; i++) {
      const a = argList.namedChild(i);
      if (!a) continue;
      argTexts.push(textOf(a, ctx.opts.fileContext.source));
      const direct = extractVarFromArg(a, ctx.opts.fileContext.source);
      if (direct) {
        args.push(direct);
        continue;
      }
      const tmp = `<marg${args.length}@${steps.length}>`;
      walkExpressionAsAssign(a, tmp, steps, ctx);
      args.push(tmp);
    }
  }

  steps.push({
    kind: 'call',
    target,
    callee,
    args,
    argTexts,
    loc: locOf(callExpr, ctx),
  });
}

/**
 * For a chained method-call receiver like `sqlx::query(&sql).fetch_all(...)`
 * or `pool.get_ref().clone()` or `x.await`, return a short root-style text
 * suitable for prepending to the next method name. This avoids putting the
 * full multi-line chain into calleeText (which makes pattern matching brittle
 * and breaks `*.method(*)` patterns).
 */
function receiverRootText(node: Node, ctx: WalkCtx): string {
  if (node.type === 'call_expression') {
    const fn = node.childForFieldName('function');
    if (fn) {
      if (fn.type === 'field_expression') {
        const f = fn.childForFieldName('field') ?? fn.namedChild(1);
        return f ? textOf(f, ctx.opts.fileContext.source) : textOf(fn, ctx.opts.fileContext.source);
      }
      return textOf(fn, ctx.opts.fileContext.source);
    }
  }
  if (node.type === 'await_expression' || node.type === 'try_expression') {
    const inner = node.namedChild(0);
    return inner ? receiverRootText(inner, ctx) : '';
  }
  return textOf(node, ctx.opts.fileContext.source);
}

function lowerMethodCall(
  expr: Node,
  target: LocalVar | null,
  steps: Step[],
  ctx: WalkCtx,
): void {
  const receiver = expr.childForFieldName('receiver');
  const methodNode = expr.childForFieldName('method');
  const argList = expr.childForFieldName('arguments');
  const methodName = methodNode ? textOf(methodNode, ctx.opts.fileContext.source) : '';

  // Build calleeText for sink/source pattern matching:
  //   - `recv.method` when recv is an identifier (matches `*.method` and
  //     `recv.method`-style patterns).
  //   - When recv is a method-chain or call, lower it FIRST so its sink
  //     effects fire, then use the recv expression's text as the prefix
  //     (so `Command::new("sh").arg(x)` matches `*.arg(*)`).
  let receiverText = '';
  let receiverVar: LocalVar | null = null;

  if (receiver) {
    if (receiver.type === 'method_call_expression' || receiver.type === 'call_expression') {
      // Lower the inner call first so its sink/source side effects fire.
      const tmp = `<recvCall@${steps.length}>`;
      walkExpressionAsAssign(receiver, tmp, steps, ctx);
      receiverVar = tmp;
      // For pattern matching, use the receiver's source text — this lets
      // `*.arg(*)` and `Command::new(*).arg(*)` both match.
      receiverText = stripRefMut(textOf(receiver, ctx.opts.fileContext.source));
    } else if (receiver.type === 'identifier') {
      receiverText = stripRefMut(textOf(receiver, ctx.opts.fileContext.source));
      receiverVar = receiverText;
    } else if (receiver.type === 'self') {
      receiverText = 'self';
      receiverVar = 'self';
    } else if (
      receiver.type === 'field_expression' ||
      receiver.type === 'scoped_identifier'
    ) {
      // `obj.field.method(...)` or `Type::CONST.method(...)` — lower for
      // side effects, capture taint into a temp so propagator can see it.
      const tmp = `<recv@${steps.length}>`;
      walkExpressionAsAssign(receiver, tmp, steps, ctx);
      receiverVar = tmp;
      receiverText = stripRefMut(textOf(receiver, ctx.opts.fileContext.source));
    } else {
      receiverText = stripRefMut(textOf(receiver, ctx.opts.fileContext.source));
      const tmp = `<recv@${steps.length}>`;
      walkExpressionAsAssign(receiver, tmp, steps, ctx);
      receiverVar = tmp;
    }
  }

  const calleeText = receiverText ? `${receiverText}.${methodName}` : methodName;
  const callee = resolveCallee(calleeText, ctx);

  // The receiver itself is the implicit first argument (its taint matters
  // for `*.arg(*)`-style patterns where index 0 = receiver).
  const args: (LocalVar | null)[] = [];
  const argTexts: string[] = [];
  if (receiverVar) {
    args.push(receiverVar);
    argTexts.push(receiverText);
  }
  if (argList) {
    for (let i = 0; i < argList.namedChildCount; i++) {
      const a = argList.namedChild(i);
      if (!a) continue;
      argTexts.push(textOf(a, ctx.opts.fileContext.source));
      const direct = extractVarFromArg(a, ctx.opts.fileContext.source);
      if (direct) {
        args.push(direct);
        continue;
      }
      const tmp = `<marg${args.length}@${steps.length}>`;
      walkExpressionAsAssign(a, tmp, steps, ctx);
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
}

function lowerMacroInvocation(
  expr: Node,
  target: LocalVar | null,
  steps: Step[],
  ctx: WalkCtx,
): void {
  // Field-name lookup may return null on some tree-sitter-rust versions —
  // fall back to type-based lookup of the named children.
  let macroNode = expr.childForFieldName('macro');
  let tokenTree = expr.childForFieldName('token_tree');
  if (!macroNode || !tokenTree) {
    for (let i = 0; i < expr.namedChildCount; i++) {
      const c = expr.namedChild(i);
      if (!c) continue;
      if (!macroNode && (c.type === 'identifier' || c.type === 'scoped_identifier')) {
        macroNode = c;
      } else if (!tokenTree && c.type === 'token_tree') {
        tokenTree = c;
      }
    }
  }
  const macroBaseText = macroNode ? textOf(macroNode, ctx.opts.fileContext.source) : '<unknown>';
  const calleeText = `${macroBaseText}!`;

  // The token tree contains arguments as an opaque sequence; we walk every
  // identifier we see and treat them as args (best-effort; macros aren't
  // expanded). This lets `format!("...{}", user)` taint a temp from `user`.
  const args: (LocalVar | null)[] = [];
  const argTexts: string[] = [];
  if (tokenTree) {
    walkMacroTokens(tokenTree, args, argTexts, steps, ctx);
  }

  // Macros aren't function calls in the callgraph sense — emit as external.
  const callee: CalleeRef = { kind: 'external', calleeText };
  steps.push({
    kind: 'call',
    target,
    callee,
    args,
    argTexts,
    loc: locOf(expr, ctx),
  });
}

function walkMacroTokens(
  node: Node,
  args: (LocalVar | null)[],
  argTexts: string[],
  steps: Step[],
  ctx: WalkCtx,
): void {
  // Token trees mostly contain literals, identifiers, punctuation, and
  // nested token_trees. We pick up any identifier as a potential arg. For
  // nested expressions like `format!("{} {}", a.b, fn(x))` the parser
  // sometimes exposes `field_expression` / `call_expression` directly here;
  // walk those into temps so their taint flows.
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (!c) continue;
    if (c.type === 'identifier') {
      const name = textOf(c, ctx.opts.fileContext.source);
      if (name && name !== 'mut') {
        args.push(name);
        argTexts.push(name);
      }
      continue;
    }
    if (
      c.type === 'field_expression' ||
      c.type === 'index_expression' ||
      c.type === 'method_call_expression' ||
      c.type === 'call_expression' ||
      c.type === 'try_expression' ||
      c.type === 'await_expression'
    ) {
      const tmp = `<mtok${args.length}@${steps.length}>`;
      walkExpressionAsAssign(c, tmp, steps, ctx);
      args.push(tmp);
      argTexts.push(textOf(c, ctx.opts.fileContext.source));
      continue;
    }
    if (c.type === 'token_tree') {
      walkMacroTokens(c, args, argTexts, steps, ctx);
      continue;
    }
    // Literal / punctuation / etc — ignore.
  }
}

function emitReturnFromExpression(expr: Node, steps: Step[], ctx: WalkCtx): void {
  if (expr.type === 'identifier') {
    steps.push({
      kind: 'return',
      from: stripRefMut(textOf(expr, ctx.opts.fileContext.source)),
      loc: locOf(expr, ctx),
    });
    return;
  }
  const synthetic = `<retval@${steps.length}>`;
  walkExpressionAsAssign(expr, synthetic, steps, ctx);
  steps.push({ kind: 'return', from: synthetic, loc: locOf(expr, ctx) });
}

function extractVarFromArg(arg: Node, source: string): LocalVar | null {
  if (arg.type === 'identifier') return textOf(arg, source);
  if (arg.type === 'self') return 'self';
  if (arg.type === 'parenthesized_expression') {
    const inner = arg.namedChild(0);
    if (inner) return extractVarFromArg(inner, source);
  }
  if (arg.type === 'reference_expression' || arg.type === 'unary_expression') {
    const inner = arg.childForFieldName('value') ?? arg.namedChild(0);
    if (inner) return extractVarFromArg(inner, source);
  }
  return null;
}

function resolveCallee(calleeText: string, ctx: WalkCtx): CalleeRef {
  // Build the per-file maps the callgraph resolver expects.
  const fileFunctions = new Map<string, typeof ctx.opts.fileContext.functions>();
  const fileImports = new Map<string, typeof ctx.opts.fileContext.imports>();
  for (const [fp, fctx] of ctx.opts.allFiles.entries()) {
    fileFunctions.set(fp, fctx.functions);
    fileImports.set(fp, fctx.imports);
  }
  const { calleeId, kind } = resolveRustCallee(
    calleeText,
    ctx.opts.filePath,
    fileFunctions,
    fileImports,
    ctx.enclosingType,
  );
  if (calleeId && (kind === 'static' || kind === 'virtual')) {
    return { kind: 'internal', functionId: calleeId, calleeText };
  }
  if (kind === 'static') {
    return { kind: 'external', calleeText };
  }
  return { kind: 'unresolved', calleeText };
}
