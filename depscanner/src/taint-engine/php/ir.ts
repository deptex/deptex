/**
 * Per-function IR lowerer for PHP (tree-sitter).
 *
 * Emits the same `Step[]` shape as the TS / Python / Java / Go lowerers:
 *   - source: `target = <pattern matching a FrameworkSource>` (member/index access)
 *   - assign: `target = source` — copy taint between locals
 *   - call:   `[target =] callee(args)` — args carry taint, returns may flow back
 *   - return: `return [expr]`
 *
 * PHP-specifics handled here:
 *   - Variables are always written `$name`. We strip the leading `$` for
 *     LocalVar names so the engine's per-function env is keyed consistently
 *     across `$foo` and `foo`.
 *   - `$obj->prop` and `Foo::CONST` and `$arr[$k]` lower to `source` steps so
 *     framework patterns like `request->input.*` match.
 *   - String interpolation `"hello $x"` (encapsed_string) walks each
 *     interpolation child as if it were a sub-expression contributing taint
 *     to the target.
 *   - `echo $x` and `print $x` emit a synthetic call step with calleeText
 *     `echo` / `print` so frameworks can declare them as XSS sinks if desired.
 *   - `function_call_expression` / `member_call_expression` /
 *     `scoped_call_expression` / `object_creation_expression` all lower to
 *     `call` steps. Object creation uses calleeText `new ClassName`.
 *   - Synthesizes tmp vars for non-Variable args (mirrors python's lowerer)
 *     so taint flows through string concatenation, nested calls, etc.
 *
 * Known v1 limitations (documented for follow-up):
 *   - `__call`/`__get` magic methods are not modeled.
 *   - Closure `use ($var)` captures aren't bound — the closure body inherits
 *     the outer env shape only by walking textual order.
 *   - `list($a, $b) = $arr` / array destructuring assigns one assign per
 *     element from the rhs as a tmp; field-level destructuring isn't modeled.
 *   - Reference-taking `&$foo` is treated as plain `$foo`.
 *   - `eval('...')` body is opaque.
 *   - Variable variables `$$x` are unresolved — no taint flows through.
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
import { resolvePhpCallee } from './callgraph';
import type { PhpFileContext } from './callgraph';

export interface LowerPhpOptions {
  /** Workspace-relative file path. */
  filePath: string;
  /** Per-file context: tree, source, imports, functions. */
  fileContext: PhpFileContext;
  /** All file contexts in the workspace, used by callee resolution. */
  allFiles: Map<string, PhpFileContext>;
  /** Built once during callgraph construction; passed through. */
  globalFunctionsByFqn: Map<string, FunctionId>;
  /** classFqn → filePath. */
  classFqnToFile: Map<string, string>;
}

/**
 * Lower a PHP `function_definition` / `method_declaration` (or the file root,
 * for the synthetic file initializer) into the engine's IR.
 */
export function lowerPhpFunction(
  funcId: FunctionId,
  funcNode: Node,
  opts: LowerPhpOptions,
): IrFunction {
  const params: LocalVar[] = [];
  let body: Node | null = null;
  let isFile = false;

  if (funcNode.type === 'function_definition' || funcNode.type === 'method_declaration') {
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
  } else if (funcNode.type === 'program' || funcNode.type === 'php_tag') {
    isFile = true;
    body = funcNode;
  } else {
    // Defensive: unknown caller — treat as file root.
    isFile = true;
    body = funcNode;
  }

  const steps: Step[] = [];
  const enclosingClass = enclosingClassOf(funcNode, opts.fileContext.source);

  // Seed local types from parameter type hints + same-function `$x = new C()` later
  // in walkAssignment so resolution can see them.
  const localTypes = new Map<string, string>();
  if (!isFile) {
    seedTypesFromParams(funcNode, opts.fileContext.source, localTypes);
  }

  if (body) {
    const ctx: WalkCtx = {
      opts,
      enclosingClass,
      isFile,
      localTypes,
    };
    walkBlock(body, steps, ctx);
  }

  return { id: funcId, params, steps };
}

interface WalkCtx {
  opts: LowerPhpOptions;
  enclosingClass: string | null;
  isFile: boolean;
  localTypes: Map<string, string>;
}

function enclosingClassOf(node: Node, source: string): string | null {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (
      cur.type === 'class_declaration' ||
      cur.type === 'trait_declaration' ||
      cur.type === 'interface_declaration' ||
      cur.type === 'enum_declaration'
    ) {
      const nameNode = cur.childForFieldName('name') ?? findChildOfType(cur, 'name');
      return textOf(nameNode, source) || null;
    }
  }
  return null;
}

function findChildOfType(node: Node, type: string): Node | null {
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child && child.type === type) return child;
  }
  return null;
}

function lastSegment(fqn: string): string {
  const stripped = fqn.startsWith('\\') ? fqn.slice(1) : fqn;
  const idx = stripped.lastIndexOf('\\');
  return idx >= 0 ? stripped.slice(idx + 1) : stripped;
}

function seedTypesFromParams(funcNode: Node, source: string, types: Map<string, string>): void {
  const params = funcNode.childForFieldName('parameters');
  if (!params) return;
  for (let i = 0; i < params.namedChildCount; i++) {
    const p = params.namedChild(i);
    if (!p) continue;
    if (p.type !== 'simple_parameter' && p.type !== 'variadic_parameter' && p.type !== 'property_promotion_parameter') continue;
    const typeNode = p.childForFieldName('type');
    const nameNode = p.childForFieldName('name');
    if (typeNode && nameNode && nameNode.type === 'variable_name') {
      const typeText = textOf(typeNode, source);
      const simple = lastSegment(typeText.replace(/^\?/, '').split('|')[0].trim());
      if (simple && /^[A-Za-z_][\w\\]*$/.test(simple)) {
        const varName = textOf(nameNode, source).replace(/^\$/, '');
        if (varName) types.set(varName, simple);
      }
    }
  }
}

function paramNameOf(p: Node, source: string): string | null {
  // simple_parameter: `Type $name = default`, `&$name`, `...$name` (variadic_parameter)
  // property_promotion_parameter: `public Type $name`
  if (p.type === 'simple_parameter' || p.type === 'variadic_parameter' || p.type === 'property_promotion_parameter') {
    const nameNode = p.childForFieldName('name');
    if (nameNode) return textOf(nameNode, source).replace(/^\$/, '');
  }
  // variable_name as a direct child (rare grammar shape).
  if (p.type === 'variable_name') return textOf(p, source).replace(/^\$/, '');
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

/** Strip `$` from a variable_name's text. */
function varName(node: Node | null | undefined, source: string): string {
  return textOf(node, source).replace(/^\$/, '');
}

/** Strip a leading `$` from a textual fragment (e.g. `$request->input` → `request->input`). */
function stripLeadingDollar(text: string): string {
  return text.replace(/^\$/, '');
}

/**
 * Walk a block (compound_statement, function/method body, file root).
 * Recurses into nested control-flow blocks and skips nested function/method
 * definitions (those are analyzed as their own IrFunctions).
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
    case 'compound_statement':
    case 'declaration_list':
      walkBlock(stmt, steps, ctx);
      return;

    case 'expression_statement': {
      // `expr;` — the inner is the expression itself.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const inner = stmt.namedChild(i);
        if (inner) walkExpressionAsAssign(inner, null, steps, ctx);
      }
      return;
    }

    case 'echo_statement': {
      // `echo $x, $y;` — each operand becomes an argument to a synthetic
      // `echo` call so spec patterns can mark `echo(*)` as a sink.
      const argLocals: (LocalVar | null)[] = [];
      const argTexts: string[] = [];
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const e = stmt.namedChild(i);
        if (!e) continue;
        argTexts.push(textOf(e, ctx.opts.fileContext.source));
        const direct = extractVarFromArg(e, ctx.opts.fileContext.source);
        if (direct) {
          argLocals.push(direct);
        } else {
          const tmp = `<arg${argLocals.length}@${steps.length}>`;
          walkExpressionAsAssign(e, tmp, steps, ctx);
          argLocals.push(tmp);
        }
      }
      steps.push({
        kind: 'call',
        target: null,
        callee: { kind: 'external', calleeText: 'echo' },
        args: argLocals,
        argTexts,
        loc: locOf(stmt, ctx),
      });
      return;
    }

    case 'return_statement': {
      // The expression (if any) is the first named child.
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
      const body = stmt.childForFieldName('body');
      if (body) walkStatement(body, steps, ctx);
      // else / elseif clauses
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'else_clause' || c.type === 'else_if_clause' || c.type === 'elseif_clause') {
          const ec = c.childForFieldName('condition');
          if (ec) walkExpressionAsAssign(ec, null, steps, ctx);
          const cb = c.childForFieldName('body');
          if (cb) walkStatement(cb, steps, ctx);
          else {
            // Some grammar shapes emit a bare body block as a child.
            for (let j = 0; j < c.namedChildCount; j++) {
              const cc = c.namedChild(j);
              if (cc && (cc.type === 'compound_statement' || cc.type === 'expression_statement')) {
                walkStatement(cc, steps, ctx);
              }
            }
          }
        }
      }
      return;
    }

    case 'while_statement':
    case 'do_statement': {
      const cond = stmt.childForFieldName('condition');
      if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
      const body = stmt.childForFieldName('body');
      if (body) walkStatement(body, steps, ctx);
      return;
    }

    case 'for_statement': {
      // `for (init; cond; update) body` — walk init/cond/update, then body.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (c && c.type !== 'compound_statement') walkExpressionAsAssign(c, null, steps, ctx);
      }
      const body = stmt.childForFieldName('body');
      if (body) walkStatement(body, steps, ctx);
      return;
    }

    case 'foreach_statement': {
      // `foreach ($arr as $k => $v) body` — the iterable is the first expr;
      // the keys/values capture from it. Best-effort: assign iterable's taint
      // to the value var.
      // Layout (typical): foreach ( <iter-expr> as <key>? <value> ) <body>
      // Use named children: first is the iterable expression, then patterns.
      let iter: Node | null = null;
      let key: Node | null = null;
      let value: Node | null = null;
      const named: Node[] = [];
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (c) named.push(c);
      }
      // Heuristic: iterable is the first child, body is the last; in between
      // are key/value variable_names or pair_pattern.
      if (named.length > 0) iter = named[0];
      // Last is body; bodies appear as compound_statement or other statement.
      const lastIsBody = named.length > 0
        && (named[named.length - 1].type === 'compound_statement' || named[named.length - 1].type.endsWith('_statement'));
      const middleEnd = lastIsBody ? named.length - 1 : named.length;
      for (let i = 1; i < middleEnd; i++) {
        const m = named[i];
        if (m.type === 'pair') {
          const kNode = m.childForFieldName('key') ?? m.namedChild(0);
          const vNode = m.childForFieldName('value') ?? m.namedChild(1);
          key = kNode;
          value = vNode;
        } else if (m.type === 'variable_name' || m.type === 'by_ref' || m.type === 'list_literal') {
          if (!value) value = m;
          else if (!key) {
            key = value;
            value = m;
          }
        }
      }
      const valueName = value && value.type === 'variable_name' ? varName(value, ctx.opts.fileContext.source) : null;
      if (iter) walkExpressionAsAssign(iter, valueName, steps, ctx);
      if (key && key.type === 'variable_name' && iter) {
        // Key is a copy of the iterable's taint too (best-effort).
        const kn = varName(key, ctx.opts.fileContext.source);
        if (kn) walkExpressionAsAssign(iter, kn, steps, ctx);
      }
      const body = lastIsBody ? named[named.length - 1] : stmt.childForFieldName('body');
      if (body) walkStatement(body, steps, ctx);
      return;
    }

    case 'switch_statement': {
      const cond = stmt.childForFieldName('condition');
      if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
      // Walk all case/default bodies.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'case_statement' || c.type === 'default_statement' || c.type === 'switch_block') {
          for (let j = 0; j < c.namedChildCount; j++) {
            const cc = c.namedChild(j);
            if (cc) walkStatement(cc, steps, ctx);
          }
        }
      }
      return;
    }

    case 'try_statement': {
      // body + catch_clause(s) + finally_clause
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (!c) continue;
        if (c.type === 'compound_statement') walkBlock(c, steps, ctx);
        else if (c.type === 'catch_clause' || c.type === 'finally_clause') {
          const body = c.childForFieldName('body');
          if (body) walkStatement(body, steps, ctx);
          else {
            // Walk the inner compound_statement.
            for (let j = 0; j < c.namedChildCount; j++) {
              const cc = c.namedChild(j);
              if (cc && cc.type === 'compound_statement') walkBlock(cc, steps, ctx);
            }
          }
        }
      }
      return;
    }

    case 'throw_expression':
    case 'throw_statement': {
      // Walk the inner expression for side-effects.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (c) walkExpressionAsAssign(c, null, steps, ctx);
      }
      return;
    }

    case 'function_definition':
    case 'method_declaration':
    case 'class_declaration':
    case 'interface_declaration':
    case 'trait_declaration':
    case 'enum_declaration':
      // Skip — analyzed as their own IrFunctions / not callable.
      return;

    case 'namespace_definition': {
      // `namespace Foo { body }` — walk the body.
      const body = findChildOfType(stmt, 'compound_statement') ?? findChildOfType(stmt, 'declaration_list');
      if (body) walkBlock(body, steps, ctx);
      return;
    }

    case 'namespace_use_declaration':
    case 'namespace_use_group_declaration':
    case 'const_declaration':
    case 'global_declaration':
    case 'static_declaration':
    case 'unset_statement':
    case 'break_statement':
    case 'continue_statement':
    case 'goto_statement':
    case 'comment':
    case 'php_tag':
    case 'text_interpolation':
      return;

    default:
      // Defensive: walk children.
      for (let i = 0; i < stmt.namedChildCount; i++) {
        const c = stmt.namedChild(i);
        if (c) walkStatement(c, steps, ctx);
      }
      return;
  }
}

/**
 * Lower an expression. If `target` is non-null, the expression's value flows
 * into target; otherwise we walk for side effects only.
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

    case 'cast_expression': {
      const inner = expr.childForFieldName('value') ?? expr.namedChild(expr.namedChildCount - 1);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }

    case 'reference_expression':
    case 'by_ref': {
      const inner = expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }

    case 'unary_op_expression':
    case 'unary_expression': {
      const inner = expr.childForFieldName('argument') ?? expr.namedChild(expr.namedChildCount - 1);
      if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
      return;
    }

    case 'augmented_assignment_expression': {
      // `$x .= $y` — combine $y into $x.
      const left = expr.childForFieldName('left');
      const right = expr.childForFieldName('right');
      const lhs = left && left.type === 'variable_name' ? varName(left, ctx.opts.fileContext.source) : null;
      if (right) walkExpressionAsAssign(right, lhs, steps, ctx);
      return;
    }

    case 'assignment_expression': {
      handleAssignment(expr, steps, ctx);
      // If this assignment is itself being used as a value (e.g. `$x = $y = foo()`),
      // copy the lhs into target for the outer expression.
      if (target) {
        const left = expr.childForFieldName('left');
        if (left && left.type === 'variable_name') {
          const lhs = varName(left, ctx.opts.fileContext.source);
          steps.push({
            kind: 'assign',
            target,
            from: lhs,
            loc: locOf(expr, ctx),
          });
        }
      }
      return;
    }

    case 'function_call_expression':
    case 'member_call_expression':
    case 'scoped_call_expression':
    case 'object_creation_expression': {
      emitCallStep(expr, target, steps, ctx);
      return;
    }

    case 'subscript_expression':
    case 'member_access_expression':
    case 'scoped_property_access_expression':
    case 'class_constant_access_expression': {
      // $arr[$i], $obj->prop, Foo::CONST — text becomes a source-pattern key.
      // Strip leading `$` so spec patterns can be written without it
      // (e.g. `request->user.*` matches `$request->user`, `_GET.*` matches `$_GET[...]`).
      if (target) {
        steps.push({
          kind: 'source',
          target,
          sourceText: stripLeadingDollar(textOf(expr, ctx.opts.fileContext.source)),
          loc: locOf(expr, ctx),
        });
      }
      return;
    }

    case 'variable_name': {
      // `$foo` — copy taint by name.
      if (target) {
        steps.push({
          kind: 'assign',
          target,
          from: varName(expr, ctx.opts.fileContext.source),
          loc: locOf(expr, ctx),
        });
      }
      return;
    }

    case 'name':
    case 'qualified_name': {
      // Bare constant or class name reference. Inert for taint unless the
      // outer expression treats it as a sub-expression (e.g. concat).
      return;
    }

    case 'string': {
      // Plain single/double-quoted with no interpolation — inert.
      // Some tree-sitter-php builds use `string` even for interpolated
      // strings; walk children to find interpolations defensively.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (!c) continue;
        if (c.type === 'interpolation' || c.type === 'variable_name' || c.type === 'subscript_expression' || c.type === 'member_access_expression') {
          walkExpressionAsAssign(c, target, steps, ctx);
        }
      }
      return;
    }

    case 'encapsed_string':
    case 'heredoc':
    case 'heredoc_body':
    case 'nowdoc':
    case 'nowdoc_body': {
      // `"$x foo $y->z"` — each interpolation child contributes taint.
      // `nowdoc` is inert (single-quoted heredoc), but cheaply walk anyway.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const c = expr.namedChild(i);
        if (!c) continue;
        if (c.type === 'string_value' || c.type === 'escape_sequence' || c.type === 'string_content') continue;
        if (c.type === 'interpolation') {
          // Walk the interpolated expression(s).
          for (let j = 0; j < c.namedChildCount; j++) {
            const inner = c.namedChild(j);
            if (inner) walkExpressionAsAssign(inner, target, steps, ctx);
          }
        } else {
          walkExpressionAsAssign(c, target, steps, ctx);
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

    case 'conditional_expression': {
      // `cond ? a : b` — both branches taint target.
      const consequence = expr.childForFieldName('body') ?? expr.namedChild(1);
      const alternative = expr.childForFieldName('alternative') ?? expr.namedChild(expr.namedChildCount - 1);
      // Walk condition for side-effects.
      const cond = expr.childForFieldName('condition') ?? expr.namedChild(0);
      if (cond) walkExpressionAsAssign(cond, null, steps, ctx);
      if (consequence) walkExpressionAsAssign(consequence, target, steps, ctx);
      if (alternative) walkExpressionAsAssign(alternative, target, steps, ctx);
      return;
    }

    case 'array_creation_expression': {
      // `[a, b, ...]` or `array(a, b, ...)` — taint flows from any element.
      for (let i = 0; i < expr.namedChildCount; i++) {
        const elem = expr.namedChild(i);
        if (!elem) continue;
        if (elem.type === 'array_element_initializer') {
          // value child is the second; key is first if a `=>` is present.
          const valueNode = elem.childForFieldName('value') ?? elem.namedChild(elem.namedChildCount - 1);
          if (valueNode) walkExpressionAsAssign(valueNode, target, steps, ctx);
        } else {
          walkExpressionAsAssign(elem, target, steps, ctx);
        }
      }
      return;
    }

    case 'list_literal': {
      // list($a, $b) used in destructuring. Inert here unless on lhs of an assign,
      // which is handled in handleAssignment.
      return;
    }

    case 'print_intrinsic': {
      // `print $x` — synthetic call to `print`.
      const inner = expr.namedChild(0);
      const argLocals: (LocalVar | null)[] = [];
      const argTexts: string[] = [];
      if (inner) {
        argTexts.push(textOf(inner, ctx.opts.fileContext.source));
        const direct = extractVarFromArg(inner, ctx.opts.fileContext.source);
        if (direct) argLocals.push(direct);
        else {
          const tmp = `<arg0@${steps.length}>`;
          walkExpressionAsAssign(inner, tmp, steps, ctx);
          argLocals.push(tmp);
        }
      }
      steps.push({
        kind: 'call',
        target,
        callee: { kind: 'external', calleeText: 'print' },
        args: argLocals,
        argTexts,
        loc: locOf(expr, ctx),
      });
      return;
    }

    case 'include_expression':
    case 'include_once_expression':
    case 'require_expression':
    case 'require_once_expression': {
      // Walk the path expr for side-effects only.
      const inner = expr.namedChild(0);
      if (inner) walkExpressionAsAssign(inner, null, steps, ctx);
      return;
    }

    case 'anonymous_function_creation_expression':
    case 'arrow_function':
    case 'function_static_declaration':
      // Inert at this level — closures are their own IrFunctions when
      // we eventually analyze them. v1: skip.
      return;

    case 'integer':
    case 'float':
    case 'boolean':
    case 'null':
    case 'shell_command_expression':
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

function handleAssignment(node: Node, steps: Step[], ctx: WalkCtx): void {
  const left = node.childForFieldName('left');
  const right = node.childForFieldName('right') ?? node.namedChild(1);
  if (!right) return;
  if (!left) {
    walkExpressionAsAssign(right, null, steps, ctx);
    return;
  }
  // Track `$x = new C(...)` for the resolution heuristic.
  if (left.type === 'variable_name' && right.type === 'object_creation_expression') {
    const typeNode = right.namedChild(0);
    if (typeNode && (typeNode.type === 'name' || typeNode.type === 'qualified_name')) {
      const v = varName(left, ctx.opts.fileContext.source);
      if (v) ctx.localTypes.set(v, lastSegment(textOf(typeNode, ctx.opts.fileContext.source)));
    }
  }

  if (left.type === 'variable_name') {
    const target = varName(left, ctx.opts.fileContext.source);
    walkExpressionAsAssign(right, target, steps, ctx);
    return;
  }

  if (left.type === 'list_literal' || left.type === 'array_creation_expression') {
    // Destructuring — synthesize a tmp for rhs, then assign each element from it.
    const tmp = `<unpack@${steps.length}>`;
    walkExpressionAsAssign(right, tmp, steps, ctx);
    for (let i = 0; i < left.namedChildCount; i++) {
      const elem = left.namedChild(i);
      if (!elem) continue;
      const target =
        elem.type === 'variable_name'
          ? varName(elem, ctx.opts.fileContext.source)
          : elem.type === 'array_element_initializer'
            ? (() => {
                const vn = elem.childForFieldName('value') ?? elem.namedChild(elem.namedChildCount - 1);
                return vn && vn.type === 'variable_name' ? varName(vn, ctx.opts.fileContext.source) : null;
              })()
            : null;
      if (target) {
        steps.push({
          kind: 'assign',
          target,
          from: tmp,
          loc: locOf(elem, ctx),
        });
      }
    }
    return;
  }

  // Subscript / member-access / scoped-property target — walk RHS for side effects only.
  walkExpressionAsAssign(right, null, steps, ctx);
}

function emitCallStep(
  expr: Node,
  target: LocalVar | null,
  steps: Step[],
  ctx: WalkCtx,
): void {
  // Method-chain pre-walk: when the receiver/object is itself a call (chain
  // like `$client->get($url)->json()`, `Foo::make()->find($id)`), lower the
  // inner call as its own Step first so its sink/source/sanitizer matching
  // fires. Mirrors JS ir.ts:393-407, Java java/ir.ts:292-299, Ruby, Python.
  if (expr.type === 'member_call_expression') {
    const obj = expr.childForFieldName('object');
    if (obj && (obj.type === 'member_call_expression' || obj.type === 'function_call_expression' || obj.type === 'scoped_call_expression' || obj.type === 'object_creation_expression')) {
      const innerTmp = `<chain@${steps.length}>`;
      walkExpressionAsAssign(obj, innerTmp, steps, ctx);
    }
  } else if (expr.type === 'scoped_call_expression') {
    const scope = expr.childForFieldName('scope');
    if (scope && (scope.type === 'member_call_expression' || scope.type === 'function_call_expression' || scope.type === 'scoped_call_expression')) {
      const innerTmp = `<chain@${steps.length}>`;
      walkExpressionAsAssign(scope, innerTmp, steps, ctx);
    }
  }

  // Determine the callee's textual root. We strip the leading `$` from any
  // variable-rooted callee/scope so spec patterns can be written without it
  // (e.g. `request->input(*)` matches `$request->input(...)`).
  let calleeText = '';
  if (expr.type === 'function_call_expression') {
    const fn = expr.childForFieldName('function');
    calleeText = stripLeadingDollar(textOf(fn, ctx.opts.fileContext.source));
  } else if (expr.type === 'member_call_expression') {
    const obj = expr.childForFieldName('object');
    const name = expr.childForFieldName('name');
    calleeText = `${stripLeadingDollar(textOf(obj, ctx.opts.fileContext.source))}->${textOf(name, ctx.opts.fileContext.source)}`;
  } else if (expr.type === 'scoped_call_expression') {
    const scope = expr.childForFieldName('scope');
    const name = expr.childForFieldName('name');
    calleeText = `${stripLeadingDollar(textOf(scope, ctx.opts.fileContext.source))}::${textOf(name, ctx.opts.fileContext.source)}`;
  } else if (expr.type === 'object_creation_expression') {
    const typeNode = expr.namedChild(0);
    calleeText = `new ${textOf(typeNode, ctx.opts.fileContext.source)}`;
  } else {
    const t = textOf(expr, ctx.opts.fileContext.source);
    const idx = t.indexOf('(');
    calleeText = stripLeadingDollar(idx >= 0 ? t.slice(0, idx) : t);
  }

  // Resolve to a CalleeRef.
  const callee = resolveCallee(calleeText, ctx);

  // Walk args. tree-sitter-php exposes call arguments via the `arguments`
  // field for *_call_expression nodes, but for `object_creation_expression`
  // some grammar builds expose it as a direct named-child `arguments` node
  // instead of a field. Fall through to a children-scan when the field is
  // missing so `new Response($bio)` lowers with `args = ['bio']` instead of
  // dropping the argument list silently.
  let argList = expr.childForFieldName('arguments');
  if (!argList) {
    for (let i = 0; i < expr.namedChildCount; i++) {
      const c = expr.namedChild(i);
      if (c && c.type === 'arguments') {
        argList = c;
        break;
      }
    }
  }
  const args: (LocalVar | null)[] = [];
  const argTexts: string[] = [];
  if (argList) {
    for (let i = 0; i < argList.namedChildCount; i++) {
      const a = argList.namedChild(i);
      if (!a) continue;
      if (a.type === 'comment') continue;
      // tree-sitter-php may wrap args in `argument` nodes; unwrap.
      let valueNode: Node = a;
      if (a.type === 'argument') {
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
}

function emitReturnFromExpression(expr: Node, steps: Step[], ctx: WalkCtx): void {
  if (expr.type === 'variable_name') {
    steps.push({
      kind: 'return',
      from: varName(expr, ctx.opts.fileContext.source),
      loc: locOf(expr, ctx),
    });
    return;
  }
  const synthetic = `<retval@${steps.length}>`;
  walkExpressionAsAssign(expr, synthetic, steps, ctx);
  steps.push({ kind: 'return', from: synthetic, loc: locOf(expr, ctx) });
}

function extractVarFromArg(arg: Node, source: string): LocalVar | null {
  if (arg.type === 'variable_name') return source.slice(arg.startIndex, arg.endIndex).replace(/^\$/, '');
  if (arg.type === 'parenthesized_expression') {
    const inner = arg.namedChild(0);
    if (inner) return extractVarFromArg(inner, source);
  }
  if (arg.type === 'argument') {
    const inner = arg.namedChild(0);
    if (inner) return extractVarFromArg(inner, source);
  }
  if (arg.type === 'reference_expression' || arg.type === 'by_ref') {
    const inner = arg.namedChild(0);
    if (inner) return extractVarFromArg(inner, source);
  }
  return null;
}

function resolveCallee(calleeText: string, ctx: WalkCtx): CalleeRef {
  const fileFunctions = new Map<string, typeof ctx.opts.fileContext.functions>();
  const fileImports = new Map<string, typeof ctx.opts.fileContext.imports>();
  for (const [fp, fctx] of ctx.opts.allFiles.entries()) {
    fileFunctions.set(fp, fctx.functions);
    fileImports.set(fp, fctx.imports);
  }
  const { calleeId, kind } = resolvePhpCallee({
    calleeText,
    filePath: ctx.opts.filePath,
    fileFunctions,
    fileImports,
    globalFunctionsByFqn: ctx.opts.globalFunctionsByFqn,
    classFqnToFile: ctx.opts.classFqnToFile,
    enclosingClass: ctx.enclosingClass,
    localTypes: ctx.localTypes,
  });
  if (calleeId && kind === 'static') {
    return { kind: 'internal', functionId: calleeId, calleeText };
  }
  if (kind === 'static') {
    return { kind: 'external', calleeText };
  }
  return { kind: 'unresolved', calleeText };
}
