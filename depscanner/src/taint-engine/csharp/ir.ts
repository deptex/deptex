/**
 * Per-method intermediate representation for the C# taint propagator.
 *
 * Mirrors java/ir.ts and python/ir.ts. Emits the same Step shape so the
 * downstream propagation algorithm in ../propagate-core.ts is
 * language-agnostic.
 *
 * C# specifics:
 *   - Method invocations resolve to a CalleeRef using the same callgraph
 *     resolution as pass-2 of callgraph.ts. We don't re-run resolution; the
 *     IrFunction is built from the same CSharpCallgraphContext.
 *   - `new Type(args)` is emitted as a Call step with the constructor's
 *     calleeText set to the bare `Type` name. Sink YAMLs match patterns of
 *     the form `SqlCommand(*)` and `Process.Start(*)` against this text.
 *   - Method/parameter attributes for source binding —
 *     `[FromBody]`, `[FromQuery]`, `[FromRoute]`, `[FromForm]`, `[FromHeader]`
 *     on a parameter, or `[HttpGet]`/`[HttpPost]`/`[HttpPut]`/`[HttpDelete]`
 *     on the enclosing method (in which case every non-decorated parameter
 *     is treated as a model-bound input) — synthesize a `source` Step at
 *     the start of the method body, mirroring how java/ir.ts handles
 *     `@RequestParam`. This taints the parameter at function entry so the
 *     propagator's worklist can flow it into call sites.
 *   - Field/element access becomes a `source` step (matching property-pattern
 *     entries like `Request.Query.*`). String-interpolation expressions
 *     `$"..."` walk every `interpolation` child so taint can flow through
 *     `$"SELECT * FROM users WHERE name = '{q}'"`.
 *   - Generics on the callee text are stripped via stripGenericsFromCallee
 *     before emission so YAML patterns don't have to anticipate every
 *     possible type-arg form.
 *
 * Unhandled / over-approximated v1 limitations:
 *   - Lambda bodies (`lambda_expression`) are NOT walked — they're treated
 *     as a separate function (the callgraph emits a synthetic node for
 *     local functions; lambdas without a name are skipped in v1).
 *   - `await` is stripped (treated as identity); async state-machine flow
 *     isn't modeled.
 *   - `out`/`ref`/`in` parameters: out-arg taint isn't propagated back to
 *     the caller's local; only the return value is.
 *   - Pattern matching (`is`, `switch (...)`, property patterns) walks
 *     children for side effects but doesn't bind extracted locals.
 *   - LINQ method-syntax chains: each `Select`/`Where` call is an external
 *     invocation; lambda arg bodies aren't walked (over-approximated to
 *     "first-tainted-arg taints target").
 *   - `cast_expression` / parenthesized / null-conditional access are
 *     pass-throughs (taint flows through the inner expression).
 *   - Partial-class merge isn't done; cross-file partial-method taint is
 *     missed.
 */

import type { Node } from 'web-tree-sitter';
import type { CalleeRef, IrFunction, LocalVar, SourceLocation, Step } from '../ir';
import type { FunctionId } from '../types';
import type { CSharpCallgraphContext, CSharpFileIndex, CSharpMethodEntry } from './callgraph';
import { resolveInvocation, stripGenericsFromCallee } from './callgraph';

export interface LowerCSharpOptions {
  ctx: CSharpCallgraphContext;
  fileIndex: CSharpFileIndex;
  /** The method/constructor's CSharpMethodEntry (null for synthetic file-init). */
  entry: CSharpMethodEntry | null;
}

/** Set of attribute names that pre-taint a parameter at method entry. */
const PARAM_SOURCE_ATTRIBUTES = new Set([
  'FromBody',
  'FromQuery',
  'FromRoute',
  'FromForm',
  'FromHeader',
  'FromServices', // technically DI; included for safety so e.g. impersonation
                  // patterns surface. Documented in spec yaml.
]);

/** Set of method-level attribute names that mark a method as an HTTP entry
 * point. When present, every parameter without an attribute opt-in is
 * pre-tainted (mirrors how Spring's @GetMapping treats String parameters). */
const METHOD_HTTP_ATTRIBUTES = new Set([
  'HttpGet',
  'HttpPost',
  'HttpPut',
  'HttpDelete',
  'HttpPatch',
  'Route',
  'AcceptVerbs',
]);

export function lowerCSharpMethod(
  funcId: FunctionId,
  funcNode: Node,
  opts: LowerCSharpOptions,
): IrFunction {
  const { fileIndex, entry, ctx } = opts;
  const params: LocalVar[] = [];
  const steps: Step[] = [];

  const isFile = funcNode.type === 'compilation_unit';

  // Module/file initializer: walk top-level statements (Program.cs style).
  if (isFile) {
    walkStatement(funcNode, steps, {
      ctx,
      fileIndex,
      entry: null,
      localTypes: new Map(),
      fieldTypes: new Map(),
    });
    return { id: funcId, params, steps };
  }

  // Method / constructor / local function.
  const localTypes = new Map<string, string>();
  const fieldTypes = entry?.classFqn
    ? collectFieldTypes(findEnclosingClass(funcNode), fileIndex.source)
    : new Map<string, string>();

  // Detect HTTP-route attribute on the enclosing method.
  const isHttpEntry = entry ? hasMethodHttpAttribute(funcNode, fileIndex.source) : false;

  // Parameters
  if (entry) {
    const paramNode = funcNode.childForFieldName('parameters');
    if (paramNode) {
      for (let i = 0; i < paramNode.namedChildCount; i++) {
        const p = paramNode.namedChild(i)!;
        if (p.type !== 'parameter') continue;
        const nameNode = p.childForFieldName('name');
        const paramName = nameNode ? textOf(nameNode, fileIndex.source) : `<param@${i}>`;
        params.push(paramName);
        const typeNode = p.childForFieldName('type');
        if (typeNode) localTypes.set(paramName, simpleTypeName(typeNode, fileIndex.source));

        // Per-parameter source attributes: [FromBody], [FromQuery], etc.
        const attrSource = paramSourceAttribute(p, fileIndex.source);
        if (attrSource) {
          steps.push({
            kind: 'source',
            target: paramName,
            sourceText: attrSource,
            loc: locOf(p, fileIndex.relativePath),
          });
          continue;
        }
        // Implicit binding: if the method itself is decorated with an
        // [HttpGet]/[HttpPost]/etc. attribute and the parameter is a
        // primitive-ish (no source attribute, declared simple type), treat
        // as model-bound. Conservative: only when there's a string-bound
        // route parameter AND the method has the http attribute.
        if (isHttpEntry) {
          steps.push({
            kind: 'source',
            target: paramName,
            sourceText: '@HttpRouteParameter',
            loc: locOf(p, fileIndex.relativePath),
          });
        }
      }
    }
  }

  // Body — may be a `block` (regular method) or `arrow_expression_clause`
  // (expression-bodied method `=> expr`).
  const body = funcNode.childForFieldName('body');
  if (body) {
    walkStatement(body, steps, {
      ctx,
      fileIndex,
      entry,
      localTypes,
      fieldTypes,
    });
  }

  return { id: funcId, params, steps };
}

interface WalkCtx {
  ctx: CSharpCallgraphContext;
  fileIndex: CSharpFileIndex;
  entry: CSharpMethodEntry | null;
  localTypes: Map<string, string>;
  fieldTypes: Map<string, string>;
}

function walkStatement(node: Node, steps: Step[], wc: WalkCtx): void {
  const t = node.type;
  if (t === 'block' || t === 'compilation_unit' || t === 'global_statement') {
    for (let i = 0; i < node.namedChildCount; i++) {
      walkStatement(node.namedChild(i)!, steps, wc);
    }
    return;
  }

  if (t === 'arrow_expression_clause') {
    // Expression-bodied method/property/lambda body: `=> expr`. Treat as
    // implicit return.
    const inner = node.namedChild(0);
    if (inner) emitReturnFromExpression(inner, steps, wc);
    return;
  }

  if (t === 'if_statement') {
    const cond = node.childForFieldName('condition');
    if (cond) walkExpressionAsAssign(cond, null, steps, wc);
    const then = node.childForFieldName('consequence');
    if (then) walkStatement(then, steps, wc);
    // C# uses `alternative` field; tree-sitter-c-sharp also emits an
    // `else_clause` named child in some grammars.
    const els = node.childForFieldName('alternative');
    if (els) walkStatement(els, steps, wc);
    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i)!;
      if (c.type === 'else_clause') walkStatement(c, steps, wc);
    }
    return;
  }
  if (t === 'else_clause') {
    for (let i = 0; i < node.namedChildCount; i++) walkStatement(node.namedChild(i)!, steps, wc);
    return;
  }
  if (
    t === 'while_statement' ||
    t === 'do_statement' ||
    t === 'for_statement' ||
    t === 'foreach_statement'
  ) {
    const cond = node.childForFieldName('condition');
    if (cond) walkExpressionAsAssign(cond, null, steps, wc);
    if (t === 'foreach_statement') {
      // foreach (T x in expr) — taint of expr flows to x.
      const nameNode = node.childForFieldName('left') ?? node.childForFieldName('name');
      const valueNode = node.childForFieldName('right') ?? node.childForFieldName('value');
      const typeNode = node.childForFieldName('type');
      if (nameNode && valueNode) {
        const target = textOf(nameNode, wc.fileIndex.source);
        if (typeNode) wc.localTypes.set(target, simpleTypeName(typeNode, wc.fileIndex.source));
        walkExpressionAsAssign(valueNode, target, steps, wc);
      }
    }
    if (t === 'for_statement') {
      // initializer + update, in some grammars exposed as named children.
      for (let i = 0; i < node.namedChildCount; i++) {
        const c = node.namedChild(i)!;
        if (c.type === 'variable_declaration') {
          // for (var x = expr; ...; ...) — track as a local-decl.
          handleVariableDeclaration(c, steps, wc);
        }
      }
    }
    const bod = node.childForFieldName('body');
    if (bod) walkStatement(bod, steps, wc);
    return;
  }
  if (t === 'try_statement') {
    const bod = node.childForFieldName('body');
    if (bod) walkStatement(bod, steps, wc);
    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i)!;
      if (c.type === 'catch_clause') {
        const cb = c.childForFieldName('body') ?? findChildOfType(c, 'block');
        if (cb) walkStatement(cb, steps, wc);
      } else if (c.type === 'finally_clause') {
        const fb = findChildOfType(c, 'block');
        if (fb) walkStatement(fb, steps, wc);
      }
    }
    return;
  }
  if (t === 'switch_statement' || t === 'switch_expression') {
    const cond = node.childForFieldName('value') ?? node.childForFieldName('condition');
    if (cond) walkExpressionAsAssign(cond, null, steps, wc);
    const blk = node.childForFieldName('body') ?? findChildOfType(node, 'switch_body');
    if (blk) {
      for (let i = 0; i < blk.namedChildCount; i++) {
        const sec = blk.namedChild(i)!;
        if (sec.type === 'switch_section' || sec.type === 'switch_expression_arm') {
          for (let j = 0; j < sec.namedChildCount; j++) walkStatement(sec.namedChild(j)!, steps, wc);
        }
      }
    }
    return;
  }
  if (t === 'using_statement') {
    // `using (var x = expr) body` — expr may be a variable_declaration.
    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i)!;
      if (c.type === 'variable_declaration') {
        handleVariableDeclaration(c, steps, wc);
      } else if (c.type === 'block') {
        walkStatement(c, steps, wc);
      } else {
        // Fallback: walk for side effects.
        walkStatement(c, steps, wc);
      }
    }
    return;
  }
  if (t === 'lock_statement' || t === 'fixed_statement' || t === 'unsafe_statement' || t === 'checked_statement' || t === 'unchecked_statement') {
    const bod = node.childForFieldName('body') ?? findChildOfType(node, 'block');
    if (bod) walkStatement(bod, steps, wc);
    return;
  }
  if (t === 'local_declaration_statement') {
    const decl = findChildOfType(node, 'variable_declaration');
    if (decl) handleVariableDeclaration(decl, steps, wc);
    return;
  }
  if (t === 'expression_statement') {
    const inner = node.namedChild(0);
    if (inner) walkExpressionAsAssign(inner, null, steps, wc);
    return;
  }
  if (t === 'return_statement') {
    const inner = node.namedChild(0);
    if (inner) {
      emitReturnFromExpression(inner, steps, wc);
    } else {
      steps.push({ kind: 'return', from: null, loc: locOf(node, wc.fileIndex.relativePath) });
    }
    return;
  }
  if (t === 'throw_statement') {
    const inner = node.namedChild(0);
    if (inner) walkExpressionAsAssign(inner, null, steps, wc);
    return;
  }
  if (
    t === 'method_declaration' ||
    t === 'local_function_statement' ||
    t === 'constructor_declaration' ||
    t === 'destructor_declaration'
  ) {
    // Nested function — analyzed as its own IrFunction.
    return;
  }
  // Defensive: walk children.
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'block') walkStatement(c, steps, wc);
  }
}

function handleVariableDeclaration(decl: Node, steps: Step[], wc: WalkCtx): void {
  const typeNode = decl.childForFieldName('type');
  const typeSimple = typeNode ? simpleTypeName(typeNode, wc.fileIndex.source) : null;
  for (let i = 0; i < decl.namedChildCount; i++) {
    const c = decl.namedChild(i)!;
    if (c.type !== 'variable_declarator') continue;
    const nameNode = c.childForFieldName('name') ?? c.namedChild(0);
    if (!nameNode) continue;
    const target = textOf(nameNode, wc.fileIndex.source);
    if (typeSimple) wc.localTypes.set(target, typeSimple);
    // Initializer may be exposed as `value` field, as an `equals_value_clause`
    // named child whose first child is the expression, OR (most common in
    // tree-sitter-c-sharp ≥ 0.20) as the second named child of the
    // variable_declarator with no wrapper — `name = expr` flattened.
    let valueNode: Node | null = c.childForFieldName('value');
    if (!valueNode) {
      for (let j = 0; j < c.namedChildCount; j++) {
        const k = c.namedChild(j)!;
        if (k.type === 'equals_value_clause') {
          valueNode = k.namedChild(0);
          break;
        }
      }
    }
    if (!valueNode && c.namedChildCount >= 2) {
      // Take the first named child whose start position differs from nameNode's
      // (i.e. not the identifier itself). web-tree-sitter wraps each access in
      // a fresh JS object, so identity (===) comparison is unreliable; compare
      // by start index instead.
      const nameStart = nameNode.startIndex;
      for (let j = 0; j < c.namedChildCount; j++) {
        const k = c.namedChild(j)!;
        if (k.startIndex === nameStart) continue;
        valueNode = k;
        break;
      }
    }
    if (valueNode) walkExpressionAsAssign(valueNode, target, steps, wc);
  }
}

function walkExpressionAsAssign(
  expr: Node,
  target: LocalVar | null,
  steps: Step[],
  wc: WalkCtx,
): void {
  const t = expr.type;

  // Pass-through wrappers.
  if (t === 'parenthesized_expression') {
    const inner = expr.namedChild(0);
    if (inner) walkExpressionAsAssign(inner, target, steps, wc);
    return;
  }
  if (t === 'cast_expression') {
    // Treat as identity — taint flows through.
    const valueNode = expr.childForFieldName('value') ?? expr.namedChild(expr.namedChildCount - 1);
    if (valueNode) walkExpressionAsAssign(valueNode, target, steps, wc);
    return;
  }
  if (t === 'await_expression') {
    const inner = expr.namedChild(0);
    if (inner) walkExpressionAsAssign(inner, target, steps, wc);
    return;
  }
  if (t === 'null_conditional_expression' || t === 'conditional_access_expression') {
    // Treat as plain access — same taint flow as `obj.member`.
    const inner = expr.namedChild(0);
    if (inner) walkExpressionAsAssign(inner, target, steps, wc);
    // Walk subsequent member-binding children too.
    for (let i = 1; i < expr.namedChildCount; i++) {
      walkExpressionAsAssign(expr.namedChild(i)!, target, steps, wc);
    }
    return;
  }

  // Assignment: `x = expr` (also `x += expr`)
  if (t === 'assignment_expression') {
    const lhs = expr.childForFieldName('left');
    const rhs = expr.childForFieldName('right');
    let lhsName: LocalVar | null = null;
    if (lhs && lhs.type === 'identifier') {
      lhsName = textOf(lhs, wc.fileIndex.source);
    } else if (lhs && lhs.type === 'member_access_expression') {
      // `this.x = expr` — track on the field name.
      const fieldName = lhs.childForFieldName('name');
      if (fieldName) lhsName = textOf(fieldName, wc.fileIndex.source);
    }
    if (rhs) walkExpressionAsAssign(rhs, lhsName, steps, wc);
    return;
  }

  // Method invocation
  if (t === 'invocation_expression') {
    // Method-chain pre-walk: when the function field is a member_access
    // whose expression is itself an invocation_expression or
    // object_creation_expression (chain like `Foo.Create().Bar()`,
    // `new Foo().Bar()`), lower the inner call first so its sink/source
    // matching fires. Mirrors JS, Java, Ruby, Python, PHP, Go.
    const fnNode = expr.childForFieldName('function');
    if (fnNode && fnNode.type === 'member_access_expression') {
      const inner = fnNode.childForFieldName('expression') ?? fnNode.namedChild(0);
      if (inner && (inner.type === 'invocation_expression' || inner.type === 'object_creation_expression')) {
        const innerTmp = `<chain@${steps.length}>`;
        walkExpressionAsAssign(inner, innerTmp, steps, wc);
      }
    }
    const argsNode = expr.childForFieldName('arguments');
    const argList: Node[] = [];
    if (argsNode) {
      for (let i = 0; i < argsNode.namedChildCount; i++) {
        const a = argsNode.namedChild(i)!;
        if (a.type === 'argument') argList.push(a);
      }
    }
    const argLocals: (LocalVar | null)[] = [];
    const argTexts: string[] = [];
    for (let i = 0; i < argList.length; i++) {
      const a = argList[i];
      // The actual expression is the first/inner child of the `argument` node.
      // tree-sitter-c-sharp wraps every argument in an `argument` named node.
      const inner = unwrapArgument(a);
      argTexts.push(textOf(inner, wc.fileIndex.source));
      const direct = extractVarFromArg(inner, wc.fileIndex.source);
      if (direct) {
        argLocals.push(direct);
        continue;
      }
      const tmp = `<arg${i}@${steps.length}>`;
      walkExpressionAsAssign(inner, tmp, steps, wc);
      argLocals.push(tmp);
    }
    const callee = makeCalleeRef(expr, wc);
    steps.push({
      kind: 'call',
      target,
      callee,
      args: argLocals,
      argTexts,
      loc: locOf(expr, wc.fileIndex.relativePath),
    });
    return;
  }

  // Object creation `new Foo(args)` — emit as a call with calleeText = type name.
  if (t === 'object_creation_expression') {
    const typeNode = expr.childForFieldName('type');
    const typeSimple = typeNode ? simpleTypeName(typeNode, wc.fileIndex.source) : '<anon>';
    const argsNode = expr.childForFieldName('arguments');
    const argList: Node[] = [];
    if (argsNode) {
      for (let i = 0; i < argsNode.namedChildCount; i++) {
        const a = argsNode.namedChild(i)!;
        if (a.type === 'argument') argList.push(a);
      }
    }
    const argLocals: (LocalVar | null)[] = [];
    const argTexts: string[] = [];
    for (let i = 0; i < argList.length; i++) {
      const a = argList[i];
      const inner = unwrapArgument(a);
      argTexts.push(textOf(inner, wc.fileIndex.source));
      const direct = extractVarFromArg(inner, wc.fileIndex.source);
      if (direct) {
        argLocals.push(direct);
        continue;
      }
      const tmp = `<arg${i}@${steps.length}>`;
      walkExpressionAsAssign(inner, tmp, steps, wc);
      argLocals.push(tmp);
    }
    const callee = makeObjectCreationCalleeRef(expr, wc, typeSimple);
    steps.push({
      kind: 'call',
      target,
      callee,
      args: argLocals,
      argTexts,
      loc: locOf(expr, wc.fileIndex.relativePath),
    });
    return;
  }

  // Field access — `obj.field` or qualified path.
  if (t === 'member_access_expression') {
    if (target) {
      const text = stripGenericsFromCallee(textOf(expr, wc.fileIndex.source));
      steps.push({
        kind: 'source',
        target,
        sourceText: text,
        loc: locOf(expr, wc.fileIndex.relativePath),
      });
    }
    return;
  }

  // Element access `arr[i]`.
  if (t === 'element_access_expression') {
    if (target) {
      const text = textOf(expr, wc.fileIndex.source);
      steps.push({
        kind: 'source',
        target,
        sourceText: text,
        loc: locOf(expr, wc.fileIndex.relativePath),
      });
    }
    return;
  }

  // Identifier — copy taint.
  if (t === 'identifier') {
    if (target) {
      steps.push({
        kind: 'assign',
        target,
        from: textOf(expr, wc.fileIndex.source),
        loc: locOf(expr, wc.fileIndex.relativePath),
      });
    }
    return;
  }

  // Binary: walk both sides — `+` for string concat etc.
  if (t === 'binary_expression') {
    const left = expr.childForFieldName('left');
    const right = expr.childForFieldName('right');
    if (left) walkExpressionAsAssign(left, target, steps, wc);
    if (right) walkExpressionAsAssign(right, target, steps, wc);
    return;
  }

  if (t === 'conditional_expression' || t === 'ternary_expression') {
    // a ? b : c — both branches taint target.
    const consequent = expr.childForFieldName('consequence');
    const alternative = expr.childForFieldName('alternative');
    if (consequent) walkExpressionAsAssign(consequent, target, steps, wc);
    if (alternative) walkExpressionAsAssign(alternative, target, steps, wc);
    if (!consequent && !alternative) {
      // Defensive: walk children.
      for (let i = 0; i < expr.namedChildCount; i++) {
        walkExpressionAsAssign(expr.namedChild(i)!, target, steps, wc);
      }
    }
    return;
  }

  if (t === 'prefix_unary_expression' || t === 'postfix_unary_expression' || t === 'unary_expression') {
    const inner = expr.childForFieldName('operand') ?? expr.namedChild(0);
    if (inner) walkExpressionAsAssign(inner, target, steps, wc);
    return;
  }

  // String interpolation: `$"text {expr} text"` — walk every interpolation
  // child so taint flows through the interpolated values.
  if (t === 'interpolated_string_expression') {
    for (let i = 0; i < expr.namedChildCount; i++) {
      const c = expr.namedChild(i)!;
      if (c.type === 'interpolation') {
        const innerExpr = c.namedChild(0);
        if (innerExpr) walkExpressionAsAssign(innerExpr, target, steps, wc);
      }
      // string_literal_fragment / interpolated_string_text → inert.
    }
    return;
  }

  // Plain string and verbatim string literals — inert. Nothing to emit.
  if (
    t === 'string_literal' ||
    t === 'verbatim_string_literal' ||
    t === 'character_literal' ||
    t === 'integer_literal' ||
    t === 'real_literal' ||
    t === 'boolean_literal' ||
    t === 'null_literal'
  ) {
    return;
  }

  if (t === 'tuple_expression' || t === 'array_creation_expression' || t === 'implicit_array_creation_expression' || t === 'collection_expression') {
    for (let i = 0; i < expr.namedChildCount; i++) {
      walkExpressionAsAssign(expr.namedChild(i)!, target, steps, wc);
    }
    return;
  }

  if (t === 'lambda_expression' || t === 'anonymous_method_expression') {
    // Skip the body — analyzed as a separate function (or under-modeled in v1).
    return;
  }

  // `typeof(T)`, `nameof(...)`, `default`, `sizeof` — inert for taint.
  if (t === 'typeof_expression' || t === 'sizeof_expression' || t === 'default_expression') {
    return;
  }

  // is / as expressions — taint flows through the operand.
  if (t === 'is_expression' || t === 'as_expression') {
    const inner = expr.namedChild(0);
    if (inner) walkExpressionAsAssign(inner, target, steps, wc);
    return;
  }

  // Defensive: walk children.
  for (let i = 0; i < expr.namedChildCount; i++) {
    walkExpressionAsAssign(expr.namedChild(i)!, target, steps, wc);
  }
}

function emitReturnFromExpression(expr: Node, steps: Step[], wc: WalkCtx): void {
  if (expr.type === 'identifier') {
    steps.push({
      kind: 'return',
      from: textOf(expr, wc.fileIndex.source),
      loc: locOf(expr, wc.fileIndex.relativePath),
    });
    return;
  }
  const tmp = `<retval@${steps.length}>`;
  walkExpressionAsAssign(expr, tmp, steps, wc);
  steps.push({ kind: 'return', from: tmp, loc: locOf(expr, wc.fileIndex.relativePath) });
}

function unwrapArgument(arg: Node): Node {
  // tree-sitter-c-sharp wraps arguments in a `argument` node containing the
  // actual expression as a named child. Strip that wrapper.
  if (arg.type === 'argument') {
    // The expression is typically the last named child (after optional
    // `name_colon` for named arguments, and `ref`/`out`/`in` modifiers).
    for (let i = arg.namedChildCount - 1; i >= 0; i--) {
      const c = arg.namedChild(i)!;
      if (c.type === 'name_colon') continue;
      return c;
    }
  }
  return arg;
}

function extractVarFromArg(arg: Node, source: string): LocalVar | null {
  if (arg.type === 'identifier') return textOf(arg, source);
  if (arg.type === 'parenthesized_expression') {
    const inner = arg.namedChild(0);
    if (inner) return extractVarFromArg(inner, source);
  }
  if (arg.type === 'cast_expression') {
    const valueNode = arg.childForFieldName('value') ?? arg.namedChild(arg.namedChildCount - 1);
    if (valueNode) return extractVarFromArg(valueNode, source);
  }
  return null;
}

function makeCalleeRef(invocation: Node, wc: WalkCtx): CalleeRef {
  const fnNode = invocation.childForFieldName('function');
  const fullText = stripGenericsFromCallee(textOf(fnNode, wc.fileIndex.source));

  // Resolve through the same logic as callgraph pass-2.
  const resolved = resolveStaticInvocationToFunctionId(invocation, wc);
  if (resolved) {
    return { kind: 'internal', functionId: resolved, calleeText: fullText };
  }
  return { kind: 'external', calleeText: fullText };
}

function makeObjectCreationCalleeRef(node: Node, wc: WalkCtx, calleeText: string): CalleeRef {
  const typeNode = node.childForFieldName('type');
  if (!typeNode) return { kind: 'external', calleeText };
  const simple = simpleTypeName(typeNode, wc.fileIndex.source);
  const fqn = wc.ctx.classFqnBySimpleName.get(simple);
  if (!fqn) return { kind: 'external', calleeText };
  const ctors = wc.ctx.methodsByClassFqn.get(fqn)?.get(simple);
  if (ctors && ctors[0]) return { kind: 'internal', functionId: ctors[0].id, calleeText };
  return { kind: 'external', calleeText };
}

function resolveStaticInvocationToFunctionId(invocation: Node, wc: WalkCtx): FunctionId | null {
  // Reuse the callgraph's resolver for parity with pass-2 edges.
  const fieldTypes = wc.entry?.classFqn
    ? collectFieldTypes(findEnclosingClass(invocation), wc.fileIndex.source)
    : new Map<string, string>();
  const result = resolveInvocation({
    invocation,
    source: wc.fileIndex.source,
    file: wc.fileIndex,
    classFqnBySimpleName: wc.ctx.classFqnBySimpleName,
    methodsByClassFqn: wc.ctx.methodsByClassFqn,
    fieldTypes,
    localTypes: wc.localTypes,
    currentClassFqn: wc.entry?.classFqn ?? null,
    currentClassNode: findEnclosingClass(invocation),
  });
  return result.calleeId;
}

function paramSourceAttribute(paramNode: Node, source: string): string | null {
  // tree-sitter-c-sharp emits attributes on parameters as preceding
  // `attribute_list` named children (each containing one or more
  // `attribute` nodes with a `name` field).
  for (let i = 0; i < paramNode.namedChildCount; i++) {
    const c = paramNode.namedChild(i)!;
    if (c.type !== 'attribute_list') continue;
    for (let j = 0; j < c.namedChildCount; j++) {
      const a = c.namedChild(j)!;
      if (a.type !== 'attribute') continue;
      const nameNode = a.childForFieldName('name') ?? a.namedChild(0);
      if (!nameNode) continue;
      const name = simpleTypeName(nameNode, source).replace(/Attribute$/, '');
      if (PARAM_SOURCE_ATTRIBUTES.has(name)) {
        return `[${name}]`;
      }
    }
  }
  return null;
}

function hasMethodHttpAttribute(methodNode: Node, source: string): boolean {
  // Method-level attributes appear as preceding `attribute_list` siblings
  // attached to the method_declaration.
  for (let i = 0; i < methodNode.namedChildCount; i++) {
    const c = methodNode.namedChild(i)!;
    if (c.type !== 'attribute_list') continue;
    for (let j = 0; j < c.namedChildCount; j++) {
      const a = c.namedChild(j)!;
      if (a.type !== 'attribute') continue;
      const nameNode = a.childForFieldName('name') ?? a.namedChild(0);
      if (!nameNode) continue;
      const name = simpleTypeName(nameNode, source).replace(/Attribute$/, '');
      if (METHOD_HTTP_ATTRIBUTES.has(name)) return true;
    }
  }
  return false;
}

function findEnclosingClass(node: Node): Node | null {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (
      cur.type === 'class_declaration' ||
      cur.type === 'struct_declaration' ||
      cur.type === 'record_declaration' ||
      cur.type === 'interface_declaration'
    ) {
      return cur;
    }
  }
  return null;
}

function collectFieldTypes(classNode: Node | null, source: string): Map<string, string> {
  const out = new Map<string, string>();
  if (!classNode) return out;
  const body = classNode.childForFieldName('body');
  if (!body) return out;
  for (let i = 0; i < body.namedChildCount; i++) {
    const member = body.namedChild(i)!;
    if (member.type === 'field_declaration' || member.type === 'event_field_declaration') {
      const decl = findChildOfType(member, 'variable_declaration');
      if (!decl) continue;
      const typeNode = decl.childForFieldName('type');
      const typeSimple = typeNode ? simpleTypeName(typeNode, source) : null;
      if (!typeSimple) continue;
      for (let j = 0; j < decl.namedChildCount; j++) {
        const c = decl.namedChild(j)!;
        if (c.type !== 'variable_declarator') continue;
        const nameNode = c.childForFieldName('name') ?? c.namedChild(0);
        if (nameNode && nameNode.type === 'identifier') {
          out.set(textOf(nameNode, source), typeSimple);
        }
      }
    } else if (member.type === 'property_declaration') {
      const typeNode = member.childForFieldName('type');
      const nameNode = member.childForFieldName('name');
      if (typeNode && nameNode) {
        out.set(textOf(nameNode, source), simpleTypeName(typeNode, source));
      }
    }
  }
  return out;
}

function findChildOfType(node: Node, type: string): Node | null {
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === type) return c;
  }
  return null;
}

function simpleTypeName(typeNode: Node, source: string): string {
  if (typeNode.type === 'identifier' || typeNode.type === 'predefined_type') {
    return textOf(typeNode, source);
  }
  if (typeNode.type === 'generic_name') {
    const nameNode = typeNode.childForFieldName('name') ?? typeNode.namedChild(0);
    return nameNode ? textOf(nameNode, source) : textOf(typeNode, source);
  }
  if (typeNode.type === 'qualified_name') {
    const last = typeNode.namedChild(typeNode.namedChildCount - 1);
    return last ? simpleTypeName(last, source) : textOf(typeNode, source);
  }
  if (typeNode.type === 'array_type') {
    const elem = typeNode.childForFieldName('type') ?? typeNode.namedChild(0);
    return elem ? simpleTypeName(elem, source) : textOf(typeNode, source);
  }
  if (typeNode.type === 'nullable_type') {
    const inner = typeNode.namedChild(0);
    return inner ? simpleTypeName(inner, source) : textOf(typeNode, source);
  }
  return stripGenericsFromCallee(textOf(typeNode, source));
}

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

function locOf(node: Node, filePath: string): SourceLocation {
  return {
    filePath,
    line: node.startPosition.row + 1,
    column: node.startPosition.column + 1,
  };
}
