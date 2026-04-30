/**
 * Per-method intermediate representation for the Java taint propagator.
 *
 * Mirrors the TS lowerer (../ir.ts) — emits the same Step shape so the
 * downstream propagation algorithm is language-agnostic.
 *
 * Java specifics:
 *   - Method invocations resolve to a CalleeRef using the same callgraph
 *     resolution as pass-2 of callgraph.ts. We don't re-run resolution; the
 *     IrFunction is built from the same JavaCallgraphContext.
 *   - `new Type(args)` is emitted as a Call step with the constructor's
 *     calleeText set to `new Type` (matching what we use for callgraph edges
 *     and what java-stdlib.yaml sink patterns expect).
 *   - Method/controller parameters annotated `@RequestParam` / `@PathVariable`
 *     / `@RequestBody` / `@RequestHeader` are pre-tainted by emitting a
 *     synthetic `source` step at the start of the method body. The pattern
 *     that matches them is `@RequestParam`, `@PathVariable`, etc. (matched
 *     verbatim in spring-boot.yaml).
 *   - Field access becomes a `source` step (matching property-pattern entries
 *     like `request.parameter.*`).
 *
 * Unhandled / over-approximated:
 *   - Lambda bodies — walked as if inline statements; closures over locals
 *     leak into the lambda's lexical env via ambient locals.
 *   - try-with-resources — declarations are walked, but the resource
 *     specifier is treated as an assignment.
 *   - Switch expressions — case bodies are flattened.
 *   - Cast expressions — pass-through.
 *   - String concatenation `a + b` — both sides taint the target (same as
 *     binary-expr handling in TS).
 */

import type { Node } from 'web-tree-sitter';
import type { CalleeRef, IrFunction, LocalVar, SourceLocation, Step } from '../ir';
import type { FunctionId } from '../types';
import type { JavaCallgraphContext, JavaFileIndex, JavaMethodEntry } from './callgraph';

export interface LowerJavaOptions {
  ctx: JavaCallgraphContext;
  fileIndex: JavaFileIndex;
  /** The method/constructor's JavaMethodEntry (null for synthetic module-init). */
  entry: JavaMethodEntry | null;
}

export function lowerJavaMethod(methodNode: Node, opts: LowerJavaOptions): IrFunction {
  const { fileIndex, entry, ctx } = opts;
  const params: LocalVar[] = [];
  const steps: Step[] = [];

  const funcId = entry?.id ?? makeModuleId(fileIndex.relativePath);

  // Collect locals/types to use during resolution
  const localTypes = new Map<string, string>();
  const fieldTypes = entry?.classFqn
    ? collectFieldTypes(findEnclosingClass(methodNode), fileIndex.source)
    : new Map<string, string>();

  // Parameters
  if (entry) {
    const paramNode = methodNode.childForFieldName('parameters');
    if (paramNode) {
      for (let i = 0; i < paramNode.namedChildCount; i++) {
        const p = paramNode.namedChild(i)!;
        if (p.type !== 'formal_parameter' && p.type !== 'spread_parameter') continue;
        const nameNode = p.childForFieldName('name');
        const paramName = nameNode ? textOf(nameNode, fileIndex.source) : `<param@${i}>`;
        params.push(paramName);
        const typeNode = p.childForFieldName('type');
        if (typeNode) localTypes.set(paramName, simpleTypeName(typeNode, fileIndex.source));

        // If the parameter has a Spring-style source annotation, emit a
        // synthetic `source` step so the propagator sees the param as
        // pre-tainted.
        const sourceText = sourceAnnotationOnParam(p, fileIndex.source);
        if (sourceText) {
          steps.push({
            kind: 'source',
            target: paramName,
            sourceText,
            loc: locOf(p, fileIndex.relativePath),
          });
        }
      }
    }
  }

  // Walk body
  const body = methodNode.childForFieldName('body');
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
  ctx: JavaCallgraphContext;
  fileIndex: JavaFileIndex;
  entry: JavaMethodEntry | null;
  localTypes: Map<string, string>;
  fieldTypes: Map<string, string>;
}

function walkStatement(node: Node, steps: Step[], wc: WalkCtx): void {
  const t = node.type;
  if (t === 'block') {
    for (let i = 0; i < node.namedChildCount; i++) walkStatement(node.namedChild(i)!, steps, wc);
    return;
  }
  if (t === 'if_statement') {
    const cond = node.childForFieldName('condition');
    if (cond) walkExpressionAsAssign(cond, null, steps, wc);
    const then = node.childForFieldName('consequence');
    if (then) walkStatement(then, steps, wc);
    const els = node.childForFieldName('alternative');
    if (els) walkStatement(els, steps, wc);
    return;
  }
  if (t === 'while_statement' || t === 'do_statement' || t === 'for_statement' || t === 'enhanced_for_statement') {
    const cond = node.childForFieldName('condition');
    if (cond) walkExpressionAsAssign(cond, null, steps, wc);
    // for-each: target var binds to iterable element — record assign
    if (t === 'enhanced_for_statement') {
      const nameNode = node.childForFieldName('name');
      const valueNode = node.childForFieldName('value');
      if (nameNode && valueNode) {
        const target = textOf(nameNode, wc.fileIndex.source);
        walkExpressionAsAssign(valueNode, target, steps, wc);
      }
    }
    const bod = node.childForFieldName('body');
    if (bod) walkStatement(bod, steps, wc);
    return;
  }
  if (t === 'try_statement' || t === 'try_with_resources_statement') {
    // Walk resource specifier (try-with-resources) like local declarations
    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i)!;
      if (c.type === 'resource_specification' || c.type === 'resource') {
        walkStatement(c, steps, wc);
      }
    }
    const bod = node.childForFieldName('body');
    if (bod) walkStatement(bod, steps, wc);
    // Catch + finally walk as blocks
    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i)!;
      if (c.type === 'catch_clause') {
        const cb = c.childForFieldName('body');
        if (cb) walkStatement(cb, steps, wc);
      } else if (c.type === 'finally_clause') {
        for (let j = 0; j < c.namedChildCount; j++) {
          const cc = c.namedChild(j)!;
          if (cc.type === 'block') walkStatement(cc, steps, wc);
        }
      }
    }
    return;
  }
  if (t === 'resource_specification') {
    for (let i = 0; i < node.namedChildCount; i++) walkStatement(node.namedChild(i)!, steps, wc);
    return;
  }
  if (t === 'resource') {
    // resource: type identifier name = expression
    const nameNode = node.childForFieldName('name');
    const valueNode = node.childForFieldName('value');
    const typeNode = node.childForFieldName('type');
    if (nameNode && valueNode) {
      const target = textOf(nameNode, wc.fileIndex.source);
      if (typeNode) wc.localTypes.set(target, simpleTypeName(typeNode, wc.fileIndex.source));
      walkExpressionAsAssign(valueNode, target, steps, wc);
    }
    return;
  }
  if (t === 'switch_expression' || t === 'switch_statement') {
    const cond = node.childForFieldName('condition');
    if (cond) walkExpressionAsAssign(cond, null, steps, wc);
    const blk = node.childForFieldName('body');
    if (blk) {
      for (let i = 0; i < blk.namedChildCount; i++) {
        const c = blk.namedChild(i)!;
        if (c.type === 'switch_block_statement_group' || c.type === 'switch_rule') {
          for (let j = 0; j < c.namedChildCount; j++) {
            walkStatement(c.namedChild(j)!, steps, wc);
          }
        }
      }
    }
    return;
  }
  if (t === 'local_variable_declaration') {
    const typeNode = node.childForFieldName('type');
    const typeSimple = typeNode ? simpleTypeName(typeNode, wc.fileIndex.source) : null;
    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i)!;
      if (c.type !== 'variable_declarator') continue;
      const nameNode = c.childForFieldName('name');
      const valueNode = c.childForFieldName('value');
      if (!nameNode) continue;
      const target = textOf(nameNode, wc.fileIndex.source);
      if (typeSimple) wc.localTypes.set(target, typeSimple);
      if (valueNode) walkExpressionAsAssign(valueNode, target, steps, wc);
    }
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
      // If `return foo()` etc — synthesize via a temp.
      if (inner.type === 'identifier') {
        steps.push({ kind: 'return', from: textOf(inner, wc.fileIndex.source), loc: locOf(inner, wc.fileIndex.relativePath) });
        return;
      }
      const tmp = `<retval@${steps.length}>`;
      walkExpressionAsAssign(inner, tmp, steps, wc);
      steps.push({ kind: 'return', from: tmp, loc: locOf(inner, wc.fileIndex.relativePath) });
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
  // synchronized / labeled / yield: walk inner block(s)
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'block') walkStatement(c, steps, wc);
  }
}

function walkExpressionAsAssign(
  expr: Node,
  target: LocalVar | null,
  steps: Step[],
  wc: WalkCtx,
): void {
  const t = expr.type;
  // Parenthesized / cast pass-through
  if (t === 'parenthesized_expression') {
    const inner = expr.namedChild(0);
    if (inner) walkExpressionAsAssign(inner, target, steps, wc);
    return;
  }
  if (t === 'cast_expression') {
    const valueNode = expr.childForFieldName('value');
    if (valueNode) walkExpressionAsAssign(valueNode, target, steps, wc);
    return;
  }
  // Assignment: `x = expr` (also `x += expr`)
  if (t === 'assignment_expression') {
    const lhs = expr.childForFieldName('left');
    const rhs = expr.childForFieldName('right');
    let lhsName: LocalVar | null = null;
    if (lhs && lhs.type === 'identifier') lhsName = textOf(lhs, wc.fileIndex.source);
    else if (lhs && lhs.type === 'field_access') {
      // `this.x = expr` — treat as plain assign to the field name (simple model)
      const fieldName = lhs.childForFieldName('field');
      if (fieldName) lhsName = textOf(fieldName, wc.fileIndex.source);
    }
    if (rhs) walkExpressionAsAssign(rhs, lhsName, steps, wc);
    return;
  }
  // Method invocation
  if (t === 'method_invocation') {
    const argsNode = expr.childForFieldName('arguments');
    const argList: Node[] = [];
    if (argsNode) {
      for (let i = 0; i < argsNode.namedChildCount; i++) argList.push(argsNode.namedChild(i)!);
    }
    const argLocals: (LocalVar | null)[] = [];
    const argTexts: string[] = [];
    for (let i = 0; i < argList.length; i++) {
      const a = argList[i];
      argTexts.push(textOf(a, wc.fileIndex.source));
      const direct = extractVarFromArg(a, wc.fileIndex.source);
      if (direct) {
        argLocals.push(direct);
        continue;
      }
      const tmp = `<arg${i}@${steps.length}>`;
      walkExpressionAsAssign(a, tmp, steps, wc);
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
  // Object creation
  if (t === 'object_creation_expression') {
    const typeNode = expr.childForFieldName('type');
    const calleeText = typeNode ? `new ${simpleTypeName(typeNode, wc.fileIndex.source)}` : 'new <unknown>';
    const argsNode = expr.childForFieldName('arguments');
    const argList: Node[] = [];
    if (argsNode) {
      for (let i = 0; i < argsNode.namedChildCount; i++) argList.push(argsNode.namedChild(i)!);
    }
    const argLocals: (LocalVar | null)[] = [];
    const argTexts: string[] = [];
    for (let i = 0; i < argList.length; i++) {
      const a = argList[i];
      argTexts.push(textOf(a, wc.fileIndex.source));
      const direct = extractVarFromArg(a, wc.fileIndex.source);
      if (direct) {
        argLocals.push(direct);
        continue;
      }
      const tmp = `<arg${i}@${steps.length}>`;
      walkExpressionAsAssign(a, tmp, steps, wc);
      argLocals.push(tmp);
    }
    const callee = makeObjectCreationCalleeRef(expr, wc, calleeText);
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
  // Field access — `obj.field` or `qualified.path`
  if (t === 'field_access') {
    if (target) {
      // Resolve through localTypes / known classes — but we use the raw text
      // for source-pattern matching (e.g. `request.getParameter` won't show
      // up here because that's a method invocation; this is for property
      // access patterns like `request.parameter.*`).
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
  // Array access
  if (t === 'array_access') {
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
  // Identifier — copy taint
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
  // String concatenation / arithmetic — both sides taint target
  if (t === 'binary_expression') {
    const left = expr.childForFieldName('left');
    const right = expr.childForFieldName('right');
    if (left) walkExpressionAsAssign(left, target, steps, wc);
    if (right) walkExpressionAsAssign(right, target, steps, wc);
    return;
  }
  if (t === 'ternary_expression') {
    const consequent = expr.childForFieldName('consequence');
    const alternative = expr.childForFieldName('alternative');
    if (consequent) walkExpressionAsAssign(consequent, target, steps, wc);
    if (alternative) walkExpressionAsAssign(alternative, target, steps, wc);
    return;
  }
  if (t === 'unary_expression' || t === 'update_expression') {
    const inner = expr.childForFieldName('operand') ?? expr.namedChild(0);
    if (inner) walkExpressionAsAssign(inner, target, steps, wc);
    return;
  }
  // String template / formatted strings — walk children
  if (t === 'template_expression' || t === 'string_interpolation') {
    for (let i = 0; i < expr.namedChildCount; i++) {
      walkExpressionAsAssign(expr.namedChild(i)!, target, steps, wc);
    }
    return;
  }
  // Lambdas — walk body for side-effect-only purposes (not perfect)
  if (t === 'lambda_expression') {
    const body = expr.childForFieldName('body');
    if (body) {
      if (body.type === 'block') walkStatement(body, steps, wc);
      else walkExpressionAsAssign(body, target, steps, wc);
    }
    return;
  }
  // Otherwise: literal / inert.
}

function extractVarFromArg(arg: Node, source: string): LocalVar | null {
  if (arg.type === 'identifier') return textOf(arg, source);
  if (arg.type === 'parenthesized_expression') {
    const inner = arg.namedChild(0);
    if (inner) return extractVarFromArg(inner, source);
  }
  if (arg.type === 'cast_expression') {
    const valueNode = arg.childForFieldName('value');
    if (valueNode) return extractVarFromArg(valueNode, source);
  }
  return null;
}

function makeCalleeRef(node: Node, wc: WalkCtx): CalleeRef {
  const objectField = node.childForFieldName('object');
  const nameField = node.childForFieldName('name');
  const fullText = node.childForFieldName('object')
    ? `${textOf(objectField, wc.fileIndex.source)}.${textOf(nameField, wc.fileIndex.source)}`
    : textOf(nameField, wc.fileIndex.source);

  // Resolve through the same logic as callgraph pass-2.
  const resolved = resolveStaticInvocationToFunctionId(node, wc);
  if (resolved) {
    return { kind: 'internal', functionId: resolved, calleeText: fullText };
  }
  return { kind: 'external', calleeText: fullText };
}

function makeObjectCreationCalleeRef(node: Node, wc: WalkCtx, calleeText: string): CalleeRef {
  const typeNode = node.childForFieldName('type');
  if (!typeNode) return { kind: 'external', calleeText };
  const simple = simpleTypeName(typeNode, wc.fileIndex.source);
  const fqn = wc.fileIndex.imports.get(simple) ?? wc.ctx.classFqnBySimpleName.get(simple);
  if (!fqn) return { kind: 'external', calleeText };
  // Look up constructor
  const ctors = wc.ctx.methodsByClassFqn.get(fqn)?.get(simple);
  if (ctors && ctors[0]) return { kind: 'internal', functionId: ctors[0].id, calleeText };
  return { kind: 'external', calleeText };
}

function resolveStaticInvocationToFunctionId(node: Node, wc: WalkCtx): FunctionId | null {
  const objectField = node.childForFieldName('object');
  const nameField = node.childForFieldName('name');
  if (!nameField) return null;
  const methodName = textOf(nameField, wc.fileIndex.source);

  if (!objectField) {
    // Bare call → enclosing class method or static import
    const cls = wc.entry?.classFqn;
    if (cls) {
      const entries = wc.ctx.methodsByClassFqn.get(cls)?.get(methodName);
      if (entries && entries[0]) return entries[0].id;
    }
    const staticDeclaringClass = wc.fileIndex.imports.get(`static:${methodName}`);
    if (staticDeclaringClass) {
      const entries = wc.ctx.methodsByClassFqn.get(staticDeclaringClass)?.get(methodName);
      if (entries && entries[0]) return entries[0].id;
    }
    return null;
  }

  const objText = textOf(objectField, wc.fileIndex.source);
  if (objText === 'super') {
    const enclosing = findEnclosingClass(node);
    if (!enclosing) return null;
    const superFqn = resolveSuperFqn(enclosing, wc);
    if (!superFqn) return null;
    const entries = wc.ctx.methodsByClassFqn.get(superFqn)?.get(methodName);
    if (entries && entries[0]) return entries[0].id;
    return null;
  }
  if (objText === 'this') {
    const cls = wc.entry?.classFqn;
    if (!cls) return null;
    const entries = wc.ctx.methodsByClassFqn.get(cls)?.get(methodName);
    if (entries && entries[0]) return entries[0].id;
    return null;
  }
  if (objectField.type === 'identifier') {
    const recvName = objText;
    const directClassFqn = wc.ctx.classFqnBySimpleName.get(recvName) ?? wc.fileIndex.imports.get(recvName);
    if (directClassFqn) {
      const entries = wc.ctx.methodsByClassFqn.get(directClassFqn)?.get(methodName);
      if (entries && entries[0]) return entries[0].id;
      return null;
    }
    const typeName = wc.localTypes.get(recvName) ?? wc.fieldTypes.get(recvName);
    if (typeName) {
      const fqn = wc.ctx.classFqnBySimpleName.get(typeName) ?? wc.fileIndex.imports.get(typeName);
      if (fqn) {
        const entries = wc.ctx.methodsByClassFqn.get(fqn)?.get(methodName);
        if (entries && entries[0]) return entries[0].id;
      }
    }
  }
  return null;
}

function resolveSuperFqn(classNode: Node, wc: WalkCtx): string | null {
  if (classNode.type !== 'class_declaration') return null;
  const superclass = classNode.childForFieldName('superclass');
  if (!superclass) return null;
  let typeNode: Node | null = superclass;
  if (superclass.namedChildCount > 0) typeNode = superclass.namedChild(0);
  if (!typeNode) return null;
  const simple = simpleTypeName(typeNode, wc.fileIndex.source);
  return wc.fileIndex.imports.get(simple) ?? wc.ctx.classFqnBySimpleName.get(simple) ?? null;
}

function sourceAnnotationOnParam(paramNode: Node, source: string): string | null {
  const modifiers = paramNode.namedChild(0);
  if (!modifiers || modifiers.type !== 'modifiers') return null;
  for (let i = 0; i < modifiers.namedChildCount; i++) {
    const c = modifiers.namedChild(i)!;
    if (c.type !== 'annotation' && c.type !== 'marker_annotation') continue;
    const nameNode = c.childForFieldName('name') ?? c.namedChild(0);
    if (!nameNode) continue;
    const name = textOf(nameNode, source);
    if (
      name === 'RequestParam' ||
      name === 'PathVariable' ||
      name === 'RequestBody' ||
      name === 'RequestHeader' ||
      name === 'CookieValue' ||
      name === 'ModelAttribute'
    ) {
      return `@${name}`;
    }
  }
  return null;
}

function findEnclosingClass(node: Node): Node | null {
  for (let cur: Node | null = node.parent; cur; cur = cur.parent) {
    if (
      cur.type === 'class_declaration' ||
      cur.type === 'interface_declaration' ||
      cur.type === 'enum_declaration' ||
      cur.type === 'record_declaration'
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
    if (member.type !== 'field_declaration') continue;
    const typeNode = member.childForFieldName('type');
    const typeSimple = typeNode ? simpleTypeName(typeNode, source) : null;
    if (!typeSimple) continue;
    for (let j = 0; j < member.namedChildCount; j++) {
      const c = member.namedChild(j)!;
      if (c.type !== 'variable_declarator') continue;
      const nameNode = c.childForFieldName('name');
      if (nameNode) out.set(textOf(nameNode, source), typeSimple);
    }
  }
  return out;
}

function simpleTypeName(typeNode: Node, source: string): string {
  if (typeNode.type === 'type_identifier') return textOf(typeNode, source);
  if (typeNode.type === 'generic_type') {
    const first = typeNode.namedChild(0);
    return first ? simpleTypeName(first, source) : textOf(typeNode, source);
  }
  if (typeNode.type === 'scoped_type_identifier') {
    const last = typeNode.namedChild(typeNode.namedChildCount - 1);
    return last ? textOf(last, source) : textOf(typeNode, source);
  }
  if (typeNode.type === 'array_type') {
    const elem = typeNode.childForFieldName('element');
    return elem ? simpleTypeName(elem, source) : textOf(typeNode, source);
  }
  return textOf(typeNode, source);
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

function makeModuleId(filePath: string): FunctionId {
  return `${filePath}:1:1:<module>`;
}
