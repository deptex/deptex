/**
 * Per-function intermediate representation for the taint propagator.
 *
 * The IR is intentionally flat: a list of `Step`s in syntactic order. We do
 * NOT model branches as control-flow joins in M2 — branches over-approximate
 * by treating the IR as straight-line, which is sound for forward taint
 * propagation (we never miss a flow this way; we may emit a flow on a path
 * that's logically dead). Real control-flow, alias analysis, and async/await
 * modeling are M3+ refinements.
 *
 * Each Step references local variable names by string. The propagator
 * maintains a `Map<varName, TaintTrace>` per function and walks the Step
 * list in order, applying each Step's effect to the env.
 */

import * as ts from 'typescript';
import type { FunctionId } from './types';

export type LocalVar = string;

export interface SourceLocation {
  filePath: string;
  line: number;
  column: number;
}

/** Reference to the callee at a Call step. */
export type CalleeRef =
  /** Resolved to a FunctionNode in the callgraph. */
  | { kind: 'internal'; functionId: FunctionId; calleeText: string }
  /** Callee text matched by an external pattern (sink/sanitizer/source) — see calleeText. */
  | { kind: 'external'; calleeText: string }
  /** Couldn't resolve — propagator over-approximates if any arg is tainted. */
  | { kind: 'unresolved'; calleeText: string };

/**
 * One step in the per-function IR.
 *
 * - `source`:      `target = <pattern matching a FrameworkSource>`
 * - `assign`:      `target = source` — copy taint between locals (or no-op if untainted)
 * - `call`:        `[target = ] callee(args)` — args carry taint to the callee, returns may carry taint back
 * - `return`:      `return [expr]` — propagates taint from expr back to the caller's call-site assignment target
 *
 * A "branch" Step is intentionally omitted in M2 — the order of steps in the
 * list reflects syntactic order, and branches join trivially.
 */
export type Step =
  | {
      kind: 'source';
      target: LocalVar;
      sourceText: string;
      loc: SourceLocation;
      /**
       * `weak: true` — only set target taint when a FrameworkSource pattern
       * matches the sourceText exactly; skip the receiver-root fallback and
       * do NOT delete target on no-match. Used by the Ruby lowerer to emit
       * a *parity* source step alongside a `call` step for 0-arg method
       * invocations (`params.x`, where syntactically the call shape hides
       * what is semantically an accessor read). Without this, the call
       * step's external-fallback would clobber any target taint a non-weak
       * source step had just set, AND a non-weak source step on a sanitizer
       * call like `q.to_i` would re-taint via the receiver-root fallback
       * after the sanitizer had cleared it.
       */
      weak?: boolean;
    }
  | { kind: 'assign'; target: LocalVar; from: LocalVar | null; loc: SourceLocation }
  | {
      kind: 'call';
      target: LocalVar | null;
      callee: CalleeRef;
      /** Argument expressions; each entry is the local var that argument resolves to (null for non-var args like literals). */
      args: (LocalVar | null)[];
      /** The full text of each argument expression (used for sink/sanitizer pattern matching). */
      argTexts: string[];
      /**
       * Positions in `args` that came from keyword arguments (Python kwargs,
       * other languages may extend later). When present and non-empty, a
       * sink matcher with positional `argument_indices` should ALSO consider
       * these positions tainted — because the language's positional indexing
       * is not stable when the caller binds args by name. Over-approximation
       * is intentional: any false-positive here is caught by Gate 3 fixture
       * round-trip in rule-generator validation. Empty / undefined means all
       * args were positional (or the lowerer doesn't model kwargs yet).
       */
      kwargIndices?: number[];
      /**
       * Parallel to `args` — when a position is a keyword argument, this
       * carries the kwarg name; positional args carry null. Phase F4: the
       * non-taint detector reads these to evaluate sanitizer-absence
       * contracts (`requests.Session(verify=False)` → kwargNames[0] ===
       * 'verify'). Only Python's IR lowerer populates this today; JS uses
       * options-object property parsing in the non-taint detector directly.
       */
      kwargNames?: (string | null)[];
      loc: SourceLocation;
    }
  | { kind: 'return'; from: LocalVar | null; loc: SourceLocation };

export interface IrFunction {
  /** Matches Callgraph.FunctionNode.id. */
  id: FunctionId;
  /** Parameter names in source order. */
  params: LocalVar[];
  /** Steps in syntactic order. */
  steps: Step[];
}

export interface LowerOptions {
  /** Workspace-relative file path used in step locations. */
  filePath: string;
  /** Source file the function lives in. */
  sourceFile: ts.SourceFile;
  /** TypeChecker for resolving callee symbols → FunctionId. */
  checker: ts.TypeChecker;
  /** Map AST node → FunctionId (from the callgraph build). */
  declarationToNodeId: Map<ts.Node, string>;
  /** Pick a function declaration from a symbol; returns the AST node we registered. */
  pickFunctionDecl: (symbol: ts.Symbol) => ts.Node | undefined;
}

/**
 * Lower a function-like AST node (or a SourceFile, for the synthetic module
 * initializer) into an IrFunction.
 *
 * The lowerer is conservative: any expression we don't recognize becomes
 * either an `assign` from `null` (for definitions) or is dropped (for
 * pure-effect statements). This keeps M2 small; M3 will harden.
 */
export function lowerFunction(
  funcId: FunctionId,
  funcNode: ts.Node,
  opts: LowerOptions,
): IrFunction {
  const params: LocalVar[] = [];
  let body: ts.Node | undefined;

  if (ts.isSourceFile(funcNode)) {
    body = funcNode;
  } else if (
    ts.isFunctionDeclaration(funcNode) ||
    ts.isFunctionExpression(funcNode) ||
    ts.isArrowFunction(funcNode) ||
    ts.isMethodDeclaration(funcNode) ||
    ts.isConstructorDeclaration(funcNode) ||
    ts.isGetAccessorDeclaration(funcNode) ||
    ts.isSetAccessorDeclaration(funcNode)
  ) {
    for (const p of funcNode.parameters) {
      if (ts.isIdentifier(p.name)) params.push(p.name.text);
      else params.push(`<param@${params.length}>`);
    }
    body = funcNode.body;
  }

  const steps: Step[] = [];
  if (body) {
    walkBody(body, steps, opts);
  }
  return { id: funcId, params, steps };
}

/** Walk the body of a function (or module) and emit Steps in syntactic order. */
function walkBody(body: ts.Node, steps: Step[], opts: LowerOptions): void {
  // For the SourceFile module-initializer case we walk top-level statements;
  // for function bodies, the body is a Block with statements.
  const containerStatements: ts.Node[] = [];
  if (ts.isSourceFile(body)) {
    containerStatements.push(...body.statements);
  } else if (ts.isBlock(body)) {
    containerStatements.push(...body.statements);
  } else {
    // Arrow with expression body: `(x) => expr`. Treat expr as `return expr`.
    emitReturnFromExpression(body as ts.Expression, steps, opts);
    return;
  }

  for (const stmt of containerStatements) {
    walkStatement(stmt, steps, opts);
  }
}

function walkStatement(stmt: ts.Node, steps: Step[], opts: LowerOptions): void {
  // Recurse into nested blocks (if, try, for, while, ...) — flatten control
  // flow because M2 over-approximates branches.
  if (ts.isBlock(stmt)) {
    for (const s of stmt.statements) walkStatement(s, steps, opts);
    return;
  }
  if (ts.isIfStatement(stmt)) {
    // Walk the condition for sink/source side effects, then both branches.
    walkExpressionAsAssign(stmt.expression, null, steps, opts);
    walkStatement(stmt.thenStatement, steps, opts);
    if (stmt.elseStatement) walkStatement(stmt.elseStatement, steps, opts);
    return;
  }
  if (ts.isForStatement(stmt) || ts.isForOfStatement(stmt) || ts.isForInStatement(stmt)) {
    walkStatement(stmt.statement, steps, opts);
    return;
  }
  if (ts.isWhileStatement(stmt) || ts.isDoStatement(stmt)) {
    walkExpressionAsAssign(stmt.expression, null, steps, opts);
    walkStatement(stmt.statement, steps, opts);
    return;
  }
  if (ts.isTryStatement(stmt)) {
    walkStatement(stmt.tryBlock, steps, opts);
    if (stmt.catchClause) walkStatement(stmt.catchClause.block, steps, opts);
    if (stmt.finallyBlock) walkStatement(stmt.finallyBlock, steps, opts);
    return;
  }
  if (ts.isSwitchStatement(stmt)) {
    walkExpressionAsAssign(stmt.expression, null, steps, opts);
    for (const clause of stmt.caseBlock.clauses) {
      for (const s of clause.statements) walkStatement(s, steps, opts);
    }
    return;
  }

  if (ts.isVariableStatement(stmt)) {
    for (const decl of stmt.declarationList.declarations) {
      if (!decl.initializer) continue;
      const target = ts.isIdentifier(decl.name) ? decl.name.text : null;
      walkExpressionAsAssign(decl.initializer, target, steps, opts);
    }
    return;
  }

  if (ts.isExpressionStatement(stmt)) {
    walkExpressionAsAssign(stmt.expression, null, steps, opts);
    return;
  }

  if (ts.isReturnStatement(stmt)) {
    if (stmt.expression) emitReturnFromExpression(stmt.expression, steps, opts);
    else steps.push({ kind: 'return', from: null, loc: locOf(stmt, opts) });
    return;
  }
}

/**
 * Lower an expression that's being either assigned to a target var, or
 * evaluated for its side effects (target=null). Emits either a 'source',
 * 'assign', or 'call' step (or no step for inert expressions).
 */
function walkExpressionAsAssign(
  expr: ts.Expression,
  target: LocalVar | null,
  steps: Step[],
  opts: LowerOptions,
): void {
  // Handle assignment expressions like `x = foo()` — treat as if the lhs
  // were a variable declaration's initializer.
  if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
    const lhs = expr.left;
    // Computed-key assignment: `obj[req.query.x] = rhs` should taint `obj`
    // from BOTH the key and the rhs. Without this, the source pattern inside
    // the key (`req.query.x`) is never read and the object never gains taint
    // from the AI-rule shape `obj[req.query.x] = ...`. Unlocks code-injection
    // flows where the object is later consumed by a template/eval sink.
    if (ts.isElementAccessExpression(lhs) && ts.isIdentifier(lhs.expression)) {
      const objName = lhs.expression.text;
      walkExpressionAsAssign(lhs.argumentExpression, objName, steps, opts);
      walkExpressionAsAssign(expr.right, objName, steps, opts);
      return;
    }
    const lhsName = ts.isIdentifier(lhs) ? lhs.text : null;
    walkExpressionAsAssign(expr.right, lhsName, steps, opts);
    return;
  }

  // Await unwraps — propagate through to the inner expression.
  if (ts.isAwaitExpression(expr)) {
    walkExpressionAsAssign(expr.expression, target, steps, opts);
    return;
  }
  // Parenthesized / non-null-assertion / type-assertion are pass-throughs.
  if (ts.isParenthesizedExpression(expr) || ts.isNonNullExpression(expr)) {
    walkExpressionAsAssign(expr.expression, target, steps, opts);
    return;
  }
  if (ts.isAsExpression(expr) || ts.isTypeAssertionExpression(expr)) {
    walkExpressionAsAssign(expr.expression, target, steps, opts);
    return;
  }

  // Call expression (or `new Foo(args)`).
  if (ts.isCallExpression(expr) || ts.isNewExpression(expr)) {
    // Method-chain support: if the callee is a member access on an inner
    // call (`a.b(x).c()`), lower the inner call as its own Step first so
    // its sink-matching fires. Without this, `res.location(q).end()` would
    // only fire `<chain>.end` as the outer callee and silently drop the
    // `res.location(*)` sink. Recurses through deeper chains (`a().b().c()`)
    // by calling walkExpressionAsAssign on the inner call, which re-enters
    // this branch.
    if (ts.isCallExpression(expr)) {
      const calleeExpr = expr.expression;
      if (
        (ts.isPropertyAccessExpression(calleeExpr) || ts.isElementAccessExpression(calleeExpr)) &&
        (ts.isCallExpression(calleeExpr.expression) || ts.isNewExpression(calleeExpr.expression))
      ) {
        const innerTmp = `<chain@${steps.length}>`;
        walkExpressionAsAssign(calleeExpr.expression, innerTmp, steps, opts);
        // Note: we don't try to propagate the inner call's return taint into
        // the outer call's args or target — that's a separate alias-tracking
        // concern handled imprecisely by the existing inner-as-temp logic
        // for direct args. The point of the pre-walk here is only to give
        // the worklist a chance to fire the inner-call sink.
      }
    }
    const callee = resolveCallee(expr, opts);
    const args: (LocalVar | null)[] = [];
    const argTexts: string[] = [];
    const argList = expr.arguments ?? [];
    for (let i = 0; i < argList.length; i++) {
      const a = argList[i];
      argTexts.push(a.getText(opts.sourceFile));
      const direct = extractVarFromArg(a);
      if (direct) {
        args.push(direct);
        continue;
      }
      // Synthesize a temp var for non-Identifier args so taint can flow through
      // template literals (`db.query(\`SELECT ${id}\`)`), direct property
      // access (`fs.readFile(req.body.x)`), nested calls (`exec(decode(x))`),
      // and string concatenation. The lowered expression's effects fire BEFORE
      // the call step, so the propagator sees the temp's taint at call time.
      const tmp = `<arg${i}@${steps.length}>`;
      walkExpressionAsAssign(a, tmp, steps, opts);
      args.push(tmp);
    }
    steps.push({
      kind: 'call',
      target,
      callee,
      args,
      argTexts,
      loc: locOf(expr, opts),
    });
    return;
  }

  // Property access / element access — text becomes the source-pattern key.
  if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) {
    if (target) {
      steps.push({
        kind: 'source',
        target,
        sourceText: expr.getText(opts.sourceFile),
        loc: locOf(expr, opts),
      });
    }
    return;
  }

  // Plain identifier — copy taint.
  if (ts.isIdentifier(expr)) {
    if (target) {
      steps.push({ kind: 'assign', target, from: expr.text, loc: locOf(expr, opts) });
    }
    return;
  }

  // Object/array literals: walk fields; if any field carries taint, the
  // whole literal is conservatively tainted into target.
  if (ts.isObjectLiteralExpression(expr)) {
    for (const prop of expr.properties) {
      if (ts.isPropertyAssignment(prop)) {
        walkExpressionAsAssign(prop.initializer, target, steps, opts);
      } else if (ts.isShorthandPropertyAssignment(prop)) {
        if (target) steps.push({ kind: 'assign', target, from: prop.name.text, loc: locOf(prop, opts) });
      }
    }
    return;
  }
  if (ts.isArrayLiteralExpression(expr)) {
    for (const el of expr.elements) {
      walkExpressionAsAssign(el, target, steps, opts);
    }
    return;
  }

  // Template literals — any tainted ${expr} taints the whole template.
  if (ts.isTemplateExpression(expr)) {
    for (const span of expr.templateSpans) {
      walkExpressionAsAssign(span.expression, target, steps, opts);
    }
    return;
  }

  // Binary expressions (concat, comparisons): walk both sides.
  if (ts.isBinaryExpression(expr)) {
    walkExpressionAsAssign(expr.left, target, steps, opts);
    walkExpressionAsAssign(expr.right, target, steps, opts);
    return;
  }

  // Conditional `cond ? a : b` — both branches taint target.
  if (ts.isConditionalExpression(expr)) {
    walkExpressionAsAssign(expr.whenTrue, target, steps, opts);
    walkExpressionAsAssign(expr.whenFalse, target, steps, opts);
    return;
  }

  // Anything else (literals, this, super, regex, function expressions
  // appearing in expression position) — inert for taint.
}

function emitReturnFromExpression(expr: ts.Expression, steps: Step[], opts: LowerOptions): void {
  // For `return foo()` we still need the call to fire (for sink detection),
  // and we need to model that the call's result may flow to the caller.
  // Strategy: lower the expression as if assigned to a synthetic var, then
  // emit return from that var.
  if (ts.isIdentifier(expr)) {
    steps.push({ kind: 'return', from: expr.text, loc: locOf(expr, opts) });
    return;
  }
  const synthetic = `<retval@${steps.length}>`;
  walkExpressionAsAssign(expr, synthetic, steps, opts);
  steps.push({ kind: 'return', from: synthetic, loc: locOf(expr, opts) });
}

/** Extract the local-var name from an argument expression, if it is one. */
function extractVarFromArg(arg: ts.Expression): LocalVar | null {
  if (ts.isIdentifier(arg)) return arg.text;
  if (ts.isParenthesizedExpression(arg) || ts.isNonNullExpression(arg)) {
    return extractVarFromArg(arg.expression);
  }
  if (ts.isAsExpression(arg) || ts.isTypeAssertionExpression(arg)) {
    return extractVarFromArg(arg.expression);
  }
  return null;
}

function resolveCallee(
  expr: ts.CallExpression | ts.NewExpression,
  opts: LowerOptions,
): CalleeRef {
  const calleeText = expr.expression.getText(opts.sourceFile);
  let symbol = opts.checker.getSymbolAtLocation(expr.expression);
  if (!symbol && ts.isPropertyAccessExpression(expr.expression)) {
    symbol = opts.checker.getSymbolAtLocation(expr.expression.name);
  }
  if (symbol && symbol.flags & ts.SymbolFlags.Alias) {
    try {
      symbol = opts.checker.getAliasedSymbol(symbol);
    } catch {
      // ignore
    }
  }
  if (symbol) {
    const decl = opts.pickFunctionDecl(symbol);
    if (decl) {
      const id = opts.declarationToNodeId.get(decl);
      if (id) return { kind: 'internal', functionId: id, calleeText };
      // External (node_modules, lib) decl — let pattern matching handle it.
      return { kind: 'external', calleeText };
    }
  }
  return { kind: 'unresolved', calleeText };
}

function locOf(node: ts.Node, opts: LowerOptions): SourceLocation {
  const { line, character } = opts.sourceFile.getLineAndCharacterOfPosition(node.getStart(opts.sourceFile));
  return { filePath: opts.filePath, line: line + 1, column: character + 1 };
}
