import type { Node } from 'web-tree-sitter';
import * as path from 'path';
import { loadLanguage, makeParser } from '../parser';
import { resolveMavenImport } from '../import-mapping/maven';
import type { ExtractedFile, ImportBinding, LanguageContext, LanguageModule, UsageSlice } from './types';

const JAVA_EXTENSIONS: readonly string[] = ['.java'];

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

function findContainingMethod(node: Node | null, source: string): string | null {
  for (let cur: Node | null = node; cur; cur = cur.parent) {
    if (cur.type === 'method_declaration' || cur.type === 'constructor_declaration') {
      return textOf(cur.childForFieldName('name'), source) || null;
    }
  }
  return null;
}

/**
 * Maps built from the file's imports + local type declarations. These drive
 * resolution of every call-site back to its originating import.
 */
interface JavaContext {
  /** simpleName (last segment) → fully-qualified import path. Multiple imports can share a simple name; we keep the last one (common in practice). */
  simpleToFqn: Map<string, string>;
  /** localVarName → simpleTypeName. Populated from field_declaration + local_variable_declaration. Instance calls resolve via this → simpleToFqn. */
  varToType: Map<string, string>;
}

function collectImports(root: Node, source: string): { imports: ImportBinding[]; ctx: JavaContext } {
  const imports: ImportBinding[] = [];
  const ctx: JavaContext = { simpleToFqn: new Map(), varToType: new Map() };

  for (let i = 0; i < root.namedChildCount; i++) {
    const child = root.namedChild(i)!;
    if (child.type !== 'import_declaration') continue;

    const fqnNode = child.namedChild(child.namedChildCount - 1);
    if (!fqnNode) continue;
    const fqn = textOf(fqnNode, source);
    if (!fqn) continue;

    // Wildcard import `import a.b.*;` — the asterisk is an anonymous child; in
    // the AST the scoped_identifier ends at `a.b`. We record it but can't
    // bind specific simple names.
    const isWildcard = source.slice(child.startIndex, child.endIndex).trim().endsWith('.*;');

    if (isWildcard) {
      imports.push({
        localName: '',
        importedName: null,
        source: fqn,
        line: child.startPosition.row,
        kind: 'namespace',
      });
      continue;
    }

    const lastDot = fqn.lastIndexOf('.');
    const simpleName = lastDot >= 0 ? fqn.slice(lastDot + 1) : fqn;

    imports.push({
      localName: simpleName,
      importedName: simpleName,
      source: fqn,
      line: child.startPosition.row,
      kind: 'named',
    });
    ctx.simpleToFqn.set(simpleName, fqn);
  }

  return { imports, ctx };
}

function collectVariableTypes(root: Node, source: string, ctx: JavaContext): void {
  const walk = (node: Node): void => {
    if (node.type === 'field_declaration' || node.type === 'local_variable_declaration') {
      const typeNode = node.childForFieldName('type');
      if (typeNode && (typeNode.type === 'type_identifier' || typeNode.type === 'generic_type' || typeNode.type === 'scoped_type_identifier')) {
        const typeName = typeNode.type === 'type_identifier'
          ? textOf(typeNode, source)
          : textOf(typeNode.namedChild(0), source);
        // Iterate all variable_declarators (one declaration can declare many names).
        for (let i = 0; i < node.namedChildCount; i++) {
          const c = node.namedChild(i)!;
          if (c.type !== 'variable_declarator') continue;
          const nameNode = c.childForFieldName('name');
          if (nameNode) ctx.varToType.set(textOf(nameNode, source), typeName);
        }
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };
  walk(root);
}

function collectUsages(
  root: Node,
  source: string,
  filePath: string,
  ctx: JavaContext,
  deps: readonly { name: string; namespace: string | null }[]
): UsageSlice[] {
  const usages: UsageSlice[] = [];

  const tryEmit = (
    importFqn: string,
    targetName: string,
    resolvedMethod: string | null,
    node: Node,
    targetType: UsageSlice['targetType']
  ): void => {
    const depName = resolveMavenImport(importFqn, deps);
    if (!depName) return;
    usages.push({
      filePath,
      lineNumber: node.startPosition.row,
      containingMethod: findContainingMethod(node, source),
      targetName,
      targetType,
      resolvedMethod,
      usageLabel: null,
      depName,
    });
  };

  const resolveIdentifier = (name: string): string | null => {
    const direct = ctx.simpleToFqn.get(name);
    if (direct) return direct;
    const type = ctx.varToType.get(name);
    if (type) return ctx.simpleToFqn.get(type) ?? null;
    return null;
  };

  const walk = (node: Node): void => {
    if (node.type === 'method_invocation') {
      const object = node.childForFieldName('object');
      const name = node.childForFieldName('name');
      const methodName = textOf(name, source);

      if (!object) {
        // Bare `m()` — unqualified; likely local method or static import (which
        // we track via simpleToFqn → fqn without a class receiver isn't
        // enough). Skip for now.
      } else if (object.type === 'identifier') {
        const objName = textOf(object, source);
        const fqn = resolveIdentifier(objName);
        if (fqn) tryEmit(fqn, `${objName}.${methodName}`, methodName, node, 'call');
      }
      // Chained calls (object is itself a method_invocation) resolve to their
      // inner receiver, which we'll pick up via the recursive walk.
    } else if (node.type === 'object_creation_expression') {
      const typeNode = node.childForFieldName('type');
      if (typeNode && (typeNode.type === 'type_identifier' || typeNode.type === 'scoped_type_identifier')) {
        const typeName = typeNode.type === 'type_identifier'
          ? textOf(typeNode, source)
          : textOf(typeNode.namedChild(0), source);
        const fqn = ctx.simpleToFqn.get(typeName);
        if (fqn) tryEmit(fqn, typeName, typeName, node, 'new');
      }
    } else if (node.type === 'method_reference') {
      const receiver = node.namedChild(0);
      const methodIdNode = node.namedChild(1);
      if (receiver?.type === 'identifier') {
        const recvName = textOf(receiver, source);
        const methodId = textOf(methodIdNode, source);
        const fqn = ctx.simpleToFqn.get(recvName);
        if (fqn) tryEmit(fqn, `${recvName}::${methodId}`, methodId, node, 'member');
      }
    }

    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };

  walk(root);
  return usages;
}

export const javaModule: LanguageModule = {
  id: 'java',
  supportsFile(filePath: string): boolean {
    return JAVA_EXTENSIONS.includes(path.extname(filePath).toLowerCase());
  },
  async extractFile(source: string, filePath: string, langCtx: LanguageContext): Promise<ExtractedFile> {
    const language = await loadLanguage('tree-sitter-java.wasm');
    const parser = await makeParser(language);
    const tree = parser.parse(source);
    if (!tree) {
      return { filePath, language: 'java', imports: [], usages: [] };
    }
    const root = tree.rootNode;
    const { imports, ctx } = collectImports(root, source);
    collectVariableTypes(root, source, ctx);
    const usages = collectUsages(root, source, filePath, ctx, langCtx.deps);
    return { filePath, language: 'java', imports, usages };
  },
};
