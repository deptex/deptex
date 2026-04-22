import type { Node } from 'web-tree-sitter';
import * as path from 'path';
import { loadLanguage, makeParser } from '../parser';
import { resolveComposerImport } from '../import-mapping/composer';
import type { ExtractedFile, ImportBinding, LanguageContext, LanguageModule, UsageSlice } from './types';

const PHP_EXTENSIONS: readonly string[] = ['.php'];

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

function findContainingMethod(node: Node | null, source: string): string | null {
  for (let cur: Node | null = node; cur; cur = cur.parent) {
    if (cur.type === 'method_declaration' || cur.type === 'function_definition') {
      return textOf(cur.childForFieldName('name'), source) || null;
    }
  }
  return null;
}

export const phpModule: LanguageModule = {
  id: 'php',
  supportsFile(filePath: string): boolean {
    return PHP_EXTENSIONS.includes(path.extname(filePath).toLowerCase());
  },
  async extractFile(source: string, filePath: string, ctx: LanguageContext): Promise<ExtractedFile> {
    const language = await loadLanguage('tree-sitter-php.wasm');
    const parser = await makeParser(language);
    const tree = parser.parse(source);
    if (!tree) return { filePath, language: 'php', imports: [], usages: [] };

    const depNames = ctx.deps.map((d) => d.name);
    const imports: ImportBinding[] = [];
    const usages: UsageSlice[] = [];

    // simpleClassName → full namespace FQN
    const simpleToFqn = new Map<string, string>();
    // $varName (without $) → simpleClassName
    const varToType = new Map<string, string>();

    const recordImport = (fqn: string, alias: string | null, line: number): void => {
      if (!fqn) return;
      const lastSlash = fqn.lastIndexOf('\\');
      const simpleName = alias ?? (lastSlash >= 0 ? fqn.slice(lastSlash + 1) : fqn);
      imports.push({
        localName: simpleName,
        importedName: simpleName,
        source: fqn,
        line,
        kind: 'named',
      });
      simpleToFqn.set(simpleName, fqn);
    };

    const walk = (node: Node): void => {
      if (node.type === 'namespace_use_declaration') {
        for (let i = 0; i < node.namedChildCount; i++) {
          const clause = node.namedChild(i)!;
          if (clause.type !== 'namespace_use_clause') continue;
          const names: Node[] = [];
          for (let j = 0; j < clause.namedChildCount; j++) {
            const c = clause.namedChild(j)!;
            if (c.type === 'name' || c.type === 'qualified_name') names.push(c);
          }
          if (names.length === 0) continue;
          const fqn = textOf(names[0], source);
          const alias = names.length > 1 ? textOf(names[1], source) : null;
          recordImport(fqn, alias, node.startPosition.row);
        }
      } else if (
        node.type === 'property_declaration' ||
        node.type === 'simple_parameter' ||
        node.type === 'typed_property'
      ) {
        // Best-effort: parameter / property with a type binding.
        const typeNode = node.childForFieldName('type');
        const nameNode = node.childForFieldName('name');
        if (typeNode?.type === 'named_type' || typeNode?.type === 'name') {
          const typeName = textOf(typeNode, source);
          if (nameNode?.type === 'variable_name') {
            const name = textOf(nameNode, source).replace(/^\$/, '');
            if (name) varToType.set(name, typeName);
          }
        }
      } else if (node.type === 'assignment_expression') {
        const left = node.childForFieldName('left');
        const right = node.namedChild(1);
        if (
          left?.type === 'variable_name' &&
          right?.type === 'object_creation_expression'
        ) {
          const varName = textOf(left, source).replace(/^\$/, '');
          const typeNode = right.namedChild(0);
          if (typeNode && (typeNode.type === 'name' || typeNode.type === 'qualified_name')) {
            varToType.set(varName, textOf(typeNode, source));
          }
        }
      } else if (node.type === 'scoped_call_expression') {
        const scope = node.childForFieldName('scope');
        const name = node.childForFieldName('name');
        if (scope?.type === 'name' && name) {
          const className = textOf(scope, source);
          const methodName = textOf(name, source);
          const fqn = simpleToFqn.get(className);
          if (fqn) {
            const depName = resolveComposerImport(fqn, depNames);
            if (depName) {
              usages.push({
                filePath,
                lineNumber: node.startPosition.row,
                containingMethod: findContainingMethod(node, source),
                targetName: `${className}::${methodName}`,
                targetType: 'call',
                resolvedMethod: methodName,
                usageLabel: null,
                depName,
              });
            }
          }
        }
      } else if (node.type === 'object_creation_expression') {
        const typeNode = node.namedChild(0);
        if (typeNode && (typeNode.type === 'name' || typeNode.type === 'qualified_name')) {
          const typeName = textOf(typeNode, source);
          const fqn = simpleToFqn.get(typeName);
          if (fqn) {
            const depName = resolveComposerImport(fqn, depNames);
            if (depName) {
              usages.push({
                filePath,
                lineNumber: node.startPosition.row,
                containingMethod: findContainingMethod(node, source),
                targetName: typeName,
                targetType: 'new',
                resolvedMethod: typeName,
                usageLabel: null,
                depName,
              });
            }
          }
        }
      } else if (node.type === 'member_call_expression') {
        const object = node.childForFieldName('object');
        const name = node.childForFieldName('name');
        if (object?.type === 'variable_name' && name) {
          const varName = textOf(object, source).replace(/^\$/, '');
          const methodName = textOf(name, source);
          const type = varToType.get(varName);
          const fqn = type ? simpleToFqn.get(type) : null;
          if (fqn) {
            const depName = resolveComposerImport(fqn, depNames);
            if (depName) {
              usages.push({
                filePath,
                lineNumber: node.startPosition.row,
                containingMethod: findContainingMethod(node, source),
                targetName: `${varName}->${methodName}`,
                targetType: 'call',
                resolvedMethod: methodName,
                usageLabel: null,
                depName,
              });
            }
          }
        }
      }
      for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
    };

    walk(tree.rootNode);
    return { filePath, language: 'php', imports, usages };
  },
};
