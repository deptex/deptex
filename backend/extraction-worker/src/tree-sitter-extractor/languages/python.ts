import type { Node } from 'web-tree-sitter';
import * as path from 'path';
import { loadLanguage, makeParser } from '../parser';
import { resolvePypiImport } from '../import-mapping/pypi';
import type { ExtractedFile, ImportBinding, LanguageContext, LanguageModule, UsageSlice } from './types';

const PY_EXTENSIONS: readonly string[] = ['.py', '.pyi'];

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

function findContainingMethod(node: Node | null, source: string): string | null {
  for (let cur: Node | null = node; cur; cur = cur.parent) {
    if (cur.type === 'function_definition') {
      return textOf(cur.childForFieldName('name'), source) || null;
    }
  }
  return null;
}

interface AliasMap {
  /** localName → moduleSource. */
  localToSource: Map<string, string>;
  /** localName → originally-imported name (or `*` for module alias). */
  localToExported: Map<string, string>;
}

function firstIdentifier(dotted: Node, source: string): string {
  return textOf(dotted, source);
}

function collectImports(root: Node, source: string): { imports: ImportBinding[]; aliases: AliasMap } {
  const imports: ImportBinding[] = [];
  const aliases: AliasMap = { localToSource: new Map(), localToExported: new Map() };

  const walk = (node: Node): void => {
    if (node.type === 'import_statement') {
      // `import X`, `import X as Y`, `import X, Y as Z`
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i)!;
        if (child.type === 'dotted_name') {
          const modSource = firstIdentifier(child, source);
          if (!modSource) continue;
          const local = modSource.split('.')[0];
          imports.push({ localName: local, importedName: null, source: modSource, line: node.startPosition.row, kind: 'namespace' });
          aliases.localToSource.set(local, modSource);
          aliases.localToExported.set(local, '*');
        } else if (child.type === 'aliased_import') {
          const nameNode = child.childForFieldName('name');
          const aliasNode = child.childForFieldName('alias');
          const modSource = textOf(nameNode, source);
          const local = textOf(aliasNode, source);
          if (modSource && local) {
            imports.push({ localName: local, importedName: null, source: modSource, line: node.startPosition.row, kind: 'namespace' });
            aliases.localToSource.set(local, modSource);
            aliases.localToExported.set(local, '*');
          }
        }
      }
    } else if (node.type === 'import_from_statement') {
      // Grammar: first named child is the module, all subsequent dotted_name /
      // aliased_import / wildcard_import children are the imports. Field-name
      // lookup is unreliable across versions, so we skip the first dotted_name
      // positionally.
      const line = node.startPosition.row;
      let moduleSeen = false;
      let modSource = '';
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i)!;
        if (!moduleSeen) {
          if (child.type === 'dotted_name') {
            modSource = textOf(child, source);
            moduleSeen = true;
          } else if (child.type === 'relative_import') {
            // `from . import x` / `from .. import y` — first-party, skip entirely.
            return;
          }
          continue;
        }
        if (!modSource) break;
        if (child.type === 'dotted_name') {
          const exported = textOf(child, source);
          const local = exported.split('.')[0];
          imports.push({ localName: local, importedName: exported, source: modSource, line, kind: 'named' });
          aliases.localToSource.set(local, modSource);
          aliases.localToExported.set(local, exported);
        } else if (child.type === 'aliased_import') {
          const nameNode = child.childForFieldName('name');
          const aliasNode = child.childForFieldName('alias');
          const exported = textOf(nameNode, source);
          const local = textOf(aliasNode, source);
          if (exported && local) {
            imports.push({ localName: local, importedName: exported, source: modSource, line, kind: 'named' });
            aliases.localToSource.set(local, modSource);
            aliases.localToExported.set(local, exported);
          }
        } else if (child.type === 'wildcard_import') {
          imports.push({ localName: '*', importedName: null, source: modSource, line, kind: 'namespace' });
        }
      }
    }

    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };

  walk(root);
  return { imports, aliases };
}

function collectUsages(
  root: Node,
  source: string,
  aliases: AliasMap,
  filePath: string,
  depNames: readonly string[]
): UsageSlice[] {
  const usages: UsageSlice[] = [];

  const tryEmit = (
    localName: string,
    targetName: string,
    resolvedMethod: string | null,
    node: Node,
    targetType: UsageSlice['targetType']
  ): void => {
    const src = aliases.localToSource.get(localName);
    if (!src) return;
    const depName = resolvePypiImport(src, depNames);
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

  const walk = (node: Node): void => {
    if (node.type === 'call') {
      const fn = node.childForFieldName('function');
      if (fn?.type === 'identifier') {
        const name = textOf(fn, source);
        if (aliases.localToSource.has(name)) {
          const exported = aliases.localToExported.get(name);
          tryEmit(name, name, exported ?? name, node, 'call');
        }
      } else if (fn?.type === 'attribute') {
        const object = fn.childForFieldName('object');
        const attr = fn.childForFieldName('attribute');
        if (object?.type === 'identifier' && attr) {
          const objName = textOf(object, source);
          const propName = textOf(attr, source);
          if (aliases.localToSource.has(objName)) {
            tryEmit(objName, `${objName}.${propName}`, propName, node, 'call');
          }
        }
      }
    }

    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };

  walk(root);
  return usages;
}

export const pythonModule: LanguageModule = {
  id: 'python',
  supportsFile(filePath: string): boolean {
    return PY_EXTENSIONS.includes(path.extname(filePath).toLowerCase());
  },
  async extractFile(source: string, filePath: string, ctx: LanguageContext): Promise<ExtractedFile> {
    const language = await loadLanguage('tree-sitter-python.wasm');
    const parser = await makeParser(language);
    const tree = parser.parse(source);
    if (!tree) {
      return { filePath, language: 'python', imports: [], usages: [] };
    }
    const { imports, aliases } = collectImports(tree.rootNode, source);
    const depNames = ctx.deps.map((d) => d.name);
    const usages = collectUsages(tree.rootNode, source, aliases, filePath, depNames);
    return { filePath, language: 'python', imports, usages };
  },
};
