import type { Node } from 'web-tree-sitter';
import * as path from 'path';
import { loadLanguage, makeParser } from '../parser';
import { resolveCargoImport } from '../import-mapping/cargo';
import type { ExtractedFile, ImportBinding, LanguageContext, LanguageModule, UsageSlice } from './types';
import { getDetectorsForLanguage } from '../../framework-rules/registry';
import type { EntryPoint } from '../../framework-rules/types';

const RUST_EXTENSIONS: readonly string[] = ['.rs'];

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

function findContainingMethod(node: Node | null, source: string): string | null {
  for (let cur: Node | null = node; cur; cur = cur.parent) {
    if (cur.type === 'function_item') {
      return textOf(cur.childForFieldName('name'), source) || null;
    }
  }
  return null;
}

/** Leftmost identifier of a scoped_identifier chain — the crate root. */
function rootIdentifier(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type === 'identifier') return textOf(node, source);
  if (node.type === 'scoped_identifier') {
    const pathField = node.childForFieldName('path');
    if (pathField) return rootIdentifier(pathField, source);
    return rootIdentifier(node.namedChild(0), source);
  }
  return null;
}

/** Rightmost identifier of a scoped_identifier chain — the imported symbol. */
function leafIdentifier(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type === 'identifier') return textOf(node, source);
  if (node.type === 'scoped_identifier') {
    // Look for a direct identifier child after the `path` field.
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i)!;
      if (node.fieldNameForChild(i) === 'path') continue;
      if (child.type === 'identifier') return textOf(child, source);
    }
    return null;
  }
  return null;
}

function collectImportsFromUse(
  useNode: Node,
  source: string,
  out: ImportBinding[],
  aliasToCrate: Map<string, string>,
  depNames: readonly string[]
): void {
  // useNode can be: identifier | scoped_identifier | scoped_use_list | use_list | use_as_clause
  // Rust binds the RIGHTMOST segment as the local name (unless aliased) —
  // `use tokio::sync::Mutex;` binds `Mutex`, not `tokio`.
  const line = useNode.startPosition.row;

  const bind = (localName: string, sourcePath: string, crate: string): void => {
    out.push({ localName, importedName: null, source: sourcePath, line, kind: 'namespace' });
    aliasToCrate.set(localName, crate);
  };

  const process = (n: Node): void => {
    if (n.type === 'identifier') {
      const crate = textOf(n, source);
      const dep = resolveCargoImport(crate, depNames);
      if (dep) bind(crate, crate, dep);
    } else if (n.type === 'scoped_identifier') {
      const root = rootIdentifier(n, source);
      const leaf = leafIdentifier(n, source);
      if (root) {
        const dep = resolveCargoImport(root, depNames);
        if (dep) bind(leaf ?? root, textOf(n, source), dep);
      }
    } else if (n.type === 'scoped_use_list') {
      const pathField = n.childForFieldName('path');
      const listField = n.childForFieldName('list');
      const rootNode = pathField ?? n.namedChild(0);
      const root = rootNode ? (rootNode.type === 'identifier' ? textOf(rootNode, source) : rootIdentifier(rootNode, source)) : null;
      if (!root) return;
      const dep = resolveCargoImport(root, depNames);
      if (!dep) return;
      const list = listField ?? n.namedChild(1);
      if (list && list.type === 'use_list') {
        for (let i = 0; i < list.namedChildCount; i++) {
          const item = list.namedChild(i)!;
          if (item.type === 'identifier') {
            bind(textOf(item, source), `${root}::${textOf(item, source)}`, dep);
          } else if (item.type === 'scoped_identifier') {
            const leaf = leafIdentifier(item, source);
            if (leaf) bind(leaf, textOf(item, source), dep);
          } else if (item.type === 'use_as_clause') {
            const alias = item.childForFieldName('alias');
            const pathInner = item.childForFieldName('path');
            if (alias && pathInner) {
              bind(textOf(alias, source), textOf(pathInner, source), dep);
            }
          }
        }
      }
    } else if (n.type === 'use_as_clause') {
      const pathNode = n.childForFieldName('path');
      const aliasNode = n.childForFieldName('alias');
      if (pathNode) {
        const crate = rootIdentifier(pathNode, source);
        if (crate) {
          const dep = resolveCargoImport(crate, depNames);
          if (dep && aliasNode) {
            bind(textOf(aliasNode, source), textOf(pathNode, source), dep);
          }
        }
      }
    }
  };

  process(useNode);
}

export const rustModule: LanguageModule = {
  id: 'rust',
  supportsFile(filePath: string): boolean {
    return RUST_EXTENSIONS.includes(path.extname(filePath).toLowerCase());
  },
  async extractFile(source: string, filePath: string, ctx: LanguageContext): Promise<ExtractedFile> {
    const language = await loadLanguage('tree-sitter-rust.wasm');
    const parser = await makeParser(language);
    const tree = parser.parse(source);
    if (!tree) return { filePath, language: 'rust', imports: [], usages: [] };

    const depNames = ctx.deps.map((d) => d.name);
    const imports: ImportBinding[] = [];
    const usages: UsageSlice[] = [];
    const aliasToCrate = new Map<string, string>();

    const walk = (node: Node): void => {
      if (node.type === 'use_declaration') {
        const arg = node.namedChild(0);
        if (arg) collectImportsFromUse(arg, source, imports, aliasToCrate, depNames);
      } else if (node.type === 'call_expression') {
        const fn = node.childForFieldName('function');
        if (fn?.type === 'scoped_identifier') {
          const root = rootIdentifier(fn, source);
          if (root) {
            const crate = aliasToCrate.get(root) ?? resolveCargoImport(root, depNames);
            if (crate) {
              // Extract the rightmost identifier as the method name.
              const fullText = textOf(fn, source);
              const methodName = fullText.split('::').pop() ?? fullText;
              usages.push({
                filePath,
                lineNumber: node.startPosition.row,
                containingMethod: findContainingMethod(node, source),
                targetName: fullText,
                targetType: 'call',
                resolvedMethod: methodName,
                usageLabel: null,
                depName: crate,
              });
            }
          }
        }
      } else if (node.type === 'macro_invocation') {
        const macroNode = node.childForFieldName('macro');
        if (macroNode) {
          const root = rootIdentifier(macroNode, source);
          if (root) {
            const crate = aliasToCrate.get(root);
            if (crate) {
              usages.push({
                filePath,
                lineNumber: node.startPosition.row,
                containingMethod: findContainingMethod(node, source),
                targetName: `${root}!`,
                targetType: 'call',
                resolvedMethod: root,
                usageLabel: null,
                depName: crate,
              });
            }
          }
        }
      }
      for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
    };

    walk(tree.rootNode);

    const extracted: ExtractedFile = { filePath, language: 'rust', imports, usages };
    const entryPoints: EntryPoint[] = [];
    for (const detector of getDetectorsForLanguage('rust')) {
      const aliases = new Set(aliasToCrate.values());
      const triggered = detector.triggerImports.length === 0 || detector.triggerImports.some((t) => aliases.has(t));
      if (!triggered) continue;
      try { entryPoints.push(...detector.detect({ source, tree, file: extracted })); } catch { /* non-fatal */ }
    }
    extracted.entryPoints = entryPoints;
    return extracted;
  },
};
