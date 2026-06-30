import type { Node } from 'web-tree-sitter';
import * as path from 'path';
import { parseSource } from '../parser';
import { resolveNpmImport } from '../import-mapping/npm';
import type { ExtractedFile, ImportBinding, LanguageContext, LanguageModule, UsageSlice } from './types';
import { getDetectorsForLanguage } from '../../framework-rules/registry';
import type { EntryPoint } from '../../framework-rules/types';
import { recordDetectorError } from '../detector-errors';

const JS_EXTENSIONS: readonly string[] = ['.js', '.mjs', '.cjs', '.jsx'];
const TS_EXTENSIONS: readonly string[] = ['.ts', '.mts', '.cts'];
const TSX_EXTENSIONS: readonly string[] = ['.tsx'];

function pickWasmForFile(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  if (TSX_EXTENSIONS.includes(ext)) return 'tree-sitter-tsx.wasm';
  if (TS_EXTENSIONS.includes(ext)) return 'tree-sitter-typescript.wasm';
  return 'tree-sitter-javascript.wasm';
}

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

/** Walk ancestors to find enclosing function/method name for a call site. */
function findContainingMethod(node: Node | null, source: string): string | null {
  for (let cur: Node | null = node; cur; cur = cur.parent) {
    const t = cur.type;
    if (t === 'function_declaration' || t === 'generator_function_declaration') {
      return textOf(cur.childForFieldName('name'), source) || null;
    }
    if (t === 'method_definition') {
      return textOf(cur.childForFieldName('name'), source) || null;
    }
    if (t === 'function_expression' || t === 'arrow_function' || t === 'generator_function') {
      // Try parent variable_declarator / assignment_expression for a name.
      const parent = cur.parent;
      if (parent?.type === 'variable_declarator') {
        const n = parent.childForFieldName('name');
        if (n) return textOf(n, source);
      }
      if (parent?.type === 'assignment_expression') {
        const left = parent.childForFieldName('left');
        if (left) return textOf(left, source);
      }
      if (parent?.type === 'pair') {
        const key = parent.childForFieldName('key');
        if (key) return textOf(key, source);
      }
      // Class-field arrow function: `handler = () => {}` inside a class body.
      if (parent?.type === 'field_definition' || parent?.type === 'public_field_definition') {
        const n = parent.childForFieldName('name') ?? parent.childForFieldName('property');
        if (n) return textOf(n, source);
      }
    }
  }
  return null;
}

interface AliasMap {
  /** localName → moduleSource (e.g. `_` → `lodash`, `template` → `lodash`). */
  localToSource: Map<string, string>;
  /** localName → originalExportedName (e.g. `cd` → `cloneDeep`, default imports map to `default`). */
  localToExported: Map<string, string>;
}

function collectImports(root: Node, source: string): { imports: ImportBinding[]; aliases: AliasMap } {
  const imports: ImportBinding[] = [];
  const aliases: AliasMap = { localToSource: new Map(), localToExported: new Map() };

  const walk = (node: Node): void => {
    if (node.type === 'import_statement') {
      const srcNode = node.childForFieldName('source');
      const srcStr = extractStringLiteral(srcNode, source);
      if (!srcStr) return;
      const line = node.startPosition.row;

      // `import 'module';` — side-effect only
      let clause: Node | null = null;
      for (let i = 0; i < node.namedChildCount; i++) {
        const c = node.namedChild(i)!;
        if (c.type === 'import_clause') { clause = c; break; }
      }
      if (!clause) {
        imports.push({ localName: '', importedName: null, source: srcStr, line, kind: 'side-effect' });
        return;
      }

      for (let i = 0; i < clause.namedChildCount; i++) {
        const spec = clause.namedChild(i)!;
        if (spec.type === 'identifier') {
          // default import: `import foo from 'bar'`
          const local = textOf(spec, source);
          imports.push({ localName: local, importedName: 'default', source: srcStr, line, kind: 'default' });
          aliases.localToSource.set(local, srcStr);
          aliases.localToExported.set(local, 'default');
        } else if (spec.type === 'namespace_import') {
          // `import * as ns from 'bar'`
          const nameNode = spec.namedChild(0);
          const local = textOf(nameNode, source);
          if (local) {
            imports.push({ localName: local, importedName: null, source: srcStr, line, kind: 'namespace' });
            aliases.localToSource.set(local, srcStr);
          }
        } else if (spec.type === 'named_imports') {
          // `import { a, b as c } from 'bar'`
          for (let j = 0; j < spec.namedChildCount; j++) {
            const imp = spec.namedChild(j)!;
            if (imp.type !== 'import_specifier') continue;
            const name = imp.childForFieldName('name');
            const alias = imp.childForFieldName('alias');
            const imported = textOf(name, source);
            const local = alias ? textOf(alias, source) : imported;
            if (imported && local) {
              imports.push({ localName: local, importedName: imported, source: srcStr, line, kind: 'named' });
              aliases.localToSource.set(local, srcStr);
              aliases.localToExported.set(local, imported);
            }
          }
        }
      }
    } else if (
      node.type === 'variable_declarator' ||
      node.type === 'assignment_expression'
    ) {
      // CJS: `const x = require('m')`, `const { a, b: c } = require('m')`,
      // `x = require('m')`, `const x = require('m')(...)` (IIFE — fastify style).
      const valueField =
        node.type === 'variable_declarator' ? node.childForFieldName('value') : node.childForFieldName('right');
      // Unwrap IIFE: `require('m')(config)` → use the inner require call and
      // flag the binding so detectors can treat the local name as an instance.
      let requireCall: import('web-tree-sitter').Node | null = null;
      let importKind: ImportBinding['kind'] = 'cjs-require';
      if (valueField?.type === 'call_expression') {
        const fn = valueField.childForFieldName('function');
        if (fn?.type === 'identifier' && textOf(fn, source) === 'require') {
          requireCall = valueField;
        } else if (fn?.type === 'call_expression') {
          const innerFn = fn.childForFieldName('function');
          if (innerFn?.type === 'identifier' && textOf(innerFn, source) === 'require') {
            requireCall = fn;
            importKind = 'cjs-require-iife';
          }
        }
      }
      if (requireCall) {
        {
          const args = requireCall.childForFieldName('arguments');
          const firstArg = args?.namedChild(0);
          const modSource = extractStringLiteral(firstArg ?? null, source);
          if (modSource) {
            const line = node.startPosition.row;
            const nameField =
              node.type === 'variable_declarator' ? node.childForFieldName('name') : node.childForFieldName('left');
            if (nameField?.type === 'identifier') {
              const local = textOf(nameField, source);
              imports.push({ localName: local, importedName: 'default', source: modSource, line, kind: importKind });
              aliases.localToSource.set(local, modSource);
              aliases.localToExported.set(local, 'default');
            } else if (nameField?.type === 'object_pattern') {
              for (let i = 0; i < nameField.namedChildCount; i++) {
                const prop = nameField.namedChild(i)!;
                if (prop.type === 'shorthand_property_identifier_pattern') {
                  const local = textOf(prop, source);
                  imports.push({ localName: local, importedName: local, source: modSource, line, kind: importKind });
                  aliases.localToSource.set(local, modSource);
                  aliases.localToExported.set(local, local);
                } else if (prop.type === 'pair_pattern') {
                  const keyNode = prop.childForFieldName('key');
                  const valueNode = prop.childForFieldName('value');
                  const exported = textOf(keyNode, source);
                  const local = valueNode?.type === 'identifier' ? textOf(valueNode, source) : exported;
                  if (exported && local) {
                    imports.push({ localName: local, importedName: exported, source: modSource, line, kind: importKind });
                    aliases.localToSource.set(local, modSource);
                    aliases.localToExported.set(local, exported);
                  }
                }
              }
            }
          }
        }
      }
    } else if (node.type === 'call_expression') {
      // Dynamic import: `import('mod')` / `await import('mod')` /
      // `const x = await import('mod')`. Tree-sitter represents the callee as
      // an `import` node, so neither the `import_statement` branch (static ESM)
      // nor the `require(...)` branch above sees it. Without this, a dep pulled
      // in only via dynamic import (e.g. `const simpleGit = await import('simple-git')`
      // in backend/src/lib/github.ts) had files_importing_count=0 and was
      // mis-classified `unreachable` → its CVEs auto-ignored. Record the module
      // as a side-effect import so the dep counts as reached (module tier).
      const fn = node.childForFieldName('function');
      const isDynamicImport =
        fn != null && (fn.type === 'import' || (fn.type === 'identifier' && textOf(fn, source) === 'import'));
      if (isDynamicImport) {
        const args = node.childForFieldName('arguments');
        const firstArg = args?.namedChild(0);
        const modSource = extractStringLiteral(firstArg ?? null, source);
        if (modSource) {
          const line = node.startPosition.row;
          imports.push({ localName: '', importedName: null, source: modSource, line, kind: 'side-effect' });
        }
      }
    }

    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };

  walk(root);
  return { imports, aliases };
}

function extractStringLiteral(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type !== 'string') return null;
  // First named child is string_fragment (or nothing for empty strings).
  const frag = node.namedChild(0);
  if (frag && frag.type === 'string_fragment') return textOf(frag, source);
  // Fallback: strip quotes.
  const raw = textOf(node, source);
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    return raw.slice(1, -1);
  }
  return null;
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
    const depName = resolveNpmImport(src, depNames);
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
    if (node.type === 'call_expression') {
      const fn = node.childForFieldName('function');
      if (fn?.type === 'identifier') {
        const name = textOf(fn, source);
        // Direct call of an imported binding: `merge(x, y)` when `merge` came from lodash.
        const exported = aliases.localToExported.get(name);
        if (exported) tryEmit(name, exported, exported, node, 'call');
      } else if (fn?.type === 'member_expression') {
        const object = fn.childForFieldName('object');
        const property = fn.childForFieldName('property');
        if (object?.type === 'identifier' && property) {
          const objName = textOf(object, source);
          const propName = textOf(property, source);
          if (aliases.localToSource.has(objName)) {
            tryEmit(objName, `${objName}.${propName}`, propName, node, 'call');
          }
        }
      }
    } else if (node.type === 'new_expression') {
      const ctor = node.childForFieldName('constructor');
      if (ctor?.type === 'identifier') {
        const name = textOf(ctor, source);
        const exported = aliases.localToExported.get(name);
        if (exported) tryEmit(name, exported, exported, node, 'new');
      }
    }

    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };

  walk(root);
  return usages;
}

export const javascriptModule: LanguageModule = {
  id: 'javascript',
  supportsFile(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return JS_EXTENSIONS.includes(ext) || TS_EXTENSIONS.includes(ext) || TSX_EXTENSIONS.includes(ext);
  },
  async extractFile(source: string, filePath: string, ctx: LanguageContext): Promise<ExtractedFile> {
    const tree = await parseSource(pickWasmForFile(filePath), source);
    if (!tree) {
      throw new Error('tree-sitter parse produced no tree (file too large or parse aborted)');
    }
    try {
      const root = tree.rootNode;
      const { imports, aliases } = collectImports(root, source);
      const depNames = ctx.deps.map((d) => d.name);
      const usages = collectUsages(root, source, aliases, filePath, depNames);

      const extracted: ExtractedFile = { filePath, language: 'javascript', imports, usages };
      const entryPoints: EntryPoint[] = [];
      for (const detector of getDetectorsForLanguage('javascript')) {
        const importedSources = new Set(imports.map((i) => i.source));
        // Empty triggerImports = run unconditionally (detectors like Next.js
        // and AWS Lambda gate on filename/export convention, not on imports).
        const triggered = detector.triggerImports.length === 0 || detector.triggerImports.some((t) => {
          if (importedSources.has(t)) return true;
          for (const imp of imports) if (imp.source.startsWith(`${t}/`)) return true;
          return false;
        });
        if (!triggered) continue;
        try {
          entryPoints.push(...detector.detect({ source, tree, file: extracted, workspaceRoot: ctx.workspaceRoot, depNames }));
        } catch (err) {
          recordDetectorError(detector.name, err);
        }
      }
      extracted.entryPoints = entryPoints;
      return extracted;
    } finally {
      tree.delete();
    }
  },
};
