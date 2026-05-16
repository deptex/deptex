import type { Node } from 'web-tree-sitter';
import * as fs from 'fs';
import * as path from 'path';
import { parseSource } from '../parser';
import { resolveGoImport } from '../import-mapping/go';
import type { ExtractedFile, ImportBinding, LanguageContext, LanguageModule, UsageSlice } from './types';
import { getDetectorsForLanguage } from '../../framework-rules/registry';
import type { EntryPoint } from '../../framework-rules/types';
import { recordDetectorError } from '../detector-errors';

const GO_EXTENSIONS: readonly string[] = ['.go'];

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

function findContainingMethod(node: Node | null, source: string): string | null {
  for (let cur: Node | null = node; cur; cur = cur.parent) {
    if (cur.type === 'function_declaration' || cur.type === 'method_declaration') {
      return textOf(cur.childForFieldName('name'), source) || null;
    }
  }
  return null;
}

/**
 * Reads the `module <path>` line from a workspace's go.mod so we can skip
 * first-party imports (subpackages of the project's own module). Returns
 * null if go.mod is absent or malformed — in that case we fall back to
 * treating every external-looking path as a dep candidate.
 */
const moduleCache = new Map<string, string | null>();
function readGoModulePath(workspaceRoot: string): string | null {
  if (moduleCache.has(workspaceRoot)) return moduleCache.get(workspaceRoot) ?? null;
  const goModPath = path.join(workspaceRoot, 'go.mod');
  let result: string | null = null;
  try {
    const content = fs.readFileSync(goModPath, 'utf8');
    const match = content.match(/^module\s+(\S+)/m);
    if (match) result = match[1];
  } catch {
    /* not a Go workspace root, or go.mod missing */
  }
  moduleCache.set(workspaceRoot, result);
  return result;
}

function stripQuotes(literal: string): string {
  if (literal.startsWith('"') && literal.endsWith('"')) return literal.slice(1, -1);
  if (literal.startsWith('`') && literal.endsWith('`')) return literal.slice(1, -1);
  return literal;
}

function collectImports(root: Node, source: string, selfModule: string | null): {
  imports: ImportBinding[];
  /** Local alias (package identifier or last-path-segment) → full import path. */
  aliasToPath: Map<string, string>;
} {
  const imports: ImportBinding[] = [];
  const aliasToPath = new Map<string, string>();

  const processSpec = (spec: Node): void => {
    const pathNode = spec.childForFieldName('path');
    if (!pathNode) return;
    const rawPath = stripQuotes(textOf(pathNode, source));
    if (!rawPath) return;
    // Skip first-party (subpackages of our own module).
    if (selfModule && (rawPath === selfModule || rawPath.startsWith(`${selfModule}/`))) return;

    const nameNode = spec.childForFieldName('name');
    let alias: string;
    let kind: ImportBinding['kind'] = 'namespace';
    if (nameNode) {
      const nameText = textOf(nameNode, source);
      if (nameText === '_' || nameText === '.') {
        // `_` = side-effect-only; `.` = name-less — skip the local binding.
        imports.push({ localName: '', importedName: null, source: rawPath, line: spec.startPosition.row, kind: 'side-effect' });
        return;
      }
      alias = nameText;
    } else {
      // Go import-path major-version convention: `.../echo/v4` exposes the
      // package as `echo`, not `v4`. Same for fiber/v2, chi/v5, etc. Skip
      // the trailing /vN+ segment and use the penultimate as the alias.
      const segs = rawPath.split('/');
      let idx = segs.length - 1;
      if (idx > 0 && /^v\d+$/.test(segs[idx])) idx -= 1;
      alias = segs[idx];
    }

    imports.push({
      localName: alias,
      importedName: null,
      source: rawPath,
      line: spec.startPosition.row,
      kind,
    });
    aliasToPath.set(alias, rawPath);
  };

  const walk = (node: Node): void => {
    if (node.type === 'import_declaration') {
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i)!;
        if (child.type === 'import_spec') {
          processSpec(child);
        } else if (child.type === 'import_spec_list') {
          for (let j = 0; j < child.namedChildCount; j++) {
            const spec = child.namedChild(j)!;
            if (spec.type === 'import_spec') processSpec(spec);
          }
        }
      }
      return;
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };

  walk(root);
  return { imports, aliasToPath };
}

function collectUsages(
  root: Node,
  source: string,
  filePath: string,
  aliasToPath: Map<string, string>,
  depNames: readonly string[]
): UsageSlice[] {
  const usages: UsageSlice[] = [];

  const walk = (node: Node): void => {
    if (node.type === 'call_expression') {
      const fn = node.childForFieldName('function');
      if (fn?.type === 'selector_expression') {
        const operand = fn.childForFieldName('operand');
        const field = fn.childForFieldName('field');
        if (operand?.type === 'identifier' && field) {
          const operandName = textOf(operand, source);
          const fieldName = textOf(field, source);
          const importPath = aliasToPath.get(operandName);
          if (importPath) {
            const depName = resolveGoImport(importPath, depNames);
            if (depName) {
              usages.push({
                filePath,
                lineNumber: node.startPosition.row,
                containingMethod: findContainingMethod(node, source),
                targetName: `${operandName}.${fieldName}`,
                targetType: 'call',
                resolvedMethod: fieldName,
                usageLabel: null,
                depName,
              });
            }
          }
        }
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
  };

  walk(root);
  return usages;
}

export const goModule: LanguageModule = {
  id: 'go',
  supportsFile(filePath: string): boolean {
    return GO_EXTENSIONS.includes(path.extname(filePath).toLowerCase());
  },
  async extractFile(source: string, filePath: string, ctx: LanguageContext): Promise<ExtractedFile> {
    const tree = await parseSource('tree-sitter-go.wasm', source);
    if (!tree) {
      throw new Error('tree-sitter parse produced no tree (file too large or parse aborted)');
    }
    try {
      const selfModule = readGoModulePath(ctx.workspaceRoot);
      const depNames = ctx.deps.map((d) => d.name);
      const { imports, aliasToPath } = collectImports(tree.rootNode, source, selfModule);
      const usages = collectUsages(tree.rootNode, source, filePath, aliasToPath, depNames);

      const extracted: ExtractedFile = { filePath, language: 'go', imports, usages };
      const entryPoints: EntryPoint[] = [];
      for (const detector of getDetectorsForLanguage('go')) {
        const triggered = detector.triggerImports.length === 0 || detector.triggerImports.some((t) => {
          for (const imp of imports) {
            if (imp.source === t || imp.source.startsWith(`${t}/`)) return true;
          }
          return false;
        });
        if (!triggered) continue;
        try {
          entryPoints.push(...detector.detect({ source, tree, file: extracted, workspaceRoot: ctx.workspaceRoot, depNames }));
        } catch (err) { recordDetectorError(detector.name, err); }
      }
      extracted.entryPoints = entryPoints;
      return extracted;
    } finally {
      tree.delete();
    }
  },
};
