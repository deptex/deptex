import type { Node } from 'web-tree-sitter';
import * as path from 'path';
import { parseSource } from '../parser';
import { resolveRubygemsImport } from '../import-mapping/rubygems';
import type { ExtractedFile, ImportBinding, LanguageContext, LanguageModule, UsageSlice } from './types';
import { getDetectorsForLanguage } from '../../framework-rules/registry';
import type { EntryPoint } from '../../framework-rules/types';
import { recordDetectorError } from '../detector-errors';

const RUBY_EXTENSIONS: readonly string[] = ['.rb', '.rake'];

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

function findContainingMethod(node: Node | null, source: string): string | null {
  for (let cur: Node | null = node; cur; cur = cur.parent) {
    if (cur.type === 'method' || cur.type === 'singleton_method') {
      return textOf(cur.childForFieldName('name'), source) || null;
    }
  }
  return null;
}

function stringContent(node: Node | null, source: string): string | null {
  if (!node || node.type !== 'string') return null;
  const content = node.namedChild(0);
  if (content?.type === 'string_content') return textOf(content, source);
  return null;
}

function extractCallMethodName(call: Node, source: string): string {
  const methodField = call.childForFieldName('method');
  if (methodField) return textOf(methodField, source);
  return '';
}

function extractRequireArgument(call: Node, source: string): string | null {
  const method = extractCallMethodName(call, source);
  if (method !== 'require' && method !== 'require_relative' && method !== 'require_dependency') return null;
  const args = call.childForFieldName('arguments');
  const first = args?.namedChild(0);
  return stringContent(first ?? null, source);
}

/**
 * Walk the top of a receiver chain to find the root constant. For
 * `ActiveSupport::Inflector.pluralize`, the receiver of the outer call is a
 * scope_resolution whose leftmost is `ActiveSupport`. We return that root.
 */
function rootReceiverConstant(node: Node | null, source: string): string | null {
  if (!node) return null;
  if (node.type === 'constant') return textOf(node, source);
  if (node.type === 'scope_resolution') {
    const scope = node.childForFieldName('scope');
    if (scope) return rootReceiverConstant(scope, source);
    // First-segment constant (e.g. `::Foo`) has no scope field.
    const first = node.namedChild(0);
    return first?.type === 'constant' ? textOf(first, source) : null;
  }
  return null;
}

export const rubyModule: LanguageModule = {
  id: 'ruby',
  supportsFile(filePath: string): boolean {
    const name = path.basename(filePath);
    if (RUBY_EXTENSIONS.includes(path.extname(filePath).toLowerCase())) return true;
    return name === 'Rakefile' || name === 'Gemfile';
  },
  async extractFile(source: string, filePath: string, ctx: LanguageContext): Promise<ExtractedFile> {
    const tree = await parseSource('tree-sitter-ruby.wasm', source);
    if (!tree) {
      throw new Error('tree-sitter parse produced no tree (file too large or parse aborted)');
    }
    try {
    const depNames = ctx.deps.map((d) => d.name);
    const imports: ImportBinding[] = [];
    const usages: UsageSlice[] = [];

    // Root-constant → gem cache. If a file requires `rest-client`, then
    // `RestClient.get(...)` is attributed to it. We build this by camelizing
    // each require root and checking against the resolved gem names.
    const constantToGem = new Map<string, string>();

    const walk = (node: Node): void => {
      if (node.type === 'call') {
        const requirePath = extractRequireArgument(node, source);
        if (requirePath) {
          const gem = resolveRubygemsImport(requirePath, depNames);
          if (gem) {
            imports.push({
              localName: requirePath.split('/')[0],
              importedName: null,
              source: requirePath,
              line: node.startPosition.row,
              kind: 'namespace',
            });
            // Best-effort constant binding: `rest-client` → `RestClient`,
            // `active_support/core_ext` → `ActiveSupport`.
            const head = requirePath.split('/')[0];
            const camel = head
              .split(/[-_]/)
              .filter(Boolean)
              .map((s) => s[0].toUpperCase() + s.slice(1))
              .join('');
            if (camel) constantToGem.set(camel, gem);
          }
        } else {
          const receiver = node.childForFieldName('receiver');
          const methodName = extractCallMethodName(node, source);
          const rootConst = rootReceiverConstant(receiver, source);
          if (rootConst && methodName) {
            const gem = constantToGem.get(rootConst);
            if (gem) {
              usages.push({
                filePath,
                lineNumber: node.startPosition.row,
                containingMethod: findContainingMethod(node, source),
                targetName: `${rootConst}.${methodName}`,
                targetType: 'call',
                resolvedMethod: methodName,
                usageLabel: null,
                depName: gem,
              });
            }
          }
        }
      }
      for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
    };

    walk(tree.rootNode);

    const extracted: ExtractedFile = { filePath, language: 'ruby', imports, usages };
    const entryPoints: EntryPoint[] = [];
    for (const detector of getDetectorsForLanguage('ruby')) {
      const importedSources = new Set(imports.map((i) => i.source));
      const triggered = detector.triggerImports.length === 0 || detector.triggerImports.some((t) => {
        if (importedSources.has(t)) return true;
        for (const imp of imports) if (imp.source.startsWith(`${t}/`)) return true;
        return false;
      });
      if (!triggered) continue;
      try { entryPoints.push(...detector.detect({ source, tree, file: extracted, workspaceRoot: ctx.workspaceRoot, depNames })); } catch (err) { recordDetectorError(detector.name, err); }
    }
    extracted.entryPoints = entryPoints;
    return extracted;
    } finally {
      tree.delete();
    }
  },
};
