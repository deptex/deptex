import type { Node } from 'web-tree-sitter';
import * as path from 'path';
import { parseSource } from '../parser';
import { resolveNugetImport } from '../import-mapping/nuget';
import type { ExtractedFile, ImportBinding, LanguageContext, LanguageModule, UsageSlice } from './types';
import { getDetectorsForLanguage } from '../../framework-rules/registry';
import type { EntryPoint } from '../../framework-rules/types';
import { recordDetectorError } from '../detector-errors';

const CSHARP_EXTENSIONS: readonly string[] = ['.cs'];

function textOf(node: Node | null, source: string): string {
  if (!node) return '';
  return source.slice(node.startIndex, node.endIndex);
}

function findContainingMethod(node: Node | null, source: string): string | null {
  for (let cur: Node | null = node; cur; cur = cur.parent) {
    if (cur.type === 'method_declaration' || cur.type === 'local_function_statement') {
      return textOf(cur.childForFieldName('name'), source) || null;
    }
  }
  return null;
}

export const csharpModule: LanguageModule = {
  id: 'csharp',
  supportsFile(filePath: string): boolean {
    return CSHARP_EXTENSIONS.includes(path.extname(filePath).toLowerCase());
  },
  async extractFile(source: string, filePath: string, ctx: LanguageContext): Promise<ExtractedFile> {
    const tree = await parseSource('tree-sitter-c_sharp.wasm', source);
    if (!tree) {
      throw new Error('tree-sitter parse produced no tree (file too large or parse aborted)');
    }
    try {
    const imports: ImportBinding[] = [];
    const usages: UsageSlice[] = [];

    /** Imported namespace FQN → matched NuGet package name (resolved once up-front). */
    const namespaceToPackage = new Map<string, string>();
    /** Simple type name → owning namespace FQN (so calls via bare class refs work). */
    const simpleToNamespace = new Map<string, string>();

    const walk = (node: Node): void => {
      if (node.type === 'using_directive') {
        // Last named child is the path (identifier or qualified_name). Other
        // tokens ("static" / "alias") appear as unnamed children.
        const target = node.namedChild(node.namedChildCount - 1);
        if (!target) return;
        const fqn = textOf(target, source);
        const depName = resolveNugetImport(fqn, ctx.deps);
        if (depName) {
          namespaceToPackage.set(fqn, depName);
          imports.push({
            localName: fqn.split('.').pop() ?? fqn,
            importedName: null,
            source: fqn,
            line: node.startPosition.row,
            kind: 'namespace',
          });
        }
        return;
      }

      if (node.type === 'invocation_expression') {
        const exprNode = node.childForFieldName('function') ?? node.namedChild(0);
        if (exprNode?.type === 'member_access_expression') {
          const recv = exprNode.childForFieldName('expression') ?? exprNode.namedChild(0);
          const name = exprNode.childForFieldName('name') ?? exprNode.namedChild(1);
          if (recv && name) {
            const fullText = textOf(exprNode, source);
            const methodName = textOf(name, source);
            // Resolve via any import whose FQN is a prefix of `recv`.
            const recvText = textOf(recv, source);
            let depName: string | null = null;
            for (const [ns, pkg] of namespaceToPackage) {
              if (recvText === ns || recvText.startsWith(`${ns}.`) || ns.endsWith(`.${recvText}`)) {
                depName = pkg;
                break;
              }
            }
            if (!depName) {
              // Try interpreting the whole member-access as an FQN.
              depName = resolveNugetImport(recvText, ctx.deps);
            }
            if (depName) {
              usages.push({
                filePath,
                lineNumber: node.startPosition.row,
                containingMethod: findContainingMethod(node, source),
                targetName: fullText,
                targetType: 'call',
                resolvedMethod: methodName,
                usageLabel: null,
                depName,
              });
            }
          }
        }
      } else if (node.type === 'object_creation_expression') {
        const typeNode = node.childForFieldName('type') ?? node.namedChild(0);
        if (typeNode) {
          const typeText = textOf(typeNode, source);
          let depName: string | null = null;
          for (const [ns, pkg] of namespaceToPackage) {
            if (ns === typeText || typeText.startsWith(`${ns}.`) || ns.endsWith(`.${typeText}`)) {
              depName = pkg;
              break;
            }
          }
          if (!depName) depName = resolveNugetImport(typeText, ctx.deps);
          if (depName) {
            usages.push({
              filePath,
              lineNumber: node.startPosition.row,
              containingMethod: findContainingMethod(node, source),
              targetName: typeText,
              targetType: 'new',
              resolvedMethod: typeText,
              usageLabel: null,
              depName,
            });
          }
        }
      }

      for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
    };

    walk(tree.rootNode);

    // Avoid lint warning until we wire simpleToNamespace-assisted resolution.
    void simpleToNamespace;

    const extracted: ExtractedFile = { filePath, language: 'csharp', imports, usages };
    const entryPoints: EntryPoint[] = [];
    for (const detector of getDetectorsForLanguage('csharp')) {
      const importedSources = new Set(imports.map((i) => i.source));
      const triggered = detector.triggerImports.length === 0 || detector.triggerImports.some((t) => {
        if (importedSources.has(t)) return true;
        for (const imp of imports) if (imp.source.startsWith(`${t}.`)) return true;
        return false;
      });
      if (!triggered) continue;
      try { entryPoints.push(...detector.detect({ source, tree, file: extracted, workspaceRoot: ctx.workspaceRoot, depNames: ctx.deps.map((d) => d.name) })); } catch (err) { recordDetectorError(detector.name, err); }
    }
    extracted.entryPoints = entryPoints;
    return extracted;
    } finally {
      tree.delete();
    }
  },
};
