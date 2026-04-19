import { parseSync } from 'oxc-parser';
import * as fs from 'fs';
import * as path from 'path';

export interface ImportInfo {
  packageName: string;
  functions: string[];
  isDefaultImport: boolean;
  defaultImportName?: string;
}

export interface FileAnalysis {
  filePath: string;
  imports: ImportInfo[];
}

export function shouldParseFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext);
}

export function shouldIgnoreFile(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/');
  const ignorePatterns = [
    'node_modules',
    '.git',
    'dist',
    'build',
    '.next',
    '.nuxt',
    'coverage',
    '.cache',
    '.turbo',
    '.vscode',
    '.idea',
  ];

  return ignorePatterns.some((pattern) => normalizedPath.includes(`/${pattern}/`) || normalizedPath.startsWith(`${pattern}/`));
}

export function findSourceFiles(dir: string, fileList: string[] = []): string[] {
  const files = fs.readdirSync(dir);

  for (const file of files) {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);

    if (stat.isDirectory()) {
      if (!shouldIgnoreFile(filePath)) {
        findSourceFiles(filePath, fileList);
      }
    } else if (stat.isFile() && shouldParseFile(filePath) && !shouldIgnoreFile(filePath)) {
      fileList.push(filePath);
    }
  }

  return fileList;
}

/**
 * Parse a single file and extract static import statements.
 * Only ESM import declarations are counted; dynamic import() and require() are not tracked.
 */
export function parseFile(filePath: string, content: string): ImportInfo[] {
  const imports: ImportInfo[] = [];

  try {
    const result = parseSync(content, { sourceFilename: filePath });
    if (result.errors?.length) {
      console.warn(`[parser] Parse issues in ${filePath}:`, result.errors.slice(0, 3).join('; '));
    }

    const programString = result.program;

    if (!programString || programString.length === 0) {
      return imports;
    }

    let programNode: any;
    if (typeof programString === 'string') {
      try {
        programNode = JSON.parse(programString);
      } catch (parseError) {
        return imports;
      }
    } else {
      programNode = result.program;
    }

    const traverse = (node: any): void => {
      if (!node || typeof node !== 'object') {
        return;
      }

      if (node.type === 'ImportDeclaration' && node.source) {
        const packageName = node.source.value;
        if (typeof packageName === 'string' && !packageName.startsWith('.')) {
          const importInfo: ImportInfo = {
            packageName,
            functions: [],
            isDefaultImport: false,
          };

          if (node.specifiers) {
            for (const specifier of node.specifiers) {
              if (specifier.type === 'ImportDefaultSpecifier') {
                importInfo.isDefaultImport = true;
                importInfo.defaultImportName = specifier.local?.name;
              } else if (specifier.type === 'ImportSpecifier') {
                const importedName = specifier.imported?.name || specifier.local?.name;
                if (importedName) {
                  importInfo.functions.push(importedName);
                }
              } else if (specifier.type === 'ImportNamespaceSpecifier') {
                importInfo.functions.push('*');
              }
            }
          }

          imports.push(importInfo);
        }
      }

      for (const key in node) {
        if (key === 'parent' || key === 'range') {
          continue;
        }
        const value = node[key];
        if (Array.isArray(value)) {
          value.forEach(traverse);
        } else if (value && typeof value === 'object') {
          traverse(value);
        }
      }
    };

    traverse(programNode);
  } catch (error) {
    console.warn(`Failed to parse ${filePath}:`, error instanceof Error ? error.message : String(error));
  }

  return imports;
}

/**
 * Analyze a repository directory and extract all imports.
 * Supports .js, .jsx, .ts, .tsx, .mjs, .cjs (node_modules, dist, etc. ignored).
 */
export function analyzeRepository(repoPath: string): FileAnalysis[] {
  const files = findSourceFiles(repoPath);
  const results: FileAnalysis[] = [];

  const extCounts = new Map<string, number>();
  for (const f of files) {
    const ext = path.extname(f).toLowerCase();
    extCounts.set(ext, (extCounts.get(ext) || 0) + 1);
  }
  console.log(
    `[parser] Found ${files.length} source file(s) (${[...extCounts.entries()].map(([e, n]) => `${e}:${n}`).join(', ') || 'none'})`
  );
  if (files.length > 0 && files.length <= 20) {
    const relative = files.map((f) => path.relative(repoPath, f).replace(/\\/g, '/'));
    console.log(`[parser] Files: ${relative.join(', ')}`);
  } else if (files.length > 20) {
    const sample = files.slice(0, 5).map((f) => path.relative(repoPath, f).replace(/\\/g, '/'));
    console.log(`[parser] Sample: ${sample.join(', ')} ...`);
  }

  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const imports = parseFile(filePath, content);

      if (imports.length > 0) {
        const relativePath = path.relative(repoPath, filePath).replace(/\\/g, '/');
        results.push({
          filePath: relativePath,
          imports,
        });
      }
    } catch (error) {
      console.warn(`Failed to read ${filePath}:`, error instanceof Error ? error.message : String(error));
    }
  }

  console.log(`[parser] Files with external imports: ${results.length}`);
  return results;
}
