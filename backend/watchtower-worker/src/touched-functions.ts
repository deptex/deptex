import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
// @ts-expect-error - oxc-parser types may not match runtime (filename, sourceText)
import { parseSync } from 'oxc-parser';

const execAsync = promisify(exec);

const JS_TS_EXT = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];

function shouldParseFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return JS_TS_EXT.includes(ext);
}

/**
 * Parse unified diff output to get per-file changed line ranges in the NEW (post-commit) file.
 * Returns array of { filePath, newFileLineRanges } where newFileLineRanges is [start, end] inclusive.
 */
export function parseUnifiedDiffForNewFileRanges(diffOutput: string): Array<{ filePath: string; newFileLineRanges: Array<[number, number]> }> {
  const result: Array<{ filePath: string; newFileLineRanges: Array<[number, number]> }> = [];
  const lines = diffOutput.split('\n');

  let currentFilePath: string | null = null;
  let currentRanges: Array<[number, number]> = [];
  let newStart = 0;
  let newCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // --- a/path or +++ b/path (we care about +++ for new file)
    if (line.startsWith('+++ ')) {
      if (currentFilePath && currentRanges.length > 0) {
        result.push({ filePath: currentFilePath, newFileLineRanges: currentRanges });
      }
      const p = line.slice(4).trim();
      currentFilePath = p.startsWith('b/') ? p.slice(2) : p;
      currentRanges = [];
      continue;
    }

    // @@ -oldStart,oldCount +newStart,newCount @@
    const hunkMatch = line.match(/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@/);
    if (hunkMatch) {
      newStart = parseInt(hunkMatch[1], 10);
      newCount = parseInt(hunkMatch[2] || '1', 10);
      const end = newStart + newCount - 1;
      if (currentFilePath && newCount > 0) {
        currentRanges.push([newStart, end]);
      }
      continue;
    }
  }

  if (currentFilePath && currentRanges.length > 0) {
    result.push({ filePath: currentFilePath, newFileLineRanges: currentRanges });
  }

  return result;
}

/**
 * Get file content at a given commit from the repo.
 */
async function getFileContentAtCommit(repoPath: string, commitSha: string, filePath: string): Promise<string | null> {
  try {
    // git show <sha>:path returns the file content at that commit; path uses forward slashes
    const normalizedPath = filePath.replace(/\\/g, '/');
    const { stdout } = await execAsync(`git show ${commitSha}:"${normalizedPath}"`, {
      cwd: repoPath,
      timeout: 15000,
      maxBuffer: 2 * 1024 * 1024,
    });
    return stdout;
  } catch {
    return null;
  }
}

/**
 * Convert character offset to 1-based line number in source.
 */
function offsetToLine(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source[i] === '\n') line++;
  }
  return line;
}

export interface ExportedDeclaration {
  name: string;
  startLine: number;
  endLine: number;
}

/**
 * Parse JS/TS source and return exported declarations with their line ranges (1-based inclusive).
 * Uses oxc-parser; collects export function/const/class and export default.
 */
export function getExportedDeclarationsWithLineRanges(filePath: string, content: string): ExportedDeclaration[] {
  const declarations: ExportedDeclaration[] = [];

  try {
    const result = parseSync(filePath, content);
    const programString = result.program;
    if (!programString || (typeof programString === 'string' && programString.length === 0)) {
      return declarations;
    }

    let programNode: any;
    if (typeof programString === 'string') {
      try {
        programNode = JSON.parse(programString);
      } catch {
        return declarations;
      }
    } else {
      programNode = programString;
    }

    function getLineRange(node: any): { startLine: number; endLine: number } | null {
      if (!node) return null;
      const start = node.start ?? node.span?.start ?? node.loc?.start?.offset;
      const end = node.end ?? node.span?.end ?? node.loc?.end?.offset;
      if (typeof start !== 'number' || typeof end !== 'number') {
        const loc = node.loc ?? node.span;
        if (loc && typeof loc.start?.line === 'number' && typeof loc.end?.line === 'number') {
          return { startLine: loc.start.line, endLine: loc.end.line };
        }
        return null;
      }
      return {
        startLine: offsetToLine(content, start),
        endLine: offsetToLine(content, end),
      };
    }

    function addDeclaration(name: string, node: any) {
      const range = getLineRange(node);
      if (range) {
        declarations.push({ name, startLine: range.startLine, endLine: range.endLine });
      }
    }

    function traverse(node: any): void {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'ExportNamedDeclaration') {
        const decl = node.declaration;
        if (decl) {
          if (decl.type === 'FunctionDeclaration' && decl.id?.name) {
            addDeclaration(decl.id.name, decl);
          } else if (decl.type === 'VariableDeclaration' && decl.declarations?.[0]) {
            const id = decl.declarations[0].id;
            const name = id?.name ?? id?.id?.name;
            if (name) addDeclaration(name, decl);
          } else if (decl.type === 'ClassDeclaration' && decl.id?.name) {
            addDeclaration(decl.id.name, decl);
          }
        }
        if (node.specifiers) {
          for (const spec of node.specifiers) {
            const name = spec.exported?.name ?? spec.exported?.value ?? spec.local?.name;
            if (name) addDeclaration(name, node);
          }
        }
        return;
      }

      if (node.type === 'ExportDefaultDeclaration') {
        const decl = node.declaration;
        if (decl?.type === 'FunctionDeclaration' && decl.id?.name) {
          addDeclaration(decl.id.name, decl);
        } else if (decl?.type === 'Identifier' && decl.name) {
          addDeclaration(decl.name, decl);
        } else {
          addDeclaration('default', node);
        }
        return;
      }

      for (const key in node) {
        if (key === 'parent' || key === 'loc' || key === 'span') continue;
        const value = node[key];
        if (Array.isArray(value)) {
          value.forEach(traverse);
        } else if (value && typeof value === 'object') {
          traverse(value);
        }
      }
    }

    traverse(programNode);
  } catch {
    // Skip unparseable files
  }

  return declarations;
}

/**
 * Check if any of the changed line ranges overlap with the declaration's line range.
 */
function rangeOverlaps(
  changedRanges: Array<[number, number]>,
  declStart: number,
  declEnd: number
): boolean {
  for (const [start, end] of changedRanges) {
    if (start <= declEnd && end >= declStart) return true;
  }
  return false;
}

/**
 * For a single commit: get full diff, parse it, for each JS/TS file get content at commit,
 * parse AST for exported declarations with line ranges, map changed lines to those declarations.
 * Returns deduplicated list of export names touched by this commit.
 */
export async function getTouchedFunctionsForCommit(repoPath: string, commitSha: string): Promise<string[]> {
  const names = new Set<string>();

  try {
    const { stdout: diffOutput } = await execAsync(`git show --no-color ${commitSha}`, {
      cwd: repoPath,
      timeout: 60000,
      maxBuffer: 10 * 1024 * 1024,
    });

    const filesWithRanges = parseUnifiedDiffForNewFileRanges(diffOutput);

    for (const { filePath, newFileLineRanges } of filesWithRanges) {
      if (!shouldParseFile(filePath)) continue;

      const content = await getFileContentAtCommit(repoPath, commitSha, filePath);
      if (!content) continue;

      const exports = getExportedDeclarationsWithLineRanges(filePath, content);

      for (const exp of exports) {
        if (rangeOverlaps(newFileLineRanges, exp.startLine, exp.endLine)) {
          names.add(exp.name);
        }
      }
    }
  } catch (err: any) {
    console.warn(`[touched-functions] Failed for commit ${commitSha}: ${err?.message ?? err}`);
  }

  return Array.from(names);
}
