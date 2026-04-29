import * as fs from 'fs';
import * as path from 'path';

// Aider-style udiff applier.
//
// Why udiff and not search/replace strings: udiff is less prone to elision
// (the editor LLM dropping lines with "// rest unchanged"), and it gives us
// a natural per-hunk context window that we can fuzzy-match if whitespace
// drifts. See https://aider.chat/docs/more/edit-formats.html.
//
// Format we accept:
//   --- a/path/to/file        OR  --- /dev/null  (for new files)
//   +++ b/path/to/file        OR  +++ /dev/null  (for deleted files)
//   @@ ... @@
//    context line
//   -removed
//   +added
//    context

export interface ParsedHunk {
  header: string;
  lines: string[]; // raw lines with leading marker preserved
}

export interface ParsedFileDiff {
  oldPath: string | null; // null = new file
  newPath: string | null; // null = deleted file
  hunks: ParsedHunk[];
}

export class DiffParseError extends Error {}
export class DiffApplyError extends Error {}

function stripPrefix(p: string): string {
  if (p === '/dev/null') return p;
  if (p.startsWith('a/') || p.startsWith('b/')) return p.slice(2);
  return p;
}

export function parseUdiff(text: string): ParsedFileDiff[] {
  // Strip ``` fences if the LLM wrapped the diff in a code block.
  let cleaned = text.replace(/^```[a-zA-Z]*\n/, '').replace(/\n```$/, '').trim();

  const lines = cleaned.split('\n');
  const files: ParsedFileDiff[] = [];

  let i = 0;
  while (i < lines.length) {
    if (!lines[i].startsWith('--- ')) {
      i++;
      continue;
    }
    if (i + 1 >= lines.length || !lines[i + 1].startsWith('+++ ')) {
      throw new DiffParseError(`Missing +++ line after --- at line ${i + 1}`);
    }
    const oldRaw = lines[i].slice(4).trim();
    const newRaw = lines[i + 1].slice(4).trim();
    const oldPath = oldRaw === '/dev/null' ? null : stripPrefix(oldRaw);
    const newPath = newRaw === '/dev/null' ? null : stripPrefix(newRaw);

    i += 2;
    const hunks: ParsedHunk[] = [];

    while (i < lines.length && !lines[i].startsWith('--- ')) {
      if (!lines[i].startsWith('@@')) {
        // Skip stray blank or commentary lines between hunks.
        i++;
        continue;
      }
      const header = lines[i];
      i++;
      const hunkLines: string[] = [];
      while (
        i < lines.length &&
        !lines[i].startsWith('@@') &&
        !lines[i].startsWith('--- ')
      ) {
        // Hunk lines must start with one of: ' ' (context), '-', '+', or '\\' (no newline marker).
        // Anything else is treated as the hunk boundary.
        const ch = lines[i][0];
        if (ch === ' ' || ch === '-' || ch === '+' || ch === '\\') {
          hunkLines.push(lines[i]);
          i++;
        } else if (lines[i] === '') {
          // Empty lines inside hunks are unusual but treat as context.
          hunkLines.push(' ');
          i++;
        } else {
          break;
        }
      }
      hunks.push({ header, lines: hunkLines });
    }

    files.push({ oldPath, newPath, hunks });
  }

  return files;
}

interface HunkText {
  oldLines: string[];
  newLines: string[];
}

function expandHunk(hunk: ParsedHunk): HunkText {
  const oldLines: string[] = [];
  const newLines: string[] = [];
  for (const raw of hunk.lines) {
    if (raw.startsWith('\\')) continue; // "\ No newline at end of file" marker
    const marker = raw[0];
    const content = raw.slice(1);
    if (marker === ' ') {
      oldLines.push(content);
      newLines.push(content);
    } else if (marker === '-') {
      oldLines.push(content);
    } else if (marker === '+') {
      newLines.push(content);
    }
  }
  return { oldLines, newLines };
}

interface HunkParts {
  removed: string[]; // only `-` lines
  added: string[];   // only `+` lines
}

function expandHunkParts(hunk: ParsedHunk): HunkParts {
  const removed: string[] = [];
  const added: string[] = [];
  for (const raw of hunk.lines) {
    if (raw.startsWith('\\')) continue;
    const marker = raw[0];
    const content = raw.slice(1);
    if (marker === '-') removed.push(content);
    else if (marker === '+') added.push(content);
  }
  return { removed, added };
}

const norm = (s: string) => s.replace(/\s+$/, '').replace(/^\s+/, '');

function findContiguous(fileLines: string[], target: string[]): number {
  if (target.length === 0) return -1;
  // Exact match.
  outer: for (let i = 0; i <= fileLines.length - target.length; i++) {
    for (let j = 0; j < target.length; j++) {
      if (fileLines[i + j] !== target[j]) continue outer;
    }
    return i;
  }
  // Whitespace-tolerant.
  outer2: for (let i = 0; i <= fileLines.length - target.length; i++) {
    for (let j = 0; j < target.length; j++) {
      if (norm(fileLines[i + j]) !== norm(target[j])) continue outer2;
    }
    return i;
  }
  return -1;
}

function findHunkOffset(fileLines: string[], oldLines: string[]): number {
  if (oldLines.length === 0) return 0;
  return findContiguous(fileLines, oldLines);
}

export function applyDiff(workDir: string, diff: ParsedFileDiff): void {
  // create
  if (diff.oldPath === null && diff.newPath) {
    const target = path.join(workDir, diff.newPath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const content = diff.hunks
      .flatMap((h) => expandHunk(h).newLines)
      .join('\n');
    fs.writeFileSync(target, content + (content.endsWith('\n') ? '' : '\n'));
    return;
  }
  // delete
  if (diff.newPath === null && diff.oldPath) {
    const target = path.join(workDir, diff.oldPath);
    if (fs.existsSync(target)) fs.unlinkSync(target);
    return;
  }
  // modify or rename
  const sourcePath = diff.oldPath!;
  const targetPath = diff.newPath ?? sourcePath;
  const sourceAbs = path.join(workDir, sourcePath);
  if (!fs.existsSync(sourceAbs)) {
    // LLMs (Qwen3 in particular) frequently emit a "modify"-shaped udiff
    // (--- a/path, +++ b/path) for what's actually a new file rather than
    // using --- /dev/null. If the diff is purely additive (no `-` lines),
    // treat it as a create so the patch lands cleanly instead of failing
    // with "Source file does not exist". Hunks with removals against a
    // non-existent file are still a real error.
    const hasRemovals = diff.hunks.some((h) =>
      h.lines.some((line) => line.startsWith('-') && !line.startsWith('---')),
    );
    if (!hasRemovals) {
      const targetAbs = path.join(workDir, targetPath);
      fs.mkdirSync(path.dirname(targetAbs), { recursive: true });
      const content = diff.hunks.flatMap((h) => expandHunk(h).newLines).join('\n');
      fs.writeFileSync(targetAbs, content + (content.endsWith('\n') ? '' : '\n'));
      return;
    }
    throw new DiffApplyError(`Source file does not exist: ${sourcePath}`);
  }

  const original = fs.readFileSync(sourceAbs, 'utf-8');
  // Preserve trailing newline behavior.
  const hadTrailingNewline = original.endsWith('\n');
  const fileLines = original.split('\n');
  if (hadTrailingNewline) fileLines.pop();

  let working = [...fileLines];

  for (const hunk of diff.hunks) {
    const { oldLines, newLines } = expandHunk(hunk);
    let offset = findHunkOffset(working, oldLines);
    if (offset === -1) {
      // Context-drift fallback: weaker editor models often emit context lines
      // that don't quite match the file (off-by-one whitespace, slightly
      // wrong surrounding code, drifted line numbers). When the full-hunk
      // match fails, try matching on JUST the `-` lines — the actual content
      // being changed. If found, replace exactly those lines with the `+`
      // lines, ignoring context. This is essentially Aider's diff-fenced
      // SEARCH/REPLACE strategy embedded in the udiff parser.
      const { removed, added } = expandHunkParts(hunk);
      if (removed.length > 0) {
        const removedOffset = findContiguous(working, removed);
        if (removedOffset !== -1) {
          working = [
            ...working.slice(0, removedOffset),
            ...added,
            ...working.slice(removedOffset + removed.length),
          ];
          continue;
        }
      }
      throw new DiffApplyError(
        `Hunk did not match in ${sourcePath} (header: ${hunk.header.trim()})`,
      );
    }
    working = [...working.slice(0, offset), ...newLines, ...working.slice(offset + oldLines.length)];
  }

  if (sourcePath !== targetPath) {
    const targetAbs = path.join(workDir, targetPath);
    fs.mkdirSync(path.dirname(targetAbs), { recursive: true });
    fs.unlinkSync(sourceAbs);
    fs.writeFileSync(targetAbs, working.join('\n') + (hadTrailingNewline ? '\n' : ''));
  } else {
    fs.writeFileSync(sourceAbs, working.join('\n') + (hadTrailingNewline ? '\n' : ''));
  }
}

export function applyDiffText(workDir: string, text: string): { filesChanged: string[] } {
  const diffs = parseUdiff(text);
  const filesChanged: string[] = [];
  for (const d of diffs) {
    applyDiff(workDir, d);
    if (d.newPath) filesChanged.push(d.newPath);
    else if (d.oldPath) filesChanged.push(d.oldPath);
  }
  return { filesChanged };
}
