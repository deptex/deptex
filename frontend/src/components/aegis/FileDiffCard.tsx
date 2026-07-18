import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { VscodeFileIcon } from './VscodeFileIcon';
import { codeTheme } from './codeTheme';

// A GitHub / Cursor-style file-edit card for a task chat: a header row with the
// file's real VSCode icon + name + a green/red +add −del stat, and the change
// shown as a static snapshot — no collapse — rendered like an editor: real
// per-line syntax highlighting (the shared oneDark theme) with only the row
// background tinted for added/removed lines. Hunk (@@) markers are dropped; you
// just see the code. Fed the raw udiff a fix-worker `edit` step produced.

type RowType = 'add' | 'del' | 'ctx';
interface DiffRow {
  type: RowType;
  text: string;
  oldNo?: number;
  newNo?: number;
}

// file extension / basename → react-syntax-highlighter (Prism) language id.
function languageForFile(file: string): string {
  const base = (file.split(/[\\/]/).pop() ?? '').toLowerCase();
  if (base === 'dockerfile' || base.startsWith('dockerfile.') || base.endsWith('.dockerfile')) {
    return 'docker';
  }
  const ext = base.includes('.') ? base.split('.').pop()! : '';
  const map: Record<string, string> = {
    ts: 'typescript', tsx: 'tsx', js: 'javascript', jsx: 'jsx', mjs: 'javascript', cjs: 'javascript',
    json: 'json', py: 'python', go: 'go', rb: 'ruby', php: 'php', java: 'java', kt: 'kotlin',
    cs: 'csharp', rs: 'rust', yml: 'yaml', yaml: 'yaml', sh: 'bash', bash: 'bash', tf: 'hcl',
    css: 'css', scss: 'scss', html: 'markup', xml: 'markup', md: 'markdown', sql: 'sql', toml: 'toml',
  };
  return map[ext] ?? 'text';
}

// Lines of unchanged context to keep before the first change and after the last
// (git emits 3, which reads as too much here). Context between changes is kept.
const MAX_CONTEXT = 2;

function capContext(rows: DiffRow[], max: number): DiffRow[] {
  const firstChange = rows.findIndex((r) => r.type !== 'ctx');
  if (firstChange === -1) return rows;
  let lastChange = firstChange;
  rows.forEach((r, i) => {
    if (r.type !== 'ctx') lastChange = i;
  });
  return rows.filter((r, i) => {
    if (r.type !== 'ctx') return true;
    if (i < firstChange) return firstChange - i <= max; // leading context
    if (i > lastChange) return i - lastChange <= max; // trailing context
    return true; // context between changes
  });
}

function parseUnifiedDiff(diff: string): {
  file: string;
  additions: number;
  deletions: number;
  rows: DiffRow[];
} {
  const lines = diff.split('\n');
  let file = '';
  let oldNo = 0;
  let newNo = 0;
  let additions = 0;
  let deletions = 0;
  const rows: DiffRow[] = [];

  for (const raw of lines) {
    if (raw.startsWith('+++ ')) {
      const p = raw.slice(4).trim().replace(/^b\//, '');
      if (p && p !== '/dev/null') file = p;
      continue;
    }
    if (raw.startsWith('--- ')) {
      if (!file) {
        const p = raw.slice(4).trim().replace(/^a\//, '');
        if (p && p !== '/dev/null') file = p;
      }
      continue;
    }
    if (raw.startsWith('diff --git') || raw.startsWith('index ')) continue;

    const hunk = raw.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) {
      // Set line numbering from the hunk header, but don't render the @@ line.
      oldNo = parseInt(hunk[1], 10);
      newNo = parseInt(hunk[2], 10);
      continue;
    }
    if (raw.startsWith('+')) {
      additions += 1;
      rows.push({ type: 'add', text: raw.slice(1), newNo });
      newNo += 1;
      continue;
    }
    if (raw.startsWith('-')) {
      deletions += 1;
      rows.push({ type: 'del', text: raw.slice(1), oldNo });
      oldNo += 1;
      continue;
    }
    const text = raw.startsWith(' ') ? raw.slice(1) : raw;
    rows.push({ type: 'ctx', text, oldNo, newNo });
    oldNo += 1;
    newNo += 1;
  }

  return { file, additions, deletions, rows };
}

// One code line, syntax-highlighted inline (no block wrapper) so it drops into a
// diff row. Empty lines render a space to keep row height.
function CodeLine({ code, language }: { code: string; language: string }) {
  return (
    <SyntaxHighlighter
      language={language}
      style={codeTheme}
      PreTag="span"
      CodeTag="span"
      customStyle={{
        background: 'transparent',
        padding: 0,
        margin: 0,
        display: 'inline',
        whiteSpace: 'pre',
        fontFamily: 'inherit',
        fontSize: 'inherit',
      }}
      codeTagProps={{ style: { background: 'transparent', fontFamily: 'inherit', fontSize: 'inherit', whiteSpace: 'pre' } }}
    >
      {code.length ? code : ' '}
    </SyntaxHighlighter>
  );
}

// Above this many rendered rows a `collapsible` card starts collapsed: it shows
// a short PREVIEW_ROWS peek (faded at the bottom) plus an Expand control that
// opens the full diff into a height-capped, scrollable body — so a long file
// doesn't dominate the panel but still shows enough to recognise the change.
const COLLAPSE_THRESHOLD = 8;
const PREVIEW_ROWS = 6;

function DiffRows({ rows, language }: { rows: DiffRow[]; language: string }) {
  return (
    <>
      {rows.map((r, i) => {
        const rowBg = r.type === 'add' ? 'bg-success/10' : r.type === 'del' ? 'bg-destructive/10' : '';
        return (
          <div key={i} className={`px-3 ${rowBg}`}>
            <CodeLine code={r.text} language={language} />
          </div>
        );
      })}
    </>
  );
}

// `collapsible` is set by the Changes tab (net PR view), where a long file — a
// bumped Gemfile.lock, a many-line code fix — shouldn't dominate the panel. The
// chat's live edit steps stay always-expanded (each is one small edit).
export function FileDiffCard({ diff, collapsible = false }: { diff: string; collapsible?: boolean }) {
  const { file, additions, deletions, rows: allRows } = parseUnifiedDiff(diff);
  const rows = capContext(allRows, MAX_CONTEXT);
  const language = languageForFile(file);
  const long = collapsible && rows.length > COLLAPSE_THRESHOLD;
  const [expanded, setExpanded] = useState(false);
  const collapsed = long && !expanded;
  const hiddenCount = rows.length - PREVIEW_ROWS;

  return (
    <div className="my-1 overflow-hidden rounded-lg border border-border bg-background-card-header">
      <div className="flex items-center gap-2 bg-background-card-header px-3 py-2">
        <VscodeFileIcon file={file} size={16} />
        <span className="truncate font-mono text-xs text-foreground/90">{file || 'file'}</span>
        <span className="ml-1 shrink-0 font-mono text-[11px] text-success">+{additions}</span>
        <span className="shrink-0 font-mono text-[11px] text-destructive">−{deletions}</span>
      </div>

      <div className="relative">
        <div
          className={`overflow-x-auto border-t border-border py-2 font-mono text-[12px] leading-relaxed ${
            long && expanded ? 'max-h-80 overflow-y-auto' : ''
          }`}
        >
          <DiffRows rows={collapsed ? rows.slice(0, PREVIEW_ROWS) : rows} language={language} />
        </div>
        {/* Fade the last preview line so it reads as "more below". */}
        {collapsed && (
          <div className="pointer-events-none absolute inset-x-0 bottom-0 h-10 bg-gradient-to-t from-background-card-header to-transparent" />
        )}
      </div>

      {long && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
          className="flex w-full items-center justify-center gap-1 border-t border-border py-1.5 text-[11px] font-medium text-foreground-secondary hover:bg-background-subtle/40 hover:text-foreground transition-colors"
        >
          {expanded ? (
            <>
              <ChevronUp className="h-3 w-3" /> Show less
            </>
          ) : (
            <>
              <ChevronDown className="h-3 w-3" /> Expand {hiddenCount} more {hiddenCount === 1 ? 'line' : 'lines'}
            </>
          )}
        </button>
      )}
    </div>
  );
}
