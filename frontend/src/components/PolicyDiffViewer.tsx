import { useMemo } from 'react';
import * as Diff from 'diff';
import Prism from 'prismjs';
import 'prismjs/components/prism-javascript';

const DIFF_OPTIONS = { ignoreWhitespace: true };

/** Syntax-highlight a line of JS for display in the diff (unchanged lines only). */
function highlightLine(text: string): string {
  if (!text.trim()) return '';
  try {
    return Prism.highlight(text, Prism.languages.javascript, 'javascript');
  } catch {
    return escapeHtml(text);
  }
}

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

export function getDiffLineCounts(baseCode: string, requestedCode: string): { added: number; removed: number } {
  const chunks = Diff.diffLines(baseCode || '', requestedCode || '', DIFF_OPTIONS);
  let added = 0;
  let removed = 0;
  for (const chunk of chunks) {
    const lineCount = (chunk.value?.match(/\n/g) || []).length + (chunk.value && !chunk.value.endsWith('\n') ? 1 : 0);
    if (chunk.added) added += lineCount;
    else if (chunk.removed) removed += lineCount;
  }
  return { added, removed };
}

interface PolicyDiffViewerProps {
  baseCode: string;
  requestedCode: string;
  className?: string;
  minHeight?: string;
}

export function PolicyDiffViewer({
  baseCode,
  requestedCode,
  className = '',
  minHeight = '360px',
}: PolicyDiffViewerProps) {
  const chunks = useMemo(() => {
    return Diff.diffLines(baseCode || '', requestedCode || '', DIFF_OPTIONS);
  }, [baseCode, requestedCode]);

  const lines = useMemo(() => {
    const result: Array<{ type: 'add' | 'remove' | 'same'; text: string; lineNum?: number }> = [];
    let lineNum = 1;
    for (const chunk of chunks) {
      const raw = (chunk.value || '').replace(/\n$/, '');
      const lineTexts = raw ? raw.split('\n') : [];
      if (chunk.added) {
        for (const line of lineTexts) {
          result.push({ type: 'add', text: line });
        }
      } else if (chunk.removed) {
        for (const line of lineTexts) {
          result.push({ type: 'remove', text: line, lineNum: lineNum++ });
        }
      } else {
        for (const line of lineTexts) {
          result.push({ type: 'same', text: line, lineNum: lineNum++ });
        }
      }
    }
    return result;
  }, [chunks]);

  return (
    <div
      className={`policy-diff-viewer rounded-none border-0 bg-[#1d1f21] overflow-auto font-mono text-sm ${className}`}
      style={{ minHeight }}
    >
      <pre className="p-4 m-0">
        {lines.map((line, i) => (
          <div
            key={i}
            className={`flex ${
              line.type === 'add'
                ? 'bg-emerald-500/25 text-emerald-100'
                : line.type === 'remove'
                  ? 'bg-red-500/25 text-red-100'
                  : 'bg-transparent'
            }`}
          >
            <span
              className={`w-10 shrink-0 select-none pr-3 text-right ${
                line.type === 'same' ? 'text-[#6e7175]' : 'text-inherit opacity-80'
              }`}
            >
              {line.type === 'remove' || line.type === 'same' ? line.lineNum : ''}
            </span>
            <span className={line.type === 'add' ? 'pl-2' : ''}>
              {line.type === 'same' ? (
                <span
                  className="policy-diff-line-syntax"
                  dangerouslySetInnerHTML={{
                    __html: highlightLine(line.text) || ' ',
                  }}
                />
              ) : (
                <>{line.text || ' '}</>
              )}
            </span>
          </div>
        ))}
      </pre>
    </div>
  );
}
