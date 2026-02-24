import { useMemo } from 'react';
import * as Diff from 'diff';

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
    return Diff.diffLines(baseCode || '', requestedCode || '');
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
      className={`rounded-lg border border-border bg-[#1d1f21] overflow-auto font-mono text-sm ${className}`}
      style={{ minHeight }}
    >
      <pre className="p-4 m-0">
        {lines.map((line, i) => (
          <div
            key={i}
            className={`flex ${
              line.type === 'add'
                ? 'bg-green-500/20 text-green-200'
                : line.type === 'remove'
                  ? 'bg-red-500/20 text-red-200'
                  : 'text-foreground-secondary'
            }`}
          >
            <span className="w-10 shrink-0 select-none pr-3 text-right text-foreground-secondary/60">
              {line.type === 'remove' || line.type === 'same' ? line.lineNum : ''}
            </span>
            <span className={line.type === 'add' ? 'pl-2' : ''}>
              {line.type === 'add' && <span className="text-green-400 mr-2">+</span>}
              {line.type === 'remove' && <span className="text-red-400 mr-2">-</span>}
              {line.text || ' '}
            </span>
          </div>
        ))}
      </pre>
    </div>
  );
}
