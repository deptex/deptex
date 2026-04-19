import { useMemo } from 'react';
import { DiffEditor } from '@monaco-editor/react';
import type { editor } from 'monaco-editor';
import {
  CODE_BLOCK_BG,
  POLICY_LANGUAGE_ID,
  beforeMountPolicyMonaco,
} from './policy-monaco-setup';

const LINE_HEIGHT = 20;
const PADDING_TOP = 8;
/** Match PolicyCodeEditor: minimal bottom padding so no dead band below last line */
const PADDING_BOTTOM = 2;
const MAX_HEIGHT_PX = 480;

/**
 * Same idea as PolicyCodeEditor.computeFitHeight: height fits content + one line
 * buffer only — no large min height (that caused empty space below short diffs).
 */
function computeDiffHeight(original: string, modified: string): number {
  const lineCount = Math.max(
    1,
    (original || '').split('\n').length,
    (modified || '').split('\n').length
  );
  return Math.min(
    MAX_HEIGHT_PX,
    (lineCount + 1) * LINE_HEIGHT + PADDING_TOP + PADDING_BOTTOM
  );
}

export interface PolicyDiffCodeEditorProps {
  original: string;
  modified: string;
  className?: string;
}

/**
 * Monaco diff editor with same deptex theme as PolicyCodeEditor (read-only both sides).
 * Used in Policy AI assistant so suggested changes match the main code block visually.
 */
export function PolicyDiffCodeEditor({
  original,
  modified,
  className = '',
}: PolicyDiffCodeEditorProps) {
  const height = useMemo(
    () => computeDiffHeight(original ?? '', modified ?? ''),
    [original, modified]
  );

  return (
    <div
      className={`policy-code-editor w-full overflow-hidden rounded-none border-0 ${className}`}
      style={{ backgroundColor: CODE_BLOCK_BG, minHeight: height }}
    >
      <DiffEditor
        width="100%"
        height={height}
        original={original ?? ''}
        modified={modified ?? ''}
        language={POLICY_LANGUAGE_ID}
        theme="deptex"
        beforeMount={beforeMountPolicyMonaco}
        loading={
          <div
            style={{
              minHeight: height,
              backgroundColor: CODE_BLOCK_BG,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#71717a',
              fontSize: 13,
            }}
          >
            Loading...
          </div>
        }
        onMount={(diffEditor) => {
          diffEditor.getOriginalEditor().updateOptions({ readOnly: true });
          diffEditor.getModifiedEditor().updateOptions({ readOnly: true });
        }}
        options={
          {
            readOnly: true,
            originalEditable: false,
            modifiedEditable: false,
            minimap: { enabled: false },
            fontSize: 13,
            lineHeight: LINE_HEIGHT,
            fontFamily: "Consolas, 'Courier New', monospace",
            lineNumbers: 'on',
            lineNumbersMinChars: 2,
            scrollBeyondLastLine: false,
            automaticLayout: true,
            tabSize: 2,
            wordWrap: 'off',
            padding: { top: PADDING_TOP, bottom: PADDING_BOTTOM },
            renderSideBySide: true,
          } as editor.IDiffEditorConstructionOptions
        }
      />
    </div>
  );
}
