import { useMemo } from 'react';
import Editor from 'react-simple-code-editor';
import Prism from 'prismjs';
import 'prismjs/components/prism-javascript';
import 'prismjs/themes/prism-tomorrow.css';

interface PolicyCodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  className?: string;
  minHeight?: string;
}

export function PolicyCodeEditor({
  value,
  onChange,
  placeholder,
  readOnly = false,
  className = '',
  minHeight = '320px',
}: PolicyCodeEditorProps) {
  const highlight = useMemo(() => (code: string) => {
    return Prism.highlight(code, Prism.languages.javascript, 'javascript');
  }, []);

  return (
    <div
      className={`rounded-lg border border-border bg-[#1d1f21] overflow-hidden ${className}`}
      style={{ minHeight }}
    >
      <Editor
        value={value}
        onValueChange={onChange}
        highlight={highlight}
        padding={16}
        placeholder={placeholder}
        readOnly={readOnly}
        style={{
          fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
          fontSize: 13,
          minHeight,
        }}
        textareaClassName="focus:outline-none"
        preClassName="m-0"
      />
    </div>
  );
}
