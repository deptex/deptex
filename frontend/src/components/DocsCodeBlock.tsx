/**
 * Read-only policy-style code block for docs — matches PoliciesPage editor chrome
 * (JS badge + title header, Monaco deptex theme, non-editable).
 */
import { PolicyCodeEditor } from './PolicyCodeEditor';
import { JsLangBadge } from './JsLangBadge';

export interface DocsCodeBlockProps {
  /** Shown in header next to JS badge (e.g. packagePolicy, Trigger body) */
  title: string;
  /** JavaScript source */
  value: string;
  className?: string;
}

export function DocsCodeBlock({ title, value, className = '' }: DocsCodeBlockProps) {
  return (
    <div className={`rounded-lg border border-border bg-background-card overflow-hidden ${className}`}>
      <div className="px-4 py-2 bg-background-card-header border-b border-border min-h-[36px] flex items-center gap-2">
        <JsLangBadge className="text-xs" />
        <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
          {title}
        </span>
      </div>
      <div className="bg-background-card">
        <PolicyCodeEditor
          value={value}
          onChange={() => {}}
          readOnly
          fitContent
        />
      </div>
    </div>
  );
}
