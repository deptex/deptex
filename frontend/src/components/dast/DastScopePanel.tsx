import { useState, type ChangeEvent } from 'react';
import { Plus, Trash2, AlertCircle } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import type { DastScopeConfig, DastScopeHeaderRule } from '../../lib/api';

interface DastScopePanelProps {
  value: DastScopeConfig;
  onChange: (next: DastScopeConfig) => void;
  disabled?: boolean;
}

const SENSITIVE_HEADER_NAMES = /^(authorization|cookie|x-api-key|x-auth-token|x-csrf-token)$/i;
const SENSITIVE_HEADER_FRAGMENT = /(token|secret|password|key)/i;

function compileError(pattern: string): string | null {
  if (pattern.length === 0) return null;
  if (pattern.length > 256) return 'Pattern too long (max 256 characters)';
  try {
    new RegExp(pattern);
    return null;
  } catch (e: any) {
    return e?.message ?? 'Invalid regex';
  }
}

function sensitiveHeaderError(name: string): string | null {
  if (name.length === 0) return null;
  if (SENSITIVE_HEADER_NAMES.test(name)) {
    return 'Use the credential panel for sensitive headers';
  }
  if (SENSITIVE_HEADER_FRAGMENT.test(name)) {
    return 'Looks like a secret — use the credential panel instead';
  }
  return null;
}

export function DastScopePanel({ value, onChange, disabled }: DastScopePanelProps) {
  const include = value.include_patterns ?? [];
  const exclude = value.exclude_patterns ?? [];
  const headers = value.header_rules ?? [];

  const updateInclude = (next: string[]) =>
    onChange({ ...value, include_patterns: next });
  const updateExclude = (next: string[]) =>
    onChange({ ...value, exclude_patterns: next });
  const updateHeaders = (next: DastScopeHeaderRule[]) =>
    onChange({ ...value, header_rules: next });

  return (
    <div className="space-y-6">
      <PatternSection
        title="Include patterns"
        description="Regex matched against request URLs. If non-empty, only matching URLs are scanned."
        patterns={include}
        onChange={updateInclude}
        disabled={disabled}
      />
      <PatternSection
        title="Exclude patterns"
        description="Regex matched against request URLs. Matching URLs are skipped (e.g. /admin/destroy)."
        patterns={exclude}
        onChange={updateExclude}
        disabled={disabled}
      />
      <HeaderRulesSection
        rules={headers}
        onChange={updateHeaders}
        disabled={disabled}
      />
    </div>
  );
}

interface PatternSectionProps {
  title: string;
  description: string;
  patterns: string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
}

function PatternSection({ title, description, patterns, onChange, disabled }: PatternSectionProps) {
  const [draft, setDraft] = useState('');
  const draftError = compileError(draft);

  const addPattern = () => {
    const trimmed = draft.trim();
    if (trimmed.length === 0 || draftError) return;
    onChange([...patterns, trimmed]);
    setDraft('');
  };

  const removeAt = (i: number) => {
    onChange(patterns.filter((_, idx) => idx !== i));
  };

  const updateAt = (i: number, next: string) => {
    onChange(patterns.map((p, idx) => (idx === i ? next : p)));
  };

  return (
    <div>
      <Label className="text-sm text-foreground">{title}</Label>
      <p className="text-xs text-foreground-secondary mt-0.5 mb-2">{description}</p>
      <div className="space-y-1.5">
        {patterns.map((p, i) => {
          const err = compileError(p);
          return (
            <div key={i} className="flex items-center gap-2">
              <PatternInput
                value={p}
                error={err}
                onChange={(v) => updateAt(i, v)}
                disabled={disabled}
              />
              <Button
                variant="outline"
                size="icon"
                onClick={() => removeAt(i)}
                disabled={disabled}
                aria-label="Remove pattern"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          );
        })}
        <div className="flex items-center gap-2">
          <PatternInput
            value={draft}
            error={draftError}
            onChange={setDraft}
            disabled={disabled}
            onEnter={addPattern}
            placeholder="^/api/.*"
          />
          <Button
            variant="outline"
            size="sm"
            onClick={addPattern}
            disabled={disabled || draft.trim().length === 0 || draftError !== null}
          >
            <Plus className="h-3.5 w-3.5 mr-1" /> Add
          </Button>
        </div>
      </div>
    </div>
  );
}

interface PatternInputProps {
  value: string;
  error: string | null;
  onChange: (v: string) => void;
  disabled?: boolean;
  onEnter?: () => void;
  placeholder?: string;
}

function PatternInput({ value, error, onChange, disabled, onEnter, placeholder }: PatternInputProps) {
  return (
    <div className="relative flex-1">
      <Input
        value={value}
        onChange={(e: ChangeEvent<HTMLInputElement>) => onChange(e.target.value)}
        disabled={disabled}
        placeholder={placeholder}
        className={
          error
            ? 'border-destructive focus-visible:ring-destructive font-mono text-xs pr-9'
            : 'font-mono text-xs pr-9'
        }
        onKeyDown={(e) => {
          if (e.key === 'Enter' && onEnter) {
            e.preventDefault();
            onEnter();
          }
        }}
      />
      {error ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="absolute right-2 top-1/2 -translate-y-1/2 text-destructive">
              <AlertCircle className="h-3.5 w-3.5" />
            </span>
          </TooltipTrigger>
          <TooltipContent className="max-w-md">{error}</TooltipContent>
        </Tooltip>
      ) : null}
    </div>
  );
}

interface HeaderRulesSectionProps {
  rules: DastScopeHeaderRule[];
  onChange: (next: DastScopeHeaderRule[]) => void;
  disabled?: boolean;
}

function HeaderRulesSection({ rules, onChange, disabled }: HeaderRulesSectionProps) {
  const [draft, setDraft] = useState<DastScopeHeaderRule>({ name: '', value: '', scope: 'all' });
  const draftError = sensitiveHeaderError(draft.name);

  const addRule = () => {
    if (draft.name.trim().length === 0 || draftError) return;
    onChange([...rules, { ...draft, name: draft.name.trim(), value: draft.value.trim() }]);
    setDraft({ name: '', value: '', scope: 'all' });
  };

  const removeAt = (i: number) => onChange(rules.filter((_, idx) => idx !== i));
  const updateAt = (i: number, next: DastScopeHeaderRule) =>
    onChange(rules.map((r, idx) => (idx === i ? next : r)));

  return (
    <div>
      <Label className="text-sm text-foreground">Header rules</Label>
      <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
        Inject custom headers into scan traffic. Sensitive header names (Authorization, Cookie,
        anything with token / secret / password / key) are blocked — use the credential panel instead.
      </p>
      <div className="space-y-1.5">
        {rules.map((rule, i) => {
          const err = sensitiveHeaderError(rule.name);
          return (
            <HeaderRuleRow
              key={i}
              rule={rule}
              error={err}
              onChange={(next) => updateAt(i, next)}
              onRemove={() => removeAt(i)}
              disabled={disabled}
            />
          );
        })}
        <div className="flex items-center gap-2">
          <HeaderRuleRow
            rule={draft}
            error={draftError}
            onChange={setDraft}
            disabled={disabled}
            placeholder
          />
          <Button
            variant="outline"
            size="sm"
            onClick={addRule}
            disabled={disabled || draft.name.trim().length === 0 || draftError !== null}
          >
            <Plus className="h-3.5 w-3.5 mr-1" /> Add
          </Button>
        </div>
      </div>
    </div>
  );
}

interface HeaderRuleRowProps {
  rule: DastScopeHeaderRule;
  error: string | null;
  onChange: (next: DastScopeHeaderRule) => void;
  onRemove?: () => void;
  disabled?: boolean;
  placeholder?: boolean;
}

function HeaderRuleRow({ rule, error, onChange, onRemove, disabled, placeholder }: HeaderRuleRowProps) {
  return (
    <div className="flex flex-1 items-center gap-2">
      <div className="relative flex-1">
        <Input
          value={rule.name}
          onChange={(e) => onChange({ ...rule, name: e.target.value })}
          disabled={disabled}
          placeholder={placeholder ? 'X-Test-User' : undefined}
          className={
            error
              ? 'border-destructive focus-visible:ring-destructive font-mono text-xs pr-9'
              : 'font-mono text-xs pr-9'
          }
        />
        {error ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="absolute right-2 top-1/2 -translate-y-1/2 text-destructive">
                <AlertCircle className="h-3.5 w-3.5" />
              </span>
            </TooltipTrigger>
            <TooltipContent className="max-w-md">{error}</TooltipContent>
          </Tooltip>
        ) : null}
      </div>
      <Input
        value={rule.value}
        onChange={(e) => onChange({ ...rule, value: e.target.value })}
        disabled={disabled}
        placeholder={placeholder ? 'scanner' : undefined}
        className="flex-1 font-mono text-xs"
      />
      <Select
        value={rule.scope}
        onValueChange={(v) => onChange({ ...rule, scope: v as DastScopeHeaderRule['scope'] })}
        disabled={disabled}
      >
        <SelectTrigger className="w-[120px]">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All</SelectItem>
          <SelectItem value="requests">Requests</SelectItem>
          <SelectItem value="responses">Responses</SelectItem>
        </SelectContent>
      </Select>
      {onRemove ? (
        <Button
          variant="outline"
          size="icon"
          onClick={onRemove}
          disabled={disabled}
          aria-label="Remove header rule"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      ) : null}
    </div>
  );
}
