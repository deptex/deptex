// Mirror of backend/src/lib/aegis-v3/plan-types.ts. The worker can't import
// from the parent backend tree (separate tsconfig + Docker image), so the
// shape lives here too. Keep in sync.

export type PlanLanguage = 'js' | 'ts' | 'python' | 'go' | 'java' | 'ruby' | 'php' | 'rust' | 'csharp';
export type PlanDiffSize = 'small' | 'medium' | 'large';
export type FindingType = 'vulnerability' | 'semgrep' | 'secret';
export type FileChangeAction = 'modify' | 'create' | 'delete';

export interface PlanFileChange {
  path: string;
  action: FileChangeAction;
  description: string;
}

export interface PlanTodo {
  title: string;
  detail?: string;
}

export interface VerificationStep {
  command: string;
  description: string;
}

export interface PlanRefusal {
  reason: string;
  manualSuggestion?: string;
}

export interface FixPlan {
  summary: string;
  finding: { type: FindingType; id: string; severity?: string };
  description: string;
  issue?: string;
  todos?: PlanTodo[];
  fileChanges: PlanFileChange[];
  testCommand: string;
  verification?: string;
  verificationSteps?: VerificationStep[];
  language: PlanLanguage;
  estimatedDiffSize: PlanDiffSize;
  wallClockBudgetSec: number;
  refusal?: PlanRefusal;
}

export const SHIP_GATE_LANGUAGES: readonly PlanLanguage[] = ['js', 'ts', 'python', 'go'] as const;
export const ALL_LANGUAGES: readonly PlanLanguage[] = [
  'js', 'ts', 'python', 'go', 'java', 'ruby', 'php', 'rust', 'csharp',
] as const;
export const MAX_DIFF_LOC = 500;
export const MAX_TOOL_CALLS = 30;
export const REPAIR_BUDGET = 2;

/**
 * Resolve which languages this worker (and the planner mirroring this env) is
 * allowed to act on. Defaults to the v1 ship gate (js/ts/python/go). Set
 * LANGUAGE_GATE to a CSV like "js,ts,python,go,java" to open up stretch
 * languages whose bootstrap is wired in sandbox.ts. Special token "all"
 * expands to every supported language.
 */
export function getEnabledLanguages(): readonly PlanLanguage[] {
  const raw = process.env.LANGUAGE_GATE?.trim();
  if (!raw) return SHIP_GATE_LANGUAGES;
  if (raw.toLowerCase() === 'all') return ALL_LANGUAGES;
  const parsed = raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s): s is PlanLanguage => (ALL_LANGUAGES as readonly string[]).includes(s));
  return parsed.length > 0 ? parsed : SHIP_GATE_LANGUAGES;
}

export function isLanguageEnabled(lang: PlanLanguage): boolean {
  return getEnabledLanguages().includes(lang);
}
