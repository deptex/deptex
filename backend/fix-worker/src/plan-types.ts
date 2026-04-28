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

export interface PlanRefusal {
  reason: string;
  manualSuggestion?: string;
}

export interface FixPlan {
  summary: string;
  finding: { type: FindingType; id: string; severity?: string };
  currentState: string[];
  desiredState: string[];
  fileChanges: PlanFileChange[];
  testCommand: string;
  language: PlanLanguage;
  estimatedDiffSize: PlanDiffSize;
  wallClockBudgetSec: number;
  refusal?: PlanRefusal;
}

export const SHIP_GATE_LANGUAGES: readonly PlanLanguage[] = ['js', 'ts', 'python', 'go'] as const;
export const MAX_DIFF_LOC = 500;
export const MAX_TOOL_CALLS = 30;
export const REPAIR_BUDGET = 2;

export function isShipGateLanguage(lang: PlanLanguage): boolean {
  return SHIP_GATE_LANGUAGES.includes(lang);
}
