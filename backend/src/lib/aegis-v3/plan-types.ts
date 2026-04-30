import { z } from 'zod';

export type FindingType = 'vulnerability' | 'semgrep' | 'secret';
export type PlanLanguage = 'js' | 'ts' | 'python' | 'go' | 'java' | 'ruby' | 'php' | 'rust' | 'csharp';
export type PlanDiffSize = 'small' | 'medium' | 'large';
export type FileChangeAction = 'modify' | 'create' | 'delete';

export type FixStatus =
  | 'planning'
  | 'awaiting_approval'
  | 'approved'
  | 'executing'
  | 'completed'
  | 'failed'
  | 'rejected';

export const FINDING_TYPES: readonly FindingType[] = ['vulnerability', 'semgrep', 'secret'] as const;
export const PLAN_LANGUAGES: readonly PlanLanguage[] = [
  'js',
  'ts',
  'python',
  'go',
  'java',
  'ruby',
  'php',
  'rust',
  'csharp',
] as const;

export const SHIP_GATE_LANGUAGES: readonly PlanLanguage[] = ['js', 'ts', 'python', 'go'] as const;

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

export interface FixRecord {
  id: string;
  organizationId: string;
  projectId: string;
  status: FixStatus;
  finding: { type: FindingType; id: string };
  plan: FixPlan | null;
  planGeneratedAt: string | null;
  planBaseSha: string | null;
  planBaseBranch: string | null;
  prUrl: string | null;
  prNumber: number | null;
  diffSummary: string | null;
  errorMessage: string | null;
  approvedAt: string | null;
  rejectedAt: string | null;
  createdAt: string;
}

const fileChangeSchema = z.object({
  path: z.string().min(1),
  action: z.enum(['modify', 'create', 'delete']),
  description: z.string().min(1),
});

const refusalSchema = z.object({
  reason: z.string().min(1),
  manualSuggestion: z.string().optional(),
});

export const fixPlanSchema = z.object({
  summary: z.string().min(1),
  finding: z.object({
    type: z.enum(['vulnerability', 'semgrep', 'secret']),
    id: z.string().min(1),
    severity: z.string().optional(),
  }),
  currentState: z.array(z.string().min(1)).min(1),
  desiredState: z.array(z.string().min(1)).min(1),
  fileChanges: z.array(fileChangeSchema),
  testCommand: z.string().min(1),
  language: z.enum(['js', 'ts', 'python', 'go', 'java', 'ruby', 'php', 'rust', 'csharp']),
  estimatedDiffSize: z.enum(['small', 'medium', 'large']),
  wallClockBudgetSec: z.number().int().positive().max(900),
  refusal: refusalSchema.optional(),
});

export const DEFAULT_WALL_CLOCK_BUDGET_SEC = 300;
export const MAX_DIFF_LOC = 500;
export const MAX_TOOL_CALLS = 30;
export const REPAIR_BUDGET = 2;

export function isShipGateLanguage(lang: PlanLanguage): boolean {
  return SHIP_GATE_LANGUAGES.includes(lang);
}
