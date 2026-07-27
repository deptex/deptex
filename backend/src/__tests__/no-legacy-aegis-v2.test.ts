// CI grep guard against the legacy aegis-v2 task / sprint / incident subsystem.
//
// The Aegis Task primitive (a task is a chat with one goal) replaced the dead
// aegis-v2 task-step / sprint-orchestration / incident-response code, which was
// removed in the same PR. This guard fails CI if any of those identifiers
// reappear in src/ — they are hard regressions. Modeled on
// no-plan-tier-references.test.ts.
//
// Note on word boundaries: matches use \b...\b, so the new table
// `aegis_agent_tasks` and the route string `/api/aegis/tasks` do NOT collide
// with the forbidden `aegis_task_steps` / legacy module names.

import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '../../..');
const BACKEND_SRC = path.resolve(__dirname, '..');
const FRONTEND_SRC = path.resolve(REPO_ROOT, 'frontend/src');

// Identifiers from the deleted aegis-v2 subsystem. Any hit is a regression.
const FORBIDDEN: string[] = [
  // Deleted modules (import specifiers)
  'sprint-orchestrator',
  'incident-engine',
  'incident-triggers',
  'incident-templates',
  'incident-postmortem',
  'incident-cron',
  // Deleted router/component bindings
  'incidentsRouter',
  'incidentCronRouter',
  'aegisTaskStepRouter',
  'IncidentResponseSection',
  // Deleted v2 functions
  'createSecuritySprint',
  'confirmInteractiveSprint',
  'getSprintSummary',
  'executeTaskStep',
  'getNextPendingStep',
  'handleIncidentStepCompletion',
  'checkIncidentTriggers',
];
// NOTE: legacy v2 *table* names (aegis_task_steps / aegis_approval_requests) are
// intentionally NOT forbidden here — the parked v2 Slack integration
// (lib/aegis/slack-bot.ts) still references them and is out of this PR's removal
// scope. This guard polices the deleted task/sprint/incident MODULES + functions.

const EXCLUDED_FILES = new Set<string>([
  path.resolve(__dirname, 'no-legacy-aegis-v2.test.ts'),
]);

function isExcluded(file: string): boolean {
  if (EXCLUDED_FILES.has(file)) return true;
  if (file.includes('node_modules')) return true;
  if (file.endsWith('.d.ts')) return true;
  return false;
}

function walk(dir: string, out: string[] = []): string[] {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (entry.isFile() && (full.endsWith('.ts') || full.endsWith('.tsx'))) {
      if (!isExcluded(full)) out.push(full);
    }
  }
  return out;
}

function findMatches(identifiers: string[], roots: string[]): Record<string, string[]> {
  const matches: Record<string, string[]> = {};
  const files = roots.flatMap((r) => walk(r));
  for (const id of identifiers) {
    const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`\\b${escaped}\\b`);
    const hits: string[] = [];
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf-8');
      if (re.test(content)) hits.push(path.relative(REPO_ROOT, file));
    }
    if (hits.length > 0) matches[id] = hits;
  }
  return matches;
}

describe('no legacy aegis-v2 references (CI grep guard)', () => {
  test('removed aegis-v2 task/sprint/incident identifiers never appear in src/', () => {
    const hits = findMatches(FORBIDDEN, [BACKEND_SRC, FRONTEND_SRC]);
    if (Object.keys(hits).length > 0) {
      const formatted = Object.entries(hits)
        .map(([id, files]) => `  ${id}: ${files.length} file(s)\n${files.map((f) => `    - ${f}`).join('\n')}`)
        .join('\n');
      throw new Error(`Forbidden legacy aegis-v2 identifiers leaked into src/:\n${formatted}`);
    }
  });
});
