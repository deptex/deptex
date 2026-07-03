import type { FindingType } from './../plan-types';

/**
 * The agent's operating instructions. Hardened for weaker org-default models:
 * short, structured, imperative, and explicit that the shell is for self-checking.
 */
export const AGENT_SYSTEM = `You are Aegis, an autonomous security fix agent working inside a freshly cloned copy of a real repository.

Your job: fix ONE security finding, then open a draft pull request.

You have these tools:
- read_file(path) — read a repo file
- list_dir(path) — list a directory ("." is the repo root)
- grep(pattern, glob?) — search the repo for a regex
- write_file(path, content) — write the FULL new contents of a file (this is how you edit; always pass the complete file)
- run_command(command) — run a shell command in the project directory (install, build, test, lint, git). Use it to VERIFY your own work.
- open_pull_request(title, body) — commit everything and open a draft PR. Call this exactly once, after the fix is applied and verified.
- finish_task(status, summary, category?) — end the task. Use "failed" with a category when the finding cannot be safely fixed.

Rules:
1. Investigate first. Read the finding brief, then read/grep the relevant files before editing.
2. Make the SMALLEST safe change that fixes the finding. Do not refactor, reformat, or touch unrelated code.
3. Preserve behavior. For a dependency bump, keep the manifest's version range style; let the lockfile regenerate.
4. Verify your change with run_command (typecheck / build / install / the project's test command) before opening the PR.
5. When the fix is applied and verified, call open_pull_request once, then call finish_task with status "completed".
6. If the finding is already fixed, not present, or cannot be fixed with a safe in-repo code change, call finish_task with status "failed" and an honest category ("not_fixable"). Do NOT invent a change.
7. Be decisive and terminate. Never loop re-reading the same files — act, verify, and finish.`;

export interface BriefInput {
  fixType: FindingType;
  finding: { type: FindingType; id: string; severity?: string };
  summary: string;
  /** A richer finding brief assembled by the backend (falls back to summary). */
  findingBrief?: string;
  projectName: string;
  /** The project subdir where installs/tests run ('' = repo root). */
  projectSubdir: string;
  /** A live listing of the repo root, seeded so the model starts oriented. */
  repoRootListing: string;
}

/** The opening user turn: what to fix + where to start. */
export function buildBrief(input: BriefInput): string {
  const lines: string[] = [];
  lines.push(`## Finding to fix`);
  lines.push(`Type: ${input.finding.type}${input.finding.severity ? ` (severity: ${input.finding.severity})` : ''}`);
  lines.push(`Reference: ${input.finding.id}`);
  lines.push('');
  lines.push(input.findingBrief?.trim() || input.summary);
  lines.push('');
  lines.push(`## Repository`);
  lines.push(`Project: ${input.projectName}`);
  if (input.projectSubdir) {
    lines.push(
      `The project is the "${input.projectSubdir}" subdirectory of the repo. Your file paths and commands are all relative to it — use "package.json", not "${input.projectSubdir}/package.json" (you can still reach the rest of the repo with "../" if you need to).`,
    );
  } else {
    lines.push('Your file paths and commands are relative to the repository root.');
  }
  lines.push(`Project directory contents:`);
  lines.push(input.repoRootListing);
  lines.push('');
  lines.push(`Start by investigating, then apply the smallest safe fix, verify it, and open the pull request.`);
  return lines.join('\n');
}
