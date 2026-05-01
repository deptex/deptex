# Cleanup Worktree

Tear down a finished worktree after its PR has been merged: remove the worktree directory, delete the local branch, delete the remote branch (if GitHub didn't already), and re-sync local `main` to `origin/main` so the next `/create-worktree` starts from clean ground.

Run this from inside the worktree you just shipped, or from anywhere with the worktree name as an argument.

## Inputs

Optional: the worktree name (the bit after `worktree-`, e.g. `cross-file-taint-engine`). If not provided, infer it from `$PWD` when the command is run from inside `.claude/worktrees/<name>/`. If neither works, list current worktrees and ask which one to clean up.

## Steps

1. **Resolve which worktree + branch to clean**
   - From cwd: if `pwd` matches `*/.claude/worktrees/<name>/*`, that's the target. Branch is `worktree-<name>`.
   - From arg: target = `.claude/worktrees/<arg>`, branch = `worktree-<arg>`.
   - **Refuse** to operate on the primary tree itself or on `main` / `prod` — only `worktree-*` branches under `.claude/worktrees/` are in scope.
   - Confirm the resolved target with the user before any destructive step ("About to clean up worktree `cross-file-taint-engine` and branch `worktree-cross-file-taint-engine`. Confirm?").

2. **Refuse to clean up uncommitted or unpushed work**
   - In the target worktree: `git -C <worktree-path> status --porcelain`. If non-empty, stop and surface the diff — the user must commit, stash, or explicitly say "discard" before this skill will proceed.
   - `git -C <worktree-path> log @{u}.. --oneline 2>/dev/null` — if there are local commits not on the remote, stop and surface them. They'd be silently destroyed by the local branch delete.
   - Both checks are mandatory. Do not offer a `--force` flag without an explicit user request.

3. **Fetch + prune so we know the real remote state**
   ```bash
   git fetch origin --prune
   ```
   - `--prune` removes remote-tracking refs (`origin/worktree-<name>`) when the upstream branch has been deleted (GitHub does this automatically on merge if "Automatically delete head branches" is enabled — Deptex has it on).
   - After this step, the absence of `origin/worktree-<name>` is the strongest signal the PR was merged and GitHub cleaned up.

4. **Confirm the PR was actually merged**
   - **Preferred check (no `gh`):** if `git rev-parse --verify origin/worktree-<name> 2>/dev/null` fails after the prune in step 3, GitHub deleted the remote branch — almost always because the PR merged. Treat as merged.
   - **Fallback check:** ask the user "Is PR merged on github.com?" (yes/no). Only proceed on yes.
   - Do NOT try to verify via `git merge-base --is-ancestor` against `origin/main` — GitHub's "Squash and merge" / "Rebase and merge" rewrites SHAs, so the original branch tip never appears in `origin/main`'s history. That check produces false negatives and would block legitimate cleanups.
   - Never use `gh` — Henry works on github.com directly.

5. **Move out of the worktree if we're inside it**
   - `git worktree remove` refuses to remove the worktree you're currently standing in.
   - If cwd is inside the target worktree, `cd` to the primary tree (`C:/Coding/Deptex` — find it via `git worktree list | head -1`) before continuing.

6. **Remove the worktree**
   ```bash
   git worktree remove .claude/worktrees/<name>
   ```
   - Removes the directory AND git's internal worktree bookkeeping in one step. Do NOT `rm -rf` the directory manually — that leaves stale entries in `.git/worktrees/` that have to be cleaned up with `git worktree prune` later.
   - If this fails because of leftover untracked files (e.g. `node_modules`, `.env`, build output), surface what's there and ask whether to `git worktree remove --force`. Don't auto-force — `.env` lives in the worktree and a stray `--force` deletes the only copy of any locally-edited secret.

7. **Delete the local branch**
   ```bash
   git branch -D worktree-<name>
   ```
   - `-D` (force) is correct here even though we already verified merge state — squash/rebase merges leave the local branch looking "unmerged" to git, so `-d` would refuse. Step 2's unpushed-commit check is what actually protects against losing work.

8. **Delete the remote branch if it still exists**
   - If step 4's preferred check showed `origin/worktree-<name>` was already gone, skip this step — GitHub already cleaned up.
   - Otherwise:
     ```bash
     git push origin --delete worktree-<name>
     ```
   - If the push fails with "remote ref does not exist", treat as success (someone else already deleted it).

9. **Sync local `main` to `origin/main`**
   ```bash
   git branch -f main origin/main
   ```
   - This is the "set up for the next feature" beat the user invokes this skill for.
   - `-f` is refused if `main` is currently checked out in the primary tree; if it is, switch off it first (e.g. `git switch -d origin/main`) and retry.
   - **Why:** `/create-worktree` re-syncs anyway, but doing it here means `git log main` in the primary tree is immediately accurate after cleanup, and any non-`/create-worktree` follow-up (a `git checkout main` to inspect the merged state) lands on the right SHAs.

10. **Report**
    - Worktree path removed
    - Local branch deleted
    - Remote branch: deleted-now / already-deleted-by-github / skipped
    - Local `main` synced to `origin/main` at `<short-sha>`
    - Suggest the natural next step: `/create-worktree <new-feature-name>`

## Rules

- Never operate on the primary tree, `main`, or `prod`. Only `worktree-*` branches under `.claude/worktrees/`.
- Never skip the uncommitted-changes / unpushed-commits checks in step 2.
- Never `rm -rf` a worktree directory — always `git worktree remove`, which keeps git's bookkeeping consistent.
- Never use `gh` to verify merge state — Henry works on github.com manually. The fetch-prune signal in step 3 + a yes/no confirmation in step 4 is the supported flow.
- Never force-delete the remote branch (`git push --force origin --delete` is not a real flag, but don't invent equivalents). If the remote rejects the delete, surface why and let the user decide.
- If the user has multiple stale worktrees from previously-merged features (a common state — see `git worktree list`), this skill cleans up ONE per invocation. Don't sweep them all without explicit instruction.
