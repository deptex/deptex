# Create Worktree

Create a new git worktree branched off the latest `origin/main` for isolated feature work. Deptex worktrees live under `.claude/worktrees/<name>/` with matching branches named `worktree-<name>`.

## Inputs

Accept a feature name from the user (e.g. `flow-builder`, `aegis-v2`). If none provided, ask for one. Keep it short, kebab-case, and specific — it becomes both the directory name and the branch suffix.

## Steps

1. **Sync local `main` to `origin/main` (always — never skip)**
   ```bash
   git fetch origin
   git branch -f main origin/main
   ```
   - Works regardless of whether local `main` drifted from origin.
   - `-f` is refused if `main` is currently checked out; if it is, switch off it first (e.g. `git switch -d origin/main`) and retry.
   - **Why:** Henry merges PRs via GitHub's "Rebase and merge" / "Squash and merge", which creates NEW SHAs on origin. Local `main` accumulates stale pre-merge commits; without this step, worktrees branch off phantom history and everything downstream breaks. This is the single most important pre-flight in the repo.

2. **Confirm the working tree is in a reasonable state**
   - `git status` — uncommitted changes in the primary tree are fine (they stay there), but flag anything surprising.

3. **Create the worktree off `origin/main`**
   ```bash
   git worktree add -b worktree-<name> .claude/worktrees/<name> origin/main
   ```
   - Branch name: `worktree-<name>`
   - Path: `.claude/worktrees/<name>/`
   - Base: `origin/main` (explicitly — never local `main`, in case step 1 was somehow skipped)

4. **Copy env files into the worktree**
   - `cp backend/.env .claude/worktrees/<name>/backend/.env`
   - `cp frontend/.env .claude/worktrees/<name>/frontend/.env` (if `frontend/.env` exists)
   - `cp backend/github-app-private-key.pem .claude/worktrees/<name>/backend/github-app-private-key.pem`
   - The first two are gitignored and contain the secrets (Supabase, Fly, Stripe, AI keys, etc.) required to run the dev servers. The PEM is referenced by `GITHUB_APP_PRIVATE_KEY_PATH=./github-app-private-key.pem` in backend/.env, resolved relative to the worktree's own backend root — without it, every `request_fix` / Aegis Fix Agent call crashes with "GitHub App private key file not found at...".
   - Do NOT commit these from the worktree.

5. **Install dependencies**
   - `cd .claude/worktrees/<name>/backend && npm install`
   - `cd .claude/worktrees/<name>/frontend && npm install`
   - Skipping this is a known trap — tsc/tests will fail in the new worktree without it.

6. **Handle ports if the user plans to run dev servers alongside the main tree**
   - Default dev servers use frontend `3000` / backend `3001`, which collide with the primary tree.
   - If asked to configure alternate ports, use `3010` (frontend) / `3011` (backend) — this is the established pattern (see flow-builder memory).
   - Update `frontend/vite.config.ts` (`server.port`) and `backend/.env` (`PORT`) in the worktree only.

7. **Report back**
   - Worktree path
   - Branch name
   - Base SHA (`origin/main` at creation time)
   - Env files copied
   - Ports if alternate ones were configured
   - Reminder that next `/push-changes` from inside this worktree will open a PR into `main`

## Rules

- Branch off `origin/main`, never off local `main`, `prod`, or another worktree branch.
- Always run step 1's `git fetch origin && git branch -f main origin/main` — do not skip even when "main looks fine".
- Never delete an existing worktree without confirmation — it may hold in-progress work.
- Never copy `.env` into version control (it's gitignored, but double-check `git status` after copying).
- Never create a worktree with a name that already exists under `.claude/worktrees/`; pick a new name or confirm reuse.
