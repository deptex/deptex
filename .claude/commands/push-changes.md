# Push Changes

Commit the current work, push to origin, and open a PR into `main`. Use this at natural stopping points on a feature branch or worktree branch.

## Inputs

Optional: a short description of the change from the user. If not provided, derive it from the diff.

## Steps

1. **Survey state (run in parallel)**
   - `git fetch origin` — always fetch before reasoning about branch state (local drifts from origin after every rebase/squash merge on GitHub)
   - `git status` (no `-uall` flag)
   - `git diff` (staged + unstaged)
   - `git log --oneline -10` to match the repo's commit style
   - `git rev-parse --abbrev-ref HEAD` to confirm the branch
   - `git rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null` to see if upstream is set
   - If local `main` has drifted from `origin/main` (common after GitHub merges) and the user is about to branch off, mention it and suggest `/create-worktree` (which auto-syncs) or `git branch -f main origin/main` before branching.

2. **Safety checks**
   - If current branch is `main` or `prod`: stop and ask the user — direct pushes to these are usually wrong.
   - If the diff contains `.env`, credentials, keys, or other likely-secret files: flag and ask before staging.
   - If there are no changes (clean tree, nothing to push): report and exit.

3. **Draft the commit message**
   - **Conventional Commits prefix required:** `feat:` / `fix:` / `chore:` / `refactor:` / `docs:` / `test:` / `perf:` / `ci:` / `build:` / `style:`
   - Plain prose describing the actual change — **no milestone labels** like "M3" or "Phase 2 M1".
   - Focus on the *why* when it's not obvious from the diff.
   - 1–2 sentences. No Co-Authored-By trailer. No "Generated with Claude Code" line. Author as Henry only.

4. **Stage and commit**
   - Stage specific files by name — never `git add -A` or `git add .`
   - Commit with the message via HEREDOC for correct formatting:
     ```bash
     git commit -m "$(cat <<'EOF'
     feat: short summary

     Optional body explaining the why.
     EOF
     )"
     ```
   - If a pre-commit hook fails, fix the underlying issue and create a **new** commit — never `--amend`, never `--no-verify`.

5. **Push**
   - First push on a branch: `git push -u origin <branch>`
   - Subsequent pushes: `git push`
   - On the first push, `git push` prints a `https://github.com/<owner>/<repo>/pull/new/<branch>` URL — capture it from the push output.

6. **Report back — do NOT run `gh`**
   - `gh` is not installed and Henry creates PRs manually on github.com. Never shell out to `gh pr create` or any other `gh` subcommand.
   - On first push, surface the "pull/new/..." URL to the user and suggest:
     - Title: the same Conventional Commits commit subject
     - Base: `main`
     - Body (markdown): a `## Summary` section only — describe what changed and why. Skip "Test plan" / verification checklists; Henry doesn't want them in PR descriptions.
       ```
       ## Summary
       <bullets describing what was added / changed / fixed>
       ```
     - No Claude footer in the PR body either.
   - On subsequent pushes to the same branch, no URL is needed — the existing PR updates automatically.

7. **Final output**
   - Commit SHA
   - Branch pushed
   - `pull/new/...` URL (first push only) or a note that the existing PR was updated

## Rules

- Never push to `main` or `prod` directly — always via PR.
- Never skip hooks (`--no-verify`) or bypass signing.
- Never force-push without explicit user approval, and never to `main`/`prod`.
- Never use `gh` for anything — Henry works on github.com directly. Surface URLs; don't automate GitHub actions.
