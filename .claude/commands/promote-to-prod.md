# Promote to Prod

Fast-forward `prod` to `main` and push, triggering the Fly worker redeploys. This is the release step — use it only when `main` is in a shippable state.

Operates entirely via `origin/*` refs so it can't be fooled by a drifted local `main`.

## Inputs

None required. Optionally the user may pass a release note / summary for the report at the end.

## Steps

1. **Fetch the truth from origin**
   ```bash
   git fetch origin
   ```
   - Always do this first. Never trust local `main` / local `prod` for this skill — GitHub's "Rebase and merge" / "Squash and merge" rewrites SHAs, so local refs drift.

2. **Verify `origin/prod` is an ancestor of `origin/main`**
   ```bash
   git merge-base --is-ancestor origin/prod origin/main
   ```
   - If this exits non-zero, `prod` has diverged from `main` on origin. Stop and surface the divergence — do not force-push without explicit user approval (the only legitimate reason for `prod` to diverge from `main` would be a hand-edit or a corrupted earlier promote, both of which deserve human review).

3. **Show what will ship and confirm with the user**
   ```bash
   git log origin/prod..origin/main --oneline
   ```
   - If the list is empty, stop — nothing to promote.
   - If non-empty, ask the user to confirm. Do not skip this even if they just invoked the skill — the list can reveal work they didn't intend to release (e.g. a feature PR that snuck in alongside a hotfix).

4. **Push `origin/main` to `origin/prod`**
   ```bash
   git push origin origin/main:prod
   ```
   - Origin-to-origin fast-forward — no local branch switching, no working tree touched.
   - Rejected if not a fast-forward (which step 2 already verified) — if this unexpectedly fails, stop and investigate.

5. **Realign local `prod` (bookkeeping, optional)**
   ```bash
   git branch -f prod origin/prod
   ```

6. **Report**
   - Commits that just shipped (from step 3's list)
   - Note that the fly-deploy workflow is now running — surface the URL `https://github.com/deptex/deptex/actions/workflows/fly-deploy.yml`
   - Remind the user to watch Fly logs if anything looks off

## Rules

- Never force-push `prod`. If step 2 fails, stop — don't "fix" it by forcing.
- Never touch local `main` in this skill. Work from `origin/*` refs only.
- Never bypass step 3's confirmation. Shipping is the one place "measure twice, cut once" matters most.
- Hotfix flow: still branch off `origin/main`, PR into `main`, then `/promote-to-prod`. Do not commit directly to `prod`.
