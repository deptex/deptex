# Explain Plan

You are giving the developer a plain-English tour of an implementation plan before they hit `/implement`. The goal: leave Henry with a solid mental model of what's about to be built, how it works, how it plugs into the existing codebase, and where his attention should land while the AI writes most of the actual code.

This is **not** a critique (that's `/review-plan`). This is **not** a code walkthrough or tutorial. This is *"here's what we're building, in English, with examples, framed for someone newer to this part of the system."*

Run this **after** `/review-plan` and any patches have been applied, **right before** `/create-worktree` + `/implement`. It's the last thing Henry reads before AI starts writing code, so it should leave him feeling oriented — not buried in detail.

## When to use it

- Before starting `/implement` on any non-trivial plan.
- When Henry is jumping into an area he hasn't worked in for a while and wants the lay of the land.
- When a plan has been heavily revised by `/review-plan` patches and the resulting state has drifted from the original intent — re-explaining sets a clean baseline.

It's overkill for tiny plans (1-2 milestone bug-fix-shaped plans). Skip it if the plan fits on one screen.

## Inputs

Optional plan slug or path. If omitted, find the most recently modified `.claude/plans/*.plan.md` (excluding `archive/`).

## Process

1. **Read the plan in full.** This is the source of truth.
2. **Read the feature brief** at `.claude/plans/feature-brief-{slug}.md` if it exists — it has the *why* in the user's voice.
3. **Read the review report** at `.claude/plans/review-{slug}.md` if it exists — it tells you which decisions were contested and what was ultimately picked.
4. **Read CLAUDE.md** for architecture context — names of existing flows you'll reference.
5. **Read 2-3 of the existing files the plan touches most heavily** so you can talk about them in concrete terms ("this hooks into the extraction pipeline at the same point where Semgrep already runs").
6. **Scan `MEMORY.md` index** for any state memories the plan implicitly relies on (e.g. competing worktrees, prior phases that shipped, conventions).
7. **Produce the explainer** in chat. Only write to a file (`.claude/plans/explainer-{slug}.md`) if the explainer comes out >1500 words AND the user explicitly asks for a written copy.

## Tone

- **Conversational, not formal.** "Here's what's going on." "Now here's the tricky part." Not "The system processes records."
- **Assume the reader knows the codebase generally but is new to THIS area.** Henry has flagged: "I'm new to this stuff because often I am." Take that seriously.
- **Concrete examples beat abstractions every time.** Not "the system processes records." Instead: "When a user clicks 'Add allowlist entry' for `lodash` v4.17.20 with reason 'used in test fixtures only', here's the chain of events..."
- **Define jargon on first use.** "Reachability — whether the vulnerable code actually runs from your app's entry points — is..." Then just "reachability" after.
- **Surface the *why* behind big decisions, not just the *what*.** If `/review-plan` resolved a contested decision, mention it: "We picked X over Y because Z. Y might come up again later."
- **If something is contested or uncertain, say so plainly.** Don't paper over it.
- **Don't critique.** That's `/review-plan`'s job. If something genuinely worries you mid-explainer, drop a one-line "watch this during implementation" note, not a paragraph of P1 anxiety.

## Structure

Output the explainer in this shape. Omit sections that don't apply. Adapt section depth to the plan — a small focused plan gets a 300-400-word explainer; a big multi-milestone plan can run 1000-1500 words but no more. **If the explainer is longer than the plan itself, you've failed.**

### 1. The TL;DR (2-3 sentences)

What this feature does in user-facing terms. No tech jargon. If you couldn't explain it to a non-technical PM in two sentences, you don't understand it well enough yet to write the rest.

### 2. Why we're building it

What's broken or missing today. What pain this solves. What the user does today as a workaround vs. what they'll do after this ships. Pull from the feature brief if it exists.

### 3. The shape of the change

What's being added or modified, in plain English with concrete examples. Group by surface area (data / API / UI / workers), and for each one explain *why it's there*:

- **New tables** — say what each one stores and why a separate table was needed instead of columns on an existing one. Example: *"We need a separate `package_maintainer_snapshots` table because we need to compare today's npm metadata against last month's to detect maintainer takeovers — that's historical data, not current state, so it doesn't belong on `dependencies`."*
- **New API routes** — give a concrete example call. *"`POST /api/orgs/:id/malicious-allowlist` with body `{ package_name: 'left-pad', ecosystem: 'npm', version: '1.0.0', reason: 'used in test fixtures only' }` — that's how a security engineer adds an entry from the UI."*
- **New UI surfaces** — paint a rough mental picture of the page layout. *"Settings → Malicious Allowlist is a Vercel-style table: list of entries on the left, 'Add entry' button top-right, three columns (package, version, who added it + when)."*
- **New worker behavior** — include rough timing. *"This runs once a week as a cron, takes ~15 min for an org with 5k deps, and silently soft-fails on individual packages so one bad fetch doesn't kill the whole sweep."*

### 4. How it plugs into existing code flows

Walk through each existing flow this touches. Use the **actual flow names from CLAUDE.md** (e.g. "Extraction Pipeline", "Aegis tool execution", "Frontend security tab fetch") and explain the change in 2-4 sentences each:

> **Extraction Pipeline.** Today, after dep-scan runs, we fan out to `populate-dependencies` which evaluates policy. We're adding a new step *before* policy: `runMaliciousChecks()`. This means findings of type `'malicious'` will exist in `pending_findings` by the time the policy engine sees them, so policy code can reference them. Concretely: the `pendingFindings` argument passed into the policy evaluator will now include malicious findings.

The point of this section is to give Henry a list of *"oh right, this is the file/flow that's about to grow."*

### 5. Walk through one example end-to-end

Pick the most important user story from the plan and walk through it concretely, layer by layer. This is the section that makes the whole feature *click*.

> **Story:** A security engineer at Acme adds `lodash@4.17.20` to the org-level allowlist after a vetted security review.
>
> 1. **UI:** They open Settings → Malicious Allowlist, click "Add entry", fill in `lodash` / `npm` / `4.17.20` / reason "vetted by security 2026-04-15". Submit.
> 2. **API:** Frontend POSTs to `/api/orgs/{id}/malicious-allowlist`. The route handler checks they have `manage_organization_settings` perm, validates the version is exact (not a range like `^4.0.0`), and inserts into `malicious_allowlist`.
> 3. **DB:** The row lands. The `auth.users` FK on `added_by` is set; `added_by_email` snapshots the email so it survives if the user is later offboarded.
> 4. **Pipeline:** Next time Acme's repo scans, `runMaliciousChecks()` fans out across deps. When it sees `lodash@4.17.20`, it calls the `apply_malicious_allowlist()` RPC, which finds the matching entry and returns `is_allowlisted=true`. The finding is suppressed.
> 5. **UI feedback:** The allowlist entry shows "1 finding suppressed" next to it on the settings page so the engineer can see it actually had an effect.

If the plan has multiple meaningfully-distinct stories, you can include 2 — but never 3+. Quality over quantity.

### 6. Stuff to know going in

The non-obvious things that'll save Henry from getting confused mid-implementation. Bullet-list, 4-8 items max. Examples of what belongs here:

- Conventions specific to this plan that aren't obvious from the code (e.g. *"we're using `version` singular not `version_range` because semver ranges are deferred to v3 — don't be surprised by the singular column name"*).
- Decisions made during `/review-plan` that override common-sense defaults (e.g. *"reachability check is self-contained, NOT reusing Phase 6 callgraph — this was a deliberate decoupling"*).
- Surfaces that look like they should be touched but aren't (e.g. *"we're NOT modifying populate-dependencies even though the pipeline runs alongside it"*).
- Migration ordering gotchas if the plan has them.
- Things that look tempting to fold in but were explicitly deferred (and why).

### 7. Where to keep your eyes during /implement

Concrete checkpoints where Henry should sanity-check the AI's work, framed as "if you only review one thing at each milestone, review this":

- **M1.X:** make sure the migration looks like the SQL in the plan — especially the CHECK constraints, easy place for AI to drift.
- **M1.Y:** verify the API route enforces RBAC; this is multi-tenant.
- **M2.Z:** eyeball the UI design pass; AI tends to forget the empty + error states.
- **General:** the integration with X is the riskiest part because Y.

This section is the explicit deliverable of "stay in the loop while AI writes code." Be specific, not generic ("review carefully" is not useful).

### 8. Open questions or risks worth holding in your head

Carry-forward from the plan's "Open Questions" or the review report's "Open Debates". The 1-3 things that aren't fully resolved and might bite during implementation. If there are none, say so explicitly: *"No outstanding open questions."*

## Rules

- **Plain English everywhere.** No file-path soup. When you cite a file, weave it into prose: *"...over in `backend/src/routes/malicious-allowlist.ts`."*
- **Concrete examples, not abstractions.** "When a user clicks X..." beats "the user initiates a request."
- **Don't repeat the plan.** Synthesize, summarize, contextualize. If Henry wanted the plan re-read he'd reread it.
- **Don't critique.** Drop a one-line "watch during implementation" note for genuine concerns, not a P1 anxiety paragraph.
- **Right-size for the plan.** Small plan → 300-400 words. Medium → 600-900. Large multi-milestone → 1000-1500 max. Never longer than the plan itself.
- **Define jargon on first use, not after.** First mention: "reachability (does this vulnerable code actually run when your app starts)". After that, just "reachability".
- **Ground every claim in the actual plan or review report.** If you say "we picked X over Y because Z", X/Y/Z must come from real source material. Don't invent rationale.
- **Output to chat by default.** Only write a file if the explainer is >1500 words AND the user asked for a saved copy.
- **One pass, no subagents.** This is a synthesis task for the main thread, not a parallel-spawn task.

## After the Explainer

End the chat output with a one-line nudge:

> "Ready to roll? Next: `/create-worktree {slug}` then `/implement`."

(Or `/implement` directly if Henry is implementing on `main` for some reason — but normally it's worktree-first per the blessed workflow.)
