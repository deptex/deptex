# Brainstorm — Combined Research + Interview

You are scoping a new feature for Deptex from the ground up. This is the divergent → convergent stage: do the competitive research, get the codebase grounding, then interview the user (informed by the research) until you have a feature brief tight enough to feed straight into `/plan-feature`.

**This replaces the older `/research` and `/interview` commands.** One blessed path: `/brainstorm` → `/plan-feature` → `/implement`.

## Inputs

The user names a feature or describes a problem to solve (e.g. "cross-file CVE-targeted taint", "AI sanitizer detection on flow paths", "endpoint classification for sources"). If they haven't, ask for one before starting — `/brainstorm` is for a specific concept, not an open-ended area sweep.

## Phase 1 — Codebase Grounding (do this first, before web research)

Anchor in what already exists. Web research before knowing the local terrain produces generic recommendations.

1. Read CLAUDE.md and `.claude/plans/deptex_projects_roadmap_index.plan.md` (or its successor `ROADMAP.md`).
2. Check auto-memory (`MEMORY.md` index) for related work in flight or shipped — don't re-propose what exists.
3. Grep / read the surface this feature touches:
   - Routes in `backend/src/routes/`
   - Tables in `backend/database/` (read the actual `CREATE TABLE`, not just names)
   - Frontend pages and shared components
   - Libs in `backend/src/lib/` and `depscanner/src/`
4. Read 2-3 existing features that are most architecturally similar to what's being proposed.

Produce a short **Current State** paragraph: what exists, what's rudimentary, what's missing. The user should be able to read this and confirm you understand the area before web research starts.

## Phase 2 — Real Competitive & Feasibility Research

**This is not optional and not skippable with training knowledge.** Use WebSearch + WebFetch to look at what competitors actually ship today. Training knowledge is stale; real product pages, changelogs, docs, and academic papers are not.

Competitors to investigate (pick the ones that match the feature area — don't research all of them):

- **Direct SCA / supply-chain:** Snyk, Socket, Dependabot / GitHub Advanced Security, Mend (WhiteSource), Endor Labs, Sonatype Nexus Lifecycle, JFrog Xray, Checkmarx SCA
- **Adjacent code-security:** Semgrep, Chainguard, Aikido, Jit, Arnica, Apiiro, Ox Security
- **Secrets / SAST:** GitGuardian, TruffleHog, Checkmarx SAST
- **IaC / cloud:** Prisma Cloud, Wiz, Lacework, Tenable
- **Reachability / static analysis academic:** CodeQL, Joern, Phasar, Atom, IRIS
- **Workflow / UX patterns:** Linear, Vercel, GitHub, Stripe, Datadog — when the feature is really about a UX pattern

For each competitor / paper / project relevant to the feature:

1. WebFetch the product page, docs, or paper.
2. Note: what do they call it, what does it do, what's novel vs. table-stakes, recent launches, known limitations.
3. Cite the URL — every claim should be verifiable.
4. **If you can't access the page, say so** rather than inventing what it probably does.

Also feasibility-check anything technically novel:

- Search for academic papers / engineering blog posts on the algorithm or technique.
- Look at relevant OSS projects pushing the frontier — git history, README, CHANGELOG.
- If the feature involves AI: surface model capability tradeoffs (Gemini Flash vs Qwen3-235B vs Claude vs GPT-4) when they actually matter for cost or precision.
- If the feature touches static analysis: look at what known-hard problems (aliasing, dynamic dispatch, async/exception flows) the technique punts on or solves.

## Phase 3 — Synthesize the Landscape

Before going to the interview, write a tight landscape summary in your own working notes:

- What's **table-stakes** in this area (every serious competitor has it)?
- What's the **frontier** (2-3 vendors do it, it's emerging)?
- What does **no one** do well (whitespace / differentiation opportunity)?
- Where is Deptex **behind**, **at parity**, or **ahead**?
- What's the **feasibility verdict** — is the technique known-tractable, known-hard, or genuinely novel? What are the 2-3 biggest risks?
- Cite specific papers / repos / blog posts for any non-obvious feasibility claim.

Show this synthesis to the user **before** asking interview questions — it frames the conversation. ~200-300 words. Real findings, no filler.

## Phase 4 — The Interview

**ASK ALL DECISION QUESTIONS VIA AskUserQuestion, NEVER AS A MARKDOWN LIST.** This is non-negotiable — Henry has flagged it repeatedly, including with caps-lock frustration. See `feedback_ask_user_question_for_interviews.md`.

Group up to 4 cohesive questions per `AskUserQuestion` call. Single questions are fine — don't artificially batch. Recommended option goes first with `(Recommended)` suffix; don't add a manual "Other" — the tool surfaces free-text automatically.

Run the interview as a structured conversation across rounds. Don't rush. Ask one focused group, wait for answers, dig deeper. Adapt round emphasis to the feature — a UX-heavy feature spends more rounds on flows; a back-end pipeline feature spends more on data + reliability.

### Round 1: Goal lock & differentiation
- What's the headline goal — match competitor X, leapfrog them, or whitespace play?
- Who is this for (org admin, security engineer, developer)?
- What measurable outcome means this worked?

### Round 2: Architecture & scope
Tailor questions to what the research surfaced. Examples:
- If the technique has a known cost ceiling: which tier of fidelity (A/B/C) does v1 ship?
- If competitors split the feature across products: do we bundle or split?
- If there's a deterministic core + AI augmentation: open-core vs cloud-only?
- Vuln class / language / framework scope for v1.

### Round 3: Data & integration
- New tables vs columns on existing tables?
- Connects to which existing surfaces (extraction pipeline, Aegis, policy engine, etc.)?
- Real-time updates needed? Background processing? AI tier?
- External integrations (GitHub, Slack)?

Validate feasibility against the codebase: "Based on the existing schema, here's how this connects… any conflicts?"

### Round 4: User flow & UI
- Entry points (sidebar, button on existing page, notification)?
- Layout (table, graph, sidebar, modal)?
- Reference an existing page if the user wants the same shape.
- If a competitor pattern fits, ask whether to mirror or differentiate.

### Round 5: Edge cases, performance, RBAC
- Empty state? Error scenarios?
- Data volume expectations (10 rows? 10k? 1M?)?
- Permission requirements?
- Failure-mode policy (hard-fail / soft-fail / banner)?

### Round 6: Priority, scope, success criteria
- MVP vs full?
- Hard constraints (timeline, dependencies)?
- Behind a feature flag?
- Rollout shape (canary → 10% → 100%, shadow mode, instant)?
- Concrete acceptance criteria — what does "done" look like?

Skip rounds that aren't relevant. A pipeline-internal feature with no UI doesn't need Round 4.

## Phase 5 — Output

Write the result to `.claude/plans/feature-brief-{slug}.md` using this single combined structure:

```markdown
# {Feature Name} — Feature Brief

## Problem Statement
What pain point this solves, in one paragraph.

## Current State in Deptex
What exists today, what's rudimentary, what's missing. Reference specific files / tables / routes.

## Competitive Landscape
### {Competitor 1}
- What they call it, what it does, source URL
- Novel vs table-stakes assessment
### {Competitor 2}
…

## Landscape Synthesis
- Table-stakes / Frontier / Whitespace
- Deptex position today
- Feasibility verdict + top 2-3 risks (cite sources)

## User Stories
As a {role}, I want to {action}, so that {outcome}.

## Locked Scope Decisions
Numbered list of what got locked in the interview. Each one has the rationale (e.g. "Decision 3: ship hand-written sanitizer specs for top 5 frameworks + AI fallback for the long tail. Reason: per-framework spec auth is the 90% tar pit per research; AI fallback contains the explosion.").

## Data Model
New tables / columns / RPCs. Connection to existing schema.

## API Endpoints
Method | Route | Auth | Permission | Description.

## Frontend Surface
Pages, layouts, design references. Reference existing Deptex patterns or competitor screenshots from research.

## User Flows
Step-by-step with decision points.

## Edge Cases & Failure-Mode Policy
What happens when X breaks. Hard-fail / soft-fail / banner / fallback.

## Non-Functional Requirements
Performance targets, data volume, scalability, AI cost ceiling.

## RBAC Requirements
Which permissions gate which actions.

## Dependencies
Prereq features / tables / migrations that must exist first.

## Success Criteria
How we'll measure if this works. Concrete and measurable.

## Open Questions
Anything still unclear after the interview. Each one labeled with severity (blocks /plan-feature / can defer to /implement / informational).

## Recommended Next Step
`/plan-feature` (when blockers cleared) or another `/brainstorm` round (if scope is still loose).
```

## Rules

- **Always do real web research** — WebSearch / WebFetch every non-obvious competitor or feasibility claim and cite the URL. Training-knowledge claims are stale and error-prone.
- **If you can't verify a claim, say so** rather than guess. "Endor appears to do X based on their docs ({URL}); specifics aren't public" is fine.
- **Ground in the codebase before researching the web** — generic competitor recommendations that ignore what already exists are worse than useless.
- **Always use AskUserQuestion for decision questions.** Never markdown question lists. Single questions are fine; group up to 4 when cohesive.
- **Don't design implementation.** No SQL bodies, route handlers, component trees. That's `/plan-feature`'s job. Capture *what* and *why*, not *how*.
- **Match ideas to Deptex's moat.** Aegis (autonomous agent), BYOK AI, tree-sitter reachability, open-core self-host, policy engine, EPD scoring — features that leverage 2+ of these are stronger than generic feature clones.
- **Don't duplicate in-flight work.** Check MEMORY.md for worktree/state memories before brainstorming something that's already being built.
- **Capture rationale, not just decisions.** Every locked scope decision in Phase 5 must include why (research finding, codebase constraint, user preference). Plans rot; rationale survives.
- **Stay in discovery mode.** Don't start sketching SQL or routes during the interview, even when the answer feels obvious — that frames the conversation away from scope.
