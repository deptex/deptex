# Feature Area Research & Brainstorm

You are helping the developer explore an **area** of Deptex (not a specific feature) and surface a ranked shortlist of ambitious feature concepts. This is the divergent, top-of-funnel stage — before `/interview`, before `/plan-feature`. Think big.

## Inputs

The user will name an area of the app — e.g. "vulnerability management", "the security tab", "PR checks", "Aegis", "policy engine", "SBOM / supply chain", "SLA and incident response". If they haven't, ask them to specify the area before starting.

## Research Process

### Step 1: Understand the Current State of Deptex in This Area

Before looking outward, understand what we already have.

1. Read CLAUDE.md for architecture context.
2. Read `.cursor/plans/deptex_projects_roadmap_index.plan.md` for where this area sits in the roadmap.
3. Check auto-memory (`MEMORY.md` index) for any in-flight or shipped work in this area — don't re-propose what's already done or underway.
4. Grep the codebase for the relevant surface:
   - Routes in `backend/src/routes/` touching this area
   - Database tables in `backend/database/` related to it
   - Frontend pages and components
   - Any libs in `backend/src/lib/` that power it
5. Summarize: what exists today, what's rudimentary, what's completely missing.

Produce a short **"Current State"** paragraph before moving on. The user should be able to read this and confirm you understand the area correctly.

### Step 2: Deep Competitive Research (Real Web, Not Training Data)

**This is not optional and not skippable with training knowledge.** Use WebSearch and WebFetch to look at what competitors actually ship today. Training knowledge is stale; real product pages, changelogs, and docs are not.

Competitors to investigate (not exhaustive — add others if relevant to the area):

- **Direct SCA / supply-chain:** Snyk, Socket, Dependabot / GitHub Advanced Security, Mend (WhiteSource), Endor Labs, Sonatype Nexus Lifecycle, JFrog Xray, Checkmarx SCA
- **Adjacent code-security:** Semgrep, Chainguard, Aikido, Jit, Arnica, Apiiro, Ox Security
- **Secrets / SAST:** GitGuardian, TruffleHog, Checkmarx SAST
- **IaC / cloud:** Prisma Cloud, Wiz, Lacework, Tenable
- **Workflow / UX patterns:** Linear, Vercel, GitHub, Stripe, Datadog — when the area is really about an interaction pattern

For each competitor relevant to the area:

1. WebFetch their product page or docs for this area.
2. Note: what do they call it, what does it do, what's novel vs. table-stakes, pricing tier, recent launches.
3. Cite the URL — every claim should be verifiable.
4. Screenshot-free summary: if you can't access the page, say so rather than inventing what it probably does.

Also search for:
- Recent (2024-2026) launches, blog posts, and "state of X" reports in this area
- Relevant academic work or OSS projects pushing the frontier (e.g. reachability analysis research, EPSS trending, LLM-based triage)

### Step 3: Synthesize the Landscape

Before brainstorming, step back and write a short landscape summary:

- What's **table-stakes** in this area (every serious competitor has it)?
- What's the **frontier** (2-3 vendors do it, it's emerging)?
- What does **no one** do well (whitespace / differentiation opportunity)?
- Where is Deptex **behind**, **at parity**, or **ahead**?

This framing drives the brainstorm — feature ideas should map to one of those four buckets.

### Step 4: Brainstorm — Generate 8-12 Feature Concepts

Deliberately vary scope and ambition. A good brainstorm mixes:

- **Table-stakes gaps** — things we're missing that every competitor has
- **Parity-plus** — areas where we could match and do slightly better (e.g. better UX, cheaper, open-core)
- **Differentiators** — features that lean into what Deptex uniquely can do (autonomous Aegis, BYOK AI, tree-sitter reachability, open-core)
- **Moonshots** — ambitious ideas that are hard but category-defining if they land

Do not self-censor at this stage. Include 1-2 ideas you expect Henry to reject — they often sharpen the thinking on the ones he accepts.

For each concept, capture:

- **Name** — short, memorable, product-y (not "add X endpoint")
- **One-liner** — what it is in one sentence
- **Target user** — org admin, team lead, security engineer, developer, CISO
- **Problem it solves** — what pain is this addressing?
- **Competitive positioning** — who does this today, how, where we'd differentiate (cite URLs)
- **Deptex fit** — which parts of our architecture / existing features this leverages (Aegis, reachability, policy engine, BYOK AI, open-core self-host, etc.)
- **Rough size** — S / M / L / XL (S = 1-2 weeks, XL = multi-phase effort)
- **Strategic bucket** — table-stakes / parity-plus / differentiator / moonshot

### Step 5: Rank and Shortlist

Score each concept on two axes (1-5 each):

- **Value** — how much does this move the product forward? (user pain, competitive pressure, strategic fit)
- **Leverage** — how much does this build on existing Deptex strengths vs. starting from zero? (moonshots can still score high here if they ride on Aegis / reachability / policy engine)

Plot the top candidates. Recommend a **shortlist of 3-5** — the ones that are high-value AND high-leverage. Flag 1-2 moonshots separately as "bigger bets to consider."

The full 8-12 list is preserved in the output for future reference.

## Output Format

Write to `.cursor/plans/research-{area-slug}.md`:

```markdown
# Research: {Area Name}

## Current State in Deptex
{One paragraph — what exists today, what's rudimentary, what's missing. Reference specific files/tables/routes.}

## Competitive Landscape
### {Competitor 1}
- What they call it: {name}
- What it does: {summary}
- Novel / table-stakes: {assessment}
- Source: {URL}

### {Competitor 2}
...

## Landscape Synthesis
- **Table-stakes:** {list}
- **Frontier:** {list}
- **Whitespace (no one does well):** {list}
- **Deptex position today:** behind / at parity / ahead in {specific sub-areas}

## Shortlist (Recommended)

### 1. {Concept Name} — {Value}/5 value, {Leverage}/5 leverage
- **One-liner:** ...
- **Target user:** ...
- **Problem:** ...
- **Competitive positioning:** ... ({URL})
- **Deptex fit:** ...
- **Size:** {S/M/L/XL}
- **Bucket:** {table-stakes/parity-plus/differentiator/moonshot}
- **Why shortlisted:** ...

### 2. {Concept Name} — ...
...

## Moonshots to Consider
{1-2 ambitious ideas worth discussing even if not shortlisted.}

## Full Brainstorm (Appendix)
{The other 3-7 concepts from Step 4 in the same format — preserved for later revisit.}

## Recommended Next Step
Run `/interview` on concept #{N} ("{Concept Name}") to refine scope before planning.
```

## Rules

- **Do real web research.** Training-knowledge competitor claims are stale and error-prone — WebSearch/WebFetch every non-obvious assertion and cite the URL.
- **If you can't verify a claim, say so** rather than guess. "Endor appears to do X based on their docs page ({URL}), but the specifics aren't public" is fine.
- **Think big.** This stage is for ambition, not MVP triage. Interview + plan will shrink scope later.
- **Don't design implementation.** No SQL, no route sketches, no component trees. That's `/plan-feature`'s job.
- **Don't duplicate in-flight work.** Check MEMORY.md for worktree/state memories before proposing something that's already being built.
- **Match ideas to Deptex's moat.** Aegis (autonomous agent), BYOK AI, tree-sitter reachability, open-core self-host, policy engine — concepts that leverage 2+ of these are stronger than generic feature clones.
- **Rank honestly.** If the shortlist is dominated by table-stakes catch-up, say so — that's a strategic signal.
- **One area at a time.** If the user's area is broad ("security"), ask them to narrow before you start.
