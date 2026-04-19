# Feature Discovery Interview

You are conducting a deep discovery interview with the developer to fully understand a new feature before any planning or implementation begins. Your goal is to extract every important detail so you can later create a comprehensive, actionable plan.

## Interview Process

Run this as a structured conversation across multiple rounds. Do NOT rush. Ask one focused group of questions at a time, wait for answers, then dig deeper.

### Round 1: The Big Picture
Start by asking:
- What is this feature in one sentence?
- Who is it for? (Which user persona — org admin, team lead, developer, security engineer?)
- What problem does it solve that isn't solved today?
- Is there an existing product or tool that does something similar you'd like to reference?

### Round 2: Competitive & Market Research

**Before going deeper, research what already exists.** This is critical — don't design in a vacuum.

1. **Search online** for how competing products handle this same problem. Focus on:
   - Direct competitors: Snyk, Socket, Dependabot, Mend (WhiteSource), Endor Labs, Semgrep, Sonatype
   - Adjacent products that do something similar (e.g., Linear for project management patterns, Datadog for observability UI patterns)
   - Open-source tools in the space
2. **Document what you find:**
   - Which competitors have this feature? What do they call it?
   - What's the common UX pattern across competitors? (If 3/4 do it the same way, that's a strong signal)
   - What do they do well? What feels clunky or missing?
   - Are there any innovative approaches from non-competitors worth borrowing?
3. **Present a brief competitive summary** to the user before continuing — "Here's what I found about how others handle this..."
4. Ask the user: Which of these approaches resonates? What would you do differently?

### Round 3: User Stories & Flows
Based on Rounds 1-2 answers, ask:
- Walk me through the ideal user flow from start to finish
- What are the entry points? (sidebar nav, button on existing page, notification, etc.)
- What decisions does the user make along the way?
- What does success look like for the user?
- Are there different flows for different roles/permissions?

### Round 4: Data & Backend

**Before asking these questions, do a quick codebase scan:**
- Read the relevant existing tables/schema in `backend/database/` that this feature might touch
- Grep for any existing code that handles similar functionality
- Check if there are existing API routes this builds on

Then ask:
- What new data does this feature need? (new tables, new columns on existing tables, new API endpoints)
- Does it connect to any existing data? (projects, teams, vulnerabilities, dependencies, policies, etc.)
- Does it need real-time updates? (Supabase Realtime)
- Does it need background processing? (QStash jobs, workers)
- Does it need AI? (Tier 1 platform AI or Tier 2 BYOK)
- Any external integrations? (GitHub, Slack, email, etc.)

After their answers, validate feasibility: "Based on the existing schema, here's how this could connect to what we have..." Flag any potential conflicts or complications early.

### Round 5: Frontend & Design

**Before asking, research UI patterns:**
- Search online for how best-in-class SaaS products (Vercel, Linear, GitHub, Stripe) handle similar UI needs
- Look at 2-3 existing Deptex pages that are most similar to what this feature needs
- Reference competitor screenshots or patterns you found in Round 2

Then ask:
- What pages/views does this need?
- Any specific UI patterns you want? (tables, graphs, cards, sidebars, modals, split panels)
- Should it follow an existing page's layout? If so, which one?
- Any specific interactions? (drag-and-drop, inline editing, bulk actions, filtering/sorting)
- Mobile responsive or desktop-only?
- Here's how [competitor X] does this — want something similar or different?

### Round 6: Edge Cases, Performance & Non-Functional Requirements
- What happens when there's no data yet? (empty states)
- Error scenarios — what could go wrong?
- **Performance expectations:** How much data will this handle? (10 rows? 10,000? 100,000?) What's the acceptable load time?
- **Scalability:** Will this grow significantly over time? Does it need pagination, virtual scrolling, or lazy loading?
- Any RBAC/permission requirements?
- Does this need to work with the existing policy engine?
- Any migration concerns for existing users/data?
- **Reliability:** Does this need to be real-time accurate or is eventual consistency OK?

### Round 7: Priority, Scope & Success Metrics
- Is this a full feature or MVP first?
- What's the must-have vs nice-to-have?
- Any hard constraints? (timeline, tech debt, dependencies on other phases)
- Should this be behind a feature flag?
- **How will we know this feature is successful?** What metrics or outcomes matter?
- **What does "done" look like?** Define concrete acceptance criteria.

## After the Interview

Once you have thorough answers to all rounds, produce a **Feature Brief** document with:

1. **Feature Name & One-liner**
2. **Problem Statement** — what pain point this solves
3. **Competitive Landscape** — summary of how competitors handle this, what we're borrowing, where we're differentiating
4. **User Stories** — as a [role], I want to [action], so that [outcome]
5. **Data Model** — new tables/columns needed, relationships, connection to existing schema
6. **API Endpoints** — routes, methods, auth requirements
7. **Frontend Views** — pages, components, layouts, design references
8. **User Flows** — step-by-step with decision points
9. **Edge Cases & Error Handling**
10. **Non-Functional Requirements** — performance targets, data volume expectations, scalability needs
11. **RBAC Requirements**
12. **Dependencies** — what existing code/features this builds on
13. **Success Criteria** — how we'll measure if this works
14. **Open Questions** — anything still unclear
15. **Scope** — MVP vs full, phased rollout plan

Save this brief to `.cursor/plans/feature-brief-{feature-name}.md` for reference during planning and implementation.

## Rules
- Ask follow-up questions when answers are vague — "what do you mean by that?" is always valid
- Reference existing Deptex patterns when relevant ("similar to how the vulnerabilities page works?")
- If the user doesn't know an answer, suggest options based on the existing codebase
- Keep the conversation natural, not robotic — you're a senior engineer helping scope a feature
- Do NOT start planning implementation details during the interview — stay in discovery mode
- Always do the competitive research — this is not optional. Present findings before asking the user to make design decisions.
- When the user mentions a competitor feature, go look it up. Don't just take their description — verify and expand on it.
