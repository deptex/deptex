# Feature Implementation Plan

You are creating a detailed, step-by-step implementation plan for a new Deptex feature. This plan should be comprehensive enough that you (or another developer) could follow it to build the feature without ambiguity.

## Inputs

Look for the feature brief in `.cursor/plans/feature-brief-*.md`. If no brief exists, ask the user to run `/interview` first, or ask them to describe the feature so you can work from that.

## Planning Process

### Step 1: Understand the Full Picture

Before writing any plan:
- Read the feature brief thoroughly
- Read CLAUDE.md for architecture context
- Read `.cursor/skills/add-new-features/SKILL.md` for where to add routes and libs
- Read `.cursor/skills/frontend-design/SKILL.md` for UI standards
- Check the roadmap at `.cursor/plans/deptex_projects_roadmap_index.plan.md` for related phases

### Step 2: Competitive & Best Practices Research

**Don't skip this.** Before designing anything, research what already exists:

1. **If the feature brief includes competitive research**, review it and go deeper on the most relevant competitors
2. **If not**, search online for how competing products (Snyk, Socket, Dependabot, Mend, Endor Labs, Semgrep, Sonatype) handle this feature
3. **Search for industry best practices** — how do top SaaS products solve this UX/technical challenge?
4. **Look at design patterns** — search for "[feature type] SaaS UI patterns" or "[feature type] dashboard design"
5. **Document your findings:**
   - What's the standard approach across the industry?
   - What patterns should we adopt vs. where should we differentiate?
   - Any technical approaches worth borrowing?
6. Present a short summary to the user: "Based on competitive research, here's the approach I recommend..."

### Step 3: Deep Codebase Analysis

**This is where most plans fail — they design in theory without understanding the actual code.** Do all of the following:

1. **Read the existing database schema** — grep `backend/database/` for tables this feature touches or relates to. Read the actual CREATE TABLE statements, not just table names.
2. **Read existing similar features** — find 2-3 features in the codebase that are most similar to what you're building. Read their:
   - Route handler (`backend/src/routes/`)
   - Database queries and patterns
   - Frontend page component
   - How they handle loading/error/empty states
3. **Trace the data flow** — for the most similar existing feature, trace the full path: UI → API call → route handler → database query → response → UI rendering
4. **Check for reusable code** — grep for existing utilities, shared components, hooks, or helpers that this feature can reuse. Don't reinvent what exists.
5. **Identify integration points** — where exactly does this feature connect to existing code? Which files will be modified vs. created?
6. **Check for potential conflicts** — are there any existing patterns, naming conventions, or architectural decisions that constrain how this should be built?

Document your codebase findings in the plan — specific file paths, existing patterns to follow, reusable components identified.

### Step 4: Design the Data Model

- Draft SQL migration(s) with exact table definitions, indexes, RLS policies, and constraints
- Identify relationships to existing tables — reference actual column names from your codebase analysis
- Consider what RPCs or database functions are needed
- Think about query patterns and add appropriate indexes
- **Consider data volume** — how many rows will this table have? Does it need partitioning, pagination support, or specific index strategies?
- Number the migration file following the convention in `backend/database/`

### Step 5: Design the API

For each endpoint:
- HTTP method + route path (following existing patterns in `backend/src/routes/`)
- Request/response shape (TypeScript types)
- Auth requirement (authenticateUser, optionalAuth, internal API key)
- Permission checks (which RBAC permission)
- Query logic (which tables, joins, filters)
- Error cases and status codes
- **Performance considerations** — will any query be slow? Does it need pagination, caching, or query optimization?

### Step 6: Design the Frontend

For each page/view:
- Component tree (which components compose the page)
- Route definition (add to `frontend/src/app/routes.tsx`)
- State management approach (local state, context, URL params)
- Data fetching pattern (useEffect + fetch, or existing patterns)
- Layout choice referencing `.cursor/skills/frontend-design/SKILL.md`
- Key UI components needed (existing shadcn components vs new custom ones)
- **Reference competitor/industry patterns** from your research — "similar to how Snyk shows X" or "following the Linear pattern for Y"
- Loading states, empty states, error states
- Responsive behavior
- **Performance** — does this page need virtual scrolling, lazy loading, or debounced search?

### Step 7: Break Into Implementation Tasks

Create an ordered task list where each task:
- Is independently testable
- Has clear acceptance criteria
- Estimates complexity (S/M/L)
- Lists file paths that will be created or modified
- Notes any dependencies on other tasks

Recommended task ordering:
1. Database migration
2. Backend types/interfaces
3. API routes (with basic happy-path testing)
4. Frontend types matching API responses
5. Core UI components (reusable pieces)
6. Page components (assembling the pieces)
7. Navigation/routing integration
8. Polish (loading states, empty states, error handling, animations)
9. Testing & validation

### Step 8: Define Testing & Validation Strategy

- **Backend:** Which endpoints need test coverage? What edge cases matter?
- **Frontend:** What user flows should be tested? Any complex interactions that need verification?
- **Integration:** How do you verify the full data flow works end-to-end?
- **Performance:** What queries should be checked for acceptable speed? Set a target (e.g., <200ms for list pages)
- **Regression:** What existing features could be affected? How to verify they still work?

### Step 9: Identify Risks & Decisions

- Technical risks (performance, complexity, unknowns)
- Design decisions that need user input before proceeding
- Dependencies on external systems
- Migration risks for existing data
- **What could go wrong in production?** (data loss, performance degradation, breaking existing features)

## Output Format

Write the plan to `.cursor/plans/{feature-name}.plan.md` using this structure:

```markdown
# {Feature Name} — Implementation Plan

## Overview
One paragraph summary of the feature and approach.

## Competitive Research & Design Rationale
What competitors do, what patterns we're adopting, where we're differentiating, and why.

## Codebase Analysis
Existing patterns we're following, reusable code identified, integration points, files that will be modified.

## Data Model
### New Tables
(SQL with full CREATE TABLE statements)

### Migrations
(Migration file names and order)

## API Design
### Endpoints
(Table: Method | Route | Auth | Permission | Description)

### Types
(TypeScript interfaces for request/response)

## Frontend Design
### Pages & Routes
(Route definitions and page descriptions)

### Component Tree
(Visual hierarchy of components per page)

### Design Specifications
(Layout, colors, spacing — referencing the design skill and competitor research)

## Implementation Tasks
(Ordered, numbered checklist with complexity and file paths)

## Testing & Validation Strategy
(What to test, how to verify, performance targets)

## Risks & Open Questions
(Bulleted list)

## Dependencies
(What existing features/code this builds on)

## Success Criteria
(How we know this is done and working correctly)
```

## Rules
- Reference existing code patterns — don't invent new conventions
- Be specific about file paths — `backend/src/routes/feature.ts`, not "add a route"
- Include exact SQL, not pseudocode — the migration should be copy-pasteable
- Design the frontend to match Deptex's existing aesthetic (reference the design skills)
- Consider RBAC from the start — don't bolt it on later
- Think about the empty state experience — first-time users matter
- If something is unclear, call it out in "Open Questions" rather than guessing
- **Always do the competitive research** — this is the difference between a mediocre feature and one that's informed by the market
- **Always do the deep codebase analysis** — plans that don't read the actual code produce implementation surprises

## After Writing the Plan

Before handing off to `/implement`, suggest the user run `/review-plan <plan-slug>`. This spawns a multi-agent debate-and-vote review of the plan itself — different lenses (skeptic, pragmatist, scope-cutter, architect, data-model auditor, etc.) read the plan, debate each other's findings, and vote on whether it's ready to build. Catches missed scope, wrong assumptions, and architectural mistakes before `/implement` burns time on them. The skill is opt-in — for small/obvious plans the user can skip straight to `/implement`.
