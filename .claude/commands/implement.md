# Feature Implementation

You are implementing a Deptex feature from a plan. You will work through the plan methodically, building each layer with production quality, and paying special attention to frontend design craft.

## Inputs

Look for the implementation plan in `.cursor/plans/*.plan.md`. If no plan exists, ask the user to run `/plan-feature` first.

## Before Starting

1. Read the full plan — every section, not just the task list
2. Read `.cursor/skills/frontend-design/SKILL.md` for design standards
3. Read `.cursor/skills/ui-principles/SKILL.md` for craft principles
4. Read `.cursor/skills/add-new-features/SKILL.md` for backend patterns
5. Check that any prerequisite migrations or features mentioned in the plan exist
6. **Read the actual code you'll be modifying or extending:**
   - Read the existing route files this feature touches or is adjacent to
   - Read the existing page components this feature builds on or sits next to
   - Read the shared components and hooks you'll be reusing
   - Read the database migration files for tables you'll reference
   - This is NOT optional — you must understand the existing code before writing new code
7. **Review the plan's competitive research section** — understand what patterns we're adopting and why
8. Identify the first task to work on

## Implementation Approach

### Database Layer
- Write clean, well-commented SQL migrations
- Include indexes for query patterns identified in the plan
- Add RLS policies where needed
- Test the migration can be applied cleanly
- **Verify foreign key references** — read the referenced tables to confirm column names and types match

### Backend Layer
- Follow existing route patterns in `backend/src/routes/`
- Register routes in `backend/src/index.ts`
- Use `authenticateUser` middleware consistently
- Add proper TypeScript types — no `any`
- Handle errors with appropriate status codes
- Follow the existing error response format
- **Check query performance** — if a query touches large tables, ensure proper indexes exist and consider pagination

### Frontend Layer — Design First

**This is where craft matters most.** Before writing component code:

1. **Study the neighborhood** — Read 2-3 existing pages similar to what you're building. Match their patterns exactly.
2. **Review the competitive research** — If the plan references a competitor's approach, make sure you understand the pattern before implementing.
3. **Plan the layout** — Decide on the page structure (sidebar+content, full-width, split panel) based on the content needs.
4. **Choose components** — Prefer existing shadcn/Radix components from `frontend/src/components/ui/`. Only create new components when truly needed.
5. **Check for reusable code** — Before building a new component, grep the codebase for similar implementations. Reuse hooks, utilities, and patterns that already exist.

**Design standards to enforce:**
- Use Tailwind tokens from the design skill, never hardcoded colors
- Follow the 4px grid for all spacing
- Cards: `rounded-lg border border-border bg-background-card`
- Tables: header `bg-background-card-header`, rows `divide-y divide-border`, hover `hover:bg-table-hover`
- Text hierarchy: `text-foreground` (primary), `text-foreground-secondary` (secondary), `text-foreground-muted` (muted)
- Buttons: use the correct variant (primary, outline, ghost, destructive)
- Loading states: skeleton shimmer matching the layout shape
- Empty states: centered icon + message + CTA button
- Animations: 150ms micro, 200-250ms transitions, no spring/bounce
- Scrollbars: `custom-scrollbar` class where scrollbars are visible

**Component structure:**
- One component per file
- Props interface at the top
- Hooks before render logic
- Early returns for loading/error/empty states
- Clean JSX — extract complex sections into sub-components

### Working Through Tasks

- Work through the plan's task list in order
- After completing each task, briefly note what was done
- **Validate against the plan** — after each task, check: does this match what the plan specified? Did I miss anything?
- If you discover something the plan missed, note it and handle it
- If you hit a blocker or design decision, ask the user rather than guessing
- Test each layer before moving to the next (SQL → API → UI)

### Quality Checks

Before considering a task done:
- TypeScript compiles without errors (run `tsc --noEmit` on modified files)
- No hardcoded colors, magic numbers, or inline styles
- Loading, empty, and error states are handled
- RBAC checks are in place for protected actions
- The UI matches the existing Deptex aesthetic
- **The feature matches the plan's design specifications** — compare what you built against what was planned
- **Existing functionality still works** — if you modified shared code, verify nothing broke

### After All Tasks Complete

Before declaring the feature done:
1. **Full plan review** — go through every section of the plan and verify each requirement was implemented
2. **Walk the user flow** — mentally trace the user's journey through the feature. Does it make sense end-to-end?
3. **Check the success criteria** — does the implementation meet the success criteria defined in the plan?
4. **Present a summary** — tell the user what was built, what works, and any deviations from the plan

## Rules
- Don't over-engineer — build what the plan says, nothing more
- Don't add console.logs that shouldn't ship
- Don't skip empty states — they're the first thing new users see
- Don't use `any` types — if you don't know the type, define it
- Reference the design skills for every frontend decision
- Ask the user when you're unsure about a design choice
- Commit at natural boundaries (migration done, API done, page done)
- **Read before you write** — every file you modify should be read first. No exceptions.
- **Follow the plan** — if you disagree with the plan, raise it with the user rather than silently deviating
