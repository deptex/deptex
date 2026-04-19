---
name: deptex-frontend-design
description: Maintain Deptex's modern SaaS enterprise frontend design matching Vercel, GitHub, Supabase style. Use when implementing UI components, pages, or styling for the project screen, Dependencies tab, Vulnerabilities tab, Compliance tab, Settings tab, or any new frontend feature.
---

# Deptex Frontend Design – Modern SaaS Enterprise Style

Apply this skill when building or modifying frontend UI to stay consistent with Deptex’s design system and modern SaaS patterns (Vercel, GitHub, Supabase).

---

## Design Philosophy

- Dark, professional enterprise aesthetic
- Minimal chrome, high information density
- Subtle borders and backgrounds to separate content
- Sparing use of brand color (green) for accents and CTAs
- Clear typography hierarchy; content-first layout

---

## Layout & Structure

### Project Layout
- **Header**: Fixed top `h-12`, `z-50`, `bg-background border-b border-border`
- **Sidebar**: Fixed left `top-12 bottom-0 z-40`; collapsed `w-12`, expanded `w-48` with `transition-[width] duration-200`
- **Main content**: `pl-12` (offset for sidebar), full viewport height
- **Page container**: `min-h-screen bg-background`, `px-6 py-6` or `px-4 sm:px-6 lg:px-8 py-8`

### Tab Layouts
- **Left nav + content**: Sidebar `w-52` or `w-64`, `border-r border-border`; content `flex-1`
- **Dependencies**: Resizable package list (min 200px, max 480px, default 320px) + detail panel
- **Settings**: Sticky section nav `w-64`, `sticky top-24 pt-8`; section content `flex-1`

---

## Color Palette

Use Tailwind tokens. Do not hardcode hex unless needed for gradients.

| Token | Usage |
|-------|--------|
| `background` | Page background (#0D0F12) |
| `background-card` | Cards, panels, active nav (#1A1C1E) |
| `background-content` | Content areas (#16181C) |
| `background-card-header` | Table headers (#141618) |
| `background-subtle` | Hover/focus states (#1A1C1E) |
| `table-hover` | Table row hover (#1f2124) |
| `foreground` | Primary text (#F0F4F8) |
| `foreground-secondary` | Secondary text (#A0A6AD) |
| `foreground-muted` | Muted text (#6C757D) |
| `primary` | Brand, links, focus rings (#025230) |
| `border` | Borders (#2C3138) |
| `success` | Success states (#22c55e) |
| `warning` | Warnings (#FFC107) |
| `destructive` | Errors, destructive actions (#EF5350) |
| `info` | Info (#2196F3) |

---

## Typography

- **Fonts**: Inter (sans), JetBrains Mono (mono)
- **Base size**: 15px
- **Title classes**: `title-xxl`–`title-xsm` (use `text-title-md`, etc.)
- **Body**: `text-sm`
- **Labels**: `text-xs font-semibold uppercase tracking-wider text-foreground-secondary`
- **Card titles**: `text-lg font-semibold`

---

## Components

### Cards
```txt
rounded-lg border border-border bg-background-card shadow-sm
```
- Header: `p-6 text-lg font-semibold` or `px-4 py-2.5 border-b border-border bg-black/20`
- Content: `p-6 pt-0` or `p-6`
- Footer: `flex items-center p-6 pt-0` or `px-6 py-3 bg-black/20 border-t border-border`

### Tables
```txt
Container: rounded-lg border border-border bg-background-card overflow-hidden
Header: bg-background-card-header border-b border-border
Header cells: px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider
Body: divide-y divide-border
Scroll: custom-scrollbar class for visible thin scrollbar
```

### Buttons
- Primary: `bg-primary text-primary-foreground border border-primary/50`
- Outline: `border border-input bg-background-card hover:bg-background-card/80`
- Ghost: `hover:bg-background-subtle`
- Icon: `h-9 w-9 rounded-md border border-border bg-background-card text-foreground-secondary hover:bg-background-subtle`
- Destructive: `variant="destructive"`
- Small actions: `size="sm" h-7 text-xs px-2`

### Inputs
```txt
h-9 px-3 py-2.5 bg-background-card border border-border rounded-md
text-sm text-foreground placeholder:text-foreground-secondary
focus:ring-2 focus:ring-primary/50 focus:border-primary
```

### Nav / Tabs
- **Active**: `text-foreground bg-background-card` or `text-foreground border-foreground`
- **Inactive**: `text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50`
- Sidepanel nav: `h-9 px-3 text-sm font-medium rounded-md`
- Sub-tabs: `pb-3 text-sm font-medium border-b-2 -mb-px`; active `border-foreground`, inactive `border-transparent`

### Badges / Pills
- Critical: `bg-destructive/10 text-destructive border-destructive/30`
- High: `bg-orange-500/10 text-orange-600`
- Medium: `bg-warning/15 text-warning`
- Low: `bg-foreground/5 text-foreground-secondary`
- Success: `variant="success"`, Destructive: `variant="destructive"`, Warning: `variant="warning"`

---

## Icons & Spacing

- **Icons**: Lucide React; `h-4 w-4` or `h-5 w-5` for buttons/headers; `h-3.5 w-3.5` for pills
- **Gaps**: `gap-2`, `gap-4`, `gap-6`, `gap-8`
- **Radius**: `rounded-md`, `rounded-lg`, `rounded-xl`; use `--radius` (0.5rem) via Tailwind

---

## Utilities & Patterns

- **Scrollbar**: Add `custom-scrollbar` where scrollbars should be visible
- **Skeleton loading**: `skeleton-shimmer` + `animate-pulse`, `bg-muted rounded`
- **Text gradient**: `text-gradient-primary` or `text-gradient-primary-diagonal`
- **Sidebar item hover**: Optional `tab-icon-shake` for icon feedback

---

## Tab-Specific Patterns

| Tab | Pattern |
|-----|---------|
| **Dependencies** | Search `pl-9 pr-4`, filter `h-9 w-9 rounded-md border`, package rows `py-1.5 pl-5 pr-3 rounded hover:bg-background-subtle` |
| **Vulnerabilities** | React Flow graph, floating card `rounded-lg border border-border bg-background-card/95 backdrop-blur-sm shadow-md` |
| **Compliance** | Sidepanel + table; `getIssueBadgeVariant(issueType)` for badges; Request Exception `variant="outline" size="sm"` |
| **Settings** | Section cards with headers; policy toggle `px-3 py-1.5 text-sm font-medium rounded-md` when active `bg-background-card text-foreground` |

---

## Avoid

- Light backgrounds or washed-out grays for main surfaces
- Heavy shadows or gradients outside accents
- Custom hex colors; prefer Tailwind tokens
- Mixing `background-subtle` for large surfaces (use `background-card` instead)
- Inconsistent padding (stick to `px-4 py-3`, `p-6`, etc.)

---

## Reference

- Tailwind: `frontend/tailwind.config.js`
- Base styles: `frontend/src/app/Main.css`
- Components: `frontend/src/components/ui/` (shadcn), `frontend/src/components/` (custom)
