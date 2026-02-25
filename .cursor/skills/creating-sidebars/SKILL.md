---
name: deptex-creating-sidebars
description: Use when creating slide-in side panels (sidebars) in Deptex. Reference the Create Project sidebar in ProjectsPage and the DeprecateSidebar, BanVersionSidebar patterns.
---

# Creating Sidebars – Deptex Pattern

Use fixed slide-in panels from the right for forms and detail views. Reference: `ProjectsPage.tsx` (Create Project), `DeprecateSidebar.tsx`, `BanVersionSidebar.tsx`.

---

## Structure

```tsx
{showSidebar && (
  <div className="fixed inset-0 z-50">
    <div
      className="fixed inset-0 bg-black/50 backdrop-blur-sm"
      onClick={handleClose}
    />

    <div
      className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl flex flex-col"
      onClick={(e) => e.stopPropagation()}
    >
      {/* Header – tinted */}
      <div className="px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]">
        <h2 className="text-lg font-semibold text-foreground">Sidebar Title</h2>
        <p className="text-sm text-foreground-secondary mt-0.5">
          Optional description.
        </p>
      </div>

      {/* Content – scrollable */}
      <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
        {/* Form content */}
      </div>

      {/* Footer – no border above, right-aligned buttons */}
      <div className="px-6 py-5 flex items-center justify-end gap-3 flex-shrink-0">
        <Button variant="outline" onClick={handleClose}>Cancel</Button>
        <Button
          onClick={handleSubmit}
          className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
        >
          Primary Action
        </Button>
      </div>
    </div>
  </div>
)}
```

---

## Key Classes

| Element  | Classes |
|----------|---------|
| Backdrop | `fixed inset-0 bg-black/50 backdrop-blur-sm` |
| Panel    | `fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl flex flex-col` |
| Header   | `px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]` (tinted top) |
| Content  | `flex-1 overflow-y-auto no-scrollbar px-6 py-6` |
| Footer   | `px-6 py-5 flex items-center justify-end gap-3 flex-shrink-0` (no `border-t`) |

---

## New Sidebar Style (Current)

- **No X close button** – Rely on backdrop click to close
- **Header**: `bg-[#141618]` (slightly darker than body)
- **Footer**: No `border-t border-border` above Cancel / primary button

---

## When to Use Sidebar vs Popup

| Use Sidebar when…          | Use Popup (Dialog) when…        |
|----------------------------|---------------------------------|
| Long forms, multi-step     | Short forms, quick confirmations |
| Content needs more width   | Content fits ~520px             |
| Following Create Project UX| Following custom integrations UX |
