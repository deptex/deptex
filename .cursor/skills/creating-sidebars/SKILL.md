---
name: deptex-creating-sidebars
description: Use when creating slide-in side panels (sidebars) in Deptex. Reference the Create Role sidebar in OrganizationSettingsPage and the PolicyExceptionSidebar patterns.
---

# Creating Sidebars – Deptex Pattern

Use floating, rounded slide-in panels from the right for forms and detail views. Reference: `OrganizationSettingsPage.tsx` (Create Role), `PolicyExceptionSidebar.tsx`.

---

## Structure

```tsx
{showSidebar && (
  <div className="fixed inset-0 z-50">
    {/* Backdrop – animated opacity */}
    <div
      className={cn(
        'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
        panelVisible ? 'opacity-100' : 'opacity-0'
      )}
      onClick={handleClose}
    />

    {/* Panel – floating rounded, animated slide */}
    <div
      className={cn(
        'fixed right-4 top-4 bottom-4 w-full max-w-[420px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
        panelVisible ? 'translate-x-0' : 'translate-x-full'
      )}
      onClick={(e) => e.stopPropagation()}
    >
      {/* Header – no X button, no border, no bg tint */}
      <div className="px-6 pt-5 pb-3 flex-shrink-0">
        <h2 className="text-xl font-semibold text-foreground">Sidebar Title</h2>
        <p className="text-sm text-foreground-secondary mt-1">Optional description.</p>
      </div>

      {/* Content – scrollable */}
      <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">
        <div className="space-y-6">
          {/* Section label with icon */}
          <div className="space-y-3">
            <label className="flex items-center gap-2 text-base font-semibold text-foreground">
              <Icon className="h-5 w-5 text-foreground-secondary" />
              Section Label
            </label>
            <input className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm ..." />
          </div>

          {/* Divider between sections */}
          <div className="border-t border-border" />

          {/* Next section */}
        </div>
      </div>

      {/* Footer – border-t, bg tint, right-aligned */}
      <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
        <Button variant="outline" onClick={handleClose}>Cancel</Button>
        <Button
          onClick={handleSubmit}
          disabled={isSubmitting}
          className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
        >
          {isSubmitting ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <ActionIcon className="h-4 w-4 mr-2" />
          )}
          Button Text
        </Button>
      </div>
    </div>
  </div>
)}
```

---

## Animation State

Animate in on mount, animate out before unmount:

```tsx
const [panelVisible, setPanelVisible] = useState(false);

useEffect(() => {
  setPanelVisible(false);
  const raf = requestAnimationFrame(() => {
    requestAnimationFrame(() => setPanelVisible(true));
  });
  return () => cancelAnimationFrame(raf);
}, []);

const handleClose = useCallback(() => {
  setPanelVisible(false);
  setTimeout(onClose, 150);
}, [onClose]);
```

---

## Key Classes

| Element  | Classes |
|----------|---------|
| Backdrop | `fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150` |
| Panel    | `fixed right-4 top-4 bottom-4 w-full max-w-[420px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out` |
| Header   | `px-6 pt-5 pb-3 flex-shrink-0` (clean, no bg tint, no border) |
| Content  | `flex-1 overflow-y-auto no-scrollbar px-6 py-4` |
| Footer   | `px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border bg-background-card-header` |

---

## Style Notes

- **Floating panel**: `right-4 top-4 bottom-4` with `rounded-xl` gives a Vercel-style floating feel
- **No X close button** – Rely on backdrop click or Cancel button to close
- **Header**: Clean, no bg tint, no border-bottom. Title is `text-xl font-semibold`
- **Footer**: Has `border-t border-border` and `bg-background-card-header` tint
- **Section labels**: Use `text-base font-semibold` with an icon via `flex items-center gap-2`
- **Dividers**: Use `<div className="border-t border-border" />` between content sections
- **Inputs**: Use `bg-background-card border border-border rounded-lg` with `focus:ring-2 focus:ring-primary focus:border-transparent`
- **Width**: Default `max-w-[420px]` for forms. Use `max-w-[560px]` for content-heavy sidebars (e.g. code diffs)

---

## When to Use Sidebar vs Popup

| Use Sidebar when…          | Use Popup (Dialog) when…        |
|----------------------------|---------------------------------|
| Long forms, multi-step     | Short forms, quick confirmations |
| Content needs more width   | Content fits ~520px             |
| Following Create Role UX   | Following custom integrations UX |
