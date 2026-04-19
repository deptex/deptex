---
name: deptex-loading-buttons
description: Use when implementing action buttons that show a loading state. Deptex uses a consistent pattern: the icon swaps to a Loader2 spinner while the button text stays the same.
---

# Loading Buttons – Deptex Pattern

When a button triggers an async action (submit, save, invite, etc.), use this pattern:

**Rule: The icon becomes a spinner; the button text stays the same.**

---

## Pattern

```tsx
<Button
  onClick={handleAction}
  disabled={loading}
  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
>
  {loading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Send className="h-4 w-4 mr-2" />}
  Send Invitation
</Button>
```

- **Icon**: Use the appropriate Lucide icon (e.g. `Send`, `Plus`, `Check`, `Save`)
- **Loading**: Replace the icon with `Loader2` + `animate-spin`; keep the same `mr-2` spacing
- **Text**: Do not change (e.g. "Send Invitation", not "Sending...")

---

## Examples

| Action       | Icon        | Text           |
|-------------|-------------|----------------|
| Send invite | `Send`      | Send Invitation |
| Add to team | `Plus`      | Add to Team    |
| Update role | `Check`     | Update Role    |
| Save        | `Save`      | Save Changes   |
| Create      | `Plus`      | Create         |

---

## Avoid

- Changing button text to "Saving...", "Inviting...", "Adding..." (text stays constant)
- Using a full-width SVG spinner instead of `Loader2`
