---
name: deptex-creating-popups
description: Use when creating centered modal dialogs (popups) in Deptex. Reference the custom integrations dialog in Organization Settings and the Invite/Add to Team dialogs in Members.
---

# Creating Popups (Dialogs) – Deptex Pattern

Use the Radix `Dialog` component for centered modal popups. Reference: `OrganizationSettingsPage.tsx` (custom integrations), `MembersPage.tsx` (Invite, Add to Team, Change Role).

---

## Structure

```tsx
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from '../../components/ui/dialog';

<Dialog open={isOpen} onOpenChange={(open) => { if (!open) handleClose(); }}>
  <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col">
    <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
      <DialogTitle>Dialog Title</DialogTitle>
      <DialogDescription className="mt-1">
        Short description of what this dialog does.
      </DialogDescription>
    </div>

    <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0">
      {/* Form fields, inputs, etc. */}
    </div>

    <DialogFooter className="px-6 py-4 bg-background">
      <Button variant="outline" onClick={handleClose}>Cancel</Button>
      <Button onClick={handleSubmit} className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40">
        Primary Action
      </Button>
    </DialogFooter>
  </DialogContent>
</Dialog>
```

---

## Key Classes

| Element    | Classes |
|-----------|---------|
| DialogContent | `sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col` |
| Header    | `px-6 pt-6 pb-4 border-b border-border flex-shrink-0` |
| Body      | `px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0` |
| Footer    | `px-6 py-4 bg-background` |

---

## Dropdowns Inside Dialogs

Dropdowns (RoleDropdown, TeamDropdown, ProjectTeamMultiSelect) should use `variant="modal"` when inside a dialog for consistent styling. Use `overflow-visible` on DialogContent so dropdowns can extend. If dropdowns get clipped, ensure the dialog content area has room to scroll (e.g. `overflow-y-auto max-h-[60vh]` on the body) so users can scroll to see options.

---

## Avoid

- `overflow-hidden` on DialogContent (use `overflow-visible` so dropdowns can extend)
- Forgetting `hideClose` if you want to rely on backdrop/cancel only
- Side panel styling (use sidebars skill for slide-in panels)
