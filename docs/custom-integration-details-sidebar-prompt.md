# Custom Integration Details Sidebar — Design Prompt

Use this prompt to describe or recreate the Custom Integration Details sidebar for design work (e.g., Figma, Google Stitch, or similar tools).

---

## Prompt

**A dark-themed SaaS settings sidebar panel for viewing and managing a custom webhook integration.**

**Layout:** A slide-in panel from the right, max width 420px, full height with 16px inset from top/bottom/right. Rounded corners (12px), subtle border, and shadow. Behind it, a semi-transparent dark backdrop with blur.

**Header:**
- Left: Integration icon (36×36px) — either a custom uploaded image in a rounded container, or a webhook/connection icon placeholder
- Right: Title (integration name, e.g., "Internal tool pipeline") in bold, 20px
- Below title: Subtitle "Custom webhook integration" in muted gray, 14px

**Content sections (scrollable):**

1. **Webhook URL**
   - Label: "Webhook URL" (semibold)
   - Monospace code block showing the full URL (e.g., "https://localhost.com") with light background and border
   - Copy (clipboard) icon button to the right

2. **Divider** — thin horizontal line

3. **Signing secret**
   - Label: "Signing secret"
   - Either:
     - Monospace code block with the secret and a copy button (when newly created or regenerated), OR
     - Helper text: "The secret was shown when you created this integration. Use Regenerate secret below to get a new one."
   - Full-width outlined button: "Regenerate secret"
   - Full-width outlined button: "Send sample ping" (with paper-airplane/send icon)

4. **Divider** — thin horizontal line

5. **Events**
   - Label: "Events"
   - Paragraph: "This webhook receives events such as `vulnerability.found`, `vulnerability.resolved`, and others. Each request is signed with HMAC-SHA256." (event names in inline code style)
   - Link/button: "View documentation" with book icon, in primary/accent color

**Footer:**
- Right-aligned: "Close" (outline button) and "Edit" (primary/accent button with pencil icon)
- Footer has a subtle darker background than the body
- Border-top separating footer from content

**Animation:** Panel slides in from the right (`translate-x`) and fades in over 150ms. Backdrop fades in. On close, reverse the animation before unmounting.

**Style:** Modern enterprise SaaS aesthetic, dark theme, clean typography, ample spacing between sections. Matches Vercel/GitHub/Supabase-style design systems.
