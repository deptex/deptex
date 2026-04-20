---
name: Phase 11 Landing Page
overview: Landing page and marketing site overhaul — header aligned with app styling, remove fake content, add Get Demo page, replace feature cards with video-driven key features, fix all NavBar and Footer links, and make Open Source and GitHub accurate.
todos:
  - id: header-app-style
    content: Make NavBar a normal header — same background as app (e.g. bg-background border-b), remove scroll-to-pill animation, consistent padding
    status: completed
  - id: header-typography
    content: Reduce gray text in NavBar — use text-foreground for nav items where appropriate, keep primary/green for hover and key CTAs (Sign in)
    status: completed
  - id: remove-company-banner
    content: Remove CompanyBanner (animating fake company names) from HomePage, or replace with "Built with cdxgen, dep-scan…" style strip
    status: completed
  - id: hero-ctas
    content: Hero and CTA section — "Start your project" -> /login, replace "View demo" with "Get a demo" / "Book a demo" linking to new /get-demo page
    status: completed
  - id: demo-page
    content: Add route /get-demo and GetDemoPage — simple page with "Request a demo" (form or contact CTA / Calendly placeholder)
    status: completed
  - id: replace-feature-cards
    content: Remove current 6-card FeaturesSection grid; rely on ProductShowcaseSection (real video/screenshots) to convey key features; optional later add Key Features section per user screenshot
    status: completed
  - id: fix-showcase-video
    content: Replace Supabase placeholder video in ProductShowcaseSection with real product screenshots or one short product video loop; update slide copy to match
    status: completed
  - id: footer-links
    content: Remap all Footer links to real routes; fix Product, Solutions, Developers, Company columns and bottom bar; GitHub/Twitter to real URLs
    status: completed
  - id: navbar-links
    content: NavBar — ensure Product/Resources/Solutions link to existing pages only; Resources Open Source accurate to one repo; remove or gate Pricing until Phase 13 if needed
    status: completed
  - id: navbar-github
    content: NavBar top-right — GitHub link to actual Deptex repo URL; replace hardcoded "12.5K" with real star count (env or GitHub API) or remove number and show "GitHub" only
    status: completed
  - id: open-source-accurate
    content: Open Source page and/or NavBar copy — reflect that Deptex has one main repo (link and description accurate)
    status: completed
  - id: update-roadmap-index
    content: Update roadmap index Phase 11 entry and any references
    status: completed
isProject: false
---

# Phase 11: Landing Page & Marketing Site Overhaul

## Goals

- **Header**: Normal app-style header (same color as app), no scroll animation, less gray text, green for Sign in / primary actions.
- **No fake content**: Remove animating company banner; fix or remove any placeholder stats (e.g. GitHub number).
- **Demo**: "Get a demo" / "Book a demo" that goes somewhere — add a simple Get Demo page.
- **Features**: Drop the 6 ugly feature cards; key features conveyed via the product showcase (video/slides). Optional: add a new Key Features section later from user screenshot.
- **Accuracy**: All NavBar and Footer links point to real routes; Open Source reflects one repo; GitHub link and stat accurate.

---

## 1. Header (NavBar) — app style and copy

**File:** `frontend/src/components/NavBar/NavBar.tsx`

- **Style**: Make header match the rest of the app.
  - Use same background as app shell (e.g. `bg-background border-b border-border`), no floating pill on scroll.
  - Remove the scroll-based transition that changes layout (e.g. `isScrolled ? "top-5" : "top-0"` and the rounded-full pill when scrolled). Keep a single, consistent header bar.
- **Typography**: Reduce reliance on gray for nav items. Use `text-foreground` for main nav labels where it fits the design; keep `text-primary` (green) for hover and for the Sign in button.
- **Links**:
  - Product: Keep links to existing feature pages (`/autonomous-agent`, `/repository-tracking`, etc.).
  - Resources: Open Source → `/open-source` (and ensure Open Source copy reflects one repo). Integrations → `/integrations`. Support → `/support` (redirects to `/docs/help`); keep or rename as "Help" if clearer.
  - Solutions: Leave as-is (user said Solutions is alright).
  - Pricing: Remove from nav until Phase 13, or link to `/pricing` with a "Coming soon" tooltip if PricingPage is minimal.
  - Docs: Keep.
- **GitHub (top right)**:
  - Link: Point to actual Deptex GitHub repo (e.g. `https://github.com/deptex/deptex` or the real org/repo).
  - Number: Replace hardcoded "12.5K" with real data — either (a) show actual GitHub star count (env var or small fetch), or (b) remove the number and show only "GitHub" / icon so it’s accurate until you have a real metric.

---

## 2. Remove company banner

**File:** `frontend/src/components/CompanyBanner.tsx`  
**File:** `frontend/src/app/pages/HomePage.tsx`

- Remove `<CompanyBanner />` from the homepage (the animating strip of fake company names is not true).
- Optional: Add a thin strip such as "Built with cdxgen, dep-scan, Semgrep, TruffleHog, OSV.dev" (no fake customer logos) in a separate component if desired; otherwise leave removed.

---

## 3. Hero and CTA sections — demo and links

**Files:** `frontend/src/app/pages/HomePage.tsx`, `frontend/src/components/CTASection.tsx`

- **Primary CTA**: "Start your project" → link to `/login`.
- **Secondary CTA**: Replace "View demo" with "Get a demo" or "Book a demo" → link to `/get-demo`.
- Optionally refresh hero tagline (e.g. "Security is complicated. We made it simple.") and one short subline; keep CTAs as above.
- In CTASection, same changes: primary → `/login`, secondary → "Get a demo" → `/get-demo`.

---

## 4. Get Demo page

**New:** `frontend/src/app/pages/GetDemoPage.tsx`  
**File:** `frontend/src/app/routes.tsx`

- Add route `path: "get-demo"` (or `"demo"`) with a public route, rendering `GetDemoPage`.
- Page content: Simple "Request a demo" or "Book a demo" — either a short form (name, email, company, message) or a CTA that links out (e.g. Calendly, typeform, or mailto). No complex flow; goal is that "Get a demo" goes to a real page.

---

## 5. Feature cards — remove; features via showcase

**File:** `frontend/src/app/pages/HomePage.tsx`  
**File:** `frontend/src/components/FeaturesSection.tsx`

- Remove the current 6-card FeaturesSection from the homepage (cards are ugly and redundant).
- Do not render `<FeaturesSection />` on the landing page. Key features are conveyed by the ProductShowcaseSection (video or slides with real product content).
- Optional follow-up: If the user provides a screenshot of a preferred "Key features" design, add a new section (new component) that matches it; keep the plan flexible for that.

---

## 6. Product showcase — real content

**File:** `frontend/src/components/ProductShowcaseSection.tsx`

- Replace the Supabase placeholder video with either:
  - Real product screenshots per slide (org dashboard, Aegis, project overview, dependencies, compliance), or
  - One short looped product video.
- Update each slide’s headline and subtext to match actual Deptex features (Aegis, Watchtower, Depscore, policy-as-code, SBOM, etc.).

---

## 7. Footer — all links accurate

**File:** `frontend/src/components/Footer.tsx`

Remap every link to a real destination:

- **Product**: Dependency Tracking → `/repository-tracking`, Policy Enforcement → `/docs/policies` or `/policies` (if under org), AI Remediation → `/autonomous-agent`, SBOM Generation → `/sbom-compliance`. Pricing → `/pricing` or remove until Phase 13.
- **Solutions**: Enterprise → `/solutions/cto-leadership`, Startups → `/solutions/startups-scaleups`, Compliance → `/sbom-compliance` or `/docs/compliance`.
- **Developers**: Documentation → `/docs`. GitHub Integration → `/integrations`. Remove CLI Tools and Webhooks if those pages don’t exist (Phase 18), or link to docs sections if they exist.
- **Company**: Remove About, Blog, Careers if no pages. Privacy → `/docs/privacy` or `/privacy` (if routed). Terms → `/docs/terms` or `/terms`.
- **Bottom bar**: Security → `/docs/security`. Remove Status if no status page.
- **Social**: GitHub → actual Deptex repo URL. Twitter → real handle or remove.

---

## 8. Open Source — one repo

**File:** `frontend/src/app/pages/OpenSourcePage.tsx` (and optionally NavBar copy)

- Ensure the Open Source page and any NavBar dropdown description say that Deptex has one main repository (or clearly list the single repo). Link to the real repo. Remove any implication of multiple repos if there’s only one.

---

## 9. Roadmap index

**File:** `.cursor/plans/deptex_projects_roadmap_index.plan.md`

- Update Phase 11 entry to "Landing Page & Marketing Site Overhaul" (or equivalent) and adjust any cancelled/merged references so the index is accurate.

---

## Files to touch (summary)

| File | Change |
|------|--------|
| `frontend/src/components/NavBar/NavBar.tsx` | Normal header style, no scroll pill, less gray, GitHub link + real stat or no stat, Pricing handled |
| `frontend/src/app/pages/HomePage.tsx` | Remove CompanyBanner, remove FeaturesSection, hero CTA "Get a demo" → /get-demo, "Start your project" → /login |
| `frontend/src/components/CompanyBanner.tsx` | Remove from homepage; optionally repurpose or delete component |
| `frontend/src/components/CTASection.tsx` | Primary → /login, secondary "Get a demo" → /get-demo |
| `frontend/src/app/pages/GetDemoPage.tsx` | **New** — simple Request/Book demo page |
| `frontend/src/app/routes.tsx` | Add route for /get-demo |
| `frontend/src/components/FeaturesSection.tsx` | No longer used on homepage (optional: delete or keep for later Key Features redesign) |
| `frontend/src/components/ProductShowcaseSection.tsx` | Real video/screenshots, accurate slide copy |
| `frontend/src/components/Footer.tsx` | Remap all links; real social URLs |
| `frontend/src/app/pages/OpenSourcePage.tsx` | Copy accurate to one repo |
| `.cursor/plans/deptex_projects_roadmap_index.plan.md` | Phase 11 description and references |

---

## Out of scope for this phase

- Fancy scroll-driven hero animation (keeping header and hero simple).
- New marketing pages other than Get Demo.
- Framework support section changes (can be a separate small task).
- Pricing page content (Phase 13); only link handling is in scope.
