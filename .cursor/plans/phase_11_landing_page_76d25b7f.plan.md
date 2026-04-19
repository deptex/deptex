---
name: Phase 11 Landing Page
overview: Repurpose Phase 11 as "Landing Page & Marketing Site Finalization" -- fix broken links/CTAs, update feature descriptions and showcase content to accurately reflect what Deptex actually does, expand framework support visuals, clean up Footer/NavBar dead links, and polish the overall marketing experience.
todos:
  - id: fix-hero-ctas
    content: Fix hero section CTAs in HomePage.tsx and CTASection.tsx -- /signup -> /login, /demo -> /docs/quick-start
    status: pending
  - id: update-features
    content: Update FeaturesSection.tsx with accurate descriptions and highlights for all 6 feature cards
    status: pending
  - id: expand-frameworks
    content: Add Dart, Elixir, Swift, NuGet to FrameworkSupportSection.tsx (4 missing ecosystems)
    status: pending
  - id: fix-showcase
    content: Replace placeholder Supabase video in ProductShowcaseSection.tsx with real product screenshots, update slide copy
    status: pending
  - id: fix-footer
    content: Remap ~15 dead links in Footer.tsx to actual routes, update social links
    status: pending
  - id: fix-navbar-pricing
    content: Handle /pricing link in NavBar.tsx (remove or add tooltip until Phase 13)
    status: pending
  - id: update-company-banner
    content: Replace fake company logos in CompanyBanner.tsx with open-source tooling logos or remove
    status: pending
  - id: responsive-polish
    content: Responsive check and animation polish across all landing page sections
    status: pending
  - id: update-roadmap-index
    content: Update roadmap index to reflect new Phase 11 (replace cancelled entry)
    status: pending
isProject: false
---

# Phase 11: Landing Page & Marketing Site Finalization

## Problem

The landing page and marketing site have several accuracy and completeness issues:

- **Broken CTAs**: Hero buttons link to `/signup` and `/demo` -- neither route exists
- **Placeholder video**: [ProductShowcaseSection.tsx](frontend/src/components/ProductShowcaseSection.tsx) uses a Supabase table editor video (not Deptex content) for all 5 carousel slides
- **Sparse feature descriptions**: [FeaturesSection.tsx](frontend/src/components/FeaturesSection.tsx) has empty `highlights` arrays and terse descriptions
- **Incomplete ecosystem list**: [FrameworkSupportSection.tsx](frontend/src/components/FrameworkSupportSection.tsx) shows 7 ecosystems but Deptex supports 11 (missing Dart/Pub, Elixir/Hex, Swift, NuGet)
- **~15 dead footer links**: [Footer.tsx](frontend/src/components/Footer.tsx) links to `/product/tracking`, `/product/policy`, `/developers/cli`, `/about`, `/blog`, `/careers`, `/status`, etc. -- none exist
- **Fake company banner**: [CompanyBanner.tsx](frontend/src/components/CompanyBanner.tsx) shows placeholder logos (Microsoft, GitHub, etc.)
- **Generic social links**: Footer Twitter/GitHub links go to `twitter.com` / `github.com` root
- **NavBar `/pricing`**: Links to a page that won't exist until Phase 13

---

## Scope

This phase focuses on making the existing landing page accurate and polished -- not adding net-new marketing pages. The feature pages (`/autonomous-agent`, `/repository-tracking`, etc.) and solution pages already exist and just need minor copy alignment.

---

## Changes

### 1. Fix Hero Section CTAs

**File:** [HomePage.tsx](frontend/src/app/pages/HomePage.tsx)

- Change "Start your project" link from `/signup` to `/login` (which handles OAuth signup)
- Change "View demo" link from `/demo` to `/docs/quick-start` (or `/docs/introduction`)
- Review hero copy -- "Security you can trust." and subtext are good but subtext should match actual current capabilities

### 2. Update Feature Cards

**File:** [FeaturesSection.tsx](frontend/src/components/FeaturesSection.tsx)

- Expand the 6 feature card descriptions to be more specific and accurate:
  - **Autonomous Security Agent**: mention Aegis, tool execution, automations, chat interface
  - **Repository Tracking**: mention GitHub/GitLab/Bitbucket support, cdxgen SBOM, extraction pipeline
  - **Anomaly Detection**: mention Watchtower, registry integrity, contributor analysis, commit forensics
  - **Vulnerability Intelligence**: mention OSV/GHSA, EPSS scoring, CISA KEV, Depscore, reachability
  - **SBOM & Compliance**: mention CycloneDX generation, license checking, policy-as-code, export
  - **Project Health**: mention health score, OpenSSF scorecard, reputation scoring, dep freshness
- Add 2-3 meaningful `highlights` per card that describe real capabilities

### 3. Expand Framework Support

**File:** [FrameworkSupportSection.tsx](frontend/src/components/FrameworkSupportSection.tsx)

- Add the 4 missing ecosystems to match actual backend support in [ecosystems.ts](backend/src/lib/ecosystems.ts): Dart (Pub), Elixir (Hex), Swift, .NET (NuGet)
- Total: 11 ecosystem logos (npm, Python, Go, Rust, Java, Ruby, PHP, Dart, Elixir, Swift, NuGet)
- Add corresponding logo images to `public/images/frameworks/`

### 4. Replace Placeholder Product Showcase Video

**File:** [ProductShowcaseSection.tsx](frontend/src/components/ProductShowcaseSection.tsx)

Currently all 5 slides show the same Supabase video. Two options:

- **Option A (screenshots)**: Replace the video element with static product screenshots per slide (org dashboard, Aegis panel, project overview, dependency graph, compliance page). Simpler and ships faster.
- **Option B (keep video structure)**: Record 5 short screen recordings of actual Deptex features. More polished but requires asset creation.

Either way, update the 5 slide descriptions to accurately reflect current features:

- Slide 1 (Organization): accurate -- mention roles, teams, integrations
- Slide 2 (AI Employee): update to reference Aegis by name, mention chat + automations + tool execution
- Slide 3 (Project Health): accurate -- mention extraction, health score, vuln summary
- Slide 4 (Dependencies): mention supply chain graph, Watchtower monitoring, version tracking
- Slide 5 (Compliance): mention policy-as-code, SBOM export, license governance

### 5. Fix Footer Links

**File:** [Footer.tsx](frontend/src/components/Footer.tsx)

Remap all dead links to actual routes:

- **Product column**: `/product/tracking` -> `/repository-tracking`, `/product/policy` -> `/docs/policies`, `/product/ai` -> `/autonomous-agent`, `/product/sbom` -> `/sbom-compliance`. Remove or comment out `/pricing` until Phase 13.
- **Solutions column**: `/solutions/enterprise` -> `/solutions/cto-leadership`, `/solutions/startups` -> `/solutions/startups-scaleups`, `/solutions/compliance` -> `/sbom-compliance`
- **Developers column**: `/developers/github` -> `/integrations`, `/developers/cli` -> remove (Phase 18), `/developers/webhooks` -> remove (Phase 18). Keep `/docs` link.
- **Company column**: Remove `/about`, `/blog`, `/careers` (don't exist). Keep `/privacy` -> `/docs/privacy`, `/terms` -> `/docs/terms`.
- **Bottom bar**: `/security` -> `/docs/security`, `/status` -> remove (no status page)
- **Social links**: Update GitHub href to actual Deptex repo URL (or leave as placeholder with a TODO comment), update Twitter similarly

### 6. Fix CTA Section Links

**File:** [CTASection.tsx](frontend/src/components/CTASection.tsx)

- Change `/signup` to `/login`, `/demo` to `/docs/quick-start`

### 7. Handle NavBar Pricing Link

**File:** [NavBar.tsx](frontend/src/components/NavBar/NavBar.tsx)

- Remove the `/pricing` nav link until Phase 13 (Billing) is implemented, or redirect to a simple "Coming soon" anchor/tooltip

### 8. Update CompanyBanner

**File:** [CompanyBanner.tsx](frontend/src/components/CompanyBanner.tsx)

- Either replace fake company logos with a generic "Trusted by developers worldwide" text treatment, or remove the section entirely until real customers/partners exist
- Alternative: replace with an open-source community banner ("Built on open-source. Powered by cdxgen, dep-scan, Semgrep, TruffleHog, OSV.dev") showing tool/project logos that Deptex actually integrates with

### 9. Responsive & Polish Pass

- Verify all sections render well on mobile (the NavBar already has a hamburger menu)
- Ensure feature card animations (intersection observer fade-in) work smoothly
- Check that framework logos display correctly with the invert filter in dark mode
- Verify the ProductShowcaseSection auto-advance timer and progress bars work properly

---

## Files Modified


| File                                                  | Change                                       |
| ----------------------------------------------------- | -------------------------------------------- |
| `frontend/src/app/pages/HomePage.tsx`                 | Fix hero CTAs, review copy                   |
| `frontend/src/components/FeaturesSection.tsx`         | Update descriptions and highlights           |
| `frontend/src/components/FrameworkSupportSection.tsx` | Add 4 missing ecosystems                     |
| `frontend/src/components/ProductShowcaseSection.tsx`  | Replace placeholder video, update slide copy |
| `frontend/src/components/CTASection.tsx`              | Fix CTA links                                |
| `frontend/src/components/Footer.tsx`                  | Remap ~15 dead links                         |
| `frontend/src/components/NavBar/NavBar.tsx`           | Handle /pricing link                         |
| `frontend/src/components/CompanyBanner.tsx`           | Replace fake logos                           |
| `public/images/frameworks/`                           | Add dart, elixir, swift, nuget logos         |


---

## Roadmap Index Updates

Update [deptex_projects_roadmap_index.plan.md](.cursor/plans/deptex_projects_roadmap_index.plan.md):

- Replace the cancelled Phase 11 entry with: "Phase 11: Landing Page & Marketing Site Finalization"
- Update the todo item `phase-11-merged` to reflect the new phase
- Add Phase 11 to the dependency graph (no hard dependencies, can be done anytime)
- Update the Phase Index links section

