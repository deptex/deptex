# Google Gemini Prompt: Deptex Product Demo Slides

Copy the prompt below into Google Gemini (or a similar AI) to generate slide content for a product demo. You can then create the slides in Google Slides and add your own screenshots where indicated.

---

## Prompt (copy from here)

You are helping create a professional product demo deck for **Deptex**, an organization-centric ASPM (Application Security Posture Management) platform. The audience is technical and security-minded. Generate slide-by-slide content for Google Slides. For each slide give: a short title, 3–5 bullet points (or one short paragraph where noted), and in brackets where to place a screenshot if needed. Use clear, benefit-focused language. Do not invent features; stick to what is described below.

---

### Slide 1: Title
- **Title:** Deptex — Organization-Centric ASPM Platform
- **Subtitle (optional):** Dependency security, policy-as-code, and supply chain visibility that adapts to your organization
- **No screenshot.** Keep this slide minimal: product name and one-line tagline.

---

### Slide 2: The Build vs Buy Dilemma
- **Title:** Why Mature Organizations Build Instead of Buy
- **Bullets:**
  - Most security tools force organizations to adapt to rigid, one-size-fits-all structures.
  - Limited integrations, non-customizable notifications, and fixed compliance rules lead to shelfware.
  - Mature teams end up building internal ASPM workflows because off-the-shelf tools lack: granular custom roles, least-privilege permissions, and compliance rules that match their actual policy.
  - The result: internal tools that wrap commercial SaaS, duplicated effort, and alert fatigue.
- **No screenshot.** This sets up the problem Deptex solves.

---

### Slide 3: The Deptex Approach — Policy as Code (1)
- **Title:** Define Your Own Rules: Policy as Code
- **Bullets:**
  - Users define their own **statuses** (e.g. Compliant, Non-Compliant, Under Review, Safe, Unsafe) and **asset tiers** (e.g. Crown Jewels, External, Internal, Non-Production — or custom tiers).
  - They write **JavaScript** for three policy surfaces: **package policy** (per-dependency allow/block), **project status** (what makes a project compliant), and **pull request check** (what blocks a PR).
  - Policies run in a sandbox and receive a rich **context** (dependency, project, tier, vulnerabilities, license, reputation score). Rules can be as specific as “block this license only for Crown Jewels” or “fail status if there are more than N critical reachable vulns.”
- **Screenshot placeholder:** [Insert screenshot of the Policies page or Monaco editor showing Package Policy / Project Status / PR Check code.]
- **Optional second bullet block:** With the open-core model, organizations can extend events and checks and call their own APIs — possibilities are not limited to out-of-the-box fields.

---

### Slide 4: The Deptex Approach — Custom Notifications
- **Title:** Custom Notifications That Reduce Alert Fatigue
- **Bullets:**
  - Notification rules can use **custom code** (custom_code_pipeline): JavaScript that receives event context (project, dependency, vulnerability, asset tier, etc.) and returns whether to notify.
  - Example: “Only send an alert for a new vulnerability if the package is imported in more than two files” or “Only notify for Crown Jewels projects” — so teams are not bombarded by “vulnerability in a package you use once.”
  - Triggers include vulnerability_discovered, weekly_digest, and custom_code_pipeline; destinations include Slack, Discord, Jira, Linear, email, PagerDuty, and custom webhooks.
- **Screenshot placeholder:** [Insert screenshot of Notification Rules or a rule with custom code.]
- Keep the tone: we wrap proven open-source scanning (e.g. dep-scan) and let you control **when** and **how** you get notified.

---

### Slide 5: Context-Aware Scoring — Depscore
- **Title:** Context-Aware Vulnerability Scoring: Depscore
- **Bullets:**
  - Each vulnerability gets a **Depscore** (0–100) that goes beyond raw CVSS: it combines **CVSS**, **EPSS**, **CISA KEV**, **reachability** (is the vulnerable code actually used?), and **environmental** context.
  - **Asset tier** matters: users assign each project an asset tier (e.g. payment service = Crown Jewels). Organizations can create **custom asset tiers** with their own **environmental multiplier** (e.g. 1.5 for critical, 0.6 for non-production). Higher-tier projects weight vulnerabilities more heavily so prioritization matches business risk.
  - Direct vs transitive, dev vs production, package reputation, and malicious-flag adjustments are also factored in. Result: one number that reflects “how much should we care about this vuln in this project?”
- **Screenshot placeholder:** [Insert screenshot of Security tab or dependency view showing Depscore and asset tier.]
- **Do not** include the full formula; keep it conceptual (CVSS + EPSS + KEV + reachability + asset tier + context).

---

### Slide 6: Graph-Centric UX
- **Title:** ASPM That Feels Like Your Organization: Graph-Centric UX
- **Bullets:**
  - Deptex improves the UX of ASPM by representing the organization as **interactive graphs** instead of only static tables.
  - **Supply chain view:** dependency graphs (project → direct → transitive) with vulnerability and policy state on nodes; ban/safe-version actions in context.
  - **Security view:** organization- and team-level vulnerability graphs (e.g. projects/dependencies as nodes, vulns and Depscore visible). Filter by severity, reachability, KEV, etc.
  - Navigating by graph makes blast radius and “what affects what” visible at a glance.
- **Screenshot placeholder:** [Insert screenshot of the dependency supply chain graph or the organization/team vulnerability graph.]
- Tone: we’re not competing on “new vuln DB” — we’re competing on **clarity and control** (policy, notifications, context, UX).

---

### Slide 7: Summary or CTA (optional)
- **Title:** Deptex in a Nutshell
- **Bullets:**
  - **Policy as code** — your statuses, your asset tiers, your rules (package, project, PR).
  - **Custom notifications** — code-driven rules to cut noise and focus on what matters.
  - **Context-aware Depscore** — CVSS + EPSS + KEV + reachability + asset tier, so prioritization matches risk.
  - **Graph-centric UX** — see your org and supply chain as graphs, not just tables.
  - **Open core** — extend with your own events and integrations.
- **No screenshot.** Use as recap or transition to Q&A/demo.

---

**Instructions for the AI:** Output the slide content in a format that is easy to copy into Google Slides (e.g. one section per slide with title and bullets). Use professional, concise language. Do not add features that were not described above. If the user asks for a different length or style (e.g. more technical, more executive), adapt the bullets accordingly but keep the facts accurate.

---

## Product facts (for your reference when editing)

- **Depscore formula (conceptual):** Base impact (CVSS × 10) × threat multiplier (CISA KEV or EPSS-based) × environmental multiplier (asset tier × reachability weight) × dependency context (direct/transitive, dev/prod, malicious, package reputation). Capped at 100.
- **Asset tiers (defaults):** Crown Jewels (multiplier 1.5), External (1.2), Internal (1.0), Non-Production (0.6). Orgs can add custom tiers with custom multipliers.
- **Policy surfaces:** Package Policy (per dependency), Project Status (project-level compliance), Pull Request Check (PR merge rules). All JavaScript, sandboxed, with rich context.
- **Notification triggers:** weekly_digest, vulnerability_discovered, custom_code_pipeline (custom code). Context includes project, dependency, vulnerability, asset tier, etc.
- **Open core:** CE (core) + EE (commercial); orgs can extend with their own events and logic.
